"""
Container format probing -- MKV Cues and MP4 moov.

Pure Python probing using EBML parsing (MKV) and struct-based atom
scanning (MP4). No FFmpeg dependency.

Source-agnostic: accepts any MediaSource protocol implementation
(Telegram, HTTP, etc.) for byte-range reads.

Provides:
- probe_mkv_cues: probe MKV file to extract seek index (MKVCueIndex)
- probe_mp4_moov: probe MP4 file to extract moov atom and build seek index (MP4Index)
"""

import base64
import hashlib
import json
import logging
import struct

from mediaflow_proxy.utils import redis_utils
from mediaflow_proxy.remuxer.ebml_parser import (
    MKVCueIndex,
    build_cue_index,
    parse_ebml_header,
    parse_seek_head,
    CUES,
    INFO,
)
from mediaflow_proxy.remuxer.mp4_parser import (
    MP4Index,
    build_cue_points_from_moov,
    is_mp4_header,
    rewrite_moov_offsets,
)

logger = logging.getLogger(__name__)

# How much of the MKV header to fetch for SeekHead + Info parsing
_HEADER_PROBE_SIZE = 64 * 1024  # 64 KB

# Max Cues element size we'll attempt to fetch
_MAX_CUES_SIZE = 2 * 1024 * 1024  # 2 MB

# Redis cache for MKV Cue indexes
_CUE_INDEX_CACHE_PREFIX = "mfp:cue_index:"
_CUE_INDEX_CACHE_TTL = 3600  # 1 hour


# =============================================================================
# MKV Cues probing
# =============================================================================


def derive_cue_cache_key(
    source_key: str = "",
    *,
    chat_id: str | int | None = None,
    message_id: int | None = None,
    file_id: str | None = None,
) -> str:
    """
    Derive a deterministic cache key for a file's cue index.

    Accepts either a pre-computed source_key (from MediaSource.cache_key)
    or legacy Telegram-style parameters for backwards compatibility.
    """
    if source_key:
        return source_key
    if file_id:
        raw = f"file_id:{file_id}"
    elif chat_id is not None and message_id is not None:
        raw = f"chat:{chat_id}:msg:{message_id}"
    else:
        return ""
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


async def _get_cached_cue_index(cache_key: str) -> MKVCueIndex | None:
    """Try to load a MKVCueIndex from Redis cache."""
    if not cache_key:
        return None
    r = await redis_utils.get_redis()
    if r is None:
        return None
    redis_key = f"{_CUE_INDEX_CACHE_PREFIX}{cache_key}"
    data = await r.get(redis_key)
    if not data:
        return None
    try:
        d = json.loads(data)
        seek_header = b""
        if d.get("seek_header_b64"):
            seek_header = base64.b64decode(d["seek_header_b64"])
        video_codec_private = b""
        if d.get("video_codec_private_b64"):
            video_codec_private = base64.b64decode(d["video_codec_private_b64"])
        index = MKVCueIndex(
            duration_ms=d["duration_ms"],
            timestamp_scale=d["timestamp_scale"],
            cue_points=[(cp[0], cp[1]) for cp in d["cue_points"]],
            segment_data_offset=d["segment_data_offset"],
            first_cluster_offset=d.get("first_cluster_offset", 0),
            seek_header=seek_header,
            audio_codec_id=d.get("audio_codec_id", ""),
            audio_bitrate=d.get("audio_bitrate", 0),
            audio_channels=d.get("audio_channels", 0),
            audio_sample_rate=d.get("audio_sample_rate", 0.0),
            video_codec_id=d.get("video_codec_id", ""),
            video_codec_private=video_codec_private,
            video_width=d.get("video_width", 0),
            video_height=d.get("video_height", 0),
            video_fps=d.get("video_fps", 0.0),
            video_default_duration_ns=d.get("video_default_duration_ns", 0),
        )
        logger.debug("[container_probe] Loaded cue index from cache: %s", cache_key)
        return index
    except (KeyError, TypeError, json.JSONDecodeError) as e:
        logger.warning("[container_probe] Invalid cached cue index: %s", e)
        return None


async def _set_cached_cue_index(cache_key: str, index: MKVCueIndex) -> None:
    """Cache a MKVCueIndex in Redis."""
    if not cache_key:
        return
    r = await redis_utils.get_redis()
    if r is None:
        return
    redis_key = f"{_CUE_INDEX_CACHE_PREFIX}{cache_key}"
    data = json.dumps(
        {
            "duration_ms": index.duration_ms,
            "timestamp_scale": index.timestamp_scale,
            "cue_points": index.cue_points,
            "segment_data_offset": index.segment_data_offset,
            "first_cluster_offset": index.first_cluster_offset,
            "seek_header_b64": base64.b64encode(index.seek_header).decode() if index.seek_header else "",
            "audio_codec_id": index.audio_codec_id,
            "audio_bitrate": index.audio_bitrate,
            "audio_channels": index.audio_channels,
            "audio_sample_rate": index.audio_sample_rate,
            "video_codec_id": index.video_codec_id,
            "video_codec_private_b64": base64.b64encode(index.video_codec_private).decode()
            if index.video_codec_private
            else "",
            "video_width": index.video_width,
            "video_height": index.video_height,
            "video_fps": index.video_fps,
            "video_default_duration_ns": index.video_default_duration_ns,
        }
    )
    await r.set(redis_key, data, ex=_CUE_INDEX_CACHE_TTL)
    logger.debug("[container_probe] Cached cue index: %s", cache_key)


async def probe_mkv_cues(
    source,
    file_size: int = 0,
    cache_key: str = "",
    header_data: bytes | None = None,
) -> MKVCueIndex | None:
    """
    Probe an MKV file's EBML header and Cues to build a seek index.

    Pure Python -- parses EBML structures directly, no FFmpeg involved.

    Makes up to two small byte-range reads via the provided source:
    1. First ~64KB: EBML header + SeekHead + Info (skipped if header_data provided)
    2. Cues section: byte range from SeekHead's Cues position

    Args:
        source: A MediaSource protocol implementation, or any object with
                a ``stream(offset, limit)`` async generator method.
        file_size: Total file size in bytes. If 0, tries ``source.file_size``.
        cache_key: Optional cache key for Redis caching. If empty, tries
                   ``source.cache_key``.
        header_data: Pre-fetched header bytes (first ~64KB). If provided,
                     skips the initial header fetch from source.

    Returns:
        MKVCueIndex if successful, None if the file has no Cues or parsing fails.
    """
    # Resolve file_size and cache_key from source if not provided
    if file_size <= 0:
        file_size = getattr(source, "file_size", 0)
    if not cache_key:
        cache_key = getattr(source, "cache_key", "")

    # Check cache first
    if cache_key:
        cached = await _get_cached_cue_index(cache_key)
        if cached:
            return cached

    try:
        # Step 1: Use pre-fetched header or fetch from source
        if header_data is None:
            header_size = min(_HEADER_PROBE_SIZE, file_size) if file_size > 0 else _HEADER_PROBE_SIZE
            header_data = b""
            async for chunk in source.stream(offset=0, limit=header_size):
                header_data += chunk

        if len(header_data) < 64:
            logger.warning("[container_probe] Header too small (%d bytes), cannot probe", len(header_data))
            return None

        # Step 2: Parse EBML header to find Segment data offset
        segment_data_offset = parse_ebml_header(header_data)

        # Step 3: Parse SeekHead to find Cues and Info positions
        seek_positions = parse_seek_head(header_data, segment_data_offset)

        if CUES not in seek_positions:
            logger.info("[container_probe] No Cues position in SeekHead, seeking not available")
            return None

        cues_relative_offset = seek_positions[CUES]
        cues_absolute_offset = segment_data_offset + cues_relative_offset

        logger.info(
            "[container_probe] SeekHead: Cues at offset %d (absolute %d), Info at %s",
            cues_relative_offset,
            cues_absolute_offset,
            seek_positions.get(INFO, "not found"),
        )

        # Step 4: Fetch the Cues element
        cues_max = file_size - cues_absolute_offset if file_size > 0 else _MAX_CUES_SIZE
        cues_fetch_size = min(_MAX_CUES_SIZE, cues_max)
        if cues_fetch_size <= 0:
            logger.warning("[container_probe] Cues offset %d beyond file size %d", cues_absolute_offset, file_size)
            return None

        cues_data = b""
        async for chunk in source.stream(offset=cues_absolute_offset, limit=cues_fetch_size):
            cues_data += chunk

        if len(cues_data) < 16:
            logger.warning("[container_probe] Cues data too small (%d bytes)", len(cues_data))
            return None

        # Step 5: Build the cue index
        index = build_cue_index(
            header_data=header_data,
            cues_data=cues_data,
            cues_file_offset=cues_absolute_offset,
            segment_data_offset=segment_data_offset,
        )

        # Cache the result
        if cache_key:
            await _set_cached_cue_index(cache_key, index)

        return index

    except Exception as e:
        logger.warning("[container_probe] Failed to probe MKV cues: %s", e)
        return None


# =============================================================================
# MP4 Moov probing
# =============================================================================

# Redis cache for MP4 indexes
_MP4_INDEX_CACHE_PREFIX = "mfp:mp4_index:"
_MP4_INDEX_CACHE_TTL = 3600  # 1 hour

# How much to read from the start for ftyp + initial atom scanning
_MP4_HEADER_PROBE_SIZE = 64 * 1024  # 64 KB

# Max moov size we'll accept
_MAX_MOOV_SIZE = 50 * 1024 * 1024  # 50 MB

# How much to read from the end of the file to find moov
_MP4_TAIL_PROBE_SIZE = 512 * 1024  # 512 KB


async def _get_cached_mp4_index(cache_key: str) -> MP4Index | None:
    """Try to load an MP4Index from Redis cache."""
    if not cache_key:
        return None
    r = await redis_utils.get_redis()
    if r is None:
        return None
    redis_key = f"{_MP4_INDEX_CACHE_PREFIX}{cache_key}"
    data = await r.get(redis_key)
    if not data:
        return None
    try:
        d = json.loads(data)
        ftyp_data = b""
        if d.get("ftyp_data_b64"):
            ftyp_data = base64.b64decode(d["ftyp_data_b64"])
        index = MP4Index(
            duration_ms=d["duration_ms"],
            timescale=d["timescale"],
            cue_points=[(cp[0], cp[1]) for cp in d["cue_points"]],
            moov_offset=d["moov_offset"],
            moov_size=d["moov_size"],
            ftyp_data=ftyp_data,
            mdat_offset=d["mdat_offset"],
            mdat_size=d["mdat_size"],
            video_codec=d.get("video_codec", ""),
            audio_codec=d.get("audio_codec", ""),
            # moov_data is NOT cached (too large), it will be re-fetched
        )
        logger.debug("[container_probe] Loaded MP4 index from cache: %s", cache_key)
        return index
    except (KeyError, TypeError, json.JSONDecodeError) as e:
        logger.warning("[container_probe] Invalid cached MP4 index: %s", e)
        return None


async def _set_cached_mp4_index(cache_key: str, index: MP4Index) -> None:
    """Cache an MP4Index in Redis (without moov_data)."""
    if not cache_key:
        return
    r = await redis_utils.get_redis()
    if r is None:
        return
    redis_key = f"{_MP4_INDEX_CACHE_PREFIX}{cache_key}"
    data = json.dumps(
        {
            "duration_ms": index.duration_ms,
            "timescale": index.timescale,
            "cue_points": index.cue_points,
            "moov_offset": index.moov_offset,
            "moov_size": index.moov_size,
            "ftyp_data_b64": base64.b64encode(index.ftyp_data).decode() if index.ftyp_data else "",
            "mdat_offset": index.mdat_offset,
            "mdat_size": index.mdat_size,
            "video_codec": index.video_codec,
            "audio_codec": index.audio_codec,
        }
    )
    await r.set(redis_key, data, ex=_MP4_INDEX_CACHE_TTL)
    logger.debug("[container_probe] Cached MP4 index: %s", cache_key)


def _scan_top_level_atoms(data: bytes) -> list[tuple[bytes, int, int]]:
    """
    Scan top-level atom headers from raw file bytes.

    Returns:
        List of (box_type, absolute_offset, total_size) for each atom found.
    """
    atoms = []
    offset = 0
    while offset + 8 <= len(data):
        size = struct.unpack_from(">I", data, offset)[0]
        box_type = data[offset + 4 : offset + 8]

        if size == 1:  # Extended size
            if offset + 16 > len(data):
                break
            size = struct.unpack_from(">Q", data, offset + 8)[0]
        elif size == 0:
            # Extends to end of file - we can't know the real size from
            # a partial read, but record what we have
            atoms.append((box_type, offset, 0))
            break

        if size < 8:
            break

        atoms.append((box_type, offset, size))
        offset += size

    return atoms


async def probe_mp4_moov(
    source,
    file_size: int = 0,
    cache_key: str = "",
    header_data: bytes | None = None,
) -> MP4Index | None:
    """
    Probe an MP4 file's moov atom to build a seek index.

    Pure Python -- scans MP4 box headers with struct, no FFmpeg involved.

    Strategy:
    1. Read first ~64KB to check for ftyp (MP4 signature).
    2. Scan top-level atoms to find moov and mdat.
    3. If moov is at the start (faststart), read it from the header data.
    4. If moov is not in the header, read from the tail of the file.
    5. Parse moov sample tables to build cue points.

    Args:
        source: A MediaSource protocol implementation with stream(offset, limit).
        file_size: Total file size in bytes.
        cache_key: Optional cache key for Redis caching.
        header_data: Pre-fetched header bytes (first ~64KB). If provided,
                     skips the initial header fetch from source.

    Returns:
        MP4Index if successful, None if not an MP4 or parsing fails.
    """
    if file_size <= 0:
        file_size = getattr(source, "file_size", 0)
    if not cache_key:
        cache_key = getattr(source, "cache_key", "")

    # Check cache first
    if cache_key:
        cached = await _get_cached_mp4_index(cache_key)
        if cached:
            # Re-fetch moov_data (not cached due to size) and rewrite offsets
            if cached.moov_size > 0 and cached.moov_size <= _MAX_MOOV_SIZE:
                moov_data = b""
                async for chunk in source.stream(offset=cached.moov_offset, limit=cached.moov_size):
                    moov_data += chunk
                if cached.mdat_offset >= 0:
                    new_mdat_start = len(cached.ftyp_data) + cached.moov_size
                    offset_delta = new_mdat_start - cached.mdat_offset
                    if offset_delta != 0:
                        moov_data = rewrite_moov_offsets(moov_data, offset_delta)
                cached.moov_data = moov_data
            return cached

    try:
        # Step 1: Use pre-fetched header or fetch from source
        if header_data is None:
            header_size = min(_MP4_HEADER_PROBE_SIZE, file_size) if file_size > 0 else _MP4_HEADER_PROBE_SIZE
            header_data = b""
            async for chunk in source.stream(offset=0, limit=header_size):
                header_data += chunk

        if len(header_data) < 12:
            return None

        # Step 2: Check for ftyp
        if not is_mp4_header(header_data):
            return None

        logger.info("[container_probe] MP4 detected, scanning atoms (header=%d bytes)", len(header_data))

        # Step 3: Scan top-level atoms from header
        atoms = _scan_top_level_atoms(header_data)

        ftyp_offset = -1
        ftyp_size = 0
        moov_offset = -1
        moov_size = 0
        mdat_offset = -1
        mdat_size = 0

        for box_type, atom_offset, atom_size in atoms:
            if box_type == b"ftyp":
                ftyp_offset = atom_offset
                ftyp_size = atom_size
            elif box_type == b"moov":
                moov_offset = atom_offset
                moov_size = atom_size
            elif box_type == b"mdat":
                mdat_offset = atom_offset
                mdat_size = atom_size

        # Step 4: If moov not found in header, scan from tail
        if moov_offset < 0 and file_size > 0:
            tail_start = max(0, file_size - _MP4_TAIL_PROBE_SIZE)
            tail_data = b""
            async for chunk in source.stream(offset=tail_start, limit=file_size - tail_start):
                tail_data += chunk

            if tail_data:
                tail_atoms = _scan_top_level_atoms(tail_data)
                for box_type, rel_offset, atom_size in tail_atoms:
                    abs_offset = tail_start + rel_offset
                    if box_type == b"moov":
                        moov_offset = abs_offset
                        moov_size = atom_size
                    elif box_type == b"mdat" and mdat_offset < 0:
                        mdat_offset = abs_offset
                        mdat_size = atom_size

                # If the initial scan yielded no moov (tail_start may land
                # inside a large mdat payload producing garbage atom headers),
                # resync by scanning 8-byte aligned windows for b"moov".
                if moov_offset < 0:
                    needle = b"moov"
                    search_pos = 0
                    while search_pos + 8 <= len(tail_data):
                        idx = tail_data.find(needle, search_pos)
                        if idx < 0 or idx < 4:
                            break
                        candidate_size = struct.unpack_from(">I", tail_data, idx - 4)[0]
                        if 8 < candidate_size <= _MAX_MOOV_SIZE:
                            moov_offset = tail_start + idx - 4
                            moov_size = candidate_size
                            break
                        search_pos = idx + 4

        if moov_offset < 0:
            logger.info("[container_probe] No moov atom found in MP4")
            return None

        if moov_size <= 0 or moov_size > _MAX_MOOV_SIZE:
            logger.warning("[container_probe] moov size %d is invalid or too large", moov_size)
            return None

        logger.info(
            "[container_probe] MP4 atoms: moov at %d (%d bytes), mdat at %d (%d bytes)",
            moov_offset,
            moov_size,
            mdat_offset,
            mdat_size,
        )

        # Step 5: Fetch full moov atom
        # Check if moov is already contained in the header data we read
        if moov_offset + moov_size <= len(header_data):
            moov_data = header_data[moov_offset : moov_offset + moov_size]
        else:
            moov_data = b""
            async for chunk in source.stream(offset=moov_offset, limit=moov_size):
                moov_data += chunk

        if len(moov_data) < moov_size:
            logger.warning(
                "[container_probe] Incomplete moov: got %d of %d bytes",
                len(moov_data),
                moov_size,
            )
            return None

        # Step 6: Parse moov body (skip box header)
        # Determine header size
        raw_size = struct.unpack_from(">I", moov_data, 0)[0]
        hdr_size = 16 if raw_size == 1 else 8
        moov_body = moov_data[hdr_size:]

        cue_points, duration_ms, timescale, video_codec, audio_codec = build_cue_points_from_moov(moov_body)

        # If mdat wasn't found via header scan, it's likely right after ftyp
        # or right after moov. Common layouts:
        # ftyp + moov + mdat (faststart) or ftyp + mdat + moov
        if mdat_offset < 0:
            # Walk atoms to find mdat by scanning just enough from the file
            # In most cases, mdat is either before or after moov
            if moov_offset < file_size // 2:
                # moov is early -> mdat likely follows
                mdat_search_offset = moov_offset + moov_size
            else:
                # moov is late -> mdat likely right after ftyp
                ftyp_size = struct.unpack_from(">I", header_data, 0)[0]
                if ftyp_size == 1:
                    ftyp_size = struct.unpack_from(">Q", header_data, 8)[0]
                mdat_search_offset = ftyp_size

            # Read a small amount to find the mdat header
            mdat_header = b""
            async for chunk in source.stream(offset=mdat_search_offset, limit=16):
                mdat_header += chunk
            if len(mdat_header) >= 8:
                box_type = mdat_header[4:8]
                if box_type == b"mdat":
                    mdat_offset = mdat_search_offset
                    raw_sz = struct.unpack_from(">I", mdat_header, 0)[0]
                    if raw_sz == 1 and len(mdat_header) >= 16:
                        mdat_size = struct.unpack_from(">Q", mdat_header, 8)[0]
                    else:
                        mdat_size = raw_sz

        # Step 7: Extract ftyp data (always in the header since it's the first atom)
        ftyp_data = b""
        if ftyp_offset >= 0 and ftyp_size > 0 and ftyp_offset + ftyp_size <= len(header_data):
            ftyp_data = header_data[ftyp_offset : ftyp_offset + ftyp_size]

        # Step 8: Rewrite moov chunk offsets for faststart pipe layout.
        # The pipe stream will be: ftyp + moov + mdat. The stco/co64
        # offsets in the original moov point to positions in the original
        # file. We need to shift them to account for the new layout.
        # New mdat position = ftyp_size + moov_size
        # Delta = new_mdat_position - original_mdat_offset
        if mdat_offset >= 0:
            new_mdat_start = len(ftyp_data) + moov_size
            offset_delta = new_mdat_start - mdat_offset
            if offset_delta != 0:
                moov_data = rewrite_moov_offsets(moov_data, offset_delta)

        index = MP4Index(
            duration_ms=duration_ms,
            timescale=timescale,
            cue_points=cue_points,
            moov_offset=moov_offset,
            moov_size=moov_size,
            moov_data=moov_data,
            ftyp_data=ftyp_data,
            mdat_offset=mdat_offset,
            mdat_size=mdat_size,
            video_codec=video_codec,
            audio_codec=audio_codec,
        )

        logger.info(
            "[container_probe] MP4 index: duration=%.1fs, %d cue points, video=%s, audio=%s",
            duration_ms / 1000.0,
            len(cue_points),
            video_codec,
            audio_codec,
        )

        if cache_key:
            await _set_cached_mp4_index(cache_key, index)

        return index

    except Exception as e:
        logger.warning("[container_probe] Failed to probe MP4 moov: %s", e)
        return None
