"""
Shared transcode request handler.

Source-agnostic orchestrator for on-the-fly fMP4 streaming with optional
seeking. Used by all proxy endpoints (Telegram, HTTP, Xtream, Acestream).

Provides two modes:

**Continuous streaming** (``handle_transcode``):
  Single-request fMP4 stream with optional ``start`` time. Simple but seeking
  requires the UI to issue a new request with a different ``start`` value.

**HLS VOD** (``handle_transcode_hls_*``):
  Three-endpoint workflow producing an M3U8 playlist, a shared init segment,
  and per-segment fMP4 fragments. Provides native seeking in all browsers and
  external players (VLC, mpv, Kodi) via standard HLS.

For non-MKV containers or when video re-encoding is needed, the universal
PyAV-based pipeline is used instead.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import TYPE_CHECKING

from fastapi import Request, Response
from starlette.responses import PlainTextResponse

import av
from fractions import Fraction

from mediaflow_proxy.remuxer.codec_utils import (
    ensure_avcc_extradata,
    extract_sps_pps_from_annexb,
    video_needs_reencode,
)
from mediaflow_proxy.remuxer.container_probe import (
    _get_cached_cue_index,
    _get_cached_mp4_index,
    probe_mkv_cues,
    probe_mp4_moov,
)
from mediaflow_proxy.remuxer.ebml_parser import CODEC_ID_H264, MKVTrack
from mediaflow_proxy.remuxer.hls_manifest import generate_vod_playlist, merge_cue_points
from mediaflow_proxy.remuxer.media_source import MediaSource, _MKV_EXTENSIONS, _MP4_EXTENSIONS
from mediaflow_proxy.remuxer.mp4_muxer import build_fmp4_init_segment
from mediaflow_proxy.remuxer.transcode_pipeline import (
    stream_segment_fmp4,
    stream_transcode_fmp4,
    stream_transcode_universal,
)
from mediaflow_proxy.utils.http_utils import EnhancedStreamingResponse
from mediaflow_proxy.utils.redis_utils import (
    hls_get_init,
    hls_get_segment,
    hls_set_init,
    hls_set_segment,
    hls_set_segment_meta,
    is_redis_configured,
)

if TYPE_CHECKING:
    from mediaflow_proxy.remuxer.ebml_parser import MKVCueIndex
    from mediaflow_proxy.remuxer.mp4_parser import MP4Index

logger = logging.getLogger(__name__)

# EBML magic bytes (MKV/WebM): 0x1A 0x45 0xDF 0xA3
_EBML_MAGIC = b"\x1a\x45\xdf\xa3"

# How much of the header to fetch for format detection + probing
_HEADER_PROBE_SIZE = 64 * 1024  # 64 KB

# Per-source probe lock to prevent thundering herd when multiple HLS
# sub-requests (init, segments) arrive concurrently before the cache
# is populated.  Keyed by cache_key.
_probe_locks: dict[str, asyncio.Lock] = {}
_probe_locks_lock = asyncio.Lock()  # protects the dict itself
_MAX_PROBE_LOCKS = 256


async def _get_probe_lock(cache_key: str) -> asyncio.Lock:
    """Return (or create) an asyncio.Lock for a given source cache key."""
    async with _probe_locks_lock:
        lock = _probe_locks.get(cache_key)
        if lock is None:
            # Evict idle locks when the dict grows too large.
            if len(_probe_locks) >= _MAX_PROBE_LOCKS:
                to_remove = [k for k, v in _probe_locks.items() if not v.locked()]
                for k in to_remove[: len(to_remove) // 2 or 1]:
                    del _probe_locks[k]
            lock = asyncio.Lock()
            _probe_locks[cache_key] = lock
        return lock


# ---------------------------------------------------------------------------
# Shared probe result
# ---------------------------------------------------------------------------


@dataclass
class _ProbeResult:
    """Intermediate result from ``_probe_source``."""

    cue_index: MKVCueIndex | None = None
    mp4_index: MP4Index | None = None
    needs_video_transcode: bool = False
    duration_ms: float = 0.0


async def _probe_source(source: MediaSource) -> _ProbeResult:
    """
    Probe a ``MediaSource`` to detect its format and extract the seek index.

    Uses a **cache-first** strategy: if a cached cue/MP4 index exists in Redis
    for this source's ``cache_key``, it is returned immediately without opening
    any connection to the source.  This is critical for HLS, where the playlist,
    init segment, and every media segment all call ``_probe_source`` -- without
    caching, each request would open a new upstream connection.

    When the cache is cold, a per-source asyncio lock prevents multiple
    concurrent requests from probing the same source simultaneously (the
    "thundering herd" problem that causes Telegram flood/auth errors).

    Returns a ``_ProbeResult`` containing the MKV cue index or MP4 index
    (at most one), plus pipeline-selection metadata.
    """
    file_size = source.file_size
    cache_key = source.cache_key

    # ── Fast path: check Redis cache before touching the source ──────
    if cache_key:
        cached_cue = await _get_cached_cue_index(cache_key)
        if cached_cue:
            logger.debug("[transcode_handler] Cache hit (MKV cue index) for %s", cache_key)
            return _build_probe_result(cue_index=cached_cue)

        cached_mp4 = await _get_cached_mp4_index(cache_key)
        if cached_mp4:
            logger.debug("[transcode_handler] Cache hit (MP4 index) for %s", cache_key)
            return _build_probe_result(mp4_index=cached_mp4)

    # ── Slow path: serialise concurrent probes per source ────────────
    if cache_key:
        lock = await _get_probe_lock(cache_key)
        async with lock:
            # Double-check cache inside the lock (another request may have
            # populated it while we were waiting).
            cached_cue = await _get_cached_cue_index(cache_key)
            if cached_cue:
                logger.debug("[transcode_handler] Cache hit after lock (MKV) for %s", cache_key)
                return _build_probe_result(cue_index=cached_cue)
            cached_mp4 = await _get_cached_mp4_index(cache_key)
            if cached_mp4:
                logger.debug("[transcode_handler] Cache hit after lock (MP4) for %s", cache_key)
                return _build_probe_result(mp4_index=cached_mp4)

            return await _do_probe(source, file_size, cache_key)
    else:
        # No cache key -- just probe directly (no lock needed).
        return await _do_probe(source, file_size, cache_key)


async def _do_probe(source: MediaSource, file_size: int, cache_key: str) -> _ProbeResult:
    """Actually probe the source (fetch header, detect format, build index)."""
    hint = getattr(source, "filename_hint", "") or ""
    hint_is_mkv = hint in _MKV_EXTENSIONS
    hint_is_mp4 = hint in _MP4_EXTENSIONS

    header_size = min(_HEADER_PROBE_SIZE, file_size) if file_size > 0 else _HEADER_PROBE_SIZE
    header_data = b""
    async for chunk in source.stream(offset=0, limit=header_size):
        header_data += chunk

    magic_is_mkv = len(header_data) >= 4 and header_data[:4] == _EBML_MAGIC
    magic_is_mp4 = len(header_data) >= 8 and header_data[4:8] == b"ftyp"

    if hint_is_mkv or (magic_is_mkv and not hint_is_mp4):
        probe_order = "mkv_first"
    elif hint_is_mp4 or (magic_is_mp4 and not hint_is_mkv):
        probe_order = "mp4_first"
    elif magic_is_mkv:
        probe_order = "mkv_first"
    elif magic_is_mp4:
        probe_order = "mp4_first"
    else:
        probe_order = "mkv_first"

    logger.info(
        "[transcode_handler] Format detection: hint=%r, magic_mkv=%s, magic_mp4=%s, order=%s",
        hint,
        magic_is_mkv,
        magic_is_mp4,
        probe_order,
    )

    cue_index = None
    mp4_index = None

    if probe_order == "mkv_first":
        cue_index = await probe_mkv_cues(
            source,
            file_size=file_size,
            cache_key=cache_key,
            header_data=header_data,
        )
        if cue_index is None and not magic_is_mkv:
            mp4_index = await probe_mp4_moov(
                source,
                file_size=file_size,
                cache_key=cache_key,
                header_data=header_data,
            )
    else:
        mp4_index = await probe_mp4_moov(
            source,
            file_size=file_size,
            cache_key=cache_key,
            header_data=header_data,
        )
        if mp4_index is None and not magic_is_mp4:
            cue_index = await probe_mkv_cues(
                source,
                file_size=file_size,
                cache_key=cache_key,
                header_data=header_data,
            )

    return _build_probe_result(cue_index=cue_index, mp4_index=mp4_index)


def _build_probe_result(
    *,
    cue_index: MKVCueIndex | None = None,
    mp4_index: MP4Index | None = None,
) -> _ProbeResult:
    """Build a ``_ProbeResult`` from the given index(es)."""
    needs_video_transcode = False
    duration_ms = 0.0

    if cue_index:
        duration_ms = cue_index.duration_ms
        video_codec = getattr(cue_index, "video_codec_id", "") or ""
        if video_codec:
            needs_video_transcode = video_needs_reencode(video_codec)
        else:
            needs_video_transcode = True
    elif mp4_index:
        duration_ms = mp4_index.duration_ms
        needs_video_transcode = True  # MP4 always uses universal pipeline

    return _ProbeResult(
        cue_index=cue_index,
        mp4_index=mp4_index,
        needs_video_transcode=needs_video_transcode,
        duration_ms=duration_ms,
    )


# ---------------------------------------------------------------------------
# Continuous fMP4 streaming (original handler)
# ---------------------------------------------------------------------------


async def handle_transcode(
    request: Request,
    source: MediaSource,
    start_time: float | None = None,
) -> Response:
    """
    Handle a transcode request for any MediaSource.

    Probes the file's seek index (MKV Cues or MP4 moov), optionally seeks,
    then streams fMP4 via the appropriate transcode pipeline.

    Args:
        request: The incoming HTTP request (for method detection).
        source: A MediaSource providing byte-range streaming.
        start_time: Optional seek time in seconds.

    Returns:
        An EnhancedStreamingResponse streaming fMP4 content, or a
        Response with headers only for HEAD requests.
    """
    file_size = source.file_size

    probe = await _probe_source(source)
    cue_index = probe.cue_index
    mp4_index = probe.mp4_index

    # ── Phase 2: Determine pipeline parameters ───────────────────────

    stream_offset = 0
    seek_header = b""
    duration_seconds = None
    estimated_size = None
    needs_video_transcode = False
    is_mp4 = mp4_index is not None

    if cue_index:
        # MKV path
        duration_seconds = cue_index.duration_ms / 1000.0
        estimated_size = cue_index.estimate_fmp4_size(file_size)

        video_codec = getattr(cue_index, "video_codec_id", "") or ""

        logger.info(
            "[transcode_handler] MKV Cues: duration=%.1fs, %d cue points, "
            "audio=%s @%dkbps, video=%s, estimated_fmp4=%s",
            duration_seconds,
            len(cue_index.cue_points),
            cue_index.audio_codec_id or "unknown",
            cue_index.audio_bitrate // 1000 if cue_index.audio_bitrate else 0,
            video_codec or "unknown",
            f"{estimated_size:,}" if estimated_size else "unknown",
        )

        # Check if video needs re-encoding.
        # If the video codec is unknown (empty), treat it as needing re-encoding
        # because the MKV fast-path only supports H.264/H.265 passthrough.
        if video_codec:
            needs_video_transcode = video_needs_reencode(video_codec)
        else:
            needs_video_transcode = True

        # Time-based seeking via the `start` query parameter.
        if start_time is not None and start_time > 0:
            target_ms = start_time * 1000.0
            absolute_offset, keyframe_time_ms = cue_index.byte_offset_for_time(target_ms)
            stream_offset = absolute_offset

            if stream_offset > 0 and cue_index.seek_header:
                seek_header = cue_index.seek_header

            logger.info(
                "[transcode_handler] Seeking to %.1fs: keyframe at %.1fs (offset %d), seek_header=%d bytes",
                start_time,
                keyframe_time_ms / 1000.0,
                absolute_offset,
                len(seek_header),
            )

    elif mp4_index:
        # MP4 path
        duration_seconds = mp4_index.duration_ms / 1000.0
        # Video always needs transcoding through universal pipeline for MP4
        needs_video_transcode = True

        logger.info(
            "[transcode_handler] MP4 index: duration=%.1fs, %d cue points, "
            "video=%s, audio=%s, moov=%d bytes, mdat_offset=%d",
            duration_seconds,
            len(mp4_index.cue_points),
            mp4_index.video_codec or "unknown",
            mp4_index.audio_codec or "unknown",
            len(mp4_index.moov_data),
            mp4_index.mdat_offset,
        )

        # Time-based seeking for MP4
        if start_time is not None and start_time > 0:
            target_ms = start_time * 1000.0
            byte_offset, keyframe_time_ms = mp4_index.byte_offset_for_time(target_ms)
            if byte_offset > 0:
                stream_offset = byte_offset
                logger.info(
                    "[transcode_handler] MP4 seeking to %.1fs: keyframe at %.1fs (offset %d)",
                    start_time,
                    keyframe_time_ms / 1000.0,
                    byte_offset,
                )
    else:
        logger.info("[transcode_handler] No MKV Cues or MP4 moov, streaming from beginning")

    stream_limit = max(0, file_size - stream_offset) if file_size > 0 else None

    # ── Phase 3: HEAD request ─────────────────────────────────────────

    if request.method == "HEAD":
        head_headers = {
            "access-control-allow-origin": "*",
            "cache-control": "no-cache, no-store",
            "content-type": "video/mp4",
            "content-disposition": "inline",
        }
        if duration_seconds is not None:
            head_headers["x-content-duration"] = f"{duration_seconds:.3f}"
        if estimated_size:
            head_headers["content-length"] = str(estimated_size)
        return Response(status_code=200, headers=head_headers)

    # ── Phase 4: Build source generator ──────────────────────────────

    if is_mp4 and mp4_index and mp4_index.moov_data:
        # MP4 on-the-fly: prepend ftyp + moov bytes, then stream mdat from offset.
        # This gives PyAV a "faststart"-style MP4 through the pipe.
        async def media_source_gen() -> AsyncIterator[bytes]:
            """Yield bytes: ftyp + moov_data + mdat bytes from offset."""
            try:
                if mp4_index.ftyp_data:
                    logger.info(
                        "[transcode_handler] Prepending %d-byte ftyp",
                        len(mp4_index.ftyp_data),
                    )
                    yield mp4_index.ftyp_data

                logger.info(
                    "[transcode_handler] Prepending %d-byte moov for faststart pipe",
                    len(mp4_index.moov_data),
                )
                yield mp4_index.moov_data

                # Determine where to start streaming mdat content.
                # If seeking, stream_offset is within the mdat data area.
                # If not seeking, start from mdat atom beginning.
                if stream_offset > 0:
                    data_offset = stream_offset
                elif mp4_index.mdat_offset > 0:
                    data_offset = mp4_index.mdat_offset
                else:
                    # Fallback: stream from after moov
                    data_offset = mp4_index.moov_offset + mp4_index.moov_size

                data_limit = file_size - data_offset if file_size > 0 else None

                logger.info(
                    "[transcode_handler] Streaming mdat from offset=%d, limit=%s",
                    data_offset,
                    data_limit,
                )

                async for chunk in source.stream(offset=data_offset, limit=data_limit):
                    yield chunk
            except asyncio.CancelledError:
                logger.debug("[transcode_handler] MP4 source cancelled by client")
            except GeneratorExit:
                logger.debug("[transcode_handler] MP4 source generator closed")
    else:
        # MKV / TS / WebM / unknown: standard streaming
        async def media_source_gen() -> AsyncIterator[bytes]:
            """Yield bytes: [seek_header] + [data from offset]."""
            try:
                if seek_header:
                    logger.info(
                        "[transcode_handler] Prepending %d-byte synthetic MKV header",
                        len(seek_header),
                    )
                    yield seek_header

                async for chunk in source.stream(offset=stream_offset, limit=stream_limit):
                    yield chunk
            except asyncio.CancelledError:
                logger.debug("[transcode_handler] Source cancelled by client")
            except GeneratorExit:
                logger.debug("[transcode_handler] Source generator closed")

    # ── Phase 5: Choose pipeline ─────────────────────────────────────

    # - MKV fast-path (EBML demux, video copy): only when we have valid MKV cues
    #   AND video doesn't need re-encoding.
    # - Universal PyAV path: for non-MKV containers (MP4/TS/WebM), or when
    #   video re-encoding is required (any codec not natively browser-compatible).
    use_mkv_fast_path = cue_index is not None and not needs_video_transcode
    pipeline_name = "MKV fast-path" if use_mkv_fast_path else "universal PyAV"

    logger.info(
        "[transcode_handler] Starting %s pipeline (offset=%d, limit=%s, seek_header=%d, video_reencode=%s, mp4=%s)",
        pipeline_name,
        stream_offset,
        stream_limit,
        len(seek_header),
        needs_video_transcode,
        is_mp4,
    )

    if use_mkv_fast_path:
        content = stream_transcode_fmp4(media_source_gen())
    else:
        content = stream_transcode_universal(media_source_gen())

    response_headers = {
        "access-control-allow-origin": "*",
        "cache-control": "no-cache, no-store",
        "content-disposition": "inline",
    }
    if duration_seconds is not None:
        response_headers["x-content-duration"] = f"{duration_seconds:.3f}"

    return EnhancedStreamingResponse(
        content=content,
        media_type="video/mp4",
        headers=response_headers,
    )


# ---------------------------------------------------------------------------
# HLS VOD helpers
# ---------------------------------------------------------------------------


@dataclass
class HLSSegmentInfo:
    """Metadata for a single HLS segment, including byte-range offsets."""

    index: int
    start_ms: float
    end_ms: float
    byte_offset: int  # absolute file offset where this segment's data starts
    byte_end: int  # absolute file offset where this segment's data ends


def _compute_segment_boundaries(
    cue_points: list[tuple[float, int]],
    duration_ms: float,
    file_size: int,
    segment_data_offset: int = 0,
    target_segment_duration_ms: float = 5000.0,
) -> list[HLSSegmentInfo]:
    """
    Compute HLS segment boundaries with byte-range offsets from cue points.

    Uses the same ``merge_cue_points`` logic as the playlist generator so
    that segment indices match between the M3U8 and the session buffer.

    **Audio overlap**: In MKV files audio and video are interleaved in
    clusters.  Cue points mark clusters that contain a video keyframe,
    but audio samples near the end of a segment's time range may reside
    in the cluster that *starts* the next segment.  To ensure the audio
    transcoder receives all source samples for the segment duration, each
    segment's ``byte_end`` is extended one raw cue-point past the next
    merged boundary.  The pipeline's frame-count limits prevent any extra
    audio/video frames from leaking into the output.

    Args:
        cue_points: Sorted ``(time_ms, byte_offset)`` list. For MKV the
            byte_offset is relative to the Segment data start; for MP4
            it is an absolute file offset.
        duration_ms: Total media duration in milliseconds.
        file_size: Total file size in bytes, used to cap the last segment.
        segment_data_offset: For MKV, the ``segment_data_offset`` from
            ``MKVCueIndex`` that converts relative cue offsets to absolute
            file offsets.  Pass 0 for MP4 (offsets are already absolute).
        target_segment_duration_ms: Minimum segment duration.

    Returns:
        List of ``HLSSegmentInfo`` -- one per HLS segment.
    """
    from bisect import bisect_right

    merged = merge_cue_points(cue_points, target_segment_duration_ms)

    # Pre-extract sorted byte offsets from raw cue_points for bisect lookup.
    # These are the byte offsets of *every* keyframe cluster in the file,
    # not just the merged segment boundaries.
    raw_offsets = sorted({off for _, off in cue_points})

    segments: list[HLSSegmentInfo] = []
    for i in range(len(merged)):
        start_ms = merged[i][0]
        end_ms = merged[i + 1][0] if i + 1 < len(merged) else duration_ms
        byte_offset = merged[i][1] + segment_data_offset

        if i + 1 < len(merged):
            next_boundary = merged[i + 1][1]  # relative offset
            # Extend byte_end one raw cue-point past the next merged
            # boundary so that trailing interleaved audio is captured.
            idx = bisect_right(raw_offsets, next_boundary)
            if idx < len(raw_offsets):
                byte_end = raw_offsets[idx] + segment_data_offset
            else:
                byte_end = file_size
        else:
            byte_end = file_size

        segments.append(
            HLSSegmentInfo(
                index=i,
                start_ms=start_ms,
                end_ms=end_ms,
                byte_offset=byte_offset,
                byte_end=byte_end,
            )
        )
    return segments


def _find_segment(
    segments: list[HLSSegmentInfo],
    start_time_ms: float,
) -> HLSSegmentInfo | None:
    """Find the segment whose start_ms matches *start_time_ms* (within 1ms tolerance)."""
    for seg in segments:
        if abs(seg.start_ms - start_time_ms) < 1.0:
            return seg
    return None


# ---------------------------------------------------------------------------
# HLS per-segment source builder
# ---------------------------------------------------------------------------


async def _build_segment_source(
    source: MediaSource,
    seg: HLSSegmentInfo,
    probe: _ProbeResult,
) -> AsyncIterator[bytes]:
    """
    Build an async byte iterator that gives PyAV a parseable container
    starting at the segment's byte offset.

    For MKV: yields ``seek_header`` (synthetic EBML + Segment + Info + Tracks)
    followed by raw bytes from ``byte_offset`` to ``byte_end``. This lets
    PyAV open a valid MKV stream from the middle of the file.

    For MP4: yields ``ftyp + moov`` bytes followed by mdat data from
    ``byte_offset`` to ``byte_end``.
    """
    byte_length = seg.byte_end - seg.byte_offset

    if probe.mp4_index and probe.mp4_index.moov_data:
        # ---- MP4: prepend ftyp + moov ----
        mp4 = probe.mp4_index
        if mp4.ftyp_data:
            yield mp4.ftyp_data
        yield mp4.moov_data
        async for chunk in source.stream(offset=seg.byte_offset, limit=byte_length):
            yield chunk
    elif probe.cue_index:
        if not probe.cue_index.seek_header:
            logger.error(
                "[build_segment_source] MKV cue_index present but seek_header is empty; "
                "cannot build a valid segment source for offset %d",
                seg.byte_offset,
            )
            return
        yield probe.cue_index.seek_header
        async for chunk in source.stream(offset=seg.byte_offset, limit=byte_length):
            yield chunk
    else:
        # ---- Fallback: stream raw bytes (TS, WebM without cues) ----
        async for chunk in source.stream(offset=seg.byte_offset, limit=byte_length):
            yield chunk


# ---------------------------------------------------------------------------
# HLS VOD handlers
# ---------------------------------------------------------------------------


async def _extract_probe_data(
    source: MediaSource,
) -> (
    tuple[
        _ProbeResult,
        list[tuple[float, int]],
        float,
        int,
        int,
    ]
    | None
):
    """
    Probe the source and extract cue points, duration, file_size, and
    the MKV segment_data_offset (0 for MP4).

    Returns ``(probe, cue_points, duration_ms, file_size, seg_data_offset)``
    or ``None`` if the source cannot be probed.
    """
    probe = await _probe_source(source)
    cue_points: list[tuple[float, int]] = []
    seg_data_offset = 0

    if probe.cue_index:
        cue_points = probe.cue_index.cue_points
        seg_data_offset = probe.cue_index.segment_data_offset
    elif probe.mp4_index:
        cue_points = probe.mp4_index.cue_points

    duration_ms = probe.duration_ms
    file_size = source.file_size

    if not cue_points or duration_ms <= 0 or file_size <= 0:
        return None

    return probe, cue_points, duration_ms, file_size, seg_data_offset


async def handle_transcode_hls_playlist(
    request: Request,
    source: MediaSource,
    init_url: str,
    segment_url_template: str,
) -> Response:
    """
    Generate an HLS VOD M3U8 playlist for on-the-fly fMP4 transcoding.

    Probes the source file to extract its keyframe index, then builds an
    ``#EXT-X-VERSION:7`` playlist.  Consecutive keyframes closer together
    than the target segment duration (5 s) are merged into a single HLS
    segment, matching ``ffmpeg -hls_time`` behaviour.

    Segment URLs use ``{start_ms}`` and ``{end_ms}`` placeholders that are
    filled with each segment's time-range in milliseconds.
    """
    result = await _extract_probe_data(source)
    if result is None:
        return PlainTextResponse(
            "Cannot generate HLS playlist: no keyframe index found",
            status_code=404,
        )
    _probe, cue_points, duration_ms, _file_size, _seg_data_offset = result

    merged = merge_cue_points(cue_points)

    playlist = generate_vod_playlist(
        cue_points=cue_points,
        duration_ms=duration_ms,
        init_url=init_url,
        segment_url_template=segment_url_template,
    )

    logger.info(
        "[hls] Playlist generated: %d segments (merged from %d cue points), duration=%.1fs",
        len(merged),
        len(cue_points),
        duration_ms / 1000.0,
    )

    return PlainTextResponse(
        content=playlist,
        media_type="application/vnd.apple.mpegurl",
        headers={
            "access-control-allow-origin": "*",
            "cache-control": "public, max-age=300",
        },
    )


def _generate_init_segment(
    width: int,
    height: int,
    fps: float,
    duration_ms: float,
    *,
    source_video_codec_private: bytes = b"",
    source_default_duration_ns: int = 0,
) -> bytes:
    """
    Generate an fMP4 init segment (ftyp + moov).

    When ``source_video_codec_private`` is provided (e.g. avcC extradata
    from an MKV source), it is used directly for the video track's
    codec_private, skipping the expensive blank-frame encode entirely.
    This is the fast path for MKV sources with H.264 video passthrough.

    When no source extradata is available, falls back to creating a
    temporary libx264 encoder and encoding a single blank frame to obtain
    the SPS/PPS extradata.
    """
    # Ensure even dimensions (H.264 requirement)
    enc_width = width if width % 2 == 0 else width + 1
    enc_height = height if height % 2 == 0 else height + 1

    if source_video_codec_private:
        # ---- Fast path: use source avcC directly ----
        video_codec_private = ensure_avcc_extradata(source_video_codec_private)
        if not video_codec_private:
            raise RuntimeError("Source video_codec_private is invalid (not avcC)")
        logger.info(
            "[hls_init] Using source avcC extradata: %d bytes",
            len(video_codec_private),
        )
    else:
        # ---- Fallback: blank-frame encode to extract SPS/PPS ----
        from mediaflow_proxy.configs import settings

        encoder = av.CodecContext.create("libx264", "w")
        encoder.width = enc_width
        encoder.height = enc_height
        encoder.pix_fmt = "yuv420p"
        encoder.time_base = Fraction(1, int(fps * 1000))
        encoder.framerate = Fraction(int(fps * 1000), 1000)
        encoder.bit_rate = 4_000_000
        encoder.gop_size = int(fps * 2)
        encoder.options = {
            "preset": settings.transcode_video_preset,
            "tune": "zerolatency",
            "profile": "high",
        }
        encoder.open()

        blank = av.VideoFrame(enc_width, enc_height, "yuv420p")
        blank.pts = 0
        first_packet_data = b""
        for pkt in encoder.encode(blank):
            first_packet_data = bytes(pkt)
            break
        for _ in encoder.encode(None):
            pass

        extradata = bytes(encoder.extradata) if encoder.extradata else b""
        if extradata:
            video_codec_private = ensure_avcc_extradata(extradata)
        elif first_packet_data:
            video_codec_private = extract_sps_pps_from_annexb(first_packet_data)
        else:
            video_codec_private = b""

        del encoder

        if not video_codec_private:
            raise RuntimeError("libx264 encoder produced no SPS/PPS extradata")

    frame_dur_ns = source_default_duration_ns if source_default_duration_ns > 0 else int(1_000_000_000 / fps)

    video_track = MKVTrack(
        track_number=1,
        track_type=1,  # video
        codec_id=CODEC_ID_H264,
        codec_private=video_codec_private,
        pixel_width=enc_width,
        pixel_height=enc_height,
        default_duration_ns=frame_dur_ns,
    )

    default_asc = bytes([0x11, 0x90])  # 48kHz stereo AAC-LC

    init_data = build_fmp4_init_segment(
        video_track=video_track,
        audio_sample_rate=48000,
        audio_channels=2,
        audio_specific_config=default_asc,
        video_timescale=90000,
        audio_timescale=48000,
        duration_ms=duration_ms if 0 < duration_ms < 86400_000 else 0.0,
    )

    logger.info(
        "[hls_init] Built init segment: %dx%d @%.1ffps, extradata=%d bytes, init=%d bytes",
        enc_width,
        enc_height,
        fps,
        len(video_codec_private),
        len(init_data),
    )
    return init_data


async def handle_transcode_hls_init(
    request: Request,
    source: MediaSource,
) -> Response:
    """
    Serve the fMP4 init segment (ftyp + moov) for an HLS transcode stream.

    **Per-segment architecture**:
    1. Check Redis for an already-cached init segment (fast path).
    2. If miss: discover the source's video dimensions by opening the first
       few bytes with PyAV, then build the init segment locally (no full
       transcode pipeline needed -- just a single blank-frame encode to
       obtain the H.264 SPS/PPS from libx264).
    3. Cache the init segment in Redis (long TTL) and return it.

    No persistent session or pipeline lock is needed.
    """
    cache_key = source.cache_key

    # ---- Redis fast path: init segment already cached ----
    if is_redis_configured():
        cached = await hls_get_init(cache_key)
        if cached is not None:
            logger.info("[hls_init] Redis cache hit: %d bytes", len(cached))
            return Response(
                content=cached,
                media_type="video/mp4",
                headers={
                    "access-control-allow-origin": "*",
                    "cache-control": "public, max-age=3600",
                    "content-length": str(len(cached)),
                },
            )

    # ---- Probe the source to get video dimensions ----
    result = await _extract_probe_data(source)
    if result is None:
        return PlainTextResponse(
            "Cannot serve init segment: no keyframe index found",
            status_code=404,
        )
    probe, cue_points, duration_ms, file_size, seg_data_offset = result

    # Discover video dimensions from the cached probe data.
    width, height, fps = 0, 0, 24.0

    if probe.cue_index:
        width = probe.cue_index.video_width
        height = probe.cue_index.video_height
        fps = probe.cue_index.video_fps or 24.0
    elif probe.mp4_index and probe.mp4_index.moov_data:
        # For MP4, extract dimensions from the moov atom
        from mediaflow_proxy.remuxer.mp4_parser import extract_video_track_from_moov

        vtrack = extract_video_track_from_moov(probe.mp4_index.moov_data)
        if vtrack:
            width = vtrack.pixel_width
            height = vtrack.pixel_height
            if vtrack.default_duration_ns > 0:
                fps = 1_000_000_000.0 / vtrack.default_duration_ns

    if width <= 0 or height <= 0:
        return PlainTextResponse(
            "Cannot determine video dimensions from probe data",
            status_code=503,
        )

    # Build the init segment from the discovered metadata.
    # For MKV sources with H.264, use the source avcC directly (fast path)
    # to match the video passthrough in stream_segment_fmp4.
    source_video_codec_private = b""
    source_default_duration_ns = 0
    if probe.cue_index and probe.cue_index.video_codec_private:
        if not video_needs_reencode(probe.cue_index.video_codec_id):
            source_video_codec_private = probe.cue_index.video_codec_private
            source_default_duration_ns = probe.cue_index.video_default_duration_ns

    try:
        init_data = _generate_init_segment(
            width,
            height,
            fps,
            duration_ms,
            source_video_codec_private=source_video_codec_private,
            source_default_duration_ns=source_default_duration_ns,
        )
    except Exception:
        logger.exception("[hls_init] Failed to generate init segment")
        return PlainTextResponse(
            "Init segment generation failed",
            status_code=503,
        )

    # Cache in Redis for other workers / future requests
    if is_redis_configured():
        await hls_set_init(cache_key, init_data)

    return Response(
        content=init_data,
        media_type="video/mp4",
        headers={
            "access-control-allow-origin": "*",
            "cache-control": "public, max-age=3600",
            "content-length": str(len(init_data)),
        },
    )


async def handle_transcode_hls_segment(
    request: Request,
    source: MediaSource,
    start_time_ms: float,
    end_time_ms: float,
    segment_number: int | None = None,
) -> Response:
    """
    Serve a single HLS fMP4 media segment (moof + mdat).

    **Per-segment architecture**:
    1. Compute segment boundaries and resolve the target segment.
    2. Check Redis for cached segment bytes (short TTL, fast path).
    3. If miss:
       a. Build a source generator from the segment's byte range.
       b. For MKV sources with H.264 video: use ``stream_segment_fmp4``
          (MKV fast-path with video passthrough and audio transcoding).
       c. For other sources or codecs needing re-encode: fall back to
          ``stream_transcode_universal`` (PyAV-based, full re-encode).
       d. Cache the segment bytes (short TTL) and output metadata (long TTL).
    4. Return the segment.

    Each segment is independently transcoded -- no persistent pipeline,
    no cross-worker locks, no sequential dependencies.
    """
    cache_key = source.cache_key
    seg_label = f"seg={segment_number}" if segment_number is not None else f"time={int(start_time_ms)}"

    # ---- Probe to get boundaries ----
    result = await _extract_probe_data(source)
    if result is None:
        return PlainTextResponse(
            "Cannot serve segment: no keyframe index found",
            status_code=404,
        )
    probe, cue_points, duration_ms, file_size, seg_data_offset = result

    boundaries = _compute_segment_boundaries(
        cue_points,
        duration_ms,
        file_size,
        seg_data_offset,
    )

    seg_info = _find_segment(boundaries, start_time_ms)
    if seg_info is None:
        return PlainTextResponse(
            f"start_ms={int(start_time_ms)} does not match any segment boundary",
            status_code=404,
        )

    seg_idx = seg_info.index

    # ---- Redis fast path: segment bytes already cached ----
    if is_redis_configured():
        cached = await hls_get_segment(cache_key, seg_idx)
        if cached is not None:
            logger.info("[hls_segment] %s Redis cache hit: %d bytes", seg_label, len(cached))
            return Response(
                content=cached,
                media_type="video/mp4",
                headers={
                    "access-control-allow-origin": "*",
                    "cache-control": "public, max-age=300",
                    "content-length": str(len(cached)),
                },
            )

    # ---- Per-segment transcode ----
    seg_duration_ms = seg_info.end_ms - seg_info.start_ms
    logger.info(
        "[hls_segment] %s transcoding: time=%.1f-%.1fs (dur=%.0fms), bytes=%d-%d (%d bytes)",
        seg_label,
        seg_info.start_ms / 1000.0,
        seg_info.end_ms / 1000.0,
        seg_duration_ms,
        seg_info.byte_offset,
        seg_info.byte_end,
        seg_info.byte_end - seg_info.byte_offset,
    )

    # Build the source generator for this segment's byte range
    source_gen = _build_segment_source(source, seg_info, probe)

    # Choose pipeline: MKV fast-path (video passthrough) for MKV sources
    # with H.264 video, universal PyAV pipeline as fallback for everything else.
    use_mkv_fastpath = (
        probe.cue_index is not None
        and probe.cue_index.video_codec_id
        and not video_needs_reencode(probe.cue_index.video_codec_id)
    )

    seg_chunks: list[bytes] = []
    try:
        if use_mkv_fastpath:
            logger.info(
                "[hls_segment] %s using MKV fast-path (video=%s passthrough)",
                seg_label,
                probe.cue_index.video_codec_id,
            )
            async for chunk in stream_segment_fmp4(
                source_gen,
                start_decode_time_ms=seg_info.start_ms,
                max_duration_ms=seg_duration_ms,
            ):
                seg_chunks.append(chunk)
        else:
            logger.info("[hls_segment] %s using universal PyAV pipeline", seg_label)
            async for chunk in stream_transcode_universal(
                source_gen,
                force_video_reencode=True,
                max_duration_ms=seg_duration_ms,
                start_decode_time_ms=seg_info.start_ms,
                emit_init_segment=False,
                force_software_encode=True,
            ):
                seg_chunks.append(chunk)
    except Exception:
        logger.exception("[hls_segment] %s pipeline error", seg_label)
        return PlainTextResponse(
            f"Segment {seg_idx} transcode failed",
            status_code=503,
        )

    if not seg_chunks:
        return PlainTextResponse(
            f"Segment {seg_idx} produced no output",
            status_code=503,
        )

    seg_data = b"".join(seg_chunks)

    # ---- Cache segment bytes (short TTL) and metadata (long TTL) ----
    if is_redis_configured():
        await hls_set_segment(cache_key, seg_idx, seg_data)

        # Store output metadata for the next segment's continuity.
        # The key fields are the segment end time and sequence info so
        # the next segment can set its start_decode_time_ms correctly.
        await hls_set_segment_meta(
            cache_key,
            seg_idx,
            {
                "end_ms": seg_info.end_ms,
                "seg_index": seg_idx,
            },
        )

    logger.info("[hls_segment] %s served: %d bytes", seg_label, len(seg_data))

    return Response(
        content=seg_data,
        media_type="video/mp4",
        headers={
            "access-control-allow-origin": "*",
            "cache-control": "public, max-age=300",
            "content-length": str(len(seg_data)),
        },
    )
