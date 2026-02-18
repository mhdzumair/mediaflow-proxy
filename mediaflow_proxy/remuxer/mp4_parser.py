"""
MP4 container parser for moov atom probing.

Provides:
- MP4Index: seek index extracted from MP4 moov atom (parallel to MKVCueIndex)
- Top-level atom scanning
- Sample table parsers (stco, co64, stss, stsz, stts, stsc)
- Moov-to-cue-point builder
- rewrite_moov_offsets: adjust stco/co64 in moov for file rearrangement

The parsers are the inverse of the builder functions in mp4_muxer.py.
Box navigation reuses the pattern from ts_muxer.py's read_box/find_box/iter_boxes.
"""

import bisect
import logging
import struct
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# =============================================================================
# MP4 Box Utilities
# =============================================================================

# Minimum bytes needed to read a standard box header
_BOX_HEADER_SIZE = 8

# ftyp brands that identify MP4/MOV containers
_MP4_BRANDS = {
    b"isom",
    b"iso2",
    b"iso3",
    b"iso4",
    b"iso5",
    b"iso6",
    b"mp41",
    b"mp42",
    b"M4V ",
    b"M4A ",
    b"f4v ",
    b"kddi",
    b"avc1",
    b"qt  ",
    b"MSNV",
    b"dash",
    b"3gp4",
    b"3gp5",
    b"3gp6",
}


def is_mp4_header(data: bytes) -> bool:
    """Check if the data starts with an ftyp box (MP4 signature)."""
    if len(data) < 8:
        return False
    size = struct.unpack_from(">I", data, 0)[0]
    box_type = data[4:8]
    if box_type != b"ftyp":
        return False
    if size < 12 or size > len(data):
        return size >= 12  # might be valid but truncated
    major_brand = data[8:12]
    return major_brand in _MP4_BRANDS


def read_box_header(data: bytes, offset: int) -> tuple[bytes, int, int] | None:
    """
    Read a box header at the given offset.

    Returns:
        (box_type, header_size, total_box_size) or None if not enough data.
    """
    if offset + 8 > len(data):
        return None

    size, box_type = struct.unpack_from(">I4s", data, offset)
    header_size = 8

    if size == 1:  # Extended size (64-bit)
        if offset + 16 > len(data):
            return None
        size = struct.unpack_from(">Q", data, offset + 8)[0]
        header_size = 16
    elif size == 0:  # Box extends to end of data
        size = len(data) - offset

    return box_type, header_size, size


def iter_top_level_boxes(data: bytes):
    """
    Iterate over top-level box headers.

    Yields:
        (box_type, header_size, total_size, data_offset)
    """
    offset = 0
    while offset < len(data):
        result = read_box_header(data, offset)
        if result is None:
            break
        box_type, header_size, total_size = result
        yield box_type, header_size, total_size, offset + header_size
        if total_size == 0:
            break
        offset += total_size


def find_box(data: bytes, target: bytes) -> bytes | None:
    """Find a box by type and return its body (data after header)."""
    for box_type, header_size, total_size, data_offset in iter_top_level_boxes(data):
        if box_type == target:
            return data[data_offset : data_offset - header_size + total_size]
    return None


def iter_boxes(data: bytes):
    """Iterate over child boxes: yields (box_type, box_body_bytes)."""
    for box_type, header_size, total_size, data_offset in iter_top_level_boxes(data):
        end = data_offset - header_size + total_size
        yield box_type, data[data_offset:end]


# =============================================================================
# Sample Table Parsers (inverse of mp4_muxer.py builders)
# =============================================================================


def parse_full_box_header(data: bytes) -> tuple[int, int, int]:
    """
    Parse a full box header (version + flags).

    Returns:
        (version, flags, header_size) where header_size is 4 bytes.
    """
    if len(data) < 4:
        return 0, 0, 0
    version = data[0]
    flags = (data[1] << 16) | (data[2] << 8) | data[3]
    return version, flags, 4


def parse_stco(data: bytes) -> list[int]:
    """
    Parse Chunk Offset box (stco) - 32-bit offsets.

    Layout: version(1) + flags(3) + entry_count(4) + [offset(4)]...
    """
    if len(data) < 8:
        return []
    _, _, hdr = parse_full_box_header(data)
    pos = hdr
    entry_count = struct.unpack_from(">I", data, pos)[0]
    pos += 4

    if len(data) < pos + entry_count * 4:
        return []

    offsets = []
    for _ in range(entry_count):
        offsets.append(struct.unpack_from(">I", data, pos)[0])
        pos += 4
    return offsets


def parse_co64(data: bytes) -> list[int]:
    """
    Parse Chunk Offset box (co64) - 64-bit offsets.

    Layout: version(1) + flags(3) + entry_count(4) + [offset(8)]...
    """
    if len(data) < 8:
        return []
    _, _, hdr = parse_full_box_header(data)
    pos = hdr
    entry_count = struct.unpack_from(">I", data, pos)[0]
    pos += 4

    if len(data) < pos + entry_count * 8:
        return []

    offsets = []
    for _ in range(entry_count):
        offsets.append(struct.unpack_from(">Q", data, pos)[0])
        pos += 8
    return offsets


def parse_stss(data: bytes) -> list[int]:
    """
    Parse Sync Sample box (stss) - keyframe indices (1-based).

    Layout: version(1) + flags(3) + entry_count(4) + [sample_number(4)]...
    """
    if len(data) < 8:
        return []
    _, _, hdr = parse_full_box_header(data)
    pos = hdr
    entry_count = struct.unpack_from(">I", data, pos)[0]
    pos += 4

    if len(data) < pos + entry_count * 4:
        return []

    indices = []
    for _ in range(entry_count):
        indices.append(struct.unpack_from(">I", data, pos)[0])
        pos += 4
    return indices


def parse_stsz(data: bytes) -> tuple[int, list[int]]:
    """
    Parse Sample Size box (stsz).

    Layout: version(1) + flags(3) + sample_size(4) + sample_count(4) + [size(4)]...

    Returns:
        (uniform_size, sizes_list).
        If uniform_size > 0, all samples have that size and sizes_list is empty.
        Otherwise, sizes_list contains per-sample sizes.
    """
    if len(data) < 12:
        return 0, []
    _, _, hdr = parse_full_box_header(data)
    pos = hdr
    sample_size = struct.unpack_from(">I", data, pos)[0]
    sample_count = struct.unpack_from(">I", data, pos + 4)[0]
    pos += 8

    if sample_size > 0:
        return sample_size, []

    if len(data) < pos + sample_count * 4:
        return 0, []

    sizes = []
    for _ in range(sample_count):
        sizes.append(struct.unpack_from(">I", data, pos)[0])
        pos += 4
    return 0, sizes


def parse_stts(data: bytes) -> list[tuple[int, int]]:
    """
    Parse Time-to-Sample box (stts) - run-length encoded durations.

    Layout: version(1) + flags(3) + entry_count(4) + [sample_count(4) + sample_delta(4)]...

    Returns:
        List of (sample_count, sample_delta) entries.
    """
    if len(data) < 8:
        return []
    _, _, hdr = parse_full_box_header(data)
    pos = hdr
    entry_count = struct.unpack_from(">I", data, pos)[0]
    pos += 4

    if len(data) < pos + entry_count * 8:
        return []

    entries = []
    for _ in range(entry_count):
        count = struct.unpack_from(">I", data, pos)[0]
        delta = struct.unpack_from(">I", data, pos + 4)[0]
        entries.append((count, delta))
        pos += 8
    return entries


def parse_stsc(data: bytes) -> list[tuple[int, int, int]]:
    """
    Parse Sample-to-Chunk box (stsc).

    Layout: version(1) + flags(3) + entry_count(4) +
            [first_chunk(4) + samples_per_chunk(4) + sample_desc_index(4)]...

    Returns:
        List of (first_chunk, samples_per_chunk, sample_desc_index) entries.
        first_chunk is 1-based.
    """
    if len(data) < 8:
        return []
    _, _, hdr = parse_full_box_header(data)
    pos = hdr
    entry_count = struct.unpack_from(">I", data, pos)[0]
    pos += 4

    if len(data) < pos + entry_count * 12:
        return []

    entries = []
    for _ in range(entry_count):
        first_chunk = struct.unpack_from(">I", data, pos)[0]
        spc = struct.unpack_from(">I", data, pos + 4)[0]
        sdi = struct.unpack_from(">I", data, pos + 8)[0]
        entries.append((first_chunk, spc, sdi))
        pos += 12
    return entries


def parse_mdhd(data: bytes) -> tuple[int, int]:
    """
    Parse Media Header box (mdhd) for timescale and duration.

    Returns:
        (timescale, duration) in media timescale units.
    """
    if len(data) < 4:
        return 0, 0
    version = data[0]
    if version == 1:
        # 64-bit: skip version(1)+flags(3)+creation(8)+modification(8)
        if len(data) < 32:
            return 0, 0
        timescale = struct.unpack_from(">I", data, 20)[0]
        duration = struct.unpack_from(">Q", data, 24)[0]
    else:
        # 32-bit: skip version(1)+flags(3)+creation(4)+modification(4)
        if len(data) < 20:
            return 0, 0
        timescale = struct.unpack_from(">I", data, 12)[0]
        duration = struct.unpack_from(">I", data, 16)[0]
    return timescale, duration


def parse_stsd_codec(data: bytes) -> str:
    """
    Parse Sample Description box (stsd) to extract the codec FourCC.

    Returns the codec name as a string (e.g. "avc1", "hvc1", "mp4a").
    """
    if len(data) < 16:
        return ""
    # version(1)+flags(3)+entry_count(4)
    pos = 8
    # First entry: size(4)+type(4)
    if pos + 8 > len(data):
        return ""
    codec_fourcc = data[pos + 4 : pos + 8]
    try:
        return codec_fourcc.decode("ascii").strip()
    except (UnicodeDecodeError, ValueError):
        return ""


# =============================================================================
# MP4 Index (parallel to MKVCueIndex)
# =============================================================================


@dataclass
class MP4Index:
    """
    Seek index extracted from an MP4 file's moov atom.

    Parallel to ``MKVCueIndex`` for MKV files. Provides keyframe-indexed
    cue points for time-based seeking and the raw moov bytes needed to
    reconstruct a streamable (faststart) MP4 for on-the-fly demuxing.
    """

    duration_ms: float = 0.0
    timescale: int = 0
    cue_points: list[tuple[float, int]] = field(default_factory=list)  # [(time_ms, byte_offset), ...]
    moov_offset: int = 0  # Absolute file offset where moov atom starts
    moov_size: int = 0  # Total size of the moov atom (header + body)
    moov_data: bytes = b""  # Raw moov atom bytes (for prepending to mdat pipe)
    ftyp_data: bytes = b""  # Raw ftyp atom bytes (for prepending before moov)
    mdat_offset: int = 0  # Absolute file offset where mdat atom starts
    mdat_size: int = 0  # Total size of the mdat atom
    video_codec: str = ""  # e.g. "avc1", "hvc1", "mp4v"
    audio_codec: str = ""  # e.g. "mp4a", "ac-3"

    def byte_offset_for_time(self, time_ms: float) -> tuple[int, float]:
        """
        Find the byte offset for the nearest keyframe at or before time_ms.

        Returns:
            (absolute_byte_offset, actual_keyframe_time_ms)
        """
        if not self.cue_points:
            return 0, 0.0

        times = [cp[0] for cp in self.cue_points]
        idx = bisect.bisect_right(times, time_ms) - 1
        if idx < 0:
            idx = 0

        cue_time_ms, byte_offset = self.cue_points[idx]
        return byte_offset, cue_time_ms


# =============================================================================
# Moov -> Cue Points Builder
# =============================================================================


def _find_nested_box(data: bytes, *path: bytes) -> bytes | None:
    """Walk a box hierarchy: find_nested_box(data, b"trak", b"mdia") etc."""
    current = data
    for box_name in path:
        found = find_box(current, box_name)
        if found is None:
            return None
        current = found
    return current


def build_cue_points_from_moov(moov_body: bytes) -> tuple[list[tuple[float, int]], float, int, str, str]:
    """
    Parse a moov body to build keyframe-indexed cue points.

    Walks the first video trak's stbl to extract:
    - Chunk offsets (stco/co64)
    - Keyframe sample indices (stss)
    - Sample sizes (stsz)
    - Sample durations (stts)
    - Sample-to-chunk mapping (stsc)
    - Timescale and duration from mdhd

    Returns:
        (cue_points, duration_ms, timescale, video_codec, audio_codec)
    """
    cue_points: list[tuple[float, int]] = []
    duration_ms = 0.0
    timescale = 0
    video_codec = ""
    audio_codec = ""

    # Find all traks
    video_stbl = None
    video_mdhd = None

    offset = 0
    data = moov_body
    while offset < len(data):
        result = read_box_header(data, offset)
        if result is None:
            break
        box_type, hdr_size, total_size = result

        if box_type == b"trak":
            trak_body = data[offset + hdr_size : offset + total_size]

            # Check handler type to identify video/audio
            hdlr_data = _find_nested_box(trak_body, b"mdia", b"hdlr")
            handler_type = b""
            if hdlr_data and len(hdlr_data) >= 12:
                # hdlr: version(1)+flags(3)+pre_defined(4)+handler_type(4)
                handler_type = hdlr_data[8:12]

            if handler_type == b"vide" and video_stbl is None:
                video_stbl = _find_nested_box(trak_body, b"mdia", b"minf", b"stbl")
                video_mdhd_data = _find_nested_box(trak_body, b"mdia", b"mdhd")
                if video_mdhd_data:
                    video_mdhd = video_mdhd_data

                stsd_data = _find_nested_box(trak_body, b"mdia", b"minf", b"stbl", b"stsd")
                if stsd_data:
                    video_codec = parse_stsd_codec(stsd_data)

            elif handler_type == b"soun" and not audio_codec:
                stsd_data = _find_nested_box(trak_body, b"mdia", b"minf", b"stbl", b"stsd")
                if stsd_data:
                    audio_codec = parse_stsd_codec(stsd_data)

        elif box_type == b"mvhd":
            # Fallback: parse mvhd for timescale/duration if no mdhd
            mvhd_body = data[offset + hdr_size : offset + total_size]
            if len(mvhd_body) >= 20:
                version = mvhd_body[0]
                if version == 1:
                    if len(mvhd_body) >= 28:
                        ts = struct.unpack_from(">I", mvhd_body, 20)[0]
                        dur = struct.unpack_from(">Q", mvhd_body, 24)[0]
                        if timescale == 0:
                            timescale = ts
                            duration_ms = dur / ts * 1000.0 if ts else 0.0
                else:
                    ts = struct.unpack_from(">I", mvhd_body, 12)[0]
                    dur = struct.unpack_from(">I", mvhd_body, 16)[0]
                    if timescale == 0:
                        timescale = ts
                        duration_ms = dur / ts * 1000.0 if ts else 0.0

        if total_size == 0:
            break
        offset += total_size

    # Parse mdhd for video timescale (more precise than mvhd)
    if video_mdhd:
        ts, dur = parse_mdhd(video_mdhd)
        if ts > 0:
            timescale = ts
            duration_ms = dur / ts * 1000.0

    if video_stbl is None:
        logger.warning("[mp4_parser] No video stbl found in moov")
        return cue_points, duration_ms, timescale, video_codec, audio_codec

    # Parse sample tables from video stbl
    stco_data = find_box(video_stbl, b"stco")
    co64_data = find_box(video_stbl, b"co64")
    stss_data = find_box(video_stbl, b"stss")
    stsz_data = find_box(video_stbl, b"stsz")
    stts_data = find_box(video_stbl, b"stts")
    stsc_data = find_box(video_stbl, b"stsc")

    # Chunk offsets
    chunk_offsets = parse_co64(co64_data) if co64_data else (parse_stco(stco_data) if stco_data else [])

    # Keyframe sample numbers (1-based)
    keyframe_samples = set(parse_stss(stss_data)) if stss_data else set()
    all_are_keyframes = not stss_data  # No stss means all samples are sync

    # Sample sizes
    uniform_size, size_list = parse_stsz(stsz_data) if stsz_data else (0, [])

    # Sample durations (run-length encoded)
    stts_entries = parse_stts(stts_data) if stts_data else []

    # Sample-to-chunk mapping
    stsc_entries = parse_stsc(stsc_data) if stsc_data else []

    if not chunk_offsets or timescale == 0:
        logger.warning(
            "[mp4_parser] Missing data: chunks=%d, timescale=%d",
            len(chunk_offsets),
            timescale,
        )
        return cue_points, duration_ms, timescale, video_codec, audio_codec

    # Expand stts to per-sample durations
    sample_durations: list[int] = []
    for count, delta in stts_entries:
        sample_durations.extend([delta] * count)

    # Expand stsc to determine which samples belong to which chunk
    # Build a mapping: chunk_index (0-based) -> samples_per_chunk
    total_chunks = len(chunk_offsets)
    chunk_sample_counts: list[int] = [0] * total_chunks

    if stsc_entries:
        for i, (first_chunk, spc, _sdi) in enumerate(stsc_entries):
            # first_chunk is 1-based
            start = first_chunk - 1
            if i + 1 < len(stsc_entries):
                end = stsc_entries[i + 1][0] - 1
            else:
                end = total_chunks
            for c in range(start, end):
                if c < total_chunks:
                    chunk_sample_counts[c] = spc
    else:
        # Default: 1 sample per chunk
        chunk_sample_counts = [1] * total_chunks

    # Count total samples
    total_samples = sum(chunk_sample_counts)

    # Get per-sample sizes
    if uniform_size > 0:
        sample_sizes = [uniform_size] * total_samples
    else:
        sample_sizes = size_list

    # Build cumulative timestamp for each sample and map keyframes to byte offsets
    current_sample = 0  # 0-based sample index
    current_time = 0  # in timescale units

    for chunk_idx, chunk_offset in enumerate(chunk_offsets):
        spc = chunk_sample_counts[chunk_idx] if chunk_idx < len(chunk_sample_counts) else 1
        byte_pos = chunk_offset

        for s in range(spc):
            sample_num = current_sample + 1  # 1-based for stss comparison
            is_keyframe = all_are_keyframes or sample_num in keyframe_samples

            if is_keyframe:
                time_ms = current_time / timescale * 1000.0
                cue_points.append((time_ms, byte_pos))

            # Advance byte position by this sample's size
            if current_sample < len(sample_sizes):
                byte_pos += sample_sizes[current_sample]

            # Advance timestamp
            if current_sample < len(sample_durations):
                current_time += sample_durations[current_sample]

            current_sample += 1

    logger.info(
        "[mp4_parser] Built %d cue points from %d samples, duration=%.1fs, video=%s, audio=%s",
        len(cue_points),
        total_samples,
        duration_ms / 1000.0,
        video_codec,
        audio_codec,
    )

    return cue_points, duration_ms, timescale, video_codec, audio_codec


# =============================================================================
# Moov Offset Rewriting (for faststart pipe construction)
# =============================================================================


def _rewrite_stco_in_place(data: bytearray, box_start: int, box_size: int, delta: int) -> int:
    """Rewrite stco chunk offsets by adding delta. Returns number of entries fixed."""
    # FullBox header: version(1) + flags(3) = 4 bytes
    body_start = box_start + 4
    if body_start + 4 > box_start + box_size:
        return 0
    entry_count = struct.unpack_from(">I", data, body_start)[0]
    pos = body_start + 4
    for _ in range(entry_count):
        if pos + 4 > box_start + box_size:
            break
        old_val = struct.unpack_from(">I", data, pos)[0]
        struct.pack_into(">I", data, pos, old_val + delta)
        pos += 4
    return entry_count


def _rewrite_co64_in_place(data: bytearray, box_start: int, box_size: int, delta: int) -> int:
    """Rewrite co64 chunk offsets by adding delta. Returns number of entries fixed."""
    body_start = box_start + 4
    if body_start + 4 > box_start + box_size:
        return 0
    entry_count = struct.unpack_from(">I", data, body_start)[0]
    pos = body_start + 4
    for _ in range(entry_count):
        if pos + 8 > box_start + box_size:
            break
        old_val = struct.unpack_from(">Q", data, pos)[0]
        struct.pack_into(">Q", data, pos, old_val + delta)
        pos += 8
    return entry_count


def _walk_and_rewrite(data: bytearray, start: int, end: int, delta: int) -> int:
    """
    Recursively walk boxes within [start, end) looking for stco/co64 boxes
    and rewriting their offsets.

    Returns total number of offset entries rewritten.
    """
    total = 0
    offset = start
    while offset + 8 <= end:
        size = struct.unpack_from(">I", data, offset)[0]
        box_type = data[offset + 4 : offset + 8]
        hdr_size = 8

        if size == 1:
            if offset + 16 > end:
                break
            size = struct.unpack_from(">Q", data, offset + 8)[0]
            hdr_size = 16
        elif size == 0:
            size = end - offset

        if size < 8 or offset + size > end:
            break

        body_start = offset + hdr_size
        body_end = offset + size

        if box_type == b"stco":
            total += _rewrite_stco_in_place(data, body_start, size - hdr_size, delta)
        elif box_type == b"co64":
            total += _rewrite_co64_in_place(data, body_start, size - hdr_size, delta)
        elif box_type in (b"moov", b"trak", b"mdia", b"minf", b"stbl"):
            # Container box -- recurse into children
            total += _walk_and_rewrite(data, body_start, body_end, delta)

        offset += size

    return total


def extract_video_track_from_moov(moov_data: bytes):
    """
    Extract video codec configuration from an MP4 moov atom.

    Walks the moov box tree to find the first video trak, extracts its
    resolution and codec-private data (avcC/hvcC), and returns a synthetic
    ``MKVTrack`` suitable for building an fMP4 init segment.

    Returns:
        An ``MKVTrack`` with video metadata, or ``None`` if no video track
        is found.
    """
    from mediaflow_proxy.remuxer.ebml_parser import (
        CODEC_ID_H264,
        CODEC_ID_H265,
        MKVTrack,
    )

    # Strip the moov box header to get the body
    if len(moov_data) < 8:
        return None
    raw_size = struct.unpack_from(">I", moov_data, 0)[0]
    hdr_size = 16 if raw_size == 1 else 8
    moov_body = moov_data[hdr_size:]

    # Walk traks looking for video handler
    offset = 0
    while offset < len(moov_body):
        result = read_box_header(moov_body, offset)
        if result is None:
            break
        box_type, box_hdr_size, total_size = result

        if box_type == b"trak":
            trak_body = moov_body[offset + box_hdr_size : offset + total_size]

            # Check handler type
            hdlr_data = _find_nested_box(trak_body, b"mdia", b"hdlr")
            handler_type = b""
            if hdlr_data and len(hdlr_data) >= 12:
                handler_type = hdlr_data[8:12]

            if handler_type == b"vide":
                # Found video trak -- extract stsd for codec config
                stsd_data = _find_nested_box(trak_body, b"mdia", b"minf", b"stbl", b"stsd")
                if not stsd_data or len(stsd_data) < 16:
                    offset += total_size
                    continue

                codec_name = parse_stsd_codec(stsd_data)

                # Map MP4 codec names to MKV codec IDs
                if codec_name in ("avc1", "avc3"):
                    mkv_codec_id = CODEC_ID_H264
                elif codec_name in ("hvc1", "hev1"):
                    mkv_codec_id = CODEC_ID_H265
                else:
                    mkv_codec_id = f"V_MP4/{codec_name}"

                # Extract codec private (avcC or hvcC box) from inside the
                # sample entry. The stsd structure is:
                #   version(1) + flags(3) + entry_count(4)
                #   then entry: size(4) + type(4) + ... + nested boxes
                # The avcC/hvcC is a child box of the sample entry.
                codec_private = b""
                width = 0
                height = 0

                # Parse sample entry to get width/height and codec config
                entry_start = 8  # skip version+flags+entry_count
                if entry_start + 8 <= len(stsd_data):
                    entry_size = struct.unpack_from(">I", stsd_data, entry_start)[0]
                    entry_body_start = entry_start + 8  # skip size+type
                    entry_end = min(entry_start + entry_size, len(stsd_data))

                    # Visual sample entry: 6 reserved + 2 data_ref_idx + ...
                    # At offset 24 from entry body start: width(2) + height(2)
                    vis_offset = entry_body_start + 24
                    if vis_offset + 4 <= entry_end:
                        width = struct.unpack_from(">H", stsd_data, vis_offset)[0]
                        height = struct.unpack_from(">H", stsd_data, vis_offset + 2)[0]

                    # Scan nested boxes for avcC or hvcC
                    # Visual sample entry fixed fields = 70 bytes from entry body
                    nested_start = entry_body_start + 70
                    if nested_start < entry_end:
                        nested_data = stsd_data[nested_start:entry_end]
                        for target in (b"avcC", b"hvcC"):
                            found = find_box(nested_data, target)
                            if found:
                                codec_private = found
                                break

                # Get duration from mdhd if available
                default_duration_ns = 0
                mdhd_data = _find_nested_box(trak_body, b"mdia", b"mdhd")
                if mdhd_data and len(mdhd_data) >= 20:
                    version = mdhd_data[0]
                    if version == 1 and len(mdhd_data) >= 28:
                        ts = struct.unpack_from(">I", mdhd_data, 20)[0]
                        dur = struct.unpack_from(">Q", mdhd_data, 24)[0]
                    else:
                        ts = struct.unpack_from(">I", mdhd_data, 12)[0]
                        dur = struct.unpack_from(">I", mdhd_data, 16)[0]
                    if ts > 0 and dur > 0:
                        # Rough estimate: assume 24fps if we can't determine.
                        default_duration_ns = int(1_000_000_000 / 24)

                return MKVTrack(
                    track_number=1,
                    track_type=1,  # video
                    codec_id=mkv_codec_id,
                    codec_private=codec_private,
                    pixel_width=width,
                    pixel_height=height,
                    default_duration_ns=default_duration_ns,
                )

        offset += total_size

    return None


def rewrite_moov_offsets(moov_data: bytes, delta: int) -> bytes:
    """
    Rewrite all stco/co64 chunk offsets in a moov atom by adding ``delta``.

    This is needed when rearranging an MP4 file for pipe streaming:
    the original moov's chunk offsets reference positions in the original
    file layout. When we prepend moov before mdat, the offsets must be
    shifted by ``delta = moov_size - original_mdat_offset``.

    Args:
        moov_data: Raw bytes of the complete moov box (header + body).
        delta: Offset adjustment to add to every chunk offset.

    Returns:
        Modified moov bytes with updated chunk offsets.
    """
    buf = bytearray(moov_data)

    # Determine moov box header size
    raw_size = struct.unpack_from(">I", buf, 0)[0]
    hdr_size = 16 if raw_size == 1 else 8

    total = _walk_and_rewrite(buf, hdr_size, len(buf), delta)
    logger.info("[mp4_parser] Rewrote %d chunk offset entries (delta=%+d)", total, delta)

    return bytes(buf)
