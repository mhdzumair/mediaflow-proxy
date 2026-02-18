"""
Pure Python EBML/MKV parser for media remuxing.

Provides two levels of MKV parsing:

Level 1 (Seeking): Parse EBML Header, SeekHead, Info, and Cues to build a
time-to-byte-offset map for fast seeking.

Level 2 (Demuxing): Parse Tracks for codec metadata (CodecID, CodecPrivate,
video/audio parameters) and Cluster/SimpleBlock/BlockGroup for extracting
individual media frames with timestamps.
"""

import bisect
import logging
import struct
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# =============================================================================
# EBML Element IDs (Matroska spec)
# =============================================================================

# Top-level
EBML_HEADER = 0x1A45DFA3
SEGMENT = 0x18538067

# SeekHead
SEEK_HEAD = 0x114D9B74
SEEK = 0x4DBB
SEEK_ID = 0x53AB
SEEK_POSITION = 0x53AC

# Info
INFO = 0x1549A966
TIMESTAMP_SCALE = 0x2AD7B1
DURATION = 0x4489

# Tracks
TRACKS = 0x1654AE6B
TRACK_ENTRY = 0xAE
TRACK_NUMBER = 0xD7
TRACK_UID = 0x73C5
TRACK_TYPE = 0x83
CODEC_ID = 0x86
CODEC_PRIVATE = 0x63A2
DEFAULT_DURATION = 0x23E383
CODEC_DELAY = 0x56AA
SEEK_PRE_ROLL = 0x56BB

# Video track settings
VIDEO = 0xE0
PIXEL_WIDTH = 0xB0
PIXEL_HEIGHT = 0xBA
DISPLAY_WIDTH = 0x54B0
DISPLAY_HEIGHT = 0x54BA

# Audio track settings
AUDIO = 0xE1
SAMPLING_FREQUENCY = 0xB5
OUTPUT_SAMPLING_FREQUENCY = 0x78B5
CHANNELS = 0x9F
BIT_DEPTH = 0x6264

# Cluster
CLUSTER = 0x1F43B675
CLUSTER_TIMESTAMP = 0xE7
SIMPLE_BLOCK = 0xA3
BLOCK_GROUP = 0xA0
BLOCK = 0xA1
BLOCK_DURATION = 0x9B

# Cues
CUES = 0x1C53BB6B
CUE_POINT = 0xBB
CUE_TIME = 0xB3
CUE_TRACK_POSITIONS = 0xB7
CUE_TRACK = 0xF7
CUE_CLUSTER_POSITION = 0xF1

# Container elements (have children, not raw data)
_CONTAINER_IDS = frozenset(
    {
        EBML_HEADER,
        SEGMENT,
        SEEK_HEAD,
        SEEK,
        INFO,
        TRACKS,
        TRACK_ENTRY,
        VIDEO,
        AUDIO,
        CLUSTER,
        BLOCK_GROUP,
        CUES,
        CUE_POINT,
        CUE_TRACK_POSITIONS,
    }
)

# Unknown/indeterminate size sentinel
UNKNOWN_SIZE = -1


# =============================================================================
# Low-level EBML parsing
# =============================================================================


def read_vint(data: bytes, pos: int) -> tuple[int, int, int]:
    """
    Read a variable-length integer (VINT) from EBML data.

    Returns:
        (raw_value, value_without_marker, new_pos)
        raw_value includes the VINT marker bit.
        value_without_marker has the marker bit masked off (for element sizes).
    """
    if pos >= len(data):
        raise ValueError(f"EBML VINT: position {pos} beyond data length {len(data)}")

    first = data[pos]
    if first == 0:
        raise ValueError(f"EBML VINT: invalid leading byte 0x00 at pos {pos}")

    # Determine length from leading byte
    length = 1
    mask = 0x80
    while mask and not (first & mask):
        length += 1
        mask >>= 1

    if pos + length > len(data):
        raise ValueError(f"EBML VINT: need {length} bytes at pos {pos}, only {len(data) - pos} available")

    # Read the raw value
    raw = 0
    for i in range(length):
        raw = (raw << 8) | data[pos + i]

    # Mask off the leading marker bit for size values
    value = raw & ~(1 << (7 * length))

    # Check for unknown/indeterminate size (all value bits set)
    all_ones = (1 << (7 * length)) - 1
    if value == all_ones:
        value = UNKNOWN_SIZE

    return raw, value, pos + length


def read_element_id(data: bytes, pos: int) -> tuple[int, int]:
    """
    Read an EBML element ID.

    Returns:
        (element_id, new_pos)
    """
    raw, _, new_pos = read_vint(data, pos)
    return raw, new_pos


def read_element_size(data: bytes, pos: int) -> tuple[int, int]:
    """
    Read an EBML element data size.

    Returns:
        (size, new_pos)  where size may be UNKNOWN_SIZE (-1)
    """
    _, value, new_pos = read_vint(data, pos)
    return value, new_pos


def read_uint(data: bytes, pos: int, length: int) -> int:
    """Read an unsigned integer of N bytes (big-endian)."""
    if length == 0:
        return 0
    value = 0
    for i in range(length):
        value = (value << 8) | data[pos + i]
    return value


def read_float(data: bytes, pos: int, length: int) -> float:
    """Read a 4 or 8 byte IEEE float (big-endian)."""
    if length == 4:
        return struct.unpack(">f", data[pos : pos + 4])[0]
    elif length == 8:
        return struct.unpack(">d", data[pos : pos + 8])[0]
    raise ValueError(f"EBML float must be 4 or 8 bytes, got {length}")


def read_element_id_bytes(data: bytes, pos: int) -> tuple[bytes, int]:
    """
    Read an EBML element ID and return it as raw bytes (for SeekID matching).

    Returns:
        (id_bytes, new_pos)
    """
    if pos >= len(data):
        raise ValueError(f"read_element_id_bytes: pos {pos} beyond data length {len(data)}")

    first = data[pos]
    length = 1
    mask = 0x80
    while mask and not (first & mask):
        length += 1
        mask >>= 1

    return data[pos : pos + length], pos + length


# =============================================================================
# Element iteration
# =============================================================================


def iter_elements(data: bytes, start: int, end: int):
    """
    Iterate over EBML elements within a range.

    Yields:
        (element_id, data_offset, data_size, element_start)
        element_start is the byte position of the element ID.
        data_offset is where the element's data begins (after ID + size).
        data_size is the declared size (may be UNKNOWN_SIZE).
    """
    pos = start
    while pos < end:
        try:
            element_start = pos
            eid, pos2 = read_element_id(data, pos)
            size, pos3 = read_element_size(data, pos2)
        except (ValueError, IndexError):
            break

        yield eid, pos3, size, element_start
        if size == UNKNOWN_SIZE:
            break
        pos = pos3 + size


# =============================================================================
# High-level MKV parsing
# =============================================================================

# MKV Track types (needed early for build_cue_index)
TRACK_TYPE_VIDEO = 1
TRACK_TYPE_AUDIO = 2
TRACK_TYPE_SUBTITLE = 17

# Common MKV codec IDs (needed early for bitrate parsing in build_cue_index)
CODEC_ID_H264 = "V_MPEG4/ISO/AVC"
CODEC_ID_H265 = "V_MPEGH/ISO/HEVC"
CODEC_ID_AAC = "A_AAC"
CODEC_ID_AC3 = "A_AC3"
CODEC_ID_EAC3 = "A_EAC3"
CODEC_ID_OPUS = "A_OPUS"
CODEC_ID_VORBIS = "A_VORBIS"
CODEC_ID_FLAC = "A_FLAC"
CODEC_ID_SRT = "S_TEXT/UTF8"
CODEC_ID_ASS = "S_TEXT/ASS"


@dataclass
class MKVCueIndex:
    """Seek index extracted from an MKV file's Cues element."""

    duration_ms: float = 0.0
    timestamp_scale: int = 1_000_000  # nanoseconds per tick (default = 1ms)
    cue_points: list[tuple[float, int]] = field(default_factory=list)  # [(time_ms, byte_offset), ...]
    segment_data_offset: int = 0  # Byte offset where Segment data begins in the file
    first_cluster_offset: int = 0  # Absolute file offset of the first Cluster element
    seek_header: bytes = b""  # Synthetic MKV header for seeking (EBML + Segment(UNKNOWN) + Info + Tracks)

    # Track metadata for size estimation and init segment generation
    audio_codec_id: str = ""  # e.g. "A_EAC3", "A_AC3"
    audio_bitrate: int = 0  # Input audio bitrate in bits/s (from frame header parsing)
    audio_channels: int = 0
    audio_sample_rate: float = 0.0
    video_codec_id: str = ""  # e.g. "V_MPEG4/ISO/AVC"
    video_codec_private: bytes = b""  # avcC / hvcC extradata for init segment
    video_width: int = 0
    video_height: int = 0
    video_fps: float = 0.0  # From default_duration_ns (0 = unknown)
    video_default_duration_ns: int = 0  # Raw default_duration_ns for MKVTrack

    def byte_offset_for_time(self, time_ms: float) -> tuple[int, float]:
        """
        Find the cluster byte offset for the nearest keyframe at or before time_ms.

        Returns:
            (absolute_byte_offset, actual_keyframe_time_ms)
        """
        if not self.cue_points:
            return 0, 0.0

        # cue_points is sorted by time_ms
        times = [cp[0] for cp in self.cue_points]
        idx = bisect.bisect_right(times, time_ms) - 1
        if idx < 0:
            idx = 0

        cue_time_ms, cluster_offset = self.cue_points[idx]
        # cluster_offset is relative to Segment data start
        absolute_offset = self.segment_data_offset + cluster_offset
        return absolute_offset, cue_time_ms

    def estimate_fmp4_size(
        self,
        mkv_file_size: int,
        output_audio_bitrate: int = 192000,
    ) -> int | None:
        """
        Estimate the total fMP4 output size from known MKV file size.

        Uses the audio bitrate delta (input vs output) and duration to
        calculate how much the audio track shrinks or grows. Video is
        copied unchanged. Container overhead difference is accounted for.

        Returns:
            Estimated fMP4 size in bytes, or None if insufficient metadata.
        """
        if self.duration_ms <= 0 or self.audio_bitrate <= 0:
            return None

        duration_s = self.duration_ms / 1000.0
        input_audio_bytes = self.audio_bitrate * duration_s / 8
        output_audio_bytes = output_audio_bitrate * duration_s / 8
        audio_delta = output_audio_bytes - input_audio_bytes  # negative = shrinks

        # fMP4 container overhead: ~430 bytes/s for moof/trun boxes
        # (2s fragments = ~3 MB for 2h file)
        fmp4_overhead = int(duration_s * 430)

        estimated = int(mkv_file_size + audio_delta + fmp4_overhead)
        return max(estimated, 0)


def parse_ebml_header(data: bytes) -> int:
    """
    Validate EBML header and find the Segment element.

    Returns:
        Byte offset where the Segment element's data begins (after its header).
    """
    pos = 0

    # Parse EBML Header element
    eid, pos = read_element_id(data, pos)
    if eid != EBML_HEADER:
        raise ValueError(f"Not an EBML file: expected 0x{EBML_HEADER:X}, got 0x{eid:X}")
    size, pos = read_element_size(data, pos)
    if size == UNKNOWN_SIZE:
        raise ValueError("EBML header has unknown size")

    # Skip EBML header content
    pos += size

    # Next should be Segment
    eid, pos = read_element_id(data, pos)
    if eid != SEGMENT:
        raise ValueError(f"Expected Segment element 0x{SEGMENT:X}, got 0x{eid:X}")
    _size, pos = read_element_size(data, pos)

    # pos is now at the start of Segment's children
    return pos


def build_seek_header(header_data: bytes, first_cluster_offset: int) -> bytes:
    """
    Build a synthetic MKV header for seeking by rewriting the Segment size
    to UNKNOWN (-1).

    When FFmpeg receives MKV data via pipe, it needs the container header
    (EBML header + Segment + Info + Tracks) to initialize decoders. For
    seeking, we stream cluster data from a mid-file byte offset, so the
    Segment's original declared size becomes wrong. Rewriting it to
    UNKNOWN_SIZE (0x01FFFFFFFFFFFFFF in EBML) tells FFmpeg to read until
    EOF, which is correct for a live/truncated stream.

    Args:
        header_data: Original file header bytes (at least first_cluster_offset bytes).
        first_cluster_offset: Byte offset of the first Cluster element.

    Returns:
        Modified header bytes (EBML header through Tracks) with Segment size
        set to UNKNOWN_SIZE.
    """
    pos = 0

    # Skip EBML Header element
    eid, pos = read_element_id(header_data, pos)
    size, pos = read_element_size(header_data, pos)
    ebml_end = pos + size

    # We now have the EBML header: header_data[0:ebml_end]
    # Next is the Segment element ID
    segment_id_start = ebml_end
    eid, segment_id_end = read_element_id(header_data, segment_id_start)
    _segment_size, segment_data_start = read_element_size(header_data, segment_id_end)

    # Build the new header:
    # 1. Original EBML header (unchanged)
    # 2. Segment element ID (unchanged)
    # 3. Segment size rewritten to UNKNOWN_SIZE (8-byte VINT: 0x01 FF FF FF FF FF FF FF)
    # 4. Segment children from original (Info, Tracks, etc.) up to first Cluster
    result = bytearray()
    result.extend(header_data[:segment_id_end])  # EBML header + Segment ID
    result.extend(b"\x01\xff\xff\xff\xff\xff\xff\xff")  # UNKNOWN_SIZE (8 bytes)
    result.extend(header_data[segment_data_start:first_cluster_offset])  # Info + Tracks

    return bytes(result)


def parse_seek_head(data: bytes, segment_data_offset: int) -> dict[int, int]:
    """
    Parse the SeekHead element to find positions of top-level elements.

    Scans from segment_data_offset for the SeekHead element, then parses
    its Seek entries.

    Returns:
        Dict mapping element_id -> byte_offset (relative to segment_data_offset).
    """
    positions = {}

    for eid, data_off, size, _ in iter_elements(data, segment_data_offset, len(data)):
        if eid == SEEK_HEAD:
            # Parse Seek entries within SeekHead
            end = data_off + size
            for seek_eid, seek_off, seek_size, _ in iter_elements(data, data_off, end):
                if seek_eid == SEEK:
                    seek_id_value = None
                    seek_position = None
                    seek_end = seek_off + seek_size
                    for child_eid, child_off, child_size, _ in iter_elements(data, seek_off, seek_end):
                        if child_eid == SEEK_ID:
                            # SeekID is stored as the raw element ID bytes
                            seek_id_value = read_uint(data, child_off, child_size)
                        elif child_eid == SEEK_POSITION:
                            seek_position = read_uint(data, child_off, child_size)
                    if seek_id_value is not None and seek_position is not None:
                        positions[seek_id_value] = seek_position
            break  # Only need the first SeekHead

        # Stop if we hit Cluster data (SeekHead is always before Clusters)
        if eid == CLUSTER:
            break

    return positions


def parse_info(data: bytes, info_offset: int) -> tuple[int, float]:
    """
    Parse the Info element to extract TimestampScale and Duration.

    Args:
        data: Buffer containing the Info element.
        info_offset: Start of the Info element (at the element ID).

    Returns:
        (timestamp_scale_ns, duration_ticks)
    """
    timestamp_scale = 1_000_000  # default: 1ms
    duration = 0.0

    # Read element header
    eid, pos = read_element_id(data, info_offset)
    if eid != INFO:
        raise ValueError(f"Expected Info element 0x{INFO:X}, got 0x{eid:X}")
    size, pos = read_element_size(data, pos)
    end = pos + size

    for child_eid, child_off, child_size, _ in iter_elements(data, pos, end):
        if child_eid == TIMESTAMP_SCALE:
            timestamp_scale = read_uint(data, child_off, child_size)
        elif child_eid == DURATION:
            duration = read_float(data, child_off, child_size)

    return timestamp_scale, duration


def parse_cues(data: bytes, cues_offset: int, timestamp_scale_ns: int) -> list[tuple[float, int]]:
    """
    Parse the Cues element into a sorted list of (time_ms, cluster_byte_offset).

    Args:
        data: Buffer containing the Cues element.
        cues_offset: Start of the Cues element (at the element ID).
        timestamp_scale_ns: Nanoseconds per timestamp tick from Info.

    Returns:
        Sorted list of (time_ms, cluster_byte_offset_relative_to_segment).
    """
    cue_points = []
    ns_per_ms = 1_000_000  # 1ms = 1,000,000 ns
    scale_ms = timestamp_scale_ns / ns_per_ms  # ticks -> ms multiplier

    # Read Cues element header
    eid, pos = read_element_id(data, cues_offset)
    if eid != CUES:
        raise ValueError(f"Expected Cues element 0x{CUES:X}, got 0x{eid:X}")
    size, pos = read_element_size(data, pos)
    end = pos + size

    for cp_eid, cp_off, cp_size, _ in iter_elements(data, pos, end):
        if cp_eid != CUE_POINT:
            continue

        cue_time_ticks = 0
        cluster_position = None
        cp_end = cp_off + cp_size

        for child_eid, child_off, child_size, _ in iter_elements(data, cp_off, cp_end):
            if child_eid == CUE_TIME:
                cue_time_ticks = read_uint(data, child_off, child_size)
            elif child_eid == CUE_TRACK_POSITIONS:
                # Parse CueTrackPositions for CueClusterPosition
                ctp_end = child_off + child_size
                for ctp_eid, ctp_off, ctp_size, _ in iter_elements(data, child_off, ctp_end):
                    if ctp_eid == CUE_CLUSTER_POSITION:
                        cluster_position = read_uint(data, ctp_off, ctp_size)
                        break  # Take the first track's position

        if cluster_position is not None:
            time_ms = cue_time_ticks * scale_ms
            cue_points.append((time_ms, cluster_position))

    cue_points.sort(key=lambda x: x[0])
    return cue_points


def parse_eac3_bitrate(frame_data: bytes) -> int | None:
    """
    Parse an EAC3 (E-AC-3 / Dolby Digital Plus) sync frame header to
    determine the bitrate in bits per second.

    EAC3 frame layout (ETSI TS 102 366):
      - Sync word: 0x0B77 (2 bytes)
      - Byte 2-3: strmtyp(2) | substreamid(3) | frmsiz(11)
      - Byte 4 bits 7-6: fscod (sample rate code)
      - Byte 4 bits 5-4: numblkscod (if fscod != 0b11)

    Returns:
        Bitrate in bits/s, or None if parsing fails.
    """
    if len(frame_data) < 6 or frame_data[0] != 0x0B or frame_data[1] != 0x77:
        return None

    # frmsiz is bits [5:15] of the 16-bit word at offset 2
    word2 = (frame_data[2] << 8) | frame_data[3]
    frmsiz = word2 & 0x07FF  # 11 bits
    frame_bytes = (frmsiz + 1) * 2

    # fscod is bits [7:6] of byte 4
    fscod = (frame_data[4] >> 6) & 0x03
    sample_rates = {0: 48000, 1: 44100, 2: 32000}

    if fscod == 3:
        # fscod2 in bits [5:4], numblkscod is always 6 blocks
        fscod2 = (frame_data[4] >> 4) & 0x03
        sr_map2 = {0: 24000, 1: 22050, 2: 16000}
        sr = sr_map2.get(fscod2, 48000)
        num_blocks = 6
    else:
        sr = sample_rates.get(fscod, 48000)
        numblkscod = (frame_data[4] >> 4) & 0x03
        num_blocks = [1, 2, 3, 6][numblkscod]

    # bitrate = frame_bytes * 8 * sample_rate / (256 * num_blocks)
    bitrate = frame_bytes * 8 * sr // (256 * num_blocks)
    return bitrate


def parse_ac3_bitrate(frame_data: bytes) -> int | None:
    """
    Parse an AC3 (Dolby Digital) sync frame header to determine the
    bitrate in bits per second.

    AC3 frame layout (ATSC A/52):
      - Sync word: 0x0B77 (2 bytes)
      - Bytes 2-3: CRC1
      - Byte 4 bits 7-6: fscod (sample rate code)
      - Byte 4 bits 5-0: frmsizecod (frame size code)

    Returns:
        Bitrate in bits/s, or None if parsing fails.
    """
    if len(frame_data) < 5 or frame_data[0] != 0x0B or frame_data[1] != 0x77:
        return None

    fscod = (frame_data[4] >> 6) & 0x03
    frmsizecod = frame_data[4] & 0x3F

    # AC3 bitrate table (kbps) indexed by frmsizecod // 2
    _AC3_BITRATES_KBPS = [
        32,
        40,
        48,
        56,
        64,
        80,
        96,
        112,
        128,
        160,
        192,
        224,
        256,
        320,
        384,
        448,
        512,
        576,
        640,
    ]
    idx = frmsizecod >> 1
    if fscod > 2 or idx >= len(_AC3_BITRATES_KBPS):
        return None

    return _AC3_BITRATES_KBPS[idx] * 1000


def _extract_first_audio_frame(
    header_data: bytes,
    cluster_start: int,
    audio_track_number: int,
) -> bytes | None:
    """
    Extract the first audio frame from the first Cluster in header data.

    Scans SimpleBlocks and BlockGroups within the Cluster for a block
    belonging to the given audio track number.

    Args:
        header_data: Buffer containing the MKV header + start of first Cluster.
        cluster_start: Byte offset of the Cluster element's children (after ID+size).
        audio_track_number: Track number of the audio track.

    Returns:
        Raw audio frame bytes, or None if not found within the data.
    """
    try:
        # Read Cluster element header to get children start
        eid, id_end = read_element_id(header_data, cluster_start)
        if eid != CLUSTER:
            return None
        size, children_start = read_element_size(header_data, id_end)
        children_end = min(
            children_start + size if size != UNKNOWN_SIZE else len(header_data),
            len(header_data),
        )

        for eid, data_off, size, _ in iter_elements(header_data, children_start, children_end):
            if eid == SIMPLE_BLOCK:
                for track_num, _, _, frame_list in extract_block_frames(header_data, data_off, size):
                    if track_num == audio_track_number and frame_list:
                        return frame_list[0]
            elif eid == BLOCK_GROUP:
                bg_end = data_off + size
                for child_eid, child_off, child_size, _ in iter_elements(header_data, data_off, bg_end):
                    if child_eid == BLOCK:
                        for track_num, _, _, frame_list in extract_block_frames(header_data, child_off, child_size):
                            if track_num == audio_track_number and frame_list:
                                return frame_list[0]
    except (ValueError, IndexError):
        pass
    return None


def build_cue_index(
    header_data: bytes,
    cues_data: bytes,
    cues_file_offset: int,
    segment_data_offset: int,
) -> MKVCueIndex:
    """
    Build a complete MKVCueIndex from pre-fetched header and Cues data.

    This is the main entry point for building the seek index. It expects:
    - header_data: the first N bytes of the file (enough for EBML header + SeekHead + Info)
    - cues_data: the bytes containing the Cues element
    - cues_file_offset: the absolute file offset where cues_data starts
    - segment_data_offset: where the Segment's children begin in the file

    Returns:
        MKVCueIndex with duration and cue points.
    """
    # Parse Info, Tracks from header data and find the first Cluster offset.
    # Scan top-level Segment children for Info (metadata), Tracks (codec info),
    # and Cluster (media data start).
    timestamp_scale = 1_000_000
    duration_ticks = 0.0
    first_cluster_offset = 0  # absolute file offset of first Cluster element
    tracks: list = []

    for eid, data_off, size, elem_start in iter_elements(header_data, segment_data_offset, len(header_data)):
        if eid == INFO:
            end = data_off + size
            for child_eid, child_off, child_size, _ in iter_elements(header_data, data_off, end):
                if child_eid == TIMESTAMP_SCALE:
                    timestamp_scale = read_uint(header_data, child_off, child_size)
                elif child_eid == DURATION:
                    duration_ticks = read_float(header_data, child_off, child_size)
        elif eid == TRACKS:
            tracks = parse_tracks(header_data, data_off, data_off + size)
        elif eid == CLUSTER:
            # elem_start is the byte offset in header_data where the Cluster
            # element ID begins -- everything before this is the MKV header
            # that FFmpeg needs for codec initialization when seeking.
            first_cluster_offset = elem_start
            break

    # Parse Cues from cues_data.
    # cues_data starts with the Cues element header (ID + size), so we must
    # first skip past it to reach the CuePoint children inside.
    cue_points = []
    ns_per_ms = 1_000_000
    scale_ms = timestamp_scale / ns_per_ms

    # Read the Cues element header to find where children start
    cues_eid, cues_id_end = read_element_id(cues_data, 0)
    if cues_eid != CUES:
        logger.warning("[ebml] Expected Cues element (0x%X), got 0x%X", CUES, cues_eid)
        return MKVCueIndex(
            duration_ms=duration_ticks * scale_ms,
            timestamp_scale=timestamp_scale,
            cue_points=[],
            segment_data_offset=segment_data_offset,
        )
    cues_size, cues_children_start = read_element_size(cues_data, cues_id_end)
    cues_children_end = (
        min(cues_children_start + cues_size, len(cues_data)) if cues_size != UNKNOWN_SIZE else len(cues_data)
    )

    for cp_eid, cp_off, cp_size, _ in iter_elements(cues_data, cues_children_start, cues_children_end):
        if cp_eid != CUE_POINT:
            continue

        cue_time_ticks = 0
        cluster_position = None
        cp_end = cp_off + cp_size

        for child_eid, child_off, child_size, _ in iter_elements(cues_data, cp_off, cp_end):
            if child_eid == CUE_TIME:
                cue_time_ticks = read_uint(cues_data, child_off, child_size)
            elif child_eid == CUE_TRACK_POSITIONS:
                ctp_end = child_off + child_size
                for ctp_eid, ctp_off, ctp_size, _ in iter_elements(cues_data, child_off, ctp_end):
                    if ctp_eid == CUE_CLUSTER_POSITION:
                        cluster_position = read_uint(cues_data, ctp_off, ctp_size)
                        break

        if cluster_position is not None:
            time_ms = cue_time_ticks * scale_ms
            cue_points.append((time_ms, cluster_position))

    cue_points.sort(key=lambda x: x[0])

    duration_ms = duration_ticks * scale_ms

    # Build synthetic seek header (MKV header with Segment size = UNKNOWN)
    seek_header = b""
    if first_cluster_offset > 0:
        try:
            seek_header = build_seek_header(header_data, first_cluster_offset)
        except Exception as e:
            logger.warning("[ebml] Failed to build seek header: %s", e)

    # Extract track metadata for size estimation and init segment generation
    audio_codec_id = ""
    audio_bitrate = 0
    audio_channels = 0
    audio_sample_rate = 0.0
    video_codec_id = ""
    video_codec_private = b""
    video_width = 0
    video_height = 0
    video_fps = 0.0
    video_default_duration_ns = 0

    audio_track = None
    for t in tracks:
        if t.track_type == TRACK_TYPE_AUDIO and not audio_track:
            audio_track = t
            audio_codec_id = t.codec_id
            audio_channels = t.channels
            audio_sample_rate = t.sample_rate
        elif t.track_type == TRACK_TYPE_VIDEO and not video_codec_id:
            video_codec_id = t.codec_id
            video_codec_private = t.codec_private
            video_width = t.pixel_width
            video_height = t.pixel_height
            video_default_duration_ns = t.default_duration_ns
            if t.default_duration_ns > 0:
                video_fps = 1_000_000_000.0 / t.default_duration_ns

    # Try to determine audio bitrate from the first audio frame in the Cluster
    if audio_track and first_cluster_offset > 0:
        frame_data = _extract_first_audio_frame(
            header_data,
            first_cluster_offset,
            audio_track.track_number,
        )
        if frame_data:
            if audio_codec_id == CODEC_ID_EAC3:
                audio_bitrate = parse_eac3_bitrate(frame_data) or 0
            elif audio_codec_id == CODEC_ID_AC3:
                audio_bitrate = parse_ac3_bitrate(frame_data) or 0

        if audio_bitrate > 0:
            logger.info(
                "[ebml] Detected audio: %s %d kbps %dch %.0fHz",
                audio_codec_id,
                audio_bitrate // 1000,
                audio_channels,
                audio_sample_rate,
            )

    index = MKVCueIndex(
        duration_ms=duration_ms,
        timestamp_scale=timestamp_scale,
        cue_points=cue_points,
        segment_data_offset=segment_data_offset,
        first_cluster_offset=first_cluster_offset,
        seek_header=seek_header,
        audio_codec_id=audio_codec_id,
        audio_bitrate=audio_bitrate,
        audio_channels=audio_channels,
        audio_sample_rate=audio_sample_rate,
        video_codec_id=video_codec_id,
        video_codec_private=video_codec_private,
        video_width=video_width,
        video_height=video_height,
        video_fps=video_fps,
        video_default_duration_ns=video_default_duration_ns,
    )

    logger.info(
        "[ebml] Built cue index: duration=%.1fs, %d cue points, segment_offset=%d, "
        "first_cluster=%d, seek_header=%d bytes, audio=%s @%dkbps",
        duration_ms / 1000,
        len(cue_points),
        segment_data_offset,
        first_cluster_offset,
        len(seek_header),
        audio_codec_id or "none",
        audio_bitrate // 1000 if audio_bitrate else 0,
    )
    return index


# =============================================================================
# Level 2: Track and Frame parsing for demuxing
# =============================================================================

# (Track type and codec ID constants are defined above in the High-level section
# since they are also needed by build_cue_index.)


@dataclass
class MKVTrack:
    """Metadata for a single track extracted from MKV Tracks element."""

    track_number: int = 0
    track_uid: int = 0
    track_type: int = 0  # 1=video, 2=audio, 17=subtitle
    codec_id: str = ""  # e.g. "V_MPEG4/ISO/AVC", "A_EAC3"
    codec_private: bytes = b""  # Codec-specific init data (avcC, AudioSpecificConfig, etc.)
    default_duration_ns: int = 0  # Default frame duration in nanoseconds
    codec_delay_ns: int = 0  # Codec delay in nanoseconds
    seek_pre_roll_ns: int = 0  # Seek pre-roll in nanoseconds

    # Video fields
    pixel_width: int = 0
    pixel_height: int = 0
    display_width: int = 0
    display_height: int = 0

    # Audio fields
    sample_rate: float = 0.0
    output_sample_rate: float = 0.0  # OutputSamplingFrequency (for SBR/HE-AAC)
    channels: int = 0
    bit_depth: int = 0

    @property
    def is_video(self) -> bool:
        return self.track_type == TRACK_TYPE_VIDEO

    @property
    def is_audio(self) -> bool:
        return self.track_type == TRACK_TYPE_AUDIO

    @property
    def is_subtitle(self) -> bool:
        return self.track_type == TRACK_TYPE_SUBTITLE

    @property
    def effective_sample_rate(self) -> float:
        """Return OutputSamplingFrequency if set, else SamplingFrequency."""
        return self.output_sample_rate if self.output_sample_rate > 0 else self.sample_rate

    @property
    def frame_duration_ms(self) -> float:
        """Default frame duration in milliseconds, or 0 if not set."""
        if self.default_duration_ns > 0:
            return self.default_duration_ns / 1_000_000.0
        return 0.0


@dataclass
class MKVFrame:
    """A single media frame extracted from an MKV Cluster."""

    track_number: int
    timestamp_ms: float  # Absolute timestamp in milliseconds
    is_keyframe: bool
    data: bytes
    duration_ms: float = 0.0  # Duration if known (from BlockDuration or DefaultDuration)


def read_string(data: bytes, pos: int, length: int) -> str:
    """Read a UTF-8 string of N bytes, stripping null terminators."""
    raw = data[pos : pos + length]
    return raw.rstrip(b"\x00").decode("utf-8", errors="replace")


def parse_tracks(data: bytes, start: int, end: int) -> list[MKVTrack]:
    """
    Parse the Tracks element children to extract track metadata.

    Args:
        data: Buffer containing the Tracks element children.
        start: Start offset of the Tracks children (after Tracks ID + size).
        end: End offset of the Tracks children.

    Returns:
        List of MKVTrack for each TrackEntry found.
    """
    tracks = []

    for eid, data_off, size, _ in iter_elements(data, start, end):
        if eid != TRACK_ENTRY:
            continue

        track = MKVTrack()
        te_end = data_off + size

        for child_eid, child_off, child_size, _ in iter_elements(data, data_off, te_end):
            if child_eid == TRACK_NUMBER:
                track.track_number = read_uint(data, child_off, child_size)
            elif child_eid == TRACK_UID:
                track.track_uid = read_uint(data, child_off, child_size)
            elif child_eid == TRACK_TYPE:
                track.track_type = read_uint(data, child_off, child_size)
            elif child_eid == CODEC_ID:
                track.codec_id = read_string(data, child_off, child_size)
            elif child_eid == CODEC_PRIVATE:
                track.codec_private = bytes(data[child_off : child_off + child_size])
            elif child_eid == DEFAULT_DURATION:
                track.default_duration_ns = read_uint(data, child_off, child_size)
            elif child_eid == CODEC_DELAY:
                track.codec_delay_ns = read_uint(data, child_off, child_size)
            elif child_eid == SEEK_PRE_ROLL:
                track.seek_pre_roll_ns = read_uint(data, child_off, child_size)
            elif child_eid == VIDEO:
                _parse_video_settings(data, child_off, child_off + child_size, track)
            elif child_eid == AUDIO:
                _parse_audio_settings(data, child_off, child_off + child_size, track)

        if track.track_number > 0:
            tracks.append(track)

    return tracks


def _parse_video_settings(data: bytes, start: int, end: int, track: MKVTrack) -> None:
    """Parse Video element children into MKVTrack fields."""
    for eid, off, size, _ in iter_elements(data, start, end):
        if eid == PIXEL_WIDTH:
            track.pixel_width = read_uint(data, off, size)
        elif eid == PIXEL_HEIGHT:
            track.pixel_height = read_uint(data, off, size)
        elif eid == DISPLAY_WIDTH:
            track.display_width = read_uint(data, off, size)
        elif eid == DISPLAY_HEIGHT:
            track.display_height = read_uint(data, off, size)


def _parse_audio_settings(data: bytes, start: int, end: int, track: MKVTrack) -> None:
    """Parse Audio element children into MKVTrack fields."""
    for eid, off, size, _ in iter_elements(data, start, end):
        if eid == SAMPLING_FREQUENCY:
            track.sample_rate = read_float(data, off, size)
        elif eid == OUTPUT_SAMPLING_FREQUENCY:
            track.output_sample_rate = read_float(data, off, size)
        elif eid == CHANNELS:
            track.channels = read_uint(data, off, size)
        elif eid == BIT_DEPTH:
            track.bit_depth = read_uint(data, off, size)


def parse_block_header(data: bytes, pos: int) -> tuple[int, int, int, int]:
    """
    Parse the header of a SimpleBlock or Block element.

    The block header starts with:
    - Track number (VINT, variable length)
    - Relative timecode (int16, signed, big-endian)
    - Flags byte (keyframe, lacing, etc.)

    Args:
        data: Buffer containing the block data.
        pos: Start of the block data (after element ID + size).

    Returns:
        (track_number, relative_timecode, flags, header_end_pos)
        flags bit layout for SimpleBlock:
          - bit 7 (0x80): keyframe
          - bits 2-1 (0x06): lacing (0=none, 1=Xiph, 2=fixed, 3=EBML)
          - bit 0 (0x01): discardable
    """
    # Track number is a VINT (but uses the raw value, not the size-masked value)
    _, track_number, pos2 = read_vint(data, pos)
    # For track number, we use the raw VINT value with marker bit removed
    # Actually, the Matroska spec says track number in Block uses the same
    # VINT encoding as element sizes, so the marker-stripped value is correct.

    # Relative timecode: signed 16-bit big-endian
    timecode_raw = (data[pos2] << 8) | data[pos2 + 1]
    if timecode_raw >= 0x8000:
        timecode_raw -= 0x10000
    pos3 = pos2 + 2

    # Flags
    flags = data[pos3]
    pos4 = pos3 + 1

    return track_number, timecode_raw, flags, pos4


def extract_block_frames(data: bytes, pos: int, block_size: int) -> list[tuple[int, int, int, list[bytes]]]:
    """
    Parse a SimpleBlock or Block and extract the frame data.

    Handles all four lacing modes: no lacing, Xiph, fixed-size, and EBML.

    Args:
        data: Buffer containing the block.
        pos: Start of the block data (after element ID + size).
        block_size: Total size of the block data.

    Returns:
        List of (track_number, relative_timecode, flags, [frame_bytes, ...])
    """
    block_end = pos + block_size
    track_number, rel_timecode, flags, header_end = parse_block_header(data, pos)
    lacing = (flags >> 1) & 0x03  # bits 2-1

    if lacing == 0:
        # No lacing: single frame = rest of block
        frame_data = bytes(data[header_end:block_end])
        return [(track_number, rel_timecode, flags, [frame_data])]

    # Laced: first byte after header is the number of frames minus one
    num_frames = data[header_end] + 1
    lace_pos = header_end + 1

    if lacing == 2:
        # Fixed-size lacing: all frames are the same size
        remaining = block_end - lace_pos
        frame_size = remaining // num_frames
        frames = []
        for _ in range(num_frames):
            frames.append(bytes(data[lace_pos : lace_pos + frame_size]))
            lace_pos += frame_size
        return [(track_number, rel_timecode, flags, frames)]

    elif lacing == 1:
        # Xiph lacing: sizes encoded as sum of 255s + remainder
        frame_sizes = []
        for _ in range(num_frames - 1):
            size = 0
            while lace_pos < block_end:
                val = data[lace_pos]
                lace_pos += 1
                size += val
                if val < 255:
                    break
            frame_sizes.append(size)

        # Last frame gets remaining bytes.
        # lace_pos is already past the size bytes; frame data starts at lace_pos.
        frames = []
        frame_data_start = lace_pos
        for sz in frame_sizes:
            frames.append(bytes(data[frame_data_start : frame_data_start + sz]))
            frame_data_start += sz
        frames.append(bytes(data[frame_data_start:block_end]))
        return [(track_number, rel_timecode, flags, frames)]

    elif lacing == 3:
        # EBML lacing: first size is VINT, subsequent are signed VINT deltas
        frame_sizes = []
        # First frame size
        _, first_size, lace_pos = read_vint(data, lace_pos)
        frame_sizes.append(first_size)
        prev_size = first_size

        for _ in range(num_frames - 2):
            # Read VINT for delta (signed: subtract midpoint)
            raw, value, lace_pos = read_vint(data, lace_pos)
            # Determine VINT length to compute the sign bias
            vint_len = 0
            test = raw
            while test > 0:
                test >>= 8
                vint_len += 1
            if vint_len == 0:
                vint_len = 1
            # Signed delta: value - ((2^(7*vint_len - 1)) - 1)
            bias = (1 << (7 * vint_len - 1)) - 1
            delta = value - bias
            current_size = prev_size + delta
            frame_sizes.append(current_size)
            prev_size = current_size

        frames = []
        frame_data_start = lace_pos
        for sz in frame_sizes:
            frames.append(bytes(data[frame_data_start : frame_data_start + sz]))
            frame_data_start += sz
        frames.append(bytes(data[frame_data_start:block_end]))
        return [(track_number, rel_timecode, flags, frames)]

    return [(track_number, rel_timecode, flags, [bytes(data[header_end:block_end])])]


def parse_cluster_frames(
    data: bytes,
    cluster_start: int,
    cluster_end: int,
    timestamp_scale_ns: int,
) -> tuple[float, list[MKVFrame]]:
    """
    Parse a single Cluster element and extract all frames.

    Args:
        data: Buffer containing the Cluster element children.
        cluster_start: Start of Cluster children (after Cluster ID + size).
        cluster_end: End of Cluster data.
        timestamp_scale_ns: Nanoseconds per timestamp tick.

    Returns:
        (cluster_timestamp_ms, list_of_MKVFrame)
    """
    scale_ms = timestamp_scale_ns / 1_000_000.0
    cluster_timecode = 0
    frames = []

    for eid, data_off, size, _ in iter_elements(data, cluster_start, cluster_end):
        if eid == CLUSTER_TIMESTAMP:
            cluster_timecode = read_uint(data, data_off, size)

        elif eid == SIMPLE_BLOCK:
            for track_num, rel_tc, flags, frame_list in extract_block_frames(data, data_off, size):
                is_kf = bool(flags & 0x80)
                abs_ts_ms = (cluster_timecode + rel_tc) * scale_ms
                for frame_data in frame_list:
                    frames.append(
                        MKVFrame(
                            track_number=track_num,
                            timestamp_ms=abs_ts_ms,
                            is_keyframe=is_kf,
                            data=frame_data,
                        )
                    )

        elif eid == BLOCK_GROUP:
            _parse_block_group(data, data_off, data_off + size, cluster_timecode, scale_ms, frames)

    cluster_ts_ms = cluster_timecode * scale_ms
    return cluster_ts_ms, frames


def _parse_block_group(
    data: bytes,
    start: int,
    end: int,
    cluster_timecode: int,
    scale_ms: float,
    frames: list[MKVFrame],
) -> None:
    """Parse a BlockGroup and append frames to the list."""
    block_data_off = 0
    block_data_size = 0
    duration_ticks = 0

    for eid, off, size, _ in iter_elements(data, start, end):
        if eid == BLOCK:
            block_data_off = off
            block_data_size = size
        elif eid == BLOCK_DURATION:
            duration_ticks = read_uint(data, off, size)

    if block_data_off == 0:
        return

    for track_num, rel_tc, flags, frame_list in extract_block_frames(data, block_data_off, block_data_size):
        # Block within BlockGroup: keyframe flag is NOT in the flags byte
        # (unlike SimpleBlock). Keyframe is inferred from context or absence
        # of ReferenceBlock. For simplicity, treat first block as keyframe if
        # there's no ReferenceBlock -- but we don't parse that here.
        # Default to non-keyframe for BlockGroup blocks.
        abs_ts_ms = (cluster_timecode + rel_tc) * scale_ms
        dur_ms = duration_ticks * scale_ms if duration_ticks > 0 else 0.0
        for frame_data in frame_list:
            frames.append(
                MKVFrame(
                    track_number=track_num,
                    timestamp_ms=abs_ts_ms,
                    is_keyframe=False,
                    data=frame_data,
                    duration_ms=dur_ms,
                )
            )
