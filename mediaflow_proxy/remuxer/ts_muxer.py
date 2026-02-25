"""
Pure Python fMP4 to MPEG-TS remuxer.

This module provides functionality to remux fragmented MP4 (fMP4) segments
to MPEG-TS format without requiring FFmpeg as an external dependency.

Supports:
- H.264/AVC video (NAL unit conversion from length-prefixed to Annex B)
- H.265/HEVC video (NAL unit conversion with VPS/SPS/PPS handling)
- AAC audio (raw AAC frames wrapped with ADTS headers)

The implementation reuses MP4Parser/MP4Atom from drm/decrypter.py for MP4 box parsing.
"""

import struct
import logging
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

# ============================================================================
# MPEG-TS Constants
# ============================================================================

TS_PACKET_SIZE = 188
TS_HEADER_SIZE = 4
TS_SYNC_BYTE = 0x47
TS_STUFFING_BYTE = 0xFF

# PID assignments
PID_PAT = 0x0000
PID_PMT = 0x1000
PID_VIDEO = 0x0100
PID_AUDIO = 0x0101
PID_NULL = 0x1FFF

# Stream types for PMT
STREAM_TYPE_H264 = 0x1B
STREAM_TYPE_H265 = 0x24
STREAM_TYPE_AAC = 0x0F

# TS clock frequency (90kHz)
TS_CLOCK_HZ = 90000

# H.264 NAL unit types
NAL_TYPE_SLICE = 1
NAL_TYPE_DPA = 2
NAL_TYPE_DPB = 3
NAL_TYPE_DPC = 4
NAL_TYPE_IDR = 5  # Keyframe
NAL_TYPE_SEI = 6
NAL_TYPE_SPS = 7
NAL_TYPE_PPS = 8
NAL_TYPE_AUD = 9  # Access Unit Delimiter

# H.265 NAL unit types
HEVC_NAL_VPS = 32
HEVC_NAL_SPS = 33
HEVC_NAL_PPS = 34
HEVC_NAL_AUD = 35
HEVC_NAL_IDR_W_RADL = 19
HEVC_NAL_IDR_N_LP = 20
HEVC_NAL_CRA_NUT = 21

# Annex B start codes
START_CODE_3 = b"\x00\x00\x01"
START_CODE_4 = b"\x00\x00\x00\x01"

# AAC sample rate index table
AAC_SAMPLE_RATES = [96000, 88200, 64000, 48000, 44100, 32000, 24000, 22050, 16000, 12000, 11025, 8000, 7350, 0, 0, 0]


# ============================================================================
# Data Classes
# ============================================================================


@dataclass
class CodecConfig:
    """Container for codec configuration extracted from moov/stsd."""

    # Video config
    video_codec: Optional[str] = None  # 'h264' or 'h265'
    video_track_id: int = 0
    video_timescale: int = 90000
    width: int = 0
    height: int = 0
    sps_list: list = field(default_factory=list)  # H.264 SPS NAL units
    pps_list: list = field(default_factory=list)  # H.264 PPS NAL units
    vps_list: list = field(default_factory=list)  # H.265 VPS NAL units
    nal_length_size: int = 4  # Usually 4 bytes for length prefix

    # Audio config
    audio_codec: Optional[str] = None  # 'aac'
    audio_track_id: int = 0
    audio_timescale: int = 48000
    sample_rate: int = 48000
    channel_count: int = 2
    aac_profile: int = 2  # 1=Main, 2=LC, 3=SSR, 4=LTP
    audio_specific_config: bytes = b""


@dataclass
class Sample:
    """Represents a single media sample from mdat."""

    data: bytes
    duration: int  # In track timescale
    pts: int  # Presentation timestamp in track timescale
    dts: int  # Decode timestamp in track timescale
    is_keyframe: bool = False
    cts_offset: int = 0  # Composition time offset


@dataclass
class TrackSamples:
    """Container for samples from a single track."""

    track_id: int
    track_type: str  # 'video' or 'audio'
    timescale: int
    samples: list = field(default_factory=list)


# ============================================================================
# CRC32 for MPEG-TS
# ============================================================================

# Pre-computed CRC32 table for MPEG-2 (polynomial 0x04C11DB7)
_CRC32_TABLE = None


def _init_crc32_table():
    """Initialize CRC32 lookup table for MPEG-2."""
    global _CRC32_TABLE
    if _CRC32_TABLE is not None:
        return

    _CRC32_TABLE = []
    for i in range(256):
        crc = i << 24
        for _ in range(8):
            if crc & 0x80000000:
                crc = (crc << 1) ^ 0x04C11DB7
            else:
                crc <<= 1
        _CRC32_TABLE.append(crc & 0xFFFFFFFF)


def crc32_mpeg2(data: bytes) -> int:
    """Calculate CRC32 for MPEG-2 TS sections."""
    _init_crc32_table()
    crc = 0xFFFFFFFF
    for byte in data:
        crc = (_CRC32_TABLE[((crc >> 24) ^ byte) & 0xFF] ^ (crc << 8)) & 0xFFFFFFFF
    return crc


# ============================================================================
# MP4 Box Parsing (minimal subset, reusing patterns from decrypter.py)
# ============================================================================


def read_box(data: memoryview, offset: int) -> Optional[tuple[bytes, int, memoryview]]:
    """
    Read a single MP4 box at the given offset.

    Returns:
        Tuple of (box_type, box_size, box_data) or None if no more boxes.
    """
    if offset + 8 > len(data):
        return None

    size, box_type = struct.unpack_from(">I4s", data, offset)
    header_size = 8

    if size == 1:  # Extended size
        if offset + 16 > len(data):
            return None
        size = struct.unpack_from(">Q", data, offset + 8)[0]
        header_size = 16
    elif size == 0:  # Box extends to end of file
        size = len(data) - offset

    if offset + size > len(data):
        return None

    box_data = data[offset + header_size : offset + size]
    return box_type, size, box_data


def find_box(data: memoryview, box_type: bytes) -> Optional[memoryview]:
    """Find a box by type within the data."""
    offset = 0
    while offset < len(data):
        result = read_box(data, offset)
        if result is None:
            break
        found_type, size, box_data = result
        if found_type == box_type:
            return box_data
        offset += size
    return None


def iter_boxes(data: memoryview):
    """Iterate over all boxes in the data."""
    offset = 0
    while offset < len(data):
        result = read_box(data, offset)
        if result is None:
            break
        box_type, size, box_data = result
        yield box_type, box_data
        offset += size


# ============================================================================
# Codec Config Extraction (Todo 1)
# ============================================================================


def extract_codec_config(init_segment: bytes) -> CodecConfig:
    """
    Extract codec configuration from fMP4 init segment (moov box).

    Parses:
    - avcC box for H.264 SPS/PPS
    - hvcC box for H.265 VPS/SPS/PPS
    - esds/mp4a for AAC audio config

    Args:
        init_segment: The fMP4 initialization segment bytes.

    Returns:
        CodecConfig with extracted codec parameters.
    """
    config = CodecConfig()
    data = memoryview(init_segment)

    # Find moov box
    moov_data = find_box(data, b"moov")
    if moov_data is None:
        logger.warning("No moov box found in init segment")
        return config

    # Process each trak box
    for box_type, box_data in iter_boxes(moov_data):
        if box_type == b"trak":
            _parse_trak_for_codec_config(box_data, config)

    return config


def _parse_trak_for_codec_config(trak_data: memoryview, config: CodecConfig):
    """Parse a trak box to extract codec configuration."""
    track_id = 0
    timescale = 90000
    handler_type = None

    # First pass: get track ID, timescale, and handler type
    for box_type, box_data in iter_boxes(trak_data):
        if box_type == b"tkhd":
            # Track header: extract track ID
            version = box_data[0]
            if version == 0:
                track_id = struct.unpack_from(">I", box_data, 12)[0]
            else:
                track_id = struct.unpack_from(">I", box_data, 20)[0]

        elif box_type == b"mdia":
            # Media box
            for mdia_type, mdia_data in iter_boxes(box_data):
                if mdia_type == b"mdhd":
                    # Media header: extract timescale
                    version = mdia_data[0]
                    if version == 0:
                        timescale = struct.unpack_from(">I", mdia_data, 12)[0]
                    else:
                        timescale = struct.unpack_from(">I", mdia_data, 20)[0]

                elif mdia_type == b"hdlr":
                    # Handler reference: determine track type
                    handler_type = bytes(mdia_data[8:12])

                elif mdia_type == b"minf":
                    # Media information
                    for minf_type, minf_data in iter_boxes(mdia_data):
                        if minf_type == b"stbl":
                            # Sample table
                            _parse_stbl_for_codec_config(minf_data, config, track_id, timescale, handler_type)


def _parse_stbl_for_codec_config(
    stbl_data: memoryview, config: CodecConfig, track_id: int, timescale: int, handler_type: bytes
):
    """Parse stbl box for codec configuration."""
    for box_type, box_data in iter_boxes(stbl_data):
        if box_type == b"stsd":
            # Sample description box
            # Skip version(1) + flags(3) + entry_count(4) = 8 bytes
            entry_count = struct.unpack_from(">I", box_data, 4)[0]
            offset = 8

            for _ in range(entry_count):
                if offset + 8 > len(box_data):
                    break

                entry_size, entry_type = struct.unpack_from(">I4s", box_data, offset)
                entry_data = box_data[offset + 8 : offset + entry_size]

                _parse_sample_entry(entry_type, entry_data, config, track_id, timescale, handler_type)
                offset += entry_size


def _parse_sample_entry(
    entry_type: bytes, entry_data: memoryview, config: CodecConfig, track_id: int, timescale: int, handler_type: bytes
):
    """Parse a sample entry for codec configuration."""

    # Video sample entries
    if entry_type in (b"avc1", b"avc3"):
        config.video_codec = "h264"
        config.video_track_id = track_id
        config.video_timescale = timescale

        # Video sample entry: skip to width/height
        # 6 bytes reserved + 2 bytes data_reference_index + 2 bytes pre_defined + 2 bytes reserved
        # + 12 bytes pre_defined + 2 bytes width + 2 bytes height = 78 bytes for video entry header
        if len(entry_data) >= 70:
            config.width = struct.unpack_from(">H", entry_data, 24)[0]
            config.height = struct.unpack_from(">H", entry_data, 26)[0]

        # Find avcC box within the sample entry
        _find_avcc(entry_data, config)

    elif entry_type == b"encv":
        # Encrypted video — determine original codec from sinf/frma or by probing
        config.video_track_id = track_id
        config.video_timescale = timescale
        if len(entry_data) >= 70:
            config.width = struct.unpack_from(">H", entry_data, 24)[0]
            config.height = struct.unpack_from(">H", entry_data, 26)[0]

        # Try to determine original codec: check for avcC first, then hvcC
        _find_avcc(entry_data, config)
        if config.sps_list:
            config.video_codec = "h264"
        else:
            _find_hvcc(entry_data, config)
            if config.vps_list or config.sps_list:
                config.video_codec = "h265"

    elif entry_type in (b"hev1", b"hvc1"):
        config.video_codec = "h265"
        config.video_track_id = track_id
        config.video_timescale = timescale

        if len(entry_data) >= 70:
            config.width = struct.unpack_from(">H", entry_data, 24)[0]
            config.height = struct.unpack_from(">H", entry_data, 26)[0]

        # Find hvcC box
        _find_hvcc(entry_data, config)

    # Audio sample entries
    elif entry_type in (b"mp4a", b"enca"):
        config.audio_codec = "aac"
        config.audio_track_id = track_id
        config.audio_timescale = timescale

        # Audio sample entry structure:
        # 6 reserved + 2 data_ref_index + 8 reserved + 2 channels + 2 sample_size +
        # 2 pre_defined + 2 reserved + 4 sample_rate (16.16 fixed point)
        # Channels at offset 16, sample_rate at offset 24
        if len(entry_data) >= 28:
            config.channel_count = struct.unpack_from(">H", entry_data, 16)[0]
            # Sample rate is stored as 16.16 fixed point at offset 24
            sample_rate_fixed = struct.unpack_from(">I", entry_data, 24)[0]
            config.sample_rate = sample_rate_fixed >> 16
            config.audio_timescale = config.sample_rate

        # Find esds box for AAC config
        _find_esds(entry_data, config)


def _find_avcc(data: memoryview, config: CodecConfig):
    """Find and parse avcC box for H.264 SPS/PPS."""
    # Video sample entry fixed fields are 78 bytes:
    # 6 reserved + 2 data_ref_index + 2 pre_defined + 2 reserved + 12 pre_defined +
    # 2 width + 2 height + 4 horizres + 4 vertres + 4 reserved + 2 frame_count +
    # 32 compressorname + 2 depth + 2 pre_defined = 78 bytes
    search_offset = 78

    for box_type, box_data in iter_boxes(data[search_offset:] if search_offset < len(data) else memoryview(b"")):
        if box_type == b"avcC":
            _parse_avcc(box_data, config)
            return
        elif box_type == b"sinf":
            # Encrypted - look for avcC inside sinf/schi
            for sinf_type, sinf_data in iter_boxes(box_data):
                if sinf_type == b"schi":
                    for schi_type, schi_data in iter_boxes(sinf_data):
                        if schi_type == b"avcC":
                            _parse_avcc(schi_data, config)
                            return


def _parse_avcc(avcc_data: memoryview, config: CodecConfig):
    """
    Parse avcC box to extract SPS and PPS NAL units.

    avcC structure:
    - configurationVersion (1 byte)
    - AVCProfileIndication (1 byte)
    - profile_compatibility (1 byte)
    - AVCLevelIndication (1 byte)
    - lengthSizeMinusOne (6 bits reserved + 2 bits) -> NAL length size
    - numOfSPS (3 bits reserved + 5 bits)
    - SPS entries: [length(2) + data] * numOfSPS
    - numOfPPS (1 byte)
    - PPS entries: [length(2) + data] * numOfPPS
    """
    if len(avcc_data) < 7:
        return

    config.nal_length_size = (avcc_data[4] & 0x03) + 1
    num_sps = avcc_data[5] & 0x1F

    offset = 6
    config.sps_list = []

    for _ in range(num_sps):
        if offset + 2 > len(avcc_data):
            break
        sps_length = struct.unpack_from(">H", avcc_data, offset)[0]
        offset += 2
        if offset + sps_length > len(avcc_data):
            break
        config.sps_list.append(bytes(avcc_data[offset : offset + sps_length]))
        offset += sps_length

    if offset >= len(avcc_data):
        return

    num_pps = avcc_data[offset]
    offset += 1
    config.pps_list = []

    for _ in range(num_pps):
        if offset + 2 > len(avcc_data):
            break
        pps_length = struct.unpack_from(">H", avcc_data, offset)[0]
        offset += 2
        if offset + pps_length > len(avcc_data):
            break
        config.pps_list.append(bytes(avcc_data[offset : offset + pps_length]))
        offset += pps_length


def _find_hvcc(data: memoryview, config: CodecConfig):
    """Find and parse hvcC box for H.265 VPS/SPS/PPS."""
    # Video sample entry fixed fields are 78 bytes (same as AVC)
    search_offset = 78

    for box_type, box_data in iter_boxes(data[search_offset:] if search_offset < len(data) else memoryview(b"")):
        if box_type == b"hvcC":
            _parse_hvcc(box_data, config)
            return
        elif box_type == b"sinf":
            # Encrypted - look for hvcC inside sinf/schi
            for sinf_type, sinf_data in iter_boxes(box_data):
                if sinf_type == b"schi":
                    for schi_type, schi_data in iter_boxes(sinf_data):
                        if schi_type == b"hvcC":
                            _parse_hvcc(schi_data, config)
                            return


def _parse_hvcc(hvcc_data: memoryview, config: CodecConfig):
    """
    Parse hvcC box to extract VPS, SPS, and PPS NAL units.

    hvcC is more complex than avcC but follows similar patterns.
    """
    if len(hvcc_data) < 23:
        return

    config.nal_length_size = (hvcc_data[21] & 0x03) + 1
    num_arrays = hvcc_data[22]

    offset = 23
    config.vps_list = []
    config.sps_list = []
    config.pps_list = []

    for _ in range(num_arrays):
        if offset + 3 > len(hvcc_data):
            break

        nal_type = hvcc_data[offset] & 0x3F
        num_nalus = struct.unpack_from(">H", hvcc_data, offset + 1)[0]
        offset += 3

        for _ in range(num_nalus):
            if offset + 2 > len(hvcc_data):
                break
            nalu_length = struct.unpack_from(">H", hvcc_data, offset)[0]
            offset += 2
            if offset + nalu_length > len(hvcc_data):
                break

            nalu_data = bytes(hvcc_data[offset : offset + nalu_length])
            offset += nalu_length

            if nal_type == HEVC_NAL_VPS:
                config.vps_list.append(nalu_data)
            elif nal_type == HEVC_NAL_SPS:
                config.sps_list.append(nalu_data)
            elif nal_type == HEVC_NAL_PPS:
                config.pps_list.append(nalu_data)


def _find_esds(data: memoryview, config: CodecConfig):
    """Find and parse esds box for AAC configuration."""
    # Audio sample entry fixed fields are 28 bytes:
    # 6 reserved + 2 data_ref_index + 8 reserved + 2 channels + 2 sample_size +
    # 2 pre_defined + 2 reserved + 4 sample_rate = 28 bytes
    search_offset = 28

    for box_type, box_data in iter_boxes(data[search_offset:] if search_offset < len(data) else memoryview(b"")):
        if box_type == b"esds":
            _parse_esds(box_data, config)
            return


def _parse_esds(esds_data: memoryview, config: CodecConfig):
    """
    Parse esds box to extract AAC audio specific config.

    esds contains ES_Descriptor with DecoderConfigDescriptor and
    DecoderSpecificInfo (AudioSpecificConfig for AAC).
    """
    if len(esds_data) < 4:
        return

    # Skip version + flags (4 bytes)
    offset = 4

    # Parse ES_Descriptor
    offset = _skip_descriptor_header(esds_data, offset)
    if offset < 0 or offset + 3 > len(esds_data):
        return

    # Skip ES_ID (2 bytes) and flags (1 byte)
    offset += 3

    # Look for DecoderConfigDescriptor (tag 0x04)
    if offset >= len(esds_data) or esds_data[offset] != 0x04:
        return

    offset = _skip_descriptor_header(esds_data, offset)
    if offset < 0 or offset + 13 > len(esds_data):
        return

    # Skip objectTypeIndication(1) + streamType(1) + bufferSizeDB(3) + maxBitrate(4) + avgBitrate(4) = 13 bytes
    offset += 13

    # Look for DecoderSpecificInfo (tag 0x05) - contains AudioSpecificConfig
    if offset >= len(esds_data) or esds_data[offset] != 0x05:
        return

    offset = _skip_descriptor_header(esds_data, offset)
    if offset < 0 or offset + 2 > len(esds_data):
        return

    # AudioSpecificConfig (at least 2 bytes)
    config.audio_specific_config = bytes(esds_data[offset:])

    # Parse AudioSpecificConfig to get profile and sample rate
    # First 5 bits: audioObjectType
    # Next 4 bits: samplingFrequencyIndex
    # Next 4 bits: channelConfiguration
    asc = esds_data[offset:]
    if len(asc) >= 2:
        audio_object_type = (asc[0] >> 3) & 0x1F
        config.aac_profile = audio_object_type

        freq_index = ((asc[0] & 0x07) << 1) | ((asc[1] >> 7) & 0x01)
        if freq_index < len(AAC_SAMPLE_RATES) and AAC_SAMPLE_RATES[freq_index] > 0:
            config.sample_rate = AAC_SAMPLE_RATES[freq_index]

        channel_config = (asc[1] >> 3) & 0x0F
        if channel_config > 0:
            config.channel_count = channel_config


def _skip_descriptor_header(data: memoryview, offset: int) -> int:
    """Skip a descriptor tag and variable-length size field."""
    if offset >= len(data):
        return -1

    # Skip tag byte
    offset += 1

    # Variable-length size (1-4 bytes, each byte has MSB set if more bytes follow)
    for _ in range(4):
        if offset >= len(data):
            return -1
        byte = data[offset]
        offset += 1
        if not (byte & 0x80):
            break

    return offset


# ============================================================================
# NAL Unit Conversion (Todo 2)
# ============================================================================


def convert_length_prefixed_to_annex_b(
    data: bytes, nal_length_size: int, codec: str, sps_list: list, pps_list: list, vps_list: list = None
) -> tuple[bytes, bool]:
    """
    Convert length-prefixed NAL units to Annex B format with start codes.

    Also determines if this sample is a keyframe and prepends SPS/PPS (and VPS for H.265)
    before keyframes.

    Args:
        data: The sample data with length-prefixed NAL units.
        nal_length_size: Size of the length prefix (usually 4).
        codec: 'h264' or 'h265'
        sps_list: List of SPS NAL units (already in raw NAL format without start code)
        pps_list: List of PPS NAL units
        vps_list: List of VPS NAL units (H.265 only)

    Returns:
        Tuple of (converted_data, is_keyframe)
    """
    result = bytearray()
    is_keyframe = False
    has_idr = False

    # First pass: check for keyframe and collect NAL units
    nal_units = []
    temp_offset = 0
    while temp_offset + nal_length_size <= len(data):
        if nal_length_size == 4:
            nal_size = struct.unpack_from(">I", data, temp_offset)[0]
        elif nal_length_size == 3:
            nal_size = (data[temp_offset] << 16) | (data[temp_offset + 1] << 8) | data[temp_offset + 2]
        elif nal_length_size == 2:
            nal_size = struct.unpack_from(">H", data, temp_offset)[0]
        else:
            nal_size = data[temp_offset]

        temp_offset += nal_length_size

        if temp_offset + nal_size > len(data):
            break

        nal_data = data[temp_offset : temp_offset + nal_size]
        if len(nal_data) > 0:
            nal_type = _get_nal_type(nal_data, codec)
            if _is_keyframe_nal(nal_type, codec):
                has_idr = True
            nal_units.append(nal_data)

        temp_offset += nal_size

    is_keyframe = has_idr

    # Prepend Access Unit Delimiter (AUD) as the first NAL in each access unit.
    # ExoPlayer's H264Reader/H265Reader uses AUDs to detect access unit boundaries.
    # Without AUDs, ExoPlayer cannot properly delimit video frames in the elementary
    # stream, which prevents the video decoder from receiving any samples.
    if codec == "h264":
        # H.264 AUD: NAL type 9, primary_pic_type in top 3 bits of second byte
        # 0xF0 = all picture types allowed (primary_pic_type = 7, reserved bits = 0)
        result.extend(START_CODE_4)
        result.extend(b"\x09\xf0")
    elif codec == "h265":
        # H.265 AUD: NAL type 35 (AUD_NUT), encoded as 2-byte NAL header + 1 byte pic_type
        # NAL header: (35 << 1) = 0x46, nuh_layer_id=0, nuh_temporal_id_plus1=1 → 0x46 0x01
        # pic_type: 0x50 = pic_type 2 (I, P, B slices allowed) in top 3 bits
        result.extend(START_CODE_4)
        result.extend(b"\x46\x01\x50")

    # If keyframe, prepend codec parameter sets (after AUD)
    if has_idr:
        if codec == "h265" and vps_list:
            for vps in vps_list:
                result.extend(START_CODE_4)
                result.extend(vps)
        for sps in sps_list:
            result.extend(START_CODE_4)
            result.extend(sps)
        for pps in pps_list:
            result.extend(START_CODE_4)
            result.extend(pps)

    # Add all NAL units with start codes
    for nal_data in nal_units:
        result.extend(START_CODE_4)
        result.extend(nal_data)

    return bytes(result), is_keyframe


def _get_nal_type(nal_data: bytes, codec: str) -> int:
    """Get the NAL unit type from the first byte."""
    if len(nal_data) == 0:
        return -1

    if codec == "h264":
        return nal_data[0] & 0x1F
    else:  # h265
        return (nal_data[0] >> 1) & 0x3F


def _is_keyframe_nal(nal_type: int, codec: str) -> bool:
    """Check if this NAL type indicates a keyframe."""
    if codec == "h264":
        return nal_type == NAL_TYPE_IDR
    else:  # h265
        return nal_type in (HEVC_NAL_IDR_W_RADL, HEVC_NAL_IDR_N_LP, HEVC_NAL_CRA_NUT)


# ============================================================================
# ADTS Header Generation (Todo 3)
# ============================================================================


def make_adts_header(frame_length: int, profile: int, sample_rate: int, channels: int) -> bytes:
    """
    Generate a 7-byte ADTS header for an AAC frame.

    Args:
        frame_length: Length of the AAC frame data (without ADTS header)
        profile: AAC profile (1=Main, 2=LC, 3=SSR, 4=LTP)
        sample_rate: Sample rate in Hz
        channels: Number of channels

    Returns:
        7-byte ADTS header
    """
    # Find sample rate index
    freq_index = 4  # Default to 44100
    for i, rate in enumerate(AAC_SAMPLE_RATES):
        if rate == sample_rate:
            freq_index = i
            break

    # ADTS profile is AAC profile - 1
    adts_profile = max(0, min(3, profile - 1))

    # Total frame length including header
    full_length = frame_length + 7

    # Build ADTS header (7 bytes)
    # Syncword: 0xFFF (12 bits)
    # ID: 0 (MPEG-4), 1 (MPEG-2) - use 0 (1 bit)
    # Layer: 00 (2 bits)
    # Protection absent: 1 (no CRC) (1 bit)
    # Profile: 2 bits (00=Main, 01=LC, 10=SSR, 11=LTP)
    # Sampling frequency index: 4 bits
    # Private bit: 0 (1 bit)
    # Channel configuration: 3 bits
    # Original/copy: 0 (1 bit)
    # Home: 0 (1 bit)
    # Copyright ID bit: 0 (1 bit)
    # Copyright ID start: 0 (1 bit)
    # Frame length: 13 bits
    # Buffer fullness: 0x7FF (11 bits) - variable bitrate
    # Number of AAC frames - 1: 00 (2 bits)

    header = bytearray(7)

    # Byte 0: syncword high (0xFF)
    header[0] = 0xFF

    # Byte 1: syncword low (4 bits) + ID + layer + protection_absent
    # 0xF (syncword) | 0 (ID=MPEG-4) | 00 (layer) | 1 (no CRC) = 0xF1
    header[1] = 0xF1

    # Byte 2: profile(2) + freq_index(4) + private(1) + channel_config_high(1)
    header[2] = ((adts_profile & 0x03) << 6) | ((freq_index & 0x0F) << 2) | ((channels >> 2) & 0x01)

    # Byte 3: channel_config_low(2) + original(1) + home(1) + copyright_id(1) + copyright_start(1) + frame_len_high(2)
    header[3] = ((channels & 0x03) << 6) | ((full_length >> 11) & 0x03)

    # Byte 4: frame_len_mid (8 bits)
    header[4] = (full_length >> 3) & 0xFF

    # Byte 5: frame_len_low(3) + buffer_fullness_high(5)
    header[5] = ((full_length & 0x07) << 5) | 0x1F  # 0x1F = high 5 bits of 0x7FF

    # Byte 6: buffer_fullness_low(6) + num_frames(2)
    header[6] = 0xFC  # 0x3F << 2 = low 6 bits of 0x7FF, 0 frames - 1

    return bytes(header)


def wrap_aac_frame_with_adts(frame_data: bytes, config: CodecConfig) -> bytes:
    """Wrap a raw AAC frame with ADTS header."""
    header = make_adts_header(len(frame_data), config.aac_profile, config.sample_rate, config.channel_count)
    return header + frame_data


# ============================================================================
# PES Packet Construction (Todo 4)
# ============================================================================


def build_pes_packet(stream_id: int, data: bytes, pts: Optional[int], dts: Optional[int]) -> bytes:
    """
    Build a PES (Packetized Elementary Stream) packet.

    Args:
        stream_id: PES stream ID (0xE0 for video, 0xC0 for audio)
        data: The elementary stream data (video NALs or audio frames)
        pts: Presentation timestamp in 90kHz clock (or None)
        dts: Decode timestamp in 90kHz clock (or None if same as PTS)

    Returns:
        Complete PES packet bytes
    """
    result = bytearray()

    # PES start code: 00 00 01
    result.extend(b"\x00\x00\x01")

    # Stream ID
    result.append(stream_id)

    # Calculate header size for PES packet length field
    has_pts = pts is not None
    has_dts = dts is not None and dts != pts

    optional_header_size = 3  # PES header flags + data length
    if has_pts:
        optional_header_size += 5  # PTS takes 5 bytes
    if has_dts:
        optional_header_size += 5  # DTS takes 5 bytes

    # PES packet length (0 for unbounded video streams, or actual size for audio)
    # For video, we use 0 to indicate unbounded
    if stream_id >= 0xE0:  # Video
        pes_packet_length = 0
    else:
        total_len = optional_header_size + len(data)
        pes_packet_length = min(total_len, 65535)  # Cap at max

    result.extend(struct.pack(">H", pes_packet_length))

    # Optional PES header
    # Marker bits (10) + scrambling (00) + priority (0) + alignment (1) + copyright (0) + original (0)
    result.append(0x80)  # 10 00 0 0 0 0

    # Flags byte: PTS_DTS_flags (2 bits) + other flags (6 bits)
    pts_dts_flags = 0
    if has_pts and has_dts:
        pts_dts_flags = 0x03  # 11 = both PTS and DTS
    elif has_pts:
        pts_dts_flags = 0x02  # 10 = PTS only

    result.append((pts_dts_flags << 6))

    # PES header data length
    header_data_length = 0
    if has_pts:
        header_data_length += 5
    if has_dts:
        header_data_length += 5
    result.append(header_data_length)

    # Encode PTS
    if has_pts:
        result.extend(_encode_timestamp(pts, 0x02 if not has_dts else 0x03))

    # Encode DTS
    if has_dts:
        result.extend(_encode_timestamp(dts, 0x01))

    # Payload
    result.extend(data)

    return bytes(result)


def _encode_timestamp(ts: int, marker_bits: int) -> bytes:
    """
    Encode a 33-bit timestamp into 5 bytes per PES spec.

    Format: marker(4) + ts32..30(3) + marker(1) + ts29..15(15) + marker(1) + ts14..0(15) + marker(1)
    """
    result = bytearray(5)

    # Ensure timestamp fits in 33 bits
    ts = ts & 0x1FFFFFFFF

    # Byte 0: marker(4) + ts[32:30](3) + marker(1)
    result[0] = ((marker_bits & 0x0F) << 4) | (((ts >> 30) & 0x07) << 1) | 0x01

    # Bytes 1-2: ts[29:15](15) + marker(1)
    result[1] = (ts >> 22) & 0xFF
    result[2] = (((ts >> 15) & 0x7F) << 1) | 0x01

    # Bytes 3-4: ts[14:0](15) + marker(1)
    result[3] = (ts >> 7) & 0xFF
    result[4] = ((ts & 0x7F) << 1) | 0x01

    return bytes(result)


# ============================================================================
# TS Packet Muxer (Todo 5)
# ============================================================================


class TSMuxer:
    """
    MPEG-TS packet multiplexer.

    Handles PAT/PMT generation, TS packetization with continuity counters,
    adaptation fields, and PCR insertion.
    """

    def __init__(self, has_video: bool = True, has_audio: bool = True):
        self.has_video = has_video
        self.has_audio = has_audio

        # Continuity counters (4-bit, wraps at 16)
        self.cc_pat = 0
        self.cc_pmt = 0
        self.cc_video = 0
        self.cc_audio = 0

        # PCR base (90kHz counter)
        self.pcr_base = 0

    def build_pat(self) -> bytes:
        """Build a PAT (Program Association Table) section."""
        # PAT structure
        section = bytearray()

        # Table ID (0x00 for PAT)
        section.append(0x00)

        # Section syntax indicator (1) + '0' + reserved (11) + section length (12 bits)
        # Section contains: transport_stream_id(2) + reserved(2)/version(5)/current(1) +
        #                   section_number(1) + last_section_number(1) + program_entries(4 each) + CRC(4)
        # = 5 + 4 + 4 = 13 bytes minimum for 1 program
        section_length = 5 + 4 + 4  # 13 bytes
        section.append(0xB0 | ((section_length >> 8) & 0x0F))
        section.append(section_length & 0xFF)

        # Transport stream ID
        section.extend(b"\x00\x01")

        # Reserved (2) + version (5) + current_next (1)
        section.append(0xC1)  # version 0, current

        # Section number
        section.append(0x00)

        # Last section number
        section.append(0x00)

        # Program entry: program_number (2) + reserved (3) + PMT_PID (13)
        section.extend(b"\x00\x01")  # Program 1
        section.append(0xE0 | ((PID_PMT >> 8) & 0x1F))
        section.append(PID_PMT & 0xFF)

        # CRC32
        crc = crc32_mpeg2(bytes(section))
        section.extend(struct.pack(">I", crc))

        return bytes(section)

    def build_pmt(self, video_codec: str = "h264", has_audio: bool = True) -> bytes:
        """Build a PMT (Program Map Table) section."""
        section = bytearray()

        # Table ID (0x02 for PMT)
        section.append(0x02)

        # Calculate section length
        # section_length = bytes from program_number through CRC (inclusive)
        # Fixed fields: program_number(2) + version/flags(1) + section_number(1) +
        #               last_section_number(1) + PCR_PID(2) + program_info_length(2) + CRC(4) = 13
        # Variable: stream_info (5 bytes per stream: stream_type(1) + elementary_PID(2) + ES_info_length(2))
        stream_info_len = 0
        if self.has_video:
            stream_info_len += 5
        if self.has_audio and has_audio:
            stream_info_len += 5

        section_length = 9 + stream_info_len + 4  # 9 fixed bytes + streams + CRC
        section.append(0xB0 | ((section_length >> 8) & 0x0F))
        section.append(section_length & 0xFF)

        # Program number
        section.extend(b"\x00\x01")

        # Reserved (2) + version (5) + current_next (1)
        section.append(0xC1)

        # Section number
        section.append(0x00)

        # Last section number
        section.append(0x00)

        # PCR PID (use video PID if available)
        pcr_pid = PID_VIDEO if self.has_video else PID_AUDIO
        section.append(0xE0 | ((pcr_pid >> 8) & 0x1F))
        section.append(pcr_pid & 0xFF)

        # Program info length (0)
        section.append(0xF0)
        section.append(0x00)

        # Stream entries
        if self.has_video:
            stream_type = STREAM_TYPE_H265 if video_codec == "h265" else STREAM_TYPE_H264
            section.append(stream_type)
            section.append(0xE0 | ((PID_VIDEO >> 8) & 0x1F))
            section.append(PID_VIDEO & 0xFF)
            section.append(0xF0)  # ES info length (0)
            section.append(0x00)

        if self.has_audio and has_audio:
            section.append(STREAM_TYPE_AAC)
            section.append(0xE0 | ((PID_AUDIO >> 8) & 0x1F))
            section.append(PID_AUDIO & 0xFF)
            section.append(0xF0)  # ES info length (0)
            section.append(0x00)

        # CRC32
        crc = crc32_mpeg2(bytes(section))
        section.extend(struct.pack(">I", crc))

        return bytes(section)

    def packetize_section(self, section: bytes, pid: int) -> list[bytes]:
        """Packetize a PSI section (PAT/PMT) into TS packets."""
        packets = []

        # Get continuity counter
        if pid == PID_PAT:
            cc = self.cc_pat
            self.cc_pat = (self.cc_pat + 1) & 0x0F
        else:
            cc = self.cc_pmt
            self.cc_pmt = (self.cc_pmt + 1) & 0x0F

        # Build packet
        packet = bytearray(TS_PACKET_SIZE)
        packet[0] = TS_SYNC_BYTE
        packet[1] = 0x40 | ((pid >> 8) & 0x1F)  # Payload unit start indicator set
        packet[2] = pid & 0xFF
        packet[3] = 0x10 | cc  # Payload only, no adaptation field

        # Pointer field (for sections at start of packet)
        packet[4] = 0x00

        # Copy section data
        section_len = min(len(section), TS_PACKET_SIZE - 5)
        packet[5 : 5 + section_len] = section[:section_len]

        # Stuffing
        for i in range(5 + section_len, TS_PACKET_SIZE):
            packet[i] = TS_STUFFING_BYTE

        packets.append(bytes(packet))
        return packets

    def packetize_pes(
        self,
        pes: bytes,
        pid: int,
        pcr: Optional[int] = None,
        is_keyframe: bool = False,
        discontinuity: bool = False,
    ) -> list[bytes]:
        """
        Packetize a PES packet into one or more TS packets.

        Args:
            pes: The complete PES packet
            pid: The PID for these packets
            pcr: Optional PCR value to include (90kHz)
            is_keyframe: True if this is a keyframe (for random access indicator)
            discontinuity: True to set discontinuity_indicator on the first packet
                           (signals CC reset at segment boundaries)

        Returns:
            List of 188-byte TS packets
        """
        packets = []
        offset = 0
        first_packet = True

        while offset < len(pes):
            packet = bytearray(TS_PACKET_SIZE)
            packet[0] = TS_SYNC_BYTE

            # TS header byte 1: TEI + PUSI + priority + PID high
            pusi = 1 if first_packet else 0
            packet[1] = (pusi << 6) | ((pid >> 8) & 0x1F)

            # TS header byte 2: PID low
            packet[2] = pid & 0xFF

            # Get continuity counter
            if pid == PID_VIDEO:
                cc = self.cc_video
                self.cc_video = (self.cc_video + 1) & 0x0F
            else:
                cc = self.cc_audio
                self.cc_audio = (self.cc_audio + 1) & 0x0F

            # Calculate payload space and adaptation field need
            header_size = TS_HEADER_SIZE
            adaptation_field = None

            if first_packet and pcr is not None:
                # Add adaptation field with PCR (and discontinuity flag if first segment packet)
                adaptation_field = self._build_adaptation_field(pcr, is_keyframe, discontinuity)
                header_size += 1 + len(adaptation_field)

            payload_space = TS_PACKET_SIZE - header_size
            remaining = len(pes) - offset

            # If this is the last packet and doesn't fill, we need stuffing
            if remaining < payload_space:
                # Need adaptation field for stuffing
                stuff_size = payload_space - remaining
                if adaptation_field is None:
                    # Create new adaptation field just for stuffing
                    if stuff_size == 1:
                        adaptation_field = b""  # Just the length byte = 0
                    else:
                        adaptation_field = bytes([0x00] + [TS_STUFFING_BYTE] * (stuff_size - 2))
                else:
                    # Extend existing adaptation field
                    adaptation_field = adaptation_field + bytes([TS_STUFFING_BYTE] * stuff_size)

                payload_space = remaining
                header_size = TS_PACKET_SIZE - payload_space

            # TS header byte 3: scrambling + adaptation + continuity
            has_adaptation = adaptation_field is not None
            packet[3] = ((1 if has_adaptation else 0) << 5) | (1 << 4) | cc

            # Write adaptation field if present
            write_pos = TS_HEADER_SIZE
            if has_adaptation:
                packet[4] = len(adaptation_field)
                write_pos = 5
                packet[write_pos : write_pos + len(adaptation_field)] = adaptation_field
                write_pos += len(adaptation_field)

            # Write payload
            payload_size = min(payload_space, len(pes) - offset)
            packet[write_pos : write_pos + payload_size] = pes[offset : offset + payload_size]
            offset += payload_size

            # Fill any remaining space with stuffing
            for i in range(write_pos + payload_size, TS_PACKET_SIZE):
                packet[i] = TS_STUFFING_BYTE

            packets.append(bytes(packet))
            first_packet = False

        return packets

    def _build_adaptation_field(self, pcr: int, is_keyframe: bool, discontinuity: bool = False) -> bytes:
        """Build an adaptation field with PCR.

        Args:
            pcr: PCR value in 90kHz ticks
            is_keyframe: True if this is a keyframe (sets random_access_indicator)
            discontinuity: True to set discontinuity_indicator (signals CC reset
                           at segment boundaries in HLS TS streams)
        """
        # Adaptation field flags:
        # discontinuity(1) + random_access(1) + priority(1) + PCR_flag(1) +
        # OPCR_flag(1) + splicing_point(1) + transport_private(1) + extension(1)
        flags = 0x10  # PCR flag set
        if is_keyframe:
            flags |= 0x40  # Random access indicator
        if discontinuity:
            flags |= 0x80  # Discontinuity indicator

        # PCR is 33-bit base + 6-bit extension (always 0 for simplicity)
        pcr_base = pcr & 0x1FFFFFFFF
        pcr_ext = 0

        pcr_bytes = bytearray(6)
        pcr_bytes[0] = (pcr_base >> 25) & 0xFF
        pcr_bytes[1] = (pcr_base >> 17) & 0xFF
        pcr_bytes[2] = (pcr_base >> 9) & 0xFF
        pcr_bytes[3] = (pcr_base >> 1) & 0xFF
        pcr_bytes[4] = ((pcr_base & 0x01) << 7) | 0x7E | ((pcr_ext >> 8) & 0x01)
        pcr_bytes[5] = pcr_ext & 0xFF

        return bytes([flags]) + bytes(pcr_bytes)

    def build_null_packet(self) -> bytes:
        """Build a null TS packet for padding."""
        packet = bytearray(TS_PACKET_SIZE)
        packet[0] = TS_SYNC_BYTE
        packet[1] = 0x1F
        packet[2] = 0xFF  # PID 0x1FFF
        packet[3] = 0x10  # Payload only
        for i in range(4, TS_PACKET_SIZE):
            packet[i] = TS_STUFFING_BYTE
        return bytes(packet)


# ============================================================================
# Main Remux Orchestration (Todo 6)
# ============================================================================


class FMP4ToTSRemuxer:
    """
    Remuxes fragmented MP4 segments to MPEG-TS.

    Usage:
        # Parse init segment once
        remuxer = FMP4ToTSRemuxer(init_segment)

        # Remux each media segment
        ts_data = remuxer.remux_segment(segment_data)
    """

    def __init__(self, init_segment: bytes):
        """
        Initialize the remuxer with an fMP4 init segment.

        Args:
            init_segment: The fMP4 initialization segment (contains moov)
        """
        self.config = extract_codec_config(init_segment)
        self.init_segment = init_segment

        has_video = self.config.video_codec is not None
        has_audio = self.config.audio_codec is not None

        self.muxer = TSMuxer(has_video=has_video, has_audio=has_audio)
        self._ts_offset = 0  # Timestamp offset for normalizing PTS/DTS
        self._dts_delay = 0  # DTS delay to ensure PTS >= DTS for B-frames

        logger.debug(f"FMP4ToTSRemuxer initialized: video={self.config.video_codec}, audio={self.config.audio_codec}")
        logger.debug(f"  Video: {self.config.width}x{self.config.height}, timescale={self.config.video_timescale}")
        logger.debug(
            f"  Audio: {self.config.sample_rate}Hz, {self.config.channel_count}ch, profile={self.config.aac_profile}"
        )
        logger.debug(f"  SPS count: {len(self.config.sps_list)}, PPS count: {len(self.config.pps_list)}")

    def remux_segment(
        self, segment_data: bytes, include_pat_pmt: bool = True, preserve_timestamps: bool = False
    ) -> bytes:
        """
        Remux an fMP4 media segment to MPEG-TS.

        Args:
            segment_data: The fMP4 media segment (contains moof + mdat)
            include_pat_pmt: Whether to include PAT/PMT at the start
            preserve_timestamps: If True, preserve the original tfdt-based timestamps
                                 from the fMP4 segment instead of normalizing to 0.
                                 This enables continuous timestamps across HLS segments
                                 since DASH tfdt values are already continuous.

        Returns:
            MPEG-TS data
        """
        # Parse segment to extract samples
        video_samples, audio_samples = self._parse_segment(segment_data)

        result = bytearray()

        # Optionally include PAT and PMT at start
        if include_pat_pmt:
            pat = self.muxer.build_pat()
            pmt = self.muxer.build_pmt(
                video_codec=self.config.video_codec or "h264", has_audio=self.config.audio_codec is not None
            )

            for packet in self.muxer.packetize_section(pat, PID_PAT):
                result.extend(packet)
            for packet in self.muxer.packetize_section(pmt, PID_PMT):
                result.extend(packet)

        # Calculate PTS delay to ensure PTS >= DTS for B-frame content.
        # In the source, B-frames can have PTS < DTS (negative CTS offset).
        #
        # For MPEG-TS:
        # - DTS must be monotonically increasing
        # - PTS must be >= DTS for each packet
        #
        # Strategy (matches FFmpeg): Find the most negative (PTS - DTS) difference
        # and shift all PTS values forward by that amount. This keeps DTS untouched
        # (preserving decode order) while ensuring PTS >= DTS for all frames.
        # The same shift is applied to audio PTS to maintain A/V sync.

        min_pts_dts_diff_90k = 0  # Will track most negative (PTS - DTS)
        for sample in video_samples:
            pts_90k = (sample.pts * TS_CLOCK_HZ) // self.config.video_timescale
            dts_90k = (sample.dts * TS_CLOCK_HZ) // self.config.video_timescale
            diff = pts_90k - dts_90k
            if diff < min_pts_dts_diff_90k:
                min_pts_dts_diff_90k = diff

        # The PTS delay is the absolute value of the most negative difference.
        # This shifts all PTS values forward so that even the most reordered
        # B-frame will have PTS >= DTS.
        self._dts_delay = -min_pts_dts_diff_90k if min_pts_dts_diff_90k < 0 else 0

        if preserve_timestamps:
            # Preserve the original tfdt-based timestamps from the fMP4 segment.
            # DASH segments already have continuous tfdt (baseMediaDecodeTime) values,
            # so we don't need to normalize to 0 and re-offset. This avoids imprecise
            # timestamp gaps/overlaps at segment boundaries that occur when using
            # EXTINF durations (which are rounded approximations).
            self._ts_offset = 0
        else:
            # Default mode: normalize timestamps to start from 0.
            # Find minimum DTS across all tracks.
            min_dts_90k = None
            for sample in video_samples:
                dts_90k = (sample.dts * TS_CLOCK_HZ) // self.config.video_timescale
                if min_dts_90k is None or dts_90k < min_dts_90k:
                    min_dts_90k = dts_90k
            for sample in audio_samples:
                dts_90k = (sample.dts * TS_CLOCK_HZ) // self.config.audio_timescale
                if min_dts_90k is None or dts_90k < min_dts_90k:
                    min_dts_90k = dts_90k

            self._ts_offset = -(min_dts_90k or 0)

        # Interleave video and audio samples by DTS
        all_samples = []

        for sample in video_samples:
            all_samples.append(("video", sample))
        for sample in audio_samples:
            all_samples.append(("audio", sample))

        # Sort by DTS (convert to common timebase - 90kHz)
        def get_sort_key(item):
            track_type, sample = item
            if track_type == "video":
                return (sample.dts * TS_CLOCK_HZ) // self.config.video_timescale
            else:
                return (sample.dts * TS_CLOCK_HZ) // self.config.audio_timescale

        all_samples.sort(key=get_sort_key)

        # Process each sample
        # When preserve_timestamps is True, we set the MPEG-TS discontinuity_indicator
        # on the first packet of each PID. This tells the demuxer that continuity
        # counters reset here (since each segment is independently muxed with CC=0).
        first_video = True
        first_audio = True
        for track_type, sample in all_samples:
            if track_type == "video":
                packets = self._process_video_sample(
                    sample, first_video, discontinuity=preserve_timestamps and first_video
                )
                first_video = False
            else:
                packets = self._process_audio_sample(sample, discontinuity=preserve_timestamps and first_audio)
                first_audio = False

            for packet in packets:
                result.extend(packet)

        return bytes(result)

    def _parse_segment(self, segment_data: bytes) -> tuple[list[Sample], list[Sample]]:
        """
        Parse an fMP4 segment to extract video and audio samples.

        Returns:
            Tuple of (video_samples, audio_samples)
        """
        data = memoryview(segment_data)

        video_samples = []
        audio_samples = []

        # Find moof and mdat boxes, and track their positions
        # DASH/HLS segments typically contain a single moof+mdat pair.
        # If multiple pairs exist (e.g., concatenated fragments), we log a warning
        # and process only the last pair since multi-fragment support would require
        # accumulating samples across pairs with adjusted data offsets.
        moof_offset = None
        moof_data = None
        mdat_data = None
        moof_count = 0

        offset = 0
        while offset < len(data):
            result = read_box(data, offset)
            if result is None:
                break
            box_type, size, box_data = result

            if box_type == b"moof":
                moof_count += 1
                if moof_count > 1:
                    logger.warning(
                        "Segment contains multiple moof boxes (%d); only the last moof+mdat pair will be processed",
                        moof_count,
                    )
                moof_offset = offset
                moof_data = box_data
            elif box_type == b"mdat":
                mdat_data = box_data

            offset += size

        if moof_offset is None or mdat_data is None:
            logger.warning("Segment missing moof or mdat box")
            return video_samples, audio_samples

        # Parse moof to get sample info for each track
        track_infos = self._parse_moof(moof_data)

        # Extract samples from the segment data using data_offset
        # data_offset in trun is relative to moof start
        for track_info in track_infos:
            samples = self._extract_samples(data, track_info, moof_offset)

            if track_info["track_id"] == self.config.video_track_id:
                video_samples = samples
            elif track_info["track_id"] == self.config.audio_track_id:
                audio_samples = samples

        return video_samples, audio_samples

    def _parse_moof(self, moof_data: memoryview) -> list[dict]:
        """Parse moof box to extract track fragment information."""
        track_infos = []

        for box_type, box_data in iter_boxes(moof_data):
            if box_type == b"traf":
                track_info = self._parse_traf(box_data)
                if track_info:
                    track_infos.append(track_info)

        return track_infos

    def _parse_traf(self, traf_data: memoryview) -> Optional[dict]:
        """Parse traf box to get sample information."""
        track_info = {
            "track_id": 0,
            "base_media_decode_time": 0,
            "default_sample_duration": 0,
            "default_sample_size": 0,
            "data_offset": 0,
            "samples": [],  # List of (size, duration, flags, cts_offset)
        }

        for box_type, box_data in iter_boxes(traf_data):
            if box_type == b"tfhd":
                self._parse_tfhd(box_data, track_info)
            elif box_type == b"tfdt":
                self._parse_tfdt(box_data, track_info)
            elif box_type == b"trun":
                self._parse_trun(box_data, track_info)

        if track_info["track_id"] == 0:
            return None

        return track_info

    def _parse_tfhd(self, data: memoryview, track_info: dict):
        """Parse tfhd (Track Fragment Header) box."""
        if len(data) < 8:
            return

        flags = struct.unpack_from(">I", data, 0)[0] & 0xFFFFFF
        track_info["track_id"] = struct.unpack_from(">I", data, 4)[0]

        offset = 8
        if flags & 0x000001:  # base-data-offset-present
            offset += 8
        if flags & 0x000002:  # sample-description-index-present
            offset += 4
        if flags & 0x000008:  # default-sample-duration-present
            if offset + 4 <= len(data):
                track_info["default_sample_duration"] = struct.unpack_from(">I", data, offset)[0]
            offset += 4
        if flags & 0x000010:  # default-sample-size-present
            if offset + 4 <= len(data):
                track_info["default_sample_size"] = struct.unpack_from(">I", data, offset)[0]
            offset += 4

    def _parse_tfdt(self, data: memoryview, track_info: dict):
        """Parse tfdt (Track Fragment Decode Time) box."""
        if len(data) < 4:
            return

        version = data[0]
        if version == 0:
            if len(data) >= 8:
                track_info["base_media_decode_time"] = struct.unpack_from(">I", data, 4)[0]
        else:
            if len(data) >= 12:
                track_info["base_media_decode_time"] = struct.unpack_from(">Q", data, 4)[0]

    def _parse_trun(self, data: memoryview, track_info: dict):
        """Parse trun (Track Fragment Run) box."""
        if len(data) < 8:
            return

        version_and_flags = struct.unpack_from(">I", data, 0)[0]
        trun_version = (version_and_flags >> 24) & 0xFF
        flags = version_and_flags & 0xFFFFFF
        sample_count = struct.unpack_from(">I", data, 4)[0]

        offset = 8

        if flags & 0x000001:  # data-offset-present
            if offset + 4 <= len(data):
                track_info["data_offset"] = struct.unpack_from(">i", data, offset)[0]
            offset += 4

        if flags & 0x000004:  # first-sample-flags-present
            offset += 4

        samples = []
        for _ in range(sample_count):
            sample_duration = track_info["default_sample_duration"]
            sample_size = track_info["default_sample_size"]
            sample_flags = 0
            cts_offset = 0

            if flags & 0x000100:  # sample-duration-present
                if offset + 4 <= len(data):
                    sample_duration = struct.unpack_from(">I", data, offset)[0]
                offset += 4

            if flags & 0x000200:  # sample-size-present
                if offset + 4 <= len(data):
                    sample_size = struct.unpack_from(">I", data, offset)[0]
                offset += 4

            if flags & 0x000400:  # sample-flags-present
                if offset + 4 <= len(data):
                    sample_flags = struct.unpack_from(">I", data, offset)[0]
                offset += 4

            if flags & 0x000800:  # sample-composition-time-offset-present
                if offset + 4 <= len(data):
                    # Per ISO 14496-12: unsigned (uint32) in version 0, signed (int32) in version 1
                    if trun_version == 0:
                        cts_offset = struct.unpack_from(">I", data, offset)[0]
                    else:
                        cts_offset = struct.unpack_from(">i", data, offset)[0]
                offset += 4

            samples.append((sample_size, sample_duration, sample_flags, cts_offset))

        track_info["samples"] = samples

    def _extract_samples(self, segment_data: memoryview, track_info: dict, moof_offset: int) -> list[Sample]:
        """Extract samples from segment data based on track info.

        Args:
            segment_data: Full segment data memoryview
            track_info: Track fragment info including data_offset
            moof_offset: Offset of moof box in segment (data_offset is relative to this)
        """
        samples = []

        # data_offset is relative to the start of the moof box
        # So actual data position = moof_offset + data_offset
        offset = moof_offset + track_info["data_offset"]
        dts = track_info["base_media_decode_time"]

        for sample_size, sample_duration, sample_flags, cts_offset in track_info["samples"]:
            if offset + sample_size > len(segment_data):
                logger.warning(
                    f"Sample extends beyond segment: offset={offset}, size={sample_size}, "
                    f"segment_len={len(segment_data)}"
                )
                break

            sample_data = bytes(segment_data[offset : offset + sample_size])

            # Check if keyframe (sample_depends_on == 2 means I-frame)
            # Flags format: reserved(4) + is_leading(2) + sample_depends_on(2) + ...
            sample_depends_on = (sample_flags >> 24) & 0x03
            is_keyframe = sample_depends_on == 2  # Doesn't depend on others

            pts = dts + cts_offset

            samples.append(
                Sample(
                    data=sample_data,
                    duration=sample_duration,
                    pts=pts,
                    dts=dts,
                    is_keyframe=is_keyframe,
                    cts_offset=cts_offset,
                )
            )

            offset += sample_size
            dts += sample_duration

        return samples

    def _process_video_sample(self, sample: Sample, is_first: bool, discontinuity: bool = False) -> list[bytes]:
        """Process a video sample and return TS packets."""
        # Convert NAL units to Annex B format
        video_data, detected_keyframe = convert_length_prefixed_to_annex_b(
            sample.data,
            self.config.nal_length_size,
            self.config.video_codec,
            self.config.sps_list,
            self.config.pps_list,
            self.config.vps_list,
        )

        is_keyframe = sample.is_keyframe or detected_keyframe

        # Convert timestamps to 90kHz TS clock
        pts_90k = (sample.pts * TS_CLOCK_HZ) // self.config.video_timescale
        dts_90k = (sample.dts * TS_CLOCK_HZ) // self.config.video_timescale

        # Apply timestamp offset (normalizes to start from 0)
        pts_90k += self._ts_offset
        dts_90k += self._ts_offset

        # Apply PTS delay to ensure PTS >= DTS for B-frame content.
        # The delay shifts all PTS values forward so that even the most reordered
        # B-frame will have PTS >= DTS, which is required by the MPEG-TS spec.
        # This matches FFmpeg's approach of shifting PTS rather than DTS.
        pts_90k += self._dts_delay

        # Ensure timestamps are non-negative
        if pts_90k < 0:
            pts_90k = 0
        if dts_90k < 0:
            dts_90k = 0

        # Include DTS when it differs from PTS (B-frame reordering)
        include_dts = dts_90k != pts_90k

        # Build PES packet
        pes = build_pes_packet(0xE0, video_data, pts_90k, dts_90k if include_dts else None)

        # Include PCR on first packet of segment and keyframes
        # Use DTS for PCR base when available (PCR should track the decode timeline,
        # not the presentation timeline). When _dts_delay shifts PTS forward for
        # B-frame content, using PTS would cause the system clock to run ahead of
        # the decode timeline, potentially causing decoder buffer underflow.
        pcr_base = (dts_90k if include_dts else pts_90k) if (is_first or is_keyframe) else None

        return self.muxer.packetize_pes(
            pes, PID_VIDEO, pcr=pcr_base, is_keyframe=is_keyframe, discontinuity=discontinuity
        )

    def _process_audio_sample(self, sample: Sample, discontinuity: bool = False) -> list[bytes]:
        """Process an audio sample and return TS packets."""
        # Wrap AAC frame with ADTS header
        audio_data = wrap_aac_frame_with_adts(sample.data, self.config)

        # Convert timestamps to 90kHz TS clock
        pts_90k = (sample.pts * TS_CLOCK_HZ) // self.config.audio_timescale

        # Apply timestamp offset (same as video for sync)
        pts_90k += self._ts_offset

        # Apply same PTS delay as video to maintain A/V sync
        pts_90k += self._dts_delay

        # Ensure timestamp is non-negative
        if pts_90k < 0:
            pts_90k = 0

        # Build PES packet (audio usually only needs PTS)
        pes = build_pes_packet(0xC0, audio_data, pts_90k, None)

        # Include PCR on first audio packet when discontinuity is set,
        # so the adaptation field is created to carry the discontinuity flag
        pcr = pts_90k if discontinuity else None

        return self.muxer.packetize_pes(pes, PID_AUDIO, pcr=pcr, is_keyframe=False, discontinuity=discontinuity)


# ============================================================================
# Public API
# ============================================================================


def remux_fmp4_to_ts(init_segment: bytes, media_segment: bytes, preserve_timestamps: bool = False) -> bytes:
    """
    Remux a fragmented MP4 segment to MPEG-TS.

    This is the main public function for converting fMP4 to TS.
    It parses the init segment for codec configuration and remuxes
    the media segment to MPEG-TS format.

    Args:
        init_segment: The fMP4 initialization segment (contains moov with codec config)
        media_segment: The fMP4 media segment (contains moof + mdat with samples)
        preserve_timestamps: If True, preserve original fMP4 tfdt timestamps
                             instead of normalizing to 0. Use this for HLS TS
                             segments from DASH sources to get continuous
                             timestamps across segments.

    Returns:
        MPEG-TS data containing the remuxed content
    """
    remuxer = FMP4ToTSRemuxer(init_segment)
    return remuxer.remux_segment(media_segment, preserve_timestamps=preserve_timestamps)
