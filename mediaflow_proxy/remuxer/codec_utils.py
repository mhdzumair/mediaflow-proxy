"""
Codec decision engine for browser compatibility detection.

Determines whether video/audio streams need transcoding for browser
playback and selects appropriate output codecs.
"""

import logging
import struct

logger = logging.getLogger(__name__)

# ────────────────────────────────────────────────────────────────────
# Browser-compatible codecs (work natively in HTML5 <video>)
# ────────────────────────────────────────────────────────────────────
BROWSER_VIDEO_CODECS = frozenset(
    {
        "V_MPEG4/ISO/AVC",  # H.264/AVC -- universal
        "h264",
        "avc1",  # FFmpeg/PyAV names
    }
)

BROWSER_AUDIO_CODECS = frozenset(
    {
        "A_AAC",  # AAC-LC -- universal
        "A_AAC/MPEG2/LC",
        "A_AAC/MPEG4/LC",
        "aac",  # FFmpeg/PyAV name
    }
)

# ────────────────────────────────────────────────────────────────────
# Video codecs that need re-encoding to H.264
# ────────────────────────────────────────────────────────────────────
VIDEO_NEEDS_REENCODE = frozenset(
    {
        "V_MPEGH/ISO/HEVC",  # H.265/HEVC (Chrome/Firefox don't support)
        "V_MPEG2",  # MPEG-2 (DVD-era)
        "V_MPEG4/ISO/SP",  # MPEG-4 Part 2 Simple Profile
        "V_MPEG4/ISO/ASP",  # MPEG-4 Part 2 Advanced Simple (DivX/Xvid)
        "V_MPEG4/ISO/AP",  # MPEG-4 Part 2 Advanced Profile
        "V_MPEG4/MS/V3",  # MS MPEG-4 v3 (WMV)
        "V_MS/VFW/FOURCC",  # Generic VFW (VC-1, etc.)
        "V_REAL/RV10",
        "V_REAL/RV20",
        "V_REAL/RV30",
        "V_REAL/RV40",
        "V_THEORA",
        "V_VP8",
        "V_VP9",  # VP9 in MKV (needs WebM container for browser)
        "V_AV1",  # AV1 (partial support, safer to reencode)
        # PyAV / FFmpeg codec names
        "hevc",
        "h265",
        "mpeg2video",
        "mpeg4",
        "vc1",
        "vp8",
        "vp9",
        "av1",
        "theora",
        "wmv3",
        "rv30",
        "rv40",
    }
)

# ────────────────────────────────────────────────────────────────────
# Audio codecs that need transcoding to AAC
# (superset of the list in audio_transcoder.py, uses both MKV and
# PyAV codec names for universal lookup)
# ────────────────────────────────────────────────────────────────────
AUDIO_NEEDS_TRANSCODE = frozenset(
    {
        # MKV CodecIDs
        "A_EAC3",
        "A_AC3",
        "A_DTS",
        "A_DTS/EXPRESS",
        "A_DTS/LOSSLESS",
        "A_OPUS",
        "A_VORBIS",
        "A_FLAC",
        "A_TRUEHD",
        "A_MLP",
        "A_PCM/INT/LIT",
        "A_PCM/INT/BIG",
        "A_PCM/FLOAT/IEEE",
        "A_REAL/28_8",
        "A_REAL/COOK",
        "A_REAL/SIPR",
        "A_REAL/ATRC",
        "A_MS/ACM",  # Generic Windows audio
        "A_MP3",
        "A_MPEG/L3",
        # PyAV / FFmpeg names
        "eac3",
        "ac3",
        "dts",
        "dca",
        "truehd",
        "mlp",
        "mp3",
        "opus",
        "vorbis",
        "flac",
        "pcm_s16le",
        "pcm_s24le",
        "pcm_f32le",
        "wmav2",
        "wmavoice",
        "wmapro",
        "cook",
        "sipr",
        "atrac3",
    }
)

# Map PyAV codec names to MKV CodecIDs (for the MKV fast-path)
_PYAV_TO_MKV_VIDEO = {
    "h264": "V_MPEG4/ISO/AVC",
    "hevc": "V_MPEGH/ISO/HEVC",
    "h265": "V_MPEGH/ISO/HEVC",
    "mpeg2video": "V_MPEG2",
    "vp8": "V_VP8",
    "vp9": "V_VP9",
    "av1": "V_AV1",
}

_PYAV_TO_MKV_AUDIO = {
    "aac": "A_AAC",
    "eac3": "A_EAC3",
    "ac3": "A_AC3",
    "dts": "A_DTS",
    "opus": "A_OPUS",
    "vorbis": "A_VORBIS",
    "flac": "A_FLAC",
    "mp3": "A_MPEG/L3",
    "truehd": "A_TRUEHD",
}


# ────────────────────────────────────────────────────────────────────
# NAL unit format conversion (Annex B ↔ AVCC)
# ────────────────────────────────────────────────────────────────────

# H.264 NAL types that belong in the init segment (avcC), not in samples
_H264_PARAM_NAL_TYPES = frozenset({7, 8, 9})  # SPS, PPS, AUD


def _find_annexb_nals(data: bytes) -> list[tuple[int, int]]:
    """
    Find all NAL unit [start, end) byte ranges in Annex B formatted data.

    Handles both 3-byte (00 00 01) and 4-byte (00 00 00 01) start codes.
    Returns a list of (start, end) tuples pointing into *data*.
    """
    size = len(data)
    nals: list[tuple[int, int]] = []
    i = 0

    while i < size - 2:
        # Scan for 0x000001 or 0x00000001
        if data[i] != 0:
            i += 1
            continue
        if data[i + 1] != 0:
            i += 2
            continue
        if data[i + 2] == 1:
            nal_start = i + 3
        elif data[i + 2] == 0 and i + 3 < size and data[i + 3] == 1:
            nal_start = i + 4
        else:
            i += 1
            continue

        # Record end of previous NAL
        if nals:
            nals[-1] = (nals[-1][0], i)
        nals.append((nal_start, size))
        i = nal_start

    return nals


def is_annexb(data: bytes) -> bool:
    """
    Return True if *data* starts with an Annex B start code.

    Disambiguates AVCC (4-byte length prefix) from Annex B when the data
    begins with ``00 00 01 xx`` or ``00 00 00 01`` by checking whether
    the AVCC interpretation yields a plausible H.264 NAL.  If the 4-byte
    big-endian length + subsequent NAL header byte is valid and the
    length fits within the data, this is AVCC -- not Annex B.
    """
    if len(data) < 5:
        return False

    # 4-byte start code: 00 00 00 01
    if data[0] == 0 and data[1] == 0 and data[2] == 0 and data[3] == 1:
        return True

    # 3-byte start code: 00 00 01 -- but could also be AVCC with length
    # that starts with 00 00 01 (i.e. length 0x000001xx = 256..511).
    if data[0] == 0 and data[1] == 0 and data[2] == 1:
        # Interpret as AVCC: 4-byte big-endian length
        avcc_len = int.from_bytes(data[0:4], "big")
        if 0 < avcc_len <= len(data) - 4:
            # Check if the NAL header byte is a valid H.264 NAL
            nal_byte = data[4]
            forbidden = (nal_byte >> 7) & 1
            nal_type = nal_byte & 0x1F
            if forbidden == 0 and 1 <= nal_type <= 12:
                # Plausible AVCC: valid length + valid NAL type
                return False
        # Not plausible AVCC, treat as Annex B
        return True

    return False


def annexb_to_avcc(data: bytes, filter_ps: bool = True) -> bytes:
    """
    Convert Annex B (start-code-prefixed) NAL units to AVCC
    (4-byte length-prefixed) format suitable for fMP4 samples.

    Args:
        data: H.264 access unit in Annex B format.
        filter_ps: If True, strip SPS/PPS/AUD NAL units (they belong
                   in the avcC box of the init segment, not in samples).

    Returns:
        The same NAL units with 4-byte big-endian length prefixes.
    """
    if not data or not is_annexb(data):
        return data  # Already AVCC or empty

    nals = _find_annexb_nals(data)
    if not nals:
        return data

    out = bytearray()
    for start, end in nals:
        # Strip trailing zero-padding before next start code
        while end > start and data[end - 1] == 0:
            end -= 1
        if end <= start:
            continue

        if filter_ps:
            nal_type = data[start] & 0x1F
            if nal_type in _H264_PARAM_NAL_TYPES:
                continue

        length = end - start
        out.extend(length.to_bytes(4, "big"))
        out.extend(data[start:end])

    # If every NAL was filtered out (e.g. packet only contains SPS/PPS/AUD),
    # return empty so callers can drop this sample. Returning original Annex-B
    # bytes here would corrupt fMP4 samples (expects AVCC length prefixes).
    return bytes(out)


# H.264 profiles that require the avcC High Profile extension fields
# (chroma_format_idc, bit_depth_luma/chroma, numSpsExt).
_HIGH_PROFILE_IDCS = frozenset({100, 110, 122, 244, 44, 83, 86, 118, 128, 138, 139, 134})


def _fix_avcc_high_profile(avcc: bytes) -> bytes:
    """
    Ensure an avcC record includes High Profile extension bytes.

    The ISO/IEC 14496-15 spec requires additional fields after the PPS
    section when ``AVCProfileIndication`` is 100 (High), 110, 122, or 244.
    Some MKV muxers omit these, causing decoders to not know the chroma
    format or bit depth, which leads to widespread decode errors.

    If the extensions are missing, appends the defaults for 4:2:0 / 8-bit
    with zero extended SPS sets.
    """
    if len(avcc) < 7:
        return avcc
    if avcc[0] != 1:
        return avcc  # Not an avcC record

    profile_idc = avcc[1]
    if profile_idc not in _HIGH_PROFILE_IDCS:
        return avcc  # Not a High Profile variant, no extensions needed

    # Walk past SPS and PPS sections to find where extensions should be
    off = 5
    num_sps = avcc[off] & 0x1F
    off += 1
    for _ in range(num_sps):
        if off + 2 > len(avcc):
            return avcc
        sps_len = struct.unpack(">H", avcc[off : off + 2])[0]
        off += 2 + sps_len

    if off >= len(avcc):
        return avcc
    num_pps = avcc[off]
    off += 1
    for _ in range(num_pps):
        if off + 2 > len(avcc):
            return avcc
        pps_len = struct.unpack(">H", avcc[off : off + 2])[0]
        off += 2 + pps_len

    # If there are already bytes after the PPS section, extensions exist
    if off < len(avcc):
        return avcc

    # Append default High Profile extensions:
    #   chroma_format_idc = 1 (4:2:0)  -> 0xFC | 0x01 = 0xFD  (reserved 111111 + 01)
    #   bit_depth_luma_minus8 = 0       -> 0xF8 | 0x00 = 0xF8  (reserved 11111 + 000)
    #   bit_depth_chroma_minus8 = 0     -> 0xF8 | 0x00 = 0xF8  (reserved 11111 + 000)
    #   numOfSequenceParameterSetExt = 0
    ext = bytearray(avcc)
    ext.append(0xFD)  # 111111_01 : chroma_format_idc = 1
    ext.append(0xF8)  # 11111_000 : bit_depth_luma_minus8 = 0
    ext.append(0xF8)  # 11111_000 : bit_depth_chroma_minus8 = 0
    ext.append(0x00)  # numOfSequenceParameterSetExt = 0
    return bytes(ext)


def ensure_avcc_extradata(extradata: bytes) -> bytes:
    """
    Ensure h264 extradata is in avcC format for the fMP4 init segment.

    PyAV returns extradata in the container's native format:
    - MKV/MP4: avcC format (starts with 0x01)
    - MPEG-TS: Annex B format (starts with 0x00 0x00)

    If Annex B, parses SPS/PPS NAL units and builds proper avcC.
    If already avcC, validates and fixes High Profile extension fields.
    """
    if not extradata or len(extradata) < 4:
        return extradata

    # Already avcC format (configurationVersion == 1)
    if extradata[0] == 0x01:
        return _fix_avcc_high_profile(extradata)

    # Parse Annex B NAL units to extract SPS and PPS
    nals = _find_annexb_nals(extradata)
    if not nals:
        return extradata

    sps_list: list[bytes] = []
    pps_list: list[bytes] = []

    for start, end in nals:
        while end > start and extradata[end - 1] == 0:
            end -= 1
        if end <= start:
            continue
        nal_type = extradata[start] & 0x1F
        nal_data = extradata[start:end]
        if nal_type == 7:  # SPS
            sps_list.append(nal_data)
        elif nal_type == 8:  # PPS
            pps_list.append(nal_data)

    if not sps_list:
        return extradata  # Can't build avcC without SPS

    sps = sps_list[0]
    if len(sps) < 4:
        return extradata

    # Build avcC box content
    avcc = bytearray()
    avcc.append(1)  # configurationVersion
    avcc.append(sps[1])  # AVCProfileIndication
    avcc.append(sps[2])  # profile_compatibility
    avcc.append(sps[3])  # AVCLevelIndication
    avcc.append(0xFF)  # 6 bits reserved (0x3F) + lengthSizeMinusOne=3 -> 4-byte NAL lengths
    avcc.append(0xE0 | len(sps_list))  # 3 bits reserved (0x07) + numOfSPS

    for s in sps_list:
        avcc.extend(struct.pack(">H", len(s)))
        avcc.extend(s)

    avcc.append(len(pps_list))  # numOfPPS
    for p in pps_list:
        avcc.extend(struct.pack(">H", len(p)))
        avcc.extend(p)

    return _fix_avcc_high_profile(bytes(avcc))


def extract_sps_pps_from_annexb(data: bytes) -> bytes:
    """
    Extract SPS and PPS NAL units from Annex B encoded data and build
    an avcC-format extradata blob.

    Hardware encoders like VideoToolbox embed SPS/PPS as in-band NAL
    units in their first keyframe output rather than setting extradata
    on the codec context.  This function finds those parameter sets
    and returns proper avcC bytes suitable for the fMP4 init segment.

    Returns:
        avcC bytes if SPS/PPS were found, empty bytes otherwise.
    """
    if not data or not is_annexb(data):
        return b""

    nals = _find_annexb_nals(data)
    if not nals:
        return b""

    sps_list: list[bytes] = []
    pps_list: list[bytes] = []

    for start, end in nals:
        # Strip trailing zero-padding
        while end > start and data[end - 1] == 0:
            end -= 1
        if end <= start:
            continue

        nal_type = data[start] & 0x1F
        if nal_type == 7:  # SPS
            sps_list.append(data[start:end])
        elif nal_type == 8:  # PPS
            pps_list.append(data[start:end])

    if not sps_list:
        return b""

    sps = sps_list[0]
    if len(sps) < 4:
        return b""

    # Build avcC box content
    avcc = bytearray()
    avcc.append(1)  # configurationVersion
    avcc.append(sps[1])  # AVCProfileIndication
    avcc.append(sps[2])  # profile_compatibility
    avcc.append(sps[3])  # AVCLevelIndication
    avcc.append(0xFF)  # 6 bits reserved + lengthSizeMinusOne=3
    avcc.append(0xE0 | len(sps_list))  # 3 bits reserved + numOfSPS

    for s in sps_list:
        avcc.extend(struct.pack(">H", len(s)))
        avcc.extend(s)

    avcc.append(len(pps_list))  # numOfPPS
    for p in pps_list:
        avcc.extend(struct.pack(">H", len(p)))
        avcc.extend(p)

    return bytes(avcc)


def video_needs_reencode(codec_id: str) -> bool:
    """Check if a video codec requires re-encoding for browser playback."""
    if not codec_id:
        return False
    return codec_id in VIDEO_NEEDS_REENCODE


def audio_needs_transcode(codec_id: str) -> bool:
    """Check if an audio codec requires transcoding for browser playback."""
    if not codec_id:
        return False
    return codec_id in AUDIO_NEEDS_TRANSCODE


def is_browser_compatible(video_codec: str, audio_codec: str) -> bool:
    """
    Check if a video+audio combination is fully browser-compatible.

    Returns True only if BOTH video and audio can be played natively in
    an HTML5 <video> element inside an MP4 container.
    """
    video_ok = video_codec in BROWSER_VIDEO_CODECS or not video_codec
    audio_ok = audio_codec in BROWSER_AUDIO_CODECS or not audio_codec
    return video_ok and audio_ok


class TranscodeDecision:
    """Result of analyzing a stream's codec compatibility."""

    __slots__ = ("transcode_video", "transcode_audio", "video_codec", "audio_codec")

    def __init__(self, video_codec: str = "", audio_codec: str = "") -> None:
        self.video_codec = video_codec
        self.audio_codec = audio_codec
        self.transcode_video = video_needs_reencode(video_codec)
        self.transcode_audio = audio_needs_transcode(audio_codec)

    @property
    def needs_transcode(self) -> bool:
        """True if any stream needs transcoding."""
        return self.transcode_video or self.transcode_audio

    @property
    def passthrough_ok(self) -> bool:
        """True if the stream can be served as-is to a browser."""
        return not self.needs_transcode

    def __repr__(self) -> str:
        parts = []
        if self.transcode_video:
            parts.append(f"video:{self.video_codec}->h264")
        if self.transcode_audio:
            parts.append(f"audio:{self.audio_codec}->aac")
        if not parts:
            parts.append("passthrough")
        return f"TranscodeDecision({', '.join(parts)})"
