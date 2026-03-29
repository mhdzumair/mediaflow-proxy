"""
GPU-accelerated video transcoder with runtime detection.

Detects available hardware encoders/decoders at first use and selects
the best available backend:
  - NVIDIA:         h264_nvenc / hevc_cuvid (NVENC + CUDA)
  - Apple macOS:    h264_videotoolbox / hevc_videotoolbox
  - Intel Linux:    h264_vaapi / h264_qsv
  - Fallback:       libx264 (CPU)

The transcoder operates at the packet/frame level via PyAV, suitable
for integration into the streaming pipeline.
"""

import logging
from dataclasses import dataclass, field
from enum import Enum
from fractions import Fraction

import av

from mediaflow_proxy.configs import settings

logger = logging.getLogger(__name__)


class HWAccelType(Enum):
    NONE = "none"
    NVIDIA = "nvidia"
    VIDEOTOOLBOX = "videotoolbox"
    VAAPI = "vaapi"
    QSV = "qsv"


@dataclass
class HWCapability:
    """Detected hardware acceleration capability."""

    accel_type: HWAccelType = HWAccelType.NONE
    h264_encoder: str = "libx264"
    h264_decoder: str | None = None  # None = use default software decoder
    hevc_decoder: str | None = None
    available_encoders: list[str] = field(default_factory=list)
    available_decoders: list[str] = field(default_factory=list)


# Module-level singleton -- populated on first call to get_hw_capability()
_hw_capability: HWCapability | None = None


def _probe_codec(name: str, mode: str = "w") -> bool:
    """
    Check if a PyAV codec is available by name.

    Args:
        name: Codec name (e.g. 'h264_videotoolbox').
        mode: 'w' for encoder, 'r' for decoder.
    """
    try:
        av.Codec(name, mode)
        return True
    except Exception:
        return False


def _detect_hw_capability() -> HWCapability:
    """
    Probe the runtime environment for hardware encoder/decoder availability.

    Checks NVIDIA, Apple VideoToolbox, Intel VAAPI/QSV in priority order.
    Falls back to libx264 CPU encoding.
    """
    cap = HWCapability()

    # Collect available encoders/decoders for logging
    hw_encoders = [
        "h264_nvenc",
        "hevc_nvenc",
        "h264_videotoolbox",
        "hevc_videotoolbox",
        "h264_vaapi",
        "hevc_vaapi",
        "h264_qsv",
        "hevc_qsv",
    ]
    hw_decoders = [
        "h264_cuvid",
        "hevc_cuvid",
        "h264_qsv",
        "hevc_qsv",
    ]

    cap.available_encoders = [c for c in hw_encoders if _probe_codec(c, "w")]
    cap.available_decoders = [c for c in hw_decoders if _probe_codec(c, "r")]

    # Priority 1: NVIDIA NVENC
    if "h264_nvenc" in cap.available_encoders:
        cap.accel_type = HWAccelType.NVIDIA
        cap.h264_encoder = "h264_nvenc"
        if "h264_cuvid" in cap.available_decoders:
            cap.h264_decoder = "h264_cuvid"
        if "hevc_cuvid" in cap.available_decoders:
            cap.hevc_decoder = "hevc_cuvid"
        return cap

    # Priority 2: Apple VideoToolbox
    if "h264_videotoolbox" in cap.available_encoders:
        cap.accel_type = HWAccelType.VIDEOTOOLBOX
        cap.h264_encoder = "h264_videotoolbox"
        # VideoToolbox decoders are used automatically via hwaccel
        return cap

    # Priority 3: Intel VAAPI (Linux)
    if "h264_vaapi" in cap.available_encoders:
        cap.accel_type = HWAccelType.VAAPI
        cap.h264_encoder = "h264_vaapi"
        return cap

    # Priority 4: Intel QSV
    if "h264_qsv" in cap.available_encoders:
        cap.accel_type = HWAccelType.QSV
        cap.h264_encoder = "h264_qsv"
        if "h264_qsv" in cap.available_decoders:
            cap.h264_decoder = "h264_qsv"
        if "hevc_qsv" in cap.available_decoders:
            cap.hevc_decoder = "hevc_qsv"
        return cap

    # Fallback: CPU
    cap.accel_type = HWAccelType.NONE
    cap.h264_encoder = "libx264"
    return cap


def get_hw_capability() -> HWCapability:
    """Get the detected hardware acceleration capability (cached singleton)."""
    global _hw_capability
    if _hw_capability is None:
        _hw_capability = _detect_hw_capability()
        if settings.transcode_prefer_gpu and _hw_capability.accel_type != HWAccelType.NONE:
            logger.info(
                "[video_transcoder] GPU acceleration: %s (encoder=%s, decoders=%s)",
                _hw_capability.accel_type.value,
                _hw_capability.h264_encoder,
                _hw_capability.available_decoders or "software",
            )
        else:
            logger.info(
                "[video_transcoder] Using CPU encoder: %s (available HW: encoders=%s, decoders=%s)",
                _hw_capability.h264_encoder,
                _hw_capability.available_encoders or "none",
                _hw_capability.available_decoders or "none",
            )
    return _hw_capability


class VideoTranscoder:
    """
    In-process video transcoder using PyAV.

    Decodes input video packets and re-encodes to H.264 using the best
    available hardware encoder (or CPU libx264 fallback).

    Operates at the frame level: caller provides raw video packets (from
    PyAV demuxer), transcoder returns encoded H.264 NAL data suitable
    for the fMP4 muxer.
    """

    def __init__(
        self,
        input_codec_name: str,
        width: int,
        height: int,
        fps: float = 24.0,
        pixel_format: str = "yuv420p",
        force_software: bool = False,
    ) -> None:
        hw = get_hw_capability()
        use_gpu = settings.transcode_prefer_gpu and hw.accel_type != HWAccelType.NONE and not force_software

        # --- Decoder ---
        hw_decoder = None
        if use_gpu:
            if "hevc" in input_codec_name or "h265" in input_codec_name:
                hw_decoder = hw.hevc_decoder
            else:
                hw_decoder = hw.h264_decoder

        decoder_name = hw_decoder or input_codec_name
        self._decoder = av.CodecContext.create(decoder_name, "r")

        # --- Encoder ---
        encoder_name = hw.h264_encoder if use_gpu else "libx264"

        # H.264 requires even dimensions
        enc_width = width if width % 2 == 0 else width + 1
        enc_height = height if height % 2 == 0 else height + 1

        self._encoder = av.CodecContext.create(encoder_name, "w")
        self._encoder.width = enc_width
        self._encoder.height = enc_height
        self._encoder.pix_fmt = "yuv420p"  # H.264 requires yuv420p
        self._encoder.time_base = Fraction(1, int(fps * 1000))
        self._encoder.framerate = Fraction(int(fps * 1000), 1000)
        self._encoder.bit_rate = _parse_bitrate(settings.transcode_video_bitrate)
        self._encoder.gop_size = int(fps * 2)  # Keyframe every ~2 seconds

        # Encoder options based on backend
        opts = {}
        if encoder_name == "libx264":
            opts["preset"] = settings.transcode_video_preset
            opts["tune"] = "zerolatency"
            opts["profile"] = "high"
        elif "nvenc" in encoder_name:
            opts["preset"] = "p4"  # NVENC preset (p1=fastest .. p7=slowest)
            opts["tune"] = "ll"  # Low latency
            opts["rc"] = "vbr"
        elif "videotoolbox" in encoder_name:
            opts["realtime"] = "1"
            opts["allow_sw"] = "1"  # Fallback to software if HW busy
        elif "vaapi" in encoder_name:
            opts["rc_mode"] = "VBR"
        elif "qsv" in encoder_name:
            opts["preset"] = "medium"

        self._encoder.options = opts
        self._encoder.open()

        width = enc_width
        height = enc_height

        self._input_codec = input_codec_name
        self._encoder_name = encoder_name
        self._frames_decoded = 0
        self._frames_encoded = 0
        self._width = width
        self._height = height
        # Tracks whether the standalone decoder was actually used (via decode_packet).
        # When the demux thread decodes frames in-thread (decode_video=True),
        # the standalone decoder is never fed packets and flushing it is wasted work.
        self._decoder_used = False
        self._flushed = False  # Prevents double-flush which causes SIGSEGV

        logger.info(
            "[video_transcoder] Initialized: %s -> %s (%s), %dx%d @%.1ffps %dk",
            input_codec_name,
            encoder_name,
            hw.accel_type.value,
            width,
            height,
            fps,
            self._encoder.bit_rate // 1000 if self._encoder.bit_rate else 0,
        )

    @property
    def codec_private_data(self) -> bytes | None:
        """H.264 extradata (SPS/PPS) from the encoder, for the fMP4 init segment."""
        if self._encoder.extradata:
            return bytes(self._encoder.extradata)
        return None

    @property
    def width(self) -> int:
        return self._width

    @property
    def height(self) -> int:
        return self._height

    def transcode_frame(self, frame: av.VideoFrame) -> list[tuple[bytes, bool, int, int]]:
        """
        Encode a decoded video frame to H.264.

        Args:
            frame: A decoded av.VideoFrame.

        Returns:
            List of (nal_data, is_keyframe, pts, dts) tuples.
        """
        self._frames_decoded += 1
        output = []

        # Ensure correct pixel format for encoder
        if frame.format.name != self._encoder.pix_fmt:
            frame = frame.reformat(format=self._encoder.pix_fmt)

        try:
            for packet in self._encoder.encode(frame):
                self._frames_encoded += 1
                output.append(
                    (
                        bytes(packet),
                        packet.is_keyframe,
                        int(packet.pts) if packet.pts is not None else 0,
                        int(packet.dts) if packet.dts is not None else 0,
                    )
                )
        except av.error.InvalidDataError as e:
            logger.debug("[video_transcoder] Encode error: %s", e)

        return output

    def decode_packet(self, packet: av.Packet) -> list[av.VideoFrame]:
        """Decode a video packet into frames."""
        self._decoder_used = True
        try:
            return list(self._decoder.decode(packet))
        except av.error.InvalidDataError as e:
            logger.debug("[video_transcoder] Decode error: %s", e)
            return []

    def flush(self) -> list[tuple[bytes, bool, int, int]]:
        """
        Flush encoder (and decoder, if it was used) buffers.

        When ``decode_video=True`` is used in PyAVDemuxer, the demux thread
        decodes frames using the container's codec context. In that case the
        standalone ``_decoder`` here is never fed any packets, so flushing
        it is skipped -- avoiding a stall that added ~5 s on some backends.

        Safe to call multiple times -- subsequent calls return an empty list.
        """
        if self._flushed:
            return []
        self._flushed = True

        output = []

        # Flush decoder only if it was actually used (via decode_packet)
        if self._decoder_used:
            try:
                for frame in self._decoder.decode(None):
                    self._frames_decoded += 1
                    if frame.format.name != self._encoder.pix_fmt:
                        frame = frame.reformat(format=self._encoder.pix_fmt)
                    for packet in self._encoder.encode(frame):
                        self._frames_encoded += 1
                        output.append(
                            (
                                bytes(packet),
                                packet.is_keyframe,
                                int(packet.pts) if packet.pts is not None else 0,
                                int(packet.dts) if packet.dts is not None else 0,
                            )
                        )
            except Exception as e:
                logger.debug("[video_transcoder] Decoder flush error: %s", e)
        else:
            logger.debug("[video_transcoder] Skipping decoder flush (decoder not used)")

        # Flush encoder
        try:
            for packet in self._encoder.encode(None):
                self._frames_encoded += 1
                output.append(
                    (
                        bytes(packet),
                        packet.is_keyframe,
                        int(packet.pts) if packet.pts is not None else 0,
                        int(packet.dts) if packet.dts is not None else 0,
                    )
                )
        except Exception as e:
            logger.debug("[video_transcoder] Encoder flush error: %s", e)

        logger.info(
            "[video_transcoder] Flushed: %d decoded, %d encoded total (decoder_used=%s)",
            self._frames_decoded,
            self._frames_encoded,
            self._decoder_used,
        )
        return output

    def close(self) -> None:
        """Release codec contexts.

        Flushes the encoder (if not already flushed) before releasing to avoid
        SIGSEGV when libx264 or hardware encoders have buffered frames at
        teardown time. Double-flushing is the most common cause of SIGSEGV
        in the transcode pipeline.

        PyAV codec contexts are released via garbage collection (no explicit
        close method), so we flush first to ensure native buffers are drained
        before the C-level codec is freed.
        """
        # flush() is idempotent -- safe to call even if already flushed
        self.flush()
        # Release references -- GC will free the native codec contexts
        self._encoder = None
        self._decoder = None

    def __del__(self) -> None:
        self.close()


def _parse_bitrate(bitrate_str: str) -> int:
    """Parse a bitrate string like '4M', '2000k', '5000000' to int bits/s."""
    s = bitrate_str.strip().lower()
    if s.endswith("m"):
        return int(float(s[:-1]) * 1_000_000)
    if s.endswith("k"):
        return int(float(s[:-1]) * 1_000)
    return int(s)
