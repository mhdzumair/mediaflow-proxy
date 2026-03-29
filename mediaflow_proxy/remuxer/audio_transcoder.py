"""
PyAV-based audio transcoder for frame-level codec conversion.

Transcodes audio frames between codecs using PyAV's CodecContext API
(Python bindings for FFmpeg's libavcodec). This provides in-process
audio transcoding without subprocess management or pipe overhead.

Supported input codecs: EAC3, AC3, AAC, Opus, Vorbis, FLAC, MP3
Output codec: AAC-LC (stereo, configurable bitrate)

Architecture:
  raw_frame_bytes -> parse() -> decode() -> resample() -> encode() -> raw_aac_bytes

Usage:
    transcoder = AudioTranscoder("eac3", sample_rate=48000, channels=6)
    for raw_eac3_frame in frames:
        aac_frames = transcoder.transcode(raw_eac3_frame)
        for aac_data in aac_frames:
            write(aac_data)
    # Flush remaining frames
    for aac_data in transcoder.flush():
        write(aac_data)
"""

import logging

import av
from av.audio.resampler import AudioResampler

from mediaflow_proxy.remuxer.ebml_parser import (
    CODEC_ID_AAC,
    CODEC_ID_AC3,
    CODEC_ID_EAC3,
    CODEC_ID_FLAC,
    CODEC_ID_OPUS,
    CODEC_ID_VORBIS,
)

logger = logging.getLogger(__name__)


def _generate_silence_aac_frame() -> bytes | None:
    """Pre-encode a single silent AAC frame (48 kHz stereo, 1024 samples).

    PyAV's AAC encoder has an intermittent ``avcodec_send_frame`` bug when
    rapidly creating/destroying codec contexts, so we retry a few times.
    This function is called once at module load; the result is cached in
    ``_SILENCE_AAC_FRAME``.
    """
    for _attempt in range(10):
        try:
            enc = av.CodecContext.create("aac", "w")
            enc.sample_rate = 48000
            enc.layout = "stereo"
            enc.format = av.AudioFormat("fltp")
            enc.bit_rate = 192000
            enc.open()

            frame = av.AudioFrame(
                format=enc.format.name,
                layout=enc.layout.name,
                samples=enc.frame_size or 1024,
            )
            frame.sample_rate = enc.sample_rate
            frame.pts = 0

            for pkt in enc.encode(frame):
                return bytes(pkt)
            # AAC priming delay: first encode buffered; flush to retrieve
            for pkt in enc.encode(None):
                return bytes(pkt)
        except Exception:
            continue
    return None


# Module-level silence frame -- generated once, reused by every transcoder.
_SILENCE_AAC_FRAME: bytes | None = _generate_silence_aac_frame()

# Map MKV codec IDs to PyAV/FFmpeg codec names
_MKV_TO_FFMPEG_CODEC = {
    CODEC_ID_EAC3: "eac3",
    CODEC_ID_AC3: "ac3",
    CODEC_ID_AAC: "aac",
    CODEC_ID_OPUS: "opus",
    CODEC_ID_VORBIS: "vorbis",
    CODEC_ID_FLAC: "flac",
    "A_DTS": "dts",
    "A_MP3": "mp3",
    "A_MPEG/L3": "mp3",
}

# Codecs that need transcoding to AAC for browser playback
NEEDS_TRANSCODE = frozenset(
    {
        CODEC_ID_EAC3,
        CODEC_ID_AC3,
        CODEC_ID_OPUS,
        CODEC_ID_VORBIS,
        CODEC_ID_FLAC,
        "A_DTS",
        "A_MP3",
        "A_MPEG/L3",
    }
)

# Output AAC settings
_OUTPUT_CODEC = "aac"
_OUTPUT_SAMPLE_FORMAT = "fltp"  # AAC requires float planar
_OUTPUT_LAYOUT = "stereo"

# Map channel count -> FFmpeg layout name
_CHANNEL_LAYOUT_MAP = {
    1: "mono",
    2: "stereo",
    3: "2.1",
    4: "quad",
    6: "5.1",
    8: "7.1",
}


def needs_transcode(codec_id: str) -> bool:
    """Check if an MKV audio codec needs transcoding for browser playback."""
    return codec_id in NEEDS_TRANSCODE


def get_ffmpeg_codec_name(mkv_codec_id: str) -> str | None:
    """Map an MKV CodecID to an FFmpeg codec name."""
    return _MKV_TO_FFMPEG_CODEC.get(mkv_codec_id)


class AudioTranscoder:
    """
    In-process audio transcoder using PyAV's CodecContext API.

    Decodes raw audio frames from one codec and encodes them to AAC-LC
    stereo, suitable for MP4 container and browser playback. No container
    I/O or subprocess involved -- operates directly on raw frame bytes.

    The transcoder handles sample format conversion and resampling
    automatically via AudioResampler.
    """

    def __init__(
        self,
        input_codec: str,
        input_sample_rate: int = 48000,
        input_channels: int = 6,
        output_sample_rate: int = 48000,
        output_channels: int = 2,
        output_bitrate: int = 192000,
    ) -> None:
        """
        Initialize the transcoder.

        Args:
            input_codec: FFmpeg codec name (e.g., "eac3", "ac3", "aac").
            input_sample_rate: Input sample rate in Hz.
            input_channels: Input channel count.
            output_sample_rate: Output sample rate in Hz (default 48000).
            output_channels: Output channel count (default 2 = stereo).
            output_bitrate: Output bitrate in bits/s (default 192000).
        """
        # Set up decoder -- use layout to configure channel count
        # (PyAV's channels property is read-only; layout drives it)
        self._decoder = av.CodecContext.create(input_codec, "r")
        self._decoder.sample_rate = input_sample_rate
        input_layout = _CHANNEL_LAYOUT_MAP.get(input_channels, "stereo")
        self._decoder.layout = input_layout

        # Set up encoder
        self._encoder = av.CodecContext.create(_OUTPUT_CODEC, "w")
        self._encoder.sample_rate = output_sample_rate
        self._encoder.layout = _OUTPUT_LAYOUT
        self._encoder.format = av.AudioFormat(_OUTPUT_SAMPLE_FORMAT)
        self._encoder.bit_rate = output_bitrate
        self._encoder.open()

        # Set up resampler for format/rate/channel conversion
        self._resampler = AudioResampler(
            format=_OUTPUT_SAMPLE_FORMAT,
            layout=_OUTPUT_LAYOUT,
            rate=output_sample_rate,
        )

        self._input_codec = input_codec
        self._frames_decoded = 0
        self._frames_encoded = 0
        self._audio_specific_config: bytes | None = None

        logger.info(
            "[audio_transcoder] Initialized: %s %dHz %dch -> aac %dHz %dch @%dk",
            input_codec,
            input_sample_rate,
            input_channels,
            output_sample_rate,
            output_channels,
            output_bitrate // 1000,
        )

    @property
    def audio_specific_config(self) -> bytes | None:
        """
        AAC AudioSpecificConfig from the encoder (available after first encode).

        This is needed for the MP4 esds box.
        """
        if self._audio_specific_config is not None:
            return self._audio_specific_config

        # PyAV exposes extradata after the encoder is opened
        if self._encoder.extradata:
            self._audio_specific_config = bytes(self._encoder.extradata)
            return self._audio_specific_config
        return None

    @property
    def output_sample_rate(self) -> int:
        return self._encoder.sample_rate

    @property
    def output_channels(self) -> int:
        return self._encoder.channels

    @property
    def frame_size(self) -> int:
        """AAC frame size (samples per frame), typically 1024."""
        return self._encoder.frame_size or 1024

    def transcode(self, raw_frame_data: bytes) -> list[bytes]:
        """
        Transcode a raw audio frame from the input codec to AAC.

        Args:
            raw_frame_data: Raw audio frame bytes (one codec frame, e.g.,
                           one EAC3 sync frame).

        Returns:
            List of raw AAC frame bytes. May return 0, 1, or more frames
            depending on codec frame sizes and buffering.
        """
        output = []

        # Parse raw bytes into packets
        packets = self._decoder.parse(raw_frame_data)

        for packet in packets:
            # Decode to PCM frames
            try:
                decoded_frames = self._decoder.decode(packet)
            except av.error.InvalidDataError as e:
                logger.debug("[audio_transcoder] Decode error (skipping frame): %s", e)
                continue

            for frame in decoded_frames:
                self._frames_decoded += 1

                # Resample to match encoder format
                resampled = self._resampler.resample(frame)
                if resampled is None:
                    continue

                # resampled can be a single frame or list of frames
                if not isinstance(resampled, list):
                    resampled = [resampled]

                for rs_frame in resampled:
                    # Encode to AAC
                    try:
                        encoded_packets = self._encoder.encode(rs_frame)
                    except av.error.InvalidDataError as e:
                        logger.debug("[audio_transcoder] Encode error: %s", e)
                        continue

                    for enc_packet in encoded_packets:
                        self._frames_encoded += 1
                        output.append(bytes(enc_packet))

        return output

    def flush(self) -> list[bytes]:
        """
        Flush the decoder and encoder buffers.

        Call this when the input stream ends to get remaining frames.

        Returns:
            List of remaining raw AAC frame bytes.
        """
        output = []

        # Flush decoder
        try:
            for frame in self._decoder.decode(None):
                self._frames_decoded += 1
                resampled = self._resampler.resample(frame)
                if resampled is None:
                    continue
                if not isinstance(resampled, list):
                    resampled = [resampled]
                for rs_frame in resampled:
                    for enc_packet in self._encoder.encode(rs_frame):
                        self._frames_encoded += 1
                        output.append(bytes(enc_packet))
        except Exception as e:
            logger.debug("[audio_transcoder] Decoder flush error: %s", e)

        # Flush resampler
        try:
            resampled = self._resampler.resample(None)
            if resampled is not None:
                if not isinstance(resampled, list):
                    resampled = [resampled]
                for rs_frame in resampled:
                    for enc_packet in self._encoder.encode(rs_frame):
                        self._frames_encoded += 1
                        output.append(bytes(enc_packet))
        except Exception as e:
            logger.debug("[audio_transcoder] Resampler flush error: %s", e)

        # Flush encoder
        try:
            for enc_packet in self._encoder.encode(None):
                self._frames_encoded += 1
                output.append(bytes(enc_packet))
        except Exception as e:
            logger.debug("[audio_transcoder] Encoder flush error: %s", e)

        logger.info(
            "[audio_transcoder] Flushed: %d decoded, %d encoded total",
            self._frames_decoded,
            self._frames_encoded,
        )
        return output

    def generate_silence_frame(self) -> bytes | None:
        """Return a pre-encoded silent AAC frame (module-level singleton)."""
        return _SILENCE_AAC_FRAME

    def close(self) -> None:
        """Release codec contexts (best-effort; PyAV AudioCodecContext may not have close())."""
        for ctx in (self._decoder, self._encoder):
            try:
                if hasattr(ctx, "close"):
                    ctx.close()
            except Exception:
                pass

    def __del__(self) -> None:
        self.close()
