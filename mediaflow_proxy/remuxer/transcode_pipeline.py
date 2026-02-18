"""
Streaming transcode pipelines producing fragmented MP4 on-the-fly.

Three pipelines are provided:

1. ``stream_transcode_fmp4`` -- **MKV fast path (continuous)**.
   Uses the custom EBML demuxer for zero-copy video passthrough (H.264/H.265)
   with audio-only transcoding. Best for MKV sources with browser-compatible
   video but incompatible audio. Emits init + media fragments.

2. ``stream_segment_fmp4`` -- **MKV fast path (HLS segment)**.
   Same EBML demuxer and video passthrough as above, but adapted for
   per-segment HLS delivery: no init segment, ``start_decode_time_ms``
   for correct tfdt placement, and frame-count bounding for precise
   segment duration control.

3. ``stream_transcode_universal`` -- **Universal path via PyAV**.
   Demuxes any container format (MKV, MP4, TS, etc.) using PyAV, optionally
   re-encodes video (GPU-accelerated when available), and transcodes audio.
   Required when the video codec needs re-encoding or the source is not MKV.

All pipelines produce on-the-fly fMP4 fragments suitable for streaming
via ``StreamingResponse``.
"""

import asyncio
import hashlib
import logging
from collections.abc import AsyncIterator

import av
from av.audio.resampler import AudioResampler

from mediaflow_proxy.remuxer.audio_transcoder import AudioTranscoder, get_ffmpeg_codec_name, needs_transcode
from mediaflow_proxy.remuxer.codec_utils import (
    _PYAV_TO_MKV_AUDIO,
    _PYAV_TO_MKV_VIDEO,
    annexb_to_avcc,
    ensure_avcc_extradata,
    audio_needs_transcode as pyav_audio_needs_transcode,
    video_needs_reencode as pyav_video_needs_reencode,
)
from mediaflow_proxy.remuxer.ebml_parser import (
    CODEC_ID_H264,
    CODEC_ID_H265,
    MKVTrack,
)
from mediaflow_proxy.remuxer.mkv_demuxer import MKVDemuxer, MKVHeader
from mediaflow_proxy.remuxer.mp4_muxer import FMP4StreamMuxer
from mediaflow_proxy.remuxer.pyav_demuxer import PyAVDemuxer
from mediaflow_proxy.remuxer.video_transcoder import VideoTranscoder

logger = logging.getLogger(__name__)

# Video timescale (90kHz is standard for MPEG transport)
_VIDEO_TIMESCALE = 90000


def derive_mp4_cache_key(
    chat_id: str | int | None,
    message_id: int | None,
    file_id: str | None,
) -> str:
    """Derive a deterministic cache key for a transcoded stream."""
    if file_id:
        raw = f"mp4:file_id:{file_id}"
    elif chat_id is not None and message_id is not None:
        raw = f"mp4:chat:{chat_id}:msg:{message_id}"
    else:
        return ""
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


async def stream_transcode_fmp4(
    source: AsyncIterator[bytes],
    *,
    max_duration_ms: float | None = None,
) -> AsyncIterator[bytes]:
    """
    Stream MKV-to-fMP4 transcoding as an async generator (continuous mode).

    This pipeline copies video (passthrough) and transcodes audio from
    EAC3/AC3 to AAC. Used for continuous single-request fMP4 streaming.
    HLS segments use the universal pipeline with video re-encoding instead.

    Yields:
      1. First yield: fMP4 init segment (ftyp + moov)
      2. Subsequent yields: fMP4 media fragments (moof + mdat)

    Args:
        source: Async iterator of MKV bytes (e.g., from Telegram stream).
        max_duration_ms: If set, stop emitting after this many milliseconds
            of media have been produced.

    Yields:
        bytes chunks forming a valid fMP4 byte stream.
    """
    transcoder = None
    video_frame_count = 0
    audio_frame_count = 0
    fragment_count = 0
    bytes_out = 0
    cancelled = False

    try:
        # Phase 1: Parse MKV header
        demuxer = MKVDemuxer()
        header = await demuxer.read_header(source)

        if not header.tracks:
            raise ValueError("MKV file has no tracks")

        video_track = _find_video_track(header)
        audio_track = _find_audio_track(header)

        if video_track is None:
            raise ValueError("No supported video track found (need H.264 or H.265)")

        logger.info(
            "[pipeline] MKV header: duration=%.1fs, video=%s %dx%d, audio=%s %dHz %dch",
            header.duration_ms / 1000.0,
            video_track.codec_id,
            video_track.pixel_width,
            video_track.pixel_height,
            audio_track.codec_id if audio_track else "none",
            int(audio_track.sample_rate) if audio_track else 0,
            audio_track.channels if audio_track else 0,
        )

        # Phase 2: Set up audio transcoder
        if audio_track and needs_transcode(audio_track.codec_id):
            ffmpeg_codec = get_ffmpeg_codec_name(audio_track.codec_id)
            if ffmpeg_codec:
                transcoder = AudioTranscoder(
                    input_codec=ffmpeg_codec,
                    input_sample_rate=int(audio_track.sample_rate),
                    input_channels=audio_track.channels,
                    output_sample_rate=48000,
                    output_channels=2,
                    output_bitrate=192000,
                )
                logger.info("[pipeline] Audio transcoding: %s -> AAC", audio_track.codec_id)
            else:
                logger.warning("[pipeline] No FFmpeg codec for %s, skipping audio", audio_track.codec_id)
                audio_track = None

        audio_timescale = 48000 if transcoder else (int(audio_track.effective_sample_rate) if audio_track else 48000)

        # Phase 3: Build init segment with placeholder AAC config
        # We'll use a default AAC config (48kHz stereo LC) initially.
        # If the encoder provides a different one, the decoder should still handle it
        # since the actual config is embedded in the AAC frames.
        default_asc = bytes([0x11, 0x90])  # 48kHz stereo LC

        muxer = FMP4StreamMuxer(
            video_track=video_track,
            audio_sample_rate=48000 if transcoder else (int(audio_track.sample_rate) if audio_track else 48000),
            audio_channels=2 if transcoder else (audio_track.channels if audio_track else 2),
            audio_specific_config=default_asc,
            video_timescale=_VIDEO_TIMESCALE,
            audio_timescale=audio_timescale,
            duration_ms=header.duration_ms,
            fragment_duration_ms=2000.0,
        )

        # Check if we can get a real ASC from the encoder before building init
        if transcoder and transcoder.audio_specific_config:
            muxer.update_audio_specific_config(transcoder.audio_specific_config)

        init_segment = muxer.build_init_segment()
        logger.info("[pipeline] Init segment: %d bytes", len(init_segment))
        yield init_segment
        bytes_out = len(init_segment)

        # Phase 4: Process frames and emit fragments
        last_video_ts_ms = 0.0
        emitted_duration_ms = 0.0

        async for frame in demuxer.iter_frames(source):
            if video_track and frame.track_number == video_track.track_number:
                # Video frame (passthrough -- no decode/re-encode)
                duration_ms = frame.duration_ms
                if duration_ms <= 0 and video_track.frame_duration_ms > 0:
                    duration_ms = video_track.frame_duration_ms
                elif duration_ms <= 0:
                    if video_frame_count > 0 and frame.timestamp_ms > last_video_ts_ms:
                        duration_ms = frame.timestamp_ms - last_video_ts_ms
                    else:
                        duration_ms = 1000.0 / 24.0  # Fallback 24fps

                duration_ticks = max(1, int(duration_ms * _VIDEO_TIMESCALE / 1000.0))

                # Pass absolute PTS for CTS (composition time offset).
                # MKV timestamps are display-order (PTS); the muxer
                # accumulates DTS monotonically, so the difference is
                # written as CTS in the trun sample entry.
                pts_ticks = int(frame.timestamp_ms * _VIDEO_TIMESCALE / 1000.0)

                # Ensure AVCC format and skip non-VCL NAL-only samples
                sample_data = annexb_to_avcc(frame.data, filter_ps=False)
                if not sample_data or not _has_valid_video_nal(sample_data, video_track.codec_id):
                    continue

                muxer.add_video_sample(
                    sample_data,
                    duration_ticks,
                    frame.is_keyframe,
                    pts_ticks=pts_ticks,
                )
                last_video_ts_ms = frame.timestamp_ms
                video_frame_count += 1
                emitted_duration_ms += duration_ms

            elif audio_track and frame.track_number == audio_track.track_number:
                if transcoder:
                    aac_frames = transcoder.transcode(frame.data)
                    for aac_data in aac_frames:
                        muxer.add_audio_sample(aac_data, transcoder.frame_size)
                        audio_frame_count += 1
                else:
                    # Audio passthrough
                    duration_ms = frame.duration_ms
                    if duration_ms <= 0 and audio_track.frame_duration_ms > 0:
                        duration_ms = audio_track.frame_duration_ms
                    elif duration_ms <= 0:
                        duration_ms = 1024.0 / audio_track.sample_rate * 1000.0
                    duration_ticks = max(1, int(duration_ms * audio_timescale / 1000.0))
                    muxer.add_audio_sample(frame.data, duration_ticks)
                    audio_frame_count += 1

            # Check if we should emit a fragment
            fragment = muxer.flush_fragment()
            if fragment:
                fragment_count += 1
                bytes_out += len(fragment)
                yield fragment

            # Duration bounding (e.g. for max_duration_ms safety net)
            if max_duration_ms is not None and emitted_duration_ms >= max_duration_ms:
                logger.debug(
                    "[pipeline] Duration limit reached (%.0fms >= %.0fms), stopping",
                    emitted_duration_ms,
                    max_duration_ms,
                )
                break

        # Flush remaining audio from transcoder
        if transcoder:
            for aac_data in transcoder.flush():
                muxer.add_audio_sample(aac_data, transcoder.frame_size)
                audio_frame_count += 1

        # Emit final fragment
        final = muxer.flush_final()
        if final:
            fragment_count += 1
            bytes_out += len(final)
            yield final

    except (GeneratorExit, asyncio.CancelledError):
        cancelled = True
        logger.info("[pipeline] Client disconnected, stopping pipeline")
    except Exception as exc:
        # Source exhausted with 0 bytes during header parsing = client disconnect
        if bytes_out == 0 and "prematurely" in str(exc):
            cancelled = True
            logger.info("[pipeline] Client disconnected before streaming started")
        else:
            logger.exception("[pipeline] Pipeline error")
    finally:
        if transcoder:
            transcoder.close()

        # Close the source generator to stop the upstream download
        if hasattr(source, "aclose"):
            try:
                await source.aclose()
            except Exception:
                pass

    if cancelled:
        logger.info(
            "[pipeline] Cancelled after %d video, %d audio frames, %d fragments, %d bytes out",
            video_frame_count,
            audio_frame_count,
            fragment_count,
            bytes_out,
        )
    else:
        logger.info(
            "[pipeline] Complete: %d video, %d audio frames, %d fragments, %d bytes out",
            video_frame_count,
            audio_frame_count,
            fragment_count,
            bytes_out,
        )


# =============================================================================
# MKV fast-path HLS segment pipeline
# =============================================================================


async def stream_segment_fmp4(
    source: AsyncIterator[bytes],
    *,
    start_decode_time_ms: float = 0.0,
    max_duration_ms: float | None = None,
) -> AsyncIterator[bytes]:
    """
    MKV fast-path pipeline for a single HLS fMP4 media segment.

    Adapted from ``stream_transcode_fmp4`` (continuous mode) but designed
    for per-segment HLS delivery:

    - **No init segment** -- HLS serves init separately.
    - **start_decode_time_ms** places the segment's tfdt correctly on
      the global HLS timeline.
    - **Frame-count bounding** stops after exactly the right number of
      video and audio frames for the segment duration.
    - **Video passthrough** with exact MKV absolute timestamps (no
      encoder, no DTS drift).
    - **AudioTranscoder** with deterministic per-frame AAC output.

    Args:
        source: Async iterator of bytes (seek_header + cluster data).
        start_decode_time_ms: Absolute time of segment start on HLS
            timeline, used for muxer tfdt and frame skipping.
        max_duration_ms: Segment duration in ms.  Controls frame-count
            bounding for both video and audio.

    Yields:
        fMP4 media fragments (moof + mdat) -- no init segment.
    """
    transcoder = None
    video_frame_count = 0
    audio_frame_count = 0
    fragment_count = 0
    bytes_out = 0
    cancelled = False

    try:
        # Phase 1: Parse MKV header from seek_header + cluster bytes
        demuxer = MKVDemuxer()
        header = await demuxer.read_header(source)

        if not header.tracks:
            raise ValueError("MKV segment source has no tracks")

        video_track = _find_video_track(header)
        audio_track = _find_audio_track(header)

        if video_track is None:
            raise ValueError("No supported video track found for segment pipeline")

        logger.info(
            "[seg_fmp4] Segment %.1f-%.1fs: video=%s %dx%d, audio=%s %dHz %dch",
            start_decode_time_ms / 1000.0,
            (start_decode_time_ms + (max_duration_ms or 0)) / 1000.0,
            video_track.codec_id,
            video_track.pixel_width,
            video_track.pixel_height,
            audio_track.codec_id if audio_track else "none",
            int(audio_track.sample_rate) if audio_track else 0,
            audio_track.channels if audio_track else 0,
        )

        # Phase 2: Set up audio transcoder
        if audio_track and needs_transcode(audio_track.codec_id):
            ffmpeg_codec = get_ffmpeg_codec_name(audio_track.codec_id)
            if ffmpeg_codec:
                transcoder = AudioTranscoder(
                    input_codec=ffmpeg_codec,
                    input_sample_rate=int(audio_track.sample_rate),
                    input_channels=audio_track.channels,
                    output_sample_rate=48000,
                    output_channels=2,
                    output_bitrate=192000,
                )
                logger.info("[seg_fmp4] Audio transcoding: %s -> AAC", audio_track.codec_id)
            else:
                logger.warning("[seg_fmp4] No FFmpeg codec for %s, skipping audio", audio_track.codec_id)
                audio_track = None

        audio_timescale = 48000 if transcoder else (int(audio_track.effective_sample_rate) if audio_track else 48000)
        aac_frame_size = transcoder.frame_size if transcoder else 1024
        audio_sr = 48000 if transcoder else (int(audio_track.sample_rate) if audio_track else 48000)

        # Phase 3: Build muxer (NO init segment emitted -- HLS serves it separately)
        default_asc = bytes([0x11, 0x90])  # 48kHz stereo LC

        muxer = FMP4StreamMuxer(
            video_track=video_track,
            audio_sample_rate=audio_sr,
            audio_channels=2 if transcoder else (audio_track.channels if audio_track else 2),
            audio_specific_config=default_asc,
            video_timescale=_VIDEO_TIMESCALE,
            audio_timescale=audio_timescale,
            duration_ms=max_duration_ms or 0.0,
            fragment_duration_ms=2000.0,
            start_decode_time_ms=start_decode_time_ms,
            audio_frame_size=aac_frame_size,
        )

        if transcoder and transcoder.audio_specific_config:
            muxer.update_audio_specific_config(transcoder.audio_specific_config)

        # Phase 4: Compute frame-count limits for precise segment bounding
        fps = 24.0
        if video_track.default_duration_ns > 0:
            fps = 1_000_000_000.0 / video_track.default_duration_ns
        elif video_track.frame_duration_ms > 0:
            fps = 1000.0 / video_track.frame_duration_ms

        _max_video_frames: int | None = None
        _max_audio_frames: int | None = None
        segment_end_ms: float | None = None

        if max_duration_ms is not None:
            segment_end_ms = start_decode_time_ms + max_duration_ms
            _max_video_frames = round(max_duration_ms * fps / 1000.0)

            # Audio frame-count: tile AAC frames across timeline and count
            # how many fall within [start_ms, end_ms).  This mirrors the
            # muxer's _audio_decode_time alignment exactly.
            if aac_frame_size > 0 and audio_sr > 0:
                end_time_ms = start_decode_time_ms + max_duration_ms
                frames_before_start = int(start_decode_time_ms / 1000.0 * audio_sr / aac_frame_size)
                frames_before_end = int(end_time_ms / 1000.0 * audio_sr / aac_frame_size)
                _max_audio_frames = frames_before_end - frames_before_start
            else:
                _max_audio_frames = None

            logger.info(
                "[seg_fmp4] Frame limits: video=%s @%.1ffps, audio=%s (frame_size=%d, sr=%d), window=%.3f-%.3fs",
                _max_video_frames,
                fps,
                _max_audio_frames,
                aac_frame_size,
                audio_sr,
                start_decode_time_ms / 1000.0,
                segment_end_ms / 1000.0 if segment_end_ms is not None else -1.0,
            )

        # Phase 5: Process frames
        last_video_ts_ms = 0.0
        _video_limit_hit = False
        _audio_limit_hit = False
        _got_keyframe = False  # Must see IDR before emitting any video

        async for frame in demuxer.iter_frames(source):
            # ── Video frame (passthrough) ──
            if video_track and frame.track_number == video_track.track_number:
                # Segment time-window clamp (critical for monotonic HLS PTS):
                # with overlapped MKV byte ranges, we may receive extra video
                # blocks from the next segment's cluster. Drop anything outside
                # [segment_start, segment_end) to prevent timestamp regressions
                # at segment boundaries.
                if segment_end_ms is not None and frame.timestamp_ms >= segment_end_ms:
                    _video_limit_hit = True
                    if _audio_limit_hit or audio_track is None:
                        break
                    continue

                # Check frame-count limit
                if _max_video_frames is not None and video_frame_count >= _max_video_frames:
                    _video_limit_hit = True
                    if _audio_limit_hit or audio_track is None:
                        break
                    continue

                # Ensure AVCC length-prefixed NAL format for fMP4.
                # Some MKV files store frames in mixed Annex B / AVCC.
                # annexb_to_avcc converts start-code NALUs to length-
                # prefixed and is a no-op for already-AVCC data.
                # filter_ps=False preserves in-band SPS/PPS updates.
                sample_data = annexb_to_avcc(frame.data, filter_ps=False)
                if not sample_data:
                    continue

                # Skip non-VCL samples (SEI-only, filler, padding).
                if not _has_valid_video_nal(sample_data, video_track.codec_id):
                    continue

                # Gate on first keyframe: fMP4 segments must start with a sync sample.
                if not _got_keyframe:
                    if not frame.is_keyframe:
                        continue
                    _got_keyframe = True
                    logger.info(
                        "[seg_fmp4] First keyframe at %.3fs",
                        frame.timestamp_ms / 1000.0,
                    )

                # Compute duration
                duration_ms = frame.duration_ms
                if duration_ms <= 0 and video_track.frame_duration_ms > 0:
                    duration_ms = video_track.frame_duration_ms
                elif duration_ms <= 0:
                    if video_frame_count > 0 and frame.timestamp_ms > last_video_ts_ms:
                        duration_ms = frame.timestamp_ms - last_video_ts_ms
                    else:
                        duration_ms = 1000.0 / fps

                duration_ticks = max(1, int(duration_ms * _VIDEO_TIMESCALE / 1000.0))

                # Absolute PTS from MKV Cluster timestamps -- exact, no
                # encoder involved, no drift.
                pts_ticks = int(frame.timestamp_ms * _VIDEO_TIMESCALE / 1000.0)

                muxer.add_video_sample(
                    sample_data,
                    duration_ticks,
                    frame.is_keyframe,
                    pts_ticks=pts_ticks,
                )
                last_video_ts_ms = frame.timestamp_ms
                video_frame_count += 1

            # ── Audio frame ──
            elif audio_track and frame.track_number == audio_track.track_number:
                # Check frame-count limit
                if _max_audio_frames is not None and audio_frame_count >= _max_audio_frames:
                    _audio_limit_hit = True
                    if _video_limit_hit or video_track is None:
                        break
                    continue

                if transcoder:
                    aac_frames = transcoder.transcode(frame.data)
                    for aac_data in aac_frames:
                        if _max_audio_frames is not None and audio_frame_count >= _max_audio_frames:
                            _audio_limit_hit = True
                            break
                        muxer.add_audio_sample(aac_data, transcoder.frame_size)
                        audio_frame_count += 1
                else:
                    # Audio passthrough
                    duration_ms = frame.duration_ms
                    if duration_ms <= 0 and audio_track.frame_duration_ms > 0:
                        duration_ms = audio_track.frame_duration_ms
                    elif duration_ms <= 0:
                        duration_ms = 1024.0 / audio_track.sample_rate * 1000.0
                    duration_ticks = max(1, int(duration_ms * audio_timescale / 1000.0))
                    muxer.add_audio_sample(frame.data, duration_ticks)
                    audio_frame_count += 1

            # Check if we should emit a fragment
            fragment = muxer.flush_fragment()
            if fragment:
                fragment_count += 1
                bytes_out += len(fragment)
                yield fragment

            # Early exit when both tracks hit their limits
            if _video_limit_hit and (_audio_limit_hit or audio_track is None):
                break
            if _audio_limit_hit and (video_track is None):
                break

        # Flush remaining audio from transcoder
        if transcoder and not _audio_limit_hit:
            for aac_data in transcoder.flush():
                if _max_audio_frames is not None and audio_frame_count >= _max_audio_frames:
                    break
                muxer.add_audio_sample(aac_data, transcoder.frame_size)
                audio_frame_count += 1

        # Emit final fragment
        final = muxer.flush_final()
        if final:
            fragment_count += 1
            bytes_out += len(final)
            yield final

    except (GeneratorExit, asyncio.CancelledError):
        cancelled = True
        logger.info("[seg_fmp4] Client disconnected, stopping segment pipeline")
    except Exception as exc:
        if bytes_out == 0 and "prematurely" in str(exc):
            cancelled = True
            logger.info("[seg_fmp4] Client disconnected before segment started")
        else:
            logger.exception("[seg_fmp4] Segment pipeline error")
    finally:
        if transcoder:
            transcoder.close()
        if hasattr(source, "aclose"):
            try:
                await source.aclose()
            except Exception:
                pass

    if cancelled:
        logger.info(
            "[seg_fmp4] Cancelled: %d video, %d audio frames, %d fragments, %d bytes",
            video_frame_count,
            audio_frame_count,
            fragment_count,
            bytes_out,
        )
    else:
        logger.info(
            "[seg_fmp4] Complete: %d video, %d audio frames, %d fragments, %d bytes",
            video_frame_count,
            audio_frame_count,
            fragment_count,
            bytes_out,
        )


# =============================================================================
# Helper functions
# =============================================================================


# H.264 VCL NAL unit types (actual video slices)
_H264_VCL_TYPES = frozenset({1, 2, 3, 4, 5})  # Non-IDR, Part A/B/C, IDR
# HEVC VCL NAL unit types (BLA through CRA, 0-21)
_HEVC_VCL_TYPES = frozenset(range(0, 22))


def _has_valid_video_nal(data: bytes, codec_id: str = CODEC_ID_H264) -> bool:
    """
    Check if AVCC/HVCC-formatted sample data contains at least one VCL NAL.

    For H.264: VCL types 1-5 (Non-IDR through IDR slice).
    For HEVC: VCL types 0-21 (BLA_W_LP through CRA_NUT).

    Returns True if at least one qualifying NAL is present.
    """
    if len(data) < 5:
        return False

    is_hevc = codec_id == CODEC_ID_H265
    vcl_types = _HEVC_VCL_TYPES if is_hevc else _H264_VCL_TYPES

    pos = 0
    size = len(data)
    while pos + 4 < size:
        nal_len = int.from_bytes(data[pos : pos + 4], "big")
        if nal_len <= 0 or nal_len > size - pos - 4:
            break
        nal_byte = data[pos + 4]
        if is_hevc:
            forbidden = (nal_byte >> 7) & 1
            nal_type = (nal_byte >> 1) & 0x3F
        else:
            forbidden = (nal_byte >> 7) & 1
            nal_type = nal_byte & 0x1F
        if forbidden == 0 and nal_type in vcl_types:
            return True
        pos += 4 + nal_len
    return False


def _find_video_track(header: MKVHeader) -> MKVTrack | None:
    """Find the first supported video track."""
    for track in header.tracks:
        if track.is_video and track.codec_id in (CODEC_ID_H264, CODEC_ID_H265):
            return track
    return None


def _find_audio_track(header: MKVHeader) -> MKVTrack | None:
    """Find the first audio track."""
    for track in header.tracks:
        if track.is_audio:
            return track
    return None


# =============================================================================
# Universal transcode pipeline (PyAV-based, any container, video re-encoding)
# =============================================================================


def _build_synthetic_mkv_track(
    codec_id: str,
    codec_private: bytes,
    *,
    width: int = 0,
    height: int = 0,
    sample_rate: float = 0.0,
    channels: int = 0,
    track_type: int = 1,
    track_number: int = 1,
    default_duration_ns: int = 0,
) -> MKVTrack:
    """
    Create a synthetic MKVTrack from PyAV stream metadata.

    The fMP4 muxer expects MKVTrack objects. This bridges PyAV stream info
    to the existing muxer interface without modifying the muxer.
    """
    return MKVTrack(
        track_number=track_number,
        track_type=track_type,
        codec_id=codec_id,
        codec_private=codec_private,
        pixel_width=width,
        pixel_height=height,
        sample_rate=sample_rate,
        channels=channels,
        default_duration_ns=default_duration_ns,
    )


def _update_init_extradata(
    video_transcoder: VideoTranscoder,
    video_track: MKVTrack,
    first_nal_data: bytes,
) -> None:
    """
    Update a video track's codec_private with SPS/PPS from the encoder.

    Hardware encoders (VideoToolbox, NVENC) often don't expose extradata
    on the codec context.  Instead, they embed SPS/PPS as in-band NAL
    units in the first keyframe.  This function extracts them and writes
    proper AVCC-format extradata into the MKVTrack so the init segment
    built from it is valid.
    """
    from mediaflow_proxy.remuxer.codec_utils import ensure_avcc_extradata, extract_sps_pps_from_annexb

    # Try encoder context first (works for libx264 / software)
    extradata = video_transcoder.codec_private_data
    if not extradata:
        # Extract from first keyframe NAL data (HW encoders)
        extradata = extract_sps_pps_from_annexb(first_nal_data)
    if extradata:
        extradata = ensure_avcc_extradata(extradata)
        video_track.codec_private = extradata
        logger.info(
            "[universal] Updated init extradata from encoder: %d bytes",
            len(extradata),
        )


async def stream_transcode_universal(
    source: AsyncIterator[bytes],
    *,
    force_video_reencode: bool = False,
    max_duration_ms: float | None = None,
    start_decode_time_ms: float = 0.0,
    emit_init_segment: bool = True,
    force_software_encode: bool = False,
) -> AsyncIterator[bytes]:
    """
    Universal transcode pipeline using PyAV for demuxing and encoding.

    Handles any container format and optionally re-encodes video using
    GPU-accelerated codecs when available.

    Args:
        source: Async iterator of container bytes (MKV, MP4, TS, etc.).
        force_video_reencode: When True, always re-encode video even if
            the codec is normally browser-compatible (e.g. H.264).  Useful
            for live MPEG-TS sources with corrupt bitstreams.
        max_duration_ms: If set, stop emitting after this many milliseconds
            of media have been produced.
        start_decode_time_ms: Initial decode time offset for fMP4 timestamps.
        emit_init_segment: Whether to yield the fMP4 init segment (ftyp+moov).
        force_software_encode: When True, force ``libx264`` software encoder
            instead of hardware (VideoToolbox/NVENC).  Used for HLS per-segment
            transcoding to avoid SIGSEGV crashes with hardware encoders.

    Yields:
        bytes chunks forming a valid fMP4 byte stream.
    """
    video_transcoder = None
    audio_encoder = None
    audio_resampler = None
    video_frame_count = 0
    audio_frame_count = 0
    fragment_count = 0
    bytes_out = 0
    cancelled = False
    _audio_flushed = False  # Prevents double-flush SIGSEGV on teardown

    # Both video and audio decode decisions are deferred until after stream
    # discovery, so the demux thread only decodes what's actually needed.
    # Video decoding is only required when the codec needs re-encoding;
    # passthrough uses raw packets.  Audio decoding is needed when the
    # codec is not browser-compatible (e.g. ac3 -> aac).
    demuxer = PyAVDemuxer(decode_video=False, decode_audio=False)

    try:
        # Phase 1: Start demuxing -- opens the container in a background thread,
        # discovers streams, and starts enqueuing packets. Awaits until stream
        # metadata is available.
        await demuxer.start(source)

        vs = demuxer.video_stream
        aus = demuxer.audio_stream

        if vs is None and aus is None:
            demuxer.enable_video_decode(False)
            demuxer.enable_audio_decode(False)
            raise ValueError("No video or audio streams found in source")

        # Phase 2: Determine what needs transcoding
        do_video_transcode = False
        do_audio_transcode = False
        video_mkv_codec = ""
        audio_mkv_codec = ""

        if vs:
            video_mkv_codec = _PYAV_TO_MKV_VIDEO.get(vs.codec_name, vs.codec_name)
            do_video_transcode = (
                force_video_reencode
                or pyav_video_needs_reencode(vs.codec_name)
                or pyav_video_needs_reencode(video_mkv_codec)
            )
        if aus:
            audio_mkv_codec = _PYAV_TO_MKV_AUDIO.get(aus.codec_name, aus.codec_name)
            do_audio_transcode = pyav_audio_needs_transcode(aus.codec_name) or pyav_audio_needs_transcode(
                audio_mkv_codec
            )

        # Tell the demux thread whether to decode video/audio in-thread.
        # This must be called before consuming packets via iter_packets().
        demuxer.enable_video_decode(do_video_transcode)
        demuxer.enable_audio_decode(do_audio_transcode)

        logger.info(
            "[universal] Streams: video=%s (reencode=%s), audio=%s (transcode=%s)",
            vs.codec_name if vs else "none",
            do_video_transcode,
            aus.codec_name if aus else "none",
            do_audio_transcode,
        )

        # Phase 3: Set up transcoders
        if do_video_transcode and vs:
            video_transcoder = VideoTranscoder(
                input_codec_name=vs.codec_name,
                width=vs.width,
                height=vs.height,
                fps=vs.fps or 24.0,
                pixel_format=vs.pixel_format or "yuv420p",
                force_software=force_software_encode,
            )

        # Audio encoding: since audio is decoded in the demux thread, we only
        # need a resampler and encoder here. No standalone decoder needed.
        audio_encoder = None
        audio_resampler = None
        if do_audio_transcode and aus:
            audio_encoder = av.CodecContext.create("aac", "w")
            audio_encoder.sample_rate = 48000
            audio_encoder.layout = "stereo"
            audio_encoder.format = av.AudioFormat("fltp")
            audio_encoder.bit_rate = 192000
            audio_encoder.open()

            audio_resampler = AudioResampler(
                format="fltp",
                layout="stereo",
                rate=48000,
            )

            logger.info(
                "[universal] Audio transcoding: %s %dHz %dch -> aac 48000Hz 2ch @192k",
                aus.codec_name,
                aus.sample_rate or 0,
                aus.channels or 0,
            )

        # Phase 4: Build init segment
        # When transcoding video, force output codec to H.264 regardless
        # of whether the encoder has produced extradata yet (libx264 emits
        # SPS/PPS only after the first encode call).
        if do_video_transcode and video_transcoder:
            raw_extradata = video_transcoder.codec_private_data or b""
            video_codec_private = ensure_avcc_extradata(raw_extradata) if raw_extradata else b""
            video_track_codec = CODEC_ID_H264  # Output is always H.264
        elif vs:
            # Ensure extradata is in avcC format (MPEG-TS returns Annex B)
            video_codec_private = ensure_avcc_extradata(vs.extradata)
            video_track_codec = video_mkv_codec or CODEC_ID_H264
        else:
            video_codec_private = b""
            video_track_codec = CODEC_ID_H264

        video_track = None
        if vs:
            output_w = video_transcoder.width if video_transcoder else vs.width
            output_h = video_transcoder.height if video_transcoder else vs.height
            frame_dur_ns = int(1_000_000_000 / (vs.fps or 24.0))
            video_track = _build_synthetic_mkv_track(
                codec_id=video_track_codec,
                codec_private=video_codec_private,
                width=output_w,
                height=output_h,
                track_type=1,
                track_number=1,
                default_duration_ns=frame_dur_ns,
            )

        audio_sr = 48000 if audio_encoder else (aus.sample_rate if aus else 48000)
        audio_ch = 2 if audio_encoder else (aus.channels if aus else 2)
        default_asc = bytes([0x11, 0x90])  # 48kHz stereo LC

        if not video_track:
            raise ValueError("No video track available for muxing")

        # AAC frame size (samples per frame), typically 1024
        aac_frame_size = audio_encoder.frame_size if audio_encoder and audio_encoder.frame_size else 1024

        muxer = FMP4StreamMuxer(
            video_track=video_track,
            audio_sample_rate=audio_sr,
            audio_channels=audio_ch,
            audio_specific_config=default_asc,
            video_timescale=_VIDEO_TIMESCALE,
            audio_timescale=audio_sr,
            # Cap duration: live/unknown streams report 0 or garbage values.
            # Anything over 24h is almost certainly wrong for a real file.
            duration_ms=vs.duration_seconds * 1000.0
            if vs and vs.duration_seconds and 0 < vs.duration_seconds < 86400
            else 0.0,
            fragment_duration_ms=2000.0,
            start_decode_time_ms=start_decode_time_ms,
            # Pass AAC frame size so the muxer can align the audio tfdt to
            # exact frame boundaries, preventing DTS discontinuities at
            # HLS segment borders.
            audio_frame_size=aac_frame_size,
        )

        if audio_encoder and audio_encoder.extradata:
            muxer.update_audio_specific_config(bytes(audio_encoder.extradata))

        # For hardware encoders (VideoToolbox, NVENC), SPS/PPS extradata may
        # not be available until the first frame is encoded.  Defer the init
        # segment emission until after the first encoded video packet so the
        # init segment always contains valid codec configuration.
        _init_emitted = False

        if emit_init_segment and not do_video_transcode:
            # No re-encoding: extradata comes from the source stream, so we
            # can emit the init segment immediately.
            init_segment = muxer.build_init_segment()
            logger.info("[universal] Init segment: %d bytes", len(init_segment))
            yield init_segment
            bytes_out = len(init_segment)
            _init_emitted = True

        # Phase 5: Process packets
        # For video passthrough: skip until first keyframe and rebase DTS/PTS
        # so fMP4 timestamps start from 0 (live TS streams have huge absolute values).
        _video_dts_base: float | None = None  # first video DTS in seconds
        _got_keyframe = do_video_transcode  # transcoded output always starts with keyframe
        _emitted_video_duration_ms = 0.0  # accumulated video duration for monitoring

        # Offset (video timescale ticks) that maps rebased-to-0 encoder PTS
        # onto the absolute timeline expected by the muxer.  When producing
        # HLS segments starting at e.g. 25 s, the muxer's tfdt is at 25 s
        # but the encoder PTS starts at 0.  Adding this offset realigns them.
        _start_offset_ticks = int(start_decode_time_ms * _VIDEO_TIMESCALE / 1000.0)

        # Pre-compute per-frame duration ticks for re-encoded video (constant
        # with zerolatency / no B-frames).  Used for frame-count-based PTS.
        _fps = (vs.fps or 24.0) if vs else 24.0
        _reencode_dur_ticks = max(1, int(_VIDEO_TIMESCALE / _fps)) if vs else 0

        # Encoder timebase denominator for setting sequential frame.pts on
        # decoded frames before encoding.  Keeps libx264's internal rate
        # control consistent.
        _enc_tb_den: int = 0
        _enc_frame_dur: int = 0
        if video_transcoder:
            _enc_tb_den = video_transcoder._encoder.time_base.denominator
            _enc_frame_dur = max(1, int(_enc_tb_den / _fps))

        # ── Frame-count-based segment bounding ──────────────────────────
        # When producing HLS segments, each segment MUST produce exactly
        # the right number of video (and audio) frames so that the next
        # segment's tfdt is contiguous.  Relying on source PTS is fragile
        # because mid-stream MKV byte ranges may not report accurate PTS.
        #
        # Video: round(duration_ms * fps / 1000) frames.
        #
        # Audio: compute by tiling AAC frames across the timeline.  The
        # audio tfdt of this segment is the cumulative count of AAC frames
        # from time=0 up to start_decode_time_ms.  The next segment's
        # audio tfdt is the cumulative count up to end_time_ms.  The
        # difference gives the exact number of frames this segment must
        # produce to keep segment borders gapless.
        _max_video_frames: int | None = None
        _max_audio_frames: int | None = None
        if max_duration_ms is not None:
            _max_video_frames = round(max_duration_ms * _fps / 1000.0)
            if aac_frame_size > 0 and audio_sr > 0:
                end_time_ms = start_decode_time_ms + max_duration_ms
                # Count of whole AAC frames from t=0 to start and end
                frames_before_start = int(start_decode_time_ms / 1000.0 * audio_sr / aac_frame_size)
                frames_before_end = int(end_time_ms / 1000.0 * audio_sr / aac_frame_size)
                _max_audio_frames = frames_before_end - frames_before_start
            else:
                _max_audio_frames = None  # no cap

        async def _process_packet(packet):
            nonlocal video_frame_count, audio_frame_count, fragment_count, bytes_out
            nonlocal _video_dts_base, _got_keyframe
            nonlocal _emitted_video_duration_ms, _init_emitted

            init_bytes: bytes | None = None  # deferred init, returned alongside fragment

            if vs and packet.stream_index == vs.index and packet.codec_type == "video":
                # ── Frame-count limit for HLS segments ──
                # Stop accepting video once we've emitted enough frames.
                if _max_video_frames is not None and video_frame_count >= _max_video_frames:
                    return None, None

                if do_video_transcode and video_transcoder and packet.decoded_frame is not None:
                    # Set sequential PTS on the decoded frame in encoder
                    # timebase *before* encoding.  The demuxer's frame.pts is
                    # in the demuxer's timebase (e.g. 1/1000 for MKV) which
                    # does NOT match the encoder's timebase (1/(fps*1000)).
                    # Passing the raw integer through causes PTS compression
                    # by ~fps-x, corrupting the output timeline.  Sequential
                    # PTS keeps libx264's rate control consistent.
                    packet.decoded_frame.pts = video_frame_count * _enc_frame_dur

                    # Frame already decoded by the demux thread -- re-encode
                    encoded = video_transcoder.transcode_frame(packet.decoded_frame)
                    for nal_data, is_kf, enc_pts, enc_dts in encoded:
                        # Convert Annex B start codes to AVCC length prefixes.
                        # Hardware encoders (VideoToolbox, NVENC) emit Annex B.
                        sample_data = annexb_to_avcc(nal_data)
                        if not sample_data:
                            continue

                        # Deferred init segment: after the first encode, the HW
                        # encoder's extradata is available.  Extract SPS/PPS and
                        # rebuild the init segment so it has correct codec config.
                        if emit_init_segment and not _init_emitted:
                            _update_init_extradata(video_transcoder, video_track, nal_data)
                            init_bytes = muxer.build_init_segment()
                            logger.info("[universal] Init segment (deferred): %d bytes", len(init_bytes))
                            bytes_out += len(init_bytes)
                            _init_emitted = True

                        # Frame-count-based PTS: since zerolatency produces
                        # no B-frames (PTS == DTS), derive PTS directly from
                        # the output frame index.  This avoids the timebase
                        # mismatch bug and guarantees monotonic timestamps.
                        pts_ticks = _start_offset_ticks + (video_frame_count * _reencode_dur_ticks)

                        muxer.add_video_sample(sample_data, _reencode_dur_ticks, is_kf, pts_ticks=pts_ticks)
                        video_frame_count += 1
                        _emitted_video_duration_ms += _reencode_dur_ticks * 1000.0 / _VIDEO_TIMESCALE
                elif do_video_transcode and video_transcoder:
                    # Fallback: raw packet (shouldn't happen with decode_video=True)
                    logger.warning("[universal] Video packet without decoded frame, skipping")
                else:
                    # Video passthrough -- wait for first keyframe before
                    # sending any video (browser can't decode without IDR).
                    if not _got_keyframe:
                        if not packet.is_keyframe:
                            return None, None
                        _got_keyframe = True
                        logger.info("[universal] First keyframe received, starting video")

                    # Convert Annex B start codes to AVCC length prefixes
                    # if needed (MPEG-TS sources).
                    sample_data = annexb_to_avcc(packet.data)
                    if not sample_data:
                        return None, None

                    dur_ticks = (
                        max(1, int(packet.duration_seconds * _VIDEO_TIMESCALE))
                        if packet.duration > 0
                        else max(1, int(_VIDEO_TIMESCALE / (vs.fps or 24.0)))
                    )

                    # Always pass PTS for CTS computation so B-frames
                    # are properly reordered by the player.
                    pts_ticks = None
                    dts_secs = packet.dts_seconds
                    pts_secs = packet.pts_seconds

                    if _video_dts_base is None:
                        _video_dts_base = dts_secs

                    if packet.pts != 0 and pts_secs != dts_secs:
                        rebased_pts = pts_secs - _video_dts_base
                        pts_ticks = max(0, int(rebased_pts * _VIDEO_TIMESCALE)) + _start_offset_ticks

                    muxer.add_video_sample(sample_data, dur_ticks, packet.is_keyframe, pts_ticks=pts_ticks)
                    video_frame_count += 1
                    _emitted_video_duration_ms += dur_ticks * 1000.0 / _VIDEO_TIMESCALE

            elif aus and packet.stream_index == aus.index and packet.codec_type == "audio":
                # Don't emit audio until the first video keyframe so A/V stay in sync
                if not _got_keyframe:
                    return None, None

                # ── Audio frame-count limit for HLS segments ──
                if _max_audio_frames is not None and audio_frame_count >= _max_audio_frames:
                    return None, None

                if do_audio_transcode and audio_encoder and audio_resampler and packet.decoded_frame is not None:
                    # Audio frame decoded by demux thread -- resample and encode
                    resampled = audio_resampler.resample(packet.decoded_frame)
                    if resampled is not None:
                        if not isinstance(resampled, list):
                            resampled = [resampled]
                        for rs_frame in resampled:
                            if _max_audio_frames is not None and audio_frame_count >= _max_audio_frames:
                                break
                            for enc_pkt in audio_encoder.encode(rs_frame):
                                muxer.add_audio_sample(bytes(enc_pkt), aac_frame_size)
                                audio_frame_count += 1
                elif do_audio_transcode and audio_encoder:
                    # Fallback: raw packet (shouldn't happen with decode_audio=True)
                    logger.warning("[universal] Audio packet without decoded frame, skipping")
                else:
                    # Audio passthrough
                    dur_ticks = max(1, int(packet.duration_seconds * audio_sr)) if packet.duration > 0 else 1024
                    muxer.add_audio_sample(packet.data, dur_ticks)
                    audio_frame_count += 1

            # Emit fragment if ready
            fragment = muxer.flush_fragment()
            if fragment:
                fragment_count += 1
                bytes_out += len(fragment)
                return init_bytes, fragment
            return init_bytes, None

        # Process all packets from the demuxer
        async for packet in demuxer.iter_packets():
            # Frame-count-based segment bounding: stop the packet loop once
            # both video and audio have emitted their target frame counts.
            # Individual _process_packet calls for each track already skip
            # frames beyond the limit, so this break is just an optimisation
            # to avoid draining the entire byte range.
            if _max_video_frames is not None:
                video_done = video_frame_count >= _max_video_frames
                audio_done = _max_audio_frames is None or audio_frame_count >= _max_audio_frames
                if video_done and audio_done:
                    logger.debug(
                        "[universal] Segment frame limits reached: video=%d/%d, audio=%d/%s, emitted=%.0fms",
                        video_frame_count,
                        _max_video_frames,
                        audio_frame_count,
                        _max_audio_frames if _max_audio_frames is not None else "unlimited",
                        _emitted_video_duration_ms,
                    )
                    break

            deferred_init, frag = await _process_packet(packet)
            if deferred_init:
                yield deferred_init
            if frag:
                yield frag

        # Flush video encoder (decoder already flushed in the demux thread).
        # Skip flush if we already reached the frame count limit for HLS
        # segments -- flushed frames would exceed the target and cause
        # DTS overlap with the next segment.
        _video_limit_hit = _max_video_frames is not None and video_frame_count >= _max_video_frames
        if video_transcoder and not _video_limit_hit:
            for nal_data, is_kf, pts, dts in video_transcoder.flush():
                sample_data = annexb_to_avcc(nal_data)
                if not sample_data:
                    continue
                # Use same frame-count-based PTS as the main encode path
                pts_ticks = _start_offset_ticks + (video_frame_count * _reencode_dur_ticks)
                muxer.add_video_sample(sample_data, _reencode_dur_ticks, is_kf, pts_ticks=pts_ticks)
                video_frame_count += 1
                _emitted_video_duration_ms += _reencode_dur_ticks * 1000.0 / _VIDEO_TIMESCALE

        # Flush audio resampler + encoder (decoder already flushed in the demux thread).
        # When audio frame limit was reached, we still need to flush the
        # encoder to drain its internal state, but we discard the output
        # to avoid exceeding the frame count.
        _audio_limit_hit = _max_audio_frames is not None and audio_frame_count >= _max_audio_frames
        if audio_encoder and audio_resampler and _audio_limit_hit:
            # Drain encoder without emitting -- prevents SIGSEGV on teardown
            try:
                audio_resampler.resample(None)
            except Exception:
                pass
            try:
                for _ in audio_encoder.encode(None):
                    pass
            except Exception:
                pass
            _audio_flushed = True
        elif audio_encoder and audio_resampler:
            try:
                resampled = audio_resampler.resample(None)
                if resampled is not None:
                    if not isinstance(resampled, list):
                        resampled = [resampled]
                    for rs_frame in resampled:
                        if _max_audio_frames is not None and audio_frame_count >= _max_audio_frames:
                            break
                        for enc_pkt in audio_encoder.encode(rs_frame):
                            muxer.add_audio_sample(bytes(enc_pkt), aac_frame_size)
                            audio_frame_count += 1
            except Exception:
                pass
            try:
                for enc_pkt in audio_encoder.encode(None):
                    if _max_audio_frames is not None and audio_frame_count >= _max_audio_frames:
                        break
                    muxer.add_audio_sample(bytes(enc_pkt), aac_frame_size)
                    audio_frame_count += 1
            except Exception:
                pass
            _audio_flushed = True

        # Final fragment
        final = muxer.flush_final()
        if final:
            fragment_count += 1
            bytes_out += len(final)
            yield final

    except (GeneratorExit, asyncio.CancelledError):
        cancelled = True
        logger.info("[universal] Client disconnected, stopping pipeline")
    except Exception as exc:
        if bytes_out == 0 and "prematurely" in str(exc):
            cancelled = True
            logger.info("[universal] Client disconnected before streaming started")
        else:
            logger.exception("[universal] Pipeline error")
    finally:
        if video_transcoder:
            video_transcoder.close()
            video_transcoder = None
        # Flush audio only if the normal path didn't already do it.
        # Double-flushing a PyAV codec context causes SIGSEGV.
        if audio_encoder and not _audio_flushed:
            try:
                for _ in audio_encoder.encode(None):
                    pass
            except Exception:
                pass
        audio_encoder = None
        audio_resampler = None
        if hasattr(source, "aclose"):
            try:
                await source.aclose()
            except Exception:
                pass
        logger.debug("[universal] Cleanup: complete")

    if cancelled:
        logger.info(
            "[universal] Cancelled after %d video, %d audio frames, %d fragments, %d bytes out",
            video_frame_count,
            audio_frame_count,
            fragment_count,
            bytes_out,
        )
    else:
        logger.info(
            "[universal] Complete: %d video, %d audio frames, %d fragments, %d bytes out",
            video_frame_count,
            audio_frame_count,
            fragment_count,
            bytes_out,
        )
