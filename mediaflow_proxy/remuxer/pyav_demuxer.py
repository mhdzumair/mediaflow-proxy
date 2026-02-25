"""
Universal PyAV-based streaming demuxer.

Bridges async byte streams to PyAV's synchronous I/O using an OS pipe,
allowing on-the-fly demuxing of any container format (MKV, MP4, TS,
FLV, WebM, etc.) from an async source.

Architecture:
  AsyncIterator[bytes]  -->  async feeder task --> queue.Queue --> writer thread (pipe)
                                                                        |
                                                                OS pipe (kernel buffer)
                                                                        |
                                    demux thread: av.open + discover + demux
                                                                        |
                                                queue.Queue --> run_in_executor consumer

Performance: Uses plain threading.Queue on both sides (writer input and
packet output) to avoid per-item ``run_coroutine_threadsafe`` overhead.
The async/thread bridge is done via ``run_in_executor`` on the consumer
side and a dedicated asyncio task on the producer side.

For MP4 inputs, the caller (transcode_handler) prepends the moov atom
to the stream so PyAV receives a "faststart"-style MP4 through the pipe.
This allows true on-the-fly demuxing for all container formats.
"""

import asyncio
import logging
import os
import queue
import threading
from collections.abc import AsyncIterator
from dataclasses import dataclass

import av

logger = logging.getLogger(__name__)

# Sentinel object to signal end-of-stream in queues
_SENTINEL = object()


@dataclass(slots=True)
class DemuxedStream:
    """Metadata about a demuxed stream."""

    index: int
    codec_name: str
    codec_type: str  # "video" or "audio"
    # Video-specific
    width: int = 0
    height: int = 0
    fps: float = 0.0
    pixel_format: str = ""
    # Audio-specific
    sample_rate: int = 0
    channels: int = 0
    # Timing
    time_base_num: int = 1
    time_base_den: int = 1000
    duration_seconds: float = 0.0
    # Raw codec extradata (e.g. SPS/PPS for H.264, AudioSpecificConfig for AAC)
    extradata: bytes = b""


@dataclass(slots=True)
class DemuxedPacket:
    """A demuxed packet with timing info."""

    stream_index: int
    codec_type: str  # "video" or "audio"
    data: bytes
    pts: int  # Presentation timestamp in stream time_base units
    dts: int  # Decode timestamp in stream time_base units
    duration: int  # Duration in stream time_base units
    is_keyframe: bool
    time_base_num: int
    time_base_den: int
    # Optional decoded frame when decode_video/decode_audio is True
    # av.VideoFrame for video, av.AudioFrame for audio
    decoded_frame: object = None

    @property
    def pts_seconds(self) -> float:
        if self.time_base_den == 0:
            return 0.0
        return self.pts * self.time_base_num / self.time_base_den

    @property
    def dts_seconds(self) -> float:
        if self.time_base_den == 0:
            return 0.0
        return self.dts * self.time_base_num / self.time_base_den

    @property
    def duration_seconds(self) -> float:
        if self.time_base_den == 0:
            return 0.0
        return self.duration * self.time_base_num / self.time_base_den


class PyAVDemuxer:
    """
    Streaming demuxer using PyAV with pipe-based I/O.

    All container I/O happens in background threads. The writer thread
    feeds source bytes into a pipe; a single demux thread opens the
    container, discovers streams, and demuxes packets -- all on the
    same file object, ensuring the pipe's read cursor is never lost.

    Performance optimisation: both the writer-input side and the
    packet-output side use plain ``queue.Queue`` (no event-loop
    involvement per item). The async/thread bridge is done via
    ``run_in_executor`` on the consumer and an asyncio task on the
    producer, eliminating ~1700 ``run_coroutine_threadsafe`` round-trips
    per 30 s of 4K content.

    Usage:
        demuxer = PyAVDemuxer()
        await demuxer.start(source_async_iter)
        # demuxer.video_stream / audio_stream are now available
        async for packet in demuxer.iter_packets():
            if packet.codec_type == "video":
                ...
    """

    def __init__(self, decode_video: bool = False, decode_audio: bool = False) -> None:
        """
        Args:
            decode_video: If True, the demux thread will decode video packets
                using the container's codec context and attach decoded frames
                to DemuxedPacket.decoded_frame. This avoids format conversion
                issues with standalone decoders (HVCC vs Annex B).
            decode_audio: If True, the demux thread will decode audio packets
                using the container's codec context and attach decoded frames
                to DemuxedPacket.decoded_frame. This is needed for codecs like
                Vorbis/Opus where the standalone decoder requires codec headers
                that are only available in the container context. Can also be
                set after start() returns (before packets are consumed) via
                the ``enable_audio_decode()`` method.
        """
        self._decode_video = decode_video
        self._decode_audio = decode_audio
        self._video_decode_decided = threading.Event()
        self._audio_decode_decided = threading.Event()
        # If decode flags were set at construction time, mark decided immediately
        if decode_video:
            self._video_decode_decided.set()
        if decode_audio:
            self._audio_decode_decided.set()
        self._container: av.InputContainer | None = None
        self._video_stream: DemuxedStream | None = None
        self._audio_stream: DemuxedStream | None = None
        # Thread-safe queues (no event-loop involvement per put/get)
        self._packet_queue: queue.Queue | None = None
        self._source_queue: queue.Queue | None = None
        self._demux_thread: threading.Thread | None = None
        self._writer_thread: threading.Thread | None = None
        self._feeder_task: asyncio.Task | None = None
        self._write_fd: int | None = None
        self._read_fd: int | None = None

    @property
    def video_stream(self) -> DemuxedStream | None:
        return self._video_stream

    @property
    def audio_stream(self) -> DemuxedStream | None:
        return self._audio_stream

    def enable_video_decode(self, enable: bool = True) -> None:
        """
        Enable or disable in-thread video decoding.

        Call this after ``start()`` returns (stream metadata is available)
        but before consuming packets via ``iter_packets()``. The demux
        thread waits for this signal before processing video packets.
        """
        self._decode_video = enable
        self._video_decode_decided.set()

    def enable_audio_decode(self, enable: bool = True) -> None:
        """
        Enable or disable in-thread audio decoding.

        Call this after ``start()`` returns (stream metadata is available)
        but before consuming packets via ``iter_packets()``. The demux
        thread waits for this signal before processing audio packets.
        """
        self._decode_audio = enable
        self._audio_decode_decided.set()

    # ── Writer side ──────────────────────────────────────────────────

    async def _async_feeder(self, source: AsyncIterator[bytes]) -> None:
        """
        Async task: pull chunks from the async source and push them
        into a plain ``queue.Queue`` for the writer thread.

        This replaces the old per-chunk ``run_coroutine_threadsafe``
        pattern, batching the async-to-sync bridge into one task.

        ``queue.Queue.put()`` is a blocking call, so we use
        ``run_in_executor`` to avoid blocking the event loop when the
        queue is full.
        """
        loop = asyncio.get_running_loop()
        sq = self._source_queue
        try:
            async for chunk in source:
                await loop.run_in_executor(None, sq.put, chunk)
        except (asyncio.CancelledError, GeneratorExit):
            pass
        except Exception:
            pass
        finally:
            sq.put(_SENTINEL)

    def _write_chunks_sync(self) -> None:
        """
        Writer thread: pull pre-buffered chunks from ``_source_queue``
        and write to the OS pipe. No event-loop interaction.
        """
        write_fd = self._write_fd
        sq = self._source_queue
        try:
            while True:
                chunk = sq.get(timeout=30.0)
                if chunk is _SENTINEL:
                    break
                os.write(write_fd, chunk)
        except Exception:
            pass
        finally:
            try:
                os.close(write_fd)
            except OSError:
                pass
            self._write_fd = None

    # ── Demux side ───────────────────────────────────────────────────

    async def start(self, source: AsyncIterator[bytes]) -> None:
        """
        Start pipe-based streaming: writer thread feeds the pipe, a single
        demux thread opens the container, discovers streams, and begins
        enqueuing packets.

        After this returns, ``video_stream`` and ``audio_stream`` are
        populated and packets are being enqueued for ``iter_packets()``.
        """
        loop = asyncio.get_running_loop()

        # Create OS pipe
        self._read_fd, self._write_fd = os.pipe()

        # Source buffer queue (async feeder task -> writer thread)
        self._source_queue = queue.Queue(maxsize=256)

        # Kick off the async feeder task
        self._feeder_task = asyncio.create_task(self._async_feeder(source))

        # Start writer thread (drains source_queue into the pipe)
        self._writer_thread = threading.Thread(
            target=self._write_chunks_sync,
            daemon=True,
            name="pyav-writer",
        )
        self._writer_thread.start()

        # Packet queue for demux-thread -> async consumer bridge
        self._packet_queue = queue.Queue(maxsize=128)
        streams_ready = threading.Event()

        def _open_and_demux():
            """
            Single background thread: open container, discover streams,
            demux all packets.

            Critical: av.open(), _discover_streams(), and container.demux()
            all happen on the same file object in the same thread. This
            ensures the pipe read cursor is never lost between open and demux.
            """
            pkt_count = 0
            pq = self._packet_queue
            try:
                # Open container from read end of pipe
                read_file = os.fdopen(self._read_fd, "rb")
                self._read_fd = None  # ownership transferred

                self._container = av.open(
                    read_file,
                    mode="r",
                    options={
                        # Tolerate mid-stream joins / broken data in live TS
                        "err_detect": "ignore_err",
                        "fflags": "+discardcorrupt+genpts",
                    },
                )
                self._discover_streams()

                # Signal stream metadata is available
                streams_ready.set()

                if self._video_stream is None and self._audio_stream is None:
                    logger.warning("[pyav_demuxer] No video or audio streams found")
                    return

                # Select streams to demux
                streams_to_demux = []
                if self._video_stream is not None:
                    streams_to_demux.append(self._container.streams[self._video_stream.index])
                if self._audio_stream is not None:
                    streams_to_demux.append(self._container.streams[self._audio_stream.index])

                # Wait for the caller to decide on video/audio decoding
                # (if not already decided at construction time).
                if not self._video_decode_decided.is_set():
                    self._video_decode_decided.wait(timeout=10.0)
                if not self._audio_decode_decided.is_set():
                    self._audio_decode_decided.wait(timeout=10.0)

                # Cache stream objects and time_base for the hot loop
                video_stream_obj = (
                    self._container.streams[self._video_stream.index] if self._video_stream is not None else None
                )
                audio_stream_obj = (
                    self._container.streams[self._audio_stream.index] if self._audio_stream is not None else None
                )

                video_tb_num = video_stream_obj.time_base.numerator if video_stream_obj else 1
                video_tb_den = video_stream_obj.time_base.denominator if video_stream_obj else 1
                audio_tb_num = audio_stream_obj.time_base.numerator if audio_stream_obj else 1
                audio_tb_den = audio_stream_obj.time_base.denominator if audio_stream_obj else 1

                decode_video = self._decode_video
                decode_audio = self._decode_audio

                # Demux and enqueue packets -- plain queue.put(), no event loop
                for packet in self._container.demux(*streams_to_demux):
                    if packet.size == 0:
                        continue

                    stream = self._container.streams[packet.stream_index]
                    is_video = stream.type == "video"
                    is_audio = stream.type == "audio"

                    # Optionally decode video packets in-thread
                    if decode_video and is_video and video_stream_obj is not None:
                        try:
                            frames = video_stream_obj.codec_context.decode(packet)
                        except Exception:
                            frames = []
                        for frame in frames:
                            pq.put(
                                DemuxedPacket(
                                    stream_index=packet.stream_index,
                                    codec_type="video",
                                    data=b"",
                                    pts=int(frame.pts) if frame.pts is not None else 0,
                                    dts=int(frame.pts) if frame.pts is not None else 0,
                                    duration=int(packet.duration) if packet.duration is not None else 0,
                                    is_keyframe=frame.key_frame,
                                    time_base_num=video_tb_num,
                                    time_base_den=video_tb_den,
                                    decoded_frame=frame,
                                )
                            )
                            pkt_count += 1

                    # Optionally decode audio packets in-thread
                    elif decode_audio and is_audio and audio_stream_obj is not None:
                        try:
                            frames = audio_stream_obj.codec_context.decode(packet)
                        except Exception:
                            frames = []
                        for frame in frames:
                            pq.put(
                                DemuxedPacket(
                                    stream_index=packet.stream_index,
                                    codec_type="audio",
                                    data=b"",
                                    pts=int(frame.pts) if frame.pts is not None else 0,
                                    dts=int(frame.pts) if frame.pts is not None else 0,
                                    duration=int(packet.duration) if packet.duration is not None else 0,
                                    is_keyframe=False,
                                    time_base_num=audio_tb_num,
                                    time_base_den=audio_tb_den,
                                    decoded_frame=frame,
                                )
                            )
                            pkt_count += 1

                    else:
                        tb_num = video_tb_num if is_video else audio_tb_num
                        tb_den = video_tb_den if is_video else audio_tb_den
                        pq.put(
                            DemuxedPacket(
                                stream_index=packet.stream_index,
                                codec_type=stream.type,
                                data=bytes(packet),
                                pts=int(packet.pts) if packet.pts is not None else 0,
                                dts=int(packet.dts) if packet.dts is not None else 0,
                                duration=int(packet.duration) if packet.duration is not None else 0,
                                is_keyframe=packet.is_keyframe,
                                time_base_num=tb_num,
                                time_base_den=tb_den,
                            )
                        )
                        pkt_count += 1

                # Flush the video decoder if we were decoding
                if decode_video and video_stream_obj is not None:
                    try:
                        for frame in video_stream_obj.codec_context.decode(None):
                            pq.put(
                                DemuxedPacket(
                                    stream_index=video_stream_obj.index,
                                    codec_type="video",
                                    data=b"",
                                    pts=int(frame.pts) if frame.pts is not None else 0,
                                    dts=int(frame.pts) if frame.pts is not None else 0,
                                    duration=0,
                                    is_keyframe=frame.key_frame,
                                    time_base_num=video_tb_num,
                                    time_base_den=video_tb_den,
                                    decoded_frame=frame,
                                )
                            )
                            pkt_count += 1
                    except Exception:
                        pass

                # Flush the audio decoder if we were decoding
                if decode_audio and audio_stream_obj is not None:
                    try:
                        for frame in audio_stream_obj.codec_context.decode(None):
                            pq.put(
                                DemuxedPacket(
                                    stream_index=audio_stream_obj.index,
                                    codec_type="audio",
                                    data=b"",
                                    pts=int(frame.pts) if frame.pts is not None else 0,
                                    dts=int(frame.pts) if frame.pts is not None else 0,
                                    duration=0,
                                    is_keyframe=False,
                                    time_base_num=audio_tb_num,
                                    time_base_den=audio_tb_den,
                                    decoded_frame=frame,
                                )
                            )
                            pkt_count += 1
                    except Exception:
                        pass

                logger.info("[pyav_demuxer] Demux complete: %d packets", pkt_count)

            except Exception as e:
                if "Invalid data" not in str(e):
                    logger.debug("[pyav_demuxer] Demux thread error: %s", e)
                # Ensure streams_ready is set even on error
                streams_ready.set()
            finally:
                pq.put(_SENTINEL)

        self._demux_thread = threading.Thread(target=_open_and_demux, daemon=True, name="pyav-demux")
        self._demux_thread.start()

        # Wait for stream discovery before returning.
        # Use run_in_executor to avoid blocking the event loop.
        await loop.run_in_executor(None, streams_ready.wait)

    async def iter_packets(self) -> AsyncIterator[DemuxedPacket]:
        """
        Yield demuxed packets from the background thread.

        Uses ``run_in_executor`` for the blocking ``queue.get()`` call,
        avoiding per-packet ``run_coroutine_threadsafe`` overhead.

        ``start()`` must be called first.
        """
        if self._packet_queue is None:
            raise RuntimeError("Call start() before iter_packets()")

        loop = asyncio.get_running_loop()
        pq = self._packet_queue

        try:
            while True:
                packet = await loop.run_in_executor(None, pq.get)
                if packet is _SENTINEL:
                    break
                yield packet

            if self._demux_thread is not None:
                self._demux_thread.join(timeout=5.0)

        except GeneratorExit:
            logger.debug("[pyav_demuxer] Generator closed")
        except asyncio.CancelledError:
            logger.debug("[pyav_demuxer] Cancelled")
        finally:
            self._cleanup()

    def _discover_streams(self) -> None:
        """Inspect the opened container and record stream metadata."""
        if self._container is None:
            return

        for stream in self._container.streams:
            if stream.type == "video" and self._video_stream is None:
                codec_ctx = stream.codec_context
                fps = float(stream.average_rate) if stream.average_rate else 24.0
                self._video_stream = DemuxedStream(
                    index=stream.index,
                    codec_name=codec_ctx.name if codec_ctx else stream.codec.name,
                    codec_type="video",
                    width=codec_ctx.width if codec_ctx else 0,
                    height=codec_ctx.height if codec_ctx else 0,
                    fps=fps,
                    pixel_format=str(codec_ctx.pix_fmt) if codec_ctx and codec_ctx.pix_fmt else "yuv420p",
                    time_base_num=stream.time_base.numerator,
                    time_base_den=stream.time_base.denominator,
                    duration_seconds=float(stream.duration * stream.time_base) if stream.duration else 0.0,
                    extradata=bytes(codec_ctx.extradata) if codec_ctx and codec_ctx.extradata else b"",
                )
                logger.info(
                    "[pyav_demuxer] Video: %s %dx%d @%.1ffps",
                    self._video_stream.codec_name,
                    self._video_stream.width,
                    self._video_stream.height,
                    self._video_stream.fps,
                )

            elif stream.type == "audio" and self._audio_stream is None:
                codec_ctx = stream.codec_context
                self._audio_stream = DemuxedStream(
                    index=stream.index,
                    codec_name=codec_ctx.name if codec_ctx else stream.codec.name,
                    codec_type="audio",
                    sample_rate=codec_ctx.sample_rate if codec_ctx else 0,
                    channels=codec_ctx.channels if codec_ctx else 0,
                    time_base_num=stream.time_base.numerator,
                    time_base_den=stream.time_base.denominator,
                    duration_seconds=float(stream.duration * stream.time_base) if stream.duration else 0.0,
                    extradata=bytes(codec_ctx.extradata) if codec_ctx and codec_ctx.extradata else b"",
                )
                logger.info(
                    "[pyav_demuxer] Audio: %s %dHz %dch",
                    self._audio_stream.codec_name,
                    self._audio_stream.sample_rate,
                    self._audio_stream.channels,
                )

    def _cleanup(self) -> None:
        """Stop threads and release all resources safely.

        The order is critical to avoid SIGSEGV from closing the container
        while the demux thread is still calling container.demux():

        1. Cancel the feeder task (stops new bytes being queued).
        2. Put a sentinel into the source queue so the writer thread
           unblocks and exits. The writer's ``finally`` closes the pipe
           write-end, which causes the demux thread to see EOF.
        3. Join the writer thread (wait for it to drain and exit).
        4. Join the demux thread (it finishes after pipe EOF).
        5. ONLY THEN close the container (no thread is using it).
        6. Close any remaining pipe FDs (read end, if still open).
        """
        # 1. Cancel feeder task
        if self._feeder_task is not None:
            self._feeder_task.cancel()
            self._feeder_task = None

        # 2. Unblock writer thread so it exits and closes the pipe
        if self._source_queue is not None:
            try:
                self._source_queue.put_nowait(_SENTINEL)
            except Exception:
                pass

        # 3. Join writer thread (it closes _write_fd in its finally block)
        if self._writer_thread is not None:
            self._writer_thread.join(timeout=5.0)
            self._writer_thread = None

        # 4. Join demux thread -- must finish before we close the container
        if self._demux_thread is not None:
            self._demux_thread.join(timeout=5.0)
            self._demux_thread = None

        # 5. Now safe to close the container (no thread is using it)
        if self._container is not None:
            try:
                self._container.close()
            except Exception:
                pass
            self._container = None

        # 6. Close any remaining pipe FDs
        for fd_name in ("_read_fd", "_write_fd"):
            fd = getattr(self, fd_name, None)
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
                setattr(self, fd_name, None)
