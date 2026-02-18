"""
Streaming MKV demuxer.

Reads an MKV byte stream via an async iterator and yields individual media
frames (MKVFrame) with absolute timestamps. Designed for on-the-fly remuxing
without buffering the entire file.

Architecture:
  AsyncIterator[bytes] -> StreamBuffer -> EBML parsing -> MKVFrame yields

The demuxer works in two phases:
  1. read_header(): Consume bytes until Tracks is fully parsed, returning
     a list of MKVTrack with codec metadata.
  2. iter_frames(): Yield MKVFrame objects from Cluster/SimpleBlock data
     as clusters arrive.
"""

import logging
from collections.abc import AsyncIterator
from dataclasses import dataclass, field

from mediaflow_proxy.remuxer.ebml_parser import (
    CLUSTER,
    CLUSTER_TIMESTAMP,
    EBML_HEADER,
    INFO,
    MKVFrame,
    MKVTrack,
    SEGMENT,
    SIMPLE_BLOCK,
    BLOCK_GROUP,
    TRACKS,
    TIMESTAMP_SCALE,
    DURATION,
    UNKNOWN_SIZE,
    extract_block_frames,
    parse_tracks,
    read_element_id,
    read_element_size,
    read_float,
    read_uint,
    _parse_block_group,
    iter_elements,
)

logger = logging.getLogger(__name__)


class StreamBuffer:
    """
    Accumulating byte buffer for streaming EBML parsing.

    Collects chunks from an async byte source and provides read-ahead
    capabilities for EBML element parsing. Supports consuming parsed
    bytes to keep memory usage bounded.
    """

    def __init__(self) -> None:
        self._chunks: list[bytes] = []
        self._total: int = 0
        self._consumed: int = 0  # Logical bytes consumed (for offset tracking)

    @property
    def available(self) -> int:
        """Number of buffered bytes available for reading."""
        return self._total

    @property
    def consumed(self) -> int:
        """Total bytes consumed so far (for absolute offset tracking)."""
        return self._consumed

    def append(self, data: bytes) -> None:
        """Add bytes to the buffer."""
        if data:
            self._chunks.append(data)
            self._total += len(data)

    def peek(self, size: int) -> bytes:
        """Read up to size bytes without consuming."""
        if size <= 0:
            return b""
        result = bytearray()
        remaining = size
        for chunk in self._chunks:
            if remaining <= 0:
                break
            take = min(len(chunk), remaining)
            result.extend(chunk[:take])
            remaining -= take
        return bytes(result)

    def get_all(self) -> bytes:
        """Get all buffered data as a single bytes object (without consuming)."""
        if len(self._chunks) == 1:
            return self._chunks[0]
        data = b"".join(self._chunks)
        self._chunks = [data]
        return data

    def consume(self, size: int) -> bytes:
        """Remove and return size bytes from the front of the buffer."""
        if size <= 0:
            return b""
        if size > self._total:
            size = self._total

        result = bytearray()
        remaining = size
        while remaining > 0 and self._chunks:
            chunk = self._chunks[0]
            if len(chunk) <= remaining:
                result.extend(chunk)
                remaining -= len(chunk)
                self._chunks.pop(0)
            else:
                result.extend(chunk[:remaining])
                self._chunks[0] = chunk[remaining:]
                remaining = 0

        consumed = len(result)
        self._total -= consumed
        self._consumed += consumed
        return bytes(result)

    def skip(self, size: int) -> int:
        """Discard size bytes from the front. Returns actual bytes skipped."""
        if size <= 0:
            return 0
        actual = min(size, self._total)
        remaining = actual
        while remaining > 0 and self._chunks:
            chunk = self._chunks[0]
            if len(chunk) <= remaining:
                remaining -= len(chunk)
                self._chunks.pop(0)
            else:
                self._chunks[0] = chunk[remaining:]
                remaining = 0
        self._total -= actual
        self._consumed += actual
        return actual


@dataclass
class MKVHeader:
    """Parsed MKV header metadata."""

    tracks: list[MKVTrack] = field(default_factory=list)
    timestamp_scale_ns: int = 1_000_000  # Default 1ms
    duration_ms: float = 0.0
    segment_data_offset: int = 0  # Absolute byte offset of Segment children


class MKVDemuxer:
    """
    Streaming async MKV demuxer.

    Reads an MKV byte stream from an async iterator and provides:
    - read_header(): Parse EBML header + Segment metadata + Tracks
    - iter_frames(): Yield MKVFrame objects from Clusters

    Usage:
        demuxer = MKVDemuxer()
        header = await demuxer.read_header(source)
        async for frame in demuxer.iter_frames(source):
            process(frame)
    """

    # Minimum bytes to try parsing an element header (ID + size)
    _MIN_ELEMENT_HEADER = 12

    def __init__(self) -> None:
        self._buf = StreamBuffer()
        self._header: MKVHeader | None = None
        self._scale_ms: float = 1.0  # timestamp_scale / 1_000_000

    @property
    def header(self) -> MKVHeader | None:
        return self._header

    async def read_header(self, source: AsyncIterator[bytes]) -> MKVHeader:
        """
        Read and parse the MKV header (EBML header, Segment, Info, Tracks).

        Consumes bytes from source until Tracks is fully parsed. Any leftover
        bytes (start of first Cluster) remain in the internal buffer for
        iter_frames().

        Returns:
            MKVHeader with track info and timing metadata.
        """
        header = MKVHeader()

        # Phase 1: Accumulate enough data for EBML header + Segment header
        await self._ensure_bytes(source, 64)

        data = self._buf.get_all()
        if len(data) < 4:
            raise ValueError(
                f"Source ended prematurely: got {len(data)} bytes, need at least an EBML header (source disconnected?)"
            )
        pos = 0

        # Parse EBML Header
        eid, pos = read_element_id(data, pos)
        if eid != EBML_HEADER:
            raise ValueError(f"Not an MKV file: expected EBML header, got 0x{eid:X}")
        size, pos = read_element_size(data, pos)
        if size == UNKNOWN_SIZE:
            raise ValueError("EBML header has unknown size")
        pos += size  # Skip EBML header content

        # Parse Segment element header
        eid, pos = read_element_id(data, pos)
        if eid != SEGMENT:
            raise ValueError(f"Expected Segment, got 0x{eid:X}")
        _seg_size, pos = read_element_size(data, pos)
        header.segment_data_offset = self._buf.consumed + pos

        # Phase 2: Parse Segment children until we have Tracks
        # We need to iterate top-level Segment children: SeekHead, Info, Tracks
        # Stop when we hit the first Cluster (media data).
        tracks_found = False

        while not tracks_found:
            # Ensure we have enough for element header
            await self._ensure_bytes(source, pos + self._MIN_ELEMENT_HEADER)
            data = self._buf.get_all()

            if pos >= len(data):
                break

            try:
                eid, pos2 = read_element_id(data, pos)
                size, pos3 = read_element_size(data, pos2)
            except (ValueError, IndexError):
                await self._ensure_bytes(source, pos + 32)
                data = self._buf.get_all()
                try:
                    eid, pos2 = read_element_id(data, pos)
                    size, pos3 = read_element_size(data, pos2)
                except (ValueError, IndexError):
                    break

            if eid == CLUSTER:
                # Reached media data; header parsing is done.
                # Don't consume the Cluster -- leave it for iter_frames.
                break

            if size == UNKNOWN_SIZE:
                # Can't handle unknown-size elements in header
                logger.warning("[mkv_demuxer] Unknown-size element 0x%X in header at pos %d", eid, pos)
                break

            # Ensure we have the full element
            elem_end = pos3 + size
            await self._ensure_bytes(source, elem_end)
            data = self._buf.get_all()

            if eid == INFO:
                self._parse_info_element(data, pos3, pos3 + size, header)
            elif eid == TRACKS:
                header.tracks = parse_tracks(data, pos3, pos3 + size)
                tracks_found = True
                logger.info(
                    "[mkv_demuxer] Parsed %d tracks: %s",
                    len(header.tracks),
                    ", ".join(f"#{t.track_number}={t.codec_id}" for t in header.tracks),
                )

            pos = elem_end

        # Consume everything up to the current position (Cluster boundary)
        self._buf.consume(pos)

        # Set timing scale
        self._scale_ms = header.timestamp_scale_ns / 1_000_000.0
        self._header = header
        return header

    async def iter_frames(self, source: AsyncIterator[bytes]) -> AsyncIterator[MKVFrame]:
        """
        Yield MKVFrame objects from Cluster/SimpleBlock data.

        Must be called after read_header(). Continues consuming bytes from
        source, parsing Clusters and yielding individual frames.
        """
        if self._header is None:
            raise RuntimeError("read_header() must be called before iter_frames()")

        while True:
            # Try to read the next element header
            if not await self._ensure_bytes_soft(source, self._MIN_ELEMENT_HEADER):
                break

            data = self._buf.get_all()
            pos = 0

            try:
                eid, pos2 = read_element_id(data, pos)
                size, pos3 = read_element_size(data, pos2)
            except (ValueError, IndexError):
                # Try to get more data
                if not await self._ensure_bytes_soft(source, len(data) + 4096):
                    break
                data = self._buf.get_all()
                try:
                    eid, pos2 = read_element_id(data, pos)
                    size, pos3 = read_element_size(data, pos2)
                except (ValueError, IndexError):
                    break

            if eid == CLUSTER:
                if size == UNKNOWN_SIZE:
                    # Unknown-size Cluster: parse children until we hit the next
                    # Cluster or run out of data
                    self._buf.consume(pos3)  # consume Cluster header
                    async for frame in self._parse_unknown_size_cluster(source):
                        yield frame
                else:
                    # Known-size Cluster: ensure we have all data
                    elem_end = pos3 + size
                    await self._ensure_bytes(source, elem_end)
                    data = self._buf.get_all()

                    for frame in self._parse_cluster_data(data, pos3, pos3 + size):
                        yield frame

                    self._buf.consume(elem_end)
            else:
                # Skip non-Cluster top-level elements
                if size == UNKNOWN_SIZE:
                    break
                elem_end = pos3 + size
                if elem_end > len(data):
                    # Need to skip bytes we don't have yet
                    self._buf.consume(len(data))
                    skip_remaining = elem_end - len(data)
                    await self._skip_bytes(source, skip_remaining)
                else:
                    self._buf.consume(elem_end)

    def _parse_info_element(self, data: bytes, start: int, end: int, header: MKVHeader) -> None:
        """Parse Info element children for timestamp scale and duration."""
        for eid, off, size, _ in iter_elements(data, start, end):
            if eid == TIMESTAMP_SCALE:
                header.timestamp_scale_ns = read_uint(data, off, size)
            elif eid == DURATION:
                scale = header.timestamp_scale_ns / 1_000_000.0
                header.duration_ms = read_float(data, off, size) * scale

    def _parse_cluster_data(self, data: bytes, start: int, end: int) -> list[MKVFrame]:
        """Parse a known-size Cluster and return its frames."""
        cluster_timecode = 0
        frames = []

        for eid, data_off, size, _ in iter_elements(data, start, end):
            if eid == CLUSTER_TIMESTAMP:
                cluster_timecode = read_uint(data, data_off, size)
            elif eid == SIMPLE_BLOCK:
                for track_num, rel_tc, flags, frame_list in extract_block_frames(data, data_off, size):
                    is_kf = bool(flags & 0x80)
                    abs_ts_ms = (cluster_timecode + rel_tc) * self._scale_ms
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
                _parse_block_group(data, data_off, data_off + size, cluster_timecode, self._scale_ms, frames)

        return frames

    async def _parse_unknown_size_cluster(self, source: AsyncIterator[bytes]) -> AsyncIterator[MKVFrame]:
        """Parse an unknown-size Cluster by reading children until next Cluster."""
        cluster_timecode = 0

        while True:
            if not await self._ensure_bytes_soft(source, self._MIN_ELEMENT_HEADER):
                break

            data = self._buf.get_all()
            pos = 0

            try:
                eid, pos2 = read_element_id(data, pos)
                size, pos3 = read_element_size(data, pos2)
            except (ValueError, IndexError):
                if not await self._ensure_bytes_soft(source, len(data) + 4096):
                    break
                data = self._buf.get_all()
                try:
                    eid, pos2 = read_element_id(data, pos)
                    size, pos3 = read_element_size(data, pos2)
                except (ValueError, IndexError):
                    break

            # A new Cluster or top-level element signals end of current Cluster
            if eid == CLUSTER or eid == SEGMENT:
                break

            if size == UNKNOWN_SIZE:
                break

            elem_end = pos3 + size
            await self._ensure_bytes(source, elem_end)
            data = self._buf.get_all()

            if eid == CLUSTER_TIMESTAMP:
                cluster_timecode = read_uint(data, pos3, size)
            elif eid == SIMPLE_BLOCK:
                for track_num, rel_tc, flags, frame_list in extract_block_frames(data, pos3, size):
                    is_kf = bool(flags & 0x80)
                    abs_ts_ms = (cluster_timecode + rel_tc) * self._scale_ms
                    for frame_data in frame_list:
                        yield MKVFrame(
                            track_number=track_num,
                            timestamp_ms=abs_ts_ms,
                            is_keyframe=is_kf,
                            data=frame_data,
                        )
            elif eid == BLOCK_GROUP:
                bg_frames = []
                _parse_block_group(data, pos3, pos3 + size, cluster_timecode, self._scale_ms, bg_frames)
                for frame in bg_frames:
                    yield frame

            self._buf.consume(elem_end)

    async def _ensure_bytes(self, source: AsyncIterator[bytes], needed: int) -> None:
        """Ensure the buffer has at least 'needed' bytes. Raises StopAsyncIteration if exhausted."""
        while self._buf.available < needed:
            try:
                chunk = await source.__anext__()
                self._buf.append(chunk)
            except StopAsyncIteration:
                return

    async def _ensure_bytes_soft(self, source: AsyncIterator[bytes], needed: int) -> bool:
        """Like _ensure_bytes but returns False instead of raising."""
        while self._buf.available < needed:
            try:
                chunk = await source.__anext__()
                if not chunk:
                    return self._buf.available > 0
                self._buf.append(chunk)
            except StopAsyncIteration:
                return self._buf.available > 0
        return True

    async def _skip_bytes(self, source: AsyncIterator[bytes], count: int) -> None:
        """Skip count bytes from the source without buffering."""
        remaining = count
        while remaining > 0:
            try:
                chunk = await source.__anext__()
                if len(chunk) <= remaining:
                    remaining -= len(chunk)
                else:
                    # Put the excess back
                    self._buf.append(chunk[remaining:])
                    remaining = 0
            except StopAsyncIteration:
                break
