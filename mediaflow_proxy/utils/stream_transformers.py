"""
Stream transformers for host-specific content manipulation.

This module provides transformer classes that can modify streaming content
on-the-fly. Each transformer handles specific content manipulation needs
for different streaming hosts (e.g., PNG wrapper stripping, TS detection).
"""

import logging
import typing

logger = logging.getLogger(__name__)


class StreamTransformer:
    """
    Base class for stream content transformers.

    Subclasses should override the transform method to implement
    specific content manipulation logic.
    """

    async def transform(self, chunk_iterator: typing.AsyncIterator[bytes]) -> typing.AsyncGenerator[bytes, None]:
        """
        Transform stream chunks.

        Args:
            chunk_iterator: Async iterator of raw bytes from upstream.

        Yields:
            Transformed bytes chunks.
        """
        async for chunk in chunk_iterator:
            yield chunk


class TSStreamTransformer(StreamTransformer):
    """
    Transformer for MPEG-TS streams with obfuscation.

    Handles streams from hosts like TurboVidPlay, StreamWish, and FileMoon
    that may have:
    - Fake PNG wrapper prepended to video data
    - 0xFF padding bytes before actual content
    - Need for TS sync byte detection
    """

    # PNG signature and IEND marker for fake PNG header detection
    _PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
    _PNG_IEND_MARKER = b"\x49\x45\x4e\x44\xae\x42\x60\x82"

    # TS packet constants
    _TS_SYNC = 0x47
    _TS_PACKET_SIZE = 188

    # Maximum bytes to buffer before forcing passthrough
    _MAX_PREFETCH = 512 * 1024  # 512 KB

    def __init__(self):
        self.buffer = bytearray()
        self.ts_started = False
        self.bytes_stripped = 0

    @staticmethod
    def _find_ts_start(buffer: bytes) -> typing.Optional[int]:
        """
        Find MPEG-TS sync byte (0x47) aligned on 188 bytes.

        Args:
            buffer: Bytes to search for TS sync pattern.

        Returns:
            Offset where TS starts, or None if not found.
        """
        TS_SYNC = 0x47
        TS_PACKET = 188

        max_i = len(buffer) - TS_PACKET
        for i in range(max(0, max_i)):
            if buffer[i] == TS_SYNC and buffer[i + TS_PACKET] == TS_SYNC:
                return i
        return None

    def _strip_fake_png_wrapper(self, chunk: bytes) -> bytes:
        """
        Strip fake PNG wrapper from chunk data.

        Some streaming services prepend a fake PNG image to video data
        to evade detection. This method detects and removes it.

        Args:
            chunk: The raw chunk data that may contain a fake PNG header.

        Returns:
            The chunk with fake PNG wrapper removed, or original chunk if not present.
        """
        if not chunk.startswith(self._PNG_SIGNATURE):
            return chunk

        # Find the IEND marker that signals end of PNG data
        iend_pos = chunk.find(self._PNG_IEND_MARKER)
        if iend_pos == -1:
            # IEND not found in this chunk - return as-is to avoid data corruption
            logger.debug("PNG signature detected but IEND marker not found in chunk")
            return chunk

        # Calculate position after IEND marker
        content_start = iend_pos + len(self._PNG_IEND_MARKER)

        # Skip any padding bytes (null or 0xFF) between PNG and actual content
        while content_start < len(chunk) and chunk[content_start] in (0x00, 0xFF):
            content_start += 1

        self.bytes_stripped = content_start
        logger.debug(f"Stripped {content_start} bytes of fake PNG wrapper from stream")

        return chunk[content_start:]

    async def transform(self, chunk_iterator: typing.AsyncIterator[bytes]) -> typing.AsyncGenerator[bytes, None]:
        """
        Transform TS stream by stripping PNG wrapper and finding TS start.

        Args:
            chunk_iterator: Async iterator of raw bytes from upstream.

        Yields:
            Cleaned TS stream bytes.
        """
        async for chunk in chunk_iterator:
            if self.ts_started:
                # Normal streaming once TS has started
                yield chunk
                continue

            # Prebuffer phase (until we find TS or pass through)
            self.buffer += chunk

            # Fast-path: if it's an m3u8 playlist, don't do TS detection
            if len(self.buffer) >= 7 and self.buffer[:7] in (b"#EXTM3U", b"#EXT-X-"):
                yield bytes(self.buffer)
                self.buffer.clear()
                self.ts_started = True
                continue

            # Strip fake PNG wrapper if present
            if self.buffer.startswith(self._PNG_SIGNATURE):
                if self._PNG_IEND_MARKER in self.buffer:
                    self.buffer = bytearray(self._strip_fake_png_wrapper(bytes(self.buffer)))

            # Skip pure 0xFF padding bytes (TurboVid style)
            while self.buffer and self.buffer[0] == 0xFF:
                self.buffer.pop(0)

            # Re-check for m3u8 playlist after stripping PNG wrapper and padding
            # This handles cases where m3u8 content is wrapped in PNG
            if len(self.buffer) >= 7 and self.buffer[:7] in (b"#EXTM3U", b"#EXT-X-"):
                logger.debug("Found m3u8 content after stripping wrapper - passing through")
                yield bytes(self.buffer)
                self.buffer.clear()
                self.ts_started = True
                continue

            ts_offset = self._find_ts_start(bytes(self.buffer))
            if ts_offset is None:
                # Keep buffering until we find TS or hit limit
                if len(self.buffer) > self._MAX_PREFETCH:
                    logger.warning("TS sync not found after large prebuffer, forcing passthrough")
                    yield bytes(self.buffer)
                    self.buffer.clear()
                    self.ts_started = True
                continue

            # TS found: emit from ts_offset and switch to pass-through
            self.ts_started = True
            out = bytes(self.buffer[ts_offset:])
            self.buffer.clear()

            if out:
                yield out


# Registry of available transformers
TRANSFORMER_REGISTRY: dict[str, type[StreamTransformer]] = {
    "ts_stream": TSStreamTransformer,
}


def get_transformer(transformer_id: typing.Optional[str]) -> typing.Optional[StreamTransformer]:
    """
    Get a transformer instance by ID.

    Args:
        transformer_id: The transformer identifier (e.g., "ts_stream").

    Returns:
        A new transformer instance, or None if transformer_id is None or not found.
    """
    if transformer_id is None:
        return None

    transformer_class = TRANSFORMER_REGISTRY.get(transformer_id)
    if transformer_class is None:
        logger.warning(f"Unknown transformer ID: {transformer_id}")
        return None

    return transformer_class()


async def apply_transformer_to_bytes(
    data: bytes,
    transformer_id: typing.Optional[str],
) -> bytes:
    """
    Apply a transformer to already-downloaded bytes data.

    This is useful when serving cached segments that need transformation.
    Creates a single-chunk async iterator and collects the transformed output.

    Args:
        data: The raw bytes data to transform.
        transformer_id: The transformer identifier (e.g., "ts_stream").

    Returns:
        Transformed bytes, or original data if no transformer specified.
    """
    if not transformer_id:
        return data

    transformer = get_transformer(transformer_id)
    if not transformer:
        return data

    async def single_chunk_iterator():
        yield data

    # Collect all transformed chunks
    result = bytearray()
    async for chunk in transformer.transform(single_chunk_iterator()):
        result.extend(chunk)

    return bytes(result)
