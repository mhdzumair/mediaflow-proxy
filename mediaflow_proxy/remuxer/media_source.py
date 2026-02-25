"""
Abstract media source protocol for source-agnostic transcode pipeline.

Decouples the transcode pipeline, MKV cue probing, and seeking logic
from any specific transport (Telegram, HTTP, etc.). Each transport
implements the MediaSource protocol to provide byte-range streaming.
"""

import hashlib
import logging
from collections.abc import AsyncIterator
from typing import Protocol, runtime_checkable
from urllib.parse import urlparse, unquote

from mediaflow_proxy.utils.http_client import create_aiohttp_session

logger = logging.getLogger(__name__)

# Extensions mapped to container format hints used by transcode_handler
_MKV_EXTENSIONS = frozenset({".mkv", ".webm"})
_MP4_EXTENSIONS = frozenset({".mp4", ".m4v", ".mov", ".m4a", ".3gp"})


def _extract_extension(path: str) -> str:
    """Extract lowercase file extension (e.g. '.mkv') from a path or URL."""
    # Strip query/fragment first for URL paths
    dot_pos = path.rfind(".")
    if dot_pos < 0:
        return ""
    ext = path[dot_pos:].lower()
    # Trim anything after the extension (query params from raw paths)
    for ch in ("?", "#", "&"):
        idx = ext.find(ch)
        if idx > 0:
            ext = ext[:idx]
    return ext


def filename_hint_from_url(url: str) -> str:
    """Derive a filename hint from a URL path (e.g. '.mkv', '.mp4')."""
    try:
        parsed = urlparse(url)
        return _extract_extension(unquote(parsed.path))
    except Exception:
        return ""


def filename_hint_from_name(filename: str) -> str:
    """Derive a filename hint from a filename string."""
    return _extract_extension(filename) if filename else ""


@runtime_checkable
class MediaSource(Protocol):
    """
    Protocol for streaming media byte ranges.

    Implementations must provide:
    - stream(): async iterator of bytes from offset/limit
    - file_size: total file size in bytes
    - cache_key: deterministic key for caching (cue index, etc.)
    - filename_hint: optional file extension hint (e.g. '.mkv', '.mp4')
    """

    @property
    def file_size(self) -> int:
        """Total file size in bytes."""
        ...

    @property
    def cache_key(self) -> str:
        """Deterministic cache key derived from the source identity."""
        ...

    @property
    def filename_hint(self) -> str:
        """Optional file extension hint (e.g. '.mkv', '.mp4') for format detection."""
        ...

    async def stream(self, offset: int = 0, limit: int | None = None) -> AsyncIterator[bytes]:
        """
        Stream bytes from the source.

        Args:
            offset: Byte offset to start from.
            limit: Number of bytes to read. None = read to end.

        Yields:
            Chunks of bytes.
        """
        ...


class TelegramMediaSource:
    """
    MediaSource backed by Telegram MTProto downloads.

    Supports two download modes:

    * **parallel** (default): Uses ``ParallelTransferrer`` with multiple
      MTProtoSender connections for maximum throughput.  Best for full-file
      streaming (e.g. ``/proxy/telegram/stream``).

    * **single** (``use_single_client=True``): Uses Telethon's built-in
      ``iter_download`` over the existing client connection.  Avoids the
      overhead of creating/destroying extra connections for each request,
      ideal for small byte-range fetches like HLS segments and probe
      headers.
    """

    def __init__(
        self,
        telegram_ref,
        file_size: int,
        file_name: str = "",
        *,
        use_single_client: bool = False,
    ) -> None:
        self._ref = telegram_ref
        self._file_size = file_size
        self._filename_hint = filename_hint_from_name(file_name)
        self._use_single_client = use_single_client

    @property
    def file_size(self) -> int:
        return self._file_size

    @property
    def cache_key(self) -> str:
        ref = self._ref
        if ref.file_id:
            raw = f"file_id:{ref.file_id}"
        elif ref.chat_id is not None and ref.message_id is not None:
            raw = f"chat:{ref.chat_id}:msg:{ref.message_id}"
        else:
            return ""
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    @property
    def filename_hint(self) -> str:
        return self._filename_hint

    async def stream(self, offset: int = 0, limit: int | None = None) -> AsyncIterator[bytes]:
        # Lazy import to avoid loading Telegram dependencies for non-Telegram routes.
        from mediaflow_proxy.utils.telegram import telegram_manager

        effective_limit = limit or self._file_size
        if self._use_single_client:
            async for chunk in telegram_manager.stream_media_single(
                self._ref,
                offset=offset,
                limit=effective_limit,
                file_size=self._file_size,
            ):
                yield chunk
        else:
            async for chunk in telegram_manager.stream_media(
                self._ref,
                offset=offset,
                limit=effective_limit,
                file_size=self._file_size,
            ):
                yield chunk


class HTTPMediaSource:
    """MediaSource backed by HTTP byte-range requests via aiohttp."""

    def __init__(self, url: str, headers: dict | None = None, file_size: int = 0) -> None:
        self._url = url
        self._headers = headers or {}
        self._file_size = file_size
        self._filename_hint = filename_hint_from_url(url)

    @property
    def file_size(self) -> int:
        return self._file_size

    @property
    def cache_key(self) -> str:
        return hashlib.sha256(self._url.encode()).hexdigest()[:16]

    @property
    def filename_hint(self) -> str:
        return self._filename_hint

    async def resolve_file_size(self) -> int:
        """Perform a HEAD request to determine file size if not already known."""
        if self._file_size > 0:
            return self._file_size

        async with create_aiohttp_session(self._url, headers=self._headers) as (session, proxy_url):
            async with session.head(
                self._url,
                headers=self._headers,
                proxy=proxy_url,
                allow_redirects=True,
            ) as resp:
                cl = resp.headers.get("content-length")
                if cl:
                    self._file_size = int(cl)
                else:
                    # Try GET with range to get content-range
                    async with session.get(
                        self._url,
                        headers={**self._headers, "range": "bytes=0-0"},
                        proxy=proxy_url,
                        allow_redirects=True,
                    ) as range_resp:
                        cr = range_resp.headers.get("content-range", "")
                        if "/" in cr:
                            try:
                                self._file_size = int(cr.split("/")[-1])
                            except ValueError:
                                pass
        return self._file_size

    async def stream(self, offset: int = 0, limit: int | None = None) -> AsyncIterator[bytes]:
        headers = dict(self._headers)

        if offset > 0 or limit is not None:
            end = ""
            if limit is not None:
                end = str(offset + limit - 1)
            headers["range"] = f"bytes={offset}-{end}"

        async with create_aiohttp_session(self._url, headers=headers) as (session, proxy_url):
            async with session.get(
                self._url,
                headers=headers,
                proxy=proxy_url,
                allow_redirects=True,
            ) as resp:
                resp.raise_for_status()
                async for chunk in resp.content.iter_any():
                    yield chunk
