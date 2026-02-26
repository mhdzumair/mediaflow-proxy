"""
Telegram MTProto proxy routes.

Provides endpoints for streaming Telegram media:
- /proxy/telegram/stream - Stream media from t.me links or file_id (&transcode=true for fMP4 audio transcode)
- /proxy/telegram/info - Get media metadata
- /proxy/telegram/status - Check session status
- /proxy/telegram/session/* - Session string generation
"""

import asyncio
import logging
import re
import secrets
from urllib.parse import quote
from functools import lru_cache
from typing import Annotated, Optional, TYPE_CHECKING

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel

from mediaflow_proxy.configs import settings
from mediaflow_proxy.remuxer.media_source import TelegramMediaSource
from mediaflow_proxy.utils.http_utils import (
    EnhancedStreamingResponse,
    ProxyRequestHeaders,
    apply_header_manipulation,
    get_proxy_headers,
)

logger = logging.getLogger(__name__)
telegram_router = APIRouter()

if TYPE_CHECKING:
    from mediaflow_proxy.utils.telegram import TelegramMediaRef


def _telegram_utils():
    from mediaflow_proxy.utils.telegram import TelegramMediaRef, parse_telegram_url, telegram_manager

    return TelegramMediaRef, parse_telegram_url, telegram_manager


@lru_cache(maxsize=1)
def _load_transcode_handlers():
    from mediaflow_proxy.remuxer.transcode_handler import (
        handle_transcode,
        handle_transcode_hls_init,
        handle_transcode_hls_playlist,
        handle_transcode_hls_segment,
    )

    return (
        handle_transcode,
        handle_transcode_hls_init,
        handle_transcode_hls_playlist,
        handle_transcode_hls_segment,
    )


def _content_disposition_inline(filename: str) -> str:
    """
    Build a Content-Disposition header value that is always latin-1 safe.

    Starlette/FastAPI requires header values to be latin-1 encodable. Telegram filenames
    may contain unicode (e.g. Cyrillic), so we use RFC 6266 `filename*` when needed.
    """
    # Sanitize newlines and carriage returns
    sanitized = (filename or "").strip().replace("\n", " ").replace("\r", " ")
    if not sanitized:
        return "inline"

    try:
        # Try if the filename is latin-1 encodable
        sanitized.encode("latin-1")
        # For the filename= parameter, we must escape backslashes and double quotes
        escaped = sanitized.replace('\\', '\\\\').replace('"', '\\"')
        return f'inline; filename="{escaped}"'
    except UnicodeEncodeError:
        # For filename*, use percent-encoding with the original (unescaped) sanitized name
        encoded = quote(sanitized, encoding="utf-8", safe="")
        return f"inline; filename*=UTF-8''{encoded}"


def get_content_type(mime_type: str, file_name: Optional[str] = None) -> str:
    """Determine content type from mime type or filename."""
    if mime_type:
        return mime_type

    if file_name:
        ext = file_name.rsplit(".", 1)[-1].lower() if "." in file_name else ""
        mime_map = {
            "mp4": "video/mp4",
            "mkv": "video/x-matroska",
            "avi": "video/x-msvideo",
            "webm": "video/webm",
            "mov": "video/quicktime",
            "mp3": "audio/mpeg",
            "m4a": "audio/mp4",
            "flac": "audio/flac",
            "ogg": "audio/ogg",
            "jpg": "image/jpeg",
            "jpeg": "image/jpeg",
            "png": "image/png",
            "gif": "image/gif",
            "webp": "image/webp",
        }
        return mime_map.get(ext, "application/octet-stream")

    return "application/octet-stream"


def parse_range_header(range_header: Optional[str], file_size: int) -> tuple[int, int]:
    """
    Parse HTTP Range header.

    Args:
        range_header: The Range header value (e.g., "bytes=0-999")
        file_size: Total file size

    Returns:
        Tuple of (start, end) byte positions
    """
    if not range_header:
        return 0, file_size - 1

    # Parse "bytes=start-end" format
    match = re.match(r"bytes=(\d*)-(\d*)", range_header)
    if not match:
        return 0, file_size - 1

    start_str, end_str = match.groups()

    if start_str and end_str:
        start = int(start_str)
        end = min(int(end_str), file_size - 1)
    elif start_str:
        start = int(start_str)
        end = file_size - 1
    elif end_str:
        # Suffix range: last N bytes
        suffix_length = int(end_str)
        start = max(0, file_size - suffix_length)
        end = file_size - 1
    else:
        start = 0
        end = file_size - 1

    # Validate start <= end (handle malformed ranges like "bytes=999-0")
    if start > end:
        return 0, file_size - 1

    return start, end


@telegram_router.head("/telegram/stream")
@telegram_router.get("/telegram/stream")
@telegram_router.head("/telegram/stream/{filename:path}")
@telegram_router.get("/telegram/stream/{filename:path}")
async def telegram_stream(
    request: Request,
    proxy_headers: Annotated[ProxyRequestHeaders, Depends(get_proxy_headers)],
    d: Optional[str] = Query(None, description="t.me link or Telegram URL"),
    url: Optional[str] = Query(None, description="Alias for 'd' parameter"),
    chat_id: Optional[str] = Query(None, description="Chat/Channel ID (use with message_id)"),
    message_id: Optional[int] = Query(None, description="Message ID (use with chat_id)"),
    file_id: Optional[str] = Query(None, description="Bot API file_id (requires file_size parameter)"),
    file_size: Optional[int] = Query(None, description="File size in bytes (required for file_id streaming)"),
    transcode: bool = Query(False, description="Transcode to browser-compatible fMP4 (EAC3/AC3->AAC)"),
    start: Optional[float] = Query(None, description="Seek start time in seconds (used with transcode=true)"),
    filename: Optional[str] = None,
):
    """
    Stream Telegram media with range request support and parallel downloads.

    Supports:
    - t.me links: https://t.me/channel/123, https://t.me/c/123456789/456
    - chat_id + message_id: Direct reference by IDs (e.g., chat_id=-100123456&message_id=789)
    - file_id + file_size: Direct streaming by Bot API file_id (requires file_size)

    When transcode=true, the media is remuxed to fragmented MP4 with
    browser-compatible codecs. Audio is transcoded to AAC. Video is passed
    through when the source codec is already browser-compatible (H.264);
    otherwise it is re-encoded to H.264.  Seeking is supported via standard
    HTTP Range requests (byte offsets are converted to time positions using
    an estimated fMP4 size). The 'start' query parameter can also be used
    for explicit time-based seeking.

    Args:
        request: The incoming HTTP request
        proxy_headers: Headers for proxy requests
        d: t.me link or Telegram URL
        url: Alias for 'd' parameter
        chat_id: Chat/Channel ID (numeric or username)
        message_id: Message ID within the chat
        file_id: Bot API file_id (requires file_size parameter)
        file_size: File size in bytes (required for file_id streaming)
        transcode: Transcode to browser-compatible format (EAC3/AC3->AAC)
        filename: Optional filename for Content-Disposition

    Returns:
        Streaming response with media content, or redirect to HLS manifest when transcoding
    """
    if not settings.enable_telegram:
        raise HTTPException(status_code=503, detail="Telegram proxy support is disabled")
    TelegramMediaRef, parse_telegram_url, telegram_manager = _telegram_utils()

    # Get the URL from either parameter
    telegram_url = d or url

    # Determine which input method was used
    if not telegram_url and not file_id and not (chat_id and message_id):
        raise HTTPException(
            status_code=400,
            detail="Provide either 'd' (t.me URL), 'chat_id' + 'message_id', or 'file_id' + 'file_size' parameters",
        )

    try:
        # Parse the reference based on input type
        if telegram_url:
            ref = parse_telegram_url(telegram_url)
        elif chat_id and message_id:
            # Direct chat_id + message_id
            # Try to parse chat_id as int, otherwise treat as username
            try:
                parsed_chat_id: int | str = int(chat_id)
            except ValueError:
                parsed_chat_id = chat_id  # Username
            ref = TelegramMediaRef(chat_id=parsed_chat_id, message_id=message_id)
        else:
            # file_id mode
            if not file_size:
                raise HTTPException(
                    status_code=400,
                    detail="file_size parameter is required when using file_id. "
                    "The file_id doesn't contain size information needed for range requests.",
                )
            ref = TelegramMediaRef(file_id=file_id)

        # Get media info (pass file_size for file_id mode)
        media_info = await telegram_manager.get_media_info(ref, file_size=file_size)
        actual_file_size = media_info.file_size
        mime_type = media_info.mime_type
        media_filename = filename or media_info.file_name

        # For file_id mode, validate access before starting stream
        # This catches FileReferenceExpiredError early, before headers are sent
        if ref.file_id and not ref.message_id:
            await telegram_manager.validate_file_access(ref, file_size=file_size)

        # Handle transcode mode: stream as fMP4 with transcoded audio
        if transcode:
            if not settings.enable_transcode:
                raise HTTPException(status_code=503, detail="Transcoding support is disabled")
            return await _handle_transcode(
                request,
                ref,
                actual_file_size,
                start_time=start,
                file_name=media_filename or "",
            )

        # Parse range header
        range_header = request.headers.get("range")
        start, end = parse_range_header(range_header, actual_file_size)
        content_length = end - start + 1

        # Handle HEAD requests
        if request.method == "HEAD":
            headers = {
                "content-type": get_content_type(mime_type, media_filename),
                "content-length": str(actual_file_size),
                "accept-ranges": "bytes",
                "access-control-allow-origin": "*",
            }
            if media_filename:
                headers["content-disposition"] = _content_disposition_inline(media_filename)
            return Response(headers=headers)

        # Build response headers
        is_range_request = range_header is not None
        status_code = 206 if is_range_request else 200

        base_headers = {
            "content-type": get_content_type(mime_type, media_filename),
            "content-length": str(content_length),
            "accept-ranges": "bytes",
            "access-control-allow-origin": "*",
        }

        if is_range_request:
            base_headers["content-range"] = f"bytes {start}-{end}/{actual_file_size}"

        if media_filename:
            base_headers["content-disposition"] = _content_disposition_inline(media_filename)

        response_headers = apply_header_manipulation(base_headers, proxy_headers)

        # Stream the content (pass file_size for file_id mode)
        async def stream_content():
            try:
                async for chunk in telegram_manager.stream_media(
                    ref, offset=start, limit=content_length, file_size=actual_file_size
                ):
                    yield chunk
            except asyncio.CancelledError:
                # Client disconnected (e.g., seeking in video player) - this is normal
                logger.debug("[telegram_stream] Stream cancelled by client")
            except GeneratorExit:
                # Generator closed - this is normal during cleanup
                logger.debug("[telegram_stream] Stream generator closed")
            except Exception as e:
                error_name = type(e).__name__
                # Handle errors that occur mid-stream (after headers sent)
                if error_name == "FileReferenceExpiredError":
                    logger.error(
                        "[telegram_stream] File reference expired mid-stream. "
                        "This file_id belongs to a different session or the reference is stale."
                    )
                    # Don't re-raise - just end the stream to avoid protocol errors
                    return
                elif error_name in ("ChannelPrivateError", "ChatAdminRequiredError", "UserNotParticipantError"):
                    logger.error(f"[telegram_stream] Access denied mid-stream: {error_name}")
                    return
                else:
                    logger.error(f"[telegram_stream] Error streaming: {e}")
                    # For unknown errors, also don't re-raise to avoid protocol errors
                    return

        return EnhancedStreamingResponse(
            stream_content(),
            status_code=status_code,
            headers=response_headers,
            media_type=get_content_type(mime_type, media_filename),
        )

    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        # Handle specific Telegram errors
        error_name = type(e).__name__

        if error_name == "FloodWaitError":
            wait_seconds = getattr(e, "seconds", 60)
            logger.warning(f"[telegram_stream] Flood wait: {wait_seconds}s")
            raise HTTPException(
                status_code=429,
                detail=f"Rate limited by Telegram. Please wait {wait_seconds} seconds.",
                headers={"Retry-After": str(wait_seconds)},
            )
        elif error_name == "ChannelPrivateError":
            raise HTTPException(
                status_code=403,
                detail="Cannot access private channel. The session user is not a member of this channel/group.",
            )
        elif error_name == "ChatAdminRequiredError":
            raise HTTPException(
                status_code=403,
                detail="Admin privileges required to access this chat.",
            )
        elif error_name == "UserNotParticipantError":
            raise HTTPException(
                status_code=403,
                detail="The session user is not a participant of this chat.",
            )
        elif error_name == "MessageIdInvalidError":
            raise HTTPException(status_code=404, detail="Message not found in the specified chat.")
        elif error_name == "AuthKeyError":
            raise HTTPException(
                status_code=401, detail="Telegram session is invalid. Please regenerate the session string."
            )
        elif error_name == "FileReferenceExpiredError":
            raise HTTPException(
                status_code=410,
                detail="File reference expired or inaccessible. "
                "This file_id belongs to a different bot/user session. "
                "Use chat_id + message_id instead, or ensure the session has access to this file.",
            )
        elif error_name == "UserBannedInChannelError":
            raise HTTPException(
                status_code=403,
                detail="The session user is banned from this channel.",
            )
        elif error_name == "ChannelInvalidError":
            raise HTTPException(
                status_code=404,
                detail="Invalid channel. The channel may not exist or the ID is incorrect.",
            )
        elif error_name == "PeerIdInvalidError":
            raise HTTPException(
                status_code=404,
                detail="Invalid chat ID. The chat/channel/user ID is incorrect or inaccessible.",
            )

        logger.exception(f"[telegram_stream] Unexpected error: {e}")
        raise HTTPException(status_code=500, detail=f"Internal error: {error_name}")


async def _handle_transcode(
    request: Request,
    ref: "TelegramMediaRef",
    file_size: int,
    start_time: float | None = None,
    file_name: str = "",
) -> Response:
    """
    Handle transcode mode: delegate to the shared transcode handler.

    Wraps the Telegram media reference in a TelegramMediaSource and
    passes it to the source-agnostic transcode handler which handles
    cue probing, seeking, and pipeline selection.
    """
    handle_transcode, _, _, _ = _load_transcode_handlers()
    source = TelegramMediaSource(ref, file_size, file_name=file_name)
    return await handle_transcode(request, source, start_time=start_time)


# ---------------------------------------------------------------------------
# HLS transcode endpoints for Telegram sources
# ---------------------------------------------------------------------------


async def _resolve_telegram_source(
    d: str | None = None,
    url: str | None = None,
    chat_id: str | None = None,
    message_id: int | None = None,
    file_id: str | None = None,
    file_size: int | None = None,
    filename: str | None = None,
    *,
    use_single_client: bool = False,
) -> TelegramMediaSource:
    """
    Resolve input parameters to a ``TelegramMediaSource``.

    Args:
        use_single_client: When ``True``, the returned source will use
            Telethon's built-in single-connection downloader instead of
            the parallel ``ParallelTransferrer``.  Should be ``True``
            for HLS requests (playlist, init, segments) where each
            request fetches a small byte range and spinning up multiple
            DC connections per request is wasteful.
    """
    if not settings.enable_telegram:
        from fastapi import HTTPException

        raise HTTPException(status_code=503, detail="Telegram proxy support is disabled")
    TelegramMediaRef, parse_telegram_url, telegram_manager = _telegram_utils()

    telegram_url = d or url

    if not telegram_url and not file_id and not (chat_id and message_id):
        from fastapi import HTTPException

        raise HTTPException(
            status_code=400,
            detail="Provide either 'd' (t.me URL), 'chat_id' + 'message_id', or 'file_id' + 'file_size'",
        )

    if telegram_url:
        ref = parse_telegram_url(telegram_url)
    elif chat_id and message_id:
        try:
            parsed_chat_id: int | str = int(chat_id)
        except ValueError:
            parsed_chat_id = chat_id
        ref = TelegramMediaRef(chat_id=parsed_chat_id, message_id=message_id)
    else:
        if not file_size:
            from fastapi import HTTPException

            raise HTTPException(
                status_code=400,
                detail="file_size is required when using file_id",
            )
        ref = TelegramMediaRef(file_id=file_id)

    media_info = await telegram_manager.get_media_info(ref, file_size=file_size)
    actual_file_size = media_info.file_size
    media_filename = filename or media_info.file_name

    return TelegramMediaSource(
        ref,
        actual_file_size,
        file_name=media_filename or "",
        use_single_client=use_single_client,
    )


@telegram_router.head("/telegram/transcode/playlist.m3u8")
@telegram_router.get("/telegram/transcode/playlist.m3u8")
async def telegram_transcode_hls_playlist(
    request: Request,
    d: Optional[str] = Query(None, description="t.me link or Telegram URL"),
    url: Optional[str] = Query(None, description="Alias for 'd'"),
    chat_id: Optional[str] = Query(None, description="Chat/Channel ID"),
    message_id: Optional[int] = Query(None, description="Message ID"),
    file_id: Optional[str] = Query(None, description="Bot API file_id"),
    file_size: Optional[int] = Query(None, description="File size in bytes"),
    filename: Optional[str] = Query(None, description="Optional filename"),
):
    """Generate an HLS VOD M3U8 playlist for a Telegram media file."""
    if not settings.enable_transcode:
        raise HTTPException(status_code=503, detail="Transcoding support is disabled")
    _, _, handle_transcode_hls_playlist, _ = _load_transcode_handlers()
    source = await _resolve_telegram_source(
        d,
        url,
        chat_id,
        message_id,
        file_id,
        file_size,
        filename,
        use_single_client=True,
    )

    # Build sub-request params using the *resolved* file_id + file_size so
    # that init/segment requests skip the Telegram API call for get_message.
    base_params = _build_telegram_hls_resolved_params(request, source)
    init_url = f"/proxy/telegram/transcode/init.mp4?{base_params}"
    segment_url_template = (
        f"/proxy/telegram/transcode/segment.m4s?{base_params}&seg={{seg}}&start_ms={{start_ms}}&end_ms={{end_ms}}"
    )

    return await handle_transcode_hls_playlist(
        request,
        source,
        init_url=init_url,
        segment_url_template=segment_url_template,
    )


@telegram_router.head("/telegram/transcode/init.mp4")
@telegram_router.get("/telegram/transcode/init.mp4")
async def telegram_transcode_hls_init(
    request: Request,
    d: Optional[str] = Query(None, description="t.me link or Telegram URL"),
    url: Optional[str] = Query(None, description="Alias for 'd'"),
    chat_id: Optional[str] = Query(None, description="Chat/Channel ID"),
    message_id: Optional[int] = Query(None, description="Message ID"),
    file_id: Optional[str] = Query(None, description="Bot API file_id"),
    file_size: Optional[int] = Query(None, description="File size in bytes"),
    filename: Optional[str] = Query(None, description="Optional filename"),
):
    """Serve the fMP4 init segment for a Telegram media file."""
    if not settings.enable_transcode:
        raise HTTPException(status_code=503, detail="Transcoding support is disabled")
    _, handle_transcode_hls_init, _, _ = _load_transcode_handlers()
    source = await _resolve_telegram_source(
        d,
        url,
        chat_id,
        message_id,
        file_id,
        file_size,
        filename,
        use_single_client=True,
    )
    return await handle_transcode_hls_init(request, source)


@telegram_router.get("/telegram/transcode/segment.m4s")
async def telegram_transcode_hls_segment(
    request: Request,
    start_ms: float = Query(..., description="Segment start time in milliseconds"),
    end_ms: float = Query(..., description="Segment end time in milliseconds"),
    seg: int | None = Query(None, description="Segment number (informational, for logging)"),
    d: Optional[str] = Query(None, description="t.me link or Telegram URL"),
    url: Optional[str] = Query(None, description="Alias for 'd'"),
    chat_id: Optional[str] = Query(None, description="Chat/Channel ID"),
    message_id: Optional[int] = Query(None, description="Message ID"),
    file_id: Optional[str] = Query(None, description="Bot API file_id"),
    file_size: Optional[int] = Query(None, description="File size in bytes"),
    filename: Optional[str] = Query(None, description="Optional filename"),
):
    """Serve a single HLS fMP4 media segment for a Telegram media file."""
    if not settings.enable_transcode:
        raise HTTPException(status_code=503, detail="Transcoding support is disabled")
    _, _, _, handle_transcode_hls_segment = _load_transcode_handlers()
    source = await _resolve_telegram_source(
        d,
        url,
        chat_id,
        message_id,
        file_id,
        file_size,
        filename,
        use_single_client=True,
    )
    return await handle_transcode_hls_segment(
        request, source, start_time_ms=start_ms, end_time_ms=end_ms, segment_number=seg
    )


def _build_telegram_hls_params(request: Request) -> str:
    """Build query string for Telegram HLS sub-requests, preserving all input params."""
    from urllib.parse import quote

    params = []
    original = request.query_params
    # Copy all original params except segment-specific ones (added per-segment)
    _seg_keys = {"seg", "start_ms", "end_ms"}
    for key in original:
        if key not in _seg_keys:
            params.append(f"{key}={quote(original[key], safe='')}")
    return "&".join(params)


def _build_telegram_hls_resolved_params(
    request: Request,
    source: "TelegramMediaSource",
) -> str:
    """
    Build query string for HLS sub-request URLs using the *resolved* source.

    Unlike ``_build_telegram_hls_params`` which blindly copies the original
    query params, this version replaces chat_id/message_id/d/url with the
    resolved file reference so that init and segment requests can skip the
    expensive ``get_message()`` Telegram API call.

    The original query params are used as a fallback for any extra parameters
    (api_password, filename, etc.).
    """
    from urllib.parse import quote

    ref = source._ref
    params: dict[str, str] = {}

    # Carry over non-identifying params from the original request
    # (api_password, filename, etc.)
    _skip_keys = {"d", "url", "chat_id", "message_id", "file_id", "file_size", "seg", "start_ms", "end_ms"}
    for key in request.query_params:
        if key not in _skip_keys:
            params[key] = request.query_params[key]

    # Use the resolved reference -- prefer chat_id + message_id (most reliable
    # for streaming), but also include file_size from the resolved source.
    if ref.chat_id is not None and ref.message_id is not None:
        params["chat_id"] = str(ref.chat_id)
        params["message_id"] = str(ref.message_id)
    elif ref.file_id:
        params["file_id"] = ref.file_id
    # Always include file_size -- it prevents unnecessary lookups
    params["file_size"] = str(source.file_size)

    return "&".join(f"{k}={quote(v, safe='')}" for k, v in params.items())


@telegram_router.get("/telegram/info")
async def telegram_info(
    d: Optional[str] = Query(None, description="t.me link or Telegram URL"),
    url: Optional[str] = Query(None, description="Alias for 'd' parameter"),
    chat_id: Optional[str] = Query(None, description="Chat/Channel ID (use with message_id)"),
    message_id: Optional[int] = Query(None, description="Message ID (use with chat_id)"),
    file_id: Optional[str] = Query(None, description="Bot API file_id"),
    file_size: Optional[int] = Query(None, description="File size in bytes (optional for file_id)"),
):
    """
    Get metadata about a Telegram media file.

    Args:
        d: t.me link or Telegram URL
        url: Alias for 'd' parameter
        chat_id: Chat/Channel ID (numeric or username)
        message_id: Message ID within the chat
        file_id: Bot API file_id
        file_size: File size in bytes (optional, will be 0 if not provided for file_id)

    Returns:
        JSON with media information (size, mime_type, filename, dimensions, duration)
    """
    if not settings.enable_telegram:
        raise HTTPException(status_code=503, detail="Telegram proxy support is disabled")
    TelegramMediaRef, parse_telegram_url, telegram_manager = _telegram_utils()

    telegram_url = d or url

    if not telegram_url and not file_id and not (chat_id and message_id):
        raise HTTPException(
            status_code=400,
            detail="Provide either 'd' (t.me URL), 'chat_id' + 'message_id', or 'file_id' parameter",
        )

    try:
        if telegram_url:
            ref = parse_telegram_url(telegram_url)
        elif chat_id and message_id:
            try:
                parsed_chat_id: int | str = int(chat_id)
            except ValueError:
                parsed_chat_id = chat_id
            ref = TelegramMediaRef(chat_id=parsed_chat_id, message_id=message_id)
        else:
            ref = TelegramMediaRef(file_id=file_id)

        media_info = await telegram_manager.get_media_info(ref, file_size=file_size)

        return {
            "file_id": media_info.file_id,
            "file_size": media_info.file_size,
            "mime_type": media_info.mime_type,
            "file_name": media_info.file_name,
            "duration": media_info.duration,
            "width": media_info.width,
            "height": media_info.height,
            "dc_id": media_info.dc_id,
        }

    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        error_name = type(e).__name__
        if error_name == "ChannelPrivateError":
            raise HTTPException(
                status_code=403,
                detail="Cannot access private channel. The session user is not a member.",
            )
        elif error_name == "MessageIdInvalidError":
            raise HTTPException(status_code=404, detail="Message not found in the specified chat.")
        elif error_name == "FileReferenceExpiredError":
            raise HTTPException(
                status_code=410,
                detail="File reference expired or inaccessible. This file_id belongs to a different session.",
            )
        elif error_name == "PeerIdInvalidError":
            raise HTTPException(
                status_code=404,
                detail="Invalid chat ID. The chat/channel/user ID is incorrect or inaccessible.",
            )
        logger.exception(f"[telegram_info] Error: {e}")
        raise HTTPException(status_code=500, detail=f"Internal error: {error_name}")


@telegram_router.get("/telegram/status")
async def telegram_status():
    """
    Get Telegram session status.

    Returns:
        JSON with session status information
    """
    if not settings.enable_telegram:
        return {
            "enabled": False,
            "status": "disabled",
            "message": "Telegram proxy support is disabled in configuration",
        }

    # Check if credentials are configured
    if not settings.telegram_api_id or not settings.telegram_api_hash:
        return {
            "enabled": True,
            "status": "not_configured",
            "message": "Telegram API credentials not configured (telegram_api_id, telegram_api_hash)",
        }

    if not settings.telegram_session_string:
        return {
            "enabled": True,
            "status": "no_session",
            "message": "Session string not configured. Generate one using the web UI.",
        }

    # Check if client is connected
    _, _, telegram_manager = _telegram_utils()
    if telegram_manager.is_initialized:
        return {
            "enabled": True,
            "status": "connected",
            "message": "Telegram client is connected and ready",
            "max_connections": settings.telegram_max_connections,
        }

    # Don't trigger connection - just report ready status
    # Connection will be established on first actual request
    return {
        "enabled": True,
        "status": "ready",
        "message": "Telegram client is configured and ready. Will connect on first request.",
        "max_connections": settings.telegram_max_connections,
    }


# =============================================================================
# Session String Generation Endpoints
# =============================================================================

# In-memory storage for pending session generation (simple approach for single-instance)
# Maps session_id -> { client, api_id, api_hash, phone_code_hash, step }
_pending_sessions: dict = {}


class SessionStartRequest(BaseModel):
    """Request to start session generation."""

    api_id: int
    api_hash: str
    auth_type: str  # "phone" or "bot"
    phone: Optional[str] = None
    bot_token: Optional[str] = None


class SessionCodeRequest(BaseModel):
    """Request to submit verification code."""

    session_id: str
    code: str


class Session2FARequest(BaseModel):
    """Request to submit 2FA password."""

    session_id: str
    password: str


@telegram_router.post("/telegram/session/start")
async def session_start(request: SessionStartRequest):
    """
    Start the session generation process.

    For phone auth: sends verification code to user's Telegram
    For bot auth: validates the bot token immediately

    Returns:
        session_id for subsequent requests, or session_string if bot auth succeeds
    """
    session_id = secrets.token_urlsafe(16)

    try:
        from telethon import TelegramClient
        from telethon.sessions import StringSession

        client = TelegramClient(StringSession(), request.api_id, request.api_hash)
        await client.connect()

        if request.auth_type == "bot":
            # Bot authentication - complete immediately
            if not request.bot_token:
                await client.disconnect()
                raise HTTPException(status_code=400, detail="Bot token is required for bot authentication")

            try:
                await client.sign_in(bot_token=request.bot_token)
                session_string = client.session.save()
                await client.disconnect()

                return {
                    "success": True,
                    "step": "complete",
                    "session_string": session_string,
                    "api_id": request.api_id,
                    "api_hash": request.api_hash,
                }
            except Exception as e:
                await client.disconnect()
                raise HTTPException(status_code=400, detail=f"Bot authentication failed: {str(e)}")

        else:
            # Phone authentication - send code
            phone = request.phone.strip() if request.phone else None
            if not phone:
                await client.disconnect()
                raise HTTPException(status_code=400, detail="Phone number is required for phone authentication")

            logger.info(f"[session_start] Sending code to phone: {phone[:4]}***")

            try:
                result = await client.send_code_request(phone)

                # Store pending session
                _pending_sessions[session_id] = {
                    "client": client,
                    "api_id": request.api_id,
                    "api_hash": request.api_hash,
                    "phone": phone,
                    "phone_code_hash": result.phone_code_hash,
                    "step": "code_sent",
                }

                return {
                    "success": True,
                    "session_id": session_id,
                    "step": "code_sent",
                    "message": "Verification code sent to your Telegram app",
                }
            except Exception as e:
                await client.disconnect()
                error_msg = str(e)
                if "PHONE_NUMBER_INVALID" in error_msg:
                    raise HTTPException(
                        status_code=400,
                        detail="Invalid phone number format. Use international format (e.g., +1234567890)",
                    )
                elif "PHONE_NUMBER_BANNED" in error_msg:
                    raise HTTPException(status_code=400, detail="This phone number is banned from Telegram")
                elif "FLOOD" in error_msg.upper():
                    raise HTTPException(status_code=429, detail="Too many attempts. Please wait before trying again.")
                raise HTTPException(status_code=400, detail=f"Failed to send code: {error_msg}")

    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"[session_start] Error: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to start session: {type(e).__name__}: {str(e)}")


@telegram_router.post("/telegram/session/verify")
async def session_verify(request: SessionCodeRequest):
    """
    Verify the code sent to user's Telegram.

    Returns:
        session_string if successful, or indicates 2FA is required
    """
    session_data = _pending_sessions.get(request.session_id)
    if not session_data:
        raise HTTPException(status_code=404, detail="Session not found or expired. Please start again.")

    client = session_data["client"]
    phone = session_data["phone"]

    try:
        await client.sign_in(phone, request.code, phone_code_hash=session_data["phone_code_hash"])

        # Success - get session string
        session_string = client.session.save()
        await client.disconnect()
        del _pending_sessions[request.session_id]

        return {
            "success": True,
            "step": "complete",
            "session_string": session_string,
            "api_id": session_data["api_id"],
            "api_hash": session_data["api_hash"],
        }

    except Exception as e:
        error_msg = str(e)

        # Check for 2FA requirement
        if (
            "Two-step verification" in error_msg
            or "password" in error_msg.lower()
            or "SessionPasswordNeededError" in type(e).__name__
        ):
            session_data["step"] = "2fa_required"
            return {
                "success": True,
                "session_id": request.session_id,
                "step": "2fa_required",
                "message": "Two-factor authentication is enabled. Please enter your 2FA password.",
            }

        # Check for invalid code
        if "PHONE_CODE_INVALID" in error_msg or "PHONE_CODE_EXPIRED" in error_msg:
            raise HTTPException(status_code=400, detail="Invalid or expired verification code. Please try again.")

        # Other error - cleanup
        await client.disconnect()
        del _pending_sessions[request.session_id]
        raise HTTPException(status_code=400, detail=f"Verification failed: {error_msg}")


@telegram_router.post("/telegram/session/2fa")
async def session_2fa(request: Session2FARequest):
    """
    Complete 2FA authentication.

    Returns:
        session_string on success
    """
    session_data = _pending_sessions.get(request.session_id)
    if not session_data:
        raise HTTPException(status_code=404, detail="Session not found or expired. Please start again.")

    if session_data.get("step") != "2fa_required":
        raise HTTPException(status_code=400, detail="2FA not required for this session")

    client = session_data["client"]

    try:
        await client.sign_in(password=request.password)

        # Success - get session string
        session_string = client.session.save()
        await client.disconnect()
        del _pending_sessions[request.session_id]

        return {
            "success": True,
            "step": "complete",
            "session_string": session_string,
            "api_id": session_data["api_id"],
            "api_hash": session_data["api_hash"],
        }

    except Exception as e:
        error_msg = str(e)

        if "PASSWORD_HASH_INVALID" in error_msg:
            raise HTTPException(status_code=400, detail="Incorrect 2FA password")

        # Other error - cleanup
        await client.disconnect()
        del _pending_sessions[request.session_id]
        raise HTTPException(status_code=400, detail=f"2FA verification failed: {error_msg}")


@telegram_router.post("/telegram/session/cancel")
async def session_cancel(session_id: str = Query(..., description="Session ID to cancel")):
    """
    Cancel a pending session generation.
    """
    session_data = _pending_sessions.pop(session_id, None)
    if session_data:
        try:
            await session_data["client"].disconnect()
        except Exception:
            pass

    return {"success": True, "message": "Session cancelled"}
