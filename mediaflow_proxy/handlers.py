import asyncio
import base64
import logging
import time
from typing import Optional
from urllib.parse import urlparse, parse_qs

import aiohttp
import tenacity
from fastapi import Request, Response, HTTPException
from starlette.background import BackgroundTask

from .const import SUPPORTED_RESPONSE_HEADERS
from .mpd_processor import process_manifest, process_playlist, process_segment, process_init_segment
from .schemas import HLSManifestParams, MPDManifestParams, MPDPlaylistParams, MPDSegmentParams, MPDInitParams
from .utils.cache_utils import (
    get_cached_mpd,
    get_cached_init_segment,
    get_cached_segment,
    set_cached_segment,
    get_cached_processed_segment,
    set_cached_processed_segment,
)
from .utils.dash_prebuffer import dash_prebuffer
from .utils.http_utils import (
    Streamer,
    DownloadError,
    download_file_with_retry,
    request_with_retry,
    EnhancedStreamingResponse,
    ProxyRequestHeaders,
    create_streamer,
    apply_header_manipulation,
)
from .utils.m3u8_processor import M3U8Processor, generate_graceful_end_playlist
from .utils.mpd_utils import pad_base64
from .utils.redis_utils import (
    acquire_stream_gate,
    release_stream_gate,
    get_cached_head,
    set_cached_head,
    check_and_set_cooldown,
    is_redis_configured,
)
from .utils.stream_transformers import StreamTransformer, get_transformer
from .utils.rate_limit_handlers import get_rate_limit_handler

from .configs import settings

logger = logging.getLogger(__name__)


def handle_exceptions(exception: Exception, context: str = "") -> Response:
    """
    Handle exceptions and return appropriate HTTP responses.

    Uses appropriate log levels based on exception type:
    - DEBUG: Expected errors like 404 Not Found
    - WARNING: Transient errors like timeouts, connection issues
    - ERROR: Only for truly unexpected errors

    Args:
        exception (Exception): The exception that was raised.
        context (str): Optional context string for better error messages.

    Returns:
        Response: An HTTP response corresponding to the exception type.
    """
    ctx = f" [{context}]" if context else ""

    if isinstance(exception, aiohttp.ClientResponseError):
        if exception.status == 404:
            logger.debug(f"Upstream 404{ctx}: {exception.request_info.url if exception.request_info else 'unknown'}")
            return Response(status_code=404, content="Upstream resource not found")
        elif exception.status in (429, 509):
            # Rate limited by upstream - pass through so the player can retry on its own
            logger.warning(f"Upstream rate limited ({exception.status}){ctx}")
            return Response(status_code=exception.status, content=f"Upstream rate limited: {exception.status}")
        elif exception.status in (502, 503, 504):
            # Upstream server errors - log at warning level as these are often transient
            logger.warning(f"Upstream server error{ctx}: {exception.status}")
            return Response(status_code=exception.status, content=f"Upstream server error: {exception.status}")
        else:
            logger.warning(f"Upstream HTTP error{ctx}: {exception}")
        return Response(status_code=exception.status, content=f"Upstream service error: {exception}")
    elif isinstance(exception, DownloadError):
        # DownloadError is expected for various upstream issues
        logger.warning(f"Download error{ctx}: {exception}")
        return Response(status_code=exception.status_code, content=str(exception))
    elif isinstance(exception, tenacity.RetryError):
        logger.warning(f"Max retries exceeded{ctx}")
        return Response(status_code=502, content="Max retries exceeded while downloading content")
    elif isinstance(exception, asyncio.TimeoutError):
        logger.warning(f"Timeout error{ctx}: upstream did not respond in time")
        return Response(status_code=504, content="Gateway timeout")
    elif isinstance(exception, aiohttp.ClientError):
        # Client errors are often network issues - warning level
        logger.warning(f"Client error{ctx}: {exception}")
        return Response(status_code=502, content=f"Upstream connection error: {exception}")
    elif isinstance(exception, HTTPException):
        # HTTPException is intentionally raised (e.g. segment unavailable) - not unexpected
        if exception.status_code >= 500:
            logger.warning(f"HTTP exception{ctx}: {exception.status_code}: {exception.detail}")
        else:
            logger.debug(f"HTTP exception{ctx}: {exception.status_code}: {exception.detail}")
        return Response(status_code=exception.status_code, content=exception.detail)
    elif isinstance(exception, ValueError) and "HTML instead of m3u8" in str(exception):
        # Expected error when upstream returns error page instead of playlist
        logger.warning(f"Upstream returned HTML{ctx}: stream may be offline or unavailable")
        return Response(status_code=502, content=str(exception))
    else:
        # Only use exception() (with traceback) for truly unexpected errors
        logger.exception(f"Unexpected error{ctx}: {exception}")
        return Response(status_code=502, content=f"Internal server error: {exception}")


async def handle_hls_stream_proxy(
    request: Request,
    hls_params: HLSManifestParams,
    proxy_headers: ProxyRequestHeaders,
    transformer_id: Optional[str] = None,
) -> Response:
    """
    Handle HLS stream proxy requests.

    This function processes HLS manifest files and streams content based on the request parameters.

    Args:
        request (Request): The incoming FastAPI request object.
        hls_params (HLSManifestParams): Parameters for the HLS manifest.
        proxy_headers (ProxyRequestHeaders): Headers to be used in the proxy request.
        transformer_id (str, optional): ID of the stream transformer to use for segment streaming.

    Returns:
        Union[Response, EnhancedStreamingResponse]: Either a processed m3u8 playlist or a streaming response.
    """
    streamer = await create_streamer()
    # Handle range requests
    content_range = proxy_headers.request.get("range", "bytes=0-")
    if "nan" in content_range.casefold():
        # Handle invalid range requests "bytes=NaN-NaN"
        raise HTTPException(status_code=416, detail="Invalid Range Header")
    proxy_headers.request.update({"range": content_range})

    try:
        # Auto-detect and resolve Vavoo links
        if "vavoo.to" in hls_params.destination:
            try:
                from mediaflow_proxy.extractors.vavoo import VavooExtractor

                vavoo_extractor = VavooExtractor(proxy_headers.request)
                resolved_data = await vavoo_extractor.extract(hls_params.destination)
                resolved_url = resolved_data["destination_url"]
                logger.info(f"Auto-resolved Vavoo URL: {hls_params.destination} -> {resolved_url}")
                # Update destination with resolved URL
                hls_params.destination = resolved_url
            except Exception as e:
                logger.warning(f"Failed to auto-resolve Vavoo URL: {e}")
                # Continue with original URL if resolution fails

        # Parse skip_segments from JSON string to list
        skip_segments_list = hls_params.get_skip_segments()

        # Get transformer instance if specified
        transformer = get_transformer(transformer_id)

        # If force_playlist_proxy is enabled, skip detection and directly process as m3u8
        if hls_params.force_playlist_proxy:
            return await fetch_and_process_m3u8(
                streamer,
                hls_params.destination,
                proxy_headers,
                request,
                hls_params.key_url,
                hls_params.force_playlist_proxy,
                hls_params.key_only_proxy,
                hls_params.no_proxy,
                skip_segments_list,
                transformer,
                hls_params.start_offset,
            )

        parsed_url = urlparse(hls_params.destination)
        # Check if the URL is a valid m3u8 playlist or m3u file
        if parsed_url.path.endswith((".m3u", ".m3u8", ".m3u_plus")) or parse_qs(parsed_url.query).get("type", [""])[
            0
        ] in ["m3u", "m3u8", "m3u_plus"]:
            return await fetch_and_process_m3u8(
                streamer,
                hls_params.destination,
                proxy_headers,
                request,
                hls_params.key_url,
                hls_params.force_playlist_proxy,
                hls_params.key_only_proxy,
                hls_params.no_proxy,
                skip_segments_list,
                transformer,
                hls_params.start_offset,
            )

        # Create initial streaming response to check content type
        await streamer.create_streaming_response(hls_params.destination, proxy_headers.request)
        response_headers = prepare_response_headers(
            streamer.response.headers, proxy_headers.response, proxy_headers.remove, proxy_headers.propagate
        )

        if "mpegurl" in response_headers.get("content-type", "").lower():
            return await fetch_and_process_m3u8(
                streamer,
                hls_params.destination,
                proxy_headers,
                request,
                hls_params.key_url,
                hls_params.force_playlist_proxy,
                hls_params.key_only_proxy,
                hls_params.no_proxy,
                skip_segments_list,
                transformer,
                hls_params.start_offset,
            )

        # If we're removing content-range but upstream returned 206, change to 200
        # (206 Partial Content requires Content-Range header per HTTP spec)
        status_code = streamer.response.status
        if status_code == 206 and "content-range" in [h.lower() for h in proxy_headers.remove]:
            status_code = 200

        return EnhancedStreamingResponse(
            streamer.stream_content(transformer),
            status_code=status_code,
            headers=response_headers,
            background=BackgroundTask(streamer.close),
        )
    except Exception as e:
        await streamer.close()
        return handle_exceptions(e)


async def handle_stream_request(
    method: str,
    video_url: str,
    proxy_headers: ProxyRequestHeaders,
    transformer_id: Optional[str] = None,
    rate_limit_handler_id: Optional[str] = None,
) -> Response:
    """
    Handle general stream requests.

    This function processes both HEAD and GET requests for video streams.
    Uses Redis for cross-worker coordination to prevent CDN rate-limiting (e.g., Vidoza 509).

    Rate limiting behavior is controlled by the rate_limit_handler parameter:
    - If specified, uses that handler's settings
    - If not specified, auto-detects based on video URL hostname
    - If no handler matches, no rate limiting is applied (fast path)

    The coordination strategy (when rate limiting is enabled):
    1. HEAD requests: Check/use Redis cache, skip upstream entirely if cached
    2. GET requests: Check cooldown FIRST, return 503 if in cooldown
    3. Only ONE request proceeds to upstream at a time via gate
    4. After upstream responds, set cooldown to prevent rapid follow-up requests

    Args:
        method (str): The HTTP method (e.g., 'GET' or 'HEAD').
        video_url (str): The URL of the video to stream.
        proxy_headers (ProxyRequestHeaders): Headers to be used in the proxy request.
        transformer_id (str, optional): ID of the stream transformer to use for content manipulation.
        rate_limit_handler_id (str, optional): ID of the rate limit handler to use (e.g., "vidoza", "aggressive").
            If not specified, auto-detects based on video URL hostname.

    Returns:
        Union[Response, EnhancedStreamingResponse]: Either a HEAD response with headers or a streaming response.
    """
    host = urlparse(video_url).hostname or "unknown"
    gate_acquired = False

    # Get rate limit handler (explicit ID, auto-detect from URL, or default no-op)
    rate_handler = get_rate_limit_handler(rate_limit_handler_id, video_url)

    # Check if rate limiting features are needed and Redis is available
    needs_rate_limiting = (
        rate_handler.cooldown_seconds > 0 or rate_handler.use_head_cache or rate_handler.use_stream_gate
    )
    redis_available = is_redis_configured()

    if needs_rate_limiting:
        logger.info(
            f"[handle_stream] Rate limiting ENABLED for {host}: "
            f"cooldown={rate_handler.cooldown_seconds}s, gate={rate_handler.use_stream_gate}, "
            f"head_cache={rate_handler.use_head_cache}, redis={redis_available}"
        )

    if needs_rate_limiting and not redis_available:
        logger.warning(f"[handle_stream] Rate limiting requested for {host} but Redis not configured - skipping")
        needs_rate_limiting = False

    # Cooldown key - prevents rapid-fire requests to same CDN URL
    cooldown_key = f"stream_cooldown:{video_url}"

    # 1. Check Redis HEAD cache first (if enabled by handler)
    cached = None
    if needs_rate_limiting and rate_handler.use_head_cache:
        cached = await get_cached_head(video_url)

    if method == "HEAD":
        if cached:
            logger.info(f"[handle_stream] Serving cached HEAD response for {host}")
            response_headers = prepare_response_headers(
                cached["headers"], proxy_headers.response, proxy_headers.remove, proxy_headers.propagate
            )
            return Response(headers=response_headers, status_code=cached["status"])
        # No cached HEAD - for rate-limited hosts, wait for cache via gate instead of hitting upstream
        if needs_rate_limiting and rate_handler.use_stream_gate:
            # Try to acquire gate - if we get it, we make the upstream HEAD request
            # If another request holds the gate, we wait and then check cache again
            gate_acquired = await acquire_stream_gate(video_url, timeout=30.0)
            if gate_acquired:
                # We got the gate - check cache again (another request may have populated it while we waited)
                cached = await get_cached_head(video_url)
                if cached:
                    await release_stream_gate(video_url)
                    logger.info(f"[handle_stream] Serving cached HEAD response after gate wait for {host}")
                    response_headers = prepare_response_headers(
                        cached["headers"], proxy_headers.response, proxy_headers.remove, proxy_headers.propagate
                    )
                    return Response(headers=response_headers, status_code=cached["status"])
                # Cache still empty - we'll make the upstream request (gate is held)
            else:
                # Gate timeout - check cache one more time before giving up
                cached = await get_cached_head(video_url)
                if cached:
                    logger.info(f"[handle_stream] Serving cached HEAD after gate timeout for {host}")
                    response_headers = prepare_response_headers(
                        cached["headers"], proxy_headers.response, proxy_headers.remove, proxy_headers.propagate
                    )
                    return Response(headers=response_headers, status_code=cached["status"])
                logger.warning(f"[handle_stream] HEAD gate timeout for {host}, no cached headers available")
                return Response(status_code=503, content="Upstream host is busy, try again later")
        # No rate limiting - proceed to upstream without gate
    else:
        # For GET requests with rate limiting: wait for cooldown and acquire gate
        if needs_rate_limiting and rate_handler.use_stream_gate:
            # Wait for gate - this serializes all requests to the same URL
            gate_acquired = await acquire_stream_gate(video_url, timeout=30.0)
            if not gate_acquired:
                logger.warning(f"[handle_stream] Gate timeout for {host}, upstream may be slow")
                return Response(status_code=503, content="Upstream host is busy, try again later")

            # Got the gate - now check/set cooldown
            # If in cooldown, wait for it to expire before proceeding
            if rate_handler.cooldown_seconds > 0:
                max_wait = rate_handler.cooldown_seconds + 1  # Wait slightly longer than cooldown
                wait_start = time.time()

                while not await check_and_set_cooldown(cooldown_key, rate_handler.cooldown_seconds):
                    # Still in cooldown - wait a bit and retry
                    elapsed = time.time() - wait_start
                    if elapsed >= max_wait:
                        # Cooldown still active after max wait - give up
                        await release_stream_gate(video_url)
                        logger.warning(f"[handle_stream] Cooldown wait timeout for {host}")
                        return Response(
                            status_code=503,
                            content="Stream busy, try again later",
                            headers={"Retry-After": str(rate_handler.retry_after_seconds)},
                        )
                    logger.debug(f"[handle_stream] Waiting for cooldown to expire for {host}...")
                    await asyncio.sleep(0.5)  # Poll every 500ms

                # Cooldown acquired - we can proceed to upstream
                logger.info(f"[handle_stream] Cooldown acquired for {host} after {time.time() - wait_start:.1f}s wait")

    streamer = await create_streamer(video_url)

    try:
        # Auto-detect and resolve Vavoo links
        if "vavoo.to" in video_url:
            try:
                from mediaflow_proxy.extractors.vavoo import VavooExtractor

                vavoo_extractor = VavooExtractor(proxy_headers.request)
                resolved_data = await vavoo_extractor.extract(video_url)
                resolved_url = resolved_data["destination_url"]
                logger.info(f"Auto-resolved Vavoo URL: {video_url} -> {resolved_url}")
                # Update video_url with resolved URL
                video_url = resolved_url
            except Exception as e:
                logger.warning(f"Failed to auto-resolve Vavoo URL: {e}")
                # Continue with original URL if resolution fails

        # Log timing for debugging seek performance
        start_time = time.time()
        range_header = proxy_headers.request.get("range", "not set")
        logger.info(f"[handle_stream] Starting upstream {method} request - range: {range_header}")

        # Track if this is an auto-added "bytes=0-" range (client didn't send range)
        # We detect this by checking if range equals exactly "bytes=0-" which indicates
        # a proxy-added default range, not a client seeking request
        auto_added_range = proxy_headers.request.get("range") == "bytes=0-"

        # Use the same HTTP method for upstream request (HEAD for HEAD, GET for GET)
        # This prevents unnecessary data download when client just wants headers
        await streamer.create_streaming_response(video_url, proxy_headers.request, method=method)

        elapsed = time.time() - start_time
        logger.info(f"[handle_stream] Upstream responded in {elapsed:.2f}s - status: {streamer.response.status}")
        logger.debug(f"Upstream response headers: {dict(streamer.response.headers)}")

        response_headers = prepare_response_headers(
            streamer.response.headers, proxy_headers.response, proxy_headers.remove, proxy_headers.propagate
        )
        logger.debug(f"Prepared response headers: {response_headers}")

        # When client didn't send a Range header but upstream returns 206 Partial Content:
        # - Convert status to 200 (full content, not partial)
        # - Remove content-range header to avoid confusing the client
        # This handles cases where we added bytes=0- range but upstream still treats it as a range request
        status_code = streamer.response.status
        if status_code == 206:
            if "content-range" in [h.lower() for h in proxy_headers.remove]:
                # Explicitly requested to remove content-range
                status_code = 200
                # Also remove content-range from response headers if present
                response_headers.pop("content-range", None)
            elif auto_added_range:
                # We auto-added bytes=0- range but got 206 - convert to 200
                # This happens when client didn't send a range but upstream responds with 206
                status_code = 200
                # Remove content-range to avoid confusing client
                response_headers.pop("content-range", None)
                # Update content-length to total size (remove range suffix if present)
                content_range = streamer.response.headers.get("Content-Range", "")
                if "/" in content_range:
                    # Extract total size from "bytes X-Y/total"
                    total_size = content_range.split("/")[-1].strip()
                    response_headers["content-length"] = total_size

        # Get transformer instance if specified
        transformer = get_transformer(transformer_id)

        # Cache headers in Redis for future HEAD probes (if rate limiting enabled)
        if needs_rate_limiting and rate_handler.use_head_cache and status_code in (200, 206):
            await set_cached_head(video_url, dict(streamer.response.headers), status_code)

        if method == "HEAD":
            # HEAD requests always release gate immediately
            if gate_acquired:
                await release_stream_gate(video_url)
                gate_acquired = False
            await streamer.close()
            return Response(headers=response_headers, status_code=status_code)
        else:
            # For GET requests: check if we need exclusive streaming
            if gate_acquired and needs_rate_limiting and rate_handler.exclusive_stream:
                # EXCLUSIVE MODE: Keep gate held during entire stream
                # Release gate in background task when stream ends
                logger.info(f"[handle_stream] Exclusive stream mode - gate held during stream for {host}")

                async def cleanup_exclusive():
                    await streamer.close()
                    await release_stream_gate(video_url)
                    logger.info(f"[handle_stream] Exclusive stream ended - gate released for {host}")

                gate_acquired = False  # Background task will release it
                return EnhancedStreamingResponse(
                    streamer.stream_content(transformer),
                    headers=response_headers,
                    status_code=status_code,
                    background=BackgroundTask(cleanup_exclusive),
                )
            else:
                # NORMAL MODE: Release gate after headers, stream continues freely
                if gate_acquired:
                    await release_stream_gate(video_url)
                    gate_acquired = False
                return EnhancedStreamingResponse(
                    streamer.stream_content(transformer),
                    headers=response_headers,
                    status_code=status_code,
                    background=BackgroundTask(streamer.close),
                )
    except Exception as e:
        await streamer.close()
        return handle_exceptions(e)
    finally:
        # Safety: release gate if not already released (error path before headers received)
        if gate_acquired:
            await release_stream_gate(video_url)


def prepare_response_headers(
    original_headers, proxy_response_headers, remove_headers=None, propagate_headers=None
) -> dict:
    """
    Prepare response headers for the proxy response.

    This function filters the original headers, ensures proper transfer encoding,
    and merges them with the proxy response headers.

    Args:
        original_headers: The original headers from the upstream response (aiohttp CIMultiDictProxy).
        proxy_response_headers (dict): Additional headers to be included in the proxy response.
        remove_headers (list, optional): List of header names to remove from the response. Defaults to None.
        propagate_headers (dict, optional): Headers that propagate to segments (rp_ prefix). Defaults to None.

    Returns:
        dict: The prepared headers for the proxy response.
    """
    remove_set = set(h.lower() for h in (remove_headers or []))
    response_headers = {}

    # Handle aiohttp CIMultiDictProxy
    for k, v in original_headers.items():
        k_lower = k.lower()
        if k_lower in SUPPORTED_RESPONSE_HEADERS and k_lower not in remove_set:
            response_headers[k_lower] = v

    # Apply propagate headers first (for segments), then response headers (response takes precedence)
    if propagate_headers:
        response_headers.update(propagate_headers)
    response_headers.update(proxy_response_headers)
    return response_headers


async def proxy_stream(
    method: str,
    destination: str,
    proxy_headers: ProxyRequestHeaders,
    transformer_id: Optional[str] = None,
    rate_limit_handler_id: Optional[str] = None,
):
    """
    Proxies the stream request to the given video URL.

    Args:
        method (str): The HTTP method (e.g., GET, HEAD).
        destination (str): The URL of the stream to be proxied.
        proxy_headers (ProxyRequestHeaders): The headers to include in the request.
        transformer_id (str, optional): ID of the stream transformer to use.
        rate_limit_handler_id (str, optional): ID of the rate limit handler to use (e.g., "vidoza").
            If not specified, auto-detects based on destination URL hostname.

    Returns:
        Response: The HTTP response with the streamed content.
    """
    return await handle_stream_request(method, destination, proxy_headers, transformer_id, rate_limit_handler_id)


async def fetch_and_process_m3u8(
    streamer: Streamer,
    url: str,
    proxy_headers: ProxyRequestHeaders,
    request: Request,
    key_url: str = None,
    force_playlist_proxy: bool = None,
    key_only_proxy: bool = False,
    no_proxy: bool = False,
    skip_segments: list = None,
    transformer: Optional[StreamTransformer] = None,
    start_offset: float = None,
):
    """
    Fetches and processes the m3u8 playlist on-the-fly, converting it to an HLS playlist.

    Args:
        streamer (Streamer): The HTTP client to use for streaming.
        url (str): The URL of the m3u8 playlist.
        proxy_headers (ProxyRequestHeaders): The headers to include in the request.
        request (Request): The incoming HTTP request.
        key_url (str, optional): The HLS Key URL to replace the original key URL. Defaults to None.
        force_playlist_proxy (bool, optional): Force all playlist URLs to be proxied through MediaFlow. Defaults to None.
        key_only_proxy (bool, optional): Only proxy the key URL, leaving segment URLs direct. Defaults to False.
        no_proxy (bool, optional): If True, returns the manifest without proxying any URLs. Defaults to False.
        skip_segments (list, optional): List of time segments to skip. Each item should have
                                        'start', 'end' (in seconds), and optionally 'type'.
        transformer (StreamTransformer, optional): Transformer to apply to the stream content.
        start_offset (float, optional): Time offset in seconds for EXT-X-START tag. Use negative
                                       values for live streams to start behind the live edge.

    Returns:
        Response: The HTTP response with the processed m3u8 playlist.
    """
    try:
        # Create streaming response if not already created
        if not streamer.response:
            await streamer.create_streaming_response(url, proxy_headers.request)

        # Initialize processor and response headers
        # skip_segments is already a list of dicts with 'start' and 'end' keys
        processor = M3U8Processor(
            request, key_url, force_playlist_proxy, key_only_proxy, no_proxy, skip_segments, start_offset
        )
        base_headers = {
            "content-disposition": "inline",
            "accept-ranges": "none",
            "content-type": "application/vnd.apple.mpegurl",
        }
        # Don't include propagate headers for manifests - they should only apply to segments
        response_headers = apply_header_manipulation(base_headers, proxy_headers, include_propagate=False)

        # Get the generator for processing
        m3u8_generator = processor.process_m3u8_streaming(
            streamer.stream_content(transformer), str(streamer.response.url)
        )

        # Pre-fetch the first chunk to validate the content before starting the response
        # This allows us to return a proper HTTP error if the upstream returns HTML
        first_chunk = None
        try:
            first_chunk = await m3u8_generator.__anext__()
        except ValueError as e:
            # Upstream returned HTML instead of m3u8 - expected error, log at warning level
            logger.warning(f"Upstream error for {url}: {e}")
            await streamer.close()
            # Return graceful end playlist if enabled, otherwise raise error
            if settings.graceful_stream_end:
                graceful_content = generate_graceful_end_playlist("Stream offline or unavailable")
                return Response(
                    content=graceful_content,
                    media_type="application/vnd.apple.mpegurl",
                    headers=response_headers,
                )
            raise HTTPException(status_code=502, detail=str(e))
        except StopAsyncIteration:
            # Empty response - this shouldn't happen for valid m3u8
            logger.warning(f"Upstream returned empty m3u8 playlist: {url}")
            await streamer.close()
            # Return graceful end playlist if enabled, otherwise raise error
            if settings.graceful_stream_end:
                graceful_content = generate_graceful_end_playlist("Empty upstream response")
                return Response(
                    content=graceful_content,
                    media_type="application/vnd.apple.mpegurl",
                    headers=response_headers,
                )
            raise HTTPException(status_code=502, detail="Upstream returned empty m3u8 playlist")

        # Create a wrapper that yields the first chunk then continues with the rest
        async def prefetched_generator():
            yield first_chunk
            try:
                async for chunk in m3u8_generator:
                    yield chunk
            except ValueError as e:
                # This shouldn't happen since we already validated the first chunk,
                # but handle it gracefully if it does
                logger.warning(f"ValueError during m3u8 streaming (after initial validation): {e}")

        # Create streaming response with on-the-fly processing
        return EnhancedStreamingResponse(
            prefetched_generator(),
            headers=response_headers,
            background=BackgroundTask(streamer.close),
        )
    except HTTPException:
        raise
    except Exception as e:
        await streamer.close()
        return handle_exceptions(e)


def _normalize_drm_key_value(value: str) -> str:
    """
    Normalize a DRM key_id or key value to lowercase hex.

    Accepts either:
    - A 32-char hex string (returned as-is, lowercased).
    - A base64url-encoded value (decoded to hex).
    - A comma-separated list of the above, for multi-key DRM scenarios.

    Commas are treated as list separators, NOT as characters to pass into
    base64 decoding.  Previously the ``len() != 32`` check was applied to
    the entire comma-joined string, and ``urlsafe_b64decode`` silently
    strips non-alphabet characters (including commas), causing adjacent keys
    to be concatenated into an oversized byte string.

    Args:
        value: The key value string, or None.

    Returns:
        Normalized hex string (or comma-joined hex strings for multi-key),
        or the original value unchanged if it is falsy.
    """
    if not value:
        return value
    if "," in value:
        parts = [_normalize_single_key(p.strip()) for p in value.split(",") if p.strip()]
        return ",".join(parts)
    return _normalize_single_key(value)


def _normalize_single_key(value: str) -> str:
    """Convert a single key_id or key to a 32-char lowercase hex string."""
    if len(value) != 32:
        return base64.urlsafe_b64decode(pad_base64(value)).hex()
    return value.lower()


async def handle_drm_key_data(key_id, key, drm_info):
    """
    Handles the DRM key data, retrieving the key ID and key from the DRM info if not provided.

    Args:
        key_id (str): The DRM key ID.
        key (str): The DRM key.
        drm_info (dict): The DRM information from the MPD manifest.

    Returns:
        tuple: The key ID and key.
    """
    if drm_info and not drm_info.get("isDrmProtected"):
        return None, None

    if not key_id or not key:
        if "keyId" in drm_info and "key" in drm_info:
            key_id = drm_info["keyId"]
            key = drm_info["key"]
        elif "laUrl" in drm_info and "keyId" in drm_info:
            # License URL with keyId - license acquisition should have been attempted already
            # If we still don't have a key, it means acquisition failed
            pass
        else:
            # Try to use extracted KID if available (from MPD/init segment analysis)
            if not key_id and drm_info.get("extracted_kids"):
                # Use the first extracted KID
                extracted_kids = drm_info["extracted_kids"]
                if extracted_kids:
                    key_id = extracted_kids[0]
                    logger.info(f"Using extracted KID from MPD/init segment: {key_id}")

            # Still require the actual decryption key
            if not key:
                if drm_info.get("extracted_kids"):
                    license_urls = drm_info.get("license_urls", [])
                    license_url_msg = f" License server: {license_urls[0]}" if license_urls else ""
                    raise HTTPException(
                        status_code=400,
                        detail=(
                            f"Key ID (KID) was automatically extracted: {key_id}. "
                            f"However, the actual decryption key must be provided via the 'key' parameter. "
                            f"The key cannot be extracted from the MPD or init segment and must be obtained "
                            f"from the license server or source website.{license_url_msg}"
                        ),
                    )
                else:
                    raise HTTPException(
                        status_code=400, detail="Unable to determine key_id and key, and they were not provided"
                    )

    return key_id, key


async def get_manifest(
    request: Request,
    manifest_params: MPDManifestParams,
    proxy_headers: ProxyRequestHeaders,
):
    """
    Retrieves and processes the MPD manifest, converting it to an HLS manifest.

    Args:
        request (Request): The incoming HTTP request.
        manifest_params (MPDManifestParams): The parameters for the manifest request.
        proxy_headers (ProxyRequestHeaders): The headers to include in the request.

    Returns:
        Response: The HTTP response with the HLS manifest.
    """
    try:
        mpd_dict = await get_cached_mpd(
            manifest_params.destination,
            headers=proxy_headers.request,
            parse_drm=not manifest_params.key_id and not manifest_params.key,
        )
    except DownloadError as e:
        raise HTTPException(status_code=e.status_code, detail=f"Failed to download MPD: {e.message}")
    drm_info = mpd_dict.get("drmInfo", {})

    # Get skip segments if provided
    skip_segments = manifest_params.get_skip_segments()

    if drm_info and not drm_info.get("isDrmProtected"):
        # For non-DRM protected MPD, we still create an HLS manifest
        return await process_manifest(
            request, mpd_dict, proxy_headers, None, None, manifest_params.resolution, skip_segments
        )

    key_id, key = await handle_drm_key_data(manifest_params.key_id, manifest_params.key, drm_info)

    # Normalize key_id and key: convert from base64 to hex when needed.
    # Each value may be a comma-separated list for multi-key DRM; each part is
    # normalized independently so that commas are never passed to urlsafe_b64decode
    # (base64 silently ignores non-alphabet characters, stripping commas and
    # concatenating the keys into a single oversized value).
    key_id = _normalize_drm_key_value(key_id)
    key = _normalize_drm_key_value(key)

    return await process_manifest(
        request, mpd_dict, proxy_headers, key_id, key, manifest_params.resolution, skip_segments
    )


async def get_playlist(
    request: Request,
    playlist_params: MPDPlaylistParams,
    proxy_headers: ProxyRequestHeaders,
):
    """
    Retrieves and processes the MPD manifest, converting it to an HLS playlist for a specific profile.

    Args:
        request (Request): The incoming HTTP request.
        playlist_params (MPDPlaylistParams): The parameters for the playlist request.
        proxy_headers (ProxyRequestHeaders): The headers to include in the request.

    Returns:
        Response: The HTTP response with the HLS playlist.
    """
    try:
        mpd_dict = await get_cached_mpd(
            playlist_params.destination,
            headers=proxy_headers.request,
            parse_drm=not playlist_params.key_id and not playlist_params.key,
            parse_segment_profile_id=playlist_params.profile_id,
        )
    except DownloadError as e:
        raise HTTPException(status_code=e.status_code, detail=f"Failed to download MPD: {e.message}")

    # Get skip segments if provided
    skip_segments = playlist_params.get_skip_segments()

    return await process_playlist(
        request, mpd_dict, playlist_params.profile_id, proxy_headers, skip_segments, playlist_params.start_offset
    )


async def get_segment(
    segment_params: MPDSegmentParams,
    proxy_headers: ProxyRequestHeaders,
    force_remux_ts: bool = None,
):
    """
    Retrieves and processes a media segment, decrypting it if necessary.

    Uses event-based coordination with the DASH prebuffer to prevent duplicate
    downloads. The prebuffer's get_or_download() handles cache checks, waiting
    for existing downloads, and starting new downloads as needed.

    Args:
        segment_params (MPDSegmentParams): The parameters for the segment request.
        proxy_headers (ProxyRequestHeaders): The headers to include in the request.
        force_remux_ts (bool, optional): If True, force remuxing to MPEG-TS regardless
            of global settings. Used by /mpd/segment.ts endpoint. Defaults to None.

    Returns:
        Response: The HTTP response with the processed segment.
    """
    try:
        live_cache_ttl = settings.mpd_live_init_cache_ttl if segment_params.is_live else None
        segment_url = segment_params.segment_url
        should_remux = force_remux_ts if force_remux_ts is not None else settings.remux_to_ts

        # Check processed segment cache first (avoids re-decrypting/re-remuxing)
        is_processed = bool(segment_params.key_id or should_remux)
        if is_processed:
            processed_content = await get_cached_processed_segment(segment_url, segment_params.key_id, should_remux)
            if processed_content:
                logger.info(f"Serving processed segment from cache: {segment_url}")
                mimetype = "video/mp2t" if should_remux else segment_params.mime_type
                response_headers = apply_header_manipulation({}, proxy_headers)
                return Response(content=processed_content, media_type=mimetype, headers=response_headers)

        # Use event-based coordination for segment download
        # get_or_download() handles:
        # - Cache check
        # - Waiting for existing downloads (via asyncio.Event)
        # - Starting new download if needed
        # - Caching the result
        # Player requests should get priority over background prebuffer activity.
        # Use a configurable lock timeout to balance responsiveness and cache reuse.
        if settings.enable_dash_prebuffer:
            segment_content = await dash_prebuffer.get_or_download(
                segment_url, proxy_headers.request, timeout=settings.dash_player_lock_timeout
            )
        else:
            # Prebuffer disabled - check cache then download directly
            segment_content = await get_cached_segment(segment_url)
            if not segment_content:
                try:
                    segment_content = await download_file_with_retry(segment_url, proxy_headers.request)
                    # Cache for future requests (synchronous to ensure it's cached before returning)
                    if segment_content and segment_params.is_live:
                        # Use create_task for non-blocking cache write, but segment is already downloaded
                        asyncio.create_task(
                            set_cached_segment(segment_url, segment_content, ttl=settings.dash_segment_cache_ttl)
                        )
                except Exception as dl_err:
                    logger.warning(f"Direct download failed when prebuffer disabled: {dl_err}")
                    segment_content = None

        # If prebuffer returned None (lock timeout or coordination failure),
        # check cache one more time - the download may have completed while we waited
        # Then fall back to a direct download if still not cached.
        # This is critical for live streams where the prebuffer may be busy
        # downloading other segments/profiles.
        if not segment_content:
            # Final cache check - download may have completed during lock wait
            segment_content = await get_cached_segment(segment_url)
            if segment_content:
                logger.info(f"Segment found in cache after prebuffer timeout: {segment_url}")
            else:
                logger.info(f"Prebuffer returned no content, falling back to direct download: {segment_url}")
                try:
                    segment_content = await download_file_with_retry(segment_url, proxy_headers.request)
                    # Cache on success for future requests
                    if segment_content and segment_params.is_live:
                        asyncio.create_task(
                            set_cached_segment(segment_url, segment_content, ttl=settings.dash_segment_cache_ttl)
                        )
                except Exception as dl_err:
                    logger.warning(f"Direct download fallback also failed: {dl_err}")

        if not segment_content:
            # Return 404 instead of 502 so players can skip and continue
            # Most video players handle 404s gracefully by skipping the segment
            raise HTTPException(status_code=404, detail="Segment unavailable")

        # Fetch init segment (uses its own cache)
        init_content = await get_cached_init_segment(
            segment_params.init_url,
            proxy_headers.request,
            cache_token=segment_params.key_id,
            ttl=live_cache_ttl,
            byte_range=segment_params.init_range,
        )

        # Trigger continuous prefetch for live streams
        if settings.enable_dash_prebuffer and segment_params.is_live:
            for mpd_url in dash_prebuffer.active_streams:
                asyncio.create_task(
                    dash_prebuffer.prefetch_upcoming_segments(
                        mpd_url,
                        segment_url,
                        proxy_headers.request,
                    )
                )
                break  # Only need to trigger once

    except Exception as e:
        return handle_exceptions(e)

    try:
        response = await process_segment(
            init_content,
            segment_content,
            segment_params.mime_type,
            proxy_headers,
            segment_params.key_id,
            segment_params.key,
            use_map=segment_params.use_map,
            remux_ts=force_remux_ts,
        )
    except Exception as e:
        return handle_exceptions(e)

    # Cache processed segment for future requests (avoids re-decrypting/re-remuxing)
    if is_processed and response.status_code == 200:
        asyncio.create_task(
            set_cached_processed_segment(
                segment_url,
                response.body,
                segment_params.key_id,
                should_remux,
                ttl=settings.processed_segment_cache_ttl,
            )
        )

    return response


async def get_init_segment(
    init_params: MPDInitParams,
    proxy_headers: ProxyRequestHeaders,
):
    """
    Retrieves and processes an initialization segment for EXT-X-MAP.

    Args:
        init_params (MPDInitParams): The parameters for the init segment request.
        proxy_headers (ProxyRequestHeaders): The headers to include in the request.

    Returns:
        Response: The HTTP response with the processed init segment.
    """
    try:
        live_cache_ttl = settings.mpd_live_init_cache_ttl if init_params.is_live else None
        init_content = await get_cached_init_segment(
            init_params.init_url,
            proxy_headers.request,
            cache_token=init_params.key_id,
            ttl=live_cache_ttl,
            byte_range=init_params.init_range,
        )
    except Exception as e:
        return handle_exceptions(e)

    return await process_init_segment(
        init_content,
        init_params.mime_type,
        proxy_headers,
        init_params.key_id,
        init_params.key,
        init_params.init_url,
    )


IP_LOOKUP_SERVICES = [
    {"url": "https://api.ipify.org?format=json", "key": "ip"},
    {"url": "https://ipinfo.io/json", "key": "ip"},
    {"url": "https://httpbin.org/ip", "key": "origin"},
]


async def get_public_ip():
    """
    Retrieves the public IP address of the MediaFlow proxy.
    Tries multiple services for reliability.

    Returns:
        dict: A dictionary with the public IP address {"ip": "x.x.x.x"}.

    Raises:
        DownloadError: If all IP lookup services fail.
    """
    for service in IP_LOOKUP_SERVICES:
        try:
            response = await request_with_retry("GET", service["url"], {})
            content = await response.text()
            import json

            data = json.loads(content)
            ip = data.get(service["key"])
            if ip:
                return {"ip": ip.strip()}
        except Exception:
            continue

    raise DownloadError(503, "Failed to retrieve public IP from all services")
