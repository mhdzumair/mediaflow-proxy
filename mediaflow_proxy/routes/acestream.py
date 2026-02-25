"""
Acestream proxy routes.

Provides endpoints for proxying acestream content:
- /proxy/acestream/manifest.m3u8 - HLS manifest proxy (primary, leverages existing HLS infrastructure)
- /proxy/acestream/stream - MPEG-TS stream proxy with fan-out to multiple clients
- /proxy/acestream/segment.ts - Segment proxy for HLS mode
"""

import asyncio
import logging
from functools import lru_cache
from typing import Annotated, TYPE_CHECKING
from urllib.parse import urlencode, urljoin, urlparse

import aiohttp
from fastapi import APIRouter, Query, Request, HTTPException, Response, Depends
from starlette.background import BackgroundTask

from mediaflow_proxy.configs import settings
from mediaflow_proxy.utils.http_client import create_aiohttp_session
from mediaflow_proxy.utils.http_utils import (
    get_original_scheme,
    get_proxy_headers,
    ProxyRequestHeaders,
    EnhancedStreamingResponse,
    apply_header_manipulation,
    create_streamer,
)
from mediaflow_proxy.utils.m3u8_processor import M3U8Processor
from mediaflow_proxy.utils.hls_prebuffer import hls_prebuffer

logger = logging.getLogger(__name__)
acestream_router = APIRouter()

if TYPE_CHECKING:
    from mediaflow_proxy.utils.acestream import AcestreamSession


def _get_acestream_manager():
    from mediaflow_proxy.utils.acestream import acestream_manager

    return acestream_manager


@lru_cache(maxsize=1)
def _load_transcode_pipeline():
    from mediaflow_proxy.remuxer.transcode_pipeline import stream_transcode_universal

    return stream_transcode_universal


class AcestreamM3U8Processor(M3U8Processor):
    """
    M3U8 processor specialized for Acestream.

    Rewrites segment URLs to go through the acestream segment proxy endpoint
    while preserving session information.
    """

    def __init__(
        self,
        request: Request,
        session: "AcestreamSession",
        key_url: str = None,
        force_playlist_proxy: bool = True,
        key_only_proxy: bool = False,
        no_proxy: bool = False,
    ):
        super().__init__(
            request=request,
            key_url=key_url,
            force_playlist_proxy=force_playlist_proxy,
            key_only_proxy=key_only_proxy,
            no_proxy=no_proxy,
        )
        self.session = session

    async def proxy_content_url(self, url: str, base_url: str) -> str:
        """
        Override to route acestream segments through the acestream segment endpoint.

        This ensures segments use /proxy/acestream/segment.ts instead of /proxy/hls/segment.ts
        """
        full_url = urljoin(base_url, url)

        # If no_proxy is enabled, return the direct URL
        if self.no_proxy:
            return full_url

        # Check if this is a playlist URL (use standard proxy for playlists)
        parsed = urlparse(full_url)
        is_playlist = parsed.path.endswith((".m3u", ".m3u8", ".m3u_plus"))

        if is_playlist:
            # Use standard playlist proxy
            return await super().proxy_content_url(url, base_url)

        # For segments, route through acestream segment endpoint
        query_params = {
            "d": full_url,
        }

        # Preserve the original id/infohash parameter from the request
        if "id" in self.request.query_params:
            query_params["id"] = self.request.query_params["id"]
        else:
            query_params["infohash"] = self.session.infohash

        # Include api_password and headers from the original request
        for key, value in self.request.query_params.items():
            if key == "api_password" or key.startswith("h_"):
                query_params[key] = value

        # Determine the segment extension
        path = parsed.path.lower()
        if path.endswith(".ts"):
            ext = "ts"
        elif path.endswith(".m4s"):
            ext = "m4s"
        elif path.endswith(".mp4"):
            ext = "mp4"
        else:
            ext = "ts"

        # Build acestream segment proxy URL
        base_proxy_url = str(
            self.request.url_for("acestream_segment_proxy", ext=ext).replace(scheme=get_original_scheme(self.request))
        )
        return f"{base_proxy_url}?{urlencode(query_params)}"


@acestream_router.head("/acestream/manifest.m3u8")
@acestream_router.get("/acestream/manifest.m3u8")
async def acestream_hls_manifest(
    request: Request,
    proxy_headers: Annotated[ProxyRequestHeaders, Depends(get_proxy_headers)],
    infohash: str = Query(None, description="Acestream infohash"),
    id: str = Query(None, description="Acestream content ID (alternative to infohash)"),
):
    """
    Proxy Acestream HLS manifest.

    Creates or reuses an acestream session and proxies the HLS manifest,
    rewriting segment URLs to go through mediaflow.

    Args:
        request: The incoming HTTP request.
        proxy_headers: Headers for proxy requests.
        infohash: The acestream infohash.
        id: Alternative content ID.

    Returns:
        Processed HLS manifest with proxied segment URLs.
    """
    if not settings.enable_acestream:
        raise HTTPException(status_code=503, detail="Acestream support is disabled")
    acestream_manager = _get_acestream_manager()

    if not infohash and not id:
        raise HTTPException(status_code=400, detail="Either 'infohash' or 'id' parameter is required")

    content_id = id
    if not infohash:
        infohash = content_id  # Use content_id as the key if no infohash

    max_retries = 2
    last_error = None

    for attempt in range(max_retries):
        try:
            # Get or create acestream session (don't increment client count for manifest requests)
            session = await acestream_manager.get_or_create_session(infohash, content_id, increment_client=False)

            if not session.playback_url:
                raise HTTPException(status_code=502, detail="Failed to get playback URL from acestream")

            logger.info(f"[acestream_hls_manifest] Using playback URL: {session.playback_url}")

            # Fetch the manifest from acestream with extended timeout for buffering
            async with create_aiohttp_session(session.playback_url, timeout=120) as (http_session, proxy_url):
                response = await http_session.get(
                    session.playback_url,
                    headers=proxy_headers.request,
                    proxy=proxy_url,
                )
                response.raise_for_status()
                manifest_content = await response.text()
                break  # Success, exit retry loop

        except asyncio.TimeoutError:
            last_error = "Timeout fetching manifest"
            if attempt < max_retries - 1:
                logger.warning(f"[acestream_hls_manifest] Timeout fetching manifest, retrying: {infohash[:16]}...")
                await asyncio.sleep(1)  # Brief delay before retry
                continue
            logger.error(f"[acestream_hls_manifest] Timeout after {max_retries} attempts")
            raise HTTPException(status_code=504, detail="Timeout fetching manifest from acestream")

        except aiohttp.ClientResponseError as e:
            last_error = e
            # If we get 403, the session is stale - invalidate and retry
            if e.status == 403 and attempt < max_retries - 1:
                logger.warning(
                    f"[acestream_hls_manifest] Session stale (403), invalidating and retrying: {infohash[:16]}..."
                )
                await acestream_manager.invalidate_session(infohash)
                continue  # Retry with fresh session
            logger.error(f"[acestream_hls_manifest] HTTP error fetching manifest: {e}")
            raise HTTPException(status_code=e.status, detail=f"Failed to fetch manifest: {e}")

        except aiohttp.ClientError as e:
            last_error = e
            logger.error(f"[acestream_hls_manifest] Client error fetching manifest: {e}")
            raise HTTPException(status_code=502, detail=f"Failed to fetch manifest: {e}")

    else:
        # Exhausted retries
        logger.error(f"[acestream_hls_manifest] Failed after {max_retries} attempts: {last_error}")
        raise HTTPException(status_code=502, detail=f"Failed to fetch manifest after retries: {last_error}")

    try:
        # Process the manifest to rewrite URLs
        processor = AcestreamM3U8Processor(
            request=request,
            session=session,
            force_playlist_proxy=True,
        )

        processed_manifest = await processor.process_m3u8(manifest_content, base_url=session.playback_url)

        # Register with HLS prebuffer for segment caching
        if settings.enable_hls_prebuffer:
            segment_urls = processor._extract_segment_urls_from_content(manifest_content, session.playback_url)
            if segment_urls:
                await hls_prebuffer.register_playlist(
                    playlist_url=session.playback_url,
                    segment_urls=segment_urls,
                    headers=proxy_headers.request,
                )

        base_headers = {
            "content-type": "application/vnd.apple.mpegurl",
            "cache-control": "no-cache, no-store, must-revalidate",
            "access-control-allow-origin": "*",
        }
        response_headers = apply_header_manipulation(base_headers, proxy_headers, include_propagate=False)

        return Response(
            content=processed_manifest, media_type="application/vnd.apple.mpegurl", headers=response_headers
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"[acestream_hls_manifest] Error: {e}")
        raise HTTPException(status_code=500, detail=f"Internal error: {e}")


# Map file extensions to MIME types for segments
SEGMENT_MIME_TYPES = {
    "ts": "video/mp2t",
    "m4s": "video/mp4",
    "mp4": "video/mp4",
    "m4a": "audio/mp4",
    "aac": "audio/aac",
}


@acestream_router.get("/acestream/segment.{ext}")
async def acestream_segment_proxy(
    request: Request,
    proxy_headers: Annotated[ProxyRequestHeaders, Depends(get_proxy_headers)],
    ext: str,
    d: str = Query(..., description="Segment URL"),
    infohash: str = Query(None, description="Acestream session infohash"),
    id: str = Query(None, description="Acestream content ID (alternative to infohash)"),
):
    """
    Proxy Acestream HLS segments.

    Uses the HLS prebuffer for segment caching if enabled.

    Args:
        request: The incoming HTTP request.
        proxy_headers: Headers for proxy requests.
        ext: Segment file extension.
        d: The segment URL to proxy.
        infohash: The acestream session infohash (for tracking).
        id: Alternative content ID.

    Returns:
        Proxied segment content.
    """
    if not settings.enable_acestream:
        raise HTTPException(status_code=503, detail="Acestream support is disabled")
    acestream_manager = _get_acestream_manager()

    # Use id or infohash for session lookup
    session_key = id or infohash
    if not session_key:
        raise HTTPException(status_code=400, detail="Either 'infohash' or 'id' parameter is required")

    segment_url = d
    mime_type = SEGMENT_MIME_TYPES.get(ext.lower(), "application/octet-stream")

    logger.debug(f"[acestream_segment_proxy] Request for: {segment_url}")

    # Touch the session to keep it alive - use touch_segment() to indicate active playback
    session = acestream_manager.get_session(session_key)
    if session:
        session.touch_segment()
        logger.debug(f"[acestream_segment_proxy] Touched session: {session_key[:16]}...")

    # Use HLS prebuffer if enabled
    if settings.enable_hls_prebuffer:
        await hls_prebuffer.request_segment(segment_url)
        segment_data = await hls_prebuffer.get_or_download(segment_url, proxy_headers.request)

        if segment_data:
            logger.info(f"[acestream_segment_proxy] Serving from prebuffer ({len(segment_data)} bytes)")
            base_headers = {
                "content-type": mime_type,
                "cache-control": "public, max-age=3600",
                "access-control-allow-origin": "*",
            }
            response_headers = apply_header_manipulation(base_headers, proxy_headers)
            return Response(content=segment_data, media_type=mime_type, headers=response_headers)

        logger.warning("[acestream_segment_proxy] Prebuffer miss, using direct streaming")

    # Fallback to direct streaming
    streamer = await create_streamer(segment_url)
    try:
        await streamer.create_streaming_response(segment_url, proxy_headers.request)

        base_headers = {
            "content-type": mime_type,
            "cache-control": "public, max-age=3600",
            "access-control-allow-origin": "*",
        }
        response_headers = apply_header_manipulation(base_headers, proxy_headers)

        return EnhancedStreamingResponse(
            streamer.stream_content(),
            status_code=streamer.response.status if streamer.response else 200,
            headers=response_headers,
            background=BackgroundTask(streamer.close),
        )
    except Exception as e:
        await streamer.close()
        logger.error(f"[acestream_segment_proxy] Error streaming segment: {e}")
        raise HTTPException(status_code=502, detail=f"Failed to stream segment: {e}")


@acestream_router.head("/acestream/stream")
@acestream_router.get("/acestream/stream")
async def acestream_ts_stream(
    request: Request,
    proxy_headers: Annotated[ProxyRequestHeaders, Depends(get_proxy_headers)],
    infohash: str = Query(None, description="Acestream infohash"),
    id: str = Query(None, description="Acestream content ID (alternative to infohash)"),
    transcode: bool = Query(False, description="Transcode to browser-compatible fMP4"),
    start: float | None = Query(None, description="Seek start time in seconds (transcode mode)"),
):
    """
    Proxy Acestream MPEG-TS stream with fan-out to multiple clients.

    Creates or reuses an acestream session and streams MPEG-TS content.
    Multiple clients can share the same upstream connection.

    When transcode=true, the MPEG-TS stream is transcoded on-the-fly to
    browser-compatible fMP4 (H.264 + AAC).

    Args:
        request: The incoming HTTP request.
        proxy_headers: Headers for proxy requests.
        infohash: The acestream infohash.
        id: Alternative content ID.
        transcode: Transcode to browser-compatible format.
        start: Seek start time in seconds (transcode mode).

    Returns:
        MPEG-TS stream (or fMP4 if transcode=true).
    """
    if not settings.enable_acestream:
        raise HTTPException(status_code=503, detail="Acestream support is disabled")
    acestream_manager = _get_acestream_manager()

    if not infohash and not id:
        raise HTTPException(status_code=400, detail="Either 'infohash' or 'id' parameter is required")

    content_id = id
    if not infohash:
        infohash = content_id

    try:
        # Get or create acestream session
        # For MPEG-TS, we need to use getstream endpoint
        base_url = f"http://{settings.acestream_host}:{settings.acestream_port}"
        session = await acestream_manager.get_or_create_session(infohash, content_id)

        if not session.playback_url:
            raise HTTPException(status_code=502, detail="Failed to get playback URL from acestream")

        # For MPEG-TS streaming, we need to convert HLS playback URL to getstream
        # Acestream uses different parameter names:
        # - 'id' for content IDs
        # - 'infohash' for magnet link hashes (40-char hex)
        if content_id:
            ts_url = f"{base_url}/ace/getstream?id={content_id}&pid={session.pid}"
        else:
            ts_url = f"{base_url}/ace/getstream?infohash={infohash}&pid={session.pid}"

        logger.info(f"[acestream_ts_stream] Streaming from: {ts_url}")

        if transcode:
            if not settings.enable_transcode:
                await acestream_manager.release_session(infohash)
                raise HTTPException(status_code=503, detail="Transcoding support is disabled")
            # Acestream provides a live MPEG-TS stream that does NOT support
            # HTTP Range requests and is not seekable.  Use an ffmpeg subprocess
            # to remux video (passthrough) and transcode audio (AC3→AAC) to
            # fragmented MP4.  The subprocess approach isolates native FFmpeg
            # crashes from the Python server process.

            if request.method == "HEAD":
                await acestream_manager.release_session(infohash)
                return Response(
                    status_code=200,
                    headers={
                        "access-control-allow-origin": "*",
                        "cache-control": "no-cache, no-store",
                        "content-type": "video/mp4",
                        "content-disposition": "inline",
                    },
                )

            async def _acestream_ts_source():
                """Single-connection async byte generator for the live TS stream."""
                try:
                    async with create_aiohttp_session(ts_url) as (session, proxy_url):
                        async with session.get(
                            ts_url,
                            proxy=proxy_url,
                            allow_redirects=True,
                        ) as resp:
                            resp.raise_for_status()
                            async for chunk in resp.content.iter_any():
                                yield chunk
                except asyncio.CancelledError:
                    logger.debug("[acestream_ts_stream] Transcode source cancelled")
                except GeneratorExit:
                    logger.debug("[acestream_ts_stream] Transcode source closed")

            # Use our custom PyAV pipeline with forced video re-encoding
            # (live MPEG-TS sources often have corrupt H.264 bitstreams
            # that browsers reject; re-encoding produces a clean stream).
            stream_transcode_universal = _load_transcode_pipeline()
            content = stream_transcode_universal(
                _acestream_ts_source(),
                force_video_reencode=True,
            )

            async def release_transcode_session():
                await acestream_manager.release_session(infohash)

            return EnhancedStreamingResponse(
                content=content,
                media_type="video/mp4",
                headers={
                    "access-control-allow-origin": "*",
                    "cache-control": "no-cache, no-store",
                    "content-disposition": "inline",
                },
                background=BackgroundTask(release_transcode_session),
            )

        streamer = await create_streamer(ts_url)
        try:
            await streamer.create_streaming_response(ts_url, proxy_headers.request)

            base_headers = {
                "content-type": "video/mp2t",
                "transfer-encoding": "chunked",
                "cache-control": "no-cache, no-store, must-revalidate",
                "access-control-allow-origin": "*",
            }
            response_headers = apply_header_manipulation(base_headers, proxy_headers)

            async def release_on_complete():
                """Release session when streaming completes."""
                await streamer.close()
                await acestream_manager.release_session(infohash)

            return EnhancedStreamingResponse(
                streamer.stream_content(),
                status_code=streamer.response.status if streamer.response else 200,
                headers=response_headers,
                background=BackgroundTask(release_on_complete),
            )

        except Exception:
            await streamer.close()
            await acestream_manager.release_session(infohash)
            raise

    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"[acestream_ts_stream] Error: {e}")
        await acestream_manager.release_session(infohash)
        raise HTTPException(status_code=500, detail=f"Internal error: {e}")


@acestream_router.get("/acestream/status")
async def acestream_status(
    infohash: str = Query(None, description="Acestream infohash to check"),
):
    """
    Get acestream session status.

    Args:
        infohash: Optional infohash to check specific session.

    Returns:
        Session status information.
    """
    if not settings.enable_acestream:
        raise HTTPException(status_code=503, detail="Acestream support is disabled")
    acestream_manager = _get_acestream_manager()

    if infohash:
        session = acestream_manager.get_session(infohash)
        if session:
            return {
                "status": "active",
                "infohash": session.infohash,
                "client_count": session.client_count,
                "is_live": session.is_live,
                "created_at": session.created_at,
                "last_access": session.last_access,
            }
        else:
            return {"status": "not_found", "infohash": infohash}

    # Return all active sessions
    sessions = acestream_manager.get_active_sessions()
    return {
        "enabled": settings.enable_acestream,
        "active_sessions": len(sessions),
        "sessions": [
            {
                "infohash": s.infohash,
                "client_count": s.client_count,
                "is_live": s.is_live,
            }
            for s in sessions.values()
        ],
    }
