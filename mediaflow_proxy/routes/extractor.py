import copy
import logging
from typing import Annotated

from fastapi import APIRouter, Query, HTTPException, Request, Depends, BackgroundTasks
from fastapi.responses import RedirectResponse

from mediaflow_proxy.extractors.base import ExtractorError
from mediaflow_proxy.extractors.factory import ExtractorFactory
from mediaflow_proxy.schemas import ExtractorURLParams
from mediaflow_proxy.utils.cache_utils import (
    get_cached_extractor_result,
    set_cache_extractor_result,
)
from mediaflow_proxy.utils.http_utils import (
    DownloadError,
    encode_mediaflow_proxy_url,
    get_original_scheme,
    ProxyRequestHeaders,
    get_proxy_headers,
)
from mediaflow_proxy.utils.base64_utils import process_potential_base64_url
from mediaflow_proxy.utils import redis_utils

extractor_router = APIRouter()
logger = logging.getLogger(__name__)

# Cooldown duration for background refresh (2 minutes)
_REFRESH_COOLDOWN = 120

# Hosts where background refresh should be DISABLED
# These hosts generate unique CDN URLs per extraction - refreshing invalidates existing streams!
# When a new URL is extracted, the old URL becomes invalid and causes 509 errors.
_NO_BACKGROUND_REFRESH_HOSTS = frozenset(
    {
        "Vidoza",
        # Add other hosts here that generate unique per-extraction URLs
    }
)


async def refresh_extractor_cache(
    cache_key: str, extractor_params: ExtractorURLParams, proxy_headers: ProxyRequestHeaders
):
    """Asynchronously refreshes the extractor cache in the background."""
    try:
        logger.info(f"Background cache refresh started for key: {cache_key}")
        extractor = ExtractorFactory.get_extractor(extractor_params.host, proxy_headers.request)
        response = await extractor.extract(extractor_params.destination, **extractor_params.extra_params)
        await set_cache_extractor_result(cache_key, response)
        logger.info(f"Background cache refresh completed for key: {cache_key}")
    except Exception as e:
        logger.error(f"Background cache refresh failed for key {cache_key}: {e}")


# Extension to content-type mapping for player compatibility
# When a player requests /extractor/video.m3u8, it can detect HLS from the URL
EXTRACTOR_EXT_CONTENT_TYPES = {
    "m3u8": "application/vnd.apple.mpegurl",
    "m3u": "application/vnd.apple.mpegurl",
    "mp4": "video/mp4",
    "mkv": "video/x-matroska",
    "ts": "video/mp2t",
    "avi": "video/x-msvideo",
    "webm": "video/webm",
}


async def _extract_url_impl(
    extractor_params: ExtractorURLParams,
    request: Request,
    background_tasks: BackgroundTasks,
    proxy_headers: ProxyRequestHeaders,
    ext: str | None = None,
):
    """
    Core extraction logic shared by all extractor endpoints.

    Args:
        extractor_params: Extraction parameters from query string
        request: FastAPI request object
        background_tasks: Background task manager
        proxy_headers: Proxy headers from request
        ext: Optional file extension hint for player compatibility (e.g., "m3u8", "mp4")
    """
    try:
        # Process potential base64 encoded destination URL
        processed_destination = process_potential_base64_url(extractor_params.destination)
        extractor_params.destination = processed_destination

        cache_key = f"{extractor_params.host}_{extractor_params.model_dump_json()}"

        # Extractor results are resolved via the pod's outgoing IP and may not
        # be valid when served from a different pod.  Namespace the cache and
        # all associated coordination keys so each pod operates on its own
        # partition of the shared Redis.  On single-instance deployments (no
        # CACHE_NAMESPACE env var) make_instance_key() is a no-op.
        instance_cache_key = redis_utils.make_instance_key(cache_key)

        response = await get_cached_extractor_result(instance_cache_key)

        if response:
            logger.info(f"Serving from cache for key: {instance_cache_key}")
            # Schedule a background refresh, but only if:
            # 1. The host is NOT in the no-refresh list (hosts with unique per-extraction URLs)
            # 2. The cooldown has elapsed (prevents flooding upstream)
            #
            # WARNING: For hosts like Vidoza, background refresh is DANGEROUS!
            # Each extraction generates a unique CDN URL. Refreshing invalidates the
            # old URL, causing 509 errors for clients still using it.
            if extractor_params.host not in _NO_BACKGROUND_REFRESH_HOSTS:
                cooldown_key = f"extractor_refresh:{instance_cache_key}"
                if await redis_utils.check_and_set_cooldown(cooldown_key, _REFRESH_COOLDOWN):
                    background_tasks.add_task(
                        refresh_extractor_cache, instance_cache_key, extractor_params, proxy_headers
                    )
            else:
                logger.debug(f"Skipping background refresh for {extractor_params.host} (unique CDN URLs)")
        else:
            # Use Redis-based in-flight tracking for cross-worker deduplication.
            # If another worker is already extracting, wait for them to finish.
            inflight_key = f"extractor:{instance_cache_key}"

            if not await redis_utils.mark_inflight(inflight_key, ttl=60):
                # Another worker is extracting - wait for them to finish and check cache
                logger.info(f"Waiting for in-flight extraction (cross-worker) for key: {instance_cache_key}")
                if await redis_utils.wait_for_completion(inflight_key, timeout=30.0):
                    # Extraction completed, check cache
                    response = await get_cached_extractor_result(instance_cache_key)
                    if response:
                        logger.info(f"Serving from cache (after wait) for key: {instance_cache_key}")

            if response is None:
                # We either marked it as in-flight (first) or waited and still no cache hit.
                # Use Redis lock to ensure only one worker extracts at a time.
                if await redis_utils.acquire_lock(f"extractor_lock:{instance_cache_key}", ttl=30, timeout=30.0):
                    try:
                        # Re-check cache after acquiring lock - another worker may have populated it
                        response = await get_cached_extractor_result(instance_cache_key)
                        if response:
                            logger.info(f"Serving from cache (after lock) for key: {instance_cache_key}")
                        else:
                            logger.info(f"Cache miss for key: {instance_cache_key}. Fetching fresh data.")
                            try:
                                extractor = ExtractorFactory.get_extractor(extractor_params.host, proxy_headers.request)
                                response = await extractor.extract(
                                    extractor_params.destination, **extractor_params.extra_params
                                )
                                await set_cache_extractor_result(instance_cache_key, response)
                            except Exception:
                                raise
                    finally:
                        await redis_utils.release_lock(f"extractor_lock:{instance_cache_key}")
                        await redis_utils.clear_inflight(inflight_key)
                else:
                    # Lock timeout - try to serve from cache anyway
                    response = await get_cached_extractor_result(instance_cache_key)
                    if not response:
                        raise HTTPException(status_code=503, detail="Extraction in progress, please retry")

        # Deep copy so each concurrent request gets its own dict to mutate
        # (pop mediaflow_endpoint, update request_headers, etc.)
        response = copy.deepcopy(response)

        # Ensure the latest request headers are used, even with cached data
        if "request_headers" not in response:
            response["request_headers"] = {}
        response["request_headers"].update(proxy_headers.request)
        response["mediaflow_proxy_url"] = str(
            request.url_for(response.pop("mediaflow_endpoint")).replace(scheme=get_original_scheme(request))
        )
        response["query_params"] = response.get("query_params", {})
        # Add API password to query params
        response["query_params"]["api_password"] = request.query_params.get("api_password")

        if "max_res" in request.query_params:
            response["query_params"]["max_res"] = request.query_params.get("max_res")

        if "no_proxy" in request.query_params:
            response["query_params"]["no_proxy"] = request.query_params.get("no_proxy")

        if extractor_params.redirect_stream:
            stream_url = encode_mediaflow_proxy_url(
                **response,
                response_headers=proxy_headers.response,
            )
            return RedirectResponse(url=stream_url, status_code=302)

        return response

    except DownloadError as e:
        logger.error(f"Extraction failed: {str(e)}")
        raise HTTPException(status_code=e.status_code, detail=str(e))
    except ExtractorError as e:
        logger.error(f"Extraction failed: {str(e)}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.exception(f"Extraction failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Extraction failed: {str(e)}")


@extractor_router.head("/video")
@extractor_router.get("/video")
async def extract_url(
    extractor_params: Annotated[ExtractorURLParams, Query()],
    request: Request,
    background_tasks: BackgroundTasks,
    proxy_headers: Annotated[ProxyRequestHeaders, Depends(get_proxy_headers)],
):
    """
    Extract clean links from various video hosting services.

    This is the base endpoint without extension. For better player compatibility
    (especially ExoPlayer), use the extension variants:
    - /extractor/video.m3u8 for HLS streams
    - /extractor/video.mp4 for MP4 streams
    """
    return await _extract_url_impl(extractor_params, request, background_tasks, proxy_headers)


@extractor_router.head("/video.{ext}")
@extractor_router.get("/video.{ext}")
async def extract_url_with_extension(
    ext: str,
    extractor_params: Annotated[ExtractorURLParams, Query()],
    request: Request,
    background_tasks: BackgroundTasks,
    proxy_headers: Annotated[ProxyRequestHeaders, Depends(get_proxy_headers)],
):
    """
    Extract clean links with file extension hint for player compatibility.

    The extension in the URL helps players like ExoPlayer detect the content type
    without needing to follow redirects or inspect headers. This is especially
    important for HLS streams where ExoPlayer needs .m3u8 in the URL to use
    HlsMediaSource instead of ProgressiveMediaSource.

    Supported extensions:
    - .m3u8, .m3u - HLS playlists (application/vnd.apple.mpegurl)
    - .mp4 - MP4 video (video/mp4)
    - .mkv - Matroska video (video/x-matroska)
    - .ts - MPEG-TS (video/mp2t)
    - .avi - AVI video (video/x-msvideo)
    - .webm - WebM video (video/webm)

    Example:
        /extractor/video.m3u8?host=TurboVidPlay&d=...&redirect_stream=true

    This URL clearly indicates HLS content, making ExoPlayer use the correct source.
    """
    ext_lower = ext.lower()
    if ext_lower not in EXTRACTOR_EXT_CONTENT_TYPES:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported extension: .{ext}. Supported: {', '.join('.' + e for e in EXTRACTOR_EXT_CONTENT_TYPES.keys())}",
        )

    return await _extract_url_impl(extractor_params, request, background_tasks, proxy_headers, ext=ext_lower)
