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


@extractor_router.head("/video")
@extractor_router.get("/video")
async def extract_url(
    extractor_params: Annotated[ExtractorURLParams, Query()],
    request: Request,
    background_tasks: BackgroundTasks,
    proxy_headers: Annotated[ProxyRequestHeaders, Depends(get_proxy_headers)],
):
    """Extract clean links from various video hosting services."""
    try:
        # Process potential base64 encoded destination URL
        processed_destination = process_potential_base64_url(extractor_params.destination)
        extractor_params.destination = processed_destination

        cache_key = f"{extractor_params.host}_{extractor_params.model_dump_json()}"
        response = await get_cached_extractor_result(cache_key)

        if response:
            logger.info(f"Serving from cache for key: {cache_key}")
            # Schedule a background refresh, but only if cooldown has elapsed.
            # This prevents flooding upstream when many requests arrive at once
            # (e.g., ExoPlayer sends HEAD + multiple GETs within seconds).
            # Using Redis-based cooldown for cross-worker coordination.
            cooldown_key = f"extractor_refresh:{cache_key}"
            if await redis_utils.check_and_set_cooldown(cooldown_key, _REFRESH_COOLDOWN):
                background_tasks.add_task(refresh_extractor_cache, cache_key, extractor_params, proxy_headers)
        else:
            # Use Redis-based in-flight tracking for cross-worker deduplication.
            # If another worker is already extracting, wait for them to finish.
            inflight_key = f"extractor:{cache_key}"

            if not await redis_utils.mark_inflight(inflight_key, ttl=60):
                # Another worker is extracting - wait for them to finish and check cache
                logger.info(f"Waiting for in-flight extraction (cross-worker) for key: {cache_key}")
                if await redis_utils.wait_for_completion(inflight_key, timeout=30.0):
                    # Extraction completed, check cache
                    response = await get_cached_extractor_result(cache_key)
                    if response:
                        logger.info(f"Serving from cache (after wait) for key: {cache_key}")

            if response is None:
                # We either marked it as in-flight (first) or waited and still no cache hit.
                # Use Redis lock to ensure only one worker extracts at a time.
                if await redis_utils.acquire_lock(f"extractor_lock:{cache_key}", ttl=30, timeout=30.0):
                    try:
                        # Re-check cache after acquiring lock - another worker may have populated it
                        response = await get_cached_extractor_result(cache_key)
                        if response:
                            logger.info(f"Serving from cache (after lock) for key: {cache_key}")
                        else:
                            logger.info(f"Cache miss for key: {cache_key}. Fetching fresh data.")
                            try:
                                extractor = ExtractorFactory.get_extractor(
                                    extractor_params.host, proxy_headers.request
                                )
                                response = await extractor.extract(
                                    extractor_params.destination, **extractor_params.extra_params
                                )
                                await set_cache_extractor_result(cache_key, response)
                            except Exception:
                                raise
                    finally:
                        await redis_utils.release_lock(f"extractor_lock:{cache_key}")
                        await redis_utils.clear_inflight(inflight_key)
                else:
                    # Lock timeout - try to serve from cache anyway
                    response = await get_cached_extractor_result(cache_key)
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
