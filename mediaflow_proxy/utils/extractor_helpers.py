"""
Helper functions for automatic stream extraction in proxy routes.

This module provides caching and extraction helpers for Sportsonline/Sportzonline
streams that are auto-detected in proxy routes.
"""

import copy
import logging
import time
from urllib.parse import urlparse

from fastapi import Request, HTTPException

from mediaflow_proxy.extractors.base import ExtractorError
from mediaflow_proxy.extractors.factory import ExtractorFactory
from mediaflow_proxy.utils.http_utils import ProxyRequestHeaders, DownloadError


logger = logging.getLogger(__name__)

# Sportsonline extraction cache
_sportsonline_extraction_cache: dict = {}
_sportsonline_cache_duration = 600  # 10 minutes in seconds


async def check_and_extract_sportsonline_stream(
    request: Request, destination: str, proxy_headers: ProxyRequestHeaders, force_refresh: bool = False
) -> dict | None:
    """
    Check if destination contains Sportsonline/Sportzonline patterns and extract stream directly.
    Uses caching to avoid repeated extractions (10 minute cache).

    Args:
        request (Request): The incoming HTTP request.
        destination (str): The destination URL to check.
        proxy_headers (ProxyRequestHeaders): The headers to include in the request.
        force_refresh (bool): Force re-extraction even if cached data exists.

    Returns:
        dict | None: Extracted stream data if Sportsonline link detected, None otherwise.
    """
    hostname = (urlparse(destination).hostname or "").lower()
    hostname_labels = {part for part in hostname.split(".") if part}
    is_sportsonline_link = bool(hostname_labels & {"sportzonline", "sportsonline", "sportzsonline"})

    if not is_sportsonline_link:
        return None

    logger.info(f"Sportsonline link detected: {destination}")

    current_time = time.time()
    if not force_refresh and destination in _sportsonline_extraction_cache:
        cached_entry = _sportsonline_extraction_cache[destination]
        if current_time - cached_entry["timestamp"] < _sportsonline_cache_duration:
            logger.info(f"Using cached Sportsonline data (age: {current_time - cached_entry['timestamp']:.1f}s)")
            return copy.deepcopy(cached_entry["data"])
        else:
            logger.info("Sportsonline cache expired, re-extracting...")
            del _sportsonline_extraction_cache[destination]

    try:
        logger.info(f"Extracting Sportsonline stream data from: {destination}")
        extractor = ExtractorFactory.get_extractor("Sportsonline", proxy_headers.request)
        result = await extractor.extract(destination)
        logger.info(f"Sportsonline extraction successful. Stream URL: {result.get('destination_url')}")
        # Cache a copy of result to prevent downstream mutations from corrupting the cache
        _sportsonline_extraction_cache[destination] = {"data": copy.deepcopy(result), "timestamp": current_time}
        logger.info(f"Sportsonline data cached for {_sportsonline_cache_duration}s")
        return result
    except (ExtractorError, DownloadError) as e:
        logger.error(f"Sportsonline extraction failed: {str(e)}")
        raise HTTPException(status_code=400, detail=f"Sportsonline extraction failed: {str(e)}")
    except Exception as e:
        logger.exception(f"Unexpected error during Sportsonline extraction: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Sportsonline extraction failed: {str(e)}")
