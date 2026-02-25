"""
Helper functions for automatic stream extraction in proxy routes.

This module provides caching and extraction helpers for DLHD/DaddyLive
and Sportsonline/Sportzonline streams that are auto-detected in proxy routes.
"""

import logging
import re
import time
from urllib.parse import urlparse

from fastapi import Request, HTTPException

from mediaflow_proxy.extractors.base import ExtractorError
from mediaflow_proxy.extractors.factory import ExtractorFactory
from mediaflow_proxy.utils.http_utils import ProxyRequestHeaders, DownloadError


logger = logging.getLogger(__name__)

# DLHD extraction cache: {original_url: {"data": extraction_result, "timestamp": time.time()}}
_dlhd_extraction_cache: dict = {}
_dlhd_cache_duration = 600  # 10 minutes in seconds

# Sportsonline extraction cache
_sportsonline_extraction_cache: dict = {}
_sportsonline_cache_duration = 600  # 10 minutes in seconds


async def check_and_extract_dlhd_stream(
    request: Request, destination: str, proxy_headers: ProxyRequestHeaders, force_refresh: bool = False
) -> dict | None:
    """
    Check if destination contains DLHD/DaddyLive patterns and extract stream directly.
    Uses caching to avoid repeated extractions (10 minute cache).

    Args:
        request (Request): The incoming HTTP request.
        destination (str): The destination URL to check.
        proxy_headers (ProxyRequestHeaders): The headers to include in the request.
        force_refresh (bool): Force re-extraction even if cached data exists.

    Returns:
        dict | None: Extracted stream data if DLHD link detected, None otherwise.
    """
    # Check for common DLHD/DaddyLive patterns in the URL
    # This includes stream-XXX pattern and domain names like dlhd.dad or daddylive.sx
    is_dlhd_link = (
        re.search(r"stream-\d+", destination)
        or "dlhd.dad" in urlparse(destination).netloc
        or "daddylive.sx" in urlparse(destination).netloc
    )

    if not is_dlhd_link:
        return None

    logger.info(f"DLHD link detected: {destination}")

    # Check cache first (unless force_refresh is True)
    current_time = time.time()
    if not force_refresh and destination in _dlhd_extraction_cache:
        cached_entry = _dlhd_extraction_cache[destination]
        cache_age = current_time - cached_entry["timestamp"]

        if cache_age < _dlhd_cache_duration:
            logger.info(f"Using cached DLHD data (age: {cache_age:.1f}s)")
            return cached_entry["data"]
        else:
            logger.info(f"DLHD cache expired (age: {cache_age:.1f}s), re-extracting...")
            del _dlhd_extraction_cache[destination]

    # Extract stream data
    try:
        logger.info(f"Extracting DLHD stream data from: {destination}")
        extractor = ExtractorFactory.get_extractor("DLHD", proxy_headers.request)
        result = await extractor.extract(destination)

        logger.info(f"DLHD extraction successful. Stream URL: {result.get('destination_url')}")

        # Handle dlhd_key_params - encode them for URL passing
        if "dlhd_key_params" in result:
            key_params = result.pop("dlhd_key_params")
            # Add key params as special query parameters for key URL handling
            result["dlhd_channel_salt"] = key_params.get("channel_salt", "")
            result["dlhd_auth_token"] = key_params.get("auth_token", "")
            result["dlhd_iframe_url"] = key_params.get("iframe_url", "")
            logger.info("DLHD key params extracted for dynamic header computation")

        # Cache a copy of result to prevent downstream mutations from corrupting the cache
        _dlhd_extraction_cache[destination] = {"data": result.copy(), "timestamp": current_time}
        logger.info(f"DLHD data cached for {_dlhd_cache_duration}s")

        return result

    except (ExtractorError, DownloadError) as e:
        logger.error(f"DLHD extraction failed: {str(e)}")
        raise HTTPException(status_code=400, detail=f"DLHD extraction failed: {str(e)}")
    except Exception as e:
        logger.exception(f"Unexpected error during DLHD extraction: {str(e)}")
        raise HTTPException(status_code=500, detail=f"DLHD extraction failed: {str(e)}")


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
    parsed_netloc = urlparse(destination).netloc
    is_sportsonline_link = "sportzonline." in parsed_netloc or "sportsonline." in parsed_netloc

    if not is_sportsonline_link:
        return None

    logger.info(f"Sportsonline link detected: {destination}")

    current_time = time.time()
    if not force_refresh and destination in _sportsonline_extraction_cache:
        cached_entry = _sportsonline_extraction_cache[destination]
        if current_time - cached_entry["timestamp"] < _sportsonline_cache_duration:
            logger.info(f"Using cached Sportsonline data (age: {current_time - cached_entry['timestamp']:.1f}s)")
            return cached_entry["data"]
        else:
            logger.info("Sportsonline cache expired, re-extracting...")
            del _sportsonline_extraction_cache[destination]

    try:
        logger.info(f"Extracting Sportsonline stream data from: {destination}")
        extractor = ExtractorFactory.get_extractor("Sportsonline", proxy_headers.request)
        result = await extractor.extract(destination)
        logger.info(f"Sportsonline extraction successful. Stream URL: {result.get('destination_url')}")
        _sportsonline_extraction_cache[destination] = {"data": result, "timestamp": current_time}
        logger.info(f"Sportsonline data cached for {_sportsonline_cache_duration}s")
        return result
    except (ExtractorError, DownloadError) as e:
        logger.error(f"Sportsonline extraction failed: {str(e)}")
        raise HTTPException(status_code=400, detail=f"Sportsonline extraction failed: {str(e)}")
    except Exception as e:
        logger.exception(f"Unexpected error during Sportsonline extraction: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Sportsonline extraction failed: {str(e)}")
