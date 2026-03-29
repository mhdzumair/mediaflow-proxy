"""
Cache utilities for mediaflow-proxy.

All caching is now done via Redis for cross-worker sharing.
See redis_utils.py for the underlying Redis operations.
"""

import logging
from typing import Optional

from mediaflow_proxy.utils.http_utils import download_file_with_retry, DownloadError
from mediaflow_proxy.utils.mpd_utils import parse_mpd, parse_mpd_dict
from mediaflow_proxy.utils import redis_utils

logger = logging.getLogger(__name__)


# =============================================================================
# Init Segment Cache
# =============================================================================


async def get_cached_init_segment(
    init_url: str,
    headers: dict,
    cache_token: str | None = None,
    ttl: Optional[int] = None,
    byte_range: str | None = None,
) -> Optional[bytes]:
    """Get initialization segment from cache or download it.

    cache_token allows differentiating entries that share the same init_url but
    rely on different DRM keys or initialization payloads (e.g. key rotation).

    ttl overrides the default cache TTL; pass a value <= 0 to skip caching entirely.

    byte_range specifies a byte range for SegmentBase MPDs (e.g., '0-11568').
    """
    use_cache = ttl is None or ttl > 0
    # Include byte_range in cache key for SegmentBase
    cache_key = f"{init_url}|{cache_token}|{byte_range}" if cache_token or byte_range else init_url

    if use_cache:
        cached_data = await redis_utils.get_cached_init_segment(cache_key)
        if cached_data is not None:
            return cached_data

    try:
        # Add Range header if byte_range is specified (for SegmentBase MPDs)
        request_headers = dict(headers)
        if byte_range:
            request_headers["Range"] = f"bytes={byte_range}"

        init_content = await download_file_with_retry(init_url, request_headers)
        if init_content and use_cache:
            cache_ttl = ttl if ttl is not None else redis_utils.DEFAULT_INIT_CACHE_TTL
            await redis_utils.set_cached_init_segment(cache_key, init_content, ttl=cache_ttl)
        return init_content
    except Exception as e:
        logger.error(f"Error downloading init segment: {e}")
        return None


# =============================================================================
# MPD Cache
# =============================================================================


async def get_cached_mpd(
    mpd_url: str,
    headers: dict,
    parse_drm: bool,
    parse_segment_profile_id: Optional[str] = None,
) -> dict:
    """Get MPD from cache or download and parse it."""
    # Try cache first
    cached_data = await redis_utils.get_cached_mpd(mpd_url)
    if cached_data is not None:
        try:
            return parse_mpd_dict(cached_data, mpd_url, parse_drm, parse_segment_profile_id)
        except Exception:
            # Invalid cached data, will re-download
            pass

    # Download and parse if not cached
    try:
        mpd_content = await download_file_with_retry(mpd_url, headers)
        mpd_dict = parse_mpd(mpd_content)
        parsed_dict = parse_mpd_dict(mpd_dict, mpd_url, parse_drm, parse_segment_profile_id)

        # Cache the original MPD dict with TTL from minimumUpdatePeriod
        cache_ttl = parsed_dict.get("minimumUpdatePeriod") or redis_utils.DEFAULT_MPD_CACHE_TTL
        await redis_utils.set_cached_mpd(mpd_url, mpd_dict, ttl=cache_ttl)
        return parsed_dict
    except DownloadError as error:
        logger.error(f"Error downloading MPD: {error}")
        raise error
    except Exception as error:
        logger.exception(f"Error processing MPD: {error}")
        raise error


# =============================================================================
# Extractor Cache
# =============================================================================


async def get_cached_extractor_result(key: str) -> Optional[dict]:
    """Get extractor result from cache."""
    return await redis_utils.get_cached_extractor(key)


async def set_cache_extractor_result(key: str, result: dict) -> bool:
    """Cache extractor result."""
    try:
        await redis_utils.set_cached_extractor(key, result)
        return True
    except Exception as e:
        logger.error(f"Error caching extractor result: {e}")
        return False


# =============================================================================
# Processed Init Segment Cache
# =============================================================================


async def get_cached_processed_init(
    init_url: str,
    key_id: str,
) -> Optional[bytes]:
    """Get processed (DRM-stripped) init segment from cache.

    Args:
        init_url: URL of the init segment
        key_id: DRM key ID used for processing

    Returns:
        Processed init segment bytes if cached, None otherwise
    """
    cache_key = f"processed|{init_url}|{key_id}"
    return await redis_utils.get_cached_processed_init(cache_key)


async def set_cached_processed_init(
    init_url: str,
    key_id: str,
    processed_content: bytes,
    ttl: Optional[int] = None,
) -> bool:
    """Cache processed (DRM-stripped) init segment.

    Args:
        init_url: URL of the init segment
        key_id: DRM key ID used for processing
        processed_content: The processed init segment bytes
        ttl: Optional TTL override

    Returns:
        True if cached successfully
    """
    cache_key = f"processed|{init_url}|{key_id}"
    try:
        cache_ttl = ttl if ttl is not None else redis_utils.DEFAULT_PROCESSED_INIT_TTL
        await redis_utils.set_cached_processed_init(cache_key, processed_content, ttl=cache_ttl)
        return True
    except Exception as e:
        logger.error(f"Error caching processed init segment: {e}")
        return False


# =============================================================================
# Processed Segment Cache (decrypted/remuxed segments)
# =============================================================================


async def get_cached_processed_segment(
    segment_url: str,
    key_id: str = None,
    remux: bool = False,
) -> Optional[bytes]:
    """Get processed (decrypted/remuxed) segment from cache.

    Args:
        segment_url: URL of the segment
        key_id: DRM key ID if decrypted
        remux: Whether the segment was remuxed to TS

    Returns:
        Processed segment bytes if cached, None otherwise
    """
    cache_key = f"proc|{segment_url}|{key_id or ''}|{remux}"
    return await redis_utils.get_cached_segment(cache_key)


async def set_cached_processed_segment(
    segment_url: str,
    content: bytes,
    key_id: str = None,
    remux: bool = False,
    ttl: int = 60,
) -> bool:
    """Cache processed (decrypted/remuxed) segment.

    Args:
        segment_url: URL of the segment
        content: Processed segment bytes
        key_id: DRM key ID if decrypted
        remux: Whether the segment was remuxed to TS
        ttl: Time to live in seconds

    Returns:
        True if cached successfully
    """
    cache_key = f"proc|{segment_url}|{key_id or ''}|{remux}"
    try:
        await redis_utils.set_cached_segment(cache_key, content, ttl=ttl)
        return True
    except Exception as e:
        logger.error(f"Error caching processed segment: {e}")
        return False


# =============================================================================
# Segment Cache
# =============================================================================


async def get_cached_segment(segment_url: str) -> Optional[bytes]:
    """Get media segment from prebuffer cache.

    Args:
        segment_url: URL of the segment

    Returns:
        Segment bytes if cached, None otherwise
    """
    return await redis_utils.get_cached_segment(segment_url)


async def set_cached_segment(segment_url: str, content: bytes, ttl: int = 60) -> bool:
    """Cache media segment with configurable TTL.

    Args:
        segment_url: URL of the segment
        content: Segment bytes
        ttl: Time to live in seconds (default 60s, configurable via dash_segment_cache_ttl)

    Returns:
        True if cached successfully
    """
    try:
        await redis_utils.set_cached_segment(segment_url, content, ttl=ttl)
        return True
    except Exception as e:
        logger.error(f"Error caching segment: {e}")
        return False
