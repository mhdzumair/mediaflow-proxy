import datetime
import logging

from cachetools import TTLCache

from .http_utils import download_file_with_retry
from .mpd_utils import parse_mpd, parse_mpd_dict

logger = logging.getLogger(__name__)

# cache dictionary
mpd_cache = TTLCache(maxsize=100, ttl=300)  # 5 minutes default TTL
init_segment_cache = TTLCache(maxsize=100, ttl=3600)  # 1 hour default TTL


async def get_cached_mpd(
    mpd_url: str,
    headers: dict,
    parse_drm: bool,
    parse_segment_profile_id: str | None = None,
    verify_ssl: bool = True,
    use_request_proxy: bool = True,
) -> dict:
    """
    Retrieves and caches the MPD manifest, parsing it if not already cached.

    Args:
        mpd_url (str): The URL of the MPD manifest.
        headers (dict): The headers to include in the request.
        parse_drm (bool): Whether to parse DRM information.
        parse_segment_profile_id (str, optional): The profile ID to parse segments for. Defaults to None.
        verify_ssl (bool, optional): Whether to verify the SSL certificate of the destination. Defaults to True.
        use_request_proxy (bool, optional): Whether to use the proxy configuration from the user's MediaFlow config. Defaults to True.

    Returns:
        dict: The parsed MPD manifest data.
    """
    current_time = datetime.datetime.now(datetime.UTC)
    if mpd_url in mpd_cache and mpd_cache[mpd_url]["expires"] > current_time:
        logger.info(f"Using cached MPD for {mpd_url}")
        return parse_mpd_dict(mpd_cache[mpd_url]["mpd"], mpd_url, parse_drm, parse_segment_profile_id)

    mpd_dict = parse_mpd(
        await download_file_with_retry(mpd_url, headers, verify_ssl=verify_ssl, use_request_proxy=use_request_proxy)
    )
    parsed_mpd_dict = parse_mpd_dict(mpd_dict, mpd_url, parse_drm, parse_segment_profile_id)
    current_time = datetime.datetime.now(datetime.UTC)
    expiration_time = current_time + datetime.timedelta(seconds=parsed_mpd_dict.get("minimumUpdatePeriod", 300))
    mpd_cache[mpd_url] = {"mpd": mpd_dict, "expires": expiration_time}
    return parsed_mpd_dict


async def get_cached_init_segment(
    init_url: str, headers: dict, verify_ssl: bool = True, use_request_proxy: bool = True
) -> bytes:
    """
    Retrieves and caches the initialization segment.

    Args:
        init_url (str): The URL of the initialization segment.
        headers (dict): The headers to include in the request.
        verify_ssl (bool, optional): Whether to verify the SSL certificate of the destination. Defaults to True.
        use_request_proxy (bool, optional): Whether to use the proxy configuration from the user's MediaFlow config. Defaults to True.

    Returns:
        bytes: The initialization segment content.
    """
    if init_url not in init_segment_cache:
        init_content = await download_file_with_retry(
            init_url, headers, verify_ssl=verify_ssl, use_request_proxy=use_request_proxy
        )
        init_segment_cache[init_url] = init_content
    return init_segment_cache[init_url]
