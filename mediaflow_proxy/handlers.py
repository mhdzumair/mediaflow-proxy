import base64
import logging

import httpx
from fastapi import Request, Response, HTTPException
from pydantic import HttpUrl
from starlette.background import BackgroundTask
from starlette.status import HTTP_206_PARTIAL_CONTENT

from .configs import settings
from .const import SUPPORTED_RESPONSE_HEADERS
from .mpd_processor import process_manifest, process_playlist, process_segment
from .utils.cache_utils import get_cached_mpd, get_cached_init_segment
from .utils.http_utils import (
    Streamer,
    DownloadError,
    download_file_with_retry,
    request_with_retry,
    EnhancedStreamingResponse,
)
from .utils.m3u8_processor import M3U8Processor
from .utils.mpd_utils import pad_base64

logger = logging.getLogger(__name__)


async def handle_hls_stream_proxy(
    request: Request, destination: str, headers: dict, key_url: HttpUrl = None, verify_ssl: bool = True
):
    """
    Handles the HLS stream proxy request, fetching and processing the m3u8 playlist or streaming the content.

    Args:
        request (Request): The incoming HTTP request.
        destination (str): The destination URL to fetch the content from.
        headers (dict): The headers to include in the request.
        key_url (str, optional): The HLS Key URL to replace the original key URL. Defaults to None.
        verify_ssl (bool, optional): Whether to verify the SSL certificate of the destination. Defaults to True.

    Returns:
        Response: The HTTP response with the processed m3u8 playlist or streamed content.
    """
    client = httpx.AsyncClient(
        follow_redirects=True,
        timeout=httpx.Timeout(30.0),
        limits=httpx.Limits(max_keepalive_connections=10, max_connections=20),
        proxy=settings.proxy_url,
        verify=verify_ssl,
    )
    streamer = Streamer(client)
    try:
        if destination.endswith((".m3u", ".m3u8")):
            return await fetch_and_process_m3u8(streamer, destination, headers, request, key_url)

        response = await streamer.head(destination, headers)
        if "mpegurl" in response.headers.get("content-type", "").lower():
            return await fetch_and_process_m3u8(streamer, destination, headers, request, key_url)

        headers.update({"range": headers.get("range", "bytes=0-")})
        # clean up the headers to only include the necessary headers and remove acl headers
        response_headers = {k: v for k, v in response.headers.multi_items() if k in SUPPORTED_RESPONSE_HEADERS}

        if transfer_encoding := response_headers.get("transfer-encoding"):
            if "chunked" not in transfer_encoding:
                transfer_encoding += ", chunked"
        else:
            transfer_encoding = "chunked"
        response_headers["transfer-encoding"] = transfer_encoding

        return EnhancedStreamingResponse(
            streamer.stream_content(destination, headers),
            status_code=HTTP_206_PARTIAL_CONTENT,
            headers=response_headers,
            background=BackgroundTask(streamer.close),
        )
    except httpx.HTTPStatusError as e:
        await client.aclose()
        logger.error(f"Upstream service error while handling request: {e}")
        return Response(status_code=e.response.status_code, content=f"Upstream service error: {e}")
    except DownloadError as e:
        await client.aclose()
        logger.error(f"Error downloading {destination}: {e}")
        return Response(status_code=e.status_code, content=str(e))
    except Exception as e:
        await client.aclose()
        logger.error(f"Internal server error while handling request: {e}")
        return Response(status_code=502, content=f"Internal server error: {e}")


async def proxy_stream(method: str, video_url: str, headers: dict, verify_ssl: bool = True):
    """
    Proxies the stream request to the given video URL.

    Args:
        method (str): The HTTP method (e.g., GET, HEAD).
        video_url (str): The URL of the video to stream.
        headers (dict): The headers to include in the request.
        verify_ssl (bool, optional): Whether to verify the SSL certificate of the destination. Defaults to True.

    Returns:
        Response: The HTTP response with the streamed content.
    """
    return await handle_stream_request(method, video_url, headers, verify_ssl)


async def handle_stream_request(method: str, video_url: str, headers: dict, verify_ssl: bool = True):
    """
    Handles the stream request, fetching the content from the video URL and streaming it.

    Args:
        method (str): The HTTP method (e.g., GET, HEAD).
        video_url (str): The URL of the video to stream.
        headers (dict): The headers to include in the request.
        verify_ssl (bool, optional): Whether to verify the SSL certificate of the destination. Defaults to True.

    Returns:
        Response: The HTTP response with the streamed content.
    """
    client = httpx.AsyncClient(
        follow_redirects=True,
        timeout=httpx.Timeout(30.0),
        limits=httpx.Limits(max_keepalive_connections=10, max_connections=20),
        proxy=settings.proxy_url,
        verify=verify_ssl,
    )
    streamer = Streamer(client)
    try:
        response = await streamer.head(video_url, headers)
        # clean up the headers to only include the necessary headers and remove acl headers
        response_headers = {k: v for k, v in response.headers.multi_items() if k in SUPPORTED_RESPONSE_HEADERS}
        if transfer_encoding := response_headers.get("transfer-encoding"):
            if "chunked" not in transfer_encoding:
                transfer_encoding += ", chunked"
        else:
            transfer_encoding = "chunked"
        response_headers["transfer-encoding"] = transfer_encoding

        if method == "HEAD":
            await streamer.close()
            return Response(headers=response_headers, status_code=HTTP_206_PARTIAL_CONTENT)
        else:
            return EnhancedStreamingResponse(
                streamer.stream_content(video_url, headers),
                headers=response_headers,
                status_code=HTTP_206_PARTIAL_CONTENT,
                background=BackgroundTask(streamer.close),
            )
    except httpx.HTTPStatusError as e:
        await client.aclose()
        logger.error(f"Upstream service error while handling {method} request: {e}")
        return Response(status_code=e.response.status_code, content=f"Upstream service error: {e}")
    except DownloadError as e:
        await client.aclose()
        logger.error(f"Error downloading {video_url}: {e}")
        return Response(status_code=e.status_code, content=str(e))
    except Exception as e:
        await client.aclose()
        logger.error(f"Internal server error while handling {method} request: {e}")
        return Response(status_code=502, content=f"Internal server error: {e}")


async def fetch_and_process_m3u8(
    streamer: Streamer, url: str, headers: dict, request: Request, key_url: HttpUrl = None
):
    """
    Fetches and processes the m3u8 playlist, converting it to an HLS playlist.

    Args:
        streamer (Streamer): The HTTP client to use for streaming.
        url (str): The URL of the m3u8 playlist.
        headers (dict): The headers to include in the request.
        request (Request): The incoming HTTP request.
        key_url (HttpUrl, optional): The HLS Key URL to replace the original key URL. Defaults to None.

    Returns:
        Response: The HTTP response with the processed m3u8 playlist.
    """
    try:
        content = await streamer.get_text(url, headers)
        processor = M3U8Processor(request, key_url)
        processed_content = await processor.process_m3u8(content, str(streamer.response.url))
        return Response(
            content=processed_content,
            media_type="application/vnd.apple.mpegurl",
            headers={
                "Cache-Control": "no-cache, no-store, must-revalidate",
                "Pragma": "no-cache",
                "Expires": "0",
            },
        )
    except httpx.HTTPStatusError as e:
        logger.error(f"HTTP error while fetching m3u8: {e}")
        return Response(status_code=e.response.status_code, content=str(e))
    except DownloadError as e:
        logger.error(f"Error downloading m3u8: {url}")
        return Response(status_code=502, content=str(e))
    except Exception as e:
        logger.exception(f"Unexpected error while processing m3u8: {e}")
        return Response(status_code=502, content=str(e))
    finally:
        await streamer.close()


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
            raise HTTPException(status_code=400, detail="LA URL is not supported yet")
        else:
            raise HTTPException(
                status_code=400, detail="Unable to determine key_id and key, and they were not provided"
            )

    return key_id, key


async def get_manifest(
    request: Request, mpd_url: str, headers: dict, key_id: str = None, key: str = None, verify_ssl: bool = True
):
    """
    Retrieves and processes the MPD manifest, converting it to an HLS manifest.

    Args:
        request (Request): The incoming HTTP request.
        mpd_url (str): The URL of the MPD manifest.
        headers (dict): The headers to include in the request.
        key_id (str, optional): The DRM key ID. Defaults to None.
        key (str, optional): The DRM key. Defaults to None.
        verify_ssl (bool, optional): Whether to verify the SSL certificate of the destination. Defaults to True.

    Returns:
        Response: The HTTP response with the HLS manifest.
    """
    try:
        mpd_dict = await get_cached_mpd(
            mpd_url, headers=headers, parse_drm=not key_id and not key, verify_ssl=verify_ssl
        )
    except DownloadError as e:
        raise HTTPException(status_code=e.status_code, detail=f"Failed to download MPD: {e.message}")
    drm_info = mpd_dict.get("drmInfo", {})

    if drm_info and not drm_info.get("isDrmProtected"):
        # For non-DRM protected MPD, we still create an HLS manifest
        return await process_manifest(request, mpd_dict, None, None)

    key_id, key = await handle_drm_key_data(key_id, key, drm_info)

    # check if the provided key_id and key are valid
    if key_id and len(key_id) != 32:
        key_id = base64.urlsafe_b64decode(pad_base64(key_id)).hex()
    if key and len(key) != 32:
        key = base64.urlsafe_b64decode(pad_base64(key)).hex()

    return await process_manifest(request, mpd_dict, key_id, key)


async def get_playlist(
    request: Request,
    mpd_url: str,
    profile_id: str,
    headers: dict,
    key_id: str = None,
    key: str = None,
    verify_ssl: bool = True,
):
    """
    Retrieves and processes the MPD manifest, converting it to an HLS playlist for a specific profile.

    Args:
        request (Request): The incoming HTTP request.
        mpd_url (str): The URL of the MPD manifest.
        profile_id (str): The profile ID to generate the playlist for.
        headers (dict): The headers to include in the request.
        key_id (str, optional): The DRM key ID. Defaults to None.
        key (str, optional): The DRM key. Defaults to None.
        verify_ssl (bool, optional): Whether to verify the SSL certificate of the destination. Defaults to True.

    Returns:
        Response: The HTTP response with the HLS playlist.
    """
    mpd_dict = await get_cached_mpd(
        mpd_url,
        headers=headers,
        parse_drm=not key_id and not key,
        parse_segment_profile_id=profile_id,
        verify_ssl=verify_ssl,
    )
    return await process_playlist(request, mpd_dict, profile_id)


async def get_segment(
    init_url: str,
    segment_url: str,
    mimetype: str,
    headers: dict,
    key_id: str = None,
    key: str = None,
    verify_ssl: bool = True,
):
    """
    Retrieves and processes a media segment, decrypting it if necessary.

    Args:
        init_url (str): The URL of the initialization segment.
        segment_url (str): The URL of the media segment.
        mimetype (str): The MIME type of the segment.
        headers (dict): The headers to include in the request.
        key_id (str, optional): The DRM key ID. Defaults to None.
        key (str, optional): The DRM key. Defaults to None.
        verify_ssl (bool, optional): Whether to verify the SSL certificate of the destination. Defaults to True.

    Returns:
        Response: The HTTP response with the processed segment.
    """
    try:
        init_content = await get_cached_init_segment(init_url, headers, verify_ssl)
        segment_content = await download_file_with_retry(segment_url, headers, verify_ssl=verify_ssl)
    except DownloadError as e:
        raise HTTPException(status_code=e.status_code, detail=f"Failed to download segment: {e.message}")
    return await process_segment(init_content, segment_content, mimetype, key_id, key)


async def get_public_ip():
    """
    Retrieves the public IP address of the MediaFlow proxy.

    Returns:
        Response: The HTTP response with the public IP address.
    """
    ip_address_data = await request_with_retry("GET", "https://api.ipify.org?format=json", {})
    return ip_address_data.json()
