from fastapi import Request, Depends, APIRouter
from pydantic import HttpUrl

from .handlers import handle_hls_stream_proxy, proxy_stream, get_manifest, get_playlist, get_segment, get_public_ip
from .utils.http_utils import get_proxy_headers, ProxyRequestHeaders

proxy_router = APIRouter()


@proxy_router.head("/hls")
@proxy_router.get("/hls")
async def hls_stream_proxy(
    request: Request,
    d: HttpUrl,
    proxy_headers: ProxyRequestHeaders = Depends(get_proxy_headers),
    key_url: HttpUrl | None = None,
    verify_ssl: bool = False,
    use_request_proxy: bool = True,
):
    """
    Proxify HLS stream requests, fetching and processing the m3u8 playlist or streaming the content.

    Args:
        request (Request): The incoming HTTP request.
        d (HttpUrl): The destination URL to fetch the content from.
        key_url (HttpUrl, optional): The HLS Key URL to replace the original key URL. Defaults to None. (Useful for bypassing some sneaky protection)
        proxy_headers (ProxyRequestHeaders): The headers to include in the request.
        verify_ssl (bool, optional): Whether to verify the SSL certificate of the destination. Defaults to False.
        use_request_proxy (bool, optional): Whether to use the MediaFlow proxy configuration. Defaults to True.

    Returns:
        Response: The HTTP response with the processed m3u8 playlist or streamed content.
    """
    destination = str(d)
    return await handle_hls_stream_proxy(request, destination, proxy_headers, key_url, verify_ssl, use_request_proxy)


@proxy_router.head("/stream")
@proxy_router.get("/stream")
async def proxy_stream_endpoint(
    request: Request,
    d: HttpUrl,
    proxy_headers: ProxyRequestHeaders = Depends(get_proxy_headers),
    verify_ssl: bool = False,
    use_request_proxy: bool = True,
):
    """
    Proxies stream requests to the given video URL.

    Args:
        request (Request): The incoming HTTP request.
        d (HttpUrl): The URL of the video to stream.
        proxy_headers (ProxyRequestHeaders): The headers to include in the request.
        verify_ssl (bool, optional): Whether to verify the SSL certificate of the destination. Defaults to False.
        use_request_proxy (bool, optional): Whether to use the MediaFlow proxy configuration. Defaults to True.

    Returns:
        Response: The HTTP response with the streamed content.
    """
    proxy_headers.request.update({"range": proxy_headers.request.get("range", "bytes=0-")})
    return await proxy_stream(request.method, str(d), proxy_headers, verify_ssl, use_request_proxy)


@proxy_router.get("/mpd/manifest")
async def manifest_endpoint(
    request: Request,
    d: HttpUrl,
    proxy_headers: ProxyRequestHeaders = Depends(get_proxy_headers),
    key_id: str = None,
    key: str = None,
    verify_ssl: bool = False,
    use_request_proxy: bool = True,
):
    """
    Retrieves and processes the MPD manifest, converting it to an HLS manifest.

    Args:
        request (Request): The incoming HTTP request.
        d (HttpUrl): The URL of the MPD manifest.
        proxy_headers (ProxyRequestHeaders): The headers to include in the request.
        key_id (str, optional): The DRM key ID. Defaults to None.
        key (str, optional): The DRM key. Defaults to None.
        verify_ssl (bool, optional): Whether to verify the SSL certificate of the destination. Defaults to False.
        use_request_proxy (bool, optional): Whether to use the MediaFlow proxy configuration. Defaults to True.

    Returns:
        Response: The HTTP response with the HLS manifest.
    """
    return await get_manifest(request, str(d), proxy_headers, key_id, key, verify_ssl, use_request_proxy)


@proxy_router.get("/mpd/playlist")
async def playlist_endpoint(
    request: Request,
    d: HttpUrl,
    profile_id: str,
    proxy_headers: ProxyRequestHeaders = Depends(get_proxy_headers),
    key_id: str = None,
    key: str = None,
    verify_ssl: bool = False,
    use_request_proxy: bool = True,
):
    """
    Retrieves and processes the MPD manifest, converting it to an HLS playlist for a specific profile.

    Args:
        request (Request): The incoming HTTP request.
        d (HttpUrl): The URL of the MPD manifest.
        profile_id (str): The profile ID to generate the playlist for.
        proxy_headers (ProxyRequestHeaders): The headers to include in the request.
        key_id (str, optional): The DRM key ID. Defaults to None.
        key (str, optional): The DRM key. Defaults to None.
        verify_ssl (bool, optional): Whether to verify the SSL certificate of the destination. Defaults to False.
        use_request_proxy (bool, optional): Whether to use the MediaFlow proxy configuration. Defaults to True.

    Returns:
        Response: The HTTP response with the HLS playlist.
    """
    return await get_playlist(request, str(d), profile_id, proxy_headers, key_id, key, verify_ssl, use_request_proxy)


@proxy_router.get("/mpd/segment")
async def segment_endpoint(
    init_url: HttpUrl,
    segment_url: HttpUrl,
    mime_type: str,
    proxy_headers: ProxyRequestHeaders = Depends(get_proxy_headers),
    key_id: str = None,
    key: str = None,
    verify_ssl: bool = False,
    use_request_proxy: bool = True,
):
    """
    Retrieves and processes a media segment, decrypting it if necessary.

    Args:
        init_url (HttpUrl): The URL of the initialization segment.
        segment_url (HttpUrl): The URL of the media segment.
        mime_type (str): The MIME type of the segment.
        proxy_headers (ProxyRequestHeaders): The headers to include in the request.
        key_id (str, optional): The DRM key ID. Defaults to None.
        key (str, optional): The DRM key. Defaults to None.
        verify_ssl (bool, optional): Whether to verify the SSL certificate of the destination. Defaults to False.
        use_request_proxy (bool, optional): Whether to use the MediaFlow proxy configuration. Defaults to True.

    Returns:
        Response: The HTTP response with the processed segment.
    """
    return await get_segment(
        str(init_url), str(segment_url), mime_type, proxy_headers, key_id, key, verify_ssl, use_request_proxy
    )


@proxy_router.get("/ip")
async def get_mediaflow_proxy_public_ip(
    use_request_proxy: bool = True,
):
    """
    Retrieves the public IP address of the MediaFlow proxy server.

    Returns:
        Response: The HTTP response with the public IP address in the form of a JSON object. {"ip": "xxx.xxx.xxx.xxx"}
    """
    return await get_public_ip(use_request_proxy)
