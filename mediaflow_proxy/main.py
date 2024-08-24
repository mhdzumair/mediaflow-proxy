import logging

from fastapi import FastAPI, Request, Depends, Security, HTTPException
from fastapi.security import APIKeyQuery
from pydantic import HttpUrl

from mediaflow_proxy.configs import settings
from .handlers import handle_hls_stream_proxy, proxy_stream, get_manifest, get_playlist, get_segment, get_public_ip

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
app = FastAPI()
api_key_query = APIKeyQuery(name="api_password", auto_error=False)


async def verify_api_key(api_key: str = Security(api_key_query)):
    """
    Verifies the API key for the request.

    Args:
        api_key (str): The API key to validate.

    Raises:
        HTTPException: If the API key is invalid.
    """
    if api_key != settings.api_password:
        raise HTTPException(status_code=403, detail="Could not validate credentials")


def get_proxy_headers(request: Request) -> dict:
    """
    Extracts proxy headers from the request query parameters.

    Args:
        request (Request): The incoming HTTP request.

    Returns:
        dict: A dictionary of proxy headers.
    """
    return {k[2:]: v for k, v in request.query_params.items() if k.startswith("h_")}


@app.head("/proxy/hls")
@app.get("/proxy/hls")
async def hls_stream_proxy(
    request: Request,
    d: HttpUrl,
    headers: dict = Depends(get_proxy_headers),
    key_url: HttpUrl | None = None,
    _: str = Depends(verify_api_key),
):
    """
    Proxify HLS stream requests, fetching and processing the m3u8 playlist or streaming the content.

    Args:
        request (Request): The incoming HTTP request.
        d (HttpUrl): The destination URL to fetch the content from.
        key_url (HttpUrl, optional): The HLS Key URL to replace the original key URL. Defaults to None. (Useful for bypassing some sneaky protection)
        headers (dict): The headers to include in the request.
        _ (str): The API key to validate.

    Returns:
        Response: The HTTP response with the processed m3u8 playlist or streamed content.
    """
    destination = str(d)
    return await handle_hls_stream_proxy(request, destination, headers, key_url)


@app.head("/proxy/stream")
@app.get("/proxy/stream")
async def proxy_stream_endpoint(
    request: Request, d: HttpUrl, headers: dict = Depends(get_proxy_headers), _: str = Depends(verify_api_key)
):
    """
    Proxies stream requests to the given video URL.

    Args:
        request (Request): The incoming HTTP request.
        d (HttpUrl): The URL of the video to stream.
        headers (dict): The headers to include in the request.
        _: str: The API key to validate.

    Returns:
        Response: The HTTP response with the streamed content.
    """
    headers.update({"range": headers.get("range", "bytes=0-")})
    return await proxy_stream(request.method, str(d), headers)


@app.get("/proxy/mpd/manifest")
async def manifest_endpoint(
    request: Request,
    d: HttpUrl,
    headers: dict = Depends(get_proxy_headers),
    key_id: str = None,
    key: str = None,
    _: str = Depends(verify_api_key),
):
    """
    Retrieves and processes the MPD manifest, converting it to an HLS manifest.

    Args:
        request (Request): The incoming HTTP request.
        d (HttpUrl): The URL of the MPD manifest.
        headers (dict): The headers to include in the request.
        key_id (str, optional): The DRM key ID. Defaults to None.
        key (str, optional): The DRM key. Defaults to None.
        _: str: The API key to validate.

    Returns:
        Response: The HTTP response with the HLS manifest.
    """
    return await get_manifest(request, str(d), headers, key_id, key)


@app.get("/proxy/mpd/playlist")
async def playlist_endpoint(
    request: Request,
    d: HttpUrl,
    profile_id: str,
    headers: dict = Depends(get_proxy_headers),
    key_id: str = None,
    key: str = None,
    _: str = Depends(verify_api_key),
):
    """
    Retrieves and processes the MPD manifest, converting it to an HLS playlist for a specific profile.

    Args:
        request (Request): The incoming HTTP request.
        d (HttpUrl): The URL of the MPD manifest.
        profile_id (str): The profile ID to generate the playlist for.
        headers (dict): The headers to include in the request.
        key_id (str, optional): The DRM key ID. Defaults to None.
        key (str, optional): The DRM key. Defaults to None.
        _: str: The API key to validate.

    Returns:
        Response: The HTTP response with the HLS playlist.
    """
    return await get_playlist(request, str(d), profile_id, headers, key_id, key)


@app.get("/proxy/mpd/segment")
async def segment_endpoint(
    init_url: HttpUrl,
    segment_url: HttpUrl,
    mime_type: str,
    headers: dict = Depends(get_proxy_headers),
    key_id: str = None,
    key: str = None,
    _: str = Depends(verify_api_key),
):
    """
    Retrieves and processes a media segment, decrypting it if necessary.

    Args:
        init_url (HttpUrl): The URL of the initialization segment.
        segment_url (HttpUrl): The URL of the media segment.
        mime_type (str): The MIME type of the segment.
        headers (dict): The headers to include in the request.
        key_id (str, optional): The DRM key ID. Defaults to None.
        key (str, optional): The DRM key. Defaults to None.
        _: str: The API key to validate.

    Returns:
        Response: The HTTP response with the processed segment.
    """
    return await get_segment(str(init_url), str(segment_url), mime_type, headers, key_id, key)


@app.get("/proxy/ip")
async def get_mediaflow_proxy_public_ip(_: str = Depends(verify_api_key)):
    """
    Retrieves the public IP address of the MediaFlow proxy server.

    Args:
        _: str: The API key to validate.

    Returns:
        Response: The HTTP response with the public IP address in the form of a JSON object. {"ip": "xxx.xxx.xxx.xxx"}
    """
    return await get_public_ip()
