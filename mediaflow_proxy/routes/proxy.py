from typing import Annotated
from urllib.parse import quote

from fastapi import Request, Depends, APIRouter, Query, HTTPException
from fastapi.responses import Response, RedirectResponse

from mediaflow_proxy.handlers import (
    handle_hls_stream_proxy,
    handle_stream_request,
    proxy_stream,
    get_manifest,
    get_playlist,
    get_segment,
    get_public_ip,
)
from mediaflow_proxy.schemas import (
    MPDSegmentParams,
    MPDPlaylistParams,
    HLSManifestParams,
    MPDManifestParams,
)
from mediaflow_proxy.utils.http_utils import get_proxy_headers, ProxyRequestHeaders

proxy_router = APIRouter()


def _check_and_redirect_dlhd_stream(request: Request, destination: str) -> RedirectResponse | None:
    """
    Check if destination contains stream-{numero} pattern and redirect to extractor if needed.
    
    Args:
        request (Request): The incoming HTTP request.
        destination (str): The destination URL to check.
        
    Returns:
        RedirectResponse | None: RedirectResponse if redirect is needed, None otherwise.
    """
    import re
    
    # Check for stream-{numero} pattern (e.g., stream-1, stream-123, etc.)
    if re.search(r'stream-\d+', destination):
        from urllib.parse import urlencode
        
        # Build redirect URL to extractor
        redirect_params = {
            "host": "DLHD",
            "redirect_stream": "true",
            "d": destination
        }
        
        # Preserve api_password if present
        if "api_password" in request.query_params:
            redirect_params["api_password"] = request.query_params["api_password"]
        
        # Build the redirect URL
        base_url = str(request.url_for("extract_url"))
        redirect_url = f"{base_url}?{urlencode(redirect_params)}"
        
        return RedirectResponse(url=redirect_url, status_code=302)
    
    return None


@proxy_router.head("/hls/manifest.m3u8")
@proxy_router.head("/hls/manifest.m3u8")
@proxy_router.get("/hls/manifest.m3u8")
async def hls_manifest_proxy(
    request: Request,
    hls_params: Annotated[HLSManifestParams, Query()],
    proxy_headers: Annotated[ProxyRequestHeaders, Depends(get_proxy_headers)],
):
    """
    Proxify HLS stream requests, fetching and processing the m3u8 playlist or streaming the content.

    Args:
        request (Request): The incoming HTTP request.
        hls_params (HLSPlaylistParams): The parameters for the HLS stream request.
        proxy_headers (ProxyRequestHeaders): The headers to include in the request.

    Returns:
        Response: The HTTP response with the processed m3u8 playlist or streamed content.
    """
    # Check if destination contains stream-{numero} pattern and redirect to extractor
    redirect_response = _check_and_redirect_dlhd_stream(request, hls_params.destination)
    if redirect_response:
        return redirect_response
    
    return await handle_hls_stream_proxy(request, hls_params, proxy_headers)


@proxy_router.get("/hls/segment")
async def hls_segment_proxy(
    request: Request,
    proxy_headers: Annotated[ProxyRequestHeaders, Depends(get_proxy_headers)],
    segment_url: str = Query(..., description="URL of the HLS segment"),
):
    """
    Proxy HLS segments with optional pre-buffering support.

    Args:
        request (Request): The incoming HTTP request.
        segment_url (str): URL of the HLS segment to proxy.
        proxy_headers (ProxyRequestHeaders): The headers to include in the request.

    Returns:
        Response: The HTTP response with the segment content.
    """
    from mediaflow_proxy.utils.hls_prebuffer import hls_prebuffer
    from mediaflow_proxy.configs import settings
    
    # Extract headers for pre-buffering
    headers = {}
    for key, value in request.query_params.items():
        if key.startswith("h_"):
            headers[key[2:]] = value
    
    # Try to get segment from pre-buffer cache first
    if settings.enable_hls_prebuffer:
        cached_segment = await hls_prebuffer.get_segment(segment_url, headers)
        if cached_segment:
            return Response(
                content=cached_segment,
                media_type="video/mp2t",
                headers={
                    "Content-Type": "video/mp2t",
                    "Cache-Control": "public, max-age=3600",
                    "Access-Control-Allow-Origin": "*"
                }
            )
    
    # Fallback to direct streaming if not in cache
    return await handle_stream_request("GET", segment_url, proxy_headers)


@proxy_router.get("/dash/segment")
async def dash_segment_proxy(
    request: Request,
    proxy_headers: Annotated[ProxyRequestHeaders, Depends(get_proxy_headers)],
    segment_url: str = Query(..., description="URL of the DASH segment"),
):
    """
    Proxy DASH segments with optional pre-buffering support.

    Args:
        request (Request): The incoming HTTP request.
        segment_url (str): URL of the DASH segment to proxy.
        proxy_headers (ProxyRequestHeaders): The headers to include in the request.

    Returns:
        Response: The HTTP response with the segment content.
    """
    from mediaflow_proxy.utils.dash_prebuffer import dash_prebuffer
    from mediaflow_proxy.configs import settings
    
    # Extract headers for pre-buffering
    headers = {}
    for key, value in request.query_params.items():
        if key.startswith("h_"):
            headers[key[2:]] = value
    
    # Try to get segment from pre-buffer cache first
    if settings.enable_dash_prebuffer:
        cached_segment = await dash_prebuffer.get_segment(segment_url, headers)
        if cached_segment:
            return Response(
                content=cached_segment,
                media_type="video/mp4",
                headers={
                    "Content-Type": "video/mp4",
                    "Cache-Control": "public, max-age=3600",
                    "Access-Control-Allow-Origin": "*"
                }
            )
    
    # Fallback to direct streaming if not in cache
    return await handle_stream_request("GET", segment_url, proxy_headers)


@proxy_router.head("/stream")
@proxy_router.get("/stream")
@proxy_router.head("/stream/{filename:path}")
@proxy_router.get("/stream/{filename:path}")
async def proxy_stream_endpoint(
    request: Request,
    proxy_headers: Annotated[ProxyRequestHeaders, Depends(get_proxy_headers)],
    destination: str = Query(..., description="The URL of the stream.", alias="d"),
    filename: str | None = None,
):
    """
    Proxify stream requests to the given video URL.

    Args:
        request (Request): The incoming HTTP request.
        proxy_headers (ProxyRequestHeaders): The headers to include in the request.
        destination (str): The URL of the stream to be proxied.
        filename (str | None): The filename to be used in the response headers.

    Returns:
        Response: The HTTP response with the streamed content.
    """
    # Check if destination contains stream-{numero} pattern and redirect to extractor
    redirect_response = _check_and_redirect_dlhd_stream(request, destination)
    if redirect_response:
        return redirect_response
    
    content_range = proxy_headers.request.get("range", "bytes=0-")
    if "nan" in content_range.casefold():
        # Handle invalid range requests "bytes=NaN-NaN"
        raise HTTPException(status_code=416, detail="Invalid Range Header")
    proxy_headers.request.update({"range": content_range})
    if filename:
        # If a filename is provided, set it in the headers using RFC 6266 format
        try:
            # Try to encode with latin-1 first (simple case)
            filename.encode("latin-1")
            content_disposition = f'attachment; filename="{filename}"'
        except UnicodeEncodeError:
            # For filenames with non-latin-1 characters, use RFC 6266 format with UTF-8
            encoded_filename = quote(filename.encode("utf-8"))
            content_disposition = f"attachment; filename*=UTF-8''{encoded_filename}"

        proxy_headers.response.update({"content-disposition": content_disposition})

    return await proxy_stream(request.method, destination, proxy_headers)


@proxy_router.get("/mpd/manifest.m3u8")
async def mpd_manifest_proxy(
    request: Request,
    manifest_params: Annotated[MPDManifestParams, Query()],
    proxy_headers: Annotated[ProxyRequestHeaders, Depends(get_proxy_headers)],
):
    """
    Retrieves and processes the MPD manifest, converting it to an HLS manifest.

    Args:
        request (Request): The incoming HTTP request.
        manifest_params (MPDManifestParams): The parameters for the manifest request.
        proxy_headers (ProxyRequestHeaders): The headers to include in the request.

    Returns:
        Response: The HTTP response with the HLS manifest.
    """
    return await get_manifest(request, manifest_params, proxy_headers)


@proxy_router.get("/mpd/playlist.m3u8")
async def playlist_endpoint(
    request: Request,
    playlist_params: Annotated[MPDPlaylistParams, Query()],
    proxy_headers: Annotated[ProxyRequestHeaders, Depends(get_proxy_headers)],
):
    """
    Retrieves and processes the MPD manifest, converting it to an HLS playlist for a specific profile.

    Args:
        request (Request): The incoming HTTP request.
        playlist_params (MPDPlaylistParams): The parameters for the playlist request.
        proxy_headers (ProxyRequestHeaders): The headers to include in the request.

    Returns:
        Response: The HTTP response with the HLS playlist.
    """
    return await get_playlist(request, playlist_params, proxy_headers)


@proxy_router.get("/mpd/segment.mp4")
async def segment_endpoint(
    segment_params: Annotated[MPDSegmentParams, Query()],
    proxy_headers: Annotated[ProxyRequestHeaders, Depends(get_proxy_headers)],
):
    """
    Retrieves and processes a media segment, decrypting it if necessary.

    Args:
        segment_params (MPDSegmentParams): The parameters for the segment request.
        proxy_headers (ProxyRequestHeaders): The headers to include in the request.

    Returns:
        Response: The HTTP response with the processed segment.
    """
    return await get_segment(segment_params, proxy_headers)


@proxy_router.get("/ip")
async def get_mediaflow_proxy_public_ip():
    """
    Retrieves the public IP address of the MediaFlow proxy server.

    Returns:
        Response: The HTTP response with the public IP address in the form of a JSON object. {"ip": "xxx.xxx.xxx.xxx"}
    """
    return await get_public_ip()