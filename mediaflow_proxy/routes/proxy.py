import asyncio
import logging
import re
from typing import Annotated
from urllib.parse import quote, unquote

import httpx
from fastapi import Request, Depends, APIRouter, Query, HTTPException, Response
from fastapi.datastructures import QueryParams

from mediaflow_proxy.configs import settings
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
from mediaflow_proxy.utils.base64_utils import process_potential_base64_url
from mediaflow_proxy.utils.dash_prebuffer import dash_prebuffer
from mediaflow_proxy.utils.extractor_helpers import (
    check_and_extract_dlhd_stream,
    check_and_extract_sportsonline_stream,
)
from mediaflow_proxy.utils.hls_prebuffer import hls_prebuffer
from mediaflow_proxy.utils.hls_utils import parse_hls_playlist, find_stream_by_resolution
from mediaflow_proxy.utils.http_utils import (
    get_proxy_headers,
    ProxyRequestHeaders,
    create_httpx_client,
    apply_header_manipulation,
)
from mediaflow_proxy.utils.m3u8_processor import M3U8Processor


logger = logging.getLogger(__name__)
proxy_router = APIRouter()


def sanitize_url(url: str) -> str:
    """
    Sanitize URL to fix common encoding issues and handle base64 encoded URLs.
    
    Args:
        url (str): The URL to sanitize.
        
    Returns:
        str: The sanitized URL.
    """
    original_url = url
    
    # First, try to process potential base64 encoded URLs
    url = process_potential_base64_url(url)
    
    # Fix malformed URLs where https%22// should be https://
    url = re.sub(r'https%22//', 'https://', url)
    url = re.sub(r'http%22//', 'http://', url)
    
    # Fix malformed URLs where https%3A%22// should be https://
    url = re.sub(r'https%3A%22//', 'https://', url)
    url = re.sub(r'http%3A%22//', 'http://', url)
    
    # Fix malformed URLs where https:"// should be https:// (after partial decoding)
    url = re.sub(r'https:"//', 'https://', url)
    url = re.sub(r'http:"//', 'http://', url)
    
    # Fix URLs where key_id and key parameters are incorrectly appended to the base URL
    # This happens when the URL contains &key_id= and &key= which should be handled as proxy parameters
    if '&key_id=' in url and '&key=' in url:
        # Split the URL at the first occurrence of &key_id= to separate the base URL from the incorrectly appended parameters
        base_url = url.split('&key_id=')[0]
        logger.info(f"Removed incorrectly appended key parameters from URL: '{url}' -> '{base_url}'")
        url = base_url
    
    # Log if URL was changed
    if url != original_url:
        logger.info(f"URL sanitized: '{original_url}' -> '{url}'")
    
    # Also try URL decoding to see what we get
    try:
        decoded_url = unquote(url)
        if decoded_url != url:
            logger.info(f"URL after decoding: '{decoded_url}'")
            # If after decoding we still have malformed protocol, fix it
            if ':"/' in decoded_url:
                # Fix https:"// or http:"// patterns
                fixed_decoded = re.sub(r'([a-z]+):"//', r'\1://', decoded_url)
                logger.info(f"Fixed decoded URL: '{fixed_decoded}'")
                return fixed_decoded
    except Exception as e:
        logger.warning(f"Error decoding URL '{url}': {e}")
    
    return url


def extract_drm_params_from_url(url: str) -> tuple[str, str, str]:
    """
    Extract DRM parameters (key_id and key) from a URL if they are incorrectly appended.
    
    Args:
        url (str): The URL that may contain appended DRM parameters.
        
    Returns:
        tuple: (clean_url, key_id, key) where clean_url has the parameters removed,
               and key_id/key are the extracted values (or None if not found).
    """
    key_id = None
    key = None
    clean_url = url
    
    # Check if URL contains incorrectly appended key_id and key parameters
    if '&key_id=' in url and '&key=' in url:
        # Extract key_id
        key_id_match = re.search(r'&key_id=([^&]+)', url)
        if key_id_match:
            key_id = key_id_match.group(1)
        
        # Extract key
        key_match = re.search(r'&key=([^&]+)', url)
        if key_match:
            key = key_match.group(1)
        
        # Remove the parameters from the URL
        clean_url = re.sub(r'&key_id=[^&]*', '', url)
        clean_url = re.sub(r'&key=[^&]*', '', clean_url)
        
        logger.info(f"Extracted DRM parameters from URL: key_id={key_id}, key={key}")
        logger.info(f"Cleaned URL: '{url}' -> '{clean_url}'")
    
    return clean_url, key_id, key


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
    # Sanitize destination URL to fix common encoding issues
    hls_params.destination = sanitize_url(hls_params.destination)
    
    # Check if this is a retry after 403 error (dlhd_retry parameter)
    force_refresh = request.query_params.get("dlhd_retry") == "1"
    
    # Check if destination contains DLHD pattern and extract stream directly
    dlhd_result = await check_and_extract_dlhd_stream(
        request, hls_params.destination, proxy_headers, force_refresh=force_refresh
    )
    dlhd_original_url = None
    if dlhd_result:
        # Store original DLHD URL for cache invalidation on 403 errors
        dlhd_original_url = hls_params.destination
        
        # Update destination and headers with extracted stream data
        hls_params.destination = dlhd_result["destination_url"]
        extracted_headers = dlhd_result.get("request_headers", {})
        proxy_headers.request.update(extracted_headers)
        
        # Check if extractor wants key-only proxy (DLHD uses hls_key_proxy endpoint)
        if dlhd_result.get("mediaflow_endpoint") == "hls_key_proxy":
            hls_params.key_only_proxy = True
        
        # Also add headers to query params so they propagate to key/segment requests
        # This is necessary because M3U8Processor encodes headers as h_* query params
        query_dict = dict(request.query_params)
        for header_name, header_value in extracted_headers.items():
            # Add header with h_ prefix to query params
            query_dict[f"h_{header_name}"] = header_value
        # Add DLHD original URL to track for cache invalidation
        if dlhd_original_url:
            query_dict["dlhd_original"] = dlhd_original_url
        # Remove retry flag from subsequent requests
        query_dict.pop("dlhd_retry", None)
        # Update request query params
        request._query_params = QueryParams(query_dict)

    # Check if destination contains Sportsonline pattern and extract stream directly
    sportsonline_result = await check_and_extract_sportsonline_stream(
        request, hls_params.destination, proxy_headers
    )
    if sportsonline_result:
        # Update destination and headers with extracted stream data
        hls_params.destination = sportsonline_result["destination_url"]
        extracted_headers = sportsonline_result.get("request_headers", {})
        proxy_headers.request.update(extracted_headers)

        # Check if extractor wants key-only proxy
        if sportsonline_result.get("mediaflow_endpoint") == "hls_key_proxy":
            hls_params.key_only_proxy = True

        # Also add headers to query params so they propagate to key/segment requests
        query_dict = dict(request.query_params)
        for header_name, header_value in extracted_headers.items():
            # Add header with h_ prefix to query params
            query_dict[f"h_{header_name}"] = header_value
        # Remove retry flag from subsequent requests
        query_dict.pop("dlhd_retry", None)
        # Update request query params
        request._query_params = QueryParams(query_dict)

    # Wrap the handler to catch 403 errors and retry with cache invalidation
    try:
        result = await _handle_hls_with_dlhd_retry(request, hls_params, proxy_headers, dlhd_original_url)
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Unexpected error in hls_manifest_proxy: {e}")
        raise HTTPException(status_code=500, detail=str(e))


async def _handle_hls_with_dlhd_retry(
    request: Request,
    hls_params: HLSManifestParams,
    proxy_headers: ProxyRequestHeaders,
    dlhd_original_url: str | None
):
    """
    Handle HLS request with automatic retry on 403 errors for DLHD streams.
    """
    # Check if resolution selection is needed (either max_res or specific resolution)
    if hls_params.max_res or hls_params.resolution:
        async with create_httpx_client(
            headers=proxy_headers.request,
            follow_redirects=True,
        ) as client:
            try:
                response = await client.get(hls_params.destination)
                response.raise_for_status()
                playlist_content = response.text
            except httpx.HTTPStatusError as e:
                raise HTTPException(
                    status_code=502,
                    detail=f"Failed to fetch HLS manifest from origin: {e.response.status_code} {e.response.reason_phrase}",
                ) from e
            except httpx.TimeoutException as e:
                raise HTTPException(
                    status_code=504,
                    detail=f"Timeout while fetching HLS manifest: {e}",
                ) from e
            except httpx.RequestError as e:
                raise HTTPException(status_code=502, detail=f"Network error fetching HLS manifest: {e}") from e
        
        streams = parse_hls_playlist(playlist_content, base_url=hls_params.destination)
        if not streams:
            raise HTTPException(
                status_code=404, detail="No streams found in the manifest."
            )

        # Select stream based on resolution parameter or max_res
        if hls_params.resolution:
            selected_stream = find_stream_by_resolution(streams, hls_params.resolution)
            if not selected_stream:
                raise HTTPException(
                    status_code=404, detail=f"No suitable stream found for resolution {hls_params.resolution}."
                )
        else:
            # max_res: select highest resolution
            selected_stream = max(
                streams,
                key=lambda s: s.get("resolution", (0, 0))[0]
                * s.get("resolution", (0, 0))[1],
            )

        if selected_stream.get("resolution", (0, 0)) == (0, 0):
            logger.warning("Selected stream has resolution (0, 0); resolution parsing may have failed or not be available in the manifest.")

        # Rebuild the manifest preserving master-level directives
        # but removing non-selected variant blocks
        lines = playlist_content.splitlines()
        selected_variant_index = streams.index(selected_stream)
        
        variant_index = -1
        new_manifest_lines = []
        i = 0
        while i < len(lines):
            line = lines[i]
            if line.startswith("#EXT-X-STREAM-INF"):
                variant_index += 1
                next_line = ""
                if i + 1 < len(lines) and not lines[i + 1].startswith("#"):
                    next_line = lines[i + 1]
                
                # Only keep the selected variant
                if variant_index == selected_variant_index:
                    new_manifest_lines.append(line)
                    if next_line:
                        new_manifest_lines.append(next_line)
                
                # Skip variant block (stream-inf + optional url)
                i += 2 if next_line else 1
                continue
            
            # Preserve all other lines (master directives, media tags, etc.)
            new_manifest_lines.append(line)
            i += 1
        
        new_manifest = "\n".join(new_manifest_lines)

        # Process the new manifest to proxy all URLs within it
        processor = M3U8Processor(request, hls_params.key_url, hls_params.force_playlist_proxy, hls_params.key_only_proxy, hls_params.no_proxy)
        processed_manifest = await processor.process_m3u8(new_manifest, base_url=hls_params.destination)
        
        return Response(content=processed_manifest, media_type="application/vnd.apple.mpegurl")
    
    return await handle_hls_stream_proxy(request, hls_params, proxy_headers)


@proxy_router.head("/hls/key_proxy/manifest.m3u8", name="hls_key_proxy")
@proxy_router.get("/hls/key_proxy/manifest.m3u8", name="hls_key_proxy")
async def hls_key_proxy(
    request: Request,
    hls_params: Annotated[HLSManifestParams, Query()],
    proxy_headers: Annotated[ProxyRequestHeaders, Depends(get_proxy_headers)],
):
    """
    Proxify HLS stream requests, but only proxy the key URL, leaving segment URLs direct.

    Args:
        request (Request): The incoming HTTP request.
        hls_params (HLSManifestParams): The parameters for the HLS stream request.
        proxy_headers (ProxyRequestHeaders): The headers to include in the request.

    Returns:
        Response: The HTTP response with the processed m3u8 playlist.
    """
    # Sanitize destination URL to fix common encoding issues
    hls_params.destination = sanitize_url(hls_params.destination)
    
    # Set the key_only_proxy flag to True
    hls_params.key_only_proxy = True
    
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
    # Sanitize segment URL to fix common encoding issues
    segment_url = sanitize_url(segment_url)
    
    # Extract headers for pre-buffering
    headers = {}
    for key, value in request.query_params.items():
        if key.startswith("h_"):
            headers[key[2:]] = value

    # Try to get segment from pre-buffer cache first
    if settings.enable_hls_prebuffer:
        cached_segment = await hls_prebuffer.get_segment(segment_url, headers)
        if cached_segment:
            # Avvia prebuffer dei successivi in background
            asyncio.create_task(hls_prebuffer.prebuffer_from_segment(segment_url, headers))
            # Apply header manipulation to cached response
            base_headers = {
                "content-type": "video/mp2t",
                "cache-control": "public, max-age=3600",
                "access-control-allow-origin": "*"
            }
            response_headers = apply_header_manipulation(base_headers, proxy_headers)
            return Response(
                content=cached_segment,
                media_type="video/mp2t",
                headers=response_headers
            )

    # Fallback to direct streaming se non in cache:
    # prima di restituire, prova comunque a far partire il prebuffer dei successivi
    if settings.enable_hls_prebuffer:
        asyncio.create_task(hls_prebuffer.prebuffer_from_segment(segment_url, headers))
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
    # Sanitize segment URL to fix common encoding issues
    segment_url = sanitize_url(segment_url)
    
    # Extract headers for pre-buffering
    headers = {}
    for key, value in request.query_params.items():
        if key.startswith("h_"):
            headers[key[2:]] = value
    
    # Try to get segment from pre-buffer cache first
    if settings.enable_dash_prebuffer:
        cached_segment = await dash_prebuffer.get_segment(segment_url, headers)
        if cached_segment:
            # Apply header manipulation to cached response
            base_headers = {
                "content-type": "video/mp4",
                "cache-control": "public, max-age=3600",
                "access-control-allow-origin": "*"
            }
            response_headers = apply_header_manipulation(base_headers, proxy_headers)
            return Response(
                content=cached_segment,
                media_type="video/mp4",
                headers=response_headers
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
    # Sanitize destination URL to fix common encoding issues
    destination = sanitize_url(destination)
    
    # Check if destination contains DLHD pattern and extract stream directly
    dlhd_result = await check_and_extract_dlhd_stream(request, destination, proxy_headers)
    if dlhd_result:
        # Update destination and headers with extracted stream data
        destination = dlhd_result["destination_url"]
        proxy_headers.request.update(dlhd_result.get("request_headers", {}))
    if proxy_headers.request.get("range", "").strip() == "":
        proxy_headers.request.pop("range", None)

    if proxy_headers.request.get("if-range", "").strip() == "":
        proxy_headers.request.pop("if-range", None)
    
    if "range" not in proxy_headers.request:
        proxy_headers.request["range"] = "bytes=0-"
    
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
    # Extract DRM parameters from destination URL if they are incorrectly appended
    clean_url, extracted_key_id, extracted_key = extract_drm_params_from_url(manifest_params.destination)
    
    # Update the destination with the cleaned URL
    manifest_params.destination = clean_url
    
    # Use extracted parameters if they exist and the manifest params don't already have them
    if extracted_key_id and not manifest_params.key_id:
        manifest_params.key_id = extracted_key_id
    if extracted_key and not manifest_params.key:
        manifest_params.key = extracted_key
    
    # Sanitize destination URL to fix common encoding issues
    manifest_params.destination = sanitize_url(manifest_params.destination)
    
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
    # Extract DRM parameters from destination URL if they are incorrectly appended
    clean_url, extracted_key_id, extracted_key = extract_drm_params_from_url(playlist_params.destination)
    
    # Update the destination with the cleaned URL
    playlist_params.destination = clean_url
    
    # Use extracted parameters if they exist and the playlist params don't already have them
    if extracted_key_id and not playlist_params.key_id:
        playlist_params.key_id = extracted_key_id
    if extracted_key and not playlist_params.key:
        playlist_params.key = extracted_key
    
    # Sanitize destination URL to fix common encoding issues
    playlist_params.destination = sanitize_url(playlist_params.destination)
    
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
