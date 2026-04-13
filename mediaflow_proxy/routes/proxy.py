import logging
import re
from functools import lru_cache
from typing import Annotated
from urllib.parse import quote, unquote

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
    get_init_segment,
    get_public_ip,
)
from mediaflow_proxy.schemas import (
    MPDSegmentParams,
    MPDPlaylistParams,
    HLSManifestParams,
    MPDManifestParams,
    MPDInitParams,
)
from mediaflow_proxy.utils.base64_utils import process_potential_base64_url
from mediaflow_proxy.utils.extractor_helpers import (
    check_and_extract_sportsonline_stream,
)
from mediaflow_proxy.utils.hls_prebuffer import hls_prebuffer
from mediaflow_proxy.utils.http_utils import (
    get_proxy_headers,
    ProxyRequestHeaders,
    apply_header_manipulation,
)
from mediaflow_proxy.utils.stream_transformers import apply_transformer_to_bytes


logger = logging.getLogger(__name__)
proxy_router = APIRouter()


@lru_cache(maxsize=1)
def _load_transcode_components():
    from mediaflow_proxy.remuxer.media_source import HTTPMediaSource
    from mediaflow_proxy.remuxer.transcode_handler import (
        handle_transcode,
        handle_transcode_hls_init,
        handle_transcode_hls_playlist,
        handle_transcode_hls_segment,
    )

    return (
        HTTPMediaSource,
        handle_transcode,
        handle_transcode_hls_init,
        handle_transcode_hls_playlist,
        handle_transcode_hls_segment,
    )


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
    url = re.sub(r"https%22//", "https://", url)
    url = re.sub(r"http%22//", "http://", url)

    # Fix malformed URLs where https%3A%22// should be https://
    url = re.sub(r"https%3A%22//", "https://", url)
    url = re.sub(r"http%3A%22//", "http://", url)

    # Fix malformed URLs where https:"// should be https:// (after partial decoding)
    url = re.sub(r'https:"//', "https://", url)
    url = re.sub(r'http:"//', "http://", url)

    # Fix URLs where key_id and key parameters are incorrectly appended to the base URL
    # This happens when the URL contains &key_id= and &key= which should be handled as proxy parameters
    if "&key_id=" in url and "&key=" in url:
        # Split the URL at the first occurrence of &key_id= to separate the base URL from the incorrectly appended parameters
        base_url = url.split("&key_id=")[0]
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
                fixed_decoded = re.sub(r'([a-z]+):"//', r"\1://", decoded_url)
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
    if "&key_id=" in url and "&key=" in url:
        # Extract key_id
        key_id_match = re.search(r"&key_id=([^&]+)", url)
        if key_id_match:
            key_id = key_id_match.group(1)

        # Extract key
        key_match = re.search(r"&key=([^&]+)", url)
        if key_match:
            key = key_match.group(1)

        # Remove the parameters from the URL
        clean_url = re.sub(r"&key_id=[^&]*", "", url)
        clean_url = re.sub(r"&key=[^&]*", "", clean_url)

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

    # Check if destination contains Sportsonline pattern and extract stream directly
    sportsonline_result = await check_and_extract_sportsonline_stream(request, hls_params.destination, proxy_headers)
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
        # Update request query params
        request._query_params = QueryParams(query_dict)

    return await handle_hls_stream_proxy(request, hls_params, proxy_headers, hls_params.transformer)


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

    return await handle_hls_stream_proxy(request, hls_params, proxy_headers, hls_params.transformer)


# Map file extensions to MIME types for HLS segments
HLS_SEGMENT_MIME_TYPES = {
    "ts": "video/mp2t",  # MPEG-TS (traditional HLS)
    "m4s": "video/mp4",  # fMP4 segment (modern HLS/CMAF)
    "mp4": "video/mp4",  # fMP4 segment (alternative extension)
    "m4a": "audio/mp4",  # Audio-only fMP4 segment
    "m4v": "video/mp4",  # Video fMP4 segment (alternative)
    "aac": "audio/aac",  # AAC audio segment
}


@proxy_router.get("/hls/segment.{ext}", name="hls_segment_proxy")
async def hls_segment_proxy(
    request: Request,
    proxy_headers: Annotated[ProxyRequestHeaders, Depends(get_proxy_headers)],
    ext: str,
    segment_url: str = Query(..., description="URL of the HLS segment", alias="d"),
    transformer: str = Query(None, description="Stream transformer ID for content manipulation"),
):
    """
    Proxy HLS segments with pre-buffering support.

    This endpoint supports multiple segment formats:
    - /hls/segment.ts  - MPEG-TS segments (traditional HLS)
    - /hls/segment.m4s - fMP4 segments (modern HLS/CMAF)
    - /hls/segment.mp4 - fMP4 segments (alternative)
    - /hls/segment.m4a - Audio fMP4 segments
    - /hls/segment.aac - AAC audio segments

    Uses event-based coordination to prevent duplicate downloads between
    player requests and background prebuffering.

    Args:
        request (Request): The incoming HTTP request.
        ext (str): File extension determining the segment format.
        segment_url (str): URL of the HLS segment to proxy.
        proxy_headers (ProxyRequestHeaders): The headers to include in the request.
        transformer (str, optional): Stream transformer ID for content manipulation.

    Returns:
        Response: The HTTP response with the segment content.
    """
    # Get MIME type for this extension
    mime_type = HLS_SEGMENT_MIME_TYPES.get(ext.lower(), "application/octet-stream")

    # Sanitize segment URL to fix common encoding issues
    original_url = segment_url
    segment_url = sanitize_url(segment_url)

    logger.info(f"[hls_segment_proxy] Request for: {segment_url}")
    if original_url != segment_url:
        logger.warning(f"[hls_segment_proxy] URL was sanitized! Original: {original_url}")

    # Extract headers for pre-buffering
    headers = {}
    for key, value in request.query_params.items():
        if key.startswith("h_"):
            headers[key[2:]] = value

    if settings.enable_hls_prebuffer:
        # Notify the prefetcher that this segment is needed (priority download)
        # This ensures the player's segment is downloaded first, then prefetcher
        # continues with sequential prefetch of remaining segments
        await hls_prebuffer.request_segment(segment_url)

        # Use cross-process coordination to get the segment
        segment_data = await hls_prebuffer.get_or_download(segment_url, headers)

        if segment_data:
            logger.info(f"[hls_segment_proxy] Serving from prebuffer ({len(segment_data)} bytes): {segment_url}")

            # Apply transformer if specified (e.g., PNG wrapper stripping)
            if transformer:
                segment_data = await apply_transformer_to_bytes(segment_data, transformer)

            # Return cached/downloaded segment
            base_headers = {
                "content-type": mime_type,
                "cache-control": "public, max-age=3600",
                "access-control-allow-origin": "*",
            }
            response_headers = apply_header_manipulation(base_headers, proxy_headers)
            return Response(content=segment_data, media_type=mime_type, headers=response_headers)

        # get_or_download returned None (timeout or error) - fall through to direct fetch
        logger.warning(f"[hls_segment_proxy] Prebuffer timeout, using direct fetch: {segment_url}")

    # Fallback to direct streaming.
    # Override the response Content-Type so that CDN-served MPEG-TS segments
    # are not interpreted as a non-video format.
    if mime_type != "application/octet-stream":
        proxy_headers.response["content-type"] = mime_type
    return await handle_stream_request("GET", segment_url, proxy_headers, transformer)


# =============================================================================
# HLS Transcode endpoints (VOD playlist + init segment + media segments)
# =============================================================================


@proxy_router.head("/transcode/playlist.m3u8")
@proxy_router.get("/transcode/playlist.m3u8")
async def transcode_hls_playlist(
    request: Request,
    proxy_headers: Annotated[ProxyRequestHeaders, Depends(get_proxy_headers)],
    destination: str = Query(..., description="The URL of the source media.", alias="d"),
):
    """
    Generate an HLS VOD M3U8 playlist for on-the-fly transcoded content.

    Probes the source file's keyframe index and generates a playlist where
    each segment corresponds to one or more keyframe intervals. The playlist
    references the init segment and media segment endpoints below.

    The generated playlist uses ``#EXT-X-VERSION:7`` with fMP4 (CMAF)
    segments for universal browser and player compatibility.

    Args:
        request: The incoming HTTP request.
        proxy_headers: Headers to forward to the source.
        destination: URL of the source media file.
    """
    if not settings.enable_transcode:
        raise HTTPException(status_code=503, detail="Transcoding support is disabled")
    HTTPMediaSource, _, _, handle_transcode_hls_playlist, _ = _load_transcode_components()
    destination = sanitize_url(destination)
    source = HTTPMediaSource(url=destination, headers=dict(proxy_headers.request))
    await source.resolve_file_size()

    # Build URLs for init and segment endpoints that preserve query params
    # (api_password, headers, etc.) from the current request.
    base_params = _build_hls_query_params(request, destination)

    init_url = f"/proxy/transcode/init.mp4?{base_params}"
    segment_url_template = (
        f"/proxy/transcode/segment.m4s?{base_params}&seg={{seg}}&start_ms={{start_ms}}&end_ms={{end_ms}}"
    )

    return await handle_transcode_hls_playlist(
        request,
        source,
        init_url=init_url,
        segment_url_template=segment_url_template,
    )


@proxy_router.head("/transcode/init.mp4")
@proxy_router.get("/transcode/init.mp4")
async def transcode_hls_init(
    request: Request,
    proxy_headers: Annotated[ProxyRequestHeaders, Depends(get_proxy_headers)],
    destination: str = Query(..., description="The URL of the source media.", alias="d"),
):
    """
    Serve the fMP4 init segment (ftyp + moov) for HLS transcode playback.

    The init segment is built from probed track metadata without running
    the full transcode pipeline.

    Args:
        request: The incoming HTTP request.
        proxy_headers: Headers to forward to the source.
        destination: URL of the source media file.
    """
    if not settings.enable_transcode:
        raise HTTPException(status_code=503, detail="Transcoding support is disabled")
    HTTPMediaSource, _, handle_transcode_hls_init, _, _ = _load_transcode_components()
    destination = sanitize_url(destination)
    source = HTTPMediaSource(url=destination, headers=dict(proxy_headers.request))
    await source.resolve_file_size()

    return await handle_transcode_hls_init(request, source)


@proxy_router.get("/transcode/segment.m4s")
async def transcode_hls_segment(
    request: Request,
    proxy_headers: Annotated[ProxyRequestHeaders, Depends(get_proxy_headers)],
    destination: str = Query(..., description="The URL of the source media.", alias="d"),
    start_ms: float = Query(..., description="Segment start time in milliseconds."),
    end_ms: float = Query(..., description="Segment end time in milliseconds."),
    seg: int | None = Query(None, description="Segment number (informational, for logging)."),
):
    """
    Serve a single HLS fMP4 media segment (moof + mdat).

    Each segment corresponds to a merged keyframe interval in the source
    file.  The time range is self-describing (from the playlist URL) so
    no cue-point re-derivation is needed.

    Args:
        request: The incoming HTTP request.
        proxy_headers: Headers to forward to the source.
        destination: URL of the source media file.
        start_ms: Segment start time in milliseconds.
        end_ms: Segment end time in milliseconds.
    """
    if not settings.enable_transcode:
        raise HTTPException(status_code=503, detail="Transcoding support is disabled")
    HTTPMediaSource, _, _, _, handle_transcode_hls_segment = _load_transcode_components()
    destination = sanitize_url(destination)
    source = HTTPMediaSource(url=destination, headers=dict(proxy_headers.request))
    await source.resolve_file_size()

    return await handle_transcode_hls_segment(
        request, source, start_time_ms=start_ms, end_time_ms=end_ms, segment_number=seg
    )


def _build_hls_query_params(request: Request, destination: str) -> str:
    """
    Build query string for HLS sub-requests, preserving auth and header params.

    Copies ``api_password``, header manipulation params (``h_*``), and the
    destination URL from the original request.
    """
    params = [f"d={quote(destination, safe='')}"]
    original = request.query_params
    if "api_password" in original:
        params.append(f"api_password={quote(original['api_password'], safe='')}")
    # Preserve header overrides (h_referer, h_origin, etc.)
    for key in original:
        if key.startswith("h_"):
            params.append(f"{key}={quote(original[key], safe='')}")
    return "&".join(params)


@proxy_router.head("/stream")
@proxy_router.get("/stream")
@proxy_router.head("/stream/{filename:path}")
@proxy_router.get("/stream/{filename:path}")
async def proxy_stream_endpoint(
    request: Request,
    proxy_headers: Annotated[ProxyRequestHeaders, Depends(get_proxy_headers)],
    destination: str = Query(..., description="The URL of the stream.", alias="d"),
    filename: str | None = None,
    transformer: str = Query(None, description="Stream transformer ID for content manipulation"),
    ratelimit: str = Query(
        None,
        description="Rate limit handler ID for host-specific rate limiting (e.g., 'vidoza', 'aggressive'). "
        "If not specified, auto-detects based on destination URL hostname. "
        "Set to 'none' to explicitly disable rate limiting.",
    ),
    transcode: bool = Query(
        False, description="Transcode to browser-compatible fMP4 (re-encode video/audio as needed)"
    ),
    start: float | None = Query(None, description="Seek start time in seconds (used with transcode=true)"),
):
    """
    Proxify stream requests to the given video URL.

    This is a general-purpose stream proxy endpoint. For HLS segments with prebuffer
    support, use the dedicated /hls/segment.ts endpoint instead.

    When transcode=true, the media is transcoded on-the-fly to browser-compatible
    fMP4 (H.264 video + AAC audio). Video is re-encoded only if the source codec
    is not browser-compatible (e.g. H.265, MPEG-2). Audio is transcoded to AAC
    when needed (e.g. EAC3, AC3, DTS). GPU acceleration is used when available.

    Rate limiting can be controlled via the `ratelimit` parameter:
    - Not specified: Auto-detects based on destination URL (e.g., Vidoza is auto-detected)
    - "vidoza": Explicitly enable Vidoza rate limiting (5s cooldown between connections)
    - "aggressive": Generic aggressive rate limiting (3s cooldown)
    - "none": Explicitly disable all rate limiting

    Args:
        request (Request): The incoming HTTP request.
        proxy_headers (ProxyRequestHeaders): The headers to include in the request.
        destination (str): The URL of the stream to be proxied.
        filename (str | None): The filename to be used in the response headers.
        transformer (str, optional): Stream transformer ID for content manipulation.
        ratelimit (str, optional): Rate limit handler ID for host-specific rate limiting.
        transcode (bool): Transcode to browser-compatible format.
        start (float, optional): Seek start time in seconds (transcode mode only).

    Returns:
        Response: The HTTP response with the streamed content.
    """
    # Log incoming request details for debugging seek issues
    range_header = proxy_headers.request.get("range", "not set")
    logger.info(
        f"[proxy_stream] Request received - filename: {filename}, range: {range_header}, "
        f"method: {request.method}, transcode: {transcode}"
    )

    # Sanitize destination URL to fix common encoding issues
    destination = sanitize_url(destination)

    # Handle transcode mode — transcode uses time-based seeking, not byte ranges
    if transcode:
        if not settings.enable_transcode:
            raise HTTPException(status_code=503, detail="Transcoding support is disabled")
        HTTPMediaSource, handle_transcode, _, _, _ = _load_transcode_components()
        transcode_headers = dict(proxy_headers.request)
        transcode_headers.pop("range", None)
        transcode_headers.pop("if-range", None)
        source = HTTPMediaSource(url=destination, headers=transcode_headers)
        await source.resolve_file_size()
        return await handle_transcode(request, source, start_time=start)

    if proxy_headers.request.get("range", "").strip() == "":
        proxy_headers.request.pop("range", None)

    if proxy_headers.request.get("if-range", "").strip() == "":
        proxy_headers.request.pop("if-range", None)

    if "range" not in proxy_headers.request:
        proxy_headers.request["range"] = "bytes=0-"
        # Mark that this range was auto-added (not from client)
        # This is used in handlers.py to decide whether to convert 206->200
        proxy_headers.auto_added_range = True

    if filename:
        # If a filename is provided (not a segment), set it in the headers using RFC 6266 format
        try:
            # Try to encode with latin-1 first (simple case)
            filename.encode("latin-1")
            content_disposition = f'attachment; filename="{filename}"'
        except UnicodeEncodeError:
            # For filenames with non-latin-1 characters, use RFC 6266 format with UTF-8
            encoded_filename = quote(filename.encode("utf-8"))
            content_disposition = f"attachment; filename*=UTF-8''{encoded_filename}"

        proxy_headers.response.update({"content-disposition": content_disposition})

    # Handle "none" as explicit disable
    rate_limit_handler_id = None if ratelimit == "none" else ratelimit

    return await proxy_stream(request.method, destination, proxy_headers, transformer, rate_limit_handler_id)


@proxy_router.head("/mpd/manifest.m3u8")
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


@proxy_router.head("/mpd/playlist.m3u8")
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

    This endpoint serves fMP4 segments without TS remuxing. The playlist generator
    already selects /segment.mp4 vs /segment.ts based on the resolved remux mode,
    so this endpoint explicitly disables remuxing regardless of global settings.

    Args:
        segment_params (MPDSegmentParams): The parameters for the segment request.
        proxy_headers (ProxyRequestHeaders): The headers to include in the request.

    Returns:
        Response: The HTTP response with the processed segment.
    """
    return await get_segment(segment_params, proxy_headers, force_remux_ts=False)


@proxy_router.get("/mpd/segment.ts")
async def segment_ts_endpoint(
    segment_params: Annotated[MPDSegmentParams, Query()],
    proxy_headers: Annotated[ProxyRequestHeaders, Depends(get_proxy_headers)],
):
    """
    Retrieves and processes a media segment, remuxing fMP4 to MPEG-TS.

    This endpoint is used for HLS playlists when remux_to_ts is enabled.
    Unlike /mpd/segment.mp4, this forces TS remuxing regardless of global settings.

    Args:
        segment_params (MPDSegmentParams): The parameters for the segment request.
        proxy_headers (ProxyRequestHeaders): The headers to include in the request.

    Returns:
        Response: The HTTP response with the MPEG-TS segment.
    """
    return await get_segment(segment_params, proxy_headers, force_remux_ts=True)


@proxy_router.get("/mpd/init.mp4")
async def init_endpoint(
    init_params: Annotated[MPDInitParams, Query()],
    proxy_headers: Annotated[ProxyRequestHeaders, Depends(get_proxy_headers)],
):
    """
    Retrieves and processes an initialization segment for use with EXT-X-MAP.

    Args:
        init_params (MPDInitParams): The parameters for the init segment request.
        proxy_headers (ProxyRequestHeaders): The headers to include in the request.

    Returns:
        Response: The HTTP response with the processed init segment.
    """
    return await get_init_segment(init_params, proxy_headers)


@proxy_router.get("/ip")
async def get_mediaflow_proxy_public_ip():
    """
    Retrieves the public IP address of the MediaFlow proxy server.

    Returns:
        Response: The HTTP response with the public IP address in the form of a JSON object. {"ip": "xxx.xxx.xxx.xxx"}
    """
    return await get_public_ip()
