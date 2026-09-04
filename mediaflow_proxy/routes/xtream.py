"""
Xtream Codes (XC) API Proxy Routes.

This module provides a stateless pass-through proxy for Xtream Codes API,
allowing users to use MediaFlow as an intermediary with any XC-compatible IPTV player.
All streams (live, VOD, series, catch-up/timeshift) are proxied without storing any data.

Configuration:
    Configure your IPTV player with:
    - Server: http://your-mediaflow-server:8888
    - Username: {base64_upstream}:{actual_username}:{api_password}
    - Password: your_xc_password

    Where:
    - base64_upstream: Base64-encoded upstream XC server URL
    - actual_username: Your actual XC username
    - api_password: Your MediaFlow API password (if configured)

    The api_password part can be omitted if MediaFlow doesn't require authentication.
"""

import base64
import logging
import re
from functools import lru_cache
from typing import Annotated
from urllib.parse import urljoin, urlencode, urlparse

from fastapi.responses import RedirectResponse
import aiohttp
from fastapi import APIRouter, Request, Depends, Query, Response, HTTPException

from mediaflow_proxy.configs import settings
from mediaflow_proxy.handlers import proxy_stream
from mediaflow_proxy.utils.base64_utils import decode_base64_url
from mediaflow_proxy.utils.http_utils import ProxyRequestHeaders, get_proxy_headers
from mediaflow_proxy.utils.http_client import create_aiohttp_session

logger = logging.getLogger(__name__)
xtream_root_router = APIRouter()


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


async def _handle_xtream_transcode(request, upstream_url: str, proxy_headers, start_time: float | None):
    """Shared transcode handler for Xtream stream endpoints."""
    if not settings.enable_transcode:
        raise HTTPException(status_code=503, detail="Transcoding support is disabled")
    HTTPMediaSource, handle_transcode, _, _, _ = _load_transcode_components()
    source = HTTPMediaSource(url=upstream_url, headers=dict(proxy_headers.request))
    await source.resolve_file_size()
    return await handle_transcode(request, source, start_time=start_time)


async def _handle_xtream_hls_playlist(request, upstream_url: str, proxy_headers):
    """Generate HLS VOD playlist for an Xtream stream."""
    if not settings.enable_transcode:
        raise HTTPException(status_code=503, detail="Transcoding support is disabled")
    HTTPMediaSource, _, _, handle_transcode_hls_playlist, _ = _load_transcode_components()
    from urllib.parse import quote

    source = HTTPMediaSource(url=upstream_url, headers=dict(proxy_headers.request))
    await source.resolve_file_size()

    # Build URLs using the generic proxy transcode endpoints with upstream URL
    encoded_url = quote(upstream_url, safe="")
    base_params = f"d={encoded_url}"
    original = request.query_params
    if "api_password" in original:
        base_params += f"&api_password={quote(original['api_password'], safe='')}"

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


async def _handle_xtream_hls_init(request, upstream_url: str, proxy_headers):
    """Serve fMP4 init segment for an Xtream stream."""
    if not settings.enable_transcode:
        raise HTTPException(status_code=503, detail="Transcoding support is disabled")
    HTTPMediaSource, _, handle_transcode_hls_init, _, _ = _load_transcode_components()
    source = HTTPMediaSource(url=upstream_url, headers=dict(proxy_headers.request))
    await source.resolve_file_size()
    return await handle_transcode_hls_init(request, source)


async def _handle_xtream_hls_segment(
    request,
    upstream_url: str,
    proxy_headers,
    start_ms: float,
    end_ms: float,
    seg: int | None = None,
):
    """Serve a single HLS fMP4 segment for an Xtream stream."""
    if not settings.enable_transcode:
        raise HTTPException(status_code=503, detail="Transcoding support is disabled")
    HTTPMediaSource, _, _, _, handle_transcode_hls_segment = _load_transcode_components()
    source = HTTPMediaSource(url=upstream_url, headers=dict(proxy_headers.request))
    await source.resolve_file_size()
    return await handle_transcode_hls_segment(
        request, source, start_time_ms=start_ms, end_time_ms=end_ms, segment_number=seg
    )


def decode_upstream_url(upstream_encoded: str) -> str:
    """
    Decode the base64-encoded upstream XC server URL.

    Args:
        upstream_encoded: Base64-encoded upstream server URL.

    Returns:
        The decoded upstream server URL.

    Raises:
        HTTPException: If the URL cannot be decoded.
    """
    decoded = decode_base64_url(upstream_encoded)
    if not decoded:
        raise HTTPException(
            status_code=400,
            detail="Invalid upstream server URL encoding. Must be base64-encoded.",
        )
    # Ensure the URL has a trailing slash for proper URL joining
    if not decoded.endswith("/"):
        decoded += "/"
    return decoded


def decode_base64_username(encoded: str) -> str | None:
    """
    Try to decode a base64-encoded username string.

    Args:
        encoded: The potentially base64-encoded string.

    Returns:
        The decoded string if successful, None otherwise.
    """
    try:
        # Handle URL-safe base64 encoding (replace - with + and _ with /)
        url_safe_encoded = encoded.replace("-", "+").replace("_", "/")

        # Add padding if necessary
        missing_padding = len(url_safe_encoded) % 4
        if missing_padding:
            url_safe_encoded += "=" * (4 - missing_padding)

        # Decode the base64 string
        decoded_bytes = base64.b64decode(url_safe_encoded)
        decoded = decoded_bytes.decode("utf-8")

        # Check if it looks like our format (contains colons and starts with http)
        if ":" in decoded:
            return decoded

        return None
    except (base64.binascii.Error, UnicodeDecodeError, ValueError):
        return None


def parse_username_with_upstream(username: str) -> tuple[str, str, str | None]:
    """
    Parse username that contains encoded upstream URL and optional API password.

    Supports two formats:
    1. Base64-encoded format (NEW - recommended for IPTV apps):
       Username is base64({upstream_url}:{actual_username}:{api_password})
       Or base64({upstream_url}:{actual_username})

    2. Legacy colon-separated format:
       {base64_upstream}:{actual_username}:{api_password}
       Or {base64_upstream}:{actual_username}

    Args:
        username: The username field which contains upstream URL and optionally API password.

    Returns:
        Tuple of (upstream_base_url, actual_username, api_password or None).

    Raises:
        HTTPException: If format is invalid.
    """
    # First, try to decode the entire username as base64
    # This is the new format where the whole string is base64-encoded
    decoded_username = decode_base64_username(username)

    if decoded_username:
        # Successfully decoded base64, now parse the decoded string
        parts = decoded_username.split(":")
        logger.debug(f"Decoded base64 username, found {len(parts)} parts")

        # The decoded format is: {upstream_url}:{actual_username}:{api_password}
        # or {upstream_url}:{actual_username}
        # Note: upstream_url contains "://" so we need to handle that

        # Find the protocol separator
        if "://" not in decoded_username:
            raise HTTPException(
                status_code=400,
                detail="Invalid username format. Decoded base64 doesn't contain valid upstream URL.",
            )

        # Split on :// first to get protocol
        proto_split = decoded_username.split("://", 1)
        if len(proto_split) != 2:
            raise HTTPException(
                status_code=400,
                detail="Invalid username format. Could not parse upstream URL protocol.",
            )

        protocol = proto_split[0]
        rest = proto_split[1]

        # Now split the rest by colons
        rest_parts = rest.split(":")

        if len(rest_parts) == 2:
            # Format: protocol://host:actual_username (no api_password, no port in URL)
            host, actual_username = rest_parts
            upstream_url = f"{protocol}://{host}"
            api_password = None
        elif len(rest_parts) == 3:
            # Could be:
            # - protocol://host:port:actual_username (no api_password)
            # - protocol://host:actual_username:api_password (no port in URL)
            # We need to determine which case by checking if the second part looks like a port
            if rest_parts[1].isdigit() and len(rest_parts[1]) <= 5:
                # Looks like a port: protocol://host:port:actual_username
                host, port, actual_username = rest_parts
                upstream_url = f"{protocol}://{host}:{port}"
                api_password = None
            else:
                # No port: protocol://host:actual_username:api_password
                host, actual_username, api_password = rest_parts
                upstream_url = f"{protocol}://{host}"
                api_password = api_password if api_password else None
        elif len(rest_parts) == 4:
            # Format: protocol://host:port:actual_username:api_password
            host, port, actual_username, api_password = rest_parts
            upstream_url = f"{protocol}://{host}:{port}"
            api_password = api_password if api_password else None
        else:
            raise HTTPException(
                status_code=400,
                detail="Invalid username format. Could not parse base64-decoded username.",
            )

        # Ensure trailing slash for URL joining
        if not upstream_url.endswith("/"):
            upstream_url += "/"

        logger.info(f"Parsed base64 username: upstream={upstream_url}, user={actual_username}")
        return upstream_url, actual_username, api_password

    # Legacy format: {base64_upstream}:{actual_username}:{api_password}
    if ":" not in username:
        raise HTTPException(
            status_code=400,
            detail="Invalid username format. Expected base64-encoded username or legacy format: {base64_upstream}:{actual_username}:{api_password}",
        )

    parts = username.split(":")

    if len(parts) == 2:
        # Format: {base64_upstream}:{actual_username}
        upstream_encoded, actual_username = parts
        api_password = None
    elif len(parts) == 3:
        # Format: {base64_upstream}:{actual_username}:{api_password}
        upstream_encoded, actual_username, api_password = parts
        api_password = api_password if api_password else None
    else:
        raise HTTPException(
            status_code=400,
            detail="Invalid username format. Expected base64-encoded username or legacy format: {base64_upstream}:{actual_username}:{api_password}",
        )

    upstream_base = decode_upstream_url(upstream_encoded)

    logger.info(f"Parsed legacy username: upstream={upstream_base}, user={actual_username}")
    return upstream_base, actual_username, api_password


def verify_xc_api_password(api_password: str | None):
    """
    Verify the API password for XC endpoints.

    Args:
        api_password: The API password from the username field.

    Raises:
        HTTPException: If API password is required but not provided or invalid.
    """
    # If no API password is configured on the server, allow access
    if not settings.api_password:
        return

    # If API password is required but not provided
    if not api_password:
        raise HTTPException(
            status_code=403,
            detail="API password required. Username format: {base64_upstream}:{actual_username}:{api_password}",
        )

    # Verify the password matches
    if api_password != settings.api_password:
        raise HTTPException(
            status_code=403,
            detail="Invalid API password",
        )


def get_mediaflow_base_url(request: Request) -> str:
    """
    Get the MediaFlow base URL for URL rewriting.

    Args:
        request: The incoming FastAPI request.

    Returns:
        The MediaFlow base URL.
    """
    scheme = request.headers.get("x-forwarded-proto", request.url.scheme)
    host = request.headers.get("x-forwarded-host", request.headers.get("host", request.url.netloc))
    return f"{scheme}://{host}"


def encode_username_for_rewrite(upstream_base: str, actual_username: str, api_password: str | None) -> str:
    """
    Create a base64-encoded username token for URL rewriting.

    Args:
        upstream_base: The upstream XC server base URL.
        actual_username: The actual XC username.
        api_password: The MediaFlow API password (if any).

    Returns:
        A base64-encoded username string.
    """
    # Remove trailing slash from upstream for cleaner encoding
    upstream_clean = upstream_base.rstrip("/")

    # Build the combined string
    if api_password:
        combined = f"{upstream_clean}:{actual_username}:{api_password}"
    else:
        combined = f"{upstream_clean}:{actual_username}"

    # Base64 encode (URL-safe)
    encoded = base64.urlsafe_b64encode(combined.encode()).decode().rstrip("=")
    return encoded


def rewrite_urls_for_api(
    content: str,
    upstream_base: str,
    mediaflow_base: str,
    actual_username: str,
    api_password: str | None,
) -> str:
    """
    Rewrite stream URLs in API responses to route through MediaFlow.

    This function replaces the upstream username in stream URLs with a base64-encoded
    token containing upstream URL + username + api_password, so MediaFlow can properly
    route the requests.

    Args:
        content: The API response content.
        upstream_base: The upstream XC server base URL.
        mediaflow_base: The MediaFlow base URL.
        actual_username: The actual XC username (to be replaced in URLs).
        api_password: The MediaFlow API password (if any).

    Returns:
        The content with rewritten URLs.
    """

    # Parse the upstream URL to get the origin for replacement
    parsed = urlparse(upstream_base)
    upstream_origin = f"{parsed.scheme}://{parsed.netloc}"

    # Create the encoded username token for MediaFlow
    encoded_username = encode_username_for_rewrite(upstream_base, actual_username, api_password)

    # Pattern to match stream URLs with username in path
    # Matches: http(s)://host(:port)/path/{username}/password/...
    # We need to replace {username} with {encoded_username}

    # First, handle the common XC stream URL patterns where username appears in the path
    # Pattern: /{prefix}/{username}/{password}/ where prefix is live, movie, series, etc.
    # or /{username}/{password}/ for short format

    # Escape special regex characters in the origin and username
    escaped_origin = re.escape(upstream_origin)
    escaped_username = re.escape(actual_username)

    # Pattern for URLs like: https://upstream/live/{username}/{password}/...
    # or https://upstream/{username}/{password}/...
    # We want to replace the upstream origin AND the username in one go

    def replace_stream_url(match):
        """Replace upstream origin with mediaflow and username with encoded token."""
        full_url = match.group(0)
        # Replace the upstream origin with mediaflow base
        new_url = full_url.replace(upstream_origin, mediaflow_base, 1)
        # Replace the username in the path with encoded username
        # The username appears after a / and before another /
        new_url = re.sub(
            r"(/(live|movie|series|timeshift|hlsr|hls)?/)" + escaped_username + r"/",
            r"\1" + encoded_username + "/",
            new_url,
        )
        # Also handle short format: /{username}/{password}/
        new_url = re.sub(
            r"^(" + re.escape(mediaflow_base) + ")/" + escaped_username + r"/([^/]+/\d+\.)",
            r"\1/" + encoded_username + r"/\2",
            new_url,
        )
        return new_url

    # Find and replace all URLs that contain the upstream origin
    # Match URLs that start with the upstream origin and contain the username
    url_pattern = escaped_origin + r'[^"\s\\]*' + escaped_username + r'[^"\s\\]*'
    content = re.sub(url_pattern, replace_stream_url, content)

    # Handle escaped URLs in JSON (where / is escaped as \/)
    escaped_upstream_json = upstream_origin.replace("/", "\\/")
    escaped_mediaflow_json = mediaflow_base.replace("/", "\\/")
    escaped_username_json = actual_username.replace("/", "\\/")

    def replace_escaped_stream_url(match):
        """Replace escaped upstream origin with mediaflow and username with encoded token."""
        full_url = match.group(0)
        new_url = full_url.replace(escaped_upstream_json, escaped_mediaflow_json, 1)
        # Replace username (handling escaped slashes)
        new_url = re.sub(
            r"(\\/(?:live|movie|series|timeshift|hlsr|hls)?\\/)" + re.escape(escaped_username_json) + r"\\/",
            r"\1" + encoded_username + "\\/",
            new_url,
        )
        # Short format
        new_url = re.sub(
            r"^("
            + re.escape(escaped_mediaflow_json)
            + ")\\/"
            + re.escape(escaped_username_json)
            + r"\\/([^\\/]+\\/\d+\.)",
            r"\1\\/" + encoded_username + r"\\/\2",
            new_url,
        )
        return new_url

    escaped_url_pattern = re.escape(escaped_upstream_json) + r'[^"\s]*' + re.escape(escaped_username_json) + r'[^"\s]*'
    content = re.sub(escaped_url_pattern, replace_escaped_stream_url, content)

    # Also do a simple domain replacement for any remaining URLs that don't have username in path
    # (like server_info URLs)
    content = content.replace(upstream_origin, mediaflow_base)
    content = content.replace(escaped_upstream_json, escaped_mediaflow_json)

    # Also replace hostname-only version (without port) if the upstream has a non-standard port
    # This handles cases where server_info.url doesn't include the port
    if parsed.port and parsed.port not in (80, 443):
        upstream_host_only = f"{parsed.scheme}://{parsed.hostname}"
        escaped_host_only_json = upstream_host_only.replace("/", "\\/")
        content = content.replace(upstream_host_only, mediaflow_base)
        content = content.replace(escaped_host_only_json, escaped_mediaflow_json)

    # IMPORTANT: Rewrite user_info.username in the response
    # Some IPTV players (like Tivimate) use the username from the response for subsequent API calls
    # So we need to replace the actual username with the encoded username in user_info
    # Pattern: "username":"actual_username" -> "username":"encoded_username"
    content = re.sub(
        r'"username"\s*:\s*"' + escaped_username + r'"',
        f'"username":"{encoded_username}"',
        content,
    )

    return content


async def forward_api_request(
    upstream_url: str,
    request: Request,
    upstream_base: str,
    actual_username: str,
    api_password: str | None,
) -> Response:
    """
    Forward an API request to upstream XC server.

    Args:
        upstream_url: The full upstream URL.
        request: The incoming FastAPI request.
        upstream_base: The decoded upstream base URL.
        actual_username: The actual XC username (for URL rewriting).
        api_password: The MediaFlow API password (for URL rewriting).

    Returns:
        The response from upstream with URLs rewritten.
    """
    mediaflow_base = get_mediaflow_base_url(request)

    async with create_aiohttp_session(upstream_url) as (session, proxy_url):
        try:
            async with session.get(upstream_url, proxy=proxy_url, allow_redirects=True) as response:
                response.raise_for_status()

                content = await response.text()
                content_type = response.headers.get("content-type", "application/json")

                # Rewrite URLs in JSON responses
                if "json" in content_type.lower():
                    content = rewrite_urls_for_api(
                        content, upstream_base, mediaflow_base, actual_username, api_password
                    )

                return Response(
                    content=content,
                    status_code=response.status,
                    media_type=content_type,
                )
        except aiohttp.ClientResponseError as e:
            logger.error(f"Upstream XC API error: {e.status}")
            raise HTTPException(
                status_code=e.status,
                detail=f"Upstream XC server error: {e.status}",
            )
        except aiohttp.ClientError as e:
            logger.error(f"Failed to connect to upstream XC server: {e}")
            raise HTTPException(
                status_code=502,
                detail=f"Failed to connect to upstream XC server: {str(e)}",
            )


# =============================================================================
# XC API Endpoints
# =============================================================================


@xtream_root_router.get("/player_api.php")
async def player_api(
    request: Request,
    username: str = Query(..., description="Format: {base64_upstream}:{actual_username}:{api_password}"),
    password: str = Query(..., description="XC password"),
    action: str = Query(None, description="API action"),
):
    """
    Player API endpoint for IPTV player compatibility.

    Handles all XC API actions including authentication, categories, streams, and EPG.

    Args:
        request: The incoming FastAPI request.
        username: Combined upstream URL, username, and API password.
        password: XC password.
        action: The API action to perform.

    Returns:
        The API response with stream URLs rewritten.
    """
    upstream_base, actual_username, api_password = parse_username_with_upstream(username)
    verify_xc_api_password(api_password)

    # Build query params for upstream (with actual username)
    query_params = {"username": actual_username, "password": password}
    if action:
        query_params["action"] = action

    # Add any other query params except our special ones
    for k, v in request.query_params.items():
        if k not in ("username", "password", "action", "api_password"):
            query_params[k] = v

    upstream_url = f"{upstream_base}player_api.php?{urlencode(query_params)}"

    logger.info(f"XC player_api.php: action={action}, upstream={upstream_base}, user={actual_username}")

    return await forward_api_request(upstream_url, request, upstream_base, actual_username, api_password)


@xtream_root_router.get("/xmltv.php")
async def xmltv_api(
    request: Request,
    username: str = Query(..., description="Format: {base64_upstream}:{actual_username}:{api_password}"),
    password: str = Query(..., description="XC password"),
):
    """
    XMLTV/EPG endpoint for electronic program guide data.

    Args:
        request: The incoming FastAPI request.
        username: Combined upstream URL, username, and API password.
        password: XC password.

    Returns:
        The EPG XML data from upstream.
    """
    upstream_base, actual_username, api_password = parse_username_with_upstream(username)
    verify_xc_api_password(api_password)

    # Build query params for upstream
    query_params = {"username": actual_username, "password": password}
    for k, v in request.query_params.items():
        if k not in ("username", "password", "api_password"):
            query_params[k] = v

    upstream_url = f"{upstream_base}xmltv.php?{urlencode(query_params)}"

    logger.info(f"XC xmltv.php: upstream={upstream_base}")

    async with create_aiohttp_session(upstream_url, timeout=60) as (session, proxy_url):
        try:
            async with session.get(upstream_url, proxy=proxy_url, allow_redirects=True) as response:
                response.raise_for_status()

                return Response(
                    content=await response.read(),
                    status_code=response.status,
                    media_type=response.headers.get("content-type", "application/xml"),
                )
        except aiohttp.ClientResponseError as e:
            raise HTTPException(status_code=e.status, detail=f"Upstream error: {e.status}")
        except aiohttp.ClientError as e:
            raise HTTPException(status_code=502, detail=f"Failed to connect: {str(e)}")


@xtream_root_router.get("/get.php")
async def get_playlist(
    request: Request,
    username: str = Query(..., description="Format: base64({upstream}:{actual_username}:{api_password})"),
    password: str = Query(..., description="XC password"),
    type: str = Query("m3u_plus", description="Playlist type (m3u, m3u_plus)"),
    output: str = Query("ts", description="Output format (ts, m3u8)"),
):
    """
    M3U playlist generation endpoint (XC API v1).

    Redirects to /proxy/hls/manifest.m3u8 which handles M3U URL rewriting.

    Args:
        request: The incoming FastAPI request.
        username: Combined upstream URL, username, and API password.
        password: XC password.
        type: Playlist type (m3u, m3u_plus).
        output: Output stream format (ts, m3u8).

    Returns:
        Redirect to HLS proxy with upstream get.php URL.
    """
    upstream_base, actual_username, api_password = parse_username_with_upstream(username)
    verify_xc_api_password(api_password)

    # Build query params for upstream get.php
    query_params = {"username": actual_username, "password": password, "type": type, "output": output}
    for k, v in request.query_params.items():
        if k not in ("username", "password", "type", "output", "api_password"):
            query_params[k] = v

    upstream_url = f"{upstream_base}get.php?{urlencode(query_params)}"

    logger.info(f"XC get.php: type={type}, output={output}, upstream={upstream_base}, user={actual_username}")

    # Redirect to HLS proxy which handles M3U URL rewriting
    mediaflow_base = get_mediaflow_base_url(request)
    hls_params = {"d": upstream_url}
    if api_password:
        hls_params["api_password"] = api_password

    redirect_url = f"{mediaflow_base}/proxy/hls/manifest.m3u8?{urlencode(hls_params)}"
    return RedirectResponse(url=redirect_url, status_code=302)


@xtream_root_router.get("/panel_api.php")
async def panel_api(
    request: Request,
    username: str = Query(..., description="Format: {base64_upstream}:{actual_username}:{api_password}"),
    password: str = Query(..., description="XC password"),
):
    """
    Panel API endpoint (alternative API used by some XC implementations).

    Args:
        request: The incoming FastAPI request.
        username: Combined upstream URL, username, and API password.
        password: XC password.

    Returns:
        The API response with stream URLs rewritten.
    """
    upstream_base, actual_username, api_password = parse_username_with_upstream(username)
    verify_xc_api_password(api_password)

    query_params = {"username": actual_username, "password": password}
    for k, v in request.query_params.items():
        if k not in ("username", "password", "api_password"):
            query_params[k] = v

    upstream_url = f"{upstream_base}panel_api.php?{urlencode(query_params)}"

    logger.info(f"XC panel_api.php: upstream={upstream_base}")
    return await forward_api_request(upstream_url, request, upstream_base, actual_username, api_password)


# =============================================================================
# Stream Proxy Endpoints
# =============================================================================


@xtream_root_router.head("/live/{username}/{password}/{stream_id}.{ext}")
@xtream_root_router.get("/live/{username}/{password}/{stream_id}.{ext}")
async def live_stream(
    username: str,
    password: str,
    stream_id: str,
    ext: str,
    request: Request,
    proxy_headers: Annotated[ProxyRequestHeaders, Depends(get_proxy_headers)],
):
    """
    Live stream endpoint.

    Username format: {base64_upstream}:{actual_username}:{api_password}
    """
    upstream_base, actual_username, api_password = parse_username_with_upstream(username)
    verify_xc_api_password(api_password)

    stream_path = f"live/{actual_username}/{password}/{stream_id}.{ext}"
    upstream_url = urljoin(upstream_base, stream_path)

    logger.info(f"XC live stream: {stream_path}")

    # For m3u8, redirect to HLS proxy
    if ext in ("m3u8", "m3u"):
        scheme = request.headers.get("x-forwarded-proto", request.url.scheme)
        host = request.headers.get("x-forwarded-host", request.headers.get("host", request.url.netloc))
        hls_params = {"d": upstream_url}
        if api_password:
            hls_params["api_password"] = api_password
        redirect_url = f"{scheme}://{host}/proxy/hls/manifest.m3u8?{urlencode(hls_params)}"
        return RedirectResponse(url=redirect_url, status_code=302)

    return await proxy_stream(request.method, upstream_url, proxy_headers)


@xtream_root_router.head("/movie/{username}/{password}/{stream_id}.{ext}")
@xtream_root_router.get("/movie/{username}/{password}/{stream_id}.{ext}")
async def movie_stream(
    username: str,
    password: str,
    stream_id: str,
    ext: str,
    request: Request,
    proxy_headers: Annotated[ProxyRequestHeaders, Depends(get_proxy_headers)],
    transcode: bool = Query(False, description="Transcode to browser-compatible fMP4"),
    hls: bool = Query(False, description="Generate HLS VOD playlist for transcode (seekable)"),
    hls_init: bool = Query(False, description="Serve fMP4 init segment"),
    seg: int | None = Query(None, description="HLS segment number (informational)"),
    start_ms: float | None = Query(None, description="HLS segment start time in milliseconds"),
    end_ms: float | None = Query(None, description="HLS segment end time in milliseconds"),
    start: float | None = Query(None, description="Seek start time in seconds (transcode mode)"),
):
    """
    VOD/movie stream endpoint.
    """
    upstream_base, actual_username, api_password = parse_username_with_upstream(username)
    verify_xc_api_password(api_password)

    stream_path = f"movie/{actual_username}/{password}/{stream_id}.{ext}"
    upstream_url = urljoin(upstream_base, stream_path)

    logger.info(f"XC movie stream: {stream_path}")

    if hls:
        return await _handle_xtream_hls_playlist(request, upstream_url, proxy_headers)
    if hls_init:
        return await _handle_xtream_hls_init(request, upstream_url, proxy_headers)
    if (start_ms is None) != (end_ms is None):
        raise HTTPException(status_code=400, detail="Both start_ms and end_ms are required for segment requests")
    if start_ms is not None and end_ms is not None:
        return await _handle_xtream_hls_segment(request, upstream_url, proxy_headers, start_ms, end_ms, seg)
    if transcode:
        return await _handle_xtream_transcode(request, upstream_url, proxy_headers, start)

    return await proxy_stream(request.method, upstream_url, proxy_headers)


@xtream_root_router.head("/series/{username}/{password}/{stream_id}.{ext}")
@xtream_root_router.get("/series/{username}/{password}/{stream_id}.{ext}")
async def series_stream(
    username: str,
    password: str,
    stream_id: str,
    ext: str,
    request: Request,
    proxy_headers: Annotated[ProxyRequestHeaders, Depends(get_proxy_headers)],
    transcode: bool = Query(False, description="Transcode to browser-compatible fMP4"),
    hls: bool = Query(False, description="Generate HLS VOD playlist for transcode (seekable)"),
    hls_init: bool = Query(False, description="Serve fMP4 init segment"),
    seg: int | None = Query(None, description="HLS segment number (informational)"),
    start_ms: float | None = Query(None, description="HLS segment start time in milliseconds"),
    end_ms: float | None = Query(None, description="HLS segment end time in milliseconds"),
    start: float | None = Query(None, description="Seek start time in seconds (transcode mode)"),
):
    """
    Series/episode stream endpoint.
    """
    upstream_base, actual_username, api_password = parse_username_with_upstream(username)
    verify_xc_api_password(api_password)

    stream_path = f"series/{actual_username}/{password}/{stream_id}.{ext}"
    upstream_url = urljoin(upstream_base, stream_path)

    logger.info(f"XC series stream: {stream_path}")

    if hls:
        return await _handle_xtream_hls_playlist(request, upstream_url, proxy_headers)
    if hls_init:
        return await _handle_xtream_hls_init(request, upstream_url, proxy_headers)
    if (start_ms is None) != (end_ms is None):
        raise HTTPException(status_code=400, detail="Both start_ms and end_ms are required for segment requests")
    if start_ms is not None and end_ms is not None:
        return await _handle_xtream_hls_segment(request, upstream_url, proxy_headers, start_ms, end_ms, seg)
    if transcode:
        return await _handle_xtream_transcode(request, upstream_url, proxy_headers, start)

    return await proxy_stream(request.method, upstream_url, proxy_headers)


@xtream_root_router.head("/timeshift/{username}/{password}/{duration}/{start}/{stream_id}.{ext}")
@xtream_root_router.get("/timeshift/{username}/{password}/{duration}/{start}/{stream_id}.{ext}")
async def timeshift_stream(
    username: str,
    password: str,
    duration: str,
    start: str,
    stream_id: str,
    ext: str,
    request: Request,
    proxy_headers: Annotated[ProxyRequestHeaders, Depends(get_proxy_headers)],
    transcode: bool = Query(False, description="Transcode to browser-compatible fMP4"),
    seek: float | None = Query(None, description="Seek start time in seconds (transcode mode)"),
):
    """
    Timeshift/catch-up stream endpoint.
    """
    upstream_base, actual_username, api_password = parse_username_with_upstream(username)
    verify_xc_api_password(api_password)

    stream_path = f"timeshift/{actual_username}/{password}/{duration}/{start}/{stream_id}.{ext}"
    upstream_url = urljoin(upstream_base, stream_path)

    logger.info(f"XC timeshift stream: {stream_path}")

    if transcode:
        return await _handle_xtream_transcode(request, upstream_url, proxy_headers, seek)

    return await proxy_stream(request.method, upstream_url, proxy_headers)


@xtream_root_router.head("/streaming/timeshift.php")
@xtream_root_router.get("/streaming/timeshift.php")
async def timeshift_php(
    request: Request,
    proxy_headers: Annotated[ProxyRequestHeaders, Depends(get_proxy_headers)],
    username: str = Query(..., description="Format: {base64_upstream}:{actual_username}:{api_password}"),
    password: str = Query(..., description="XC password"),
    stream: str = Query(..., description="Stream ID"),
    start: str = Query(..., description="Start time"),
    duration: str = Query(None, description="Duration in minutes"),
):
    """
    Timeshift.php catch-up endpoint (alternative format).
    """
    upstream_base, actual_username, api_password = parse_username_with_upstream(username)
    verify_xc_api_password(api_password)

    # Build query params for upstream
    query_params = {"username": actual_username, "password": password, "stream": stream, "start": start}
    if duration:
        query_params["duration"] = duration
    for k, v in request.query_params.items():
        if k not in ("username", "password", "stream", "start", "duration", "api_password"):
            query_params[k] = v

    upstream_url = f"{upstream_base}streaming/timeshift.php?{urlencode(query_params)}"

    logger.info(f"XC timeshift.php: stream={stream}, start={start}")

    return await proxy_stream(request.method, upstream_url, proxy_headers)


@xtream_root_router.head("/hlsr/{token}/{username}/{password}/{channel_id}/{start}/{end}/index.m3u8")
@xtream_root_router.get("/hlsr/{token}/{username}/{password}/{channel_id}/{start}/{end}/index.m3u8")
async def hlsr_catchup(
    token: str,
    username: str,
    password: str,
    channel_id: str,
    start: str,
    end: str,
    request: Request,
    proxy_headers: Annotated[ProxyRequestHeaders, Depends(get_proxy_headers)],
):
    """
    HLSR catch-up stream endpoint.
    """
    upstream_base, actual_username, api_password = parse_username_with_upstream(username)
    verify_xc_api_password(api_password)

    stream_path = f"hlsr/{token}/{actual_username}/{password}/{channel_id}/{start}/{end}/index.m3u8"
    upstream_url = urljoin(upstream_base, stream_path)

    logger.info(f"XC HLSR catch-up: channel={channel_id}")

    # Redirect to HLS proxy for proper m3u8 handling
    scheme = request.headers.get("x-forwarded-proto", request.url.scheme)
    host = request.headers.get("x-forwarded-host", request.headers.get("host", request.url.netloc))
    hls_params = {"d": upstream_url}
    if api_password:
        hls_params["api_password"] = api_password
    redirect_url = f"{scheme}://{host}/proxy/hls/manifest.m3u8?{urlencode(hls_params)}"
    return RedirectResponse(url=redirect_url, status_code=302)


@xtream_root_router.head("/hls/{token}/{stream_id}.m3u8")
@xtream_root_router.get("/hls/{token}/{stream_id}.m3u8")
async def hls_stream(
    token: str,
    stream_id: str,
    request: Request,
    proxy_headers: Annotated[ProxyRequestHeaders, Depends(get_proxy_headers)],
):
    """
    HLS stream endpoint with token authentication.

    Note: This endpoint doesn't use the username format since it's token-based.
    The api_password should be passed as a query parameter if required.
    """
    # For token-based HLS, check api_password from query params
    api_password = request.query_params.get("api_password")
    if settings.api_password and api_password != settings.api_password:
        raise HTTPException(status_code=403, detail="Invalid API password")

    # Get upstream from query params (must be base64-encoded)
    upstream_encoded = request.query_params.get("upstream")
    if not upstream_encoded:
        raise HTTPException(status_code=400, detail="Missing 'upstream' query parameter")

    upstream_base = decode_upstream_url(upstream_encoded)
    stream_path = f"hls/{token}/{stream_id}.m3u8"
    upstream_url = urljoin(upstream_base, stream_path)

    logger.info(f"XC HLS stream: {stream_path}")

    # Redirect to HLS proxy
    scheme = request.headers.get("x-forwarded-proto", request.url.scheme)
    host = request.headers.get("x-forwarded-host", request.headers.get("host", request.url.netloc))
    hls_params = {"d": upstream_url}
    if api_password:
        hls_params["api_password"] = api_password
    redirect_url = f"{scheme}://{host}/proxy/hls/manifest.m3u8?{urlencode(hls_params)}"
    return RedirectResponse(url=redirect_url, status_code=302)


@xtream_root_router.head("/{username}/{password}/{stream_id}.{ext}")
@xtream_root_router.get("/{username}/{password}/{stream_id}.{ext}")
async def live_stream_short(
    username: str,
    password: str,
    stream_id: str,
    ext: str,
    request: Request,
    proxy_headers: Annotated[ProxyRequestHeaders, Depends(get_proxy_headers)],
):
    """
    Short format live stream endpoint (without /live/ prefix).
    """
    upstream_base, actual_username, api_password = parse_username_with_upstream(username)
    verify_xc_api_password(api_password)

    stream_path = f"{actual_username}/{password}/{stream_id}.{ext}"
    upstream_url = urljoin(upstream_base, stream_path)

    logger.info(f"XC short live stream: {stream_path}")

    # For m3u8, redirect to HLS proxy
    if ext in ("m3u8", "m3u"):
        scheme = request.headers.get("x-forwarded-proto", request.url.scheme)
        host = request.headers.get("x-forwarded-host", request.headers.get("host", request.url.netloc))
        hls_params = {"d": upstream_url}
        if api_password:
            hls_params["api_password"] = api_password
        redirect_url = f"{scheme}://{host}/proxy/hls/manifest.m3u8?{urlencode(hls_params)}"
        return RedirectResponse(url=redirect_url, status_code=302)

    return await proxy_stream(request.method, upstream_url, proxy_headers)


# =============================================================================
# Stream Endpoints WITHOUT Extension (for players like IMPlayer)
# These handle URLs like /{username}/{password}/{stream_id} without .ts/.m3u8
# =============================================================================


@xtream_root_router.head("/live/{username}/{password}/{stream_id}")
@xtream_root_router.get("/live/{username}/{password}/{stream_id}")
async def live_stream_no_ext(
    username: str,
    password: str,
    stream_id: str,
    request: Request,
    proxy_headers: Annotated[ProxyRequestHeaders, Depends(get_proxy_headers)],
):
    """
    Live stream endpoint without extension (defaults to .ts).
    Some players like IMPlayer don't include the extension in stream URLs.
    """
    upstream_base, actual_username, api_password = parse_username_with_upstream(username)
    verify_xc_api_password(api_password)

    # Default to .ts format when no extension provided
    stream_path = f"live/{actual_username}/{password}/{stream_id}"
    upstream_url = urljoin(upstream_base, stream_path)

    logger.info(f"XC live stream (no ext): {stream_path}")

    return await proxy_stream(request.method, upstream_url, proxy_headers)


@xtream_root_router.head("/movie/{username}/{password}/{stream_id}")
@xtream_root_router.get("/movie/{username}/{password}/{stream_id}")
async def movie_stream_no_ext(
    username: str,
    password: str,
    stream_id: str,
    request: Request,
    proxy_headers: Annotated[ProxyRequestHeaders, Depends(get_proxy_headers)],
    transcode: bool = Query(False, description="Transcode to browser-compatible fMP4"),
    hls: bool = Query(False, description="Generate HLS VOD playlist for transcode (seekable)"),
    hls_init: bool = Query(False, description="Serve fMP4 init segment"),
    seg: int | None = Query(None, description="HLS segment number (informational)"),
    start_ms: float | None = Query(None, description="HLS segment start time in milliseconds"),
    end_ms: float | None = Query(None, description="HLS segment end time in milliseconds"),
    start: float | None = Query(None, description="Seek start time in seconds (transcode mode)"),
):
    """
    Movie stream endpoint without extension.
    """
    upstream_base, actual_username, api_password = parse_username_with_upstream(username)
    verify_xc_api_password(api_password)

    stream_path = f"movie/{actual_username}/{password}/{stream_id}"
    upstream_url = urljoin(upstream_base, stream_path)

    logger.info(f"XC movie stream (no ext): {stream_path}")

    if hls:
        return await _handle_xtream_hls_playlist(request, upstream_url, proxy_headers)
    if hls_init:
        return await _handle_xtream_hls_init(request, upstream_url, proxy_headers)
    if (start_ms is None) != (end_ms is None):
        raise HTTPException(status_code=400, detail="Both start_ms and end_ms are required for segment requests")
    if start_ms is not None and end_ms is not None:
        return await _handle_xtream_hls_segment(request, upstream_url, proxy_headers, start_ms, end_ms, seg)
    if transcode:
        return await _handle_xtream_transcode(request, upstream_url, proxy_headers, start)

    return await proxy_stream(request.method, upstream_url, proxy_headers)


@xtream_root_router.head("/series/{username}/{password}/{stream_id}")
@xtream_root_router.get("/series/{username}/{password}/{stream_id}")
async def series_stream_no_ext(
    username: str,
    password: str,
    stream_id: str,
    request: Request,
    proxy_headers: Annotated[ProxyRequestHeaders, Depends(get_proxy_headers)],
    transcode: bool = Query(False, description="Transcode to browser-compatible fMP4"),
    hls: bool = Query(False, description="Generate HLS VOD playlist for transcode (seekable)"),
    hls_init: bool = Query(False, description="Serve fMP4 init segment"),
    seg: int | None = Query(None, description="HLS segment number (informational)"),
    start_ms: float | None = Query(None, description="HLS segment start time in milliseconds"),
    end_ms: float | None = Query(None, description="HLS segment end time in milliseconds"),
    start: float | None = Query(None, description="Seek start time in seconds (transcode mode)"),
):
    """
    Series stream endpoint without extension.
    """
    upstream_base, actual_username, api_password = parse_username_with_upstream(username)
    verify_xc_api_password(api_password)

    stream_path = f"series/{actual_username}/{password}/{stream_id}"
    upstream_url = urljoin(upstream_base, stream_path)

    logger.info(f"XC series stream (no ext): {stream_path}")

    if hls:
        return await _handle_xtream_hls_playlist(request, upstream_url, proxy_headers)
    if hls_init:
        return await _handle_xtream_hls_init(request, upstream_url, proxy_headers)
    if (start_ms is None) != (end_ms is None):
        raise HTTPException(status_code=400, detail="Both start_ms and end_ms are required for segment requests")
    if start_ms is not None and end_ms is not None:
        return await _handle_xtream_hls_segment(request, upstream_url, proxy_headers, start_ms, end_ms, seg)
    if transcode:
        return await _handle_xtream_transcode(request, upstream_url, proxy_headers, start)

    return await proxy_stream(request.method, upstream_url, proxy_headers)


@xtream_root_router.head("/{username}/{password}/{stream_id}")
@xtream_root_router.get("/{username}/{password}/{stream_id}")
async def live_stream_short_no_ext(
    username: str,
    password: str,
    stream_id: str,
    request: Request,
    proxy_headers: Annotated[ProxyRequestHeaders, Depends(get_proxy_headers)],
):
    """
    Short format live stream endpoint without extension (without /live/ prefix).
    Some players like IMPlayer use this format without extension.
    """
    upstream_base, actual_username, api_password = parse_username_with_upstream(username)
    verify_xc_api_password(api_password)

    stream_path = f"{actual_username}/{password}/{stream_id}"
    upstream_url = urljoin(upstream_base, stream_path)

    logger.info(f"XC short live stream (no ext): {stream_path}")

    return await proxy_stream(request.method, upstream_url, proxy_headers)
