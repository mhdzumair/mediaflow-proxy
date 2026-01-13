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

import logging
from typing import Annotated
from urllib.parse import urljoin, urlencode, urlparse

from fastapi.responses import RedirectResponse
import httpx
from fastapi import APIRouter, Request, Depends, Query, Response, HTTPException

from mediaflow_proxy.configs import settings
from mediaflow_proxy.handlers import proxy_stream
from mediaflow_proxy.utils.base64_utils import decode_base64_url
from mediaflow_proxy.utils.http_utils import (
    ProxyRequestHeaders,
    get_proxy_headers,
    create_httpx_client,
)

logger = logging.getLogger(__name__)
xtream_root_router = APIRouter()


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


def parse_username_with_upstream(username: str) -> tuple[str, str, str | None]:
    """
    Parse username that contains encoded upstream URL and optional API password.

    Username format: {base64_upstream}:{actual_username}:{api_password}
    Or without API password: {base64_upstream}:{actual_username}

    Args:
        username: The username field which contains upstream URL and optionally API password.

    Returns:
        Tuple of (upstream_base_url, actual_username, api_password or None).

    Raises:
        HTTPException: If format is invalid.
    """
    if ":" not in username:
        raise HTTPException(
            status_code=400,
            detail="Invalid username format. Expected: {base64_upstream}:{actual_username} or {base64_upstream}:{actual_username}:{api_password}",
        )

    parts = username.split(":")

    if len(parts) == 2:
        # Format: {base64_upstream}:{actual_username}
        upstream_encoded, actual_username = parts
        api_password = None
    elif len(parts) == 3:
        # Format: {base64_upstream}:{actual_username}:{api_password}
        upstream_encoded, actual_username, api_password = parts
    else:
        raise HTTPException(
            status_code=400,
            detail="Invalid username format. Expected: {base64_upstream}:{actual_username} or {base64_upstream}:{actual_username}:{api_password}",
        )

    upstream_base = decode_upstream_url(upstream_encoded)

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


def rewrite_urls_for_api(
    content: str,
    upstream_base: str,
    mediaflow_base: str,
) -> str:
    """
    Rewrite stream URLs in API responses to route through MediaFlow.

    Args:
        content: The API response content.
        upstream_base: The upstream XC server base URL.
        mediaflow_base: The MediaFlow base URL.

    Returns:
        The content with rewritten URLs.
    """
    # Parse the upstream URL to get the origin for replacement
    parsed = urlparse(upstream_base)
    upstream_origin = f"{parsed.scheme}://{parsed.netloc}"

    # Replace upstream URLs with MediaFlow URLs
    content = content.replace(upstream_origin, mediaflow_base)

    # Also handle escaped URLs in JSON
    escaped_origin = upstream_origin.replace("/", "\\/")
    escaped_mediaflow = mediaflow_base.replace("/", "\\/")
    content = content.replace(escaped_origin, escaped_mediaflow)

    return content


async def forward_api_request(
    upstream_url: str,
    request: Request,
    upstream_base: str,
) -> Response:
    """
    Forward an API request to upstream XC server.

    Args:
        upstream_url: The full upstream URL.
        request: The incoming FastAPI request.
        upstream_base: The decoded upstream base URL.

    Returns:
        The response from upstream with URLs rewritten.
    """
    mediaflow_base = get_mediaflow_base_url(request)

    async with create_httpx_client(follow_redirects=True) as client:
        try:
            response = await client.get(upstream_url)
            response.raise_for_status()

            content = response.text
            content_type = response.headers.get("content-type", "application/json")

            # Rewrite URLs in JSON responses
            if "json" in content_type.lower():
                content = rewrite_urls_for_api(content, upstream_base, mediaflow_base)

            return Response(
                content=content,
                status_code=response.status_code,
                media_type=content_type,
            )
        except httpx.HTTPStatusError as e:
            logger.error(f"Upstream XC API error: {e.response.status_code}")
            raise HTTPException(
                status_code=e.response.status_code,
                detail=f"Upstream XC server error: {e.response.status_code}",
            )
        except httpx.RequestError as e:
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

    return await forward_api_request(upstream_url, request, upstream_base)


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

    async with create_httpx_client(follow_redirects=True, timeout=httpx.Timeout(60.0)) as client:
        try:
            response = await client.get(upstream_url)
            response.raise_for_status()

            return Response(
                content=response.content,
                status_code=response.status_code,
                media_type=response.headers.get("content-type", "application/xml"),
            )
        except httpx.HTTPStatusError as e:
            raise HTTPException(status_code=e.response.status_code, detail=f"Upstream error: {e.response.status_code}")
        except httpx.RequestError as e:
            raise HTTPException(status_code=502, detail=f"Failed to connect: {str(e)}")


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
    return await forward_api_request(upstream_url, request, upstream_base)


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
):
    """
    VOD/movie stream endpoint.
    """
    upstream_base, actual_username, api_password = parse_username_with_upstream(username)
    verify_xc_api_password(api_password)

    stream_path = f"movie/{actual_username}/{password}/{stream_id}.{ext}"
    upstream_url = urljoin(upstream_base, stream_path)

    logger.info(f"XC movie stream: {stream_path}")
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
):
    """
    Series/episode stream endpoint.
    """
    upstream_base, actual_username, api_password = parse_username_with_upstream(username)
    verify_xc_api_password(api_password)

    stream_path = f"series/{actual_username}/{password}/{stream_id}.{ext}"
    upstream_url = urljoin(upstream_base, stream_path)

    logger.info(f"XC series stream: {stream_path}")
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
):
    """
    Timeshift/catch-up stream endpoint.
    """
    upstream_base, actual_username, api_password = parse_username_with_upstream(username)
    verify_xc_api_password(api_password)

    stream_path = f"timeshift/{actual_username}/{password}/{duration}/{start}/{stream_id}.{ext}"
    upstream_url = urljoin(upstream_base, stream_path)

    logger.info(f"XC timeshift stream: {stream_path}")
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
