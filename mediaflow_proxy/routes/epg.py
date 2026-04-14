"""
EPG Proxy — XMLTV/EPG pass-through with caching.

Supports Channels DVR, Plex, Emby, and any XMLTV-compatible EPG client.

Usage:
    GET /proxy/epg?d=<epg_url>&api_password=<key>

With custom headers for protected sources:
    GET /proxy/epg?d=<url>&h_Authorization=Bearer+<token>&api_password=<key>

With cache TTL override:
    GET /proxy/epg?d=<url>&cache_ttl=7200&api_password=<key>
"""

import hashlib
import logging
import time
from typing import Optional

import aiohttp
from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import Response

from mediaflow_proxy.configs import settings
from mediaflow_proxy.utils.base64_utils import process_potential_base64_url
from mediaflow_proxy.utils.http_client import create_aiohttp_session

logger = logging.getLogger(__name__)
epg_router = APIRouter()

# In-memory EPG cache: {cache_key: (content_bytes, content_type, fetch_timestamp)}
# EPG data rarely changes; default TTL is 1 hour.
_epg_cache: dict[str, tuple[bytes, str, float]] = {}


def _get_cached_epg(cache_key: str, ttl: int) -> Optional[tuple[bytes, str]]:
    """Return (content, content_type) from cache if the entry exists and has not expired."""
    entry = _epg_cache.get(cache_key)
    if entry is None:
        return None
    content, content_type, ts = entry
    if time.monotonic() - ts < ttl:
        return content, content_type
    # Expired — evict lazily
    del _epg_cache[cache_key]
    return None


def _set_cached_epg(cache_key: str, content: bytes, content_type: str) -> None:
    _epg_cache[cache_key] = (content, content_type, time.monotonic())


def _build_cache_key(destination: str, request_headers: dict[str, str]) -> str:
    """
    Incorporate auth-bearing headers into the cache key so that different
    credentials don't serve each other's cached EPG data.
    """
    if not request_headers:
        return destination
    header_hash = hashlib.md5(str(sorted(request_headers.items())).encode()).hexdigest()[:8]
    return f"{destination}|{header_hash}"


@epg_router.get("/epg")
@epg_router.head("/epg")
async def epg_proxy(
    request: Request,
    destination: str = Query(
        ...,
        alias="d",
        description="URL of the XMLTV/EPG source. Supports plain URLs and base64-encoded URLs.",
    ),
    cache_ttl: Optional[int] = Query(
        None,
        description=(
            "Cache lifetime in seconds. 0 disables caching. Defaults to the EPG_CACHE_TTL setting (3600 s = 1 h)."
        ),
    ),
):
    """
    Proxy EPG / XMLTV data from any upstream source with optional caching.

    **Channels DVR setup:** enter this URL as your custom EPG source:

        http://<proxy-host>:<port>/proxy/epg?d=<epg_url>&api_password=<key>

    **Protected EPG sources** — pass authentication via `h_` header params:

        ?d=<url>&h_Authorization=Bearer+<token>&api_password=<key>

    Base64-encoded destination URLs are automatically decoded.

    Returns the XMLTV XML with `Content-Type: application/xml`.
    """
    # Resolve base64-encoded destination URLs
    destination = process_potential_base64_url(destination)

    if not destination.startswith(("http://", "https://")):
        raise HTTPException(
            status_code=400,
            detail="Destination must be an http:// or https:// URL.",
        )

    # Collect upstream request headers from h_<name> query params
    request_headers: dict[str, str] = {
        key[2:]: value for key, value in request.query_params.items() if key.startswith("h_")
    }

    # Effective TTL — per-request override or global config
    effective_ttl: int = cache_ttl if cache_ttl is not None else settings.epg_cache_ttl
    cache_key = _build_cache_key(destination, request_headers)

    # --- Cache read -------------------------------------------------------
    if effective_ttl > 0:
        cached = _get_cached_epg(cache_key, effective_ttl)
        if cached is not None:
            content, content_type = cached
            logger.debug("[epg_proxy] Cache HIT: %s", destination)
            if request.method == "HEAD":
                return Response(
                    status_code=200,
                    headers={
                        "Content-Type": content_type,
                        "Content-Length": str(len(content)),
                        "X-EPG-Cache": "HIT",
                        "Cache-Control": f"public, max-age={effective_ttl}",
                    },
                )
            return Response(
                content=content,
                media_type=content_type,
                headers={
                    "X-EPG-Cache": "HIT",
                    "Cache-Control": f"public, max-age={effective_ttl}",
                },
            )

    # --- Upstream fetch ---------------------------------------------------
    logger.info("[epg_proxy] Fetching EPG from: %s", destination)

    async with create_aiohttp_session(destination, timeout=120) as (session, proxy_url):
        try:
            async with session.get(
                destination,
                headers=request_headers,
                proxy=proxy_url,
                allow_redirects=True,
            ) as response:
                response.raise_for_status()
                content = await response.read()
                content_type = response.headers.get("content-type", "application/xml; charset=utf-8")

                # Normalise to XML content type if upstream returns something unexpected
                if not any(t in content_type.lower() for t in ("xml", "text")):
                    content_type = "application/xml; charset=utf-8"

                if effective_ttl > 0:
                    _set_cached_epg(cache_key, content, content_type)
                    logger.info(
                        "[epg_proxy] Cached %d bytes from %s (TTL=%ds)",
                        len(content),
                        destination,
                        effective_ttl,
                    )

                if request.method == "HEAD":
                    return Response(
                        status_code=200,
                        headers={
                            "Content-Type": content_type,
                            "Content-Length": str(len(content)),
                            "X-EPG-Cache": "MISS",
                            "Cache-Control": f"public, max-age={effective_ttl}",
                        },
                    )
                return Response(
                    content=content,
                    media_type=content_type,
                    headers={
                        "X-EPG-Cache": "MISS",
                        "Cache-Control": f"public, max-age={effective_ttl}",
                    },
                )

        except aiohttp.ClientResponseError as e:
            logger.warning("[epg_proxy] Upstream HTTP %s for %s", e.status, destination)
            raise HTTPException(
                status_code=e.status,
                detail=f"Upstream EPG error: HTTP {e.status}",
            )
        except aiohttp.ClientConnectorError as e:
            logger.error("[epg_proxy] Cannot connect to %s: %s", destination, e)
            raise HTTPException(
                status_code=502,
                detail=f"Cannot connect to EPG source: {e}",
            )
        except TimeoutError:
            logger.error("[epg_proxy] Timeout fetching %s", destination)
            raise HTTPException(status_code=504, detail="EPG source timed out")
        except aiohttp.ClientError as e:
            logger.error("[epg_proxy] Fetch error for %s: %s", destination, e)
            raise HTTPException(status_code=502, detail=f"EPG fetch failed: {e}")
