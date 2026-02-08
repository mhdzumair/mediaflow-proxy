import re
import logging

from typing import Any, Dict, Optional
from urllib.parse import urlparse

import aiohttp

from mediaflow_proxy.extractors.base import BaseExtractor, ExtractorError, HttpResponse
from mediaflow_proxy.utils.http_client import create_aiohttp_session
from mediaflow_proxy.configs import settings


logger = logging.getLogger(__name__)

# Silenzia l'errore ConnectionResetError su Windows
logging.getLogger("asyncio").setLevel(logging.CRITICAL)


class DLHDExtractor(BaseExtractor):
    """DLHD (DaddyLive) URL extractor for M3U8 streams.


    Notes:
    - Multi-domain support for daddylive.sx / dlhd.dad
    - Robust extraction of auth parameters and server lookup
    - Uses retries/timeouts via BaseExtractor where possible
    - Multi-iframe fallback for resilience
    - Supports FlareSolverr for Cloudflare bypass
    """

    def __init__(self, request_headers: dict):
        super().__init__(request_headers)
        self.mediaflow_endpoint = "hls_manifest_proxy"
        self._iframe_context: Optional[str] = None
        self._flaresolverr_cookies: Optional[str] = None
        self._flaresolverr_user_agent: Optional[str] = None

    async def _fetch_via_flaresolverr(self, url: str) -> HttpResponse:
        """Fetch a URL using FlareSolverr to bypass Cloudflare protection."""
        if not settings.flaresolverr_url:
            raise ExtractorError("FlareSolverr URL not configured. Set FLARESOLVERR_URL in environment.")

        flaresolverr_endpoint = f"{settings.flaresolverr_url.rstrip('/')}/v1"
        payload = {
            "cmd": "request.get",
            "url": url,
            "maxTimeout": settings.flaresolverr_timeout * 1000,
        }

        logger.info(f"Using FlareSolverr to fetch: {url}")

        async with aiohttp.ClientSession() as session:
            async with session.post(
                flaresolverr_endpoint,
                json=payload,
                timeout=aiohttp.ClientTimeout(total=settings.flaresolverr_timeout + 10),
            ) as response:
                if response.status != 200:
                    raise ExtractorError(f"FlareSolverr returned status {response.status}")

                data = await response.json()

        if data.get("status") != "ok":
            raise ExtractorError(f"FlareSolverr failed: {data.get('message', 'Unknown error')}")

        solution = data.get("solution", {})
        html_content = solution.get("response", "")
        final_url = solution.get("url", url)
        status = solution.get("status", 200)

        # Store cookies and user-agent for subsequent requests
        cookies = solution.get("cookies", [])
        if cookies:
            cookie_str = "; ".join([f"{c['name']}={c['value']}" for c in cookies])
            self._flaresolverr_cookies = cookie_str
            logger.info(f"FlareSolverr provided {len(cookies)} cookies")

        user_agent = solution.get("userAgent")
        if user_agent:
            self._flaresolverr_user_agent = user_agent
            logger.info(f"FlareSolverr user-agent: {user_agent}")

        logger.info(f"FlareSolverr successfully bypassed Cloudflare for: {url}")

        return HttpResponse(
            status=status,
            headers={},
            text=html_content,
            content=html_content.encode("utf-8", errors="replace"),
            url=final_url,
        )

    async def _make_request(
        self, url: str, method: str = "GET", headers: Optional[Dict] = None, use_flaresolverr: bool = False, **kwargs
    ) -> HttpResponse:
        """Override to disable SSL verification and optionally use FlareSolverr."""
        # Use FlareSolverr for Cloudflare-protected pages
        if use_flaresolverr and settings.flaresolverr_url:
            return await self._fetch_via_flaresolverr(url)

        timeout = kwargs.pop("timeout", 15)
        kwargs.pop("retries", 3)  # consumed but not used directly
        kwargs.pop("backoff_factor", 0.5)  # consumed but not used directly

        # Merge headers
        request_headers = self.base_headers.copy()
        if headers:
            request_headers.update(headers)

        # Add FlareSolverr cookies if available
        if self._flaresolverr_cookies:
            existing_cookies = request_headers.get("Cookie", "")
            if existing_cookies:
                request_headers["Cookie"] = f"{existing_cookies}; {self._flaresolverr_cookies}"
            else:
                request_headers["Cookie"] = self._flaresolverr_cookies

        # Use FlareSolverr user-agent if available
        if self._flaresolverr_user_agent:
            request_headers["User-Agent"] = self._flaresolverr_user_agent

        # Use create_aiohttp_session with verify=False for SSL bypass
        async with create_aiohttp_session(url, timeout=timeout, verify=False) as (session, proxy_url):
            async with session.request(method, url, headers=request_headers, proxy=proxy_url, **kwargs) as response:
                content = await response.read()
                final_url = str(response.url)
                status = response.status
                resp_headers = dict(response.headers)

                if status >= 400:
                    raise ExtractorError(f"HTTP error {status} while requesting {url}")

                return HttpResponse(
                    status=status,
                    headers=resp_headers,
                    text=content.decode("utf-8", errors="replace"),
                    content=content,
                    url=final_url,
                )

    async def _extract_lovecdn_stream(self, iframe_url: str, iframe_content: str, headers: dict) -> Dict[str, Any]:
        """
        Estrattore alternativo per iframe lovecdn.ru che usa un formato diverso.
        """
        try:
            # Cerca pattern di stream URL diretto
            m3u8_patterns = [
                r'["\']([^"\']*\.m3u8[^"\']*)["\']',
                r'source[:\s]+["\']([^"\']+)["\']',
                r'file[:\s]+["\']([^"\']+\.m3u8[^"\']*)["\']',
                r'hlsManifestUrl[:\s]*["\']([^"\']+)["\']',
            ]

            stream_url = None
            for pattern in m3u8_patterns:
                matches = re.findall(pattern, iframe_content)
                for match in matches:
                    if ".m3u8" in match and match.startswith("http"):
                        stream_url = match
                        logger.info(f"Found direct m3u8 URL: {stream_url}")
                        break
                if stream_url:
                    break

            # Pattern 2: Cerca costruzione dinamica URL
            if not stream_url:
                channel_match = re.search(r'(?:stream|channel)["\s:=]+["\']([^"\']+)["\']', iframe_content)
                server_match = re.search(r'(?:server|domain|host)["\s:=]+["\']([^"\']+)["\']', iframe_content)

                if channel_match:
                    channel_name = channel_match.group(1)
                    server = server_match.group(1) if server_match else "newkso.ru"
                    stream_url = f"https://{server}/{channel_name}/mono.m3u8"
                    logger.info(f"Constructed stream URL: {stream_url}")

            if not stream_url:
                # Fallback: cerca qualsiasi URL che sembri uno stream
                url_pattern = r'https?://[^\s"\'<>]+\.m3u8[^\s"\'<>]*'
                matches = re.findall(url_pattern, iframe_content)
                if matches:
                    stream_url = matches[0]
                    logger.info(f"Found fallback stream URL: {stream_url}")

            if not stream_url:
                raise ExtractorError("Could not find stream URL in lovecdn.ru iframe")

            # Usa iframe URL come referer
            iframe_origin = f"https://{urlparse(iframe_url).netloc}"
            stream_headers = {"User-Agent": headers["User-Agent"], "Referer": iframe_url, "Origin": iframe_origin}

            # Determina endpoint in base al dominio dello stream
            endpoint = "hls_key_proxy"

            logger.info(f"Using lovecdn.ru stream with endpoint: {endpoint}")

            return {
                "destination_url": stream_url,
                "request_headers": stream_headers,
                "mediaflow_endpoint": endpoint,
            }

        except Exception as e:
            raise ExtractorError(f"Failed to extract lovecdn.ru stream: {e}")

    async def _extract_new_auth_flow(self, iframe_url: str, iframe_content: str, headers: dict) -> Dict[str, Any]:
        """Handles the new authentication flow found in recent updates."""

        def _extract_params(js: str) -> Dict[str, Optional[str]]:
            params = {}
            patterns = {
                "channel_key": r'(?:const|var|let)\s+(?:CHANNEL_KEY|channelKey)\s*=\s*["\']([^"\']+)["\']',
                "auth_token": r'(?:const|var|let)\s+AUTH_TOKEN\s*=\s*["\']([^"\']+)["\']',
                "auth_country": r'(?:const|var|let)\s+AUTH_COUNTRY\s*=\s*["\']([^"\']+)["\']',
                "auth_ts": r'(?:const|var|let)\s+AUTH_TS\s*=\s*["\']([^"\']+)["\']',
                "auth_expiry": r'(?:const|var|let)\s+AUTH_EXPIRY\s*=\s*["\']([^"\']+)["\']',
            }
            for key, pattern in patterns.items():
                match = re.search(pattern, js)
                params[key] = match.group(1) if match else None
            return params

        params = _extract_params(iframe_content)

        missing_params = [k for k, v in params.items() if not v]
        if missing_params:
            # This is not an error, just means it's not the new flow
            raise ExtractorError(f"Not the new auth flow: missing params {missing_params}")

        logger.info("New auth flow detected. Proceeding with POST auth.")

        # 1. Initial Auth POST
        auth_url = "https://security.newkso.ru/auth2.php"

        iframe_origin = f"https://{urlparse(iframe_url).netloc}"
        auth_headers = headers.copy()
        auth_headers.update(
            {
                "Accept": "*/*",
                "Accept-Language": "en-US,en;q=0.9",
                "Origin": iframe_origin,
                "Referer": iframe_url,
                "Sec-Fetch-Dest": "empty",
                "Sec-Fetch-Mode": "cors",
                "Sec-Fetch-Site": "cross-site",
                "Priority": "u=1, i",
            }
        )

        # Build form data for multipart/form-data
        form_data = aiohttp.FormData()
        form_data.add_field("channelKey", params["channel_key"])
        form_data.add_field("country", params["auth_country"])
        form_data.add_field("timestamp", params["auth_ts"])
        form_data.add_field("expiry", params["auth_expiry"])
        form_data.add_field("token", params["auth_token"])

        try:
            async with create_aiohttp_session(auth_url, timeout=12, verify=False) as (session, proxy_url):
                async with session.post(
                    auth_url,
                    headers=auth_headers,
                    data=form_data,
                    proxy=proxy_url,
                ) as response:
                    content = await response.read()
                    response.raise_for_status()
                    import json

                    auth_data = json.loads(content.decode("utf-8"))
                    if not (auth_data.get("valid") or auth_data.get("success")):
                        raise ExtractorError(f"Initial auth failed with response: {auth_data}")
            logger.info("New auth flow: Initial auth successful.")
        except ExtractorError:
            raise
        except Exception as e:
            raise ExtractorError(f"New auth flow failed during initial auth POST: {e}")

        # 2. Server Lookup
        server_lookup_url = f"https://{urlparse(iframe_url).netloc}/server_lookup.js?channel_id={params['channel_key']}"
        try:
            # Use _make_request as it handles retries
            lookup_resp = await self._make_request(server_lookup_url, headers=headers, timeout=10)
            server_data = lookup_resp.json()
            server_key = server_data.get("server_key")
            if not server_key:
                raise ExtractorError(f"No server_key in lookup response: {server_data}")
            logger.info(f"New auth flow: Server lookup successful - Server key: {server_key}")
        except ExtractorError:
            raise
        except Exception as e:
            raise ExtractorError(f"New auth flow failed during server lookup: {e}")

        # 3. Build final stream URL
        channel_key = params["channel_key"]
        auth_token = params["auth_token"]
        # The JS logic uses .css, not .m3u8
        if server_key == "top1/cdn":
            stream_url = f"https://top1.newkso.ru/top1/cdn/{channel_key}/mono.css"
        else:
            stream_url = f"https://{server_key}new.newkso.ru/{server_key}/{channel_key}/mono.css"

        logger.info(f"New auth flow: Constructed stream URL: {stream_url}")

        stream_headers = {
            "User-Agent": headers["User-Agent"],
            "Referer": iframe_url,
            "Origin": iframe_origin,
            "Authorization": f"Bearer {auth_token}",
            "X-Channel-Key": channel_key,
        }

        return {
            "destination_url": stream_url,
            "request_headers": stream_headers,
            "mediaflow_endpoint": "hls_manifest_proxy",
        }

    async def _extract_direct_stream(self, channel_id: str) -> Dict[str, Any]:
        """
        Direct stream extraction using server lookup API.
        This is the simpler, more reliable approach that bypasses iframe complexity.
        """
        channel_key = f"premium{channel_id}"
        server_lookup_url = f"https://chevy.dvalna.ru/server_lookup?channel_id={channel_key}"

        logger.info(f"Attempting direct stream extraction for channel: {channel_key}")

        try:
            # Get server key from lookup API
            lookup_resp = await self._make_request(server_lookup_url, timeout=10)
            server_data = lookup_resp.json()
            server_key = server_data.get("server_key")

            if not server_key:
                raise ExtractorError(f"No server_key in lookup response: {server_data}")

            logger.info(f"Server lookup successful - Server key: {server_key}")

            # Build stream URL based on server key
            # Pattern: https://{server_key}new.dvalna.ru/{server_key}/{channel_key}/mono.css
            stream_url = f"https://{server_key}new.dvalna.ru/{server_key}/{channel_key}/mono.css"

            logger.info(f"Constructed stream URL: {stream_url}")

            # The referer should be an iframe URL that would normally embed this stream
            iframe_referer = f"https://hitsplay.fun/premiumtv/daddyhd.php?id={channel_id}"

            stream_headers = {
                "User-Agent": self._flaresolverr_user_agent
                or "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
                "Referer": iframe_referer,
                "Origin": "https://hitsplay.fun",
            }

            # Use hls_key_proxy since the stream is AES-128 encrypted and needs key proxying
            return {
                "destination_url": stream_url,
                "request_headers": stream_headers,
                "mediaflow_endpoint": "hls_key_proxy",
            }

        except ExtractorError:
            raise
        except Exception as e:
            raise ExtractorError(f"Direct stream extraction failed: {e}")

    async def extract(self, url: str, **kwargs) -> Dict[str, Any]:
        """Main extraction flow - uses direct server lookup for simplicity and reliability."""

        def extract_channel_id(u: str) -> Optional[str]:
            match_watch_id = re.search(r"watch\.php\?id=(\d+)", u)
            if match_watch_id:
                return match_watch_id.group(1)
            return None

        try:
            channel_id = extract_channel_id(url)
            if not channel_id:
                raise ExtractorError(f"Unable to extract channel ID from {url}")

            logger.info(f"Extracting DLHD stream for channel ID: {channel_id}")

            # Try direct stream extraction first (simpler, more reliable)
            try:
                return await self._extract_direct_stream(channel_id)
            except ExtractorError as e:
                logger.warning(f"Direct stream extraction failed: {e}")

            # Fallback to legacy iframe-based extraction if direct fails
            logger.info("Falling back to iframe-based extraction...")
            return await self._extract_via_iframe(url, channel_id)

        except Exception as e:
            raise ExtractorError(f"Extraction failed: {str(e)}")

    async def _extract_via_iframe(self, url: str, channel_id: str) -> Dict[str, Any]:
        """Legacy iframe-based extraction flow - used as fallback."""
        baseurl = "https://dlhd.dad/"

        daddy_origin = urlparse(baseurl).scheme + "://" + urlparse(baseurl).netloc
        daddylive_headers = {
            "User-Agent": self._flaresolverr_user_agent
            or "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
            "Referer": baseurl,
            "Origin": daddy_origin,
        }

        # 1. Request initial page - use FlareSolverr if available to bypass Cloudflare
        use_flaresolverr = settings.flaresolverr_url is not None
        resp1 = await self._make_request(url, headers=daddylive_headers, timeout=15, use_flaresolverr=use_flaresolverr)
        resp1_text = resp1.text

        # Update headers with FlareSolverr user-agent after initial request
        if self._flaresolverr_user_agent:
            daddylive_headers["User-Agent"] = self._flaresolverr_user_agent

        player_links = re.findall(r'<button[^>]*data-url="([^"]+)"[^>]*>Player\s*\d+</button>', resp1_text)
        if not player_links:
            raise ExtractorError("No player links found on the page.")

        # Prova tutti i player e raccogli tutti gli iframe validi
        last_player_error = None
        iframe_candidates = []

        for player_url in player_links:
            try:
                if not player_url.startswith("http"):
                    player_url = baseurl + player_url.lstrip("/")

                daddylive_headers["Referer"] = player_url
                daddylive_headers["Origin"] = player_url
                resp2 = await self._make_request(player_url, headers=daddylive_headers, timeout=12)
                resp2_text = resp2.text
                iframes2 = re.findall(r'<iframe.*?src="([^"]*)"', resp2_text)

                # Raccogli tutti gli iframe trovati
                for iframe in iframes2:
                    if iframe not in iframe_candidates:
                        iframe_candidates.append(iframe)
                        logger.info(f"Found iframe candidate: {iframe}")

            except Exception as e:
                last_player_error = e
                logger.warning(f"Failed to process player link {player_url}: {e}")
                continue

        if not iframe_candidates:
            if last_player_error:
                raise ExtractorError(f"All player links failed. Last error: {last_player_error}")
            raise ExtractorError("No valid iframe found in any player page")

        # Try each iframe until one works
        last_iframe_error = None

        for iframe_candidate in iframe_candidates:
            try:
                logger.info(f"Trying iframe: {iframe_candidate}")

                iframe_domain = urlparse(iframe_candidate).netloc
                if not iframe_domain:
                    logger.warning(f"Invalid iframe URL format: {iframe_candidate}")
                    continue

                self._iframe_context = iframe_candidate
                resp3 = await self._make_request(iframe_candidate, headers=daddylive_headers, timeout=12)
                iframe_content = resp3.text
                logger.info(f"Successfully loaded iframe from: {iframe_domain}")

                if "lovecdn.ru" in iframe_domain:
                    logger.info("Detected lovecdn.ru iframe - using alternative extraction")
                    return await self._extract_lovecdn_stream(iframe_candidate, iframe_content, daddylive_headers)
                else:
                    logger.info("Attempting new auth flow extraction.")
                    return await self._extract_new_auth_flow(iframe_candidate, iframe_content, daddylive_headers)

            except Exception as e:
                logger.warning(f"Failed to process iframe {iframe_candidate}: {e}")
                last_iframe_error = e
                continue

        raise ExtractorError(f"All iframe candidates failed. Last error: {last_iframe_error}")
