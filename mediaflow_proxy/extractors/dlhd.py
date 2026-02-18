import hashlib
import hmac
import re
import time
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

# Default fingerprint parameters
DEFAULT_DLHD_USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64; rv:146.0) Gecko/20100101 Firefox/146.0"
DEFAULT_DLHD_SCREEN_RESOLUTION = "1920x1080"
DEFAULT_DLHD_TIMEZONE = "UTC"
DEFAULT_DLHD_LANGUAGE = "en"


def compute_fingerprint(
    user_agent: str = DEFAULT_DLHD_USER_AGENT,
    screen_resolution: str = DEFAULT_DLHD_SCREEN_RESOLUTION,
    timezone: str = DEFAULT_DLHD_TIMEZONE,
    language: str = DEFAULT_DLHD_LANGUAGE,
) -> str:
    """
    Compute the X-Fingerprint header value.

    Algorithm:
    fingerprint = SHA256(useragent + screen_resolution + timezone + language).hex()[:16]

    Args:
        user_agent: The user agent string
        screen_resolution: The screen resolution (e.g., "1920x1080")
        timezone: The timezone (e.g., "UTC")
        language: The language code (e.g., "en")

    Returns:
        The 16-character fingerprint
    """
    combined = f"{user_agent}{screen_resolution}{timezone}{language}"
    return hashlib.sha256(combined.encode("utf-8")).hexdigest()[:16]


def compute_key_path(resource: str, number: str, timestamp: int, fingerprint: str, secret_key: str) -> str:
    """
    Compute the X-Key-Path header value.

    Algorithm:
    key_path = HMAC-SHA256("resource|number|timestamp|fingerprint", secret_key).hex()[:16]

    Args:
        resource: The resource from the key URL
        number: The number from the key URL
        timestamp: The Unix timestamp
        fingerprint: The fingerprint value
        secret_key: The HMAC secret key (channel_salt)

    Returns:
        The 16-character key path
    """
    combined = f"{resource}|{number}|{timestamp}|{fingerprint}"
    hmac_hash = hmac.new(secret_key.encode("utf-8"), combined.encode("utf-8"), hashlib.sha256).hexdigest()
    return hmac_hash[:16]


def compute_key_headers(key_url: str, secret_key: str) -> tuple[int, int, str, str] | None:
    """
    Compute X-Key-Timestamp, X-Key-Nonce, X-Key-Path, and X-Fingerprint for a /key/ URL.

    Algorithm:
    1. Extract resource and number from URL pattern /key/{resource}/{number}
    2. ts = Unix timestamp in seconds
    3. hmac_hash = HMAC-SHA256(resource, secret_key).hex()
    4. nonce = proof-of-work: find i where MD5(hmac+resource+number+ts+i)[:4] < 0x1000
    5. fingerprint = compute_fingerprint()
    6. key_path = HMAC-SHA256("resource|number|ts|fingerprint", secret_key).hex()[:16]

    Args:
        key_url: The key URL containing /key/{resource}/{number}
        secret_key: The HMAC secret key (channel_salt)

    Returns:
        Tuple of (timestamp, nonce, key_path, fingerprint) or None if URL doesn't match pattern
    """
    # Extract resource and number from URL
    pattern = r"/key/([^/]+)/(\d+)"
    match = re.search(pattern, key_url)

    if not match:
        return None

    resource = match.group(1)
    number = match.group(2)

    ts = int(time.time())

    # Compute HMAC-SHA256
    hmac_hash = hmac.new(secret_key.encode("utf-8"), resource.encode("utf-8"), hashlib.sha256).hexdigest()

    # Proof-of-work loop
    nonce = 0
    for i in range(100000):
        combined = f"{hmac_hash}{resource}{number}{ts}{i}"
        md5_hash = hashlib.md5(combined.encode("utf-8")).hexdigest()
        prefix_value = int(md5_hash[:4], 16)

        if prefix_value < 0x1000:  # < 4096
            nonce = i
            break

    fingerprint = compute_fingerprint()
    key_path = compute_key_path(resource, number, ts, fingerprint, secret_key)

    return ts, nonce, key_path, fingerprint


class DLHDExtractor(BaseExtractor):
    """DLHD (DaddyLive) URL extractor for M3U8 streams.

    Supports the new authentication flow with:
    - EPlayerAuth extraction (auth_token, channel_key, channel_salt)
    - Server lookup for dynamic server selection
    - Dynamic key header computation for AES-128 encrypted streams
    """

    def __init__(self, request_headers: dict):
        super().__init__(request_headers)
        self.mediaflow_endpoint = "hls_key_proxy"
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

    async def _extract_session_data(self, iframe_url: str, main_url: str) -> dict | None:
        """
        Fetch the iframe URL and extract auth_token, channel_key, and channel_salt.

        Args:
            iframe_url: The iframe URL to fetch
            main_url: The main site domain for Referer header

        Returns:
            Dict with auth_token, channel_key, channel_salt, or None if not found
        """
        headers = {
            "User-Agent": self._flaresolverr_user_agent or DEFAULT_DLHD_USER_AGENT,
            "Referer": f"https://{main_url}/",
        }

        try:
            resp = await self._make_request(iframe_url, headers=headers, timeout=12)
            html = resp.text
        except Exception as e:
            logger.warning(f"Error fetching iframe URL: {e}")
            return None

        # Pattern to extract EPlayerAuth.init block with authToken, channelKey, channelSalt
        # Matches: EPlayerAuth.init({ authToken: '...', channelKey: '...', ..., channelSalt: '...' });
        auth_pattern = r"EPlayerAuth\.init\s*\(\s*\{\s*authToken:\s*'([^']+)'"
        channel_key_pattern = r"channelKey:\s*'([^']+)'"
        channel_salt_pattern = r"channelSalt:\s*'([^']+)'"

        # Pattern to extract server lookup base URL from fetchWithRetry call
        lookup_pattern = r"fetchWithRetry\s*\(\s*'([^']+server_lookup\?channel_id=)"

        auth_match = re.search(auth_pattern, html)
        channel_key_match = re.search(channel_key_pattern, html)
        channel_salt_match = re.search(channel_salt_pattern, html)
        lookup_match = re.search(lookup_pattern, html)

        if auth_match and channel_key_match and channel_salt_match:
            result = {
                "auth_token": auth_match.group(1),
                "channel_key": channel_key_match.group(1),
                "channel_salt": channel_salt_match.group(1),
            }
            if lookup_match:
                result["server_lookup_url"] = lookup_match.group(1) + result["channel_key"]

            return result

        return None

    async def _get_server_key(self, server_lookup_url: str, iframe_url: str) -> str | None:
        """
        Fetch the server lookup URL and extract the server_key.

        Args:
            server_lookup_url: The server lookup URL
            iframe_url: The iframe URL for extracting the host for headers

        Returns:
            The server_key or None if not found
        """
        parsed = urlparse(iframe_url)
        iframe_host = parsed.netloc

        headers = {
            "User-Agent": self._flaresolverr_user_agent or DEFAULT_DLHD_USER_AGENT,
            "Referer": f"https://{iframe_host}/",
            "Origin": f"https://{iframe_host}",
        }

        try:
            resp = await self._make_request(server_lookup_url, headers=headers, timeout=10)
            data = resp.json()
            return data.get("server_key")
        except Exception as e:
            logger.warning(f"Error fetching server lookup: {e}")
            return None

    def _build_m3u8_url(self, server_key: str, channel_key: str) -> str:
        """
        Build the m3u8 URL based on the server_key.

        Args:
            server_key: The server key from server lookup
            channel_key: The channel key

        Returns:
            The m3u8 URL (with .css extension as per the original implementation)
        """
        if server_key == "top1/cdn":
            return f"https://top1.dvalna.ru/top1/cdn/{channel_key}/mono.css"
        else:
            return f"https://{server_key}new.dvalna.ru/{server_key}/{channel_key}/mono.css"

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

    async def _extract_lovecdn_stream(self, iframe_url: str, iframe_content: str, headers: dict) -> Dict[str, Any]:
        """
        Alternative extractor for lovecdn.ru iframe that uses a different format.
        """
        try:
            # Look for direct stream URL patterns
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

            # Pattern 2: Look for dynamic URL construction
            if not stream_url:
                channel_match = re.search(r'(?:stream|channel)["\s:=]+["\']([^"\']+)["\']', iframe_content)
                server_match = re.search(r'(?:server|domain|host)["\s:=]+["\']([^"\']+)["\']', iframe_content)

                if channel_match:
                    channel_name = channel_match.group(1)
                    server = server_match.group(1) if server_match else "newkso.ru"
                    stream_url = f"https://{server}/{channel_name}/mono.m3u8"
                    logger.info(f"Constructed stream URL: {stream_url}")

            if not stream_url:
                # Fallback: look for any URL that looks like a stream
                url_pattern = r'https?://[^\s"\'<>]+\.m3u8[^\s"\'<>]*'
                matches = re.findall(url_pattern, iframe_content)
                if matches:
                    stream_url = matches[0]
                    logger.info(f"Found fallback stream URL: {stream_url}")

            if not stream_url:
                raise ExtractorError("Could not find stream URL in lovecdn.ru iframe")

            # Use iframe URL as referer
            iframe_origin = f"https://{urlparse(iframe_url).netloc}"
            stream_headers = {"User-Agent": headers["User-Agent"], "Referer": iframe_url, "Origin": iframe_origin}

            # Determine endpoint based on the stream domain
            endpoint = "hls_key_proxy"

            logger.info(f"Using lovecdn.ru stream with endpoint: {endpoint}")

            return {
                "destination_url": stream_url,
                "request_headers": stream_headers,
                "mediaflow_endpoint": endpoint,
            }

        except Exception as e:
            raise ExtractorError(f"Failed to extract lovecdn.ru stream: {e}")

    async def _extract_direct_stream(self, channel_id: str) -> Dict[str, Any]:
        """
        Direct stream extraction using server lookup API with the new auth flow.
        This extracts auth_token, channel_key, channel_salt and computes key headers.
        """
        # Common iframe domains for DLHD
        iframe_domains = ["lefttoplay.xyz"]

        for iframe_domain in iframe_domains:
            try:
                iframe_url = f"https://{iframe_domain}/premiumtv/daddyhd.php?id={channel_id}"
                logger.info(f"Attempting extraction via {iframe_domain}")

                session_data = await self._extract_session_data(iframe_url, "dlhd.link")

                if not session_data:
                    logger.debug(f"No session data from {iframe_domain}")
                    continue

                logger.info(f"Got session data from {iframe_domain}: channel_key={session_data['channel_key']}")

                # Get server key
                if "server_lookup_url" not in session_data:
                    logger.debug(f"No server lookup URL from {iframe_domain}")
                    continue

                server_key = await self._get_server_key(session_data["server_lookup_url"], iframe_url)

                if not server_key:
                    logger.debug(f"No server key from {iframe_domain}")
                    continue

                logger.info(f"Got server key: {server_key}")

                # Build m3u8 URL
                m3u8_url = self._build_m3u8_url(server_key, session_data["channel_key"])
                logger.info(f"M3U8 URL: {m3u8_url}")

                # Build stream headers with auth
                iframe_origin = f"https://{iframe_domain}"
                stream_headers = {
                    "User-Agent": self._flaresolverr_user_agent or DEFAULT_DLHD_USER_AGENT,
                    "Referer": iframe_url,
                    "Origin": iframe_origin,
                    "Authorization": f"Bearer {session_data['auth_token']}",
                }

                # Return the result with key header parameters
                # These will be used to compute headers when fetching keys
                return {
                    "destination_url": m3u8_url,
                    "request_headers": stream_headers,
                    "mediaflow_endpoint": "hls_key_proxy",
                    # Force playlist processing since DLHD uses .css extension for m3u8
                    "force_playlist_proxy": True,
                    # Key header computation parameters
                    "dlhd_key_params": {
                        "channel_salt": session_data["channel_salt"],
                        "auth_token": session_data["auth_token"],
                        "iframe_url": iframe_url,
                    },
                }

            except Exception as e:
                logger.warning(f"Failed extraction via {iframe_domain}: {e}")
                continue

        raise ExtractorError(f"Failed to extract stream from all iframe domains for channel {channel_id}")

    async def extract(self, url: str, **kwargs) -> Dict[str, Any]:
        """Main extraction flow - uses direct server lookup with new auth flow."""

        def extract_channel_id(u: str) -> Optional[str]:
            match_watch_id = re.search(r"watch\.php\?id=(\d+)", u)
            if match_watch_id:
                return match_watch_id.group(1)
            # Also try stream-XXX pattern
            match_stream = re.search(r"stream-(\d+)", u)
            if match_stream:
                return match_stream.group(1)
            return None

        try:
            channel_id = extract_channel_id(url)
            if not channel_id:
                raise ExtractorError(f"Unable to extract channel ID from {url}")

            logger.info(f"Extracting DLHD stream for channel ID: {channel_id}")

            # Try direct stream extraction with new auth flow
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

        # Try all players and collect all valid iframes
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

                # Collect all found iframes
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
