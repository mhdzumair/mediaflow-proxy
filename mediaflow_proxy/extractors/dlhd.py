import re
import base64
import logging
from typing import Any, Dict, Optional
from urllib.parse import urlparse, quote, urlunparse

from mediaflow_proxy.extractors.base import BaseExtractor, ExtractorError

logger = logging.getLogger(__name__)


class DLHDExtractor(BaseExtractor):
    """DLHD (DaddyLive) URL extractor for M3U8 streams."""

    def __init__(self, request_headers: dict):
        super().__init__(request_headers)
        # Default to HLS proxy endpoint
        self.mediaflow_endpoint = "hls_manifest_proxy"
        # Cache for the resolved base URL to avoid repeated network calls
        self._cached_base_url = None
        # Store iframe context for newkso.ru requests
        self._iframe_context = None

    def _get_headers_for_url(self, url: str, base_headers: dict) -> dict:
        """Get appropriate headers for the given URL, applying newkso.ru specific headers if needed."""
        headers = base_headers.copy()
        
        # Check if URL contains newkso.ru domain
        parsed_url = urlparse(url)
        if "newkso.ru" in parsed_url.netloc:
            # Use iframe URL as referer if available, otherwise use the newkso domain itself
            if self._iframe_context:
                iframe_origin = f"https://{urlparse(self._iframe_context).netloc}"
                newkso_headers = {
                    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36',
                    'Referer': self._iframe_context,
                    'Origin': iframe_origin
                }
                logger.info(f"Applied newkso.ru specific headers with iframe context for URL: {url}")
                logger.debug(f"Headers applied: {newkso_headers}")
            else:
                # Fallback to newkso domain itself
                newkso_origin = f"{parsed_url.scheme}://{parsed_url.netloc}"
                newkso_headers = {
                    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36',
                    'Referer': newkso_origin,
                    'Origin': newkso_origin
                }
                logger.info(f"Applied newkso.ru specific headers (fallback) for URL: {url}")
                logger.debug(f"Headers applied: {newkso_headers}")
            
            headers.update(newkso_headers)
        
        return headers

    async def _make_request(self, url: str, method: str = "GET", headers: dict = None, **kwargs):
        """Override _make_request to apply newkso.ru specific headers when needed."""
        request_headers = headers or {}
        
        # Apply newkso.ru specific headers if the URL contains newkso.ru
        final_headers = self._get_headers_for_url(url, request_headers)
        
        return await super()._make_request(url, method, final_headers, **kwargs)

    async def extract(self, url: str, **kwargs) -> Dict[str, Any]:
        """Extract DLHD stream URL and required headers (logica tvproxy adattata async, con fallback su endpoint alternativi)."""
        from urllib.parse import urlparse, quote_plus

        async def get_daddylive_base_url():
            if self._cached_base_url:
                return self._cached_base_url
            try:
                resp = await self._make_request("https://daddylive.sx/")
                # resp.url is the final URL after redirects
                base_url = str(resp.url)
                if not base_url.endswith('/'):
                    base_url += '/'
                self._cached_base_url = base_url
                return base_url
            except Exception:
                # Fallback to default if request fails
                return "https://daddylive.sx/"

        def extract_channel_id(url):
            match_premium = re.search(r'/premium(\d+)/mono\.m3u8$', url)
            if match_premium:
                return match_premium.group(1)
            # Handle both normal and URL-encoded patterns
            match_player = re.search(r'/(?:watch|stream|cast|player)/stream-(\d+)\.php', url)
            if match_player:
                return match_player.group(1)
            # Handle URL-encoded patterns like %2Fstream%2Fstream-123.php or just stream-123.php
            match_encoded = re.search(r'(?:%2F|/)stream-(\d+)\.php', url, re.IGNORECASE)
            if match_encoded:
                return match_encoded.group(1)
            # Handle direct stream- pattern without path
            match_direct = re.search(r'stream-(\d+)\.php', url)
            if match_direct:
                return match_direct.group(1)
            return None

        async def try_endpoint(baseurl, endpoint, channel_id):
            stream_url = f"{baseurl}{endpoint}stream-{channel_id}.php"
            daddy_origin = urlparse(baseurl).scheme + "://" + urlparse(baseurl).netloc
            daddylive_headers = {
                'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36',
                'Referer': baseurl,
                'Origin': daddy_origin
            }
            # 1. Richiesta alla pagina stream/cast/player/watch
            resp1 = await self._make_request(stream_url, headers=daddylive_headers)
            # 2. Estrai link Player 2
            iframes = re.findall(r'<a[^>]*href="([^"]+)"[^>]*>\s*<button[^>]*>\s*Player\s*2\s*</button>', resp1.text)
            if not iframes:
                raise ExtractorError("No Player 2 link found")
            url2 = iframes[0]
            url2 = baseurl + url2
            url2 = url2.replace('//cast', '/cast')
            daddylive_headers['Referer'] = url2
            daddylive_headers['Origin'] = url2
            # 3. Richiesta alla pagina Player 2
            resp2 = await self._make_request(url2, headers=daddylive_headers)
            # 4. Estrai iframe
            iframes2 = re.findall(r'iframe src="([^"]*)', resp2.text)
            if not iframes2:
                raise ExtractorError("No iframe found in Player 2 page")
            iframe_url = iframes2[0]
            # Store iframe context for newkso.ru requests
            self._iframe_context = iframe_url
            resp3 = await self._make_request(iframe_url, headers=daddylive_headers)
            iframe_content = resp3.text
            # 5. Estrai parametri auth (robusto)
            def extract_var(js, name):
                m = re.search(rf'var (?:__)?{name}\s*=\s*atob\("([^"]+)"\)', js)
                if m:
                    return base64.b64decode(m.group(1)).decode('utf-8')
                return None
            channel_key = re.search(r'channelKey\s*=\s*"([^"]+)"', iframe_content)
            channel_key = channel_key.group(1) if channel_key else None
            auth_ts = extract_var(iframe_content, 'c')
            auth_rnd = extract_var(iframe_content, 'd')
            auth_sig = extract_var(iframe_content, 'e')
            auth_host = extract_var(iframe_content, 'a')
            auth_php = extract_var(iframe_content, 'b')
            if not all([channel_key, auth_ts, auth_rnd, auth_sig, auth_host, auth_php]):
                raise ExtractorError("Error extracting parameters: one or more parameters not found")
            auth_sig = quote_plus(auth_sig)
            # 6. Richiesta auth
            auth_url = f'{auth_host}{auth_php}?channel_id={channel_key}&ts={auth_ts}&rnd={auth_rnd}&sig={auth_sig}'
            auth_resp = await self._make_request(auth_url, headers=daddylive_headers)
            # 7. Lookup server
            host = re.findall('(?s)m3u8 =.*?:.*?:.*?".*?".*?"([^"]*)', iframe_content)[0]
            server_lookup = re.findall(r'n fetchWithRetry\(\s*\'([^\']*)', iframe_content)[0]
            server_lookup_url = f"https://{urlparse(iframe_url).netloc}{server_lookup}{channel_key}"
            lookup_resp = await self._make_request(server_lookup_url, headers=daddylive_headers)
            server_data = lookup_resp.json()
            server_key = server_data['server_key']
            referer_raw = f'https://{urlparse(iframe_url).netloc}'
            clean_m3u8_url = f'https://{server_key}{host}{server_key}/{channel_key}/mono.m3u8'
            
            # Check if the final stream URL is on newkso.ru domain
            if "newkso.ru" in clean_m3u8_url:
                # For newkso.ru streams, use iframe URL as referer
                stream_headers = {
                    'User-Agent': daddylive_headers['User-Agent'],
                    'Referer': iframe_url,
                    'Origin': referer_raw
                }
                logger.info(f"Applied iframe-specific headers for newkso.ru stream URL: {clean_m3u8_url}")
                logger.debug(f"Stream headers for newkso.ru: {stream_headers}")
            else:
                # For other domains, use the original logic
                stream_headers = {
                    'User-Agent': daddylive_headers['User-Agent'],
                    'Referer': referer_raw,
                    'Origin': referer_raw
                }
            return {
                "destination_url": clean_m3u8_url,
                "request_headers": stream_headers,
                "mediaflow_endpoint": self.mediaflow_endpoint,
            }

        try:
            clean_url = url
            channel_id = extract_channel_id(clean_url)
            if not channel_id:
                raise ExtractorError(f"Unable to extract channel ID from {clean_url}")

            baseurl = await get_daddylive_base_url()
            endpoints = ["stream/", "cast/", "player/", "watch/"]
            last_exc = None
            for endpoint in endpoints:
                try:
                    return await try_endpoint(baseurl, endpoint, channel_id)
                except Exception as exc:
                    last_exc = exc
                    continue
            raise ExtractorError(f"Extraction failed: {str(last_exc)}")
        except Exception as e:
            raise ExtractorError(f"Extraction failed: {str(e)}")

    async def _lookup_server(
        self, lookup_url_base: str, auth_url_base: str, auth_data: Dict[str, str], headers: Dict[str, str]
    ) -> str:
        """Lookup server information and generate stream URL."""
        try:
            # Construct server lookup URL
            server_lookup_url = f"{lookup_url_base}/server_lookup.php?channel_id={quote(auth_data['channel_key'])}"

            # Make server lookup request
            server_response = await self._make_request(server_lookup_url, headers=headers)

            server_data = server_response.json()
            server_key = server_data.get("server_key")

            if not server_key:
                raise ExtractorError("Failed to get server key")

            # Extract domain parts from auth URL for constructing stream URL
            auth_domain_parts = urlparse(auth_url_base).netloc.split(".")
            domain_suffix = ".".join(auth_domain_parts[1:]) if len(auth_domain_parts) > 1 else auth_domain_parts[0]

            # Generate the m3u8 URL based on server response pattern
            if "/" in server_key:
                # Handle special case like "top1/cdn"
                parts = server_key.split("/")
                return f"https://{parts[0]}.{domain_suffix}/{server_key}/{auth_data['channel_key']}/mono.m3u8"
            else:
                # Handle normal case
                return f"https://{server_key}new.{domain_suffix}/{server_key}/{auth_data['channel_key']}/mono.m3u8"

        except Exception as e:
            raise ExtractorError(f"Server lookup failed: {str(e)}")

    def _extract_auth_data(self, html_content: str) -> Dict[str, str]:
        """Extract authentication data from player page."""
        try:
            channel_key_match = re.search(r'var\s+channelKey\s*=\s*["\']([^"\']+)["\']', html_content)
            if not channel_key_match:
                return {}
            channel_key = channel_key_match.group(1)

            # New pattern with atob
            auth_ts_match = re.search(r'var\s+__c\s*=\s*atob\([\'"]([^\'"]+)[\'"]\)', html_content)
            auth_rnd_match = re.search(r'var\s+__d\s*=\s*atob\([\'"]([^\'"]+)[\'"]\)', html_content)
            auth_sig_match = re.search(r'var\s+__e\s*=\s*atob\([\'"]([^\'"]+)[\'"]\)', html_content)

            if auth_ts_match and auth_rnd_match and auth_sig_match:
                return {
                    "channel_key": channel_key,
                    "auth_ts": base64.b64decode(auth_ts_match.group(1)).decode("utf-8"),
                    "auth_rnd": base64.b64decode(auth_rnd_match.group(1)).decode("utf-8"),
                    "auth_sig": base64.b64decode(auth_sig_match.group(1)).decode("utf-8"),
                }

            # Original pattern
            auth_ts_match = re.search(r'var\s+authTs\s*=\s*["\']([^"\']+)["\']', html_content)
            auth_rnd_match = re.search(r'var\s+authRnd\s*=\s*["\']([^"\']+)["\']', html_content)
            auth_sig_match = re.search(r'var\s+authSig\s*=\s*["\']([^"\']+)["\']', html_content)

            if auth_ts_match and auth_rnd_match and auth_sig_match:
                return {
                    "channel_key": channel_key,
                    "auth_ts": auth_ts_match.group(1),
                    "auth_rnd": auth_rnd_match.group(1),
                    "auth_sig": auth_sig_match.group(1),
                }
            return {}
        except Exception:
            return {}

    def _extract_auth_url_base(self, html_content: str) -> Optional[str]:
        """Extract auth URL base from player page script content."""
        try:
            # New atob pattern for auth base URL
            auth_url_base_match = re.search(r'var\s+__a\s*=\s*atob\([\'"]([^\'"]+)[\'"]\)', html_content)
            if auth_url_base_match:
                decoded_url = base64.b64decode(auth_url_base_match.group(1)).decode("utf-8")
                return decoded_url.strip().rstrip("/")

            # Look for auth URL or domain in fetchWithRetry call or similar patterns
            auth_url_match = re.search(r'fetchWithRetry\([\'"]([^\'"]*/auth\.php)', html_content)

            if auth_url_match:
                auth_url = auth_url_match.group(1)
                # Extract base URL up to the auth.php part
                return auth_url.split("/auth.php")[0]

            # Try finding domain directly
            domain_match = re.search(r'[\'"]https://([^/\'\"]+)(?:/[^\'\"]*)?/auth\.php', html_content)

            if domain_match:
                return f"https://{domain_match.group(1)}"

            return None
        except Exception:
            return None

    def _get_origin(self, url: str) -> str:
        """Extract origin from URL."""
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"

    def _derive_auth_url_base(self, player_domain: str) -> Optional[str]:
        """Attempt to derive auth URL base from player domain."""
        try:
            # Typical pattern is to use a subdomain for auth domain
            parsed = urlparse(player_domain)
            domain_parts = parsed.netloc.split(".")

            # Get the top-level domain and second-level domain
            if len(domain_parts) >= 2:
                base_domain = ".".join(domain_parts[-2:])
                # Try common subdomains for auth
                for prefix in ["auth", "api", "cdn"]:
                    potential_auth_domain = f"https://{prefix}.{base_domain}"
                    return potential_auth_domain

            return None
        except Exception:
            return None
