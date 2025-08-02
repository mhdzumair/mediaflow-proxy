import re
import base64
from typing import Any, Dict, Optional
from urllib.parse import urlparse, quote, urlunparse

from mediaflow_proxy.extractors.base import BaseExtractor, ExtractorError


class DLHDExtractor(BaseExtractor):
    """DLHD (DaddyLive) URL extractor for M3U8 streams."""

    def __init__(self, request_headers: dict):
        super().__init__(request_headers)
        # Default to HLS proxy endpoint
        self.mediaflow_endpoint = "hls_manifest_proxy"

    async def extract(self, url: str, **kwargs) -> Dict[str, Any]:
        """Extract DLHD stream URL and required headers (logica tvproxy adattata async, con fallback su endpoint alternativi)."""
        import httpx
        from urllib.parse import urlparse, quote_plus

        async def get_daddylive_base_url():
            github_url = 'https://raw.githubusercontent.com/nzo66/dlhd_url/refs/heads/main/dlhd.xml'
            try:
                async with httpx.AsyncClient(timeout=10) as client:
                    resp = await client.get(github_url)
                    resp.raise_for_status()
                    content = resp.text
                    match = re.search(r'src\s*=\s*"([^"]*)"', content)
                    if match:
                        base_url = match.group(1)
                        if not base_url.endswith('/'):
                            base_url += '/'
                        return base_url
            except Exception:
                pass
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
            async with httpx.AsyncClient(timeout=15, follow_redirects=True, verify=False) as client:
                # 1. Richiesta alla pagina stream/cast/player/watch
                resp1 = await client.get(stream_url, headers=daddylive_headers)
                resp1.raise_for_status()
                # 2. Estrai link Player 2
                iframes = re.findall(r'<a[^>]*href="([^"]+)"[^>]*>\s*<button[^>]*>\s*Player\s*2\s*</button>', resp1.text)
                if not iframes:
                    raise ExtractorError("Nessun link Player 2 trovato")
                url2 = iframes[0]
                url2 = baseurl + url2
                url2 = url2.replace('//cast', '/cast')
                daddylive_headers['Referer'] = url2
                daddylive_headers['Origin'] = url2
                # 3. Richiesta alla pagina Player 2
                resp2 = await client.get(url2, headers=daddylive_headers)
                resp2.raise_for_status()
                # 4. Estrai iframe
                iframes2 = re.findall(r'iframe src="([^"]*)', resp2.text)
                if not iframes2:
                    raise ExtractorError("Nessun iframe trovato nella pagina Player 2")
                iframe_url = iframes2[0]
                resp3 = await client.get(iframe_url, headers=daddylive_headers)
                resp3.raise_for_status()
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
                    raise ExtractorError("Errore estrazione parametri: uno o più parametri non trovati")
                auth_sig = quote_plus(auth_sig)
                # 6. Richiesta auth
                auth_url = f'{auth_host}{auth_php}?channel_id={channel_key}&ts={auth_ts}&rnd={auth_rnd}&sig={auth_sig}'
                auth_resp = await client.get(auth_url, headers=daddylive_headers)
                auth_resp.raise_for_status()
                # 7. Lookup server
                host = re.findall('(?s)m3u8 =.*?:.*?:.*?".*?".*?"([^"]*)', iframe_content)[0]
                server_lookup = re.findall(r'n fetchWithRetry\(\s*\'([^\']*)', iframe_content)[0]
                server_lookup_url = f"https://{urlparse(iframe_url).netloc}{server_lookup}{channel_key}"
                lookup_resp = await client.get(server_lookup_url, headers=daddylive_headers)
                lookup_resp.raise_for_status()
                server_data = lookup_resp.json()
                server_key = server_data['server_key']
                referer_raw = f'https://{urlparse(iframe_url).netloc}'
                clean_m3u8_url = f'https://{server_key}{host}{server_key}/{channel_key}/mono.m3u8'
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
                raise ExtractorError(f"Impossibile estrarre ID canale da {clean_url}")

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

    async def _try_extract_with_url(self, player_url: str, channel_origin: str) -> Dict[str, Any]:
        """Try to extract stream using the given player URL with all available methods."""
        # Attempt 1: _handle_vecloud with player_url
        try:
            referer_for_vecloud = channel_origin + "/"
            if re.search(r"/stream/([a-zA-Z0-9-]+)", player_url):
                referer_for_vecloud = self._get_origin(player_url) + "/"
            return await self._handle_vecloud(player_url, referer_for_vecloud)
        except Exception:
            pass # Fail, Continue
            
        # Attempt 2: If _handle_vecloud fail and the URL is not /stream/, try _handle_playnow
        # and then _handle_vecloud again with the URL resulting from playnow.
        if not re.search(r"/stream/([a-zA-Z0-9-]+)", player_url):
            try:
                playnow_derived_player_url = await self._handle_playnow(player_url, channel_origin + "/")
                if re.search(r"/stream/([a-zA-Z0-9-]+)", playnow_derived_player_url):
                    try:
                        referer_for_vecloud_after_playnow = self._get_origin(playnow_derived_player_url) + "/"
                        return await self._handle_vecloud(playnow_derived_player_url, referer_for_vecloud_after_playnow)
                    except Exception:
                        pass 
            except Exception:
                pass

        # If all previous attempts have failed, proceed with standard authentication.
        player_url_for_auth = player_url
        player_origin_for_auth = self._get_origin(player_url_for_auth)
        
        # Get player page to extract authentication information
        player_headers = {
            "referer": player_origin_for_auth + "/",
            "origin": player_origin_for_auth,
            "user-agent": self.base_headers["user-agent"],
        }

        player_response = await self._make_request(player_url_for_auth, headers=player_headers)
        player_content = player_response.text

        # Extract authentication details from script tag
        auth_data = self._extract_auth_data(player_content)
        if not auth_data:
            raise ExtractorError("Failed to extract authentication data from player")

        # Extract auth URL base if not provided
        final_auth_url_base = self._extract_auth_url_base(player_content)

        # If still no auth URL base, try to derive from player URL structure
        if not final_auth_url_base:
            # Try to extract from player URL structure
            player_domain_for_auth_derive = self._get_origin(player_url_for_auth)
            # Attempt to construct a standard auth domain
            final_auth_url_base = self._derive_auth_url_base(player_domain_for_auth_derive)

            if not final_auth_url_base:
                raise ExtractorError("Could not determine auth URL base")

        # Construct auth URL
        auth_url = (
            f"{final_auth_url_base}/auth.php?channel_id={auth_data['channel_key']}"
            f"&ts={auth_data['auth_ts']}&rnd={auth_data['auth_rnd']}"
            f"&sig={quote(auth_data['auth_sig'])}"
        )

        # Make auth request
        auth_req_headers = {
            "referer": player_origin_for_auth + "/",
            "origin": player_origin_for_auth,
            "user-agent": self.base_headers["user-agent"],
        }

        auth_response = await self._make_request(auth_url, headers=auth_req_headers)

        # Check if authentication succeeded
        if auth_response.json().get("status") != "ok":
            raise ExtractorError("Authentication failed")

        # Look up the server and generate the stream URL
        final_stream_url = await self._lookup_server(
            lookup_url_base=player_origin_for_auth,
            auth_url_base=final_auth_url_base,
            auth_data=auth_data,
            headers=auth_req_headers,
        )

        # Set up the final stream headers
        stream_headers = {
            "referer": player_url_for_auth,
            "origin": player_origin_for_auth,
            "user-agent": self.base_headers["user-agent"],
        }

        # Return the stream URL with headers
        return {
            "destination_url": final_stream_url,
            "request_headers": stream_headers,
            "mediaflow_endpoint": self.mediaflow_endpoint,
        }

    def _create_alternative_url(self, original_url: str, new_path: str) -> Optional[str]:
        """Create alternative URL by replacing the path with the new path."""
        try:
            # Parse the original URL
            parsed = urlparse(original_url)
            
            # Extract the path components
            path_parts = parsed.path.strip('/').split('/')
            
            # If the URL contains /stream/, replace it with the new path
            if '/stream/' in parsed.path:
                # Replace /stream/ with the new path
                new_path_clean = new_path.strip('/')
                new_url_path = parsed.path.replace('/stream/', f'/{new_path_clean}/')
                return urlunparse((
                    parsed.scheme,
                    parsed.netloc,
                    new_url_path,
                    parsed.params,
                    parsed.query,
                    parsed.fragment
                ))
            
            return None
        except Exception:
            return None

    async def _handle_vecloud(self, player_url: str, channel_referer: str) -> Dict[str, Any]:
        """Handle vecloud URLs with their specific API.

        Args:
            player_url: The vecloud player URL
            channel_referer: The referer of the channel page
        Returns:
            Dict containing stream URL and required headers
        """
        try:
            # Extract stream ID from vecloud URL
            stream_id_match = re.search(r"/stream/([a-zA-Z0-9-]+)", player_url)
            if not stream_id_match:
                raise ExtractorError("Could not extract stream ID from vecloud URL")

            stream_id = stream_id_match.group(1)

            response = await self._make_request(
                player_url, headers={"referer": channel_referer, "user-agent": self.base_headers["user-agent"]}
            )
            player_url = str(response.url)

            # Construct API URL
            player_parsed = urlparse(player_url)
            player_domain = player_parsed.netloc
            player_origin = f"{player_parsed.scheme}://{player_parsed.netloc}"
            api_url = f"{player_origin}/api/source/{stream_id}?type=live"

            # Set up headers for API request
            api_headers = {
                "referer": player_url,
                "origin": player_origin,
                "user-agent": self.base_headers["user-agent"],
                "content-type": "application/json",
            }

            api_data = {"r": channel_referer, "d": player_domain}

            # Make API request
            api_response = await self._make_request(api_url, method="POST", headers=api_headers, json=api_data)
            api_data = api_response.json()

            # Check if request was successful
            if not api_data.get("success"):
                raise ExtractorError("Vecloud API request failed")

            # Extract stream URL from response
            stream_url = api_data.get("player", {}).get("source_file")

            if not stream_url:
                raise ExtractorError("Could not find stream URL in vecloud response")

            # Set up stream headers
            stream_headers = {
                "referer": player_origin + "/",
                "origin": player_origin,
                "user-agent": self.base_headers["user-agent"],
            }

            # Return the stream URL with headers
            return {
                "destination_url": stream_url,
                "request_headers": stream_headers,
                "mediaflow_endpoint": self.mediaflow_endpoint,
            }

        except Exception as e:
            raise ExtractorError(f"Vecloud extraction failed: {str(e)}")

    async def _handle_playnow(self, player_iframe: str, channel_origin: str) -> str:
        """Handle playnow URLs."""
        # Set up headers for the playnow request
        playnow_headers = {"referer": channel_origin + "/", "user-agent": self.base_headers["user-agent"]}

        # Make the playnow request
        playnow_response = await self._make_request(player_iframe, headers=playnow_headers)
        player_url = self._extract_player_url(playnow_response.text)
        if not player_url:
            raise ExtractorError("Could not extract player URL from playnow response")
        return player_url

    def _extract_player_url(self, html_content: str) -> Optional[str]:
        """Extract player iframe URL from channel page HTML."""
        try:
            # Look for iframe with allowfullscreen attribute
            iframe_match = re.search(
                r'<iframe[^>]*src=["\']([^"\']+)["\'][^>]*allowfullscreen', html_content, re.IGNORECASE
            )

            if not iframe_match:
                # Try alternative pattern without requiring allowfullscreen
                iframe_match = re.search(
                    r'<iframe[^>]*src=["\']([^"\']+(?:premiumtv|daddylivehd|vecloud)[^"\']*)["\']',
                    html_content,
                    re.IGNORECASE,
                )

            if iframe_match:
                return iframe_match.group(1).strip()

            return None
        except Exception:
            return None

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
