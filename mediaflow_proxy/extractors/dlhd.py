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
            # 5. Estrai parametri auth (robusto) - Handle both old and new formats
            def extract_var_old_format(js, name):
                # Try multiple patterns for variable extraction (old format)
                patterns = [
                    rf'var (?:__)?{name}\s*=\s*atob\("([^"]+)"\)',
                    rf'var (?:__)?{name}\s*=\s*atob\(\'([^\']+)\'\)',
                    rf'(?:var\s+)?(?:__)?{name}\s*=\s*atob\s*\(\s*["\']([^"\']+)["\']\s*\)',
                    rf'(?:let|const)\s+(?:__)?{name}\s*=\s*atob\s*\(\s*["\']([^"\']+)["\']\s*\)'
                ]
                for pattern in patterns:
                    m = re.search(pattern, js)
                    if m:
                        try:
                            return base64.b64decode(m.group(1)).decode('utf-8')
                        except Exception as decode_error:
                            logger.warning(f"Failed to decode base64 for variable {name}: {decode_error}")
                            continue
                return None
            
            def extract_bundle_format(js):
                """Extract parameters from new BUNDLE format"""
                try:
                    # Look for BUNDLE variable
                    bundle_patterns = [
                        r'const\s+BUNDLE\s*=\s*["\']([^"\']+)["\']',
                        r'var\s+BUNDLE\s*=\s*["\']([^"\']+)["\']',
                        r'let\s+BUNDLE\s*=\s*["\']([^"\']+)["\']'
                    ]
                    
                    bundle_data = None
                    for pattern in bundle_patterns:
                        match = re.search(pattern, js)
                        if match:
                            bundle_data = match.group(1)
                            break
                    
                    if not bundle_data:
                        return None
                    
                    # Decode the bundle (base64 -> JSON -> decode each field)
                    import json
                    bundle_json = base64.b64decode(bundle_data).decode('utf-8')
                    bundle_obj = json.loads(bundle_json)
                    
                    # Decode each base64 field
                    decoded_bundle = {}
                    for key, value in bundle_obj.items():
                        try:
                            decoded_bundle[key] = base64.b64decode(value).decode('utf-8')
                        except Exception as e:
                            logger.warning(f"Failed to decode bundle field {key}: {e}")
                            decoded_bundle[key] = value
                    
                    return decoded_bundle
                    
                except Exception as e:
                    logger.warning(f"Failed to extract bundle format: {e}")
                    return None
            
            # Try multiple patterns for channel key extraction
            channel_key = None
            channel_key_patterns = [
                r'const\s+CHANNEL_KEY\s*=\s*["\']([^"\']+)["\']',
                r'var\s+CHANNEL_KEY\s*=\s*["\']([^"\']+)["\']',
                r'let\s+CHANNEL_KEY\s*=\s*["\']([^"\']+)["\']',
                r'channelKey\s*=\s*["\']([^"\']+)["\']',
                r'var\s+channelKey\s*=\s*["\']([^"\']+)["\']',
                r'(?:let|const)\s+channelKey\s*=\s*["\']([^"\']+)["\']'
            ]
            for pattern in channel_key_patterns:
                match = re.search(pattern, iframe_content)
                if match:
                    channel_key = match.group(1)
                    break
            
            # Try new bundle format first
            bundle_data = extract_bundle_format(iframe_content)
            if bundle_data:
                logger.info("Using new BUNDLE format for parameter extraction")
                auth_host = bundle_data.get('b_host')
                auth_php = bundle_data.get('b_script')
                auth_ts = bundle_data.get('b_ts')
                auth_rnd = bundle_data.get('b_rnd')
                auth_sig = bundle_data.get('b_sig')
                logger.debug(f"Bundle data extracted: {bundle_data}")
            else:
                logger.info("Falling back to old format for parameter extraction")
                # Fall back to old format
                auth_ts = extract_var_old_format(iframe_content, 'c')
                auth_rnd = extract_var_old_format(iframe_content, 'd')
                auth_sig = extract_var_old_format(iframe_content, 'e')
                auth_host = extract_var_old_format(iframe_content, 'a')
                auth_php = extract_var_old_format(iframe_content, 'b')
            
            # Log what we found for debugging
            logger.debug(f"Extracted parameters: channel_key={channel_key}, auth_ts={auth_ts}, auth_rnd={auth_rnd}, auth_sig={auth_sig}, auth_host={auth_host}, auth_php={auth_php}")
            
            # Check which parameters are missing
            missing_params = []
            if not channel_key:
                missing_params.append('channel_key/CHANNEL_KEY')
            if not auth_ts:
                missing_params.append('auth_ts (var c / b_ts)')
            if not auth_rnd:
                missing_params.append('auth_rnd (var d / b_rnd)')
            if not auth_sig:
                missing_params.append('auth_sig (var e / b_sig)')
            if not auth_host:
                missing_params.append('auth_host (var a / b_host)')
            if not auth_php:
                missing_params.append('auth_php (var b / b_script)')
            
            if missing_params:
                logger.error(f"Missing parameters: {', '.join(missing_params)}")
                # Log a portion of the iframe content for debugging (first 2000 chars)
                logger.debug(f"Iframe content sample: {iframe_content[:2000]}")
                raise ExtractorError(f"Error extracting parameters: missing {', '.join(missing_params)}")
            auth_sig = quote_plus(auth_sig)
            # 6. Richiesta auth
            auth_url = f'{auth_host}{auth_php}?channel_id={channel_key}&ts={auth_ts}&rnd={auth_rnd}&sig={auth_sig}'
            auth_resp = await self._make_request(auth_url, headers=daddylive_headers)
            # 7. Lookup server - Extract host parameter
            host = None
            host_patterns = [
                r'(?s)m3u8 =.*?:.*?:.*?".*?".*?"([^"]*)',  # Original pattern
                r'm3u8\s*=.*?"([^"]*)"',  # Simplified m3u8 pattern
                r'host["\']?\s*[:=]\s*["\']([^"\']*)',  # host: or host= pattern
                r'["\']([^"\']*\.newkso\.ru[^"\']*)',  # Direct newkso.ru pattern
                r'["\']([^"\']*\/premium\d+[^"\']*)',  # premium path pattern
                r'url.*?["\']([^"\']*newkso[^"\']*)',  # URL with newkso
            ]
            
            for pattern in host_patterns:
                matches = re.findall(pattern, iframe_content)
                if matches:
                    host = matches[0]
                    logger.debug(f"Found host with pattern '{pattern}': {host}")
                    break
            
            if not host:
                logger.error("Failed to extract host from iframe content")
                logger.debug(f"Iframe content for host extraction: {iframe_content[:2000]}")
                # Try to find any newkso.ru related URLs
                potential_hosts = re.findall(r'["\']([^"\']*newkso[^"\']*)', iframe_content)
                if potential_hosts:
                    logger.debug(f"Potential host URLs found: {potential_hosts}")
                raise ExtractorError("Failed to extract host parameter")
            
            # Extract server lookup URL from fetchWithRetry call (dynamic extraction)
            server_lookup = None
            
            # Look for the server_lookup.php pattern in JavaScript
            if "fetchWithRetry('/server_lookup.php?channel_id='" in iframe_content:
                server_lookup = '/server_lookup.php?channel_id='
                logger.debug('Found server lookup URL: /server_lookup.php?channel_id=')
            elif '/server_lookup.php' in iframe_content:
                # Try to extract the full path
                js_lines = iframe_content.split('\n')
                for js_line in js_lines:
                    if 'server_lookup.php' in js_line and 'fetchWithRetry' in js_line:
                        # Extract the URL from the fetchWithRetry call
                        start = js_line.find("'")
                        if start != -1:
                            end = js_line.find("'", start + 1)
                            if end != -1:
                                potential_url = js_line[start+1:end]
                                if 'server_lookup' in potential_url:
                                    server_lookup = potential_url
                                    logger.debug(f'Extracted server lookup URL: {server_lookup}')
                                    break
            
            if not server_lookup:
                logger.error('Failed to extract server lookup URL from iframe content')
                logger.debug(f'Iframe content sample: {iframe_content[:2000]}')
                raise ExtractorError('Failed to extract server lookup URL')
            
            server_lookup_url = f"https://{urlparse(iframe_url).netloc}{server_lookup}{channel_key}"
            logger.debug(f"Server lookup URL: {server_lookup_url}")
            
            try:
                lookup_resp = await self._make_request(server_lookup_url, headers=daddylive_headers)
                server_data = lookup_resp.json()
                server_key = server_data.get('server_key')
                if not server_key:
                    logger.error(f"No server_key in response: {server_data}")
                    raise ExtractorError("Failed to get server key from lookup response")
                
                logger.info(f"Server lookup successful - Server key: {server_key}")
            except Exception as lookup_error:
                logger.error(f"Server lookup request failed: {lookup_error}")
                raise ExtractorError(f"Server lookup failed: {str(lookup_error)}")
            
            referer_raw = f'https://{urlparse(iframe_url).netloc}'
            
            # Extract URL construction logic dynamically from JavaScript
            # Simple approach: look for newkso.ru URLs and construct based on server_key
            
            # Check if we have the special case server_key
            if server_key == 'top1/cdn':
                clean_m3u8_url = f'https://top1.newkso.ru/top1/cdn/{channel_key}/mono.m3u8'
                logger.info(f'Using special case URL for server_key \'top1/cdn\': {clean_m3u8_url}')
            else:
                clean_m3u8_url = f'https://{server_key}new.newkso.ru/{server_key}/{channel_key}/mono.m3u8'
                logger.info(f'Using general case URL for server_key \'{server_key}\': {clean_m3u8_url}')
            
            logger.info(f'Generated stream URL: {clean_m3u8_url}')
            logger.debug(f'Server key: {server_key}, Channel key: {channel_key}')
            
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
