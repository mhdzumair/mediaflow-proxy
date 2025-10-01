import re
import base64
import logging
from typing import Any, Dict, Optional
from urllib.parse import urlparse, quote_plus

import httpx

from mediaflow_proxy.extractors.base import BaseExtractor, ExtractorError

logger = logging.getLogger(__name__)


class DLHDExtractor(BaseExtractor):
    """DLHD (DaddyLive) URL extractor for M3U8 streams.

    Notes:
    - Multi-domain support for daddylive.sx / dlhd.dad
    - Robust extraction of auth parameters and server lookup
    - Uses retries/timeouts via BaseExtractor where possible
    """

    def __init__(self, request_headers: dict):
        super().__init__(request_headers)
        self.mediaflow_endpoint = "hls_manifest_proxy"
        self._cached_base_url: Optional[str] = None
        self._iframe_context: Optional[str] = None
        self._auth_cache: Dict[str, Dict[str, Any]] = {}

    def _get_headers_for_url(self, url: str, base_headers: dict) -> dict:
        """Return headers adapted for newkso.ru or other domains if needed."""
        headers = base_headers.copy()
        parsed_url = urlparse(url)
        if "newkso.ru" in parsed_url.netloc:
            if self._iframe_context:
                iframe_origin = f"https://{urlparse(self._iframe_context).netloc}"
                newkso_headers = {
                    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36',
                    'Referer': self._iframe_context,
                    'Origin': iframe_origin
                }
            else:
                newkso_origin = f"{parsed_url.scheme}://{parsed_url.netloc}"
                newkso_headers = {
                    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36',
                    'Referer': newkso_origin,
                    'Origin': newkso_origin
                }
            headers.update(newkso_headers)
        return headers

    async def _make_request(self, url: str, method: str = "GET", headers: Optional[Dict] = None, **kwargs) -> Any:
        """Override to disable SSL verification for this extractor and use fetch_with_retry if available."""
        from mediaflow_proxy.utils.http_utils import create_httpx_client, fetch_with_retry

        timeout = kwargs.pop("timeout", 15)
        retries = kwargs.pop("retries", 3)
        backoff_factor = kwargs.pop("backoff_factor", 0.5)

        # create_httpx_client is expected to accept verify and timeout params similar to prior usage
        async with create_httpx_client(verify=False, timeout=httpx.Timeout(timeout)) as client:
            try:
                # Prefer helper function if exists (do not pass unsupported kwargs like 'retries')
                return await fetch_with_retry(client, method, url, headers or {}, timeout=timeout)
            except Exception:
                # Fallback to direct request so exceptions bubble with status etc.
                logger.debug("fetch_with_retry failed or unavailable; falling back to direct request for %s", url)
                response = await client.request(method, url, headers=headers or {}, timeout=timeout)
                response.raise_for_status()
                return response

    async def extract(self, url: str, **kwargs) -> Dict[str, Any]:
        """Main extraction flow: resolve base, fetch players, extract iframe, auth and final m3u8."""
        from urllib.parse import urlparse

        async def resolve_base_url(preferred_host: Optional[str] = None) -> str:
            if self._cached_base_url:
                return self._cached_base_url

            DOMAINS = [
                'https://daddylive.sx/',
                'https://dlhd.dad/'
            ]

            if preferred_host:
                ph = preferred_host if preferred_host.endswith('/') else preferred_host + '/'
                if ph in DOMAINS:
                    candidates = [ph] + [d for d in DOMAINS if d != ph]
                else:
                    candidates = [ph] + DOMAINS
            else:
                candidates = DOMAINS[:]

            for base in candidates:
                try:
                    resp = await self._make_request(base, timeout=10, retries=2)
                    final_url = str(resp.url)
                    if not final_url.endswith('/'):
                        final_url += '/'
                    self._cached_base_url = final_url
                    logger.info(f"Resolved base domain: {final_url}")
                    return final_url
                except Exception as e:
                    logger.warning(f"Base domain attempt failed for {base}: {e}")

            fallback = candidates[0]
            logger.warning(f"All domain resolution attempts failed, using fallback: {fallback}")
            self._cached_base_url = fallback
            return fallback

        def extract_channel_id(u: str) -> Optional[str]:
            match_premium = re.search(r'/premium(\d+)/mono\.m3u8$', u)
            if match_premium:
                return match_premium.group(1)
            match_player = re.search(r'/(?:watch|stream|cast|player)/stream-(\d+)\.php', u)
            if match_player:
                return match_player.group(1)
            match_watch_id = re.search(r'watch\.php\?id=(\d+)', u)
            if match_watch_id:
                return match_watch_id.group(1)
            match_encoded = re.search(r'(?:%2F|/)stream-(\d+)\.php', u, re.IGNORECASE)
            if match_encoded:
                return match_encoded.group(1)
            match_direct = re.search(r'stream-(\d+)\.php', u)
            if match_direct:
                return match_direct.group(1)
            return None

        async def get_stream_data(baseurl: str, initial_url: str, channel_id: str):
            daddy_origin = urlparse(baseurl).scheme + "://" + urlparse(baseurl).netloc
            daddylive_headers = {
                'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36',
                'Referer': baseurl,
                'Origin': daddy_origin
            }

            # 1. Request initial page
            resp1 = await self._make_request(initial_url, headers=daddylive_headers, timeout=15)
            player_links = re.findall(r'<button[^>]*data-url="([^"]+)"[^>]*>Player\s*\d+</button>', resp1.text)
            if not player_links:
                raise ExtractorError("No player links found on the page.")

            last_player_error = None
            iframe_url = None
            for player_url in player_links:
                try:
                    if not player_url.startswith('http'):
                        player_url = baseurl + player_url.lstrip('/')

                    daddylive_headers['Referer'] = player_url
                    daddylive_headers['Origin'] = player_url
                    resp2 = await self._make_request(player_url, headers=daddylive_headers, timeout=12)
                    iframes2 = re.findall(r'iframe src="([^"]*)', resp2.text)
                    if iframes2:
                        iframe_url = iframes2[0]
                        break
                except Exception as e:
                    last_player_error = e
                    logger.warning(f"Failed to process player link {player_url}: {e}")
                    continue

            if not iframe_url:
                if last_player_error:
                    raise ExtractorError(f"All player links failed. Last error: {last_player_error}")
                raise ExtractorError("No valid iframe found in any player page")

            # store iframe context for newkso headers
            self._iframe_context = iframe_url
            resp3 = await self._make_request(iframe_url, headers=daddylive_headers, timeout=12)
            iframe_content = resp3.text

            # Try to extract parameters via JSON-like encoded XJZ or older patterns
            def extract_auth_params(js: str) -> Dict[str, Optional[str]]:
                # NEW: Try XKZK/PWAROS format first
                try:
                    # Look for const XKZK = "..."
                    xkzk_pattern = r'(?:const|var|let)\s+XKZK\s*=\s*["\']([^"\']+)["\']'
                    xkzk_match = re.search(xkzk_pattern, js)
                    
                    if xkzk_match:
                        b64_data = xkzk_match.group(1)
                        logger.info(f"Found XKZK data: {b64_data[:50]}...")
                        
                        import json
                        json_data = base64.b64decode(b64_data).decode('utf-8')
                        obj_data = json.loads(json_data)
                        logger.info(f"Decoded XKZK object: {obj_data}")
                        
                        decoded_params = {}
                        for k, v in obj_data.items():
                            try:
                                decoded_params[k] = base64.b64decode(v).decode('utf-8')
                            except Exception:
                                decoded_params[k] = v
                        
                        logger.info(f"Final decoded params: {decoded_params}")
                        
                        return {
                            "auth_host": decoded_params.get('b_host'),
                            "auth_php": decoded_params.get('b_script'),
                            "auth_ts": decoded_params.get('b_ts'),
                            "auth_rnd": decoded_params.get('b_rnd'),
                            "auth_sig": decoded_params.get('b_sig')
                        }
                except Exception as e:
                    logger.debug(f"Could not process XKZK format: {e}")

                # FALLBACK: Try old XJZ format
                try:
                    pattern = r'(?:const|var|let)\s+XJZ\s*=\s*["\']([^"\']+)["\']'
                    match = re.search(pattern, js)
                    if not match:
                        return {}

                    b64_data = match.group(1)
                    import json
                    json_data = base64.b64decode(b64_data).decode('utf-8')
                    obj_data = json.loads(json_data)

                    decoded_params = {}
                    for k, v in obj_data.items():
                        try:
                            decoded_params[k] = base64.b64decode(v).decode('utf-8')
                        except Exception:
                            decoded_params[k] = v

                    return {
                        "auth_host": decoded_params.get('b_host'),
                        "auth_php": decoded_params.get('b_script'), 
                        "auth_ts": decoded_params.get('b_ts'),
                        "auth_rnd": decoded_params.get('b_rnd'),
                        "auth_sig": decoded_params.get('b_sig')
                    }
                except Exception as e:
                    logger.debug(f"Could not process XJZ format: {e}")
                    return {}


            # Extract channel key with multiple patterns
            channel_key = None
            for pattern in [
                r'const\s+CHANNEL_KEY\s*=\s*["\']([^"\']+)["\']',
                r'var\s+CHANNEL_KEY\s*=\s*["\']([^"\']+)["\']',
                r'let\s+CHANNEL_KEY\s*=\s*["\']([^"\']+)["\']',
                r'channelKey\s*=\s*["\']([^"\']+)["\']',
                r'var\s+channelKey\s*=\s*["\']([^"\']+)["\']',
                r'(?:let|const)\s+channelKey\s*=\s*["\']([^"\']+)["\']'
            ]:
                m = re.search(pattern, iframe_content)
                if m:
                    channel_key = m.group(1)
                    break

            params = extract_auth_params(iframe_content)
            auth_host = params.get("auth_host")
            auth_php = params.get("auth_php")
            auth_ts = params.get("auth_ts")
            auth_rnd = params.get("auth_rnd")
            auth_sig = params.get("auth_sig")

            # If older patterns exist, try to parse them
            if not channel_key:
                m = re.search(r'var\s+channelKey\s*=\s*["\']([^"\']+)["\']', iframe_content)
                if m:
                    channel_key = m.group(1)

            if not auth_ts or not auth_rnd or not auth_sig or not auth_host or not auth_php:
                # fallback to older extraction
                # atob patterns
                try:
                    atob_a = re.search(r'var\s+__a\s*=\s*atob\([\'"]([^\'"]+)[\'"]\)', iframe_content)
                    if atob_a:
                        auth_host_dec = base64.b64decode(atob_a.group(1)).decode('utf-8')
                        auth_host = auth_host or auth_host_dec.rstrip('/')
                    # channel key via var __k or similar
                    if not channel_key:
                        m_k = re.search(r'var\s+channelKey\s*=\s*["\']([^"\']+)["\']', iframe_content)
                        if m_k:
                            channel_key = m_k.group(1)
                    # atob for ts/rnd/sig
                    atob_ts = re.search(r'var\s+__c\s*=\s*atob\([\'"]([^\'"]+)[\'"]\)', iframe_content)
                    atob_rnd = re.search(r'var\s+__d\s*=\s*atob\([\'"]([^\'"]+)[\'"]\)', iframe_content)
                    atob_sig = re.search(r'var\s+__e\s*=\s*atob\([\'"]([^\'"]+)[\'"]\)', iframe_content)
                    if atob_ts and atob_rnd and atob_sig:
                        auth_ts = base64.b64decode(atob_ts.group(1)).decode('utf-8')
                        auth_rnd = base64.b64decode(atob_rnd.group(1)).decode('utf-8')
                        auth_sig = base64.b64decode(atob_sig.group(1)).decode('utf-8')
                except Exception:
                    logger.debug("Fallback atob parsing failed.")

            # Validate presence
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
                logger.debug(f"Iframe content sample: {iframe_content[:2000]}")
                raise ExtractorError(f"Error extracting parameters: missing {', '.join(missing_params)}")

            # Normalize auth_php if needed
            normalized_auth_php = auth_php.strip().lstrip('/')
            if normalized_auth_php == 'a.php':
                logger.info("Replacing any 'a.php' variant with '/auth.php' for compatibility.")
                auth_php = '/auth.php'
            # Build auth_url robustly
            if auth_host.endswith('/') and auth_php.startswith('/'):
                auth_url = f'{auth_host[:-1]}{auth_php}'
            elif not auth_host.endswith('/') and not auth_php.startswith('/'):
                auth_url = f'{auth_host}/{auth_php}'
            else:
                auth_url = f'{auth_host}{auth_php}'
            auth_sig_quoted = quote_plus(auth_sig)
            auth_url = f'{auth_url}?channel_id={channel_key}&ts={auth_ts}&rnd={auth_rnd}&sig={auth_sig_quoted}'

            iframe_origin = f"https://{urlparse(iframe_url).netloc}"
            auth_headers = daddylive_headers.copy()
            auth_headers['Referer'] = iframe_url
            auth_headers['Origin'] = iframe_origin

            try:
                auth_resp = await self._make_request(auth_url, headers=auth_headers, timeout=12)
                # ensure success
                try:
                    auth_resp.raise_for_status()
                except Exception as e:
                    # try invalidating cache and retrying as a last resort
                    if channel_id in self._auth_cache:
                        del self._auth_cache[channel_id]
                        logger.info(f"Cache for channel {channel_id} invalidated due to auth failure; retrying once.")
                        return await get_stream_data(baseurl, initial_url, channel_id)
                    raise ExtractorError(f"Authentication failed: {e}")
            except Exception as auth_error:
                logger.warning(f"Auth request failed: {auth_error}.")
                if channel_id in self._auth_cache:
                    del self._auth_cache[channel_id]
                raise ExtractorError(f"Authentication failed after retry or without cache: {auth_error}")

            # server lookup
            server_lookup = None
            if "fetchWithRetry('/server_lookup.js?channel_id='" in iframe_content:
                server_lookup = '/server_lookup.js?channel_id='
            else:
                # try to find explicit server_lookup patterns
                js_lines = iframe_content.split('\n')
                for js_line in js_lines:
                    if 'server_lookup.' in js_line and 'fetchWithRetry' in js_line: # Look for .js or .php
                        start = js_line.find("'")
                        if start != -1:
                            end = js_line.find("'", start + 1)
                            if end != -1:
                                potential_url = js_line[start+1:end]
                                if 'server_lookup' in potential_url and ('?' in potential_url or potential_url.endswith(('.js', '.php'))):
                                    server_lookup = potential_url
                                    break

            if not server_lookup:
                logger.error('Failed to extract server lookup URL from iframe content')
                logger.debug(f'Iframe content sample: {iframe_content[:2000]}')
                raise ExtractorError('Failed to extract server lookup URL')

            server_lookup_url = f"https://{urlparse(iframe_url).netloc}{server_lookup}{channel_key}"
            try:
                lookup_resp = await self._make_request(server_lookup_url, headers=daddylive_headers, timeout=10)
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

            # Build final stream URL
            if server_key == 'top1/cdn':
                clean_m3u8_url = f'https://top1.newkso.ru/top1/cdn/{channel_key}/mono.m3u8'
                logger.info(f'Using special case URL for server_key \'top1/cdn\': {clean_m3u8_url}')
            else:
                # general case: attempt to assemble reasonable URL
                # if server_key contains slashes, leave as-is; otherwise use previous pattern
                if '/' in server_key:
                    parts = server_key.split('/')
                    domain = parts[0]
                    clean_m3u8_url = f'https://{domain}.newkso.ru/{server_key}/{channel_key}/mono.m3u8'
                else:
                    clean_m3u8_url = f'https://{server_key}new.newkso.ru/{server_key}/{channel_key}/mono.m3u8'
                logger.info(f'Using generated URL for server_key \'{server_key}\': {clean_m3u8_url}')

            # If newkso.ru domain, switch to hls_key_proxy and use iframe referer
            if "newkso.ru" in clean_m3u8_url:
                self.mediaflow_endpoint = "hls_key_proxy"
                stream_headers = {
                    'User-Agent': daddylive_headers['User-Agent'],
                    'Referer': iframe_url,
                    'Origin': referer_raw
                }
                logger.info("Using 'hls_key_proxy' for newkso.ru stream. Only the key will be proxied.")
            else:
                # Use key-only proxy for all DLHD streams as requested
                self.mediaflow_endpoint = "hls_key_proxy"
                stream_headers = {
                    'User-Agent': daddylive_headers['User-Agent'],
                    'Referer': referer_raw,
                    'Origin': referer_raw
                }
                logger.info("Using 'hls_key_proxy' for DLHD stream. Only the key will be proxied.")

            # cache auth data
            self._auth_cache[channel_id] = {
                "auth_data": {
                    "auth_host": auth_host,
                    "auth_php": auth_php,
                    "auth_ts": auth_ts,
                    "auth_rnd": auth_rnd,
                    "auth_sig": auth_sig
                },
                "iframe_url": iframe_url,
                "timestamp": __import__('time').time()
            }
            logger.info(f"Successfully cached auth data for channel_id: {channel_id}")

            return {
                "destination_url": clean_m3u8_url,
                "request_headers": stream_headers,
                "mediaflow_endpoint": self.mediaflow_endpoint,
            }

        try:
            parsed_original = urlparse(url)
            host_lower = parsed_original.netloc.lower()
            preferred = None
            if 'daddylive.sx' in host_lower:
                preferred = 'https://daddylive.sx/'
            elif 'dlhd.dad' in host_lower:
                preferred = 'https://dlhd.dad/'

            baseurl = await resolve_base_url(preferred)
            channel_id = extract_channel_id(url)
            if not channel_id:
                raise ExtractorError(f"Unable to extract channel ID from {url}")

            return await get_stream_data(baseurl, url, channel_id)

        except Exception as e:
            raise ExtractorError(f"Extraction failed: {str(e)}")
