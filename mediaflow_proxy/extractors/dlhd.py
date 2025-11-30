import re
import base64
import logging

from typing import Any, Dict, Optional, List
from urllib.parse import urlparse, quote_plus, urljoin


import httpx


from mediaflow_proxy.extractors.base import BaseExtractor, ExtractorError


logger = logging.getLogger(__name__)

# Silenzia l'errore ConnectionResetError su Windows
logging.getLogger('asyncio').setLevel(logging.CRITICAL)


class DLHDExtractor(BaseExtractor):
    """DLHD (DaddyLive) URL extractor for M3U8 streams.


    Notes:
    - Multi-domain support for daddylive.sx / dlhd.dad
    - Robust extraction of auth parameters and server lookup
    - Uses retries/timeouts via BaseExtractor where possible
    - Multi-iframe fallback for resilience
    """


    def __init__(self, request_headers: dict):
        super().__init__(request_headers)
        self.mediaflow_endpoint = "hls_manifest_proxy"
        self._iframe_context: Optional[str] = None



    async def _make_request(self, url: str, method: str = "GET", headers: Optional[Dict] = None, **kwargs) -> Any:
        """Override to disable SSL verification for this extractor and use fetch_with_retry if available."""
        from mediaflow_proxy.utils.http_utils import create_httpx_client, fetch_with_retry


        timeout = kwargs.pop("timeout", 15)
        retries = kwargs.pop("retries", 3)
        backoff_factor = kwargs.pop("backoff_factor", 0.5)


        async with create_httpx_client(verify=False, timeout=httpx.Timeout(timeout)) as client:
            try:
                return await fetch_with_retry(client, method, url, headers or {}, timeout=timeout)
            except Exception:
                logger.debug("fetch_with_retry failed or unavailable; falling back to direct request for %s", url)
                response = await client.request(method, url, headers=headers or {}, timeout=timeout)
                response.raise_for_status()
                return response


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
                    if '.m3u8' in match and match.startswith('http'):
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
                    server = server_match.group(1) if server_match else 'newkso.ru'
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
                raise ExtractorError(f"Could not find stream URL in lovecdn.ru iframe")
            
            # Usa iframe URL come referer
            iframe_origin = f"https://{urlparse(iframe_url).netloc}"
            stream_headers = {
                'User-Agent': headers['User-Agent'],
                'Referer': iframe_url,
                'Origin': iframe_origin
            }
            
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
        auth_url = 'https://security.newkso.ru/auth2.php'
        # Use files parameter to force multipart/form-data which is required by the server
        # (None, value) tells httpx to send it as a form field, not a file upload
        multipart_data = {
            'channelKey': (None, params["channel_key"]),
            'country': (None, params["auth_country"]),
            'timestamp': (None, params["auth_ts"]),
            'expiry': (None, params["auth_expiry"]),
            'token': (None, params["auth_token"]),
        }

        iframe_origin = f"https://{urlparse(iframe_url).netloc}"
        auth_headers = headers.copy()
        auth_headers.update({
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Origin': iframe_origin,
            'Referer': iframe_url,
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'cross-site',
            'Priority': 'u=1, i',
        })
        
        from mediaflow_proxy.utils.http_utils import create_httpx_client
        try:
            async with create_httpx_client(verify=False) as client:
                # Note: using 'files' instead of 'data' to ensure multipart/form-data Content-Type
                auth_resp = await client.post(auth_url, files=multipart_data, headers=auth_headers, timeout=12)
                auth_resp.raise_for_status()
                auth_data = auth_resp.json()
                if not (auth_data.get("valid") or auth_data.get("success")):
                    raise ExtractorError(f"Initial auth failed with response: {auth_data}")
            logger.info("New auth flow: Initial auth successful.")
        except Exception as e:
            raise ExtractorError(f"New auth flow failed during initial auth POST: {e}")

        # 2. Server Lookup
        server_lookup_url = f"https://{urlparse(iframe_url).netloc}/server_lookup.js?channel_id={params['channel_key']}"
        try:
            # Use _make_request as it handles retries and expects JSON
            lookup_resp = await self._make_request(server_lookup_url, headers=headers, timeout=10)
            server_data = lookup_resp.json()
            server_key = server_data.get('server_key')
            if not server_key:
                raise ExtractorError(f"No server_key in lookup response: {server_data}")
            logger.info(f"New auth flow: Server lookup successful - Server key: {server_key}")
        except Exception as e:
            raise ExtractorError(f"New auth flow failed during server lookup: {e}")

        # 3. Build final stream URL
        channel_key = params['channel_key']
        auth_token = params['auth_token']
        # The JS logic uses .css, not .m3u8
        if server_key == 'top1/cdn':
            stream_url = f'https://top1.newkso.ru/top1/cdn/{channel_key}/mono.css'
        else:
            stream_url = f'https://{server_key}new.newkso.ru/{server_key}/{channel_key}/mono.css'
        
        logger.info(f'New auth flow: Constructed stream URL: {stream_url}')

        stream_headers = {
            'User-Agent': headers['User-Agent'],
            'Referer': iframe_url,
            'Origin': iframe_origin,
            'Authorization': f'Bearer {auth_token}',
            'X-Channel-Key': channel_key
        }

        return {
            "destination_url": stream_url,
            "request_headers": stream_headers,
            "mediaflow_endpoint": "hls_manifest_proxy",
        }

    async def extract(self, url: str, **kwargs) -> Dict[str, Any]:
        """Main extraction flow: resolve base, fetch players, extract iframe, auth and final m3u8."""
        baseurl = "https://dlhd.dad/"

        def extract_channel_id(u: str) -> Optional[str]:
            match_watch_id = re.search(r'watch\.php\?id=(\d+)', u)
            if match_watch_id:
                return match_watch_id.group(1)
            return None


        async def get_stream_data(initial_url: str):
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


            # Prova tutti i player e raccogli tutti gli iframe validi
            last_player_error = None
            iframe_candidates = []

            for player_url in player_links:
                try:
                    if not player_url.startswith('http'):
                        player_url = baseurl + player_url.lstrip('/')


                    daddylive_headers['Referer'] = player_url
                    daddylive_headers['Origin'] = player_url
                    resp2 = await self._make_request(player_url, headers=daddylive_headers, timeout=12)
                    iframes2 = re.findall(r'<iframe.*?src="([^"]*)"', resp2.text)

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


            # Prova ogni iframe finché uno non funziona
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

                    if 'lovecdn.ru' in iframe_domain:
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


        try:
            channel_id = extract_channel_id(url)
            if not channel_id:
                raise ExtractorError(f"Unable to extract channel ID from {url}")

            logger.info(f"Using base domain: {baseurl}")
            return await get_stream_data(url)


        except Exception as e:
            raise ExtractorError(f"Extraction failed: {str(e)}")
