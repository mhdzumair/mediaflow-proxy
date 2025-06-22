import re
import base64
from typing import Any, Dict, Optional
from urllib.parse import urlparse, quote

from mediaflow_proxy.extractors.base import BaseExtractor, ExtractorError

class DLHDExtractor(BaseExtractor):
    """DLHD (DaddyLive) URL extractor for M3U8 streams."""

    def __init__(self, request_headers: dict):
        super().__init__(request_headers)
        # Default to HLS proxy endpoint
        self.mediaflow_endpoint = "hls_manifest_proxy"

    async def extract(self, url: str, **kwargs) -> Dict[str, Any]:
        """Extract DLHD stream URL and required headers."""
        try:
            channel_url = url
            channel_origin = self._get_origin(channel_url)

            player_url_from_arg = kwargs.get("player_url")
            stream_url_from_arg = kwargs.get("stream_url")
            auth_url_base_from_arg = kwargs.get("auth_url_base")

            current_player_url_for_processing: str

            # Se non fornito, estrai player_url dalla pagina del canale
            if not player_url_from_arg:
                channel_headers = {
                    "referer": channel_origin + "/",
                    "origin": channel_origin,
                    "user-agent": self.base_headers["user-agent"],
                }
                channel_response = await self._make_request(channel_url, headers=channel_headers)
                extracted_iframe_url = self._extract_player_url(channel_response.text)
                if not extracted_iframe_url:
                    raise ExtractorError("Could not extract player URL from channel page")
                current_player_url_for_processing = extracted_iframe_url
            else:
                current_player_url_for_processing = player_url_from_arg

            # 1° tentativo: _handle_vecloud
            referer_for_vecloud = channel_origin + "/"
            if re.search(r"/stream/([a-zA-Z0-9-]+)", current_player_url_for_processing):
                referer_for_vecloud = self._get_origin(current_player_url_for_processing) + "/"
            try:
                return await self._handle_vecloud(current_player_url_for_processing, referer_for_vecloud)
            except Exception:
                # LOGICA AGGIUNTA: se fallisce e la URL contiene /stream/stream, prova con /cast/stream
                stream_pattern = re.compile(r"/stream/([a-zA-Z0-9\-]+\.php)")
                match = stream_pattern.search(current_player_url_for_processing)
                if match:
                    alternative_url = current_player_url_for_processing.replace("/stream/", "/cast/", 1)
                    try:
                        referer_for_vecloud_alt = self._get_origin(alternative_url) + "/"
                        return await self._handle_vecloud(alternative_url, referer_for_vecloud_alt)
                    except Exception:
                        pass  # anche il secondo tentativo è fallito, prosegui con fallback
                pass

            # 2° tentativo: se non è una /stream/, prova _handle_playnow e poi _handle_vecloud
            if not re.search(r"/stream/([a-zA-Z0-9-]+)", current_player_url_for_processing):
                try:
                    playnow_derived_player_url = await self._handle_playnow(current_player_url_for_processing, channel_origin + "/")
                    if re.search(r"/stream/([a-zA-Z0-9-]+)", playnow_derived_player_url):
                        try:
                            referer_for_vecloud_after_playnow = self._get_origin(playnow_derived_player_url) + "/"
                            return await self._handle_vecloud(playnow_derived_player_url, referer_for_vecloud_after_playnow)
                        except Exception:
                            pass
                except Exception:
                    pass

            # Fallback: autenticazione standard
            player_url_for_auth = current_player_url_for_processing
            player_origin_for_auth = self._get_origin(player_url_for_auth)

            player_headers = {
                "referer": player_origin_for_auth + "/",
                "origin": player_origin_for_auth,
                "user-agent": self.base_headers["user-agent"],
            }

            player_response = await self._make_request(player_url_for_auth, headers=player_headers)
            player_content = player_response.text

            auth_data = self._extract_auth_data(player_content)
            if not auth_data:
                raise ExtractorError("Failed to extract authentication data from player")

            final_auth_url_base = auth_url_base_from_arg
            if not final_auth_url_base:
                final_auth_url_base = self._extract_auth_url_base(player_content)
            if not final_auth_url_base:
                if stream_url_from_arg:
                    final_auth_url_base = self._get_origin(stream_url_from_arg)
                else:
                    player_domain_for_auth_derive = self._get_origin(player_url_for_auth)
                    final_auth_url_base = self._derive_auth_url_base(player_domain_for_auth_derive)
            if not final_auth_url_base:
                raise ExtractorError("Could not determine auth URL base")

            auth_url = (
                f"{final_auth_url_base}/auth.php?channel_id={auth_data['channel_key']}"
                f"&ts={auth_data['auth_ts']}&rnd={auth_data['auth_rnd']}"
                f"&sig={quote(auth_data['auth_sig'])}"
            )

            auth_req_headers = {
                "referer": player_origin_for_auth + "/",
                "origin": player_origin_for_auth,
                "user-agent": self.base_headers["user-agent"],
            }

            auth_response = await self._make_request(auth_url, headers=auth_req_headers)

            if auth_response.json().get("status") != "ok":
                raise ExtractorError("Authentication failed")

            final_stream_url = stream_url_from_arg
            if not final_stream_url:
                final_stream_url = await self._lookup_server(
                    lookup_url_base=player_origin_for_auth,
                    auth_url_base=final_auth_url_base,
                    auth_data=auth_data,
                    headers=auth_req_headers,
                )

            stream_headers = {
                "referer": player_url_for_auth,
                "origin": player_origin_for_auth,
                "user-agent": self.base_headers["user-agent"],
            }

            return {
                "destination_url": final_stream_url,
                "request_headers": stream_headers,
                "mediaflow_endpoint": self.mediaflow_endpoint,
            }

        except Exception as e:
            raise ExtractorError(f"Extraction failed: {str(e)}")

    async def _handle_vecloud(self, player_url: str, channel_referer: str) -> Dict[str, Any]:
        """Handle vecloud URLs with their specific API."""
        try:
            stream_id_match = re.search(r"/stream/([a-zA-Z0-9-]+)", player_url)
            if not stream_id_match:
                raise ExtractorError("Could not extract stream ID from vecloud URL")
            stream_id = stream_id_match.group(1)

            response = await self._make_request(
                player_url, headers={"referer": channel_referer, "user-agent": self.base_headers["user-agent"]}
            )
            player_url = str(response.url)

            player_parsed = urlparse(player_url)
            player_domain = player_parsed.netloc
            player_origin = f"{player_parsed.scheme}://{player_parsed.netloc}"
            api_url = f"{player_origin}/api/source/{stream_id}?type=live"

            api_headers = {
                "referer": player_url,
                "origin": player_origin,
                "user-agent": self.base_headers["user-agent"],
                "content-type": "application/json",
            }

            api_data = {"r": channel_referer, "d": player_domain}

            api_response = await self._make_request(api_url, method="POST", headers=api_headers, json=api_data)
            api_data = api_response.json()

            if not api_data.get("success"):
                raise ExtractorError("Vecloud API request failed")

            stream_url = api_data.get("player", {}).get("source_file")
            if not stream_url:
                raise ExtractorError("Could not find stream URL in vecloud response")

            stream_headers = {
                "referer": player_origin + "/",
                "origin": player_origin,
                "user-agent": self.base_headers["user-agent"],
            }

            return {
                "destination_url": stream_url,
                "request_headers": stream_headers,
                "mediaflow_endpoint": self.mediaflow_endpoint,
            }

        except Exception as e:
            raise ExtractorError(f"Vecloud extraction failed: {str(e)}")

    async def _handle_playnow(self, player_iframe: str, channel_origin: str) -> str:
        playnow_headers = {"referer": channel_origin + "/", "user-agent": self.base_headers["user-agent"]}
        playnow_response = await self._make_request(player_iframe, headers=playnow_headers)
        player_url = self._extract_player_url(playnow_response.text)
        if not player_url:
            raise ExtractorError("Could not extract player URL from playnow response")
        return player_url

    def _extract_player_url(self, html_content: str) -> Optional[str]:
        try:
            iframe_match = re.search(
                r'<iframe[^>]*src=["\']([^"\']+)["\'][^>]*allowfullscreen', html_content, re.IGNORECASE
            )
            if not iframe_match:
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
        try:
            server_lookup_url = f"{lookup_url_base}/server_lookup.php?channel_id={quote(auth_data['channel_key'])}"
            server_response = await self._make_request(server_lookup_url, headers=headers)
            server_data = server_response.json()
            server_key = server_data.get("server_key")
            if not server_key:
                raise ExtractorError("Failed to get server key")
            auth_domain_parts = urlparse(auth_url_base).netloc.split(".")
            domain_suffix = ".".join(auth_domain_parts[1:]) if len(auth_domain_parts) > 1 else auth_domain_parts[0]
            if "/" in server_key:
                parts = server_key.split("/")
                return f"<https://{parts>[0]}.{domain_suffix}/{server_key}/{auth_data['channel_key']}/mono.m3u8"
            else:
                return f"https://{server_key}new.{domain_suffix}/{server_key}/{auth_data['channel_key']}/mono.m3u8"
        except Exception as e:
            raise ExtractorError(f"Server lookup failed: {str(e)}")

    def _extract_auth_data(self, html_content: str) -> Dict[str, str]:
        try:
            channel_key_match = re.search(r'var\s+channelKey\s*=\s*["\']([^"\']+)["\']', html_content)
            if not channel_key_match:
                return {}
            channel_key = channel_key_match.group(1)
            auth_ts_match = re.search(r'var\s+__c\s*=\s*atob\([\'"]([^\'"]+)[\'"]\)', html_content)
            auth_rnd_match = re.search(r'var\s+__d\s*=\s*atob\([\'"]([^\'"]+)[\'"]\)', html_content)
            auth_sig_match = re.search(r'var\s+__e\s*=\s*atob\([\'"]([^\'"]+)[\'"]\)', html_content)
            if all([auth_ts_match, auth_rnd_match, auth_sig_match]):
                return {
                    "channel_key": channel_key,
                    "auth_ts": base64.b64decode(auth_ts_match.group(1)).decode("utf-8"),
                    "auth_rnd": base64.b64decode(auth_rnd_match.group(1)).decode("utf-8"),
                    "auth_sig": base64.b64decode(auth_sig_match.group(1)).decode("utf-8"),
                }
            auth_ts_match = re.search(r'var\s+authTs\s*=\s*["\']([^"\']+)["\']', html_content)
            auth_rnd_match = re.search(r'var\s+authRnd\s*=\s*["\']([^"\']+)["\']', html_content)
            auth_sig_match = re.search(r'var\s+authSig\s*=\s*["\']([^"\']+)["\']', html_content)
            if all([auth_ts_match, auth_rnd_match, auth_sig_match]):
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
        try:
            auth_url_base_match = re.search(r'var\s+__a\s*=\s*atob\([\'"]([^\'"]+)[\'"]\)', html_content)
            if auth_url_base_match:
                decoded_url = base64.b64decode(auth_url_base_match.group(1)).decode("utf-8")
                return decoded_url.strip().rstrip("/")
            auth_url_match = re.search(r'fetchWithRetry\([\'"]([^\'"]*/auth\.php)', html_content)
            if auth_url_match:
                auth_url = auth_url_match.group(1)
                return auth_url.split("/auth.php")[0]
            domain_match = re.search(r'[\'"]https://([^/\'\"]+)(?:/[^\'\"]*)?/auth\.php', html_content)
            if domain_match:
                return f"https://{domain_match.group(1)}"
            return None
        except Exception:
            return None

    def _get_origin(self, url: str) -> str:
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"

    def _derive_auth_url_base(self, player_domain: str) -> Optional[str]:
        try:
            parsed = urlparse(player_domain)
            domain_parts = parsed.netloc.split(".")
            if len(domain_parts) >= 2:
                base_domain = ".".join(domain_parts[-2:])
                for prefix in ["auth", "api", "cdn"]:
                    potential_auth_domain = f"https://{prefix}.{base_domain}"
                    return potential_auth_domain
            return None
        except Exception:
            return None
