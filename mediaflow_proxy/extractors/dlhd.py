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
                # LOGICA MODIFICATA: se fallisce e la URL contiene /stream/, prova con /cast/
                if "/stream/" in current_player_url_for_processing:
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

    # ... Tutte le altre funzioni della classe rimangono invariate (come da file allegato) ...
