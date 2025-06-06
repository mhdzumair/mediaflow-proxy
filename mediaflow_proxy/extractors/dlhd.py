import re
from typing import Dict, Any, Optional
from urllib.parse import urlparse, quote

from mediaflow_proxy.extractors.base import BaseExtractor, ExtractorError


class DLHDExtractor(BaseExtractor):
    """DLHD (DaddyLive) URL extractor for M3U8 streams."""

    def __init__(self, request_headers: dict):
        super().__init__(request_headers)
        # Default to HLS proxy endpoint
        self.mediaflow_endpoint = "hls_manifest_proxy"

    async def extract(self, url: str, **kwargs) -> Dict[str, Any]:
        """Extract DLHD stream URL and required headers.

        Args:
            url: The DaddyLive channel URL (required)

        Keyword Args:
            player_url: Direct player URL (optional)
            stream_url: The stream URL (optional)
            auth_url_base: Base URL for auth requests (optional)

        Returns:
            Dict containing stream URL and required headers
        """
        try:
            # Channel URL is required and serves as the referer
            channel_url = url
            player_origin = self._get_origin(channel_url)

            # Check for direct parameters
            player_url = kwargs.get("player_url")
            stream_url = kwargs.get("stream_url")
            auth_url_base = kwargs.get("auth_url_base")

            # If player URL not provided, extract it from channel page
            if not player_url:
                # Get the channel page to extract the player iframe URL
                channel_headers = {
                    "referer": player_origin + "/",
                    "origin": player_origin,
                    "user-agent": self.base_headers["user-agent"],
                }

                channel_response = await self._make_request(channel_url, headers=channel_headers)
                player_url = self._extract_player_url(channel_response.text)

                if not player_url:
                    raise ExtractorError("Could not extract player URL from channel page")

                if not re.search(r"/stream/([a-zA-Z0-9-]+)", player_url):
                    iframe_player_url = await self._handle_playnow(player_url, player_origin)
                    player_origin = self._get_origin(player_url)
                    player_url = iframe_player_url

            try:
                return await self._handle_vecloud(player_url, player_origin + "/")
            except Exception as e:
                pass

            # Get player page to extract authentication information
            player_headers = {
                "referer": player_origin + "/",
                "origin": player_origin,
                "user-agent": self.base_headers["user-agent"],
            }

            player_response = await self._make_request(player_url, headers=player_headers)
            player_content = player_response.text

            # Extract authentication details from script tag
            auth_data = self._extract_auth_data(player_content)
            if not auth_data:
                raise ExtractorError("Failed to extract authentication data from player")

            # Extract auth URL base if not provided
            if not auth_url_base:
                auth_url_base = self._extract_auth_url_base(player_content)

            # If still no auth URL base, try to derive from stream URL or player URL
            if not auth_url_base:
                if stream_url:
                    auth_url_base = self._get_origin(stream_url)
                else:
                    # Try to extract from player URL structure
                    player_domain = self._get_origin(player_url)
                    # Attempt to construct a standard auth domain
                    auth_url_base = self._derive_auth_url_base(player_domain)

                if not auth_url_base:
                    raise ExtractorError("Could not determine auth URL base")

            # Construct auth URL
            auth_url = (
                f"{auth_url_base}/auth.php?channel_id={auth_data['channel_key']}"
                f"&ts={auth_data['auth_ts']}&rnd={auth_data['auth_rnd']}"
                f"&sig={quote(auth_data['auth_sig'])}"
            )

            # Make auth request
            player_origin = self._get_origin(player_url)
            auth_headers = {
                "referer": player_origin + "/",
                "origin": player_origin,
                "user-agent": self.base_headers["user-agent"],
            }

            auth_response = await self._make_request(auth_url, headers=auth_headers)

            # Check if authentication succeeded
            if auth_response.json().get("status") != "ok":
                raise ExtractorError("Authentication failed")

            # If no stream URL provided, look up the server and generate the stream URL
            if not stream_url:
                stream_url = await self._lookup_server(
                    lookup_url_base=player_origin,
                    auth_url_base=auth_url_base,
                    auth_data=auth_data,
                    headers=auth_headers,
                )

            # Set up the final stream headers
            stream_headers = {
                "referer": player_url,
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
            raise ExtractorError(f"Extraction failed: {str(e)}")

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
            # Extract channel key
            channel_key_match = re.search(r'var\s+channelKey\s*=\s*["\']([^"\']+)["\']', html_content)
            # Extract auth timestamp
            auth_ts_match = re.search(r'var\s+authTs\s*=\s*["\']([^"\']+)["\']', html_content)
            # Extract auth random value
            auth_rnd_match = re.search(r'var\s+authRnd\s*=\s*["\']([^"\']+)["\']', html_content)
            # Extract auth signature
            auth_sig_match = re.search(r'var\s+authSig\s*=\s*["\']([^"\']+)["\']', html_content)

            if not all([channel_key_match, auth_ts_match, auth_rnd_match, auth_sig_match]):
                return {}

            return {
                "channel_key": channel_key_match.group(1),
                "auth_ts": auth_ts_match.group(1),
                "auth_rnd": auth_rnd_match.group(1),
                "auth_sig": auth_sig_match.group(1),
            }
        except Exception:
            return {}

    def _extract_auth_url_base(self, html_content: str) -> Optional[str]:
        """Extract auth URL base from player page script content."""
        try:
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
