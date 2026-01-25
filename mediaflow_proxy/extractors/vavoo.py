import logging
from typing import Any, Dict, Optional

from mediaflow_proxy.extractors.base import BaseExtractor, ExtractorError

logger = logging.getLogger(__name__)


class VavooExtractor(BaseExtractor):
    """Vavoo URL extractor for resolving vavoo.to links.

    Supports two URL formats:
    1. Web-VOD API links: https://vavoo.to/web-vod/api/get?link=...
       These redirect (302) to external video hosts (Doodstream, etc.)
    2. Legacy mediahubmx format (currently broken on Vavoo's end)

    Features:
    - Uses BaseExtractor's retry/timeouts
    - Improved headers to mimic Android okhttp client
    - Robust JSON handling and logging
    """

    def __init__(self, request_headers: dict):
        super().__init__(request_headers)
        self.mediaflow_endpoint = "proxy_stream_endpoint"

    async def _resolve_web_vod_link(self, url: str) -> str:
        """Resolve a web-vod API link by getting the redirect Location header."""
        import aiohttp

        try:
            # Use aiohttp directly with allow_redirects=False to get the Location header
            timeout = aiohttp.ClientTimeout(total=10)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(
                    url,
                    headers={"Accept": "application/json"},
                    allow_redirects=False,
                ) as resp:
                    # Check for redirect
                    if resp.status in (301, 302, 303, 307, 308):
                        location = resp.headers.get("Location") or resp.headers.get("location")
                        if location:
                            logger.info(f"Vavoo web-vod redirected to: {location}")
                            return location

                    # If we got a 200, the response might contain the URL
                    if resp.status == 200:
                        text = await resp.text()
                        if text and text.startswith("http"):
                            logger.info(f"Vavoo web-vod resolved to: {text.strip()}")
                            return text.strip()

                    raise ExtractorError(f"Vavoo web-vod API returned unexpected status {resp.status}")

        except ExtractorError:
            raise
        except Exception as e:
            raise ExtractorError(f"Failed to resolve Vavoo web-vod link: {e}")

    async def get_auth_signature(self) -> Optional[str]:
        """Get authentication signature for Vavoo API (async)."""
        headers = {
            "user-agent": "okhttp/4.11.0",
            "accept": "application/json",
            "content-type": "application/json; charset=utf-8",
            "accept-encoding": "gzip",
        }
        import time

        current_time = int(time.time() * 1000)

        data = {
            "token": "",
            "reason": "app-blur",
            "locale": "de",
            "theme": "dark",
            "metadata": {
                "device": {
                    "type": "Handset",
                    "brand": "google",
                    "model": "Pixel",
                    "name": "sdk_gphone64_arm64",
                    "uniqueId": "d10e5d99ab665233",
                },
                "os": {"name": "android", "version": "13"},
                "app": {"platform": "android", "version": "3.1.21"},
                "version": {"package": "tv.vavoo.app", "binary": "3.1.21", "js": "3.1.21"},
            },
            "appFocusTime": 0,
            "playerActive": False,
            "playDuration": 0,
            "devMode": False,
            "hasAddon": True,
            "castConnected": False,
            "package": "tv.vavoo.app",
            "version": "3.1.21",
            "process": "app",
            "firstAppStart": current_time,
            "lastAppStart": current_time,
            "ipLocation": "",
            "adblockEnabled": True,
            "proxy": {
                "supported": ["ss", "openvpn"],
                "engine": "ss",
                "ssVersion": 1,
                "enabled": True,
                "autoServer": True,
                "id": "de-fra",
            },
            "iap": {"supported": False},
        }

        try:
            resp = await self._make_request(
                "https://www.vavoo.tv/api/app/ping",
                method="POST",
                json=data,
                headers=headers,
                timeout=10,
                retries=2,
            )
            try:
                result = resp.json()
            except Exception:
                logger.warning("Vavoo ping returned non-json response (status=%s).", resp.status)
                return None

            addon_sig = result.get("addonSig") if isinstance(result, dict) else None
            if addon_sig:
                logger.info("Successfully obtained Vavoo authentication signature")
                return addon_sig
            else:
                logger.warning("No addonSig in Vavoo API response: %s", result)
                return None
        except ExtractorError as e:
            logger.warning("Failed to get Vavoo auth signature: %s", e)
            return None

    async def extract(self, url: str, **kwargs) -> Dict[str, Any]:
        """Extract Vavoo stream URL (async).

        Supports:
        - Direct play URLs: https://vavoo.to/play/{id}/index.m3u8 (Live TV)
        - Web-VOD API links: https://vavoo.to/web-vod/api/get?link=...
        - Legacy mediahubmx links (may not work due to Vavoo API changes)
        """
        if "vavoo.to" not in url:
            raise ExtractorError("Not a valid Vavoo URL")

        # Check if this is a direct play URL (Live TV)
        # These URLs are already m3u8 streams but need auth signature
        if "/play/" in url and url.endswith(".m3u8"):
            signature = await self.get_auth_signature()
            if not signature:
                raise ExtractorError("Failed to get Vavoo authentication signature for Live TV")

            stream_headers = {
                "user-agent": "okhttp/4.11.0",
                "referer": "https://vavoo.to/",
                "mediahubmx-signature": signature,
            }
            return {
                "destination_url": url,
                "request_headers": stream_headers,
                "mediaflow_endpoint": "hls_manifest_proxy",
            }

        # Check if this is a web-vod API link (new format)
        if "/web-vod/api/get" in url:
            resolved_url = await self._resolve_web_vod_link(url)
            stream_headers = {
                "user-agent": self.base_headers.get("user-agent", "Mozilla/5.0"),
                "referer": "https://vavoo.to/",
            }
            return {
                "destination_url": resolved_url,
                "request_headers": stream_headers,
                "mediaflow_endpoint": self.mediaflow_endpoint,
            }

        # Legacy mediahubmx flow
        signature = await self.get_auth_signature()
        if not signature:
            raise ExtractorError("Failed to get Vavoo authentication signature")

        resolved_url = await self._resolve_vavoo_link(url, signature)
        if not resolved_url:
            raise ExtractorError("Failed to resolve Vavoo URL")

        stream_headers = {
            "user-agent": self.base_headers.get("user-agent", "okhttp/4.11.0"),
            "referer": "https://vavoo.to/",
        }

        return {
            "destination_url": resolved_url,
            "request_headers": stream_headers,
            "mediaflow_endpoint": self.mediaflow_endpoint,
        }

    async def _resolve_vavoo_link(self, link: str, signature: str) -> Optional[str]:
        """Resolve a Vavoo link using the MediaHubMX API (async)."""
        headers = {
            "user-agent": "okhttp/4.11.0",
            "accept": "application/json",
            "content-type": "application/json; charset=utf-8",
            "accept-encoding": "gzip",
            "mediahubmx-signature": signature,
        }
        data = {"language": "de", "region": "AT", "url": link, "clientVersion": "3.1.21"}
        try:
            logger.info(f"Attempting to resolve Vavoo URL: {link}")
            resp = await self._make_request(
                "https://vavoo.to/mediahubmx-resolve.json",
                method="POST",
                json=data,
                headers=headers,
                timeout=12,
                retries=3,
                backoff_factor=0.6,
            )
            try:
                result = resp.json()
            except Exception:
                logger.warning(
                    "Vavoo resolve returned non-json response (status=%s). Body preview: %s",
                    resp.status,
                    getattr(resp, "text", "")[:500],
                )
                return None

            logger.debug("Vavoo API response: %s", result)

            # Accept either list or dict with 'url'
            if isinstance(result, list) and result and isinstance(result[0], dict) and result[0].get("url"):
                resolved_url = result[0]["url"]
                logger.info("Successfully resolved Vavoo URL to: %s", resolved_url)
                return resolved_url
            elif isinstance(result, dict) and result.get("url"):
                resolved_url = result["url"]
                logger.info("Successfully resolved Vavoo URL to: %s", resolved_url)
                return resolved_url
            else:
                logger.warning("No URL found in Vavoo API response: %s", result)
                return None
        except ExtractorError as e:
            logger.error(f"Vavoo resolution failed for URL {link}: {e}")
            raise ExtractorError(f"Vavoo resolution failed: {str(e)}") from e
        except Exception as e:
            logger.error(f"Unexpected error while resolving Vavoo URL {link}: {e}")
            raise ExtractorError(f"Vavoo resolution failed: {str(e)}") from e
