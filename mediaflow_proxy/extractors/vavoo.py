from typing import Any, Dict, Optional
from mediaflow_proxy.extractors.base import BaseExtractor, ExtractorError

class VavooExtractor(BaseExtractor):
    """Vavoo URL extractor for resolving vavoo.to links (solo httpx, async)."""

    def __init__(self, request_headers: dict):
        super().__init__(request_headers)
        self.mediaflow_endpoint = "proxy_stream_endpoint"

    async def get_auth_signature(self) -> Optional[str]:
        """Get authentication signature for Vavoo API (async, httpx, pulito)."""
        import httpx
        headers = {
            "user-agent": "okhttp/4.11.0",
            "accept": "application/json", 
            "content-type": "application/json; charset=utf-8",
            "accept-encoding": "gzip"
        }
        data = {
            "token": "tosFwQCJMS8qrW_AjLoHPQ41646J5dRNha6ZWHnijoYQQQoADQoXYSo7ki7O5-CsgN4CH0uRk6EEoJ0728ar9scCRQW3ZkbfrPfeCXW2VgopSW2FWDqPOoVYIuVPAOnXCZ5g",
            "reason": "app-blur",
            "locale": "de",
            "theme": "dark",
            "metadata": {
                "device": {
                    "type": "Handset",
                    "brand": "google",
                    "model": "Nexus",
                    "name": "21081111RG",
                    "uniqueId": "d10e5d99ab665233"
                },
                "os": {
                    "name": "android",
                    "version": "7.1.2",
                    "abis": ["arm64-v8a", "armeabi-v7a", "armeabi"],
                    "host": "android"
                },
                "app": {
                    "platform": "android",
                    "version": "3.1.20",
                    "buildId": "289515000",
                    "engine": "hbc85",
                    "signatures": ["6e8a975e3cbf07d5de823a760d4c2547f86c1403105020adee5de67ac510999e"],
                    "installer": "app.revanced.manager.flutter"
                },
                "version": {
                    "package": "tv.vavoo.app",
                    "binary": "3.1.20",
                    "js": "3.1.20"
                }
            },
            "appFocusTime": 0,
            "playerActive": False,
            "playDuration": 0,
            "devMode": False,
            "hasAddon": True,
            "castConnected": False,
            "package": "tv.vavoo.app",
            "version": "3.1.20",
            "process": "app",
            "firstAppStart": 1743962904623,
            "lastAppStart": 1743962904623,
            "ipLocation": "",
            "adblockEnabled": True,
            "proxy": {
                "supported": ["ss", "openvpn"],
                "engine": "ss", 
                "ssVersion": 1,
                "enabled": True,
                "autoServer": True,
                "id": "pl-waw"
            },
            "iap": {
                "supported": False
            }
        }
        try:
            async with httpx.AsyncClient(timeout=20) as client:
                resp = await client.post("https://www.vavoo.tv/api/app/ping", json=data, headers=headers)
                resp.raise_for_status()
                result = resp.json()
                addon_sig = result.get("addonSig")
                return addon_sig if addon_sig else None
        except Exception:
            return None

    async def extract(self, url: str, **kwargs) -> Dict[str, Any]:
        """Extract Vavoo stream URL (async, httpx)."""
        if "vavoo.to" not in url:
            raise ExtractorError("Not a valid Vavoo URL")

        # Get authentication signature
        signature = await self.get_auth_signature()
        if not signature:
            raise ExtractorError("Failed to get Vavoo authentication signature")

        # Resolve the URL
        resolved_url = await self._resolve_vavoo_link(url, signature)
        if not resolved_url:
            raise ExtractorError("Failed to resolve Vavoo URL")

        # Set up headers for the resolved stream
        stream_headers = {
            "user-agent": self.base_headers["user-agent"],
            "referer": "https://vavoo.to/",
        }

        return {
            "destination_url": resolved_url,
            "request_headers": stream_headers,
            "mediaflow_endpoint": self.mediaflow_endpoint,
        }

    async def _resolve_vavoo_link(self, link: str, signature: str) -> Optional[str]:
        """Resolve a Vavoo link using the MediaHubMX API (async, httpx)."""
        headers = {
            "user-agent": "MediaHubMX/2",
            "accept": "application/json",
            "content-type": "application/json; charset=utf-8", 
            "accept-encoding": "gzip",
            "mediahubmx-signature": signature
        }
        data = {
            "language": "de",
            "region": "AT", 
            "url": link,
            "clientVersion": "3.0.2"
        }
        try:
            async with httpx.AsyncClient(timeout=20) as client:
                resp = await client.post("https://vavoo.to/mediahubmx-resolve.json", json=data, headers=headers)
                resp.raise_for_status()
                result = resp.json()
                if isinstance(result, list) and result and result[0].get("url"):
                    return result[0]["url"]
                elif isinstance(result, dict) and result.get("url"):
                    return result["url"]
                else:
                    return None
        except Exception as e:
            raise ExtractorError(f"Vavoo resolution failed: {str(e)}") 
