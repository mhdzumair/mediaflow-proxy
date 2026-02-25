import logging
import time
import re
import uuid
from typing import Any, Dict, Optional
from urllib.parse import quote

from mediaflow_proxy.extractors.base import BaseExtractor, ExtractorError

logger = logging.getLogger(__name__)


class VavooExtractor(BaseExtractor):
    """Vavoo URL extractor per risolvere link vavoo.to"""

    API_UA = "electron-fetch/1.0 electron (+https://github.com/arantes555/electron-fetch)"
    TS_UA = "VAVOO/2.6"

    def __init__(self, request_headers: dict):
        super().__init__(request_headers)
        self.mediaflow_endpoint = "proxy_stream_endpoint"

    async def _get_auth_signature(self) -> Optional[str]:
        """Get authentication signature via /api/app/ping (electron flow)."""
        unique_id = uuid.uuid4().hex[:16]
        headers = {
            "user-agent": self.API_UA,
            "accept": "*/*",
            "Accept-Language": "de",
            "Accept-Encoding": "gzip, deflate",
            "content-type": "application/json; charset=utf-8",
            "Connection": "close",
        }
        body = {
            "token": "8Us2TfjeOFrzqFFTEjL3E5KfdAWGa5PV3wQe60uK4BmzlkJRMYFu0ufaM_eeDXKS2U04XUuhbDTgGRJrJARUwzDyCcRToXhW5AcDekfFMfwNUjuieeQ1uzeDB9YWyBL2cn5Al3L3gTnF8Vk1t7rPwkBob0swvxA",
            "reason": "player.enter",
            "locale": "de",
            "theme": "dark",
            "metadata": {
                "device": {"type": "Desktop", "brand": "Unknown", "model": "Unknown", "name": "Unknown", "uniqueId": unique_id},
                "os": {"name": "windows", "version": "10.0.22631", "abis": [], "host": "electron"},
                "app": {"platform": "electron", "version": "3.1.4", "buildId": "288045000", "engine": "jsc", "signatures": [], "installer": "unknown"},
                "version": {"package": "tv.vavoo.app", "binary": "3.1.4", "js": "3.1.4"},
            },
            "appFocusTime": 27229,
            "playerActive": True,
            "playDuration": 0,
            "devMode": False,
            "hasAddon": False,
            "castConnected": False,
            "package": "tv.vavoo.app",
            "version": "3.1.4",
            "process": "app",
            "firstAppStart": int(time.time() * 1000) - 86400000,
            "lastAppStart": int(time.time() * 1000),
            "ipLocation": "",
            "adblockEnabled": False,
            "proxy": {"supported": ["ss"], "engine": "ss", "enabled": False, "autoServer": True, "id": "ca-bhs"},
            "iap": {"supported": True},
        }
        try:
            resp = await self._make_request(
                "https://www.vavoo.tv/api/app/ping",
                method="POST",
                json=body,
                headers=headers,
                timeout=15,
                retries=2,
            )
            try:
                result = resp.json()
            except Exception:
                logger.warning("Vavoo ping returned non-json response (status=%s).", resp.status)
                return None
            addon_sig = result.get("addonSig") if isinstance(result, dict) else None
            if addon_sig:
                logger.info("Successfully obtained Vavoo auth signature (electron mode)")
                return addon_sig
            logger.warning("No addonSig in Vavoo API response: %s", result)
            return None
        except Exception as e:
            logger.debug("_get_auth_signature error: %s", e)
            return None

    async def _get_ts_signature(self) -> Optional[str]:
        """Get TS-based signature via /api/box/ping2 (fallback)."""
        vec = "9frjpxPjxSNilxJPCJ0XGYs6scej3dW/h/VWlnKUiLSG8IP7mfyDU7NirOlld+VtCKGj03XjetfliDMhIev7wcARo+YTU8KPFuVQP9E2DVXzY2BFo1NhE6qEmPfNDnm74eyl/7iFJ0EETm6XbYyz8IKBkAqPN/Spp3PZ2ulKg3QBSDxcVN4R5zRn7OsgLJ2CNTuWkd/h451lDCp+TtTuvnAEhcQckdsydFhTZCK5IiWrrTIC/d4qDXEd+GtOP4hPdoIuCaNzYfX3lLCwFENC6RZoTBYLrcKVVgbqyQZ7DnLqfLqvf3z0FVUWx9H21liGFpByzdnoxyFkue3NzrFtkRL37xkx9ITucepSYKzUVEfyBh+/3mtzKY26VIRkJFkpf8KVcCRNrTRQn47Wuq4gC7sSwT7eHCAydKSACcUMMdpPSvbvfOmIqeBNA83osX8FPFYUMZsjvYNEE3arbFiGsQlggBKgg1V3oN+5ni3Vjc5InHg/xv476LHDFnNdAJx448ph3DoAiJjr2g4ZTNynfSxdzA68qSuJY8UjyzgDjG0RIMv2h7DlQNjkAXv4k1BrPpfOiOqH67yIarNmkPIwrIV+W9TTV/yRyE1LEgOr4DK8uW2AUtHOPA2gn6P5sgFyi68w55MZBPepddfYTQ+E1N6R/hWnMYPt/i0xSUeMPekX47iucfpFBEv9Uh9zdGiEB+0P3LVMP+q+pbBU4o1NkKyY1V8wH1Wilr0a+q87kEnQ1LWYMMBhaP9yFseGSbYwdeLsX9uR1uPaN+u4woO2g8sw9Y5ze5XMgOVpFCZaut02I5k0U4WPyN5adQjG8sAzxsI3KsV04DEVymj224iqg2Lzz53Xz9yEy+7/85ILQpJ6llCyqpHLFyHq/kJxYPhDUF755WaHJEaFRPxUqbparNX+mCE9Xzy7Q/KTgAPiRS41FHXXv+7XSPp4cy9jli0BVnYf13Xsp28OGs/D8Nl3NgEn3/eUcMN80JRdsOrV62fnBVMBNf36+LbISdvsFAFr0xyuPGmlIETcFyxJkrGZnhHAxwzsvZ+Uwf8lffBfZFPRrNv+tgeeLpatVcHLHZGeTgWWml6tIHwWUqv2TVJeMkAEL5PPS4Gtbscau5HM+FEjtGS+KClfX1CNKvgYJl7mLDEf5ZYQv5kHaoQ6RcPaR6vUNn02zpq5/X3EPIgUKF0r/0ctmoT84B2J1BKfCbctdFY9br7JSJ6DvUxyde68jB+Il6qNcQwTFj4cNErk4x719Y42NoAnnQYC2/qfL/gAhJl8TKMvBt3Bno+va8ve8E0z8yEuMLUqe8OXLce6nCa+L5LYK1aBdb60BYbMeWk1qmG6Nk9OnYLhzDyrd9iHDd7X95OM6X5wiMVZRn5ebw4askTTc50xmrg4eic2U1w1JpSEjdH/u/hXrWKSMWAxaj34uQnMuWxPZEXoVxzGyuUbroXRfkhzpqmqqqOcypjsWPdq5BOUGL/Riwjm6yMI0x9kbO8+VoQ6RYfjAbxNriZ1cQ+AW1fqEgnRWXmjt4Z1M0ygUBi8w71bDML1YG6UHeC2cJ2CCCxSrfycKQhpSdI1QIuwd2eyIpd4LgwrMiY3xNWreAF+qobNxvE7ypKTISNrz0iYIhU0aKNlcGwYd0FXIRfKVBzSBe4MRK2pGLDNO6ytoHxvJweZ8h1XG8RWc4aB5gTnB7Tjiqym4b64lRdj1DPHJnzD4aqRixpXhzYzWVDN2kONCR5i2quYbnVFN4sSfLiKeOwKX4JdmzpYixNZXjLkG14seS6KR0Wl8Itp5IMIWFpnNokjRH76RYRZAcx0jP0V5/GfNNTi5QsEU98en0SiXHQGXnROiHpRUDXTl8FmJORjwXc0AjrEMuQ2FDJDmAIlKUSLhjbIiKw3iaqp5TVyXuz0ZMYBhnqhcwqULqtFSuIKpaW8FgF8QJfP2frADf4kKZG1bQ99MrRrb2A="
        try:
            resp = await self._make_request(
                "https://www.vavoo.tv/api/box/ping2",
                method="POST",
                data={"vec": vec},
                timeout=15,
                retries=2,
            )
            try:
                result = resp.json()
            except Exception:
                return None
            return (result.get("response") or {}).get("signed")
        except Exception as e:
            logger.debug("_get_ts_signature error: %s", e)
            return None

    async def _resolve_with_auth(self, url: str, signature: str) -> Optional[str]:
        """Resolve a Vavoo link using the MediaHubMX API with electron-mode signature."""
        headers = {
            "user-agent": self.API_UA,
            "accept": "*/*",
            "Accept-Language": "de",
            "Accept-Encoding": "gzip, deflate",
            "content-type": "application/json; charset=utf-8",
            "Connection": "close",
            "mediahubmx-signature": signature,
        }
        payload = {"language": "de", "region": "AT", "url": url, "clientVersion": "3.1.4"}
        try:
            resp = await self._make_request(
                "https://vavoo.to/mediahubmx-resolve.json",
                method="POST",
                json=payload,
                headers=headers,
                timeout=15,
                retries=3,
                backoff_factor=0.6,
            )
            try:
                result = resp.json()
            except Exception:
                logger.warning("Vavoo resolve returned non-json (status=%s)", resp.status)
                return None
            logger.debug("Vavoo API response: %s", result)
            if isinstance(result, list) and result and isinstance(result[0], dict) and result[0].get("url"):
                return str(result[0]["url"])
            if isinstance(result, dict):
                if result.get("url"):
                    return str(result["url"])
                if isinstance(result.get("data"), dict) and result["data"].get("url"):
                    return str(result["data"]["url"])
            logger.warning("No URL found in Vavoo API response: %s", result)
            return None
        except Exception as e:
            logger.debug("_resolve_with_auth error: %s", e)
            return None

    async def _follow_stream_url(self, url: str) -> str:
        """Follow redirects and extract final stream URL."""
        stream_headers = {
            "User-Agent": self.API_UA,
            "Accept": "*/*",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "close",
        }
        try:
            resp = await self._make_request(url, method="HEAD", headers=stream_headers, timeout=15, retries=1)
            final_url = str(getattr(resp, "url", url))
            ctype = (getattr(resp, "headers", {}).get("Content-Type") or "").lower()
            if "text/html" in ctype:
                resp2 = await self._make_request(url, method="GET", headers=stream_headers, timeout=15, retries=1)
                text = getattr(resp2, "text", "") or ""
                m3u8 = re.findall(r'(https?://[^\s"\'<>]+\.m3u8[^\s"\'<>]*)', text)
                if m3u8:
                    return m3u8[0]
                generic = re.findall(r'(https?://[^\s"\'<>]+(?:\.ts|/live/|/stream/|/playlist|/index)[^\s"\'<>]*)', text)
                if generic:
                    return generic[0]
            return final_url
        except Exception:
            return url

    async def _build_ts_fallback(self, url: str) -> Optional[str]:
        """Build a .ts fallback URL for vavoo-iptv streams using ping2 signature."""
        if "vavoo-iptv" not in url:
            return None
        ts_sig = await self._get_ts_signature()
        if not ts_sig:
            return None
        base = re.sub(r"/index\.m3u8(?:\?.*)?$", "", url.replace("vavoo-iptv", "live2")).rstrip("/")
        ts_url = f"{base}.ts?n=1&b=5&vavoo_auth={quote(ts_sig, safe='')}"
        try:
            resp = await self._make_request(ts_url, method="GET", headers={"User-Agent": self.TS_UA}, timeout=15, retries=1)
            if getattr(resp, "status", 400) < 400:
                return ts_url
        except Exception:
            pass
        return None

    async def _resolve_web_vod_link(self, url: str) -> str:
        """Resolve a web-vod API link by getting the redirect Location header."""
        try:
            resp = await self._make_request(
                url,
                method="GET",
                headers={"Accept": "application/json"},
                timeout=10,
                retries=2,
                allow_redirects=False,
            )
            status = getattr(resp, "status", 0)
            if status in (301, 302, 303, 307, 308):
                location = (getattr(resp, "headers", {}).get("Location")
                            or getattr(resp, "headers", {}).get("location"))
                if location:
                    logger.info("Vavoo web-vod redirected to: %s", location)
                    return location
            if status == 200:
                text = getattr(resp, "text", "") or ""
                if text and text.startswith("http"):
                    logger.info("Vavoo web-vod resolved to: %s", text.strip())
                    return text.strip()
            raise ExtractorError(f"Vavoo web-vod API returned unexpected status {status}")
        except ExtractorError:
            raise
        except Exception as e:
            raise ExtractorError(f"Failed to resolve Vavoo web-vod link: {e}")

    async def extract(self, url: str, **kwargs) -> Dict[str, Any]:
        """Extract Vavoo stream URL.

        Flow:
        1. Auth Resolve Mode: electron-mode signature → mediahubmx-resolve
        2. TS Fallback Mode: ping2 signature → live2 .ts URL
        3. Direct Fallback: raw URL with VAVOO UA
        """
        if "vavoo.to" not in url:
            raise ExtractorError("Not a valid Vavoo URL")

        # Web-VOD links (new format)
        if "/web-vod/api/get" in url:
            resolved_url = await self._resolve_web_vod_link(url)
            stream_headers = {
                "user-agent": self.API_UA,
                "referer": "https://vavoo.to/",
            }
            return {
                "destination_url": resolved_url,
                "request_headers": stream_headers,
                "mediaflow_endpoint": self.mediaflow_endpoint,
            }

        resolved_url = None
        stream_headers = None

        # Mode 1: Auth Resolve (electron signature + mediahubmx)
        sig = await self._get_auth_signature()
        if sig:
            candidate = await self._resolve_with_auth(url, sig)
            if candidate:
                candidate = await self._follow_stream_url(candidate)
                resolved_url = candidate
                stream_headers = {
                    "user-agent": self.API_UA,
                    "referer": "https://vavoo.to/",
                    "origin": "https://vavoo.to",
                    "mediahubmx-signature": sig,
                }
                logger.info("Using Auth Resolve Mode: %s", resolved_url)

        # Mode 2: TS Fallback (ping2 + live2 .ts)
        if not resolved_url:
            ts_url = await self._build_ts_fallback(url)
            if ts_url:
                resolved_url = ts_url
                stream_headers = {"user-agent": self.TS_UA}
                logger.info("Using TS Fallback Mode: %s", resolved_url)

        # Mode 3: Direct Fallback
        if not resolved_url:
            resolved_url = url
            stream_headers = {
                "user-agent": self.TS_UA,
                "referer": "https://vavoo.to/",
            }
            logger.info("Using Direct Fallback Mode: %s", resolved_url)

        return {
            "destination_url": resolved_url,
            "request_headers": stream_headers,
            "mediaflow_endpoint": self.mediaflow_endpoint,
        }
