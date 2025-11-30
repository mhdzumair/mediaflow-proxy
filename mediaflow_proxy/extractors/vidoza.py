import re
from typing import Dict, Any
from urllib.parse import urlparse

from mediaflow_proxy.extractors.base import BaseExtractor, ExtractorError


class VidozaExtractor(BaseExtractor):
    def __init__(self, request_headers: dict):
        super().__init__(request_headers)
        # if your base doesn’t set this, keep it; otherwise you can remove:
        self.mediaflow_endpoint = "proxy_stream_endpoint"

    async def extract(self, url: str, **kwargs) -> Dict[str, Any]:
        parsed = urlparse(url)

        # Accept vidoza + videzz
        if not parsed.hostname or not (
            parsed.hostname.endswith("vidoza.net")
            or parsed.hostname.endswith("videzz.net")
        ):
            raise ExtractorError("VIDOZA: Invalid domain")

        headers = self.base_headers.copy()
        headers.update(
            {
                "referer": "https://vidoza.net/",
                "user-agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/120.0.0.0 Safari/537.36"
                ),
                "accept": "*/*",
                "accept-language": "en-US,en;q=0.9",
            }
        )

        # 1) Fetch the embed page (or whatever URL you pass in)
        response = await self._make_request(url, headers=headers)
        html = response.text or ""

        if not html:
            raise ExtractorError("VIDOZA: Empty HTML from Vidoza")

        cookies = response.cookies or {}

        # 2) Extract final link with REGEX
        pattern = re.compile(
            r"""["']?\s*(?:file|src)\s*["']?\s*[:=,]?\s*["'](?P<url>[^"']+)"""
            r"""(?:[^}>\]]+)["']?\s*res\s*["']?\s*[:=]\s*["']?(?P<label>[^"',]+)""",
            re.IGNORECASE,
        )

        match = pattern.search(html)
        if not match:
            raise ExtractorError("VIDOZA: Unable to extract video + label from JS")

        mp4_url = match.group("url")
        label = match.group("label").strip()

        # Fix URLs like //str38.vidoza.net/...
        if mp4_url.startswith("//"):
            mp4_url = "https:" + mp4_url

        # 3) Attach cookies (token may depend on these)
        if cookies:
            headers["cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())

        return {
            "destination_url": mp4_url,
            "request_headers": headers,
            "mediaflow_endpoint": self.mediaflow_endpoint,
        }
