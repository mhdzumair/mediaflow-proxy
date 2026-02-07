import re
from typing import Dict, Any
from urllib.parse import urlparse

from mediaflow_proxy.extractors.base import BaseExtractor, ExtractorError


class VidozaExtractor(BaseExtractor):
    def __init__(self, request_headers: dict):
        super().__init__(request_headers)
        self.mediaflow_endpoint = "proxy_stream_endpoint"

    async def extract(self, url: str, **kwargs) -> Dict[str, Any]:
        parsed = urlparse(url)

        if not parsed.hostname or not (
            parsed.hostname.endswith("vidoza.net") or parsed.hostname.endswith("videzz.net")
        ):
            raise ExtractorError("VIDOZA: Invalid domain")

        # Use the correct referer for clones
        referer = f"https://{parsed.hostname}/"

        headers = self.base_headers.copy()
        headers.update(
            {
                "referer": referer,
                "user-agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/120.0.0.0 Safari/537.36"
                ),
                "accept": "*/*",
                "accept-language": "en-US,en;q=0.9",
            }
        )

        # 1) Fetch embed page
        response = await self._make_request(url, headers=headers)
        html = response.text or ""

        if not html:
            raise ExtractorError("VIDOZA: Empty HTML")

        # 2) Extract video URL
        pattern = re.compile(
            r"""["']?\s*(?:file|src)\s*["']?\s*[:=,]?\s*["'](?P<url>[^"']+)"""
            r"""(?:[^}>\]]+)["']?\s*res\s*["']?\s*[:=]\s*["']?(?P<label>[^"',]+)""",
            re.IGNORECASE,
        )

        match = pattern.search(html)
        if not match:
            raise ExtractorError("VIDOZA: Video URL not found")

        video_url = match.group("url")

        if video_url.startswith("//"):
            video_url = "https:" + video_url

        return {
            "destination_url": video_url,
            "request_headers": headers,
            "mediaflow_endpoint": self.mediaflow_endpoint,
        }
