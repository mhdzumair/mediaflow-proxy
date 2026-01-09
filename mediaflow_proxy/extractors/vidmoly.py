import re
from typing import Dict, Any
from urllib.parse import urljoin, urlparse

from mediaflow_proxy.extractors.base import BaseExtractor, ExtractorError


class VidmolyExtractor(BaseExtractor):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mediaflow_endpoint = "hls_manifest_proxy"

    async def extract(self, url: str) -> Dict[str, Any]:
        parsed = urlparse(url)
        if not parsed.hostname or "vidmoly" not in parsed.hostname:
            raise ExtractorError("VIDMOLY: Invalid domain")

        headers = {
            "User-Agent":
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120 Safari/537.36",
            "Referer": url,
            "Sec-Fetch-Dest": "iframe",
        }

        # --- Fetch embed page ---
        response = await self._make_request(url, headers=headers)
        html = response.text

        # --- Extract master m3u8 ---
        match = re.search(
            r'sources:\s*\[\{file:"([^"]+)',
            html
        )
        if not match:
            raise ExtractorError("VIDMOLY: Stream URL not found")

        master_url = match.group(1)

        if not master_url.startswith("http"):
            master_url = urljoin(url, master_url)

        # --- Validate stream (prevents Stremio timeout) ---
        try:
            test = await self._make_request(master_url, headers=headers)
        except Exception as e:
            if "timeout" in str(e).lower():
                raise ExtractorError("VIDMOLY: Request timed out")
            raise

        if test.status_code >= 400:
            raise ExtractorError(
                f"VIDMOLY: Stream unavailable ({test.status_code})"
            )

        # Return MASTER playlist, not variant
        # Let MediaFlow Proxy handle variants
        return {
            "destination_url": master_url,
            "request_headers": headers,
            "mediaflow_endpoint": self.mediaflow_endpoint,
        }
