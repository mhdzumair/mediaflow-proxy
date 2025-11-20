import re
from typing import Dict, Any
from urllib.parse import urlparse

from mediaflow_proxy.extractors.base import BaseExtractor, ExtractorError


class VidozaExtractor(BaseExtractor):
    """
    Vidoza extractor (MP4).
    Always uses video_proxy since Vidoza serves direct .mp4 files.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mediaflow_endpoint = "video_proxy"   

    async def extract(self, url: str) -> Dict[str, Any]:
        parsed = urlparse(url)

        # Accept vidoza.net / vidoza.co / videzz.net
        valid_domains = ("vidoza.net", "vidoza.co", "videzz.net")
        hostname = parsed.hostname.lower() if parsed.hostname else ""
        if not hostname or not (hostname in valid_domains or any(hostname.endswith(f".{d}") for d in valid_domains)):
            raise ExtractorError("Vidoza: Invalid domain")

        # Fetch embed page
        response = await self._make_request(url)
        html = response.text

        if not html or "Video not found" in html:
            raise ExtractorError("Vidoza: embed page not found")

        # Extract direct MP4 URL
        match = re.search(
            r'(?:file|src)\s*[:=]\s*["\'](?P<url>https?://[^"\']+\.mp4)["\']',
            html,
            re.IGNORECASE
        )

        if not match:
            raise ExtractorError("Vidoza: direct MP4 URL not found")

        mp4_url = match.group("url")

        # Ensure MP4 URL is valid
        parsed_mp4 = urlparse(mp4_url)
        if parsed_mp4.scheme not in ("http", "https"):
            raise ExtractorError("Vidoza: Invalid MP4 URL scheme")

        # Build headers
        headers = self.base_headers.copy()
        headers["referer"] = url

        # Return structure for MediaFlow Proxy
        return {
            "destination_url": mp4_url,
            "request_headers": headers,
            "mediaflow_endpoint": self.mediaflow_endpoint,  # video_proxy
        }
