import re
from typing import Dict, Any
from urllib.parse import urlparse

from mediaflow_proxy.extractors.base import BaseExtractor, ExtractorError


class VidozaExtractor(BaseExtractor):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Use segment_endpoint since final URL is a direct .mp4
        self.mediaflow_endpoint = "stream"

    async def extract(self, url: str, **kwargs) -> Dict[str, Any]:
        parsed = urlparse(url)
        # Accept videzz.net domain (redirect from vidoza.net)
        if not parsed.hostname or not parsed.hostname.endswith("videzz.net"):
            raise ExtractorError("VIDOZA: Invalid domain")

        # Fetch the embed page
        response = await self._make_request(
            url,
            headers={"referer": "https://vidoza.net/"}  # required for IP-locked .mp4
        )
        html = response.text

        # Extract the .mp4 URL
        match = re.search(r'https://[^"]+\.mp4', html)
        if not match:
            raise ExtractorError("VIDOZA: Unable to find video URL in embed page")

        mp4_url = match.group(0)

        # Prepare headers for proxy request
        headers = self.base_headers.copy()
        headers["referer"] = "https://vidoza.net/"

        return {
            "destination_url": mp4_url,
            "request_headers": headers,
            "mediaflow_endpoint": self.mediaflow_endpoint,
        }