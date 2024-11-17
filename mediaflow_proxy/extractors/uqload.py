import re
from typing import Dict

from mediaflow_proxy.extractors.base import BaseExtractor, ExtractorError


class UqloadExtractor(BaseExtractor):
    """Uqload URL extractor."""

    referer = "https://uqload.to/"

    async def extract(self, url: str, **kwargs) -> Dict[str, str]:
        """Extract Uqload URL."""
        response = await self._make_request(url)

        video_url_match = re.search(r'sources: \["(.*?)"]', response.text)
        if not video_url_match:
            raise ExtractorError("Failed to extract video URL")

        self.base_headers["referer"] = self.referer
        return {
            "destination_url": video_url_match.group(1),
            "request_headers": self.base_headers,
            "mediaflow_endpoint": self.mediaflow_endpoint,
        }
