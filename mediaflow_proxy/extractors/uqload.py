import re
from typing import Dict, Tuple

from mediaflow_proxy.extractors.base import BaseExtractor


class UqloadExtractor(BaseExtractor):
    """Uqload URL extractor."""

    async def extract(self, url: str) -> Tuple[str, Dict[str, str]]:
        """Extract Uqload URL."""
        response = await self._make_request(url)

        video_url_match = re.search(r'sources: \["(.*?)"\]', response.text)
        if not video_url_match:
            raise ValueError("Failed to extract video URL")

        return video_url_match.group(1), {"Referer": "https://uqload.to/"}
