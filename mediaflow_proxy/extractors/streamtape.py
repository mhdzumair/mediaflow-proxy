import re
from typing import Dict, Any

from mediaflow_proxy.extractors.base import BaseExtractor, ExtractorError


class StreamtapeExtractor(BaseExtractor):
    """Streamtape URL extractor."""

    async def extract(self, url: str, **kwargs) -> Dict[str, Any]:
        """Extract Streamtape URL."""
        response = await self._make_request(url)

        # Extract and decode URL
        matches = re.findall(r"id=.*?(?=')", response.text)
        if not matches:
            raise ExtractorError("Failed to extract URL components")
        final_url = next(
            (
                f"https://streamtape.com/get_video?{matches[i + 1]}"
                for i in range(len(matches) - 1)
                if matches[i] == matches[i + 1]
            ),
            None,
        )

        self.base_headers["referer"] = url
        return {
            "destination_url": final_url,
            "request_headers": self.base_headers,
            "mediaflow_endpoint": self.mediaflow_endpoint,
        }
