import re
import time
from typing import Tuple, Dict

from mediaflow_proxy.extractors.base import BaseExtractor


class DoodStreamExtractor(BaseExtractor):
    """DoodStream URL extractor."""

    def __init__(self, proxy_enabled: bool, request_headers: dict):
        super().__init__(proxy_enabled, request_headers)
        self.base_url = "https://d000d.com"

    async def extract(self, url: str) -> Tuple[str, Dict[str, str]]:
        """Extract DoodStream URL."""
        response = await self._make_request(url)

        # Extract URL pattern
        pattern = r"(\/pass_md5\/.*?)'.*(\?token=.*?expiry=)"
        match = re.search(pattern, response.text, re.DOTALL)
        if not match:
            raise ValueError("Failed to extract URL pattern")

        # Build final URL
        pass_url = f"{self.base_url}{match[1]}"
        referer = f"{self.base_url}/"
        headers = {"range": "bytes=0-", "referer": referer}

        rebobo_response = await self._make_request(pass_url, headers=headers)
        timestamp = str(int(time.time()))
        final_url = f"{rebobo_response.text}123456789{match[2]}{timestamp}"

        return final_url, {"Referer": referer}
