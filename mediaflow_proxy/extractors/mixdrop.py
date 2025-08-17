from typing import Dict, Any

from mediaflow_proxy.extractors.base import BaseExtractor, ExtractorError
from mediaflow_proxy.utils.packed import eval_solver


class MixdropExtractor(BaseExtractor):
    """Mixdrop URL extractor."""

    async def extract(self, url: str, **kwargs) -> Dict[str, Any]:
        """Extract Mixdrop URL."""
        if "club" in url:
            url = url.replace("club", "ps").split("/2")[0]

        headers = {"accept-language": "en-US,en;q=0.5"}
        pattern = r'MDCore.wurl ?= ?"(.*?)"'

        final_url = f"https:{await eval_solver(self, url, headers, pattern)}"

        self.base_headers["referer"] = url
        return {
            "destination_url": final_url,
            "request_headers": self.base_headers,
            "mediaflow_endpoint": self.mediaflow_endpoint,
        }
