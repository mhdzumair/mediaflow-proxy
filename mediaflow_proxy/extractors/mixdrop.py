import re
import string
from typing import Dict, Any

from mediaflow_proxy.extractors.base import BaseExtractor, ExtractorError


class MixdropExtractor(BaseExtractor):
    """Mixdrop URL extractor."""

    async def extract(self, url: str, **kwargs) -> Dict[str, Any]:
        """Extract Mixdrop URL."""
        if "club" in url:
            url = url.replace("club", "ps").split("/2")[0]
        response = await self._make_request(url, headers={"accept-language": "en-US,en;q=0.5"})

        # Extract and decode URL
        match = re.search(r"}\('(.+)',.+,'(.+)'\.split", response.text)
        if not match:
            raise ExtractorError("Failed to extract URL components")

        s1, s2 = match.group(1, 2)
        schema = s1.split(";")[2][5:-1]
        terms = s2.split("|")

        # Build character mapping
        charset = string.digits + string.ascii_letters
        char_map = {charset[i]: terms[i] or charset[i] for i in range(len(terms))}

        # Construct final URL
        final_url = "https:" + "".join(char_map.get(c, c) for c in schema)

        self.base_headers["referer"] = url
        return {
            "destination_url": final_url,
            "request_headers": self.base_headers,
            "mediaflow_endpoint": self.mediaflow_endpoint,
        }
