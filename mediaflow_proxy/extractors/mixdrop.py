import re
import string
from typing import Dict, Tuple

from mediaflow_proxy.extractors.base import BaseExtractor


class MixdropExtractor(BaseExtractor):
    """Mixdrop URL extractor."""

    async def extract(self, url: str) -> Tuple[str, Dict[str, str]]:
        """Extract Mixdrop URL."""
        response = await self._make_request(url)

        # Extract and decode URL
        match = re.search(r"\}\('(.+)',.+,'(.+)'\.split", response.text)
        if not match:
            raise ValueError("Failed to extract URL components")

        s1, s2 = match.group(1, 2)
        schema = s1.split(";")[2][5:-1]
        terms = s2.split("|")

        # Build character mapping
        charset = string.digits + string.ascii_letters
        char_map = {charset[i]: terms[i] or charset[i] for i in range(len(terms))}

        # Construct final URL
        final_url = "https:" + "".join(char_map.get(c, c) for c in schema)

        return final_url, {"User-Agent": self.base_headers["User-Agent"]}
