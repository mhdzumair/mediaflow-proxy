import re
from typing import Dict, Any

from mediaflow_proxy.extractors.base import BaseExtractor


class SupervideoExtractor(BaseExtractor):
    """Supervideo URL extractor."""

    async def extract(self, url: str, **kwargs) -> Dict[str, Any]:
        """Extract Supervideo URL."""
        response = await self._make_request(url)
        # Extract and decode URL
        s2 = re.search(r"\}\('(.+)',.+,'(.+)'\.split", response.text).group(2)
        terms = s2.split("|")
        hfs = next(terms[i] for i in range(terms.index("file"), len(terms)) if "hfs" in terms[i])
        result = terms[terms.index("urlset") + 1 : terms.index("hls")]

        base_url = f"https://{hfs}.serversicuro.cc/hls/"
        final_url = base_url + ",".join(reversed(result)) + (".urlset/master.m3u8" if result else "")

        self.base_headers["referer"] = url
        return {
            "destination_url": final_url,
            "request_headers": self.base_headers,
            "mediaflow_endpoint": self.mediaflow_endpoint,
        }
