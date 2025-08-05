import re
from typing import Dict, Any

from bs4 import BeautifulSoup

from mediaflow_proxy.extractors.base import BaseExtractor, ExtractorError


class MaxstreamExtractor(BaseExtractor):
    """Maxstream URL extractor."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mediaflow_endpoint = "hls_manifest_proxy"

    async def get_uprot(self, link: str):
        """Extract MaxStream URL."""
        if "msf" in link:
            link = link.replace("msf", "mse")
        response = await self._make_request(link)
        soup = BeautifulSoup(response.text, "lxml")
        maxstream_url = soup.find("a")
        maxstream_url = maxstream_url.get("href")
        return maxstream_url

    async def extract(self, url: str, **kwargs) -> Dict[str, Any]:
        """Extract Maxstream URL."""
        maxstream_url = await self.get_uprot(url)
        response = await self._make_request(maxstream_url, headers={"accept-language": "en-US,en;q=0.5"})

        # Extract and decode URL
        match = re.search(r"\}\('(.+)',.+,'(.+)'\.split", response.text)
        if not match:
            raise ExtractorError("Failed to extract URL components")

        s1 = match.group(2)
        # Extract Terms
        terms = s1.split("|")
        urlset_index = terms.index("urlset")
        hls_index = terms.index("hls")
        sources_index = terms.index("sources")
        result = terms[urlset_index + 1 : hls_index]
        reversed_elements = result[::-1]
        first_part = terms[hls_index + 1 : sources_index]
        reversed_first_part = first_part[::-1]
        first_url_part = ""
        for first_part in reversed_first_part:
            if "0" in first_part:
                first_url_part += first_part
            else:
                first_url_part += first_part + "-"

        base_url = f"https://{first_url_part}.host-cdn.net/hls/"
        if len(reversed_elements) == 1:
            final_url = base_url + "," + reversed_elements[0] + ".urlset/master.m3u8"
        lenght = len(reversed_elements)
        i = 1
        for element in reversed_elements:
            base_url += element + ","
            if lenght == i:
                base_url += ".urlset/master.m3u8"
            else:
                i += 1
        final_url = base_url

        self.base_headers["referer"] = url
        return {
            "destination_url": final_url,
            "request_headers": self.base_headers,
            "mediaflow_endpoint": self.mediaflow_endpoint,
        }
