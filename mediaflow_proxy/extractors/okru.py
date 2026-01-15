import json
from typing import Dict, Any

from bs4 import BeautifulSoup, SoupStrainer

from mediaflow_proxy.extractors.base import BaseExtractor


class OkruExtractor(BaseExtractor):
    """Okru URL extractor."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mediaflow_endpoint = "hls_manifest_proxy"

    async def extract(self, url: str, **kwargs) -> Dict[str, Any]:
        """Extract Okru URL."""
        response = await self._make_request(url)
        soup = BeautifulSoup(response.text, "lxml", parse_only=SoupStrainer("div"))
        if soup:
            div = soup.find("div", {"data-module": "OKVideo"})
            data_options = div.get("data-options")
            data = json.loads(data_options)
            metadata = json.loads(data["flashvars"]["metadata"])
            final_url = (
                metadata.get("hlsMasterPlaylistUrl") or metadata.get("hlsManifestUrl") or metadata.get("ondemandHls")
            )
            self.base_headers["referer"] = url
            return {
                "destination_url": final_url,
                "request_headers": self.base_headers,
                "mediaflow_endpoint": self.mediaflow_endpoint,
            }
