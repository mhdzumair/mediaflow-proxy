from typing import Dict, Any

from mediaflow_proxy.extractors.base import BaseExtractor
from mediaflow_proxy.utils.packed import eval_solver


class FastreamExtractor(BaseExtractor):
    """Fastream URL extractor."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mediaflow_endpoint = "hls_manifest_proxy"

    async def extract(self, url: str, **kwargs) -> Dict[str, Any]:
        headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Connection": "keep-alive",
            "Accept-Language": "en-US,en;q=0.5",
            "user-agent": "Mozilla/5.0 (X11; Linux x86_64; rv:138.0) Gecko/20100101 Firefox/138.0",
        }
        patterns = [r'file:"(.*?)"']

        final_url = await eval_solver(self, url, headers, patterns)

        self.base_headers["referer"] = f"https://{url.replace('https://', '').split('/')[0]}/"
        self.base_headers["origin"] = f"https://{url.replace('https://', '').split('/')[0]}"
        self.base_headers["Accept-Language"] = "en-US,en;q=0.5"
        self.base_headers["Accept"] = "*/*"
        self.base_headers["user-agent"] = "Mozilla/5.0 (X11; Linux x86_64; rv:138.0) Gecko/20100101 Firefox/138.0"

        return {
            "destination_url": final_url,
            "request_headers": self.base_headers,
            "mediaflow_endpoint": self.mediaflow_endpoint,
        }
