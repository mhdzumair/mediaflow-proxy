import re
from typing import Dict, Any

from mediaflow_proxy.extractors.base import BaseExtractor, ExtractorError
from mediaflow_proxy.utils.packed import eval_solver


class FileMoonExtractor(BaseExtractor):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mediaflow_endpoint = "hls_manifest_proxy"

    async def extract(self, url: str, **kwargs) -> Dict[str, Any]:
        response = await self._make_request(url)

        pattern = r"iframe.*?src=[\"'](.*?)[\"']"
        match = re.search(pattern, response.text, re.DOTALL)
        if not match:
            raise ExtractorError("Failed to extract iframe URL")
        iframe_url = match.group(1)

        headers = {'Referer': url}
        patterns = [r'file:"(.*?)"']

        final_url = await eval_solver(self, iframe_url, headers, patterns)

        self.base_headers["referer"] = url
        return {
            "destination_url": final_url,
            "request_headers": self.base_headers,
            "mediaflow_endpoint": self.mediaflow_endpoint,
        }
