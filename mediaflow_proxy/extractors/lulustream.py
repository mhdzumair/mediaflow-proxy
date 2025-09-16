import re
from typing import Dict, Any

from mediaflow_proxy.extractors.base import BaseExtractor, ExtractorError


class LuluStreamExtractor(BaseExtractor):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mediaflow_endpoint = "hls_manifest_proxy"

    async def extract(self, url: str, **kwargs) -> Dict[str, Any]:
        response = await self._make_request(url)

        # See https://github.com/Gujal00/ResolveURL/blob/master/script.module.resolveurl/lib/resolveurl/plugins/lulustream.py
        pattern = r'''sources:\s*\[{file:\s*["'](?P<url>[^"']+)'''
        match = re.search(pattern, response.text, re.DOTALL)
        if not match:
            raise ExtractorError("Failed to extract source URL")
        final_url = match.group(1)

        self.base_headers["referer"] = url
        return {
            "destination_url": final_url,
            "request_headers": self.base_headers,
            "mediaflow_endpoint": self.mediaflow_endpoint,
        }
