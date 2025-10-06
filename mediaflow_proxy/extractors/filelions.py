from typing import Dict, Any

from mediaflow_proxy.extractors.base import BaseExtractor
from mediaflow_proxy.utils.packed import eval_solver

class FileLionsExtractor(BaseExtractor):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mediaflow_endpoint = "hls_manifest_proxy"

    async def extract(self, url: str, **kwargs) -> Dict[str, Any]:
        headers  = {}
        patterns = [ # See https://github.com/Gujal00/ResolveURL/blob/master/script.module.resolveurl/lib/resolveurl/plugins/filelions.py
            r'''sources:\s*\[{file:\s*["'](?P<url>[^"']+)''',
            r'''["']hls4["']:\s*["'](?P<url>[^"']+)''',
            r'''["']hls2["']:\s*["'](?P<url>[^"']+)'''
        ]

        final_url = await eval_solver(self, url, headers, patterns)

        self.base_headers["referer"] = url
        return {
            "destination_url": final_url,
            "request_headers": self.base_headers,
            "mediaflow_endpoint": self.mediaflow_endpoint,
        }
