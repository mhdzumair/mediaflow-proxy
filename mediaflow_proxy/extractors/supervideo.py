import re
from typing import Dict, Any

from mediaflow_proxy.extractors.base import BaseExtractor
from mediaflow_proxy.utils.packed import eval_solver




class SupervideoExtractor(BaseExtractor):
    """Supervideo URL extractor."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mediaflow_endpoint = "hls_manifest_proxy"
        
    async def extract(self, url: str, **kwargs) -> Dict[str, Any]:
        #Init headers needed for the request.
        headers  = {'Accept': '*/*', 'Connection': 'keep-alive', 'User-Agent': 'Mozilla/5.0 (Linux; Android 12) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.5060.71 Mobile Safari/537.36', 'user-agent': 'Mozilla/5.0 (Linux; Android 12) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.5060.71 Mobile Safari/537.36'}

        
        """Extract Supervideo URL."""
        final_url = await eval_solver(self,url,headers)

        self.base_headers["referer"] = url
        return {
            "destination_url": final_url,
            "request_headers": self.base_headers,
            "mediaflow_endpoint": self.mediaflow_endpoint,
        }
