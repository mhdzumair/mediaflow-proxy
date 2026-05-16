from typing import Dict, Any

from mediaflow_proxy.extractors.base import BaseExtractor
from mediaflow_proxy.utils.packed import eval_solver


class StreamHGExtractor(BaseExtractor):
    """StreamHG URL extractor."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mediaflow_endpoint = "hls_manifest_proxy"
    
    async def extract(self, url: str, **kwargs) -> Dict[str, Any]:
        """Extract StreamHG URL."""
        headers = {}
        patterns = [r'"hls2":"([^"]+)"']

        final_url = await eval_solver(self, url, headers, patterns)

        return {
            "destination_url": final_url,
            "request_headers": self.base_headers,
            "mediaflow_endpoint": self.mediaflow_endpoint,
        }
