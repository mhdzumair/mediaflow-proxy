import re
from typing import Dict, Any

from mediaflow_proxy.extractors.base import BaseExtractor, ExtractorError
from mediaflow_proxy.utils.packed import eval_solver


class StreamWishExtractor(BaseExtractor):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mediaflow_endpoint = "hls_manifest_proxy"  # same as FileMoon

    async def extract(self, url: str, **kwargs) -> Dict[str, Any]:
        #
        # 1. Load embed page
        #
        response = await self._make_request(url)

        #
        # 2. Follow iframe (StreamWish always nests iframe OR direct eval)
        #
        iframe_match = re.search(
            r'<iframe[^>]+src=["\']([^"\']+)["\']',
            response.text,
            re.DOTALL
        )

        if iframe_match:
            iframe_url = iframe_match.group(1)
        else:
            # no iframe → treat embed itself as packed page
            iframe_url = url

        headers = {"Referer": url}

        #
        # 3. Patterns to capture the real .m3u8
        #
        patterns = [
            r'"(\/stream\/[^"]+master\.m3u8[^"]*)"',  # main pattern
            r"'(\/stream\/[^']+master\.m3u8[^']*)'",  # alternate
        ]

        #
        # 4. Use MediaFlow eval solver (same as FileMoon)
        #
        final_url = await eval_solver(
            self,
            iframe_url,
            headers,
            patterns
        )

        if not final_url:
            raise ExtractorError("StreamWish: Failed to extract master m3u8")

        #
        # 5. Set referer correctly
        #
        self.base_headers["referer"] = url

        #
        # 6. Output to MediaFlow
        #
        return {
            "destination_url": final_url,
            "request_headers": self.base_headers,
            "mediaflow_endpoint": self.mediaflow_endpoint,
        }
