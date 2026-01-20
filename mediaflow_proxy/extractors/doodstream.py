import re
import time
from urllib.parse import urlparse, urljoin

from mediaflow_proxy.extractors.base import BaseExtractor, ExtractorError


class DoodStreamExtractor(BaseExtractor):
    """
    Dood / MyVidPlay extractor
    Resolves to direct CDN MP4
    """

    def __init__(self, request_headers: dict):
        super().__init__(request_headers)
        self.base_url = "https://myvidplay.com"

    async def extract(self, url: str, **kwargs):
        parsed = urlparse(url)
        video_id = parsed.path.rstrip("/").split("/")[-1]
        if not video_id:
            raise ExtractorError("Invalid Dood URL")

        headers = {
            "User-Agent": self.base_headers.get("User-Agent") or "Mozilla/5.0",
            "Referer": f"{self.base_url}/",
        }

        embed_url = f"{self.base_url}/e/{video_id}"
        html = (await self._make_request(embed_url, headers=headers)).text

        match = re.search(r"(\/pass_md5\/[^']+)", html)
        if not match:
            raise ExtractorError("Dood: pass_md5 not found")

        pass_url = urljoin(self.base_url, match.group(1))

        base_stream = (await self._make_request(pass_url, headers=headers)).text.strip()

        token_match = re.search(r"token=([^&]+)", html)
        if not token_match:
            raise ExtractorError("Dood: token missing")

        token = token_match.group(1)

        final_url = f"{base_stream}123456789?token={token}&expiry={int(time.time())}"

        return {
            "destination_url": final_url,
            "request_headers": headers,
            "mediaflow_endpoint": "proxy_stream_endpoint",
        }
