import re
from typing import Dict, Any
from urllib.parse import urljoin

from mediaflow_proxy.extractors.base import BaseExtractor, ExtractorError


class VidmolyExtractor(BaseExtractor):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mediaflow_endpoint = "hls_manifest_proxy"

    async def extract(self, url: str, **kwargs) -> Dict[str, Any]:
        # --- Request the main embed page ---
        response = await self._make_request(url)
        html = response.text

        # Extract the initial m3u8 URL
        match = re.search(r'sources\s*:\s*\[\{file:"([^"]+)"', html)
        if not match:
            raise ExtractorError("VIDMOLY: stream URL not found")

        master_url = match.group(1)

        # --- Fetch master playlist ---
        playlist_resp = await self._make_request(master_url)
        playlist_text = playlist_resp.text

        # Parse variant streams (bandwidth + URL)
        variants = re.findall(
            r'#EXT-X-STREAM-INF:.*?BANDWIDTH=(\d+).*?\n([^\n]+)',
            playlist_text,
            flags=re.DOTALL
        )

        if not variants:
            # No variants → use master URL directly
            best_url = master_url
        else:
            # Pick highest bandwidth variant
            variants.sort(key=lambda x: int(x[0]), reverse=True)
            best_url = variants[0][1]

            # Fix relative URLs
            if not best_url.startswith("http"):
                best_url = urljoin(master_url, best_url)

        # Return the structure required by MediaFlow Proxy
        self.base_headers["referer"] = url
        return {
            "destination_url": best_url,
            "request_headers": self.base_headers,
            "mediaflow_endpoint": self.mediaflow_endpoint,
        }
