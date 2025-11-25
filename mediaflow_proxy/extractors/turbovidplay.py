import re
from typing import Dict, Any

from mediaflow_proxy.extractors.base import BaseExtractor, ExtractorError


class TurboVidPlayExtractor(BaseExtractor):
    domains = [
        "turboviplay.com",
        "emturbovid.com",
        "tuborstb.co",
        "javggvideo.xyz",
        "stbturbo.xyz",
        "turbovidhls.com",
    ]

    mediaflow_endpoint = "hls_manifest_proxy"

    async def extract(self, url: str, **kwargs):
        #
        # 1. Load embed
        #
        response = await self._make_request(url)
        html = response.text

        #
        # 2. Extract urlPlay or data-hash
        #
        m = re.search(r'(?:urlPlay|data-hash)\s*=\s*[\'"]([^\'"]+)', html)
        if not m:
            raise ExtractorError("TurboViPlay: No media URL found")

        media_url = m.group(1)

        # Normalize protocol
        if media_url.startswith("//"):
            media_url = "https:" + media_url
        elif media_url.startswith("/"):
            media_url = response.url.origin + media_url

        #
        # 3. Fetch the intermediate playlist
        #
        data_resp = await self._make_request(media_url, headers={"Referer": url})
        playlist = data_resp.text

        #
        # 4. Extract real m3u8 URL
        #
        m2 = re.search(r'https?://[^\'"\s]+\.m3u8', playlist)
        if not m2:
            raise ExtractorError("TurboViPlay: Unable to extract playlist URL")

        real_m3u8 = m2.group(0)

        #
        # 5. Final headers
        #
        self.base_headers["referer"] = url

        #
        # 6. Always return master proxy (your MediaFlow only supports this)
        #
        return {
            "destination_url": real_m3u8,
            "request_headers": self.base_headers,
            "mediaflow_endpoint": "hls_manifest_proxy",
        }
