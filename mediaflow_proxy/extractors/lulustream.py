import re
from typing import Dict, Any

from curl_cffi.requests import AsyncSession

from mediaflow_proxy.extractors.base import BaseExtractor, ExtractorError


class LuluStreamExtractor(BaseExtractor):
    """LuluStream URL extractor.

    Uses curl_cffi + Chrome impersonation to bypass Cloudflare protection.
    lulustream.com embeds are served via luluvdo.com.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mediaflow_endpoint = "hls_manifest_proxy"

    async def extract(self, url: str, **kwargs) -> Dict[str, Any]:
        proxy = self._get_proxy(url)
        async with AsyncSession() as session:
            response = await session.get(
                url,
                impersonate="chrome",
                timeout=30,
                allow_redirects=True,
                **({"proxy": proxy} if proxy else {}),
            )

        if response.status_code >= 400:
            raise ExtractorError(f"HTTP {response.status_code} while fetching {url}")

        # See https://github.com/Gujal00/ResolveURL/blob/master/script.module.resolveurl/lib/resolveurl/plugins/lulustream.py
        pattern = r"""sources:\s*\[{file:\s*["'](?P<url>[^"']+)"""
        match = re.search(pattern, response.text, re.DOTALL)
        if not match:
            raise ExtractorError("LuluStream: Failed to extract source URL")
        final_url = match.group("url")

        self.base_headers["referer"] = url
        return {
            "destination_url": final_url,
            "request_headers": self.base_headers,
            "mediaflow_endpoint": self.mediaflow_endpoint,
        }
