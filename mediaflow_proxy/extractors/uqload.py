import re
from typing import Dict, Any
from urllib.parse import urljoin

from curl_cffi.requests import AsyncSession

from mediaflow_proxy.extractors.base import BaseExtractor, ExtractorError


class UqloadExtractor(BaseExtractor):
    """Uqload URL extractor.

    Uses curl_cffi + Chrome impersonation to handle Cloudflare protection.
    Follows redirects automatically (uqload.bz/co/io all redirect to uqload.is).
    """

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

        video_url_match = re.search(r'sources:\s*\["(https?://[^"]+)"', response.text)
        if not video_url_match:
            raise ExtractorError("Uqload: video URL not found in page source")

        final_url = str(response.url)
        self.base_headers["referer"] = urljoin(final_url, "/")
        return {
            "destination_url": video_url_match.group(1),
            "request_headers": self.base_headers,
            "mediaflow_endpoint": self.mediaflow_endpoint,
        }
