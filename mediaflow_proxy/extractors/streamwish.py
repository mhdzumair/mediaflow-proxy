import re
from typing import Dict, Any
from urllib.parse import urljoin, urlparse

from mediaflow_proxy.extractors.base import BaseExtractor, ExtractorError
from mediaflow_proxy.utils.packed import eval_solver


class StreamWishExtractor(BaseExtractor):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mediaflow_endpoint = "hls_manifest_proxy"

    async def extract(self, url: str, **_kwargs: Any) -> Dict[str, Any]:
        referer = self.base_headers.get("Referer")
        if not referer:
            parsed = urlparse(url)
            referer = f"{parsed.scheme}://{parsed.netloc}/"

        headers = {"Referer": referer}
        response = await self._make_request(url, headers=headers)

        iframe_match = re.search(r'<iframe[^>]+src=["\']([^"\']+)["\']', response.text, re.DOTALL)
        iframe_url = urljoin(url, iframe_match.group(1)) if iframe_match else url

        iframe_response = await self._make_request(iframe_url, headers=headers)
        html = iframe_response.text

        final_url = self._extract_m3u8(html)

        if not final_url and "eval(function(p,a,c,k,e,d)" in html:
            try:
                final_url = await eval_solver(
                    self,
                    iframe_url,
                    headers,
                    [
                        # absolute m3u8
                        r'(https?://[^"\']+\.m3u8[^"\']*)',
                        # relative stream paths
                        r'(\/stream\/[^"\']+\.m3u8[^"\']*)',
                    ],
                )
            except Exception:
                final_url = None

        if not final_url:
            raise ExtractorError("StreamWish: Failed to extract m3u8")

        if final_url.startswith("/"):
            final_url = urljoin(iframe_url, final_url)

        origin = f"{urlparse(referer).scheme}://{urlparse(referer).netloc}"
        self.base_headers.update(
            {
                "Referer": referer,
                "Origin": origin,
            }
        )

        return {
            "destination_url": final_url,
            "request_headers": self.base_headers,
            "mediaflow_endpoint": self.mediaflow_endpoint,
        }

    @staticmethod
    def _extract_m3u8(text: str) -> str | None:
        """
        Extract first absolute m3u8 URL from text
        """
        match = re.search(r'https?://[^"\']+\.m3u8[^"\']*', text)
        return match.group(0) if match else None
