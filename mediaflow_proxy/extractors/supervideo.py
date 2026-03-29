import re
from typing import Dict, Any
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup, SoupStrainer
from curl_cffi.requests import AsyncSession

from mediaflow_proxy.extractors.base import BaseExtractor, ExtractorError
from mediaflow_proxy.utils.packed import unpack, detect, UnpackingError


class SupervideoExtractor(BaseExtractor):
    """Supervideo URL extractor.

    Uses curl_cffi to bypass Cloudflare protection.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mediaflow_endpoint = "hls_manifest_proxy"

    async def extract(self, url: str, **kwargs) -> Dict[str, Any]:
        """Extract video URL from Supervideo.

        Uses curl_cffi with Chrome impersonation to bypass Cloudflare.
        """

        patterns = [r'file:"(.*?)"']

        try:
            async with AsyncSession() as session:
                response = await session.get(url, impersonate="chrome")

                if response.status_code != 200:
                    raise ExtractorError(f"HTTP {response.status_code} while fetching {url}")

                soup = BeautifulSoup(response.text, "lxml", parse_only=SoupStrainer("script"))
                script_all = soup.find_all("script")

                for script in script_all:
                    if script.text and detect(script.text):
                        unpacked_code = unpack(script.text)
                        for pattern in patterns:
                            match = re.search(pattern, unpacked_code)
                            if match:
                                extracted_url = match.group(1)
                                if not urlparse(extracted_url).scheme:
                                    extracted_url = urljoin(url, extracted_url)

                                self.base_headers["referer"] = url
                                return {
                                    "destination_url": extracted_url,
                                    "request_headers": self.base_headers,
                                    "mediaflow_endpoint": self.mediaflow_endpoint,
                                }

                raise ExtractorError("No packed JS found or no file URL pattern matched")

        except UnpackingError as e:
            raise ExtractorError(f"Failed to unpack Supervideo JS: {e}")
        except Exception as e:
            if isinstance(e, ExtractorError):
                raise
            raise ExtractorError(f"Supervideo extraction failed: {e}")
