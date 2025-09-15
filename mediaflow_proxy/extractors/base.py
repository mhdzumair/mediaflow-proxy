from abc import ABC, abstractmethod
from typing import Dict, Optional, Any

import httpx

from mediaflow_proxy.configs import settings
from mediaflow_proxy.utils.http_utils import create_httpx_client, DownloadError


class ExtractorError(Exception):
    """Base exception for all extractors."""

    pass


class BaseExtractor(ABC):
    """Base class for all URL extractors."""

    def __init__(self, request_headers: dict):
        self.base_headers = {
            "user-agent": settings.user_agent,
        }
        self.mediaflow_endpoint = "proxy_stream_endpoint"
        self.base_headers.update(request_headers)

    async def _make_request(
        self, url: str, method: str = "GET", headers: Optional[Dict] = None, **kwargs
    ) -> httpx.Response:
        """Make HTTP request with error handling."""
        try:
            async with create_httpx_client() as client:
                request_headers = self.base_headers.copy()
                request_headers.update(headers or {})
                response = await client.request(
                    method,
                    url,
                    headers=request_headers,
                    **kwargs,
                )
                response.raise_for_status()
                return response
        except httpx.HTTPStatusError as e:
            raise DownloadError(e.response.status_code, f"HTTP error {e.response.status_code} while requesting {url}")
        except Exception as e:
            raise ExtractorError(f"Request failed for URL {url}: {str(e)}")

    @abstractmethod
    async def extract(self, url: str, **kwargs) -> Dict[str, Any]:
        """Extract final URL and required headers."""
        pass
