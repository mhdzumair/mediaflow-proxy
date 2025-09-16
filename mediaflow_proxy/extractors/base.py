from abc import ABC, abstractmethod
from typing import Dict, Optional, Any

import httpx

from mediaflow_proxy.configs import settings
from mediaflow_proxy.utils.http_utils import DownloadError, request_with_retry


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
        request_headers = self.base_headers.copy()
        request_headers.update(headers or {})
        try:
            response = await request_with_retry(method, url, request_headers, **kwargs)
            return response
        except DownloadError as e:
            # Normalize retry-layer errors into extractor domain
            raise ExtractorError(f"Request failed for URL {url}: {e.message}")
        except httpx.TimeoutException as e:
            # Fallback in case timeout bubbles up directly
            raise ExtractorError(f"Timeout while requesting {url}: {str(e)}")
        except httpx.HTTPStatusError as e:
            # Normalize HTTP errors to extractor domain
            raise ExtractorError(f"HTTP error {e.response.status_code} while requesting {url}")
        except Exception as e:
            raise ExtractorError(f"Request failed for URL {url}: {str(e)}")

    @abstractmethod
    async def extract(self, url: str, **kwargs) -> Dict[str, Any]:
        """Extract final URL and required headers."""
        pass
