from abc import ABC, abstractmethod
from typing import Dict, Tuple, Optional

import httpx

from mediaflow_proxy.configs import settings
from mediaflow_proxy.utils.http_utils import create_httpx_client


class BaseExtractor(ABC):
    """Base class for all URL extractors."""

    def __init__(self, request_headers: dict):
        self.base_headers = {
            "user-agent": settings.user_agent,
            "accept-language": "en-US,en;q=0.5",
        }
        self.base_headers.update(request_headers)

    async def _make_request(self, url: str, headers: Optional[Dict] = None, **kwargs) -> httpx.Response:
        """Make HTTP request with error handling."""
        try:
            async with create_httpx_client() as client:
                request_headers = self.base_headers
                request_headers.update(headers or {})
                response = await client.get(
                    url,
                    headers=request_headers,
                    **kwargs,
                )
                response.raise_for_status()
                return response
        except httpx.HTTPError as e:
            raise ValueError(f"HTTP request failed: {str(e)}")
        except Exception as e:
            raise ValueError(f"Request failed: {str(e)}")

    @abstractmethod
    async def extract(self, url: str) -> Tuple[str, Dict[str, str]]:
        """Extract final URL and required headers."""
        pass
