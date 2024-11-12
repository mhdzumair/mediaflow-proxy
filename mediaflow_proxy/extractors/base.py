from abc import ABC, abstractmethod
from typing import Dict, Tuple, Optional

import httpx

from mediaflow_proxy.configs import settings


class BaseExtractor(ABC):
    """Base class for all URL extractors."""

    def __init__(self, proxy_enabled: bool, request_headers: dict):
        self.proxy_url = settings.proxy_url if proxy_enabled else None
        self.base_headers = {
            "User-Agent": settings.user_agent,
            "Accept-Language": "en-US,en;q=0.5",
            **request_headers,
        }

    async def _make_request(
        self, url: str, headers: Optional[Dict] = None, follow_redirects: bool = True, **kwargs
    ) -> httpx.Response:
        """Make HTTP request with error handling."""
        try:
            async with httpx.AsyncClient(proxy=self.proxy_url) as client:
                response = await client.get(
                    url,
                    headers={**self.base_headers, **(headers or {})},
                    follow_redirects=follow_redirects,
                    timeout=30,
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
