# base.py
from abc import ABC, abstractmethod
from typing import Dict, Optional, Any
import httpx
from urllib.parse import urlparse
from mediaflow_proxy.configs import settings

class ExtractorError(Exception):
    pass

class BaseExtractor(ABC):
    def __init__(self, request_headers: dict):
        self.base_headers = {"user-agent": settings.user_agent}
        self.mediaflow_endpoint = "proxy_stream_endpoint"
        self.base_headers.update(request_headers)
        # Client persistenti: verify a livello DI CLIENT, non per-request
        self._default_client = httpx.AsyncClient(timeout=httpx.Timeout(20.0))  # verify=True di default
        self._insecure_client = httpx.AsyncClient(timeout=httpx.Timeout(20.0), verify=False)  # solo per newkso.ru

    async def _make_request(
        self, url: str, method: str = "GET", headers: Optional[Dict] = None, **kwargs
    ) -> httpx.Response:
        try:
            netloc = urlparse(url).netloc
            client = self._insecure_client if "newkso.ru" in netloc else self._default_client
            req_headers = self.base_headers.copy()
            req_headers.update(headers or {})
            kwargs.pop("verify", None)  # rimuove verify per-request che causa TypeError
            resp = await client.request(method, url, headers=req_headers, **kwargs)
            resp.raise_for_status()
            return resp
        except httpx.HTTPError as e:
            raise ExtractorError(f"HTTP request failed for URL {url}: {str(e)}")
        except Exception as e:
            raise ExtractorError(f"Request failed for URL {url}: {str(e)}")

    async def aclose(self):
        await self._default_client.aclose()
        await self._insecure_client.aclose()
