from abc import ABC, abstractmethod
from typing import Dict, Optional, Any

import httpx
import ssl
import certifi  # optional: use Mozilla CA bundle if preferred
from urllib.parse import urlparse

from mediaflow_proxy.configs import settings


class ExtractorError(Exception):
    """Base exception for all extractors."""
    pass


class BaseExtractor(ABC):
    """Base class for all URL extractors."""

    def __init__(self, request_headers: dict):
        # Base headers for the application
        self.base_headers = {
            "user-agent": settings.user_agent,
        }
        self.mediaflow_endpoint = "proxy_stream_endpoint"
        self.base_headers.update(request_headers)

        # SSL contexts:
        # - default_ctx: uses system or certifi trust store (secure verification)
        # - custom_ctx: load extra root/intermediate CAs for specific domains
        #
        # Option A: system trust store (recommended if the container has updated ca-certificates)
        default_ctx = ssl.create_default_context()
        # Option B: start from certifi bundle (uncomment if you prefer Mozilla bundle)
        # default_ctx = ssl.create_default_context(cafile=certifi.where())

        # Custom context for domains behind TLS inspection or with non-standard chains
        custom_ctx = ssl.create_default_context()
        # If you have a PEM with additional CAs, mount it and enable the line below:
        # custom_ctx.load_verify_locations(cafile="/app/certs/ca-bundle.pem")

        # Granular timeouts to better tolerate slow endpoints and control TTFB
        default_timeout = httpx.Timeout(connect=10.0, read=30.0, write=30.0, pool=30.0)

        # Persistent HTTPX clients:
        # - Certificate verification configured at client level (verify=SSLContext)
        # - Automatic redirects enabled for 3xx
        self._default_client = httpx.AsyncClient(
            timeout=default_timeout,
            follow_redirects=True,
            verify=default_ctx,
        )

        self._custom_ca_client = httpx.AsyncClient(
            timeout=default_timeout,
            follow_redirects=True,
            verify=custom_ctx,
        )

        # Domains that should use the custom CA client (adjust as needed)
        self._custom_ca_domains = (
            "newkso.ru",
            "testdrivenetwork.click",
        )

    async def _make_request(
        self, url: str, method: str = "GET", headers: Optional[Dict] = None, **kwargs
    ) -> httpx.Response:
        """Make HTTP request with error handling."""
        try:
            netloc = urlparse(url).netloc

            # Choose client per-domain; use custom CA for listed domains
            use_custom = any(d in netloc for d in self._custom_ca_domains)
            client = self._custom_ca_client if use_custom else self._default_client

            # Compose effective headers
            request_headers = self.base_headers.copy()
            request_headers.update(headers or {})

            # Allow per-request timeout override; verification stays at client level
            req_timeout = kwargs.pop("timeout", None)
            kwargs.pop("verify", None)

            response = await client.request(
                method,
                url,
                headers=request_headers,
                timeout=req_timeout,
                **kwargs,
            )
            # Raise for 4xx/5xx; 3xx are already followed thanks to follow_redirects=True
            response.raise_for_status()
            return response
        except httpx.HTTPError as e:
            raise ExtractorError(f"HTTP request failed for URL {url}: {str(e)}")
        except Exception as e:
            raise ExtractorError(f"Request failed for URL {url}: {str(e)}")

    async def aclose(self):
        """Close HTTP clients on application shutdown."""
        await self._default_client.aclose()
        await self._custom_ca_client.aclose()

    @abstractmethod
    async def extract(self, url: str, **kwargs) -> Dict[str, Any]:
        """Extract final URL and required headers."""
        pass

    async def _request_with_retry(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict] = None,
        attempts: int = 3,
        base_delay: float = 0.5,
        timeout: Optional[httpx.Timeout] = None,
        **kwargs,
    ) -> httpx.Response:
        """
        Perform a request with simple exponential backoff on ReadTimeout/ConnectTimeout.
        Use the 'timeout' parameter to set a higher read timeout for slow endpoints.
        """
        import asyncio
        from httpx import ReadTimeout, ConnectTimeout

        delay = base_delay
        last_exc: Optional[Exception] = None

        for _ in range(attempts):
            try:
                return await self._make_request(
                    url,
                    method=method,
                    headers=headers,
                    timeout=timeout,
                    **kwargs,
                )
            except ExtractorError as e:
                msg = str(e)
                if "ReadTimeout" in msg or "ConnectTimeout" in msg:
                    last_exc = e
                    await asyncio.sleep(delay)
                    delay *= 2
                    continue
                raise
        raise last_exc or ExtractorError(f"Retries exhausted for {url}")
