from abc import ABC, abstractmethod
from typing import Dict, Optional, Any

import httpx
import ssl
import certifi  # opzionale: per partire dal bundle Mozilla
from urllib.parse import urlparse

from mediaflow_proxy.configs import settings


class ExtractorError(Exception):
    """Base exception for all extractors."""
    pass


class BaseExtractor(ABC):
    """Base class for all URL extractors."""

    def __init__(self, request_headers: dict):
        # App base headers
        self.base_headers = {
            "user-agent": settings.user_agent,
        }
        self.mediaflow_endpoint = "proxy_stream_endpoint"
        self.base_headers.update(request_headers)

        # SSL contexts:
        # - default_ctx: use system or certifi CA bundle (secure verification)
        # - custom_ctx: add extra CA/intermediates required by specific domains
        #
        # Option A: system trust store (recommended if container has updated ca-certificates)
        default_ctx = ssl.create_default_context()
        # Option B: start from certifi bundle (uncomment if preferred)
        # default_ctx = ssl.create_default_context(cafile=certifi.where())

        # Custom context for domains with non-standard chains or enterprise interception
        custom_ctx = ssl.create_default_context()
        # If you have a PEM with additional root/intermediate CAs, mount and load it here:
        # custom_ctx.load_verify_locations(cafile="/app/certs/ca-bundle.pem")

        # Persistent HTTPX clients:
        # - No per-request verify: certificate verification is configured at client level
        # - Automatic redirects enabled to follow 301/302 (e.g., daddylive.sx -> thedaddy.top)
        # - Reasonable timeout; add more parameters if needed (http2, proxies, etc.)
        self._default_client = httpx.AsyncClient(
            timeout=httpx.Timeout(20.0),
            follow_redirects=True,
            verify=default_ctx,  # secure verification using system/certifi store
        )

        # Client with custom CA bundle for specific domains (instead of verify=False)
        self._custom_ca_client = httpx.AsyncClient(
            timeout=httpx.Timeout(20.0),
            follow_redirects=True,
            verify=custom_ctx,  # secure verification with additional CA(s)
        )

        # Domains requiring the custom CA context (adjust as needed)
        self._custom_ca_domains = (
            "newkso.ru",
        )

    async def _make_request(
        self, url: str, method: str = "GET", headers: Optional[Dict] = None, **kwargs
    ) -> httpx.Response:
        """Make HTTP request with error handling."""
        try:
            netloc = urlparse(url).netloc

            # Select client based on domain; use custom CA client for specific domains
            use_custom = any(d in netloc for d in self._custom_ca_domains)
            client = self._custom_ca_client if use_custom else self._default_client  # [uses SSLContext verify]

            # Build effective headers
            request_headers = self.base_headers.copy()
            request_headers.update(headers or {})

            # Remove 'verify' from kwargs to avoid TypeError on async calls; verify is configured on the client
            kwargs.pop("verify", None)

            response = await client.request(
                method,
                url,
                headers=request_headers,
                **kwargs,
            )
            # raise_for_status raises for 4xx/5xx; 3xx are followed due to follow_redirects=True
            response.raise_for_status()
            return response
        except httpx.HTTPError as e:
            raise ExtractorError(f"HTTP request failed for URL {url}: {str(e)}")
        except Exception as e:
            raise ExtractorError(f"Request failed for URL {url}: {str(e)}")

    async def aclose(self):
        """Close clients on app shutdown."""
        await self._default_client.aclose()
        await self._custom_ca_client.aclose()

    @abstractmethod
    async def extract(self, url: str, **kwargs) -> Dict[str, Any]:
        """Extract final URL and required headers."""
        pass
