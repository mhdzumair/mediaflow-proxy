from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Dict, Optional, Any
from urllib.parse import urlparse

import asyncio
import aiohttp
import json
import logging

from mediaflow_proxy.configs import settings
from mediaflow_proxy.utils.http_client import create_aiohttp_session
from mediaflow_proxy.utils.http_utils import DownloadError

logger = logging.getLogger(__name__)


class ExtractorError(Exception):
    """Base exception for all extractors."""

    pass


@dataclass
class HttpResponse:
    """
    Simple response container for extractor HTTP requests.

    Uses aiohttp-style naming conventions:
    - status (not status_code)
    - text (pre-loaded content as string)
    - content (pre-loaded content as bytes)
    """

    status: int
    headers: Dict[str, str]
    text: str
    content: bytes
    url: str

    def json(self) -> Any:
        """Parse response content as JSON."""
        return json.loads(self.text)

    def get_origin(self) -> str:
        """Get the origin (scheme + host) from the response URL."""
        parsed = urlparse(self.url)
        return f"{parsed.scheme}://{parsed.netloc}"


class BaseExtractor(ABC):
    """Base class for all URL extractors.

    Improvements:
    - Built-in retry/backoff for transient network errors
    - Configurable timeouts and per-request overrides
    - Better logging of non-200 responses and body previews for debugging
    """

    def __init__(self, request_headers: dict):
        self.base_headers = {
            "user-agent": settings.user_agent,
        }
        self.mediaflow_endpoint = "proxy_stream_endpoint"
        # merge incoming headers (e.g. Accept-Language / Referer) with default base headers
        self.base_headers.update(request_headers or {})

    async def _make_request(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict] = None,
        timeout: Optional[float] = None,
        retries: int = 3,
        backoff_factor: float = 0.5,
        raise_on_status: bool = True,
        **kwargs,
    ) -> HttpResponse:
        """
        Make HTTP request with retry and timeout support using aiohttp.

        Parameters
        ----------
        url : str
            The URL to request.
        method : str
            HTTP method (GET, POST, etc.). Defaults to GET.
        headers : dict | None
            Additional headers to merge with base headers.
        timeout : float | None
            Seconds to wait for the request. Defaults to 15s.
        retries : int
            Number of attempts for transient errors.
        backoff_factor : float
            Base for exponential backoff between retries.
        raise_on_status : bool
            If True, HTTP non-2xx raises DownloadError.
        **kwargs
            Additional arguments passed to aiohttp request (e.g., data, json).

        Returns
        -------
        HttpResponse
            Response object with pre-loaded content.
        """
        attempt = 0
        last_exc = None

        # Build request headers merging base and per-request
        request_headers = self.base_headers.copy()
        if headers:
            request_headers.update(headers)

        timeout_val = timeout or 15.0

        while attempt < retries:
            try:
                async with create_aiohttp_session(url, timeout=timeout_val) as (session, proxy_url):
                    async with session.request(
                        method,
                        url,
                        headers=request_headers,
                        proxy=proxy_url,
                        **kwargs,
                    ) as response:
                        # Read content while session is still open
                        content = await response.read()
                        text = content.decode("utf-8", errors="replace")
                        final_url = str(response.url)
                        status = response.status
                        resp_headers = dict(response.headers)

                        if raise_on_status and status >= 400:
                            body_preview = text[:500]
                            logger.debug(
                                "HTTP error for %s (status=%s) -- body preview: %s",
                                url,
                                status,
                                body_preview,
                            )
                            raise DownloadError(status, f"HTTP error {status} while requesting {url}")

                        return HttpResponse(
                            status=status,
                            headers=resp_headers,
                            text=text,
                            content=content,
                            url=final_url,
                        )

            except DownloadError:
                # Do not retry on explicit HTTP status errors (they are intentional)
                raise
            except (asyncio.TimeoutError, aiohttp.ClientError) as e:
                # Transient network error - retry with backoff
                last_exc = e
                attempt += 1
                sleep_for = backoff_factor * (2 ** (attempt - 1))
                logger.warning(
                    "Transient network error (attempt %s/%s) for %s: %s — retrying in %.1fs",
                    attempt,
                    retries,
                    url,
                    e,
                    sleep_for,
                )
                await asyncio.sleep(sleep_for)
                continue
            except Exception as e:
                # Unexpected exception - wrap as ExtractorError to keep interface consistent
                logger.exception("Unhandled exception while requesting %s: %s", url, e)
                raise ExtractorError(f"Request failed for URL {url}: {str(e)}")

        logger.error("All retries failed for %s: %s", url, last_exc)
        raise ExtractorError(f"Request failed for URL {url}: {str(last_exc)}")

    @abstractmethod
    async def extract(self, url: str, **kwargs) -> Dict[str, Any]:
        """Extract final URL and required headers."""
        pass
