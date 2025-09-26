from abc import ABC, abstractmethod
from typing import Dict, Optional, Any

import asyncio
import httpx
import logging

from mediaflow_proxy.configs import settings
from mediaflow_proxy.utils.http_utils import create_httpx_client, DownloadError

logger = logging.getLogger(__name__)


class ExtractorError(Exception):
    """Base exception for all extractors."""
    pass


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
    ) -> httpx.Response:
        """
        Make HTTP request with retry and timeout support.

        Parameters
        ----------
        timeout : float | None
            Seconds to wait for the request (applied to httpx.Timeout). Defaults to 15s.
        retries : int
            Number of attempts for transient errors.
        backoff_factor : float
            Base for exponential backoff between retries.
        raise_on_status : bool
            If True, HTTP non-2xx raises DownloadError (preserves status code).
        """
        attempt = 0
        last_exc = None

        # build request headers merging base and per-request
        request_headers = self.base_headers.copy()
        if headers:
            request_headers.update(headers)

        timeout_cfg = httpx.Timeout(timeout or 15.0)

        while attempt < retries:
            try:
                async with create_httpx_client(timeout=timeout_cfg) as client:
                    response = await client.request(
                        method,
                        url,
                        headers=request_headers,
                        **kwargs,
                    )

                    if raise_on_status:
                        try:
                            response.raise_for_status()
                        except httpx.HTTPStatusError as e:
                            # Provide a short body preview for debugging
                            body_preview = ""
                            try:
                                body_preview = e.response.text[:500]
                            except Exception:
                                body_preview = "<unreadable body>"
                            logger.debug(
                                "HTTPStatusError for %s (status=%s) -- body preview: %s",
                                url,
                                e.response.status_code,
                                body_preview,
                            )
                            raise DownloadError(e.response.status_code, f"HTTP error {e.response.status_code} while requesting {url}")
                    return response

            except DownloadError:
                # Do not retry on explicit HTTP status errors (they are intentional)
                raise
            except (httpx.ReadTimeout, httpx.ConnectTimeout, httpx.NetworkError, httpx.TransportError) as e:
                # Transient network error — retry with backoff
                last_exc = e
                attempt += 1
                sleep_for = backoff_factor * (2 ** (attempt - 1))
                logger.warning("Transient network error (attempt %s/%s) for %s: %s — retrying in %.1fs",
                               attempt, retries, url, e, sleep_for)
                await asyncio.sleep(sleep_for)
                continue
            except Exception as e:
                # Unexpected exception — wrap as ExtractorError to keep interface consistent
                logger.exception("Unhandled exception while requesting %s: %s", url, e)
                raise ExtractorError(f"Request failed for URL {url}: {str(e)}")

        logger.error("All retries failed for %s: %s", url, last_exc)
        raise ExtractorError(f"Request failed for URL {url}: {str(last_exc)}")

    @abstractmethod
    async def extract(self, url: str, **kwargs) -> Dict[str, Any]:
        """Extract final URL and required headers."""
        pass
