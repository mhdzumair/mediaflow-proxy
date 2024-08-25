import logging
from urllib import parse

import httpx
import tenacity
from starlette.requests import Request
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type

from mediaflow_proxy.configs import settings
from mediaflow_proxy.const import SUPPORTED_REQUEST_HEADERS

logger = logging.getLogger(__name__)


class DownloadError(Exception):
    def __init__(self, status_code, message):
        self.status_code = status_code
        self.message = message
        super().__init__(message)


@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=4, max=10),
    retry=retry_if_exception_type(DownloadError),
)
async def fetch_with_retry(client, method, url, headers, follow_redirects=True, **kwargs):
    """
    Fetches a URL with retry logic.

    Args:
        client (httpx.AsyncClient): The HTTP client to use for the request.
        method (str): The HTTP method to use (e.g., GET, POST).
        url (str): The URL to fetch.
        headers (dict): The headers to include in the request.
        follow_redirects (bool, optional): Whether to follow redirects. Defaults to True.
        **kwargs: Additional arguments to pass to the request.

    Returns:
        httpx.Response: The HTTP response.

    Raises:
        DownloadError: If the request fails after retries.
    """
    try:
        response = await client.request(method, url, headers=headers, follow_redirects=follow_redirects, **kwargs)
        response.raise_for_status()
        return response
    except httpx.TimeoutException:
        logger.warning(f"Timeout while downloading {url}")
        raise DownloadError(409, f"Timeout while downloading {url}")
    except httpx.HTTPStatusError as e:
        logger.error(f"HTTP error {e.response.status_code} while downloading {url}")
        # if e.response.status_code == 404:
        #     logger.error(f"Segment Resource not found: {url}")
        #     raise e
        raise DownloadError(e.response.status_code, f"HTTP error {e.response.status_code} while downloading {url}")
    except Exception as e:
        logger.error(f"Error downloading {url}: {e}")
        raise


class Streamer:
    def __init__(self, client):
        """
        Initializes the Streamer with an HTTP client.

        Args:
            client (httpx.AsyncClient): The HTTP client to use for streaming.
        """
        self.client = client
        self.response = None

    async def stream_content(self, url: str, headers: dict):
        """
        Streams content from a URL.

        Args:
            url (str): The URL to stream content from.
            headers (dict): The headers to include in the request.

        Yields:
            bytes: Chunks of the streamed content.
        """
        async with self.client.stream("GET", url, headers=headers, follow_redirects=True) as self.response:
            self.response.raise_for_status()
            async for chunk in self.response.aiter_bytes():
                yield chunk

    async def head(self, url: str, headers: dict):
        """
        Sends a HEAD request to a URL.

        Args:
            url (str): The URL to send the HEAD request to.
            headers (dict): The headers to include in the request.

        Returns:
            httpx.Response: The HTTP response.
        """
        try:
            self.response = await fetch_with_retry(self.client, "HEAD", url, headers)
        except tenacity.RetryError as e:
            raise e.last_attempt.result()
        return self.response

    async def get_text(self, url: str, headers: dict):
        """
        Sends a GET request to a URL and returns the response text.

        Args:
            url (str): The URL to send the GET request to.
            headers (dict): The headers to include in the request.

        Returns:
            str: The response text.
        """
        try:
            self.response = await fetch_with_retry(self.client, "GET", url, headers)
        except tenacity.RetryError as e:
            raise e.last_attempt.result()
        return self.response.text

    async def close(self):
        """
        Closes the HTTP client and response.
        """
        if self.response:
            await self.response.aclose()
        await self.client.aclose()


async def download_file_with_retry(url: str, headers: dict, timeout: float = 10.0):
    """
    Downloads a file with retry logic.

    Args:
        url (str): The URL of the file to download.
        headers (dict): The headers to include in the request.
        timeout (float, optional): The request timeout. Defaults to 10.0.

    Returns:
        bytes: The downloaded file content.

    Raises:
        DownloadError: If the download fails after retries.
    """
    async with httpx.AsyncClient(follow_redirects=True, timeout=timeout, proxy=settings.proxy_url) as client:
        try:
            response = await fetch_with_retry(client, "GET", url, headers)
            return response.content
        except DownloadError as e:
            logger.error(f"Failed to download file: {e}")
            raise e
        except tenacity.RetryError as e:
            raise DownloadError(502, f"Failed to download file: {e.last_attempt.result()}")


async def request_with_retry(method: str, url: str, headers: dict, timeout: float = 10.0, **kwargs):
    """
    Sends an HTTP request with retry logic.

    Args:
        method (str): The HTTP method to use (e.g., GET, POST).
        url (str): The URL to send the request to.
        headers (dict): The headers to include in the request.
        timeout (float, optional): The request timeout. Defaults to 10.0.
        **kwargs: Additional arguments to pass to the request.

    Returns:
        httpx.Response: The HTTP response.

    Raises:
        DownloadError: If the request fails after retries.
    """
    async with httpx.AsyncClient(follow_redirects=True, timeout=timeout, proxy=settings.proxy_url) as client:
        try:
            response = await fetch_with_retry(client, method, url, headers, **kwargs)
            return response
        except DownloadError as e:
            logger.error(f"Failed to download file: {e}")
            raise


def encode_mediaflow_proxy_url(
    mediaflow_proxy_url: str,
    endpoint: str | None = None,
    destination_url: str | None = None,
    query_params: dict | None = None,
    request_headers: dict | None = None,
) -> str:
    """
    Encodes a MediaFlow proxy URL with query parameters and headers.

    Args:
        mediaflow_proxy_url (str): The base MediaFlow proxy URL.
        endpoint (str, optional): The endpoint to append to the base URL. Defaults to None.
        destination_url (str, optional): The destination URL to include in the query parameters. Defaults to None.
        query_params (dict, optional): Additional query parameters to include. Defaults to None.
        request_headers (dict, optional): Headers to include as query parameters. Defaults to None.

    Returns:
        str: The encoded MediaFlow proxy URL.
    """
    query_params = query_params or {}
    if destination_url is not None:
        query_params["d"] = destination_url

    # Add headers if provided
    if request_headers:
        query_params.update(
            {key if key.startswith("h_") else f"h_{key}": value for key, value in request_headers.items()}
        )
    # Encode the query parameters
    encoded_params = parse.urlencode(query_params, quote_via=parse.quote)

    # Construct the full URL
    if endpoint is None:
        return f"{mediaflow_proxy_url}?{encoded_params}"

    base_url = parse.urljoin(mediaflow_proxy_url, endpoint)
    return f"{base_url}?{encoded_params}"


def get_original_scheme(request: Request) -> str:
    """
    Determines the original scheme (http or https) of the request.

    Args:
        request (Request): The incoming HTTP request.

    Returns:
        str: The original scheme ('http' or 'https')
    """
    # Check the X-Forwarded-Proto header first
    forwarded_proto = request.headers.get("X-Forwarded-Proto")
    if forwarded_proto:
        return forwarded_proto

    # Check if the request is secure
    if request.url.scheme == "https" or request.headers.get("X-Forwarded-Ssl") == "on":
        return "https"

    # Check for other common headers that might indicate HTTPS
    if (
        request.headers.get("X-Forwarded-Ssl") == "on"
        or request.headers.get("X-Forwarded-Protocol") == "https"
        or request.headers.get("X-Url-Scheme") == "https"
    ):
        return "https"

    # Default to http if no indicators of https are found
    return "http"


def get_proxy_headers(request: Request) -> dict:
    """
    Extracts proxy headers from the request query parameters.

    Args:
        request (Request): The incoming HTTP request.

    Returns:
        dict: A dictionary of proxy headers.
    """
    request_headers = {k: v for k, v in request.headers.items() if k in SUPPORTED_REQUEST_HEADERS}
    request_headers.update({k[2:].lower(): v for k, v in request.query_params.items() if k.startswith("h_")})
    return request_headers
