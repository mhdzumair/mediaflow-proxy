import logging
import typing
from dataclasses import dataclass
from functools import partial
from urllib import parse
from urllib.parse import urlencode

import anyio
import h11
import httpx
import tenacity
from fastapi import Response
from starlette.background import BackgroundTask
from starlette.concurrency import iterate_in_threadpool
from starlette.requests import Request
from starlette.types import Receive, Send, Scope
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
from tqdm.asyncio import tqdm as tqdm_asyncio

from mediaflow_proxy.configs import settings
from mediaflow_proxy.const import SUPPORTED_REQUEST_HEADERS
from mediaflow_proxy.utils.crypto_utils import EncryptionHandler

logger = logging.getLogger(__name__)


class DownloadError(Exception):
    def __init__(self, status_code, message):
        self.status_code = status_code
        self.message = message
        super().__init__(message)


def create_httpx_client(follow_redirects: bool = True, **kwargs) -> httpx.AsyncClient:
    """Creates an HTTPX client with configured proxy routing"""
    mounts = settings.transport_config.get_mounts()
    kwargs.setdefault("timeout", settings.transport_config.timeout)
    client = httpx.AsyncClient(mounts=mounts, follow_redirects=follow_redirects, **kwargs)
    return client


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
        if e.response.status_code == 404:
            logger.error(f"Segment Resource not found: {url}")
            raise e
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
        self.progress_bar = None
        self.bytes_transferred = 0
        self.start_byte = 0
        self.end_byte = 0
        self.total_size = 0

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=4, max=10),
        retry=retry_if_exception_type(DownloadError),
    )
    async def create_streaming_response(self, url: str, headers: dict):
        """
        Creates and sends a streaming request.

        Args:
            url (str): The URL to stream from.
            headers (dict): The headers to include in the request.

        """
        try:
            request = self.client.build_request("GET", url, headers=headers)
            self.response = await self.client.send(request, stream=True, follow_redirects=True)
            self.response.raise_for_status()
        except httpx.TimeoutException:
            logger.warning("Timeout while creating streaming response")
            raise DownloadError(409, "Timeout while creating streaming response")
        except httpx.HTTPStatusError as e:
            logger.error(f"HTTP error {e.response.status_code} while creating streaming response")
            if e.response.status_code == 404:
                logger.error(f"Segment Resource not found: {url}")
                raise e
            raise DownloadError(
                e.response.status_code, f"HTTP error {e.response.status_code} while creating streaming response"
            )
        except httpx.RequestError as e:
            logger.error(f"Error creating streaming response: {e}")
            raise DownloadError(502, f"Error creating streaming response: {e}")
        except Exception as e:
            logger.error(f"Error creating streaming response: {e}")
            raise RuntimeError(f"Error creating streaming response: {e}")

    async def stream_content(self) -> typing.AsyncGenerator[bytes, None]:
        """
        Streams the content from the response.
        """
        if not self.response:
            raise RuntimeError("No response available for streaming")

        try:
            self.parse_content_range()

            if settings.enable_streaming_progress:
                with tqdm_asyncio(
                    total=self.total_size,
                    initial=self.start_byte,
                    unit="B",
                    unit_scale=True,
                    unit_divisor=1024,
                    desc="Streaming",
                    ncols=100,
                    mininterval=1,
                ) as self.progress_bar:
                    async for chunk in self.response.aiter_bytes():
                        yield chunk
                        chunk_size = len(chunk)
                        self.bytes_transferred += chunk_size
                        self.progress_bar.set_postfix_str(
                            f"📥 : {self.format_bytes(self.bytes_transferred)}", refresh=False
                        )
                        self.progress_bar.update(chunk_size)
            else:
                async for chunk in self.response.aiter_bytes():
                    yield chunk
                    self.bytes_transferred += len(chunk)

        except httpx.TimeoutException:
            logger.warning("Timeout while streaming")
            raise DownloadError(409, "Timeout while streaming")
        except httpx.RemoteProtocolError as e:
            # Special handling for connection closed errors
            if "peer closed connection without sending complete message body" in str(e):
                logger.warning(f"Remote server closed connection prematurely: {e}")
                # If we've received some data, just log the warning and return normally
                if self.bytes_transferred > 0:
                    logger.info(
                        f"Partial content received ({self.bytes_transferred} bytes). Continuing with available data."
                    )
                    return
                else:
                    # If we haven't received any data, raise an error
                    raise DownloadError(502, f"Remote server closed connection without sending any data: {e}")
            else:
                logger.error(f"Protocol error while streaming: {e}")
                raise DownloadError(502, f"Protocol error while streaming: {e}")
        except GeneratorExit:
            logger.info("Streaming session stopped by the user")
        except Exception as e:
            logger.error(f"Error streaming content: {e}")
            raise

    @staticmethod
    def format_bytes(size) -> str:
        power = 2**10
        n = 0
        units = {0: "B", 1: "KB", 2: "MB", 3: "GB", 4: "TB"}
        while size > power:
            size /= power
            n += 1
        return f"{size:.2f} {units[n]}"

    def parse_content_range(self):
        content_range = self.response.headers.get("Content-Range", "")
        if content_range:
            range_info = content_range.split()[-1]
            self.start_byte, self.end_byte, self.total_size = map(int, range_info.replace("/", "-").split("-"))
        else:
            self.start_byte = 0
            self.total_size = int(self.response.headers.get("Content-Length", 0))
            self.end_byte = self.total_size - 1 if self.total_size > 0 else 0

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
        if self.progress_bar:
            self.progress_bar.close()
        await self.client.aclose()


async def download_file_with_retry(url: str, headers: dict):
    """
    Downloads a file with retry logic.

    Args:
        url (str): The URL of the file to download.
        headers (dict): The headers to include in the request.

    Returns:
        bytes: The downloaded file content.

    Raises:
        DownloadError: If the download fails after retries.
    """
    async with create_httpx_client() as client:
        try:
            response = await fetch_with_retry(client, "GET", url, headers)
            return response.content
        except DownloadError as e:
            logger.error(f"Failed to download file: {e}")
            raise e
        except tenacity.RetryError as e:
            raise DownloadError(502, f"Failed to download file: {e.last_attempt.result()}")


async def request_with_retry(method: str, url: str, headers: dict, **kwargs) -> httpx.Response:
    """
    Sends an HTTP request with retry logic.

    Args:
        method (str): The HTTP method to use (e.g., GET, POST).
        url (str): The URL to send the request to.
        headers (dict): The headers to include in the request.
        **kwargs: Additional arguments to pass to the request.

    Returns:
        httpx.Response: The HTTP response.

    Raises:
        DownloadError: If the request fails after retries.
    """
    async with create_httpx_client() as client:
        try:
            response = await fetch_with_retry(client, method, url, headers, **kwargs)
            return response
        except DownloadError as e:
            logger.error(f"Failed to download file: {e}")
            raise


def encode_mediaflow_proxy_url(
    mediaflow_proxy_url: str,
    endpoint: typing.Optional[str] = None,
    destination_url: typing.Optional[str] = None,
    query_params: typing.Optional[dict] = None,
    request_headers: typing.Optional[dict] = None,
    response_headers: typing.Optional[dict] = None,
    encryption_handler: EncryptionHandler = None,
    expiration: int = None,
    ip: str = None,
    filename: typing.Optional[str] = None,
) -> str:
    """
    Encodes & Encrypt (Optional) a MediaFlow proxy URL with query parameters and headers.

    Args:
        mediaflow_proxy_url (str): The base MediaFlow proxy URL.
        endpoint (str, optional): The endpoint to append to the base URL. Defaults to None.
        destination_url (str, optional): The destination URL to include in the query parameters. Defaults to None.
        query_params (dict, optional): Additional query parameters to include. Defaults to None.
        request_headers (dict, optional): Headers to include as query parameters. Defaults to None.
        response_headers (dict, optional): Headers to include as query parameters. Defaults to None.
        encryption_handler (EncryptionHandler, optional): The encryption handler to use. Defaults to None.
        expiration (int, optional): The expiration time for the encrypted token. Defaults to None.
        ip (str, optional): The public IP address to include in the query parameters. Defaults to None.
        filename (str, optional): Filename to be preserved for media players like Infuse. Defaults to None.

    Returns:
        str: The encoded MediaFlow proxy URL.
    """
    # Prepare query parameters
    query_params = query_params or {}
    if destination_url is not None:
        query_params["d"] = destination_url

    # Add headers if provided
    if request_headers:
        query_params.update(
            {key if key.startswith("h_") else f"h_{key}": value for key, value in request_headers.items()}
        )
    if response_headers:
        query_params.update(
            {key if key.startswith("r_") else f"r_{key}": value for key, value in response_headers.items()}
        )

    # Construct the base URL
    if endpoint is None:
        base_url = mediaflow_proxy_url
    else:
        base_url = parse.urljoin(mediaflow_proxy_url, endpoint)

    # Ensure base_url doesn't end with a slash for consistent handling
    if base_url.endswith("/"):
        base_url = base_url[:-1]

    # Handle encryption if needed
    if encryption_handler:
        encrypted_token = encryption_handler.encrypt_data(query_params, expiration, ip)

        # Parse the base URL to get its components
        parsed_url = parse.urlparse(base_url)

        # Insert the token at the beginning of the path
        new_path = f"/_token_{encrypted_token}{parsed_url.path}"

        # Reconstruct the URL with the token at the beginning of the path
        url_parts = list(parsed_url)
        url_parts[2] = new_path  # Update the path component

        # Build the URL
        url = parse.urlunparse(url_parts)

        # Add filename at the end if provided
        if filename:
            url = f"{url}/{parse.quote(filename)}"

        return url
    else:
        # No encryption, use regular query parameters
        url = base_url
        if filename:
            url = f"{url}/{parse.quote(filename)}"

        if query_params:
            return f"{url}?{urlencode(query_params)}"
        return url


def encode_stremio_proxy_url(
    stremio_proxy_url: str,
    destination_url: str,
    request_headers: typing.Optional[dict] = None,
    response_headers: typing.Optional[dict] = None,
) -> str:
    """
    Encodes a Stremio proxy URL with destination URL and headers.

    Format: http://127.0.0.1:11470/proxy/d=<encoded_origin>&h=<headers>&r=<response_headers>/<path><query>

    Args:
        stremio_proxy_url (str): The base Stremio proxy URL.
        destination_url (str): The destination URL to proxy.
        request_headers (dict, optional): Headers to include as query parameters. Defaults to None.
        response_headers (dict, optional): Response headers to include as query parameters. Defaults to None.

    Returns:
        str: The encoded Stremio proxy URL.
    """
    # Parse the destination URL to separate origin, path, and query
    parsed_dest = parse.urlparse(destination_url)
    dest_origin = f"{parsed_dest.scheme}://{parsed_dest.netloc}"
    dest_path = parsed_dest.path.lstrip("/")
    dest_query = parsed_dest.query

    # Prepare query parameters list for proper handling of multiple headers
    query_parts = []

    # Add destination origin (scheme + netloc only) with proper encoding
    query_parts.append(f"d={parse.quote_plus(dest_origin)}")

    # Add request headers
    if request_headers:
        for key, value in request_headers.items():
            header_string = f"{key}:{value}"
            query_parts.append(f"h={parse.quote_plus(header_string)}")

    # Add response headers
    if response_headers:
        for key, value in response_headers.items():
            header_string = f"{key}:{value}"
            query_parts.append(f"r={parse.quote_plus(header_string)}")

    # Ensure base_url doesn't end with a slash for consistent handling
    base_url = stremio_proxy_url.rstrip("/")

    # Construct the URL path with query string
    query_string = "&".join(query_parts)

    # Build the final URL: /proxy/{opts}/{pathname}{search}
    url_path = f"/proxy/{query_string}"

    # Append the path from destination URL
    if dest_path:
        url_path = f"{url_path}/{dest_path}"

    # Append the query string from destination URL
    if dest_query:
        url_path = f"{url_path}?{dest_query}"

    return f"{base_url}{url_path}"


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


@dataclass
class ProxyRequestHeaders:
    request: dict
    response: dict


def get_proxy_headers(request: Request) -> ProxyRequestHeaders:
    """
    Extracts proxy headers from the request query parameters.

    Args:
        request (Request): The incoming HTTP request.

    Returns:
        ProxyRequest: A named tuple containing the request headers and response headers.
    """
    request_headers = {k: v for k, v in request.headers.items() if k in SUPPORTED_REQUEST_HEADERS}
    request_headers.update({k[2:].lower(): v for k, v in request.query_params.items() if k.startswith("h_")})
    response_headers = {k[2:].lower(): v for k, v in request.query_params.items() if k.startswith("r_")}
    return ProxyRequestHeaders(request_headers, response_headers)


class EnhancedStreamingResponse(Response):
    body_iterator: typing.AsyncIterable[typing.Any]

    def __init__(
        self,
        content: typing.Union[typing.AsyncIterable[typing.Any], typing.Iterable[typing.Any]],
        status_code: int = 200,
        headers: typing.Optional[typing.Mapping[str, str]] = None,
        media_type: typing.Optional[str] = None,
        background: typing.Optional[BackgroundTask] = None,
    ) -> None:
        if isinstance(content, typing.AsyncIterable):
            self.body_iterator = content
        else:
            self.body_iterator = iterate_in_threadpool(content)
        self.status_code = status_code
        self.media_type = self.media_type if media_type is None else media_type
        self.background = background
        self.init_headers(headers)
        self.actual_content_length = 0

    @staticmethod
    async def listen_for_disconnect(receive: Receive) -> None:
        try:
            while True:
                message = await receive()
                if message["type"] == "http.disconnect":
                    logger.debug("Client disconnected")
                    break
        except Exception as e:
            logger.error(f"Error in listen_for_disconnect: {str(e)}")

    async def stream_response(self, send: Send) -> None:
        try:
            # Initialize headers
            headers = list(self.raw_headers)

            # Set the transfer-encoding to chunked for streamed responses with content-length
            # when content-length is present. This ensures we don't hit protocol errors
            # if the upstream connection is closed prematurely.
            for i, (name, _) in enumerate(headers):
                if name.lower() == b"content-length":
                    # Replace content-length with transfer-encoding: chunked for streaming
                    headers[i] = (b"transfer-encoding", b"chunked")
                    headers = [h for h in headers if h[0].lower() != b"content-length"]
                    logger.debug("Switched from content-length to chunked transfer-encoding for streaming")
                    break

            # Start the response
            await send(
                {
                    "type": "http.response.start",
                    "status": self.status_code,
                    "headers": headers,
                }
            )

            # Track if we've sent any data
            data_sent = False

            try:
                async for chunk in self.body_iterator:
                    if not isinstance(chunk, (bytes, memoryview)):
                        chunk = chunk.encode(self.charset)
                    try:
                        await send({"type": "http.response.body", "body": chunk, "more_body": True})
                        data_sent = True
                        self.actual_content_length += len(chunk)
                    except (ConnectionResetError, anyio.BrokenResourceError):
                        logger.info("Client disconnected during streaming")
                        return

                # Successfully streamed all content
                await send({"type": "http.response.body", "body": b"", "more_body": False})
            except (httpx.RemoteProtocolError, h11._util.LocalProtocolError) as e:
                # Handle connection closed errors
                if data_sent:
                    # We've sent some data to the client, so try to complete the response
                    logger.warning(f"Remote protocol error after partial streaming: {e}")
                    try:
                        await send({"type": "http.response.body", "body": b"", "more_body": False})
                        logger.info(
                            f"Response finalized after partial content ({self.actual_content_length} bytes transferred)"
                        )
                    except Exception as close_err:
                        logger.warning(f"Could not finalize response after remote error: {close_err}")
                else:
                    # No data was sent, re-raise the error
                    logger.error(f"Protocol error before any data was streamed: {e}")
                    raise
        except Exception as e:
            logger.exception(f"Error in stream_response: {str(e)}")
            if not isinstance(e, (ConnectionResetError, anyio.BrokenResourceError)):
                try:
                    # Try to send an error response if client is still connected
                    await send(
                        {
                            "type": "http.response.start",
                            "status": 502,
                            "headers": [(b"content-type", b"text/plain")],
                        }
                    )
                    error_message = f"Streaming error: {str(e)}".encode("utf-8")
                    await send({"type": "http.response.body", "body": error_message, "more_body": False})
                except Exception:
                    # If we can't send an error response, just log it
                    pass

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        async with anyio.create_task_group() as task_group:
            streaming_completed = False
            stream_func = partial(self.stream_response, send)
            listen_func = partial(self.listen_for_disconnect, receive)

            async def wrap(func: typing.Callable[[], typing.Awaitable[None]]) -> None:
                try:
                    await func()
                    # If this is the stream_response function and it completes successfully, mark as done
                    if func == stream_func:
                        nonlocal streaming_completed
                        streaming_completed = True
                except Exception as e:
                    if isinstance(e, (httpx.RemoteProtocolError, h11._util.LocalProtocolError)):
                        # Handle protocol errors more gracefully
                        logger.warning(f"Protocol error during streaming: {e}")
                    elif not isinstance(e, anyio.get_cancelled_exc_class()):
                        logger.exception("Error in streaming task")
                        # Only re-raise if it's not a protocol error or cancellation
                        raise
                finally:
                    # Only cancel the task group if we're in disconnect listener or
                    # if streaming_completed is True (meaning we finished normally)
                    if func == listen_func or streaming_completed:
                        task_group.cancel_scope.cancel()

            # Start the streaming response in a separate task
            task_group.start_soon(wrap, stream_func)
            # Listen for disconnect events
            await wrap(listen_func)

        if self.background is not None:
            await self.background()
