import logging
import typing
from dataclasses import dataclass
from functools import partial
from urllib import parse
from urllib.parse import urlencode

import anyio
import h11
import httpx # Ensure httpx is imported for type hints and exception handling
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
        httpx.HTTPStatusError: If a 404 error occurs (not wrapped in DownloadError).
    """
    try:
        response = await client.request(method, url, headers=headers, follow_redirects=follow_redirects, **kwargs)
        response.raise_for_status()
        return response
    except httpx.TimeoutException as e:
        logger.warning(f"Timeout while downloading {url}: {e}")
        raise DownloadError(409, f"Timeout while downloading {url}: {e}")
    except httpx.HTTPStatusError as e:
        logger.error(f"HTTP error {e.response.status_code} while downloading {url} (Request URL: {e.request.url})")
        if e.response.status_code == 404:
            logger.error(f"Segment Resource not found: {url}")
            raise e  # Do not wrap 404 in DownloadError, let it propagate as is
        # For other HTTP status errors (5xx, some 4xx), wrap in DownloadError to make them retryable.
        raise DownloadError(e.response.status_code, f"HTTP error {e.response.status_code} while downloading {url}: {e}")
    except httpx.RequestError as e:  # Catches ConnectError, ReadError, ProtocolError (like RemoteProtocolError), etc.
        logger.error(f"Request error downloading {url}: {e}")
        # Wrap these network/protocol related errors in DownloadError to make them retryable.
        # Using 502 (Bad Gateway) as a general code for upstream communication issues.
        raise DownloadError(502, f"Request error while downloading {url}: {e}")
    except Exception as e:  # Generic fallback for truly unexpected errors
        logger.error(f"Unexpected error downloading {url}: {e}", exc_info=True)
        # Re-raise to avoid retrying unknown states. If this becomes common, specific errors should be caught above.
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
        except httpx.TimeoutException as e:
            logger.warning(f"Timeout while creating streaming response for {url}: {e}")
            raise DownloadError(409, f"Timeout while creating streaming response for {url}: {e}")
        except httpx.HTTPStatusError as e:
            logger.error(f"HTTP error {e.response.status_code} while creating streaming response for {url} (Request URL: {e.request.url})")
            if e.response.status_code == 404:
                logger.error(f"Resource not found for streaming: {url}")
                raise e # Do not wrap 404
            raise DownloadError(
                e.response.status_code, f"HTTP error {e.response.status_code} while creating streaming response for {url}: {e}"
            )
        except httpx.RequestError as e:
            logger.error(f"Request error creating streaming response for {url}: {e}")
            raise DownloadError(502, f"Request error creating streaming response for {url}: {e}")
        except Exception as e: # Generic fallback
            logger.error(f"Unexpected error creating streaming response for {url}: {e}", exc_info=True)
            # Runtime Error might be too generic, consider if this should be a DownloadError or a more specific custom error
            raise RuntimeError(f"Unexpected error creating streaming response for {url}: {e}")


    async def stream_content(self) -> typing.AsyncGenerator[bytes, None]:
        """
        Streams the content from the response.
        """
        if not self.response:
            # This state should ideally not be reached if create_streaming_response was called and succeeded.
            logger.error("Streamer.stream_content called without a valid response object.")
            raise RuntimeError("No response available for streaming. Call create_streaming_response first.")

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

        except httpx.TimeoutException as e: # Timeout during streaming
            logger.warning(f"Timeout while streaming content from {self.response.url}: {e}")
            raise DownloadError(409, f"Timeout while streaming content: {e}")
        except httpx.RemoteProtocolError as e:
            logger.warning(f"Remote protocol error while streaming content from {self.response.url}: {e}")
            if "peer closed connection without sending complete message body" in str(e):
                if self.bytes_transferred > 0:
                    logger.info(f"Partial content received ({self.bytes_transferred} bytes) due to premature close. Continuing with available data.")
                    # The generator will simply stop yielding, effectively ending the stream.
                    # The client will receive what has been transferred so far.
                    return
                else:
                    logger.error(f"Remote server closed connection without sending any data from {self.response.url}: {e}")
                    raise DownloadError(502, f"Remote server closed connection without sending any data: {e}")
            else:
                # Other types of RemoteProtocolError
                raise DownloadError(502, f"Protocol error while streaming: {e}")
        except httpx.ReadError as e: # General read error during streaming
            logger.warning(f"Read error while streaming content from {self.response.url}: {e}")
            raise DownloadError(502, f"Read error while streaming content: {e}")
        except GeneratorExit:
            logger.info(f"Streaming session stopped by the client for {self.response.url if self.response else 'unknown URL'}")
        except Exception as e: # Fallback for other errors during streaming
            logger.error(f"Unexpected error streaming content from {self.response.url if self.response else 'unknown URL'}: {e}", exc_info=True)
            # Depending on the nature of 'e', this might need to be a DownloadError or re-raised
            raise # Re-raise the original unknown error

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
            try:
                # Example: "bytes 0-1023/2048"
                range_part, total_part = content_range.split(" ")[1].split("/")
                self.start_byte, self.end_byte = map(int, range_part.split("-"))
                self.total_size = int(total_part)
            except ValueError as e:
                logger.warning(f"Could not parse Content-Range header '{content_range}': {e}. Falling back to Content-Length.")
                self.start_byte = 0
                self.total_size = int(self.response.headers.get("Content-Length", 0))
                self.end_byte = self.total_size - 1 if self.total_size > 0 else 0
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
            # fetch_with_retry will handle retries and wrap errors appropriately
            self.response = await fetch_with_retry(self.client, "GET", url, headers)
            return self.response.text
        except tenacity.RetryError as e:
            # This means all retry attempts by fetch_with_retry failed.
            # The last attempt's exception (which would be a DownloadError or unhandled httpx.HTTPStatusError for 404)
            # is available in e.last_attempt.result()
            logger.error(f"Failed to get text from {url} after multiple retries: {e.last_attempt.exception()}")
            raise e.last_attempt.exception() # Raise the underlying error from the last attempt


    async def close(self):
        """
        Closes the HTTP client and response.
        """
        if self.response:
            await self.response.aclose()
        if self.progress_bar:
            self.progress_bar.close()
        # Client is typically managed externally (e.g., via context manager)
        # If Streamer owns the client, it should close it here.
        # await self.client.aclose() # Assuming client is passed and managed outside, or via 'async with'

async def download_file_with_retry(url: str, headers: dict):
    """
    Downloads a file with retry logic.

    Args:
        url (str): The URL of the file to download.
        headers (dict): The headers to include in the request.

    Returns:
        bytes: The downloaded file content.

    Raises:
        DownloadError: If the download fails after retries (wrapped by fetch_with_retry).
        httpx.HTTPStatusError: If a 404 error occurs and is not retried.
        tenacity.RetryError: If all retries fail, this will contain the last exception.
    """
    async with create_httpx_client() as client:
        try:
            # fetch_with_retry handles retries and error wrapping.
            # If it exhausts retries, tenacity.RetryError is raised by the decorator.
            response = await fetch_with_retry(client, "GET", url, headers)
            return response.content
        except tenacity.RetryError as e:
            # Log the final failure and re-raise the core exception from the last attempt
            logger.error(f"Failed to download file {url} after multiple retries: {e.last_attempt.exception()}")
            raise e.last_attempt.exception() # This will be DownloadError or unhandled HTTPStatusError(404)
        # Specific exceptions like DownloadError or HTTPStatusError(404) from the first attempt (if not retried)
        # or from the last attempt of a retry sequence will propagate directly if not caught by tenacity.RetryError


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
        httpx.HTTPStatusError: If a 404 error occurs and is not retried.
        tenacity.RetryError: If all retries fail.
    """
    async with create_httpx_client(**kwargs.pop("client_kwargs", {})) as client: # Allow passing client kwargs
        try:
            response = await fetch_with_retry(client, method, url, headers, **kwargs)
            return response
        except tenacity.RetryError as e:
            logger.error(f"Request {method} {url} failed after multiple retries: {e.last_attempt.exception()}")
            raise e.last_attempt.exception()


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
    dest_path = parsed_dest.path.lstrip('/')
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
        return forwarded_proto.lower() # Normalize to lowercase

    # Check if the request is secure (based on Starlette/Uvicorn interpretation)
    if request.url.scheme == "https":
        return "https"
    
    # Fallback for other common headers, ensure consistent checking
    if (
        request.headers.get("X-Forwarded-Ssl", "").lower() == "on"
        or request.headers.get("X-Forwarded-Protocol", "").lower() == "https"
        or request.headers.get("X-Url-Scheme", "").lower() == "https"
        or request.headers.get("Front-End-Https", "").lower() == "on" # Another common one
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
        ProxyRequestHeaders: A dataclass containing the request headers and response headers.
    """
    # Start with supported headers from the original request
    request_headers = {
        k.lower(): v for k, v in request.headers.items() if k.lower() in SUPPORTED_REQUEST_HEADERS
    }
    # Override or add with headers from query parameters (h_ prefix)
    request_headers.update(
        {k[2:].lower().replace("_", "-"): v for k, v in request.query_params.items() if k.startswith("h_")}
    )
    # Response headers are solely from query parameters (r_ prefix)
    response_headers = {
        k[2:].lower().replace("_", "-"): v for k, v in request.query_params.items() if k.startswith("r_")
    }
    return ProxyRequestHeaders(request=request_headers, response=response_headers)


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
        self.actual_content_length = 0 # To track bytes sent to client

    @staticmethod
    async def listen_for_disconnect(receive: Receive) -> None:
        # Renamed from listen_for_disconnect for clarity if used more broadly
        """Listens for an HTTP disconnect message."""
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                logger.debug("Client disconnected.")
                break
            # Could log other message types if needed for debugging, e.g., lifespan messages

    async def stream_response(self, send: Send) -> None:
        # Prepare headers, ensuring byte keys and values
        response_headers = []
        has_content_length = False
        for k, v in self.raw_headers:
            if k.lower() == b"content-length":
                has_content_length = True
            response_headers.append((k, v))

        # If Content-Length is present, it might conflict with chunked encoding.
        # For streaming, it's often better to use chunked encoding if the total size isn't known upfront
        # or if we want to handle premature closes from upstream more gracefully by not promising a fixed length.
        # However, some clients rely on Content-Length.
        # If Content-Length is set, and we stream, we must send exactly that many bytes.
        # If upstream closes early, and we have Content-Length, this is an issue.
        # The logic in Streamer.stream_content handles this by potentially just ending the stream.
        # Here, for EnhancedStreamingResponse, we are proxying.

        # Decision: If Content-Length is present, keep it. If not, add Transfer-Encoding: chunked.
        # This behavior is standard for FastAPI/Starlette's StreamingResponse.
        # The issue "peer closed connection without sending complete message body" is about the *upstream* connection.
        # This EnhancedStreamingResponse is about the *downstream* connection to the client.

        # Let's stick to Starlette's StreamingResponse behavior:
        # It sends Content-Length if available, otherwise Transfer-Encoding: chunked.

        await send(
            {
                "type": "http.response.start",
                "status": self.status_code,
                "headers": response_headers,
            }
        )

        data_sent_to_client = False
        try:
            async for chunk in self.body_iterator:
                if not isinstance(chunk, bytes):
                    chunk = chunk.encode(self.charset)
                
                # Guard against sending empty initial chunks if upstream provides them,
                # unless it's the *only* chunk (empty body).
                # This is more relevant if `more_body` logic is complex.
                # For now, send what we get.
                
                self.actual_content_length += len(chunk)
                await send({"type": "http.response.body", "body": chunk, "more_body": True})
                data_sent_to_client = True
            
            # After the loop, send the final empty chunk.
            await send({"type": "http.response.body", "body": b"", "more_body": False})
            logger.debug(f"Successfully streamed {self.actual_content_length} bytes to client.")

        except (anyio.BrokenResourceError, ConnectionResetError) as e:
            # Client disconnected or connection reset by client.
            logger.info(f"Client connection error during streaming: {type(e).__name__} - {e}")
            # This is not an error on our side; the client just left.
            # The `listen_for_disconnect` task_group.cancel_scope.cancel() will handle cleanup.
            # No need to try sending further messages.
            raise # Re-raise to be caught by the __call__ method's task group handling

        except Exception as e:
            # This catches errors from self.body_iterator (e.g., upstream errors propagated by Streamer)
            # or errors during send().
            logger.error(f"Error during response streaming: {type(e).__name__} - {e}", exc_info=True)
            
            # If we haven't started the response to the client, we might be able to send a 500.
            # But `http.response.start` is already sent.
            # If data has been sent, we can't change the status code.
            # The best we can do is stop sending and log. The client will experience a truncated response.
            # If no data was sent, it's still tricky. Starlette's default error handling might take over
            # if this exception propagates out of __call__, but here we are in a task.
            # For now, just re-raise. The task group will handle cancellation.
            raise # Re-raise to be caught by the __call__ method's task group handling


    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """
        ASGI application call. Manages streaming content and listening for client disconnects.
        """
        async with anyio.create_task_group() as task_group:
            
            # Flag to indicate if streaming completed successfully or was intentionally stopped
            # (e.g., by client disconnect handled gracefully by stream_response).
            self.streaming_flow_completed = False

            async def stream_task_wrapper():
                try:
                    await self.stream_response(send)
                    self.streaming_flow_completed = True # Mark as completed normally
                except (anyio.BrokenResourceError, ConnectionResetError):
                    # Client disconnected, this is expected to be handled by listen_task_wrapper's cancellation.
                    logger.info("Stream task: Client disconnected. Stream_response was interrupted.")
                    # Do not mark as completed, let listen_task_wrapper trigger cancellation.
                except Exception as e:
                    logger.error(f"Stream task: Exception during streaming: {e}", exc_info=True)
                    # An error occurred in streaming, do not mark as completed.
                    # Let listen_task_wrapper trigger cancellation if client is still there,
                    # or this might propagate if listen_task_wrapper already exited.
                    # This ensures the task group is aware of the failure.
                    raise # Re-raise to make the task group aware of the failure.
                finally:
                    # This finally block might not be strictly necessary if cancellations are handled well.
                    if not task_group.cancel_scope.cancel_called:
                         task_group.cancel_scope.cancel()


            async def listen_task_wrapper():
                try:
                    await self.listen_for_disconnect(receive)
                    # If listen_for_disconnect finishes, it means client disconnected.
                except anyio.get_cancelled_exc_class():
                    # Task was cancelled, likely because streaming finished or an error occurred.
                    pass
                except Exception as e:
                    logger.error(f"Listen task: Exception: {e}", exc_info=True)
                finally:
                    # If this task finishes (e.g., client disconnected), cancel the other tasks.
                    if not task_group.cancel_scope.cancel_called:
                        task_group.cancel_scope.cancel()
            
            task_group.start_soon(stream_task_wrapper)
            task_group.start_soon(listen_task_wrapper)

        # After task group exits (due to completion or cancellation)
        if self.background is not None:
            await self.background()