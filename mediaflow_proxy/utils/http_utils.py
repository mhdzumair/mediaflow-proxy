import asyncio
import logging
import typing
from dataclasses import dataclass
from functools import partial
from urllib import parse
from urllib.parse import urlencode

import aiohttp
from aiohttp import ClientSession, ClientTimeout, ClientResponse
import anyio
import tenacity
from fastapi import Response
from starlette.background import BackgroundTask
from starlette.concurrency import iterate_in_threadpool
from starlette.requests import Request
from starlette.types import Receive, Send, Scope
from tenacity import retry, stop_after_attempt, wait_exponential
from tqdm.asyncio import tqdm as tqdm_asyncio

from mediaflow_proxy.configs import settings
from mediaflow_proxy.const import SUPPORTED_REQUEST_HEADERS
from mediaflow_proxy.utils.crypto_utils import EncryptionHandler
from mediaflow_proxy.utils.stream_transformers import StreamTransformer
from mediaflow_proxy.utils.http_client import (
    create_aiohttp_session,
    get_routing_config,
    _ensure_routing_initialized,
    _create_connector,
)

logger = logging.getLogger(__name__)


class DownloadError(Exception):
    def __init__(self, status_code, message):
        self.status_code = status_code
        self.message = message
        super().__init__(message)


def retry_if_download_error_not_404(retry_state):
    """Retry on DownloadError except for 404 errors."""
    if retry_state.outcome.failed:
        exception = retry_state.outcome.exception()
        if isinstance(exception, DownloadError):
            return exception.status_code != 404
    return False


@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=4, max=10),
    retry=retry_if_download_error_not_404,
)
async def fetch_with_retry(
    session: ClientSession,
    method: str,
    url: str,
    headers: dict,
    proxy: typing.Optional[str] = None,
    **kwargs,
) -> ClientResponse:
    """
    Fetches a URL with retry logic using native aiohttp.

    Args:
        session: The aiohttp ClientSession to use for the request.
        method: The HTTP method to use (e.g., GET, POST).
        url: The URL to fetch.
        headers: The headers to include in the request.
        proxy: Optional proxy URL for HTTP proxies.
        **kwargs: Additional arguments to pass to the request.

    Returns:
        ClientResponse: The HTTP response.

    Raises:
        DownloadError: If the request fails after retries.
    """
    try:
        response = await session.request(method, url, headers=headers, proxy=proxy, **kwargs)
        response.raise_for_status()
        return response
    except asyncio.TimeoutError:
        logger.warning(f"Timeout while downloading {url}")
        raise DownloadError(409, f"Timeout while downloading {url}")
    except aiohttp.ClientResponseError as e:
        if e.status == 404:
            logger.debug(f"Segment not found (404): {url}")
            raise DownloadError(404, f"Not found (404): {url}")
        logger.error(f"HTTP error {e.status} while downloading {url}")
        raise DownloadError(e.status, f"HTTP error {e.status} while downloading {url}")
    except aiohttp.ClientError as e:
        logger.error(f"Client error downloading {url}: {e}")
        raise DownloadError(502, f"Client error downloading {url}: {e}")
    except Exception as e:
        logger.error(f"Error downloading {url}: {e}")
        raise


class Streamer:
    """Handles streaming HTTP responses using aiohttp."""

    def __init__(self, session: ClientSession, proxy_url: typing.Optional[str] = None):
        """
        Initializes the Streamer with an aiohttp session.

        Args:
            session: The aiohttp ClientSession to use for streaming.
            proxy_url: Optional proxy URL for HTTP proxies.
        """
        self.session = session
        self.proxy_url = proxy_url
        self.response: typing.Optional[ClientResponse] = None
        self.progress_bar = None
        self.bytes_transferred = 0
        self.start_byte = 0
        self.end_byte = 0
        self.total_size = 0
        # Store request details for potential retry during streaming
        self._current_url: typing.Optional[str] = None
        self._current_headers: typing.Optional[dict] = None

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=4, max=10),
        retry=retry_if_download_error_not_404,
    )
    async def create_streaming_response(self, url: str, headers: dict, method: str = "GET"):
        """
        Creates and sends a streaming request.

        Args:
            url: The URL to stream from.
            headers: The headers to include in the request.
            method: HTTP method to use (GET or HEAD). Defaults to GET.
                    For HEAD requests, will fallback to GET if server doesn't support HEAD.
        """
        # Store request details for potential retry during streaming
        self._current_url = url
        self._current_headers = headers.copy()

        try:
            if method.upper() == "HEAD":
                # Try HEAD first, fallback to GET if server doesn't support it
                try:
                    self.response = await self.session.head(url, headers=headers, proxy=self.proxy_url)
                    self.response.raise_for_status()
                except (aiohttp.ClientResponseError, aiohttp.ClientError) as head_error:
                    # HEAD failed, fallback to GET (some servers don't support HEAD)
                    logger.debug(f"HEAD request failed ({head_error}), falling back to GET")
                    self.response = await self.session.get(url, headers=headers, proxy=self.proxy_url)
                    self.response.raise_for_status()
            else:
                self.response = await self.session.get(url, headers=headers, proxy=self.proxy_url)
                self.response.raise_for_status()
        except asyncio.TimeoutError:
            logger.warning("Timeout while creating streaming response")
            raise DownloadError(409, "Timeout while creating streaming response")
        except aiohttp.ClientResponseError as e:
            if e.status == 404:
                logger.debug(f"Segment not found (404): {url}")
                raise DownloadError(404, f"Not found (404): {url}")
            # Don't retry rate-limit errors (429, 509) - retrying while other connections
            # are still active just wastes time. Let the player handle its own retry logic.
            if e.status in (429, 509):
                logger.warning(f"Rate limited ({e.status}) by upstream: {url}")
                raise aiohttp.ClientResponseError(e.request_info, e.history, status=e.status, message=e.message)
            logger.error(f"HTTP error {e.status} while creating streaming response")
            raise DownloadError(e.status, f"HTTP error {e.status} while creating streaming response")
        except aiohttp.ClientError as e:
            logger.error(f"Error creating streaming response: {e}")
            raise DownloadError(502, f"Error creating streaming response: {e}")
        except Exception as e:
            logger.error(f"Error creating streaming response: {e}")
            raise RuntimeError(f"Error creating streaming response: {e}")

    async def _retry_connection(self, from_byte: int) -> bool:
        """
        Attempt to reconnect to the upstream using Range header.

        Args:
            from_byte: The byte position to resume from.

        Returns:
            bool: True if reconnection was successful, False otherwise.
        """
        if not self._current_url or not self._current_headers:
            return False

        # Close existing response if any
        if self.response:
            self.response.close()
            self.response = None

        # Create new headers with Range
        retry_headers = self._current_headers.copy()
        if self.total_size > 0:
            retry_headers["Range"] = f"bytes={from_byte}-{self.total_size - 1}"
        else:
            retry_headers["Range"] = f"bytes={from_byte}-"

        try:
            self.response = await self.session.get(self._current_url, headers=retry_headers, proxy=self.proxy_url)
            # Accept both 200 and 206 (Partial Content) as valid responses
            if self.response.status in (200, 206):
                logger.info(f"Successfully reconnected at byte {from_byte}")
                return True
            else:
                logger.warning(f"Retry connection returned unexpected status: {self.response.status}")
                return False
        except Exception as e:
            logger.warning(f"Failed to reconnect: {e}")
            return False

    async def stream_content(
        self, transformer: typing.Optional[StreamTransformer] = None
    ) -> typing.AsyncGenerator[bytes, None]:
        """
        Stream content from the response, optionally applying a transformer.

        Includes automatic retry logic when upstream disconnects mid-stream,
        using Range headers to resume from the last successful byte.

        Args:
            transformer: Optional StreamTransformer to apply host-specific
                        content manipulation (e.g., PNG stripping, TS detection).
                        If None, content is streamed directly without modification.

        Yields:
            Bytes chunks from the upstream response.
        """
        if not self.response:
            raise RuntimeError("No response available for streaming")

        retry_count = 0
        max_retries = settings.upstream_retry_attempts if settings.upstream_retry_on_disconnect else 0

        while True:
            try:
                self.parse_content_range()

                # Create async generator from response content
                async def raw_chunks():
                    async for chunk in self.response.content.iter_any():
                        yield chunk

                # Choose the chunk source based on whether we have a transformer
                # Note: Transformer state may not survive reconnection properly for all transformers
                if transformer and retry_count == 0:
                    chunk_source = transformer.transform(raw_chunks())
                else:
                    chunk_source = raw_chunks()

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
                        async for chunk in chunk_source:
                            yield chunk
                            self.bytes_transferred += len(chunk)
                            self.progress_bar.update(len(chunk))
                else:
                    async for chunk in chunk_source:
                        yield chunk
                        self.bytes_transferred += len(chunk)

                # Successfully completed streaming
                return

            except asyncio.TimeoutError:
                logger.warning("Timeout while streaming")
                raise DownloadError(409, "Timeout while streaming")
            except (aiohttp.ServerDisconnectedError, aiohttp.ClientPayloadError, aiohttp.ClientError) as e:
                # Handle connection errors with potential retry
                error_type = type(e).__name__
                logger.warning(f"{error_type} while streaming after {self.bytes_transferred} bytes: {e}")

                # Check if we should retry
                if retry_count < max_retries and self.bytes_transferred > 0:
                    retry_count += 1
                    resume_from = self.start_byte + self.bytes_transferred
                    logger.info(f"Attempting reconnection (retry {retry_count}/{max_retries}) from byte {resume_from}")

                    # Wait before retry
                    await asyncio.sleep(settings.upstream_retry_delay)

                    if await self._retry_connection(resume_from):
                        # Successfully reconnected, continue the loop to resume streaming
                        continue
                    else:
                        logger.warning(f"Reconnection failed on retry {retry_count}")

                # No more retries or reconnection failed
                if self.bytes_transferred > 0:
                    logger.info(
                        f"Partial content received ({self.bytes_transferred} bytes). "
                        f"Graceful termination after {retry_count} retry attempts."
                    )
                    return
                else:
                    raise DownloadError(502, f"{error_type} while streaming: {e}")
            except GeneratorExit:
                logger.info("Streaming session stopped by the user")
                return

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

    async def get_text(self, url: str, headers: dict) -> str:
        """
        Sends a GET request to a URL and returns the response text.

        Args:
            url: The URL to send the GET request to.
            headers: The headers to include in the request.

        Returns:
            str: The response text.
        """
        try:
            self.response = await fetch_with_retry(self.session, "GET", url, headers, proxy=self.proxy_url)
            return await self.response.text()
        except tenacity.RetryError as e:
            raise e.last_attempt.result()

    async def close(self):
        """
        Closes the HTTP response and session.
        """
        if self.response:
            self.response.close()
        if self.progress_bar:
            self.progress_bar.close()
        await self.session.close()


async def download_file_with_retry(url: str, headers: dict) -> bytes:
    """
    Downloads a file with retry logic.

    Args:
        url: The URL of the file to download.
        headers: The headers to include in the request.

    Returns:
        bytes: The downloaded file content.

    Raises:
        DownloadError: If the download fails after retries.
    """
    async with create_aiohttp_session(url) as (session, proxy_url):
        try:
            response = await fetch_with_retry(session, "GET", url, headers, proxy=proxy_url)
            return await response.read()
        except DownloadError as e:
            logger.error(f"Failed to download file: {e}")
            raise e
        except tenacity.RetryError as e:
            raise DownloadError(502, f"Failed to download file: {e.last_attempt.result()}")


async def request_with_retry(method: str, url: str, headers: dict, **kwargs) -> ClientResponse:
    """
    Sends an HTTP request with retry logic.

    Args:
        method: The HTTP method to use (e.g., GET, POST).
        url: The URL to send the request to.
        headers: The headers to include in the request.
        **kwargs: Additional arguments to pass to the request.

    Returns:
        ClientResponse: The HTTP response.

    Raises:
        DownloadError: If the request fails after retries.
    """
    async with create_aiohttp_session(url) as (session, proxy_url):
        try:
            response = await fetch_with_retry(session, method, url, headers, proxy=proxy_url, **kwargs)
            # Read the content so it's available after session closes
            await response.read()
            return response
        except DownloadError as e:
            logger.error(f"Failed to make request: {e}")
            raise


async def create_streamer(url: str = None) -> Streamer:
    """
    Create a Streamer configured for the given URL.

    The Streamer manages its own session lifecycle. Call streamer.close()
    when done to release resources.

    Args:
        url: Optional URL for routing configuration (SSL/proxy settings).

    Returns:
        Streamer: A configured Streamer instance.
    """
    _ensure_routing_initialized()

    routing_config = get_routing_config()
    route_match = routing_config.match_url(url)

    # Use sock_read timeout: no total timeout, but timeout if no data received
    # for sock_read seconds. This correctly handles:
    # - Live streams (indefinite duration)
    # - Large file downloads (total time depends on file size)
    # - Seek operations (upstream may take time to seek)
    # - Dead connection detection (timeout if no data flows)
    timeout_config = ClientTimeout(
        total=None,
        sock_read=settings.transport_config.timeout,
    )

    connector, proxy_url = _create_connector(route_match.proxy_url, route_match.verify_ssl)

    session = ClientSession(connector=connector, timeout=timeout_config)
    return Streamer(session, proxy_url)


# Keep setup_streamer as alias for backward compatibility during transition
async def setup_streamer(url: str = None) -> typing.Tuple[ClientSession, str, Streamer]:
    """
    Set up an aiohttp session and streamer.

    DEPRECATED: Use create_streamer() instead which returns only the Streamer.

    Args:
        url: Optional URL for routing configuration.

    Returns:
        Tuple of (session, proxy_url, streamer)
    """
    streamer = await create_streamer(url)
    return streamer.session, streamer.proxy_url, streamer


def encode_mediaflow_proxy_url(
    mediaflow_proxy_url: str,
    endpoint: typing.Optional[str] = None,
    destination_url: typing.Optional[str] = None,
    query_params: typing.Optional[dict] = None,
    request_headers: typing.Optional[dict] = None,
    response_headers: typing.Optional[dict] = None,
    propagate_response_headers: typing.Optional[dict] = None,
    remove_response_headers: typing.Optional[list[str]] = None,
    encryption_handler: EncryptionHandler = None,
    expiration: int = None,
    ip: str = None,
    filename: typing.Optional[str] = None,
    stream_transformer: typing.Optional[str] = None,
) -> str:
    """
    Encodes & Encrypt (Optional) a MediaFlow proxy URL with query parameters and headers.

    Args:
        mediaflow_proxy_url: The base MediaFlow proxy URL.
        endpoint: The endpoint to append to the base URL. Defaults to None.
        destination_url: The destination URL to include in the query parameters. Defaults to None.
        query_params: Additional query parameters to include. Defaults to None.
        request_headers: Headers to include as query parameters. Defaults to None.
        response_headers: Headers to include as query parameters (r_ prefix). Defaults to None.
        propagate_response_headers: Response headers that propagate to segments (rp_ prefix). Defaults to None.
        remove_response_headers: List of response header names to remove. Defaults to None.
        encryption_handler: The encryption handler to use. Defaults to None.
        expiration: The expiration time for the encrypted token. Defaults to None.
        ip: The public IP address to include in the query parameters. Defaults to None.
        filename: Filename to be preserved for media players like Infuse. Defaults to None.
        stream_transformer: ID of the stream transformer to apply. Defaults to None.

    Returns:
        str: The encoded MediaFlow proxy URL.
    """
    # Prepare query parameters
    query_params = query_params or {}
    if destination_url is not None:
        query_params["d"] = destination_url

    # Add headers if provided (always use lowercase prefix for consistency)
    # Filter out empty values to avoid URLs like &h_if-range=&h_referer=...
    # Also exclude dynamic per-request headers (range, if-range) that are already handled
    # via SUPPORTED_REQUEST_HEADERS from the player's actual request. Encoding them as h_
    # query params would bake in stale values that override the player's real headers on
    # subsequent requests (e.g., when seeking to a different position).
    if request_headers:
        query_params.update(
            {
                key if key.lower().startswith("h_") else f"h_{key}": value
                for key, value in request_headers.items()
                if value and (key.lower().removeprefix("h_") not in SUPPORTED_REQUEST_HEADERS)
            }
        )
    if response_headers:
        query_params.update(
            {
                key if key.lower().startswith("r_") else f"r_{key}": value
                for key, value in response_headers.items()
                if value  # Skip empty/None values
            }
        )
    # Add propagate response headers (rp_ prefix - these propagate to segments)
    if propagate_response_headers:
        query_params.update(
            {
                key if key.lower().startswith("rp_") else f"rp_{key}": value
                for key, value in propagate_response_headers.items()
                if value  # Skip empty/None values
            }
        )

    # Add remove headers if provided (x_ prefix for "exclude")
    if remove_response_headers:
        query_params["x_headers"] = ",".join(remove_response_headers)

    # Add stream transformer if provided
    if stream_transformer:
        query_params["transformer"] = stream_transformer

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
        stremio_proxy_url: The base Stremio proxy URL.
        destination_url: The destination URL to proxy.
        request_headers: Headers to include as query parameters. Defaults to None.
        response_headers: Response headers to include as query parameters. Defaults to None.

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
        request: The incoming HTTP request.

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
    remove: list  # headers to remove from response
    propagate: dict  # response headers to propagate to segments (rp_ prefix)


def apply_header_manipulation(
    base_headers: dict, proxy_headers: ProxyRequestHeaders, include_propagate: bool = True
) -> dict:
    """
    Apply response header additions and removals.

    This function filters out headers specified in proxy_headers.remove,
    then merges in headers from proxy_headers.response and optionally proxy_headers.propagate.

    Args:
        base_headers: The base headers to start with.
        proxy_headers: The proxy headers containing response additions and removals.
        include_propagate: Whether to include propagate headers (rp_).
                          Set to False for manifests, True for segments. Defaults to True.

    Returns:
        dict: The manipulated headers.
    """
    remove_set = set(h.lower() for h in proxy_headers.remove)
    result = {k: v for k, v in base_headers.items() if k.lower() not in remove_set}
    # Apply propagate headers first (for segments), then response headers (response takes precedence)
    if include_propagate:
        result.update(proxy_headers.propagate)
    result.update(proxy_headers.response)
    return result


def get_proxy_headers(request: Request) -> ProxyRequestHeaders:
    """
    Extracts proxy headers from the request query parameters.

    Args:
        request: The incoming HTTP request.

    Returns:
        ProxyRequest: A named tuple containing the request headers, response headers, and headers to remove.
    """
    request_headers = {k: v for k, v in request.headers.items() if k in SUPPORTED_REQUEST_HEADERS and v}

    # Extract h_ prefixed headers from query params, filtering out empty values
    for k, v in request.query_params.items():
        if k.lower().startswith("h_") and v:  # Skip empty values
            request_headers[k[2:].lower()] = v

    request_headers.setdefault("user-agent", settings.user_agent)

    # Handle common misspelling of referer
    if "referrer" in request_headers:
        if "referer" not in request_headers:
            request_headers["referer"] = request_headers.pop("referrer")

    # r_ prefix: response headers (manifest only, not propagated to segments)
    # Filter out empty values
    response_headers = {
        k[2:].lower(): v
        for k, v in request.query_params.items()
        if k.lower().startswith("r_") and not k.lower().startswith("rp_") and v
    }

    # rp_ prefix: response headers that propagate to segments
    # Filter out empty values
    propagate_headers = {k[3:].lower(): v for k, v in request.query_params.items() if k.lower().startswith("rp_") and v}

    for k, v in propagate_headers.items():
        if k not in request_headers:
            request_headers[k] = v

    # Parse headers to remove from response (x_headers parameter)
    x_headers_param = request.query_params.get("x_headers", "")
    remove_headers = [h.strip().lower() for h in x_headers_param.split(",") if h.strip()] if x_headers_param else []

    return ProxyRequestHeaders(request_headers, response_headers, remove_headers, propagate_headers)


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
        # Track if response headers have been sent to prevent duplicate headers
        response_started = False
        # Track if response finalization (more_body: False) has been sent to prevent ASGI protocol violation
        finalization_sent = False
        try:
            # Initialize headers
            headers = list(self.raw_headers)

            # Start the response
            await send(
                {
                    "type": "http.response.start",
                    "status": self.status_code,
                    "headers": headers,
                }
            )
            response_started = True

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
                finalization_sent = True
            except (aiohttp.ServerDisconnectedError, aiohttp.ClientPayloadError, aiohttp.ClientError) as e:
                # Handle connection closed / read errors gracefully
                if data_sent:
                    # We've sent some data to the client. With Content-Length set, we cannot
                    # gracefully finalize a partial response - h11 will raise LocalProtocolError
                    # if we try to send more_body: False without delivering all promised bytes.
                    # The best we can do is log and return silently, letting the client handle
                    # the incomplete response (most players will just stop or retry).
                    logger.warning(
                        f"Upstream connection error after partial streaming ({self.actual_content_length} bytes transferred): {e}"
                    )
                    # Don't try to finalize - just return and let the connection close naturally
                    return
                else:
                    # No data was sent, re-raise the error
                    logger.error(f"Upstream error before any data was streamed: {e}")
                    raise
        except Exception as e:
            logger.exception(f"Error in stream_response: {str(e)}")
            if not isinstance(e, (ConnectionResetError, anyio.BrokenResourceError)) and not response_started:
                # Only attempt to send error response if headers haven't been sent yet
                try:
                    await send(
                        {
                            "type": "http.response.start",
                            "status": 502,
                            "headers": [(b"content-type", b"text/plain")],
                        }
                    )
                    error_message = f"Streaming error: {str(e)}".encode("utf-8")
                    await send({"type": "http.response.body", "body": error_message, "more_body": False})
                    finalization_sent = True
                except Exception:
                    # If we can't send an error response, just log it
                    pass
            elif response_started and not finalization_sent and not data_sent:
                # Response started but no data sent yet - we can safely finalize
                # (If data was sent with Content-Length, we can't finalize without h11 error)
                try:
                    await send({"type": "http.response.body", "body": b"", "more_body": False})
                    finalization_sent = True
                except Exception:
                    pass
            # If data was sent but streaming failed, just return silently
            # The client will see an incomplete response which is unavoidable with Content-Length

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        async with anyio.create_task_group() as task_group:
            stream_func = partial(self.stream_response, send)
            listen_func = partial(self.listen_for_disconnect, receive)

            async def wrap(func: typing.Callable[[], typing.Awaitable[None]]) -> None:
                try:
                    await func()
                except Exception as e:
                    # Note: stream_response and listen_for_disconnect handle their own exceptions
                    # internally. This is a safety net for any unexpected exceptions that might
                    # escape due to future code changes.
                    if not isinstance(e, anyio.get_cancelled_exc_class()):
                        logger.exception(f"Unexpected error in streaming task: {type(e).__name__}: {e}")
                        # Re-raise unexpected errors to surface bugs rather than silently swallowing them
                        raise
                finally:
                    # Cancel task group when either task completes or fails:
                    # - stream_func finished (success or failure) -> stop listening for disconnect
                    # - listen_func finished (client disconnected) -> stop streaming
                    task_group.cancel_scope.cancel()

            # Start the streaming response in a separate task
            task_group.start_soon(wrap, stream_func)
            # Listen for disconnect events
            await wrap(listen_func)

        if self.background is not None:
            await self.background()
