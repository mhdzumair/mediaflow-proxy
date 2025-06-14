import codecs
import re
from typing import AsyncGenerator
from urllib import parse

from mediaflow_proxy.configs import settings
from mediaflow_proxy.utils.crypto_utils import encryption_handler
from mediaflow_proxy.utils.http_utils import encode_mediaflow_proxy_url, encode_stremio_proxy_url, get_original_scheme


class M3U8Processor:
    def __init__(self, request, key_url: str = None, force_playlist_proxy: bool = None):
        """
        Initializes the M3U8Processor with the request and URL prefix.

        Args:
            request (Request): The incoming HTTP request.
            key_url (HttpUrl, optional): The URL of the key server. Defaults to None.
            force_playlist_proxy (bool, optional): Force all playlist URLs to be proxied through MediaFlow. Defaults to None.
        """
        self.request = request
        self.key_url = parse.urlparse(key_url) if key_url else None
        self.force_playlist_proxy = force_playlist_proxy
        self.mediaflow_proxy_url = str(
            request.url_for("hls_manifest_proxy").replace(scheme=get_original_scheme(request))
        )

    async def process_m3u8(self, content: str, base_url: str) -> str:
        """
        Processes the m3u8 content, proxying URLs and handling key lines.

        Args:
            content (str): The m3u8 content to process.
            base_url (str): The base URL to resolve relative URLs.

        Returns:
            str: The processed m3u8 content.
        """
        lines = content.splitlines()
        processed_lines = []
        for line in lines:
            if "URI=" in line:
                processed_lines.append(await self.process_key_line(line, base_url))
            elif not line.startswith("#") and line.strip():
                processed_lines.append(await self.proxy_content_url(line, base_url))
            else:
                processed_lines.append(line)
        return "\n".join(processed_lines)

    async def process_m3u8_streaming(
        self, content_iterator: AsyncGenerator[bytes, None], base_url: str
    ) -> AsyncGenerator[str, None]:
        """
        Processes the m3u8 content on-the-fly, yielding processed lines as they are read.

        Args:
            content_iterator: An async iterator that yields chunks of the m3u8 content.
            base_url (str): The base URL to resolve relative URLs.

        Yields:
            str: Processed lines of the m3u8 content.
        """
        buffer = ""  # String buffer for decoded content
        decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")

        # Process the content chunk by chunk
        async for chunk in content_iterator:
            if isinstance(chunk, str):
                chunk = chunk.encode("utf-8")

            # Incrementally decode the chunk
            decoded_chunk = decoder.decode(chunk)
            buffer += decoded_chunk

            # Process complete lines
            lines = buffer.split("\n")
            if len(lines) > 1:
                # Process all complete lines except the last one
                for line in lines[:-1]:
                    if line:  # Skip empty lines
                        processed_line = await self.process_line(line, base_url)
                        yield processed_line + "\n"

                # Keep the last line in the buffer (it might be incomplete)
                buffer = lines[-1]

        # Process any remaining data in the buffer plus final bytes
        final_chunk = decoder.decode(b"", final=True)
        if final_chunk:
            buffer += final_chunk

        if buffer:  # Process the last line if it's not empty
            processed_line = await self.process_line(buffer, base_url)
            yield processed_line

    async def process_line(self, line: str, base_url: str) -> str:
        """
        Process a single line from the m3u8 content.

        Args:
            line (str): The line to process.
            base_url (str): The base URL to resolve relative URLs.

        Returns:
            str: The processed line.
        """
        if "URI=" in line:
            return await self.process_key_line(line, base_url)
        elif not line.startswith("#") and line.strip():
            return await self.proxy_content_url(line, base_url)
        else:
            return line

    async def process_key_line(self, line: str, base_url: str) -> str:
        """
        Processes a key line in the m3u8 content, proxying the URI.

        Args:
            line (str): The key line to process.
            base_url (str): The base URL to resolve relative URLs.

        Returns:
            str: The processed key line.
        """
        uri_match = re.search(r'URI="([^"]+)"', line)
        if uri_match:
            original_uri = uri_match.group(1)
            uri = parse.urlparse(original_uri)
            if self.key_url:
                uri = uri._replace(scheme=self.key_url.scheme, netloc=self.key_url.netloc)
            new_uri = await self.proxy_url(uri.geturl(), base_url)
            line = line.replace(f'URI="{original_uri}"', f'URI="{new_uri}"')
        return line

    async def proxy_content_url(self, url: str, base_url: str) -> str:
        """
        Proxies a content URL based on the configured routing strategy.

        Args:
            url (str): The URL to proxy.
            base_url (str): The base URL to resolve relative URLs.

        Returns:
            str: The proxied URL.
        """
        full_url = parse.urljoin(base_url, url)

        # Determine routing strategy based on configuration
        routing_strategy = settings.m3u8_content_routing

        # Check if we should force MediaFlow proxy for all playlist URLs
        if self.force_playlist_proxy:
            return await self.proxy_url(full_url, base_url, use_full_url=True)

        # For playlist URLs, always use MediaFlow proxy regardless of strategy
        # Check for actual playlist file extensions, not just substring matches
        parsed_url = parse.urlparse(full_url)
        if (parsed_url.path.endswith((".m3u", ".m3u8", ".m3u_plus")) or
            parse.parse_qs(parsed_url.query).get("type", [""])[0] in ["m3u", "m3u8", "m3u_plus"]):
            return await self.proxy_url(full_url, base_url, use_full_url=True)

        # Route non-playlist content URLs based on strategy
        if routing_strategy == "direct":
            # Return the URL directly without any proxying
            return full_url
        elif routing_strategy == "stremio" and settings.stremio_proxy_url:
            # Use Stremio proxy for content URLs
            query_params = dict(self.request.query_params)
            request_headers = {k[2:]: v for k, v in query_params.items() if k.startswith("h_")}
            response_headers = {k[2:]: v for k, v in query_params.items() if k.startswith("r_")}

            return encode_stremio_proxy_url(
                settings.stremio_proxy_url,
                full_url,
                request_headers=request_headers if request_headers else None,
                response_headers=response_headers if response_headers else None,
            )
        else:
            # Default to MediaFlow proxy (routing_strategy == "mediaflow" or fallback)
            return await self.proxy_url(full_url, base_url, use_full_url=True)

    async def proxy_url(self, url: str, base_url: str, use_full_url: bool = False) -> str:
        """
        Proxies a URL, encoding it with the MediaFlow proxy URL.

        Args:
            url (str): The URL to proxy.
            base_url (str): The base URL to resolve relative URLs.
            use_full_url (bool): Whether to use the URL as-is (True) or join with base_url (False).

        Returns:
            str: The proxied URL.
        """
        if use_full_url:
            full_url = url
        else:
            full_url = parse.urljoin(base_url, url)

        query_params = dict(self.request.query_params)
        has_encrypted = query_params.pop("has_encrypted", False)
        # Remove the response headers from the query params to avoid it being added to the consecutive requests
        [query_params.pop(key, None) for key in list(query_params.keys()) if key.startswith("r_")]
        # Remove force_playlist_proxy to avoid it being added to subsequent requests
        query_params.pop("force_playlist_proxy", None)

        return encode_mediaflow_proxy_url(
            self.mediaflow_proxy_url,
            "",
            full_url,
            query_params=query_params,
            encryption_handler=encryption_handler if has_encrypted else None,
        )
