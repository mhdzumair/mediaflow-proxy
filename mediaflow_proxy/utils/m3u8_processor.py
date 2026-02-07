import asyncio
import codecs
import logging
import re
from typing import AsyncGenerator, List, Optional

from urllib import parse

from mediaflow_proxy.configs import settings
from mediaflow_proxy.utils.crypto_utils import encryption_handler
from mediaflow_proxy.utils.http_utils import encode_mediaflow_proxy_url, encode_stremio_proxy_url, get_original_scheme
from mediaflow_proxy.utils.hls_prebuffer import hls_prebuffer

logger = logging.getLogger(__name__)


def generate_graceful_end_playlist(message: str = "Stream ended") -> str:
    """
    Generate a minimal valid m3u8 playlist that signals stream end.

    This is used when upstream fails but we want to provide a graceful
    end to the player instead of an abrupt error. Most players will
    interpret this as the stream ending normally.

    Args:
        message: Optional message to include as a comment.

    Returns:
        str: A valid m3u8 playlist string with EXT-X-ENDLIST.
    """
    return f"""#EXTM3U
#EXT-X-VERSION:3
#EXT-X-TARGETDURATION:1
#EXT-X-PLAYLIST-TYPE:VOD
# {message}
#EXT-X-ENDLIST
"""


def generate_error_playlist(error_message: str = "Stream unavailable") -> str:
    """
    Generate a minimal valid m3u8 playlist for error scenarios.

    Unlike generate_graceful_end_playlist, this includes a very short
    segment duration to signal something went wrong while still being
    a valid playlist that players can parse.

    Args:
        error_message: Error message to include as a comment.

    Returns:
        str: A valid m3u8 playlist string.
    """
    return f"""#EXTM3U
#EXT-X-VERSION:3
#EXT-X-TARGETDURATION:1
#EXT-X-PLAYLIST-TYPE:VOD
# Error: {error_message}
#EXT-X-ENDLIST
"""


class SkipSegmentFilter:
    """
    Helper class to filter HLS segments based on time ranges.

    Tracks cumulative playback time and determines which segments
    should be skipped based on the provided skip segment list.
    """

    def __init__(self, skip_segments: Optional[List[dict]] = None):
        """
        Initialize the skip segment filter.

        Args:
            skip_segments: List of skip segment dicts with 'start' and 'end' keys.
        """
        self.skip_segments = skip_segments or []
        self.current_time = 0.0  # Cumulative playback time in seconds

    def should_skip_segment(self, duration: float) -> bool:
        """
        Determine if the current segment should be skipped.

        Args:
            duration: Duration of the current segment in seconds.

        Returns:
            True if the segment overlaps with any skip range, False otherwise.
        """
        segment_start = self.current_time
        segment_end = self.current_time + duration

        # Check if this segment overlaps with any skip range
        for skip in self.skip_segments:
            skip_start = skip.get("start", 0)
            skip_end = skip.get("end", 0)

            # Check for overlap: segment overlaps if it starts before skip ends AND ends after skip starts
            if segment_start < skip_end and segment_end > skip_start:
                logger.debug(
                    f"Skipping segment at {segment_start:.2f}s-{segment_end:.2f}s "
                    f"(overlaps with skip range {skip_start:.2f}s-{skip_end:.2f}s)"
                )
                return True

        return False

    def advance_time(self, duration: float):
        """Advance the cumulative playback time."""
        self.current_time += duration

    def has_skip_segments(self) -> bool:
        """Check if there are any skip segments configured."""
        return bool(self.skip_segments)


class M3U8Processor:
    def __init__(
        self,
        request,
        key_url: str = None,
        force_playlist_proxy: bool = None,
        key_only_proxy: bool = False,
        no_proxy: bool = False,
        skip_segments: Optional[List[dict]] = None,
        start_offset: Optional[float] = None,
    ):
        """
        Initializes the M3U8Processor with the request and URL prefix.

        Args:
            request (Request): The incoming HTTP request.
            key_url (HttpUrl, optional): The URL of the key server. Defaults to None.
            force_playlist_proxy (bool, optional): Force all playlist URLs to be proxied through MediaFlow. Defaults to None.
            key_only_proxy (bool, optional): Only proxy the key URL, leaving segment URLs direct. Defaults to False.
            no_proxy (bool, optional): If True, returns the manifest without proxying any URLs. Defaults to False.
            skip_segments (List[dict], optional): List of time segments to skip. Each dict should have
                                                  'start', 'end' (in seconds), and optionally 'type'.
            start_offset (float, optional): Time offset in seconds for EXT-X-START tag. Use negative values
                                           for live streams to start behind the live edge.
        """
        self.request = request
        self.key_url = parse.urlparse(key_url) if key_url else None
        self.key_only_proxy = key_only_proxy
        self.no_proxy = no_proxy
        self.force_playlist_proxy = force_playlist_proxy
        self.skip_filter = SkipSegmentFilter(skip_segments)
        # Track if user explicitly provided start_offset (vs using default)
        self._user_provided_start_offset = start_offset is not None
        # Store the explicit value or default (will be applied conditionally for live streams)
        self._start_offset_value = start_offset if start_offset is not None else settings.livestream_start_offset
        self.mediaflow_proxy_url = str(
            request.url_for("hls_manifest_proxy").replace(scheme=get_original_scheme(request))
        )
        # Base URL for segment proxy - extension will be appended based on actual segment
        # url_for with path param returns URL with placeholder, so we build it manually
        self.segment_proxy_base_url = str(
            request.url_for("hls_manifest_proxy").replace(scheme=get_original_scheme(request))
        ).replace("/hls/manifest.m3u8", "/hls/segment")
        self.playlist_url = None  # Will be set when processing starts

    def _should_apply_start_offset(self, content: str) -> bool:
        """
        Determine if start_offset should be applied to this playlist.

        Args:
            content: The playlist content to check.

        Returns:
            True if start_offset should be applied, False otherwise.
        """
        if self._start_offset_value is None:
            return False

        # If user explicitly provided start_offset, always use it
        if self._user_provided_start_offset:
            return True

        # Using default from settings - only apply for live streams
        # VOD playlists have #EXT-X-ENDLIST tag or #EXT-X-PLAYLIST-TYPE:VOD
        # Also skip master playlists (they have #EXT-X-STREAM-INF)
        is_vod = "#EXT-X-ENDLIST" in content or "#EXT-X-PLAYLIST-TYPE:VOD" in content
        is_master = "#EXT-X-STREAM-INF" in content

        return not is_vod and not is_master

    async def process_m3u8(self, content: str, base_url: str) -> str:
        """
        Processes the m3u8 content, proxying URLs and handling key lines.

        For content filtering with skip_segments, this follows the IntroHater approach:
        - Segments within skip ranges are completely removed (EXTINF + URL)
        - A #EXT-X-DISCONTINUITY marker is added BEFORE the URL of the first segment
          after a skipped section (not before the EXTINF)

        Args:
            content (str): The m3u8 content to process.
            base_url (str): The base URL to resolve relative URLs.

        Returns:
            str: The processed m3u8 content.
        """
        # Store the playlist URL for prebuffering
        self.playlist_url = base_url

        lines = content.splitlines()
        processed_lines = []

        # Track if we need to add discontinuity before next URL (after skipping segments)
        discontinuity_pending = False
        # Buffer the current EXTINF line - only output when we output the URL
        pending_extinf: Optional[str] = None
        # Track if we've injected EXT-X-START tag
        start_offset_injected = False
        # Determine if we should apply start_offset (checks if live stream)
        apply_start_offset = self._should_apply_start_offset(content)

        i = 0
        while i < len(lines):
            line = lines[i]

            # Inject EXT-X-START tag right after #EXTM3U (only for live streams or if user explicitly requested)
            if line.strip() == "#EXTM3U" and apply_start_offset and not start_offset_injected:
                processed_lines.append(line)
                processed_lines.append(f"#EXT-X-START:TIME-OFFSET={self._start_offset_value:.1f},PRECISE=YES")
                start_offset_injected = True
                i += 1
                continue

            # Handle EXTINF lines (segment duration markers)
            if line.startswith("#EXTINF:"):
                duration = self._parse_extinf_duration(line)

                if self.skip_filter.has_skip_segments() and self.skip_filter.should_skip_segment(duration):
                    # Skip this segment entirely - don't buffer the EXTINF
                    discontinuity_pending = True  # Mark that we need discontinuity before next kept segment
                    self.skip_filter.advance_time(duration)
                    pending_extinf = None
                    i += 1
                    continue
                else:
                    # Keep this segment
                    self.skip_filter.advance_time(duration)
                    pending_extinf = line
                    i += 1
                    continue

            # Handle segment URLs (non-comment, non-empty lines)
            if not line.startswith("#") and line.strip():
                if pending_extinf is None:
                    # No pending EXTINF means this segment was skipped
                    i += 1
                    continue

                # Add discontinuity BEFORE the EXTINF if we just skipped segments
                # Per HLS spec, EXT-X-DISCONTINUITY must appear before the first segment of the new content
                if discontinuity_pending:
                    processed_lines.append("#EXT-X-DISCONTINUITY")
                    discontinuity_pending = False

                # Output the buffered EXTINF and proxied URL
                processed_lines.append(pending_extinf)
                processed_lines.append(await self.proxy_content_url(line, base_url))
                pending_extinf = None
                i += 1
                continue

            # Handle existing discontinuity markers - pass through but reset pending flag
            if line.startswith("#EXT-X-DISCONTINUITY"):
                processed_lines.append(line)
                discontinuity_pending = False  # Don't add duplicate
                i += 1
                continue

            # Handle key lines
            if "URI=" in line:
                processed_lines.append(await self.process_key_line(line, base_url))
                i += 1
                continue

            # All other lines (headers, comments, etc.)
            processed_lines.append(line)
            i += 1

        # Log skip statistics
        if self.skip_filter.has_skip_segments():
            logger.info(f"Content filtering: processed playlist with {len(self.skip_filter.skip_segments)} skip ranges")

        # Register playlist with the priority-based prefetcher
        if settings.enable_hls_prebuffer and "#EXTM3U" in content and self.playlist_url:
            # Skip master playlists
            if "#EXT-X-STREAM-INF" not in content:
                segment_urls = self._extract_segment_urls_from_content(content, self.playlist_url)

                if segment_urls:
                    headers = {}
                    for key, value in self.request.query_params.items():
                        if key.startswith("h_"):
                            headers[key[2:]] = value

                    logger.info(
                        f"[M3U8Processor] Registering playlist ({len(segment_urls)} segments): {self.playlist_url}"
                    )
                    asyncio.create_task(
                        hls_prebuffer.register_playlist(
                            self.playlist_url,
                            segment_urls,
                            headers,
                        )
                    )

        return "\n".join(processed_lines)

    def _parse_extinf_duration(self, line: str) -> float:
        """
        Parse the duration from an #EXTINF line.

        Args:
            line: The #EXTINF line (e.g., "#EXTINF:10.0," or "#EXTINF:10,title")

        Returns:
            The duration in seconds as a float.
        """
        # Format: #EXTINF:<duration>[,<title>]
        match = re.match(r"#EXTINF:(\d+(?:\.\d+)?)", line)
        if match:
            return float(match.group(1))
        return 0.0

    async def process_m3u8_streaming(
        self, content_iterator: AsyncGenerator[bytes, None], base_url: str
    ) -> AsyncGenerator[str, None]:
        """
        Processes the m3u8 content on-the-fly, yielding processed lines as they are read.
        Optimized to avoid accumulating the entire playlist content in memory.

        Note: When skip_segments are configured, this method buffers lines to properly
        handle EXTINF + segment URL pairs that need to be skipped together.

        Args:
            content_iterator: An async iterator that yields chunks of the m3u8 content.
            base_url (str): The base URL to resolve relative URLs.

        Yields:
            str: Processed lines of the m3u8 content.

        Raises:
            ValueError: If the content is not a valid m3u8 playlist (e.g., HTML error page).
        """
        # Store the playlist URL for prebuffering
        self.playlist_url = base_url

        buffer = ""  # String buffer for decoded content
        raw_content = ""  # Accumulate raw content for prebuffer
        decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
        is_playlist_detected = False
        is_html_detected = False
        initial_check_done = False

        # State for skip segment filtering
        discontinuity_pending = False  # Track if we need discontinuity before next URL
        pending_extinf = None  # Buffer EXTINF line until we decide to emit it
        # Track if we've injected EXT-X-START tag
        start_offset_injected = False
        # Buffer header lines until we know if it's a master playlist (for default start_offset)
        header_buffer = []
        header_flushed = False

        # Process the content chunk by chunk
        async for chunk in content_iterator:
            if isinstance(chunk, str):
                chunk = chunk.encode("utf-8")

            # Incrementally decode the chunk
            decoded_chunk = decoder.decode(chunk)
            buffer += decoded_chunk
            raw_content += decoded_chunk  # Accumulate for prebuffer

            # Early detection: check if this is HTML instead of m3u8
            # This helps catch upstream error pages quickly
            if not initial_check_done and len(buffer) > 50:
                initial_check_done = True
                buffer_lower = buffer.lower().strip()
                # Check for HTML markers
                if buffer_lower.startswith("<!doctype") or buffer_lower.startswith("<html"):
                    is_html_detected = True
                    logger.error(f"Upstream returned HTML instead of m3u8 playlist: {base_url}")
                    # Raise an error so the HTTP handler returns a proper error response
                    # This allows the player to retry or show an error instead of thinking
                    # the stream has ended normally
                    raise ValueError(
                        f"Upstream returned HTML instead of m3u8 playlist. "
                        f"The stream may be offline or unavailable: {base_url}"
                    )

            # Check for playlist marker early to avoid accumulating content
            if not is_playlist_detected and "#EXTM3U" in buffer:
                is_playlist_detected = True

            # Process complete lines
            lines = buffer.split("\n")
            if len(lines) > 1:
                # Process all complete lines except the last one
                for line in lines[:-1]:
                    if not line:  # Skip empty lines
                        continue

                    # Buffer header lines until we can determine playlist type
                    # This allows us to decide whether to inject EXT-X-START
                    if not header_flushed:
                        # Always buffer the current line first
                        header_buffer.append(line)

                        # Check if we can now determine playlist type
                        # Only check the current line, not raw_content (which may contain future content)
                        is_master = "#EXT-X-STREAM-INF" in line
                        is_media = "#EXTINF" in line

                        if is_master or is_media:
                            # For non-user-provided (default) start_offset, determine if this
                            # is a live stream before injecting. We need to avoid injecting
                            # EXT-X-START with negative offsets into VOD playlists, as players
                            # like VLC interpret negative offsets as "from the end" and start
                            # playing near the end of the video.
                            #
                            # Live stream indicators (checked in header):
                            # - No #EXT-X-PLAYLIST-TYPE:VOD tag
                            # - No #EXT-X-ENDLIST tag (may not be visible yet in streaming)
                            # - #EXT-X-MEDIA-SEQUENCE > 0 (live windows have rolling sequence)
                            #
                            # VOD indicators:
                            # - #EXT-X-PLAYLIST-TYPE:VOD in header
                            # - #EXT-X-ENDLIST in raw_content (if small enough to be buffered)
                            # - #EXT-X-MEDIA-SEQUENCE:0 or absent (VOD starts from beginning)
                            header_content = "\n".join(header_buffer)
                            all_content = header_content + "\n" + raw_content

                            is_explicitly_vod = (
                                "#EXT-X-PLAYLIST-TYPE:VOD" in all_content or "#EXT-X-ENDLIST" in all_content
                            )

                            # Check for live stream indicator: #EXT-X-MEDIA-SEQUENCE with value > 0
                            # Live streams have a rolling window so their media sequence increments
                            is_likely_live = False
                            seq_match = re.search(r"#EXT-X-MEDIA-SEQUENCE:\s*(\d+)", all_content)
                            if seq_match and int(seq_match.group(1)) > 0:
                                is_likely_live = True

                            # Flush header buffer with or without EXT-X-START
                            should_inject = (
                                self._start_offset_value is not None
                                and not is_master
                                and (
                                    self._user_provided_start_offset
                                    or (is_media and not is_explicitly_vod and is_likely_live)
                                )  # User provided OR it's a live media playlist
                            )

                            for header_line in header_buffer:
                                # Process header lines to rewrite URLs (e.g., #EXT-X-KEY)
                                processed_header_line = await self.process_line(header_line, base_url)
                                yield processed_header_line + "\n"
                                if header_line.strip() == "#EXTM3U" and should_inject and not start_offset_injected:
                                    yield f"#EXT-X-START:TIME-OFFSET={self._start_offset_value:.1f},PRECISE=YES\n"
                                    start_offset_injected = True

                            header_buffer = []
                            header_flushed = True
                        # If not master/media yet, continue buffering (line already added above)
                        continue

                    # If user explicitly provided start_offset and we haven't injected yet
                    # (handles edge case where we flush header before seeing EXTINF/STREAM-INF)
                    if (
                        line.strip() == "#EXTM3U"
                        and self._user_provided_start_offset
                        and self._start_offset_value is not None
                        and not start_offset_injected
                    ):
                        yield line + "\n"
                        yield f"#EXT-X-START:TIME-OFFSET={self._start_offset_value:.1f},PRECISE=YES\n"
                        start_offset_injected = True
                        continue

                    # Handle segment filtering if skip_segments are configured
                    if self.skip_filter.has_skip_segments():
                        result = await self._process_line_with_filtering(
                            line, base_url, discontinuity_pending, pending_extinf
                        )
                        processed_line, discontinuity_pending, pending_extinf = result
                        if processed_line is not None:
                            yield processed_line + "\n"
                    else:
                        # No filtering, process normally
                        processed_line = await self.process_line(line, base_url)
                        yield processed_line + "\n"

                # Keep the last line in the buffer (it might be incomplete)
                buffer = lines[-1]

        # If HTML was detected, we already returned an error playlist
        if is_html_detected:
            return

        # Flush any remaining header buffer (for short playlists or edge cases)
        # At this point we have the full raw_content so we can make a definitive determination
        if header_buffer and not header_flushed:
            is_master = "#EXT-X-STREAM-INF" in raw_content
            is_vod = "#EXT-X-ENDLIST" in raw_content or "#EXT-X-PLAYLIST-TYPE:VOD" in raw_content
            # For default offset, also require positive live indicator
            is_likely_live = False
            seq_match = re.search(r"#EXT-X-MEDIA-SEQUENCE:\s*(\d+)", raw_content)
            if seq_match and int(seq_match.group(1)) > 0:
                is_likely_live = True
            should_inject = (
                self._start_offset_value is not None
                and not is_master
                and (
                    self._user_provided_start_offset
                    or (not is_vod and is_likely_live)  # Default offset: only inject for live streams
                )
            )
            for header_line in header_buffer:
                yield header_line + "\n"
                if header_line.strip() == "#EXTM3U" and should_inject and not start_offset_injected:
                    yield f"#EXT-X-START:TIME-OFFSET={self._start_offset_value:.1f},PRECISE=YES\n"
                    start_offset_injected = True
            header_buffer = []

        # Process any remaining data in the buffer plus final bytes
        final_chunk = decoder.decode(b"", final=True)
        if final_chunk:
            buffer += final_chunk

        # Final validation: if we never detected a valid m3u8 playlist marker
        if not is_playlist_detected:
            logger.error(f"Invalid m3u8 content from upstream (no #EXTM3U marker found): {base_url}")
            yield "#EXTM3U\n"
            yield "#EXT-X-PLAYLIST-TYPE:VOD\n"
            yield "# ERROR: Invalid m3u8 content from upstream (no #EXTM3U marker found)\n"
            yield "# The upstream server may have returned an error page\n"
            yield "#EXT-X-ENDLIST\n"
            return

        if buffer:  # Process the last line if it's not empty
            if self.skip_filter.has_skip_segments():
                result = await self._process_line_with_filtering(
                    buffer, base_url, discontinuity_pending, pending_extinf
                )
                processed_line, _, _ = result
                if processed_line is not None:
                    yield processed_line
            else:
                processed_line = await self.process_line(buffer, base_url)
                yield processed_line

        # Log skip statistics
        if self.skip_filter.has_skip_segments():
            logger.info(f"Content filtering: processed playlist with {len(self.skip_filter.skip_segments)} skip ranges")

        # Register playlist with the priority-based prefetcher
        # The prefetcher uses a smart approach:
        # 1. When player requests a segment, it gets priority (downloaded first)
        # 2. After serving priority segment, prefetcher continues sequentially
        # 3. Multiple users watching same channel share the prefetcher
        # 4. Inactive prefetchers are cleaned up automatically
        if settings.enable_hls_prebuffer and is_playlist_detected and self.playlist_url and raw_content:
            # Skip master playlists (they contain variant streams, not segments)
            if "#EXT-X-STREAM-INF" not in raw_content:
                # Extract segment URLs from the playlist
                segment_urls = self._extract_segment_urls_from_content(raw_content, self.playlist_url)

                if segment_urls:
                    # Extract headers for prefetcher
                    headers = {}
                    for key, value in self.request.query_params.items():
                        if key.startswith("h_"):
                            headers[key[2:]] = value

                    logger.info(
                        f"[M3U8Processor] Registering playlist ({len(segment_urls)} segments): {self.playlist_url}"
                    )
                    asyncio.create_task(
                        hls_prebuffer.register_playlist(
                            self.playlist_url,
                            segment_urls,
                            headers,
                        )
                    )

    async def _process_line_with_filtering(
        self, line: str, base_url: str, discontinuity_pending: bool, pending_extinf: Optional[str]
    ) -> tuple:
        """
        Process a single line with segment filtering (skip/mute/black).

        Uses the IntroHater approach: discontinuity is added BEFORE the URL of the
        first segment after a skipped section, not before the EXTINF.

        Returns a tuple of (processed_lines, discontinuity_pending, pending_extinf).
        processed_lines is None if the line should be skipped, otherwise a string to output.
        """
        # Handle EXTINF lines (segment duration markers)
        if line.startswith("#EXTINF:"):
            duration = self._parse_extinf_duration(line)

            if self.skip_filter.should_skip_segment(duration):
                # Skip this segment - don't buffer the EXTINF
                self.skip_filter.advance_time(duration)
                return (None, True, None)  # discontinuity_pending = True, clear pending
            else:
                # Keep this segment
                self.skip_filter.advance_time(duration)
                return (None, discontinuity_pending, line)  # Buffer EXTINF

        # Handle segment URLs (non-comment, non-empty lines)
        if not line.startswith("#") and line.strip():
            if pending_extinf is None:
                # No pending EXTINF means this segment was skipped
                return (None, discontinuity_pending, None)

            # Build output: optional discontinuity + EXTINF + URL
            # Per HLS spec, EXT-X-DISCONTINUITY must appear before the first segment of the new content
            processed_url = await self.proxy_content_url(line, base_url)

            output_lines = []
            if discontinuity_pending:
                output_lines.append("#EXT-X-DISCONTINUITY")
            output_lines.append(pending_extinf)
            output_lines.append(processed_url)

            return ("\n".join(output_lines), False, None)

        # Handle existing discontinuity markers - pass through and reset pending
        if line.startswith("#EXT-X-DISCONTINUITY"):
            return (line, False, pending_extinf)

        # Handle key lines
        if "URI=" in line:
            processed = await self.process_key_line(line, base_url)
            return (processed, discontinuity_pending, pending_extinf)

        # All other lines (headers, comments, etc.)
        return (line, discontinuity_pending, pending_extinf)

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
        # If no_proxy is enabled, just resolve relative URLs without proxying
        if self.no_proxy:
            uri_match = re.search(r'URI="([^"]+)"', line)
            if uri_match:
                original_uri = uri_match.group(1)
                full_url = parse.urljoin(base_url, original_uri)
                line = line.replace(f'URI="{original_uri}"', f'URI="{full_url}"')
            return line

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

        # If no_proxy is enabled, return the direct URL without any proxying
        if self.no_proxy:
            return full_url

        # If key_only_proxy is enabled, return the direct URL for segments
        if self.key_only_proxy and not url.endswith((".m3u", ".m3u8")):
            return full_url

        # Determine routing strategy based on configuration
        routing_strategy = settings.m3u8_content_routing

        # Check if we should force MediaFlow proxy for all playlist URLs
        if self.force_playlist_proxy:
            return await self.proxy_url(full_url, base_url, use_full_url=True, is_playlist=True)

        # For playlist URLs, always use MediaFlow proxy regardless of strategy
        # Check for actual playlist file extensions, not just substring matches
        parsed_url = parse.urlparse(full_url)
        is_playlist_url = parsed_url.path.endswith((".m3u", ".m3u8", ".m3u_plus")) or parse.parse_qs(
            parsed_url.query
        ).get("type", [""])[0] in ["m3u", "m3u8", "m3u_plus"]

        if is_playlist_url:
            return await self.proxy_url(full_url, base_url, use_full_url=True, is_playlist=True)

        # Route non-playlist content URLs (segments) based on strategy
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
            # Use stream endpoint for segment URLs
            return await self.proxy_url(full_url, base_url, use_full_url=True, is_playlist=False)

    def _extract_segment_urls_from_content(self, content: str, base_url: str) -> list:
        """
        Extract segment URLs from HLS playlist content.

        Args:
            content: Raw playlist content
            base_url: Base URL for resolving relative URLs

        Returns:
            List of absolute segment URLs
        """
        segment_urls = []
        for line in content.split("\n"):
            line = line.strip()
            if line and not line.startswith("#"):
                # Absolute URL
                if line.startswith("http://") or line.startswith("https://"):
                    segment_urls.append(line)
                else:
                    # Relative URL - resolve against base
                    segment_urls.append(parse.urljoin(base_url, line))
        return segment_urls

    async def proxy_url(self, url: str, base_url: str, use_full_url: bool = False, is_playlist: bool = True) -> str:
        """
        Proxies a URL, encoding it with the MediaFlow proxy URL.

        Args:
            url (str): The URL to proxy.
            base_url (str): The base URL to resolve relative URLs.
            use_full_url (bool): Whether to use the URL as-is (True) or join with base_url (False).
            is_playlist (bool): Whether this is a playlist URL (uses manifest endpoint) or segment URL (uses stream endpoint).

        Returns:
            str: The proxied URL.
        """
        if use_full_url:
            full_url = url
        else:
            full_url = parse.urljoin(base_url, url)

        query_params = dict(self.request.query_params)
        has_encrypted = query_params.pop("has_encrypted", False)
        # Remove the response headers (r_) from the query params to avoid it being added to the consecutive requests
        # BUT keep rp_ (response propagate) headers as they should propagate to segments
        [
            query_params.pop(key, None)
            for key in list(query_params.keys())
            if key.lower().startswith("r_") and not key.lower().startswith("rp_")
        ]
        # Remove manifest-only parameters to avoid them being added to subsequent requests
        query_params.pop("force_playlist_proxy", None)
        if not is_playlist:
            query_params.pop("start_offset", None)

        # Use appropriate proxy URL based on content type
        if is_playlist:
            proxy_url = self.mediaflow_proxy_url
        else:
            # Determine segment extension from the URL
            # Default to .ts for traditional HLS, but detect fMP4 extensions
            segment_ext = "ts"
            url_lower = full_url.lower()
            # Check for fMP4/CMAF extensions
            if url_lower.endswith(".m4s"):
                segment_ext = "m4s"
            elif url_lower.endswith(".mp4"):
                segment_ext = "mp4"
            elif url_lower.endswith(".m4a"):
                segment_ext = "m4a"
            elif url_lower.endswith(".m4v"):
                segment_ext = "m4v"
            elif url_lower.endswith(".aac"):
                segment_ext = "aac"
            # Build segment proxy URL with correct extension
            proxy_url = f"{self.segment_proxy_base_url}.{segment_ext}"
            # Remove h_range header - each segment should handle its own range requests
            query_params.pop("h_range", None)

        return encode_mediaflow_proxy_url(
            proxy_url,
            None,  # No endpoint - URL is already complete
            full_url,
            query_params=query_params,
            encryption_handler=encryption_handler if has_encrypted else None,
        )
