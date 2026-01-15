"""
HLS Pre-buffer system with priority-based sequential prefetching.

This module provides a smart prebuffering system that:
- Prioritizes player-requested segments (downloaded immediately)
- Prefetches remaining segments sequentially in background
- Supports multiple users watching the same channel (shared prefetcher)
- Cleans up inactive prefetchers automatically

Architecture:
1. When playlist is fetched, register_playlist() creates a PlaylistPrefetcher
2. PlaylistPrefetcher runs a background loop: priority queue -> sequential prefetch
3. When player requests a segment, request_segment() adds it to priority queue
4. Prefetcher downloads priority segment first, then continues sequential
"""

import asyncio
import logging
import time
from typing import Dict, Optional, List
from urllib.parse import urljoin

from mediaflow_proxy.utils.base_prebuffer import BasePrebuffer
from mediaflow_proxy.utils.cache_utils import get_cached_segment
from mediaflow_proxy.configs import settings

logger = logging.getLogger(__name__)


class PlaylistPrefetcher:
    """
    Manages prefetching for a single playlist with priority support.

    Key design for live streams with changing tokens:
    - Does NOT start prefetching immediately on registration
    - Only starts prefetching AFTER player requests a segment
    - This ensures we prefetch from the CURRENT playlist, not stale ones

    The prefetcher runs a background loop that:
    1. Waits for player to request a segment (priority)
    2. Downloads the priority segment first
    3. Then prefetches subsequent segments sequentially
    4. Stops when cancelled or all segments are prefetched
    """

    def __init__(
        self,
        playlist_url: str,
        segment_urls: List[str],
        headers: Dict[str, str],
        prebuffer: "HLSPreBuffer",
        prefetch_limit: int = 5,
    ):
        """
        Initialize a playlist prefetcher.

        Args:
            playlist_url: URL of the HLS playlist
            segment_urls: Ordered list of segment URLs from the playlist
            headers: Headers to use for requests
            prebuffer: Parent HLSPreBuffer instance for download methods
            prefetch_limit: Maximum number of segments to prefetch ahead of player position
        """
        self.playlist_url = playlist_url
        self.segment_urls = segment_urls
        self.headers = headers
        self.prebuffer = prebuffer
        self.prefetch_limit = prefetch_limit

        self.last_access = time.time()
        self.current_index = 0  # Next segment to prefetch sequentially
        self.player_index = 0  # Last segment index requested by player
        self.priority_event = asyncio.Event()  # Signals priority segment available
        self.priority_url: Optional[str] = None  # Current priority segment
        self.cancelled = False
        self._task: Optional[asyncio.Task] = None
        self._lock = asyncio.Lock()  # Protects priority_url

        # Track which segments are already cached or being downloaded
        self.downloading: set = set()

        # Track if prefetching has been activated by a player request
        self.activated = False

    def start(self) -> None:
        """Start the prefetch background task."""
        if self._task is None or self._task.done():
            self._task = asyncio.create_task(self._run())
            logger.info(f"[PlaylistPrefetcher] Started (waiting for activation): {self.playlist_url}")

    def stop(self) -> None:
        """Stop the prefetch background task."""
        self.cancelled = True
        self.priority_event.set()  # Wake up the loop
        if self._task and not self._task.done():
            self._task.cancel()
        logger.info(f"[PlaylistPrefetcher] Stopped for: {self.playlist_url}")

    def update_segments(self, segment_urls: List[str]) -> None:
        """
        Update segment URLs (called when playlist is refreshed).

        Args:
            segment_urls: New list of segment URLs
        """
        self.segment_urls = segment_urls
        self.last_access = time.time()
        logger.debug(f"[PlaylistPrefetcher] Updated segments ({len(segment_urls)}): {self.playlist_url}")

    async def request_priority(self, segment_url: str) -> None:
        """
        Player requested this segment - update indices and activate prefetching.

        The player will download this segment via get_or_download().
        The prefetcher's job is to prefetch segments AHEAD of the player,
        not to download the segment the player is already requesting.

        For VOD/movie streams: handles seek by detecting large jumps in segment
        index and resetting the prefetch window accordingly.

        Args:
            segment_url: URL of the segment the player needs
        """
        self.last_access = time.time()
        self.activated = True  # Activate prefetching

        # Update player position for prefetch limit calculation
        segment_index = self._find_segment_index(segment_url)
        if segment_index >= 0:
            old_player_index = self.player_index
            self.player_index = segment_index
            # Start prefetching from the NEXT segment (player handles current one)
            self.current_index = segment_index + 1

            # Detect seek: if player jumped more than prefetch_limit segments
            # This handles VOD seek scenarios where user jumps to different position
            jump_distance = abs(segment_index - old_player_index)
            if jump_distance > self.prefetch_limit and old_player_index >= 0:
                logger.info(
                    f"[PlaylistPrefetcher] Seek detected: jumped {jump_distance} segments "
                    f"(from {old_player_index} to {segment_index})"
                )

        # Signal the prefetch loop to wake up and start prefetching ahead
        async with self._lock:
            self.priority_url = segment_url
            self.priority_event.set()

    def _find_segment_index(self, segment_url: str) -> int:
        """Find the index of a segment URL in the list."""
        try:
            return self.segment_urls.index(segment_url)
        except ValueError:
            return -1

    async def _run(self) -> None:
        """
        Main prefetch loop.

        For live streams: waits until activated by player request before prefetching.
        Priority: Player-requested segment > Sequential prefetch
        After downloading priority segment, continue sequential from that point.

        Prefetching is LIMITED to `prefetch_limit` segments ahead of the player's
        current position to avoid downloading the entire stream.
        """
        logger.info(f"[PlaylistPrefetcher] Loop started for: {self.playlist_url}")

        while not self.cancelled:
            try:
                # Wait for activation (player request) before doing anything
                if not self.activated:
                    try:
                        await asyncio.wait_for(self.priority_event.wait(), timeout=1.0)
                    except asyncio.TimeoutError:
                        continue

                # Check for priority segment first
                async with self._lock:
                    priority_url = self.priority_url
                    self.priority_url = None
                    self.priority_event.clear()

                if priority_url:
                    # Player is already downloading this segment via get_or_download()
                    # We just need to update our indices and skip to prefetching NEXT segments
                    # This avoids duplicate download attempts and inflated cache miss stats
                    priority_index = self._find_segment_index(priority_url)
                    if priority_index >= 0:
                        self.player_index = priority_index
                        self.current_index = priority_index + 1  # Start prefetching from next segment
                        logger.info(
                            f"[PlaylistPrefetcher] Player at index {self.player_index}, "
                            f"will prefetch up to {self.prefetch_limit} segments ahead"
                        )
                    continue

                # Calculate prefetch limit based on player position
                max_prefetch_index = self.player_index + self.prefetch_limit + 1

                # No priority - prefetch next sequential segment (only if within limit)
                if (
                    self.activated
                    and self.current_index < len(self.segment_urls)
                    and self.current_index < max_prefetch_index
                ):
                    url = self.segment_urls[self.current_index]

                    # Skip if already cached or being downloaded
                    if url not in self.downloading:
                        cached = await get_cached_segment(url)
                        if not cached:
                            logger.info(
                                f"[PlaylistPrefetcher] Prefetching [{self.current_index}] "
                                f"(player at {self.player_index}, limit {self.prefetch_limit}): {url}"
                            )
                            await self._download_segment(url)
                        else:
                            logger.debug(f"[PlaylistPrefetcher] Already cached [{self.current_index}]: {url}")

                    self.current_index += 1
                else:
                    # Reached prefetch limit or end of segments - wait for player to advance
                    try:
                        await asyncio.wait_for(self.priority_event.wait(), timeout=1.0)
                    except asyncio.TimeoutError:
                        pass

            except asyncio.CancelledError:
                logger.info(f"[PlaylistPrefetcher] Loop cancelled: {self.playlist_url}")
                return
            except Exception as e:
                logger.warning(f"[PlaylistPrefetcher] Error in loop: {e}")
                await asyncio.sleep(0.5)

        logger.info(f"[PlaylistPrefetcher] Loop ended: {self.playlist_url}")

    async def _download_segment(self, url: str) -> None:
        """
        Download and cache a segment using the parent prebuffer.

        Args:
            url: URL of the segment to download
        """
        if url in self.downloading:
            return

        self.downloading.add(url)
        try:
            # Use the base prebuffer's get_or_download for cross-process coordination
            await self.prebuffer.get_or_download(url, self.headers)
        finally:
            self.downloading.discard(url)


class HLSPreBuffer(BasePrebuffer):
    """
    Pre-buffer system for HLS streams with priority-based prefetching.

    Features:
    - Priority queue: Player-requested segments downloaded first
    - Sequential prefetch: Background prefetch of remaining segments
    - Multi-user support: Multiple users share same prefetcher
    - Automatic cleanup: Inactive prefetchers removed after timeout
    """

    def __init__(
        self,
        max_cache_size: Optional[int] = None,
        prebuffer_segments: Optional[int] = None,
    ):
        """
        Initialize the HLS pre-buffer system.

        Args:
            max_cache_size: Maximum number of segments to cache (uses config if None)
            prebuffer_segments: Number of segments to pre-buffer ahead (uses config if None)
        """
        super().__init__(
            max_cache_size=max_cache_size or settings.hls_prebuffer_cache_size,
            prebuffer_segments=prebuffer_segments or settings.hls_prebuffer_segments,
            max_memory_percent=settings.hls_prebuffer_max_memory_percent,
            emergency_threshold=settings.hls_prebuffer_emergency_threshold,
            segment_ttl=settings.hls_segment_cache_ttl,
        )

        self.inactivity_timeout = settings.hls_prebuffer_inactivity_timeout

        # Active prefetchers: playlist_url -> PlaylistPrefetcher
        self.active_prefetchers: Dict[str, PlaylistPrefetcher] = {}

        # Reverse mapping: segment URL -> playlist_url
        self.segment_to_playlist: Dict[str, str] = {}

        # Lock for prefetcher management
        self._prefetcher_lock = asyncio.Lock()

        # Cleanup task
        self._cleanup_task: Optional[asyncio.Task] = None
        self._cleanup_interval = 30  # Check every 30 seconds

    def log_stats(self) -> None:
        """Log current prebuffer statistics with HLS-specific info."""
        stats = self.stats.to_dict()
        stats["active_prefetchers"] = len(self.active_prefetchers)
        logger.info(f"HLS Prebuffer Stats: {stats}")

    def _extract_segment_urls(self, playlist_content: str, base_url: str) -> List[str]:
        """
        Extract segment URLs from HLS playlist content.

        Args:
            playlist_content: Content of the HLS playlist
            base_url: Base URL for resolving relative URLs

        Returns:
            List of segment URLs
        """
        segment_urls = []
        lines = playlist_content.split("\n")

        for line in lines:
            line = line.strip()
            if line and not line.startswith("#"):
                # Absolute URL
                if line.startswith("http://") or line.startswith("https://"):
                    segment_urls.append(line)
                else:
                    # Relative URL - resolve against base
                    segment_url = urljoin(base_url, line)
                    segment_urls.append(segment_url)

        return segment_urls

    def _is_master_playlist(self, playlist_content: str) -> bool:
        """Check if this is a master playlist (contains variant streams)."""
        return "#EXT-X-STREAM-INF" in playlist_content

    async def register_playlist(
        self,
        playlist_url: str,
        segment_urls: List[str],
        headers: Dict[str, str],
    ) -> None:
        """
        Register a playlist for prefetching.

        Creates a new PlaylistPrefetcher or updates existing one.
        Called by M3U8 processor when a playlist is fetched.

        Args:
            playlist_url: URL of the HLS playlist
            segment_urls: Ordered list of segment URLs from the playlist
            headers: Headers to use for requests
        """
        if not segment_urls:
            logger.debug(f"[register_playlist] No segments, skipping: {playlist_url}")
            return

        async with self._prefetcher_lock:
            # Update reverse mapping
            for url in segment_urls:
                self.segment_to_playlist[url] = playlist_url

            if playlist_url in self.active_prefetchers:
                # Update existing prefetcher
                prefetcher = self.active_prefetchers[playlist_url]
                prefetcher.update_segments(segment_urls)
                prefetcher.headers = headers
                logger.info(f"[register_playlist] Updated existing prefetcher: {playlist_url}")
            else:
                # Create new prefetcher with configured prefetch limit
                prefetcher = PlaylistPrefetcher(
                    playlist_url=playlist_url,
                    segment_urls=segment_urls,
                    headers=headers,
                    prebuffer=self,
                    prefetch_limit=settings.hls_prebuffer_segments,
                )
                self.active_prefetchers[playlist_url] = prefetcher
                prefetcher.start()
                logger.info(
                    f"[register_playlist] Created new prefetcher ({len(segment_urls)} segments, "
                    f"prefetch_limit={settings.hls_prebuffer_segments}): {playlist_url}"
                )

            # Ensure cleanup task is running
            self._ensure_cleanup_task()

    async def request_segment(self, segment_url: str) -> None:
        """
        Player requested a segment - set as priority for prefetching.

        Finds the prefetcher for this segment and adds it to priority queue.
        Called by the segment endpoint when a segment is requested.

        Args:
            segment_url: URL of the segment the player needs
        """
        playlist_url = self.segment_to_playlist.get(segment_url)
        if not playlist_url:
            logger.debug(f"[request_segment] No prefetcher found for: {segment_url}")
            return

        prefetcher = self.active_prefetchers.get(playlist_url)
        if prefetcher:
            await prefetcher.request_priority(segment_url)
        else:
            logger.debug(f"[request_segment] Prefetcher not active for: {playlist_url}")

    def _ensure_cleanup_task(self) -> None:
        """Ensure the cleanup task is running."""
        if self._cleanup_task is None or self._cleanup_task.done():
            self._cleanup_task = asyncio.create_task(self._cleanup_loop())

    async def _cleanup_loop(self) -> None:
        """Periodically clean up inactive prefetchers."""
        while True:
            try:
                await asyncio.sleep(self._cleanup_interval)
                await self._cleanup_inactive_prefetchers()
            except asyncio.CancelledError:
                return
            except Exception as e:
                logger.warning(f"[cleanup_loop] Error: {e}")

    async def _cleanup_inactive_prefetchers(self) -> None:
        """Remove prefetchers that haven't been accessed recently."""
        now = time.time()
        to_remove = []

        async with self._prefetcher_lock:
            for playlist_url, prefetcher in self.active_prefetchers.items():
                inactive_time = now - prefetcher.last_access
                if inactive_time > self.inactivity_timeout:
                    to_remove.append(playlist_url)
                    logger.info(f"[cleanup] Removing inactive prefetcher ({inactive_time:.0f}s): {playlist_url}")

            for playlist_url in to_remove:
                prefetcher = self.active_prefetchers.pop(playlist_url, None)
                if prefetcher:
                    prefetcher.stop()
                    # Clean up reverse mapping
                    for url in prefetcher.segment_urls:
                        self.segment_to_playlist.pop(url, None)

        if to_remove:
            logger.info(f"[cleanup] Removed {len(to_remove)} inactive prefetchers")

    def get_stats(self) -> dict:
        """Get current prebuffer statistics."""
        stats = self.stats.to_dict()
        stats["active_prefetchers"] = len(self.active_prefetchers)
        return stats

    def clear_cache(self) -> None:
        """Clear all prebuffer state and log final stats."""
        self.log_stats()

        # Stop all prefetchers
        for prefetcher in self.active_prefetchers.values():
            prefetcher.stop()

        self.active_prefetchers.clear()
        self.segment_to_playlist.clear()
        self.stats.reset()

        logger.info("HLS pre-buffer state cleared")

    async def close(self) -> None:
        """Close the pre-buffer system."""
        self.clear_cache()
        if self._cleanup_task:
            self._cleanup_task.cancel()


# Global HLS pre-buffer instance
hls_prebuffer = HLSPreBuffer()
