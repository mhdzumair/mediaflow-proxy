"""
DASH Pre-buffer system for reducing latency and improving streaming performance.

This module extends BasePrebuffer with DASH-specific functionality including
MPD parsing integration, profile handling, and init segment management.
"""

import asyncio
import logging
import time
from typing import Dict, Optional, List

from mediaflow_proxy.utils.base_prebuffer import BasePrebuffer
from mediaflow_proxy.utils.cache_utils import (
    get_cached_mpd,
    get_cached_init_segment,
)
from mediaflow_proxy.configs import settings

logger = logging.getLogger(__name__)


class DASHPreBuffer(BasePrebuffer):
    """
    Pre-buffer system for DASH streams.

    Extends BasePrebuffer with DASH-specific features:
    - MPD manifest parsing and profile handling
    - Init segment prebuffering
    - Live stream segment tracking
    - Profile-based segment prefetching

    Uses event-based download coordination from BasePrebuffer to prevent
    duplicate downloads between player requests and background prebuffering.
    """

    def __init__(
        self,
        max_cache_size: Optional[int] = None,
        prebuffer_segments: Optional[int] = None,
    ):
        """
        Initialize the DASH pre-buffer system.

        Args:
            max_cache_size: Maximum number of segments to cache (uses config if None)
            prebuffer_segments: Number of segments to pre-buffer ahead (uses config if None)
        """
        super().__init__(
            max_cache_size=max_cache_size or settings.dash_prebuffer_cache_size,
            prebuffer_segments=prebuffer_segments or settings.dash_prebuffer_segments,
            max_memory_percent=settings.dash_prebuffer_max_memory_percent,
            emergency_threshold=settings.dash_prebuffer_emergency_threshold,
            segment_ttl=settings.dash_segment_cache_ttl,
        )

        self.inactivity_timeout = settings.dash_prebuffer_inactivity_timeout

        # DASH-specific state
        # Track active streams for prefetching: mpd_url -> stream_info
        self.active_streams: Dict[str, dict] = {}
        self.prefetch_tasks: Dict[str, asyncio.Task] = {}

        # Additional stats for DASH
        self.init_segments_prebuffered = 0

        # Cleanup task
        self._cleanup_task: Optional[asyncio.Task] = None

    def log_stats(self) -> None:
        """Log current prebuffer statistics with DASH-specific info."""
        stats = self.stats.to_dict()
        stats["init_segments_prebuffered"] = self.init_segments_prebuffered
        stats["active_streams"] = len(self.active_streams)
        logger.info(f"DASH Prebuffer Stats: {stats}")

    async def prebuffer_dash_manifest(
        self,
        mpd_url: str,
        headers: Dict[str, str],
    ) -> None:
        """
        Pre-buffer segments from a DASH manifest using existing MPD parsing.

        Args:
            mpd_url: URL of the DASH manifest
            headers: Headers to use for requests
        """
        try:
            # First get the basic MPD info without segments
            parsed_mpd = await get_cached_mpd(mpd_url, headers, parse_drm=False)
            if not parsed_mpd:
                logger.warning(f"Failed to get parsed MPD for prebuffering: {mpd_url}")
                return

            is_live = parsed_mpd.get("isLive", False)
            base_profiles = parsed_mpd.get("profiles", [])

            if not base_profiles:
                logger.warning(f"No profiles found in MPD for prebuffering: {mpd_url}")
                return

            # Now get segments for each profile by parsing with profile_id
            profiles_with_segments = []
            for profile in base_profiles:
                profile_id = profile.get("id")
                if profile_id:
                    parsed_with_segments = await get_cached_mpd(
                        mpd_url, headers, parse_drm=False, parse_segment_profile_id=profile_id
                    )
                    # Find the matching profile with segments
                    for p in parsed_with_segments.get("profiles", []):
                        if p.get("id") == profile_id:
                            profiles_with_segments.append(p)
                            break

            # Store stream info for ongoing prefetching
            self.active_streams[mpd_url] = {
                "headers": headers,
                "is_live": is_live,
                "profiles": profiles_with_segments,
                "last_access": time.time(),
            }

            # Prebuffer init segments and media segments
            await self._prebuffer_profiles(profiles_with_segments, headers, is_live)

            # Start cleanup task if not running
            self._ensure_cleanup_task_running()

            logger.info(
                f"Pre-buffered DASH manifest: {mpd_url} (live={is_live}, profiles={len(profiles_with_segments)})"
            )

        except Exception as e:
            logger.warning(f"Failed to pre-buffer DASH manifest {mpd_url}: {e}")

    async def _prebuffer_profiles(
        self,
        profiles: List[dict],
        headers: Dict[str, str],
        is_live: bool = False,
    ) -> None:
        """
        Pre-buffer init segments and media segments for all profiles.

        For live streams, prebuffers from the END of the segment list.
        For VOD, prebuffers from the beginning.

        Args:
            profiles: List of parsed profiles with resolved URLs
            headers: Headers to use for requests
            is_live: Whether this is a live stream
        """
        if self._should_skip_for_memory():
            logger.warning("Memory usage too high, skipping prebuffer")
            return

        # Collect all segment URLs to prebuffer
        segment_urls = []
        init_urls = []

        for profile in profiles:
            # Collect init segment URL
            init_url = profile.get("initUrl")
            if init_url:
                init_urls.append(init_url)

            # Get segments to prebuffer
            segments = profile.get("segments", [])
            if not segments:
                continue

            # For live streams, prebuffer from the END (most recent)
            if is_live:
                segments_to_buffer = segments[-self.prebuffer_segment_count :]
            else:
                segments_to_buffer = segments[: self.prebuffer_segment_count]

            for segment in segments_to_buffer:
                segment_url = segment.get("media")
                if segment_url:
                    segment_urls.append(segment_url)

        # Prebuffer init segments (using special init cache)
        for init_url in init_urls:
            asyncio.create_task(self._prebuffer_init_segment(init_url, headers))

        # Prebuffer media segments using base class method
        if segment_urls:
            await self.prebuffer_segments_batch(segment_urls, headers)

    async def _prebuffer_init_segment(
        self,
        init_url: str,
        headers: Dict[str, str],
    ) -> None:
        """
        Prebuffer an init segment using the init segment cache.

        Args:
            init_url: URL of the init segment
            headers: Headers for the request
        """
        try:
            # get_cached_init_segment handles both caching and downloading
            content = await get_cached_init_segment(init_url, headers)
            if content:
                self.init_segments_prebuffered += 1
                self.stats.bytes_prebuffered += len(content)
                logger.debug(f"Prebuffered init segment ({len(content)} bytes)")
        except Exception as e:
            logger.warning(f"Failed to prebuffer init segment: {e}")

    async def prefetch_upcoming_segments(
        self,
        mpd_url: str,
        current_segment_url: str,
        headers: Dict[str, str],
        profile_id: Optional[str] = None,
    ) -> None:
        """
        Prefetch upcoming segments based on current playback position.

        Called when a segment is requested to prefetch the next N segments.

        Args:
            mpd_url: URL of the MPD manifest
            current_segment_url: URL of the currently requested segment
            headers: Headers to use for requests
            profile_id: Optional profile ID to limit prefetching to
        """
        self.stats.prefetch_triggered += 1

        try:
            # First check if we have cached profiles with segments
            if mpd_url in self.active_streams:
                # Update last access time
                self.active_streams[mpd_url]["last_access"] = time.time()
                profiles = self.active_streams[mpd_url].get("profiles", [])
            else:
                # Get parsed MPD
                parsed_mpd = await get_cached_mpd(mpd_url, headers, parse_drm=False)
                if not parsed_mpd:
                    return
                profiles = parsed_mpd.get("profiles", [])

            for profile in profiles:
                pid = profile.get("id")
                if profile_id and pid != profile_id:
                    continue

                segments = profile.get("segments", [])

                # If no segments, try to get them by parsing with profile_id
                if not segments and pid:
                    parsed_with_segments = await get_cached_mpd(
                        mpd_url, headers, parse_drm=False, parse_segment_profile_id=pid
                    )
                    for p in parsed_with_segments.get("profiles", []):
                        if p.get("id") == pid:
                            segments = p.get("segments", [])
                            break

                # Find current segment index
                current_index = -1
                for i, segment in enumerate(segments):
                    if segment.get("media") == current_segment_url:
                        current_index = i
                        break

                if current_index < 0:
                    continue

                # Collect next N segment URLs
                segment_urls = []
                end_index = min(current_index + 1 + self.prebuffer_segment_count, len(segments))
                for i in range(current_index + 1, end_index):
                    segment_url = segments[i].get("media")
                    if segment_url:
                        segment_urls.append(segment_url)

                if segment_urls:
                    logger.debug(f"Prefetching {len(segment_urls)} upcoming segments from index {current_index + 1}")
                    # Run prefetch in background
                    asyncio.create_task(self.prebuffer_segments_batch(segment_urls, headers, max_concurrent=3))

        except Exception as e:
            logger.warning(f"Failed to prefetch upcoming segments: {e}")

    async def prefetch_for_live_playlist(
        self,
        profiles: List[dict],
        headers: Dict[str, str],
    ) -> None:
        """
        Prefetch segments for a live playlist refresh.

        Called from process_playlist to ensure upcoming segments are cached.

        Args:
            profiles: List of profiles with resolved segment URLs
            headers: Headers to use for requests
        """
        segment_urls = []

        for profile in profiles:
            segments = profile.get("segments", [])
            if not segments:
                continue

            # For live, prefetch the last N segments (most recent)
            segments_to_prefetch = segments[-self.prebuffer_segment_count :]

            for segment in segments_to_prefetch:
                segment_url = segment.get("media")
                if segment_url:
                    # Check if already cached before adding
                    cached = await self.try_get_cached(segment_url)
                    if not cached:
                        segment_urls.append(segment_url)

        if segment_urls:
            logger.debug(f"Live playlist prefetch: {len(segment_urls)} segments")
            asyncio.create_task(self.prebuffer_segments_batch(segment_urls, headers, max_concurrent=3))

    def _ensure_cleanup_task_running(self) -> None:
        """Ensure the cleanup task is running."""
        if self._cleanup_task is None or self._cleanup_task.done():
            self._cleanup_task = asyncio.create_task(self._cleanup_inactive_streams())

    async def _cleanup_inactive_streams(self) -> None:
        """
        Periodically check for and clean up inactive streams.

        Runs in the background and removes streams that haven't been
        accessed recently.
        """
        while True:
            try:
                await asyncio.sleep(30)  # Check every 30 seconds

                if not self.active_streams:
                    logger.debug("No active DASH streams to monitor, stopping cleanup")
                    return

                current_time = time.time()
                streams_to_remove = []

                for mpd_url, stream_info in self.active_streams.items():
                    last_access = stream_info.get("last_access", 0)
                    time_since_access = current_time - last_access

                    if time_since_access > self.inactivity_timeout:
                        streams_to_remove.append(mpd_url)
                        logger.info(f"Cleaning up inactive DASH stream ({time_since_access:.0f}s idle)")

                # Remove inactive streams
                for mpd_url in streams_to_remove:
                    self.active_streams.pop(mpd_url, None)
                    task = self.prefetch_tasks.pop(mpd_url, None)
                    if task:
                        task.cancel()

                if streams_to_remove:
                    logger.info(f"Cleaned up {len(streams_to_remove)} inactive DASH stream(s)")

            except asyncio.CancelledError:
                logger.debug("DASH cleanup task cancelled")
                return
            except Exception as e:
                logger.warning(f"Error in DASH cleanup task: {e}")

    def get_stats(self) -> dict:
        """Get current prebuffer statistics."""
        stats = self.stats.to_dict()
        stats["init_segments_prebuffered"] = self.init_segments_prebuffered
        stats["active_streams"] = len(self.active_streams)
        return stats

    def clear_cache(self) -> None:
        """Clear active streams tracking and log final stats."""
        self.log_stats()
        self.active_streams.clear()
        for task in self.prefetch_tasks.values():
            task.cancel()
        self.prefetch_tasks.clear()
        # Cancel cleanup task
        if self._cleanup_task and not self._cleanup_task.done():
            self._cleanup_task.cancel()
        self._cleanup_task = None
        self.stats.reset()
        self.init_segments_prebuffered = 0
        logger.info("DASH pre-buffer state cleared")

    async def close(self) -> None:
        """Close the pre-buffer system."""
        self.clear_cache()


# Global DASH pre-buffer instance
dash_prebuffer = DASHPreBuffer()
