import asyncio
import logging
import time
import psutil
from dataclasses import dataclass, field
from typing import Dict, Optional, List, Set

from mediaflow_proxy.utils.http_utils import create_httpx_client, download_file_with_retry
from mediaflow_proxy.utils.cache_utils import (
    get_cached_mpd,
    get_cached_init_segment,
    get_cached_segment,
    set_cached_segment,
)
from mediaflow_proxy.configs import settings

logger = logging.getLogger(__name__)


@dataclass
class PrebufferStats:
    """Statistics for prebuffer performance tracking."""

    cache_hits: int = 0
    cache_misses: int = 0
    segments_prebuffered: int = 0
    init_segments_prebuffered: int = 0
    bytes_prebuffered: int = 0
    prefetch_triggered: int = 0
    last_reset: float = field(default_factory=time.time)

    @property
    def hit_rate(self) -> float:
        """Calculate cache hit rate percentage."""
        total = self.cache_hits + self.cache_misses
        return (self.cache_hits / total * 100) if total > 0 else 0.0

    def reset(self) -> None:
        """Reset statistics."""
        self.cache_hits = 0
        self.cache_misses = 0
        self.segments_prebuffered = 0
        self.init_segments_prebuffered = 0
        self.bytes_prebuffered = 0
        self.prefetch_triggered = 0
        self.last_reset = time.time()

    def to_dict(self) -> dict:
        """Convert stats to dictionary for logging."""
        return {
            "cache_hits": self.cache_hits,
            "cache_misses": self.cache_misses,
            "hit_rate": f"{self.hit_rate:.1f}%",
            "segments_prebuffered": self.segments_prebuffered,
            "init_segments_prebuffered": self.init_segments_prebuffered,
            "bytes_prebuffered_mb": f"{self.bytes_prebuffered / 1024 / 1024:.2f}",
            "prefetch_triggered": self.prefetch_triggered,
            "uptime_seconds": int(time.time() - self.last_reset),
        }


class DASHPreBuffer:
    """
    Pre-buffer system for DASH streams to reduce latency and improve streaming performance.
    Uses the existing MPD parsing infrastructure to get fully resolved segment URLs.

    Features:
    - Initial prebuffering when manifest is first requested
    - Continuous prefetching triggered on each segment request
    - Smart segment selection (prebuffer from end for live streams)
    - Cache statistics and monitoring
    """

    def __init__(self, max_cache_size: Optional[int] = None, prebuffer_segments: Optional[int] = None):
        """
        Initialize the DASH pre-buffer system.

        Args:
            max_cache_size (int): Maximum number of segments to cache (uses config if None)
            prebuffer_segments (int): Number of segments to pre-buffer ahead (uses config if None)
        """
        self.max_cache_size = max_cache_size or settings.dash_prebuffer_cache_size
        self.prebuffer_segments = prebuffer_segments or settings.dash_prebuffer_segments
        self.max_memory_percent = settings.dash_prebuffer_max_memory_percent
        self.emergency_threshold = settings.dash_prebuffer_emergency_threshold
        self.segment_ttl = settings.dash_segment_cache_ttl
        self.inactivity_timeout = settings.dash_prebuffer_inactivity_timeout

        # Track active streams for prefetching
        self.active_streams: Dict[str, dict] = {}  # mpd_url -> stream_info
        self.prefetch_tasks: Dict[str, asyncio.Task] = {}

        # Track URLs being downloaded to avoid duplicates
        self._downloading: Set[str] = set()
        self._download_lock = asyncio.Lock()

        # Statistics
        self.stats = PrebufferStats()

        self.client = create_httpx_client()

        # Start cleanup task
        self._cleanup_task: Optional[asyncio.Task] = None

    def _get_memory_usage_percent(self) -> float:
        """Get current memory usage percentage."""
        try:
            memory = psutil.virtual_memory()
            return memory.percent
        except Exception as e:
            logger.warning(f"Failed to get memory usage: {e}")
            return 0.0

    def _check_memory_threshold(self) -> bool:
        """Check if memory usage exceeds the emergency threshold."""
        memory_percent = self._get_memory_usage_percent()
        return memory_percent > self.emergency_threshold

    def record_cache_hit(self) -> None:
        """Record a cache hit for statistics."""
        self.stats.cache_hits += 1

    def record_cache_miss(self) -> None:
        """Record a cache miss for statistics."""
        self.stats.cache_misses += 1

    def log_stats(self) -> None:
        """Log current prebuffer statistics."""
        logger.info(f"DASH Prebuffer Stats: {self.stats.to_dict()}")

    async def prebuffer_dash_manifest(self, mpd_url: str, headers: Dict[str, str]) -> None:
        """
        Pre-buffer segments from a DASH manifest using existing MPD parsing.

        Args:
            mpd_url (str): URL of the DASH manifest
            headers (Dict[str, str]): Headers to use for requests
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

    async def _prebuffer_profiles(self, profiles: List[dict], headers: Dict[str, str], is_live: bool = False) -> None:
        """
        Pre-buffer init segments and media segments for all profiles.

        For live streams, prebuffers from the END of the segment list (most recent segments).
        For VOD, prebuffers from the beginning.

        Args:
            profiles: List of parsed profiles with resolved URLs
            headers: Headers to use for requests
            is_live: Whether this is a live stream
        """
        # Check memory before starting
        if self._get_memory_usage_percent() > self.max_memory_percent:
            logger.warning("Memory usage too high, skipping prebuffer")
            return

        tasks = []

        for profile in profiles:
            # Prebuffer init segment
            init_url = profile.get("initUrl")
            if init_url:
                tasks.append(self._download_and_cache_init(init_url, headers))

            # Get segments to prebuffer
            segments = profile.get("segments", [])
            if not segments:
                continue

            # For live streams, prebuffer from the END (most recent segments)
            # For VOD, prebuffer from the beginning
            if is_live:
                # Take last N segments (most recent for live)
                segments_to_buffer = segments[-self.prebuffer_segments :]
            else:
                # Take first N segments for VOD
                segments_to_buffer = segments[: self.prebuffer_segments]

            for segment in segments_to_buffer:
                segment_url = segment.get("media")
                if segment_url:
                    tasks.append(self._download_and_cache_segment(segment_url, headers))

        # Execute downloads in parallel with concurrency limit
        if tasks:
            semaphore = asyncio.Semaphore(5)

            async def limited_task(task):
                async with semaphore:
                    return await task

            await asyncio.gather(*[limited_task(t) for t in tasks], return_exceptions=True)

    async def _download_and_cache_init(self, init_url: str, headers: Dict[str, str]) -> None:
        """Download and cache an init segment using the shared cache."""
        # Avoid duplicate downloads
        async with self._download_lock:
            if init_url in self._downloading:
                return
            self._downloading.add(init_url)

        try:
            # Check memory
            if self._get_memory_usage_percent() > self.max_memory_percent:
                return

            # get_cached_init_segment handles both caching and downloading
            content = await get_cached_init_segment(init_url, headers)
            if content:
                self.stats.init_segments_prebuffered += 1
                self.stats.bytes_prebuffered += len(content)
                logger.debug(f"Prebuffered init segment ({len(content)} bytes): {init_url}")
        except Exception as e:
            logger.warning(f"Failed to prebuffer init segment {init_url}: {e}")
        finally:
            async with self._download_lock:
                self._downloading.discard(init_url)

    async def _download_and_cache_segment(self, segment_url: str, headers: Dict[str, str]) -> None:
        """Download and cache a media segment using the shared cache."""
        # Check if already cached
        cached = await get_cached_segment(segment_url)
        if cached:
            logger.debug(f"Segment already cached: {segment_url}")
            return

        # Avoid duplicate downloads
        async with self._download_lock:
            if segment_url in self._downloading:
                return
            self._downloading.add(segment_url)

        try:
            # Check memory
            if self._get_memory_usage_percent() > self.max_memory_percent:
                return

            content = await download_file_with_retry(segment_url, headers)
            if content:
                # Use configurable TTL
                await set_cached_segment(segment_url, content, ttl=self.segment_ttl)
                self.stats.segments_prebuffered += 1
                self.stats.bytes_prebuffered += len(content)
                logger.debug(f"Prebuffered segment ({len(content)} bytes, TTL={self.segment_ttl}s): {segment_url}")
        except Exception as e:
            logger.warning(f"Failed to prebuffer segment {segment_url}: {e}")
        finally:
            async with self._download_lock:
                self._downloading.discard(segment_url)

    async def prefetch_upcoming_segments(
        self, mpd_url: str, current_segment_url: str, headers: Dict[str, str], profile_id: Optional[str] = None
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
                # Get parsed MPD - need to parse with profile_id to get segments
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

                # Prefetch next N segments
                tasks = []
                end_index = min(current_index + 1 + self.prebuffer_segments, len(segments))
                for i in range(current_index + 1, end_index):
                    segment_url = segments[i].get("media")
                    if segment_url:
                        tasks.append(self._download_and_cache_segment(segment_url, headers))

                if tasks:
                    logger.debug(f"Prefetching {len(tasks)} upcoming segments from index {current_index + 1}")
                    # Run prefetch in background without blocking
                    asyncio.create_task(self._run_prefetch_tasks(tasks))

        except Exception as e:
            logger.warning(f"Failed to prefetch upcoming segments: {e}")

    async def prefetch_for_live_playlist(self, profiles: List[dict], headers: Dict[str, str]) -> None:
        """
        Prefetch segments for a live playlist refresh.
        Called from process_playlist to ensure upcoming segments are cached.

        Args:
            profiles: List of profiles with resolved segment URLs
            headers: Headers to use for requests
        """
        tasks = []

        for profile in profiles:
            segments = profile.get("segments", [])
            if not segments:
                continue

            # For live, prefetch the last N segments (most recent)
            segments_to_prefetch = segments[-self.prebuffer_segments :]

            for segment in segments_to_prefetch:
                segment_url = segment.get("media")
                if segment_url:
                    # Check if already cached before adding task
                    cached = await get_cached_segment(segment_url)
                    if not cached:
                        tasks.append(self._download_and_cache_segment(segment_url, headers))

        if tasks:
            logger.debug(f"Live playlist prefetch: {len(tasks)} segments")
            asyncio.create_task(self._run_prefetch_tasks(tasks))

    async def _run_prefetch_tasks(self, tasks: List) -> None:
        """Run prefetch tasks with concurrency limit."""
        semaphore = asyncio.Semaphore(3)  # Limit concurrent prefetch downloads

        async def limited_task(task):
            async with semaphore:
                return await task

        await asyncio.gather(*[limited_task(t) for t in tasks], return_exceptions=True)

    def _ensure_cleanup_task_running(self) -> None:
        """Ensure the cleanup task is running."""
        if self._cleanup_task is None or self._cleanup_task.done():
            self._cleanup_task = asyncio.create_task(self._cleanup_inactive_streams())

    async def _cleanup_inactive_streams(self) -> None:
        """
        Periodically check for and clean up inactive streams.
        Runs in the background and removes streams that haven't been accessed recently.
        """
        while True:
            try:
                await asyncio.sleep(30)  # Check every 30 seconds

                if not self.active_streams:
                    # No streams to monitor, stop the task
                    logger.debug("No active DASH streams to monitor, stopping cleanup task")
                    return

                current_time = time.time()
                streams_to_remove = []

                for mpd_url, stream_info in self.active_streams.items():
                    last_access = stream_info.get("last_access", 0)
                    time_since_access = current_time - last_access

                    if time_since_access > self.inactivity_timeout:
                        streams_to_remove.append(mpd_url)
                        logger.info(
                            f"Cleaning up inactive DASH stream ({time_since_access:.0f}s idle): {mpd_url[:60]}..."
                        )

                # Remove inactive streams
                for mpd_url in streams_to_remove:
                    self.active_streams.pop(mpd_url, None)
                    # Cancel any prefetch tasks for this stream
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
        return self.stats.to_dict()

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
        logger.info("DASH pre-buffer state cleared")

    async def close(self) -> None:
        """Close the pre-buffer system."""
        self.clear_cache()
        await self.client.aclose()


# Global DASH pre-buffer instance
dash_prebuffer = DASHPreBuffer()
