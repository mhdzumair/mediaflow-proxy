"""
Base prebuffer class with shared functionality for HLS and DASH prebuffering.

This module provides cross-process download coordination using Redis-based locking
to prevent duplicate downloads across multiple uvicorn workers. Both player requests
and background prebuffer tasks use the same coordination mechanism.
"""

import asyncio
import logging
import time
import psutil
from abc import ABC
from dataclasses import dataclass, field
from typing import Dict, Optional

from mediaflow_proxy.utils.cache_utils import (
    get_cached_segment,
    set_cached_segment,
)
from mediaflow_proxy.utils.http_utils import download_file_with_retry
from mediaflow_proxy.utils import redis_utils

logger = logging.getLogger(__name__)


@dataclass
class PrebufferStats:
    """Statistics for prebuffer performance tracking."""

    cache_hits: int = 0
    cache_misses: int = 0
    segments_prebuffered: int = 0
    bytes_prebuffered: int = 0
    prefetch_triggered: int = 0
    downloads_coordinated: int = 0  # Times we waited for existing download
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
        self.bytes_prebuffered = 0
        self.prefetch_triggered = 0
        self.downloads_coordinated = 0
        self.last_reset = time.time()

    def to_dict(self) -> dict:
        """Convert stats to dictionary for logging."""
        return {
            "cache_hits": self.cache_hits,
            "cache_misses": self.cache_misses,
            "hit_rate": f"{self.hit_rate:.1f}%",
            "segments_prebuffered": self.segments_prebuffered,
            "bytes_prebuffered_mb": f"{self.bytes_prebuffered / 1024 / 1024:.2f}",
            "prefetch_triggered": self.prefetch_triggered,
            "downloads_coordinated": self.downloads_coordinated,
            "uptime_seconds": int(time.time() - self.last_reset),
        }


class BasePrebuffer(ABC):
    """
    Base class for prebuffer systems with cross-process download coordination.

    This class provides:
    - Cross-process coordination using Redis locks to prevent duplicate downloads
    - Memory usage monitoring
    - Cache statistics tracking
    - Shared download and caching logic

    The Redis-based locking ensures that even with multiple uvicorn workers,
    only one worker downloads any given segment at a time.

    Subclasses should implement protocol-specific logic (HLS playlist parsing,
    DASH MPD handling, etc.) while inheriting the core download coordination.
    """

    def __init__(
        self,
        max_cache_size: int,
        prebuffer_segments: int,
        max_memory_percent: float,
        emergency_threshold: float,
        segment_ttl: int = 60,
        prebuffer_lock_timeout: float = 1.0,
    ):
        """
        Initialize the base prebuffer.

        Args:
            max_cache_size: Maximum number of segments to track
            prebuffer_segments: Number of segments to pre-buffer ahead
            max_memory_percent: Maximum memory usage percentage before skipping prebuffer
            emergency_threshold: Memory threshold for emergency cleanup
            segment_ttl: TTL for cached segments in seconds
            prebuffer_lock_timeout: Lock acquisition timeout (seconds) for background prebuffer tasks
        """
        self.max_cache_size = max_cache_size
        self.prebuffer_segment_count = prebuffer_segments
        self.max_memory_percent = max_memory_percent
        self.emergency_threshold = emergency_threshold
        self.segment_ttl = segment_ttl
        self.prebuffer_lock_timeout = prebuffer_lock_timeout

        # Statistics (per-worker, not shared - but that's fine for monitoring)
        self.stats = PrebufferStats()

        # Stats logging task
        self._stats_task: Optional[asyncio.Task] = None
        self._stats_interval = 60  # Log stats every 60 seconds

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
        return self._get_memory_usage_percent() > self.emergency_threshold

    def _should_skip_for_memory(self) -> bool:
        """Check if we should skip prebuffering due to high memory usage."""
        return self._get_memory_usage_percent() > self.max_memory_percent

    def record_cache_hit(self) -> None:
        """Record a cache hit for statistics."""
        self.stats.cache_hits += 1
        self._ensure_stats_logging()

    def record_cache_miss(self) -> None:
        """Record a cache miss for statistics."""
        self.stats.cache_misses += 1
        self._ensure_stats_logging()

    def _ensure_stats_logging(self) -> None:
        """Ensure the stats logging task is running."""
        if self._stats_task is None or self._stats_task.done():
            self._stats_task = asyncio.create_task(self._periodic_stats_logging())

    async def _periodic_stats_logging(self) -> None:
        """Periodically log prebuffer statistics."""
        while True:
            try:
                await asyncio.sleep(self._stats_interval)

                # Only log if there's been activity
                if self.stats.cache_hits > 0 or self.stats.cache_misses > 0:
                    self.log_stats()
            except asyncio.CancelledError:
                return
            except Exception as e:
                logger.warning(f"Error in stats logging: {e}")

    async def get_or_download(
        self,
        url: str,
        headers: Dict[str, str],
        timeout: float = 10.0,
    ) -> Optional[bytes]:
        """
        Get a segment from cache or download it, with cross-process coordination.

        This is the primary method for getting segments. It:
        1. Checks cache first (immediate return if hit)
        2. Acquires Redis lock to prevent duplicate downloads across workers
        3. Double-checks cache after acquiring lock
        4. Downloads and caches if needed

        The Redis-based locking ensures that even with multiple uvicorn workers,
        only one worker downloads any given segment at a time.

        Args:
            url: URL of the segment to get
            headers: Headers to use for the request
            timeout: Maximum time to wait for lock acquisition (seconds).
                     Keep this short (10s) for player requests - if lock is held
                     too long, fall back to direct streaming.

        Returns:
            Segment data if successful, None if failed or timed out
        """
        self._ensure_stats_logging()

        # Check cache first (Redis cache is shared across workers)
        cached = await get_cached_segment(url)
        if cached:
            self.record_cache_hit()
            logger.info(f"[get_or_download] CACHE HIT ({len(cached)} bytes): {url}")
            return cached

        # Cache miss - need to coordinate download across workers
        logger.info(f"[get_or_download] CACHE MISS: {url}")

        lock_key = f"segment_download:{url}"
        lock_acquired = False

        try:
            # Acquire Redis lock - only one worker downloads at a time
            lock_acquired = await redis_utils.acquire_lock(lock_key, ttl=30, timeout=timeout)

            if not lock_acquired:
                logger.warning(f"[get_or_download] Lock TIMEOUT ({timeout}s), falling back to streaming: {url}")
                return None

            # Double-check cache after acquiring lock
            # Another worker may have completed the download while we waited
            cached = await get_cached_segment(url)
            if cached:
                # Count this as a cache hit since we didn't download
                self.record_cache_hit()
                self.stats.downloads_coordinated += 1
                logger.info(f"[get_or_download] Found in cache after lock (coordinated): {url}")
                return cached

            # We're the one who needs to download - count as miss now
            self.record_cache_miss()

            # We're the first - download and cache
            logger.info(f"[get_or_download] Downloading: {url}")
            content = await self._download_and_cache(url, headers)
            return content

        except Exception as e:
            logger.warning(f"[get_or_download] Error during download coordination: {e}")
            return None
        finally:
            if lock_acquired:
                await redis_utils.release_lock(lock_key)

    async def _download_and_cache(
        self,
        url: str,
        headers: Dict[str, str],
    ) -> Optional[bytes]:
        """
        Download a segment and cache it.

        This method should only be called while holding the Redis lock.

        Args:
            url: URL to download
            headers: Headers for the request

        Returns:
            Downloaded content if successful, None otherwise
        """
        try:
            content = await download_file_with_retry(url, headers)
            if content:
                logger.info(f"[_download_and_cache] Downloaded {len(content)} bytes, caching: {url}")
                await set_cached_segment(url, content, ttl=self.segment_ttl)
                self.stats.segments_prebuffered += 1
                self.stats.bytes_prebuffered += len(content)
                return content
            else:
                logger.warning(f"[_download_and_cache] Download returned empty: {url}")
                return None
        except Exception as e:
            logger.warning(f"[_download_and_cache] Failed to download: {url} - {e}")
            return None

    async def try_get_cached(self, url: str) -> Optional[bytes]:
        """
        Check cache only, don't download.

        Use this for background prebuffer tasks that shouldn't block
        if segment isn't available yet.

        Args:
            url: URL to check in cache

        Returns:
            Cached data if available, None otherwise
        """
        return await get_cached_segment(url)

    async def prebuffer_segment(self, url: str, headers: Dict[str, str]) -> None:
        """
        Prebuffer a single segment in the background.

        This method uses Redis locking to prevent duplicate downloads
        across multiple workers.

        Args:
            url: URL of segment to prebuffer
            headers: Headers for the request
        """
        if self._should_skip_for_memory():
            logger.debug("Skipping prebuffer due to high memory usage")
            return

        # Check if already cached
        cached = await get_cached_segment(url)
        if cached:
            logger.debug(f"[prebuffer_segment] Already cached, skipping: {url}")
            return

        lock_key = f"segment_download:{url}"
        lock_acquired = False

        try:
            # Try to acquire lock with short timeout for prebuffering
            # If lock is held by another process, skip this segment
            lock_acquired = await redis_utils.acquire_lock(lock_key, ttl=30, timeout=self.prebuffer_lock_timeout)

            if not lock_acquired:
                # Another process is downloading, skip this segment
                logger.debug(f"[prebuffer_segment] Lock busy, skipping: {url}")
                return

            # Double-check cache after acquiring lock
            cached = await get_cached_segment(url)
            if cached:
                logger.debug(f"[prebuffer_segment] Found in cache after lock: {url}")
                return

            # Download and cache
            logger.info(f"[prebuffer_segment] Downloading: {url}")
            await self._download_and_cache(url, headers)

        except Exception as e:
            logger.warning(f"[prebuffer_segment] Error: {e}")
        finally:
            if lock_acquired:
                await redis_utils.release_lock(lock_key)

    async def prebuffer_segments_batch(
        self,
        urls: list,
        headers: Dict[str, str],
        max_concurrent: int = 2,
    ) -> None:
        """
        Prebuffer multiple segments with concurrency control.

        Args:
            urls: List of segment URLs to prebuffer
            headers: Headers for requests
            max_concurrent: Maximum concurrent downloads (default 2 to avoid
                           lock contention with player requests)
        """
        if self._should_skip_for_memory():
            logger.warning("Skipping prebuffer due to high memory usage")
            return

        semaphore = asyncio.Semaphore(max_concurrent)

        async def limited_prebuffer(url: str):
            async with semaphore:
                await self.prebuffer_segment(url, headers)

        # Start all prebuffer tasks
        tasks = [limited_prebuffer(url) for url in urls]
        await asyncio.gather(*tasks, return_exceptions=True)

    def log_stats(self) -> None:
        """Log current prebuffer statistics."""
        logger.info(f"Prebuffer Stats: {self.stats.to_dict()}")
