import asyncio
import logging
import time
import psutil
from dataclasses import dataclass, field
from typing import Dict, Optional, List, Set
from urllib.parse import urljoin

from mediaflow_proxy.utils.http_utils import create_httpx_client, download_file_with_retry
from mediaflow_proxy.utils.cache_utils import get_cached_segment, set_cached_segment
from mediaflow_proxy.configs import settings

logger = logging.getLogger(__name__)


@dataclass
class HLSPrebufferStats:
    """Statistics for HLS prebuffer performance tracking."""
    cache_hits: int = 0
    cache_misses: int = 0
    segments_prebuffered: int = 0
    bytes_prebuffered: int = 0
    prefetch_triggered: int = 0
    playlists_tracked: int = 0
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
        self.playlists_tracked = 0
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
            "playlists_tracked": self.playlists_tracked,
            "uptime_seconds": int(time.time() - self.last_reset),
        }


class HLSPreBuffer:
    """
    Pre-buffer system for HLS streams to reduce latency and improve streaming performance.
    Uses the shared SEGMENT_CACHE for consistent caching across the application.
    
    Features:
    - Initial prebuffering when playlist is first requested
    - Continuous prefetching triggered on each segment request
    - Automatic playlist refresh for live streams
    - Cache statistics and monitoring
    """
    
    def __init__(self, max_cache_size: Optional[int] = None, prebuffer_segments: Optional[int] = None):
        """
        Initialize the HLS pre-buffer system.
        
        Args:
            max_cache_size (int): Maximum number of segments to cache (uses config if None)
            prebuffer_segments (int): Number of segments to pre-buffer ahead (uses config if None)
        """
        self.max_cache_size = max_cache_size or settings.hls_prebuffer_cache_size
        self.prebuffer_segments = prebuffer_segments or settings.hls_prebuffer_segments
        self.max_memory_percent = settings.hls_prebuffer_max_memory_percent
        self.emergency_threshold = settings.hls_prebuffer_emergency_threshold
        self.segment_ttl = 60  # Segment cache TTL in seconds
        self.inactivity_timeout = settings.hls_prebuffer_inactivity_timeout  # Seconds before stopping refresh
        
        # Track playlist -> segment URLs mapping
        self.segment_urls: Dict[str, List[str]] = {}
        
        # Reverse mapping: segment URL -> (playlist_url, index)
        self.segment_to_playlist: Dict[str, tuple] = {}
        
        # Playlist state: {headers, last_access, refresh_task, target_duration, is_live}
        self.playlist_state: Dict[str, dict] = {}
        
        # Track URLs being downloaded to avoid duplicates
        self._downloading: Set[str] = set()
        self._download_lock = asyncio.Lock()
        
        # Statistics
        self.stats = HLSPrebufferStats()
        
        self.client = create_httpx_client()
    
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
    
    def record_cache_hit(self) -> None:
        """Record a cache hit for statistics."""
        self.stats.cache_hits += 1
    
    def record_cache_miss(self) -> None:
        """Record a cache miss for statistics."""
        self.stats.cache_misses += 1
    
    def log_stats(self) -> None:
        """Log current prebuffer statistics."""
        logger.info(f"HLS Prebuffer Stats: {self.stats.to_dict()}")
    
    def _parse_target_duration(self, playlist_content: str) -> Optional[int]:
        """Parse EXT-X-TARGETDURATION from a media playlist."""
        for line in playlist_content.splitlines():
            line = line.strip()
            if line.startswith("#EXT-X-TARGETDURATION:"):
                try:
                    value = line.split(":", 1)[1].strip()
                    return int(float(value))
                except Exception:
                    return None
        return None
    
    def _is_live_playlist(self, playlist_content: str) -> bool:
        """Check if playlist is live (no EXT-X-ENDLIST tag)."""
        return "#EXT-X-ENDLIST" not in playlist_content
    
    def _extract_segment_urls(self, playlist_content: str, base_url: str) -> List[str]:
        """
        Extract segment URLs from HLS playlist content.
        
        Args:
            playlist_content (str): Content of the HLS playlist
            base_url (str): Base URL for resolving relative URLs
            
        Returns:
            List[str]: List of segment URLs
        """
        segment_urls = []
        lines = playlist_content.split('\n')
        
        for line in lines:
            line = line.strip()
            if line and not line.startswith('#'):
                # Absolute URL
                if line.startswith('http://') or line.startswith('https://'):
                    segment_urls.append(line)
                else:
                    # Relative URL - resolve against base
                    segment_url = urljoin(base_url, line)
                    segment_urls.append(segment_url)
        
        logger.debug(f"Extracted {len(segment_urls)} segment URLs from playlist")
        return segment_urls
    
    def _extract_variant_urls(self, playlist_content: str, base_url: str) -> List[str]:
        """
        Extract variant playlist URLs from master playlist.
        
        Args:
            playlist_content (str): Content of the master playlist
            base_url (str): Base URL for resolving relative URLs
            
        Returns:
            List[str]: List of variant playlist URLs
        """
        variant_urls = []
        lines = [line.strip() for line in playlist_content.split('\n')]
        take_next_uri = False
        
        for line in lines:
            if line.startswith("#EXT-X-STREAM-INF"):
                take_next_uri = True
                continue
            if take_next_uri:
                take_next_uri = False
                if line and not line.startswith('#'):
                    variant_urls.append(urljoin(base_url, line))
        
        logger.debug(f"Extracted {len(variant_urls)} variant URLs from master playlist")
        return variant_urls
    
    async def prebuffer_playlist(self, playlist_url: str, headers: Dict[str, str], start_refresh: bool = False) -> None:
        """
        Pre-buffer segments from an HLS playlist.
        
        This method only does initial segment parsing and optional prebuffering.
        The refresh loop is NOT started here - it's started when segments are actually requested
        via get_segment() or prebuffer_from_segment().
        
        Args:
            playlist_url (str): URL of the HLS playlist
            headers (Dict[str, str]): Headers to use for requests
            start_refresh (bool): Whether to start the refresh loop (only True when called from segment request)
        """
        try:
            # Skip if already tracking this playlist (avoid duplicate prebuffering)
            if playlist_url in self.playlist_state:
                logger.debug(f"Playlist already being tracked, skipping: {playlist_url}")
                return
            
            logger.debug(f"Starting pre-buffer for playlist: {playlist_url}")
            
            # Download playlist
            playlist_content = await download_file_with_retry(playlist_url, headers)
            if not playlist_content:
                logger.warning(f"Failed to download playlist: {playlist_url}")
                return
            
            playlist_text = playlist_content.decode('utf-8', errors='ignore')
            
            # Check if master playlist - don't prebuffer variants automatically
            # Let the player choose which variant to use
            if "#EXT-X-STREAM-INF" in playlist_text:
                logger.debug("Master playlist detected, not prebuffering variants (will prebuffer when player requests)")
                return
            
            # Media playlist - extract segments
            segment_urls = self._extract_segment_urls(playlist_text, playlist_url)
            if not segment_urls:
                logger.warning(f"No segments found in playlist: {playlist_url}")
                return
            
            # Store segment URLs and build reverse mapping
            self.segment_urls[playlist_url] = segment_urls
            for idx, url in enumerate(segment_urls):
                self.segment_to_playlist[url] = (playlist_url, idx)
            
            # Determine if live
            is_live = self._is_live_playlist(playlist_text)
            target_duration = self._parse_target_duration(playlist_text) or 6
            
            # For live streams, prebuffer from the END (most recent)
            # For VOD, prebuffer from the beginning
            if is_live:
                segments_to_buffer = segment_urls[-self.prebuffer_segments:]
            else:
                segments_to_buffer = segment_urls[:self.prebuffer_segments]
            
            # Prebuffer segments
            await self._prebuffer_segments(segments_to_buffer, headers)
            
            logger.info(f"Pre-buffered {len(segments_to_buffer)} segments for {playlist_url} (live={is_live})")
            self.stats.playlists_tracked += 1
            
            # Store playlist state (but don't start refresh loop unless explicitly requested)
            self.playlist_state[playlist_url] = {
                "headers": headers,
                "last_access": time.time(),
                "refresh_task": None,
                "target_duration": target_duration,
                "is_live": is_live,
            }
            
            # Only start refresh loop if explicitly requested (i.e., when segment is being played)
            if start_refresh and is_live:
                self._start_refresh_loop(playlist_url, headers, target_duration)
            
        except Exception as e:
            logger.warning(f"Failed to pre-buffer playlist {playlist_url}: {e}")
    
    def _start_refresh_loop(self, playlist_url: str, headers: Dict[str, str], target_duration: int) -> None:
        """Start the refresh loop for a live playlist if not already running."""
        state = self.playlist_state.get(playlist_url)
        if not state:
            return
        
        if not state.get("refresh_task") or state["refresh_task"].done():
            task = asyncio.create_task(
                self._refresh_playlist_loop(playlist_url, headers, target_duration)
            )
            state["refresh_task"] = task
            logger.debug(f"Started refresh loop for: {playlist_url}")
    
    async def _prebuffer_segments(self, segment_urls: List[str], headers: Dict[str, str]) -> None:
        """
        Pre-buffer a list of segments.
        
        Args:
            segment_urls: List of segment URLs to prebuffer
            headers: Headers to use for requests
        """
        # Check memory before starting
        if self._get_memory_usage_percent() > self.max_memory_percent:
            logger.warning("Memory usage too high, skipping prebuffer")
            return
        
        tasks = []
        for url in segment_urls:
            tasks.append(self._download_and_cache_segment(url, headers))
        
        if tasks:
            # Use semaphore to limit concurrent downloads
            semaphore = asyncio.Semaphore(5)
            
            async def limited_task(task):
                async with semaphore:
                    return await task
            
            await asyncio.gather(*[limited_task(t) for t in tasks], return_exceptions=True)
    
    async def _download_and_cache_segment(self, segment_url: str, headers: Dict[str, str]) -> None:
        """Download and cache a segment using the shared cache."""
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
                await set_cached_segment(segment_url, content, ttl=self.segment_ttl)
                self.stats.segments_prebuffered += 1
                self.stats.bytes_prebuffered += len(content)
                logger.debug(f"Prebuffered HLS segment ({len(content)} bytes): {segment_url}")
        except Exception as e:
            logger.warning(f"Failed to prebuffer segment {segment_url}: {e}")
        finally:
            async with self._download_lock:
                self._downloading.discard(segment_url)
    
    async def get_segment(self, segment_url: str, headers: Dict[str, str]) -> Optional[bytes]:
        """
        Get a segment from cache or download it.
        
        Args:
            segment_url: URL of the segment
            headers: Headers to use for request
            
        Returns:
            Segment data if available, None otherwise
        """
        # Check cache first
        cached = await get_cached_segment(segment_url)
        if cached:
            self.record_cache_hit()
            logger.info(f"HLS Segment cache HIT: {segment_url.split('/')[-1]}")
            
            # Update last access time for playlist and ensure refresh loop is running
            mapping = self.segment_to_playlist.get(segment_url)
            if mapping:
                playlist_url = mapping[0]
                state = self.playlist_state.get(playlist_url)
                if state:
                    state["last_access"] = time.time()
                    # Start refresh loop if this is a live stream and not already running
                    if state.get("is_live") and (not state.get("refresh_task") or state["refresh_task"].done()):
                        self._start_refresh_loop(playlist_url, headers, state.get("target_duration", 6))
            
            return cached
        
        self.record_cache_miss()
        
        # Download and cache
        try:
            content = await download_file_with_retry(segment_url, headers)
            if content:
                await set_cached_segment(segment_url, content, ttl=self.segment_ttl)
                return content
        except Exception as e:
            logger.warning(f"Failed to get segment {segment_url}: {e}")
        
        return None
    
    async def prebuffer_from_segment(self, segment_url: str, headers: Dict[str, str]) -> None:
        """
        Trigger prebuffering of next segments based on current segment.
        This is called when a segment is actually being played, so we start the refresh loop here.
        
        Args:
            segment_url: URL of the current segment
            headers: Headers to use for requests
        """
        self.stats.prefetch_triggered += 1
        
        mapping = self.segment_to_playlist.get(segment_url)
        if not mapping:
            return
        
        playlist_url, current_index = mapping
        
        # Update last access time and ensure refresh loop is running
        state = self.playlist_state.get(playlist_url)
        if state:
            state["last_access"] = time.time()
            # Start refresh loop if this is a live stream and not already running
            if state.get("is_live") and (not state.get("refresh_task") or state["refresh_task"].done()):
                self._start_refresh_loop(playlist_url, headers, state.get("target_duration", 6))
        
        # Get segment list
        segment_list = self.segment_urls.get(playlist_url, [])
        if not segment_list:
            return
        
        # Prebuffer next N segments
        start_index = current_index + 1
        end_index = min(start_index + self.prebuffer_segments, len(segment_list))
        next_segments = segment_list[start_index:end_index]
        
        if next_segments:
            logger.debug(f"Prefetching {len(next_segments)} upcoming HLS segments")
            asyncio.create_task(self._prebuffer_segments(next_segments, headers))
    
    async def prebuffer_next_segments(
        self, playlist_url: str, current_segment_index: int, headers: Dict[str, str]
    ) -> None:
        """
        Pre-buffer next segments based on current playback position.
        
        Args:
            playlist_url: URL of the playlist
            current_segment_index: Index of current segment
            headers: Headers to use for requests
        """
        segment_list = self.segment_urls.get(playlist_url, [])
        if not segment_list:
            return
        
        start_index = current_segment_index + 1
        end_index = min(start_index + self.prebuffer_segments, len(segment_list))
        next_segments = segment_list[start_index:end_index]
        
        if next_segments:
            await self._prebuffer_segments(next_segments, headers)
    
    async def _refresh_playlist_loop(
        self, playlist_url: str, headers: Dict[str, str], target_duration: int
    ) -> None:
        """
        Periodically refresh a live playlist to track new segments.
        Only prebuffers new segments if there's been recent activity.
        
        Args:
            playlist_url: URL of the playlist
            headers: Headers to use for requests
            target_duration: Target segment duration for refresh interval
        """
        sleep_interval = max(2, min(15, target_duration))
        
        while True:
            try:
                state = self.playlist_state.get(playlist_url)
                if not state:
                    logger.info(f"HLS prebuffer: playlist state removed, stopping refresh: {playlist_url}")
                    return
                
                last_access = state.get("last_access", 0)
                time_since_access = time.time() - last_access
                
                # Check for inactivity - use configurable timeout
                if time_since_access > self.inactivity_timeout:
                    logger.info(f"Stopping HLS prebuffer for inactive playlist ({time_since_access:.0f}s idle): {playlist_url}")
                    self._cleanup_playlist(playlist_url)
                    return
                
                # Only refresh and prebuffer if there's been recent activity (within 2x target duration)
                # This prevents unnecessary fetching when stream is paused/stopped
                recent_activity = time_since_access < (target_duration * 2)
                
                if not recent_activity:
                    # Just wait, don't fetch anything
                    await asyncio.sleep(sleep_interval)
                    continue
                
                # Refresh playlist
                playlist_content = await download_file_with_retry(playlist_url, headers)
                if not playlist_content:
                    await asyncio.sleep(sleep_interval)
                    continue
                
                playlist_text = playlist_content.decode('utf-8', errors='ignore')
                
                # Update target duration if changed
                new_target = self._parse_target_duration(playlist_text)
                if new_target:
                    sleep_interval = max(2, min(15, new_target))
                
                # Extract new segment URLs
                new_urls = self._extract_segment_urls(playlist_text, playlist_url)
                if new_urls:
                    old_urls = set(self.segment_urls.get(playlist_url, []))
                    self.segment_urls[playlist_url] = new_urls
                    
                    # Update reverse mapping
                    for idx, url in enumerate(new_urls):
                        self.segment_to_playlist[url] = (playlist_url, idx)
                    
                    # Find new segments and prebuffer them (only if recently active)
                    new_segment_urls = [u for u in new_urls if u not in old_urls]
                    if new_segment_urls and recent_activity:
                        # Prebuffer the most recent new segments
                        segments_to_buffer = new_segment_urls[-self.prebuffer_segments:]
                        asyncio.create_task(self._prebuffer_segments(segments_to_buffer, headers))
                        logger.debug(f"Prebuffering {len(segments_to_buffer)} new segments for {playlist_url}")
                
            except Exception as e:
                logger.debug(f"Playlist refresh error for {playlist_url}: {e}")
            
            await asyncio.sleep(sleep_interval)
    
    def _cleanup_playlist(self, playlist_url: str) -> None:
        """Clean up state for a playlist."""
        # Remove segment mappings
        urls = self.segment_urls.pop(playlist_url, [])
        for url in urls:
            self.segment_to_playlist.pop(url, None)
        
        # Remove playlist state
        state = self.playlist_state.pop(playlist_url, None)
        if state and state.get("refresh_task"):
            state["refresh_task"].cancel()
    
    def get_stats(self) -> dict:
        """Get current prebuffer statistics."""
        return self.stats.to_dict()
    
    def clear_cache(self) -> None:
        """Clear all prebuffer state and log final stats."""
        self.log_stats()
        
        # Cancel all refresh tasks
        for state in self.playlist_state.values():
            if state.get("refresh_task"):
                state["refresh_task"].cancel()
        
        self.segment_urls.clear()
        self.segment_to_playlist.clear()
        self.playlist_state.clear()
        self.stats.reset()
        
        logger.info("HLS pre-buffer state cleared")
    
    async def close(self) -> None:
        """Close the pre-buffer system."""
        self.clear_cache()
        await self.client.aclose()


# Global HLS pre-buffer instance
hls_prebuffer = HLSPreBuffer()
