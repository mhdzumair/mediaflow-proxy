import asyncio
import logging
import psutil
from typing import Dict, Optional, List
from urllib.parse import urlparse
import httpx
from mediaflow_proxy.utils.http_utils import create_httpx_client
from mediaflow_proxy.configs import settings

logger = logging.getLogger(__name__)


class HLSPreBuffer:
    """
    Pre-buffer system for HLS streams to reduce latency and improve streaming performance.
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
        self.segment_cache: Dict[str, bytes] = {}
        self.segment_urls: Dict[str, List[str]] = {}
        self.client = create_httpx_client()
        
    async def prebuffer_playlist(self, playlist_url: str, headers: Dict[str, str]) -> None:
        """
        Pre-buffer segments from an HLS playlist.
        
        Args:
            playlist_url (str): URL of the HLS playlist
            headers (Dict[str, str]): Headers to use for requests
        """
        try:
            logger.debug(f"Starting pre-buffer for playlist: {playlist_url}")
            
            # Download and parse playlist
            response = await self.client.get(playlist_url, headers=headers)
            response.raise_for_status()
            playlist_content = response.text
            
            # Check if this is a master playlist (contains variants)
            if "#EXT-X-STREAM-INF" in playlist_content:
                logger.debug(f"Master playlist detected, finding first variant")
                # Extract variant URLs
                variant_urls = self._extract_variant_urls(playlist_content, playlist_url)
                if variant_urls:
                    # Pre-buffer the first variant
                    first_variant_url = variant_urls[0]
                    logger.debug(f"Pre-buffering first variant: {first_variant_url}")
                    await self.prebuffer_playlist(first_variant_url, headers)
                else:
                    logger.warning("No variants found in master playlist")
                return
            
            # Extract segment URLs
            segment_urls = self._extract_segment_urls(playlist_content, playlist_url)
            
            # Store segment URLs for this playlist
            self.segment_urls[playlist_url] = segment_urls
            
            # Pre-buffer first few segments
            await self._prebuffer_segments(segment_urls[:self.prebuffer_segments], headers)
            
            logger.info(f"Pre-buffered {min(self.prebuffer_segments, len(segment_urls))} segments for {playlist_url}")
            
        except Exception as e:
            logger.warning(f"Failed to pre-buffer playlist {playlist_url}: {e}")
    
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
        
        logger.debug(f"Analyzing playlist with {len(lines)} lines")
        
        for line in lines:
            line = line.strip()
            if line and not line.startswith('#'):
                # Check if line contains a URL (http/https) or is a relative path
                if 'http://' in line or 'https://' in line:
                    segment_urls.append(line)
                    logger.debug(f"Found absolute URL: {line}")
                elif line and not line.startswith('#'):
                    # This might be a relative path to a segment
                    parsed_base = urlparse(base_url)
                    # Ensure proper path joining
                    if line.startswith('/'):
                        segment_url = f"{parsed_base.scheme}://{parsed_base.netloc}{line}"
                    else:
                        # Get the directory path from base_url
                        base_path = parsed_base.path.rsplit('/', 1)[0] if '/' in parsed_base.path else ''
                        segment_url = f"{parsed_base.scheme}://{parsed_base.netloc}{base_path}/{line}"
                    segment_urls.append(segment_url)
                    logger.debug(f"Found relative path: {line} -> {segment_url}")
        
        logger.debug(f"Extracted {len(segment_urls)} segment URLs from playlist")
        if segment_urls:
            logger.debug(f"First segment URL: {segment_urls[0]}")
        else:
            logger.debug("No segment URLs found in playlist")
            # Log first few lines for debugging
            for i, line in enumerate(lines[:10]):
                logger.debug(f"Line {i}: {line}")
        
        return segment_urls
    
    def _extract_variant_urls(self, playlist_content: str, base_url: str) -> List[str]:
        """
        Extract variant URLs from master playlist content.
        
        Args:
            playlist_content (str): Content of the master playlist
            base_url (str): Base URL for resolving relative URLs
            
        Returns:
            List[str]: List of variant URLs
        """
        variant_urls = []
        lines = playlist_content.split('\n')
        
        for line in lines:
            line = line.strip()
            if line and not line.startswith('#') and ('http://' in line or 'https://' in line):
                # Resolve relative URLs
                if line.startswith('http'):
                    variant_urls.append(line)
                else:
                    # Join with base URL for relative paths
                    parsed_base = urlparse(base_url)
                    variant_url = f"{parsed_base.scheme}://{parsed_base.netloc}{line}"
                    variant_urls.append(variant_url)
        
        logger.debug(f"Extracted {len(variant_urls)} variant URLs from master playlist")
        if variant_urls:
            logger.debug(f"First variant URL: {variant_urls[0]}")
        
        return variant_urls
    
    async def _prebuffer_segments(self, segment_urls: List[str], headers: Dict[str, str]) -> None:
        """
        Pre-buffer specific segments.
        
        Args:
            segment_urls (List[str]): List of segment URLs to pre-buffer
            headers (Dict[str, str]): Headers to use for requests
        """
        tasks = []
        for url in segment_urls:
            if url not in self.segment_cache:
                tasks.append(self._download_segment(url, headers))
        
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
    
    def _get_memory_usage_percent(self) -> float:
        """
        Get current memory usage percentage.
        
        Returns:
            float: Memory usage percentage
        """
        try:
            memory = psutil.virtual_memory()
            return memory.percent
        except Exception as e:
            logger.warning(f"Failed to get memory usage: {e}")
            return 0.0
    
    def _check_memory_threshold(self) -> bool:
        """
        Check if memory usage exceeds the emergency threshold.
        
        Returns:
            bool: True if emergency cleanup is needed
        """
        memory_percent = self._get_memory_usage_percent()
        return memory_percent > self.emergency_threshold
    
    def _emergency_cache_cleanup(self) -> None:
        """
        Perform emergency cache cleanup when memory usage is high.
        """
        if self._check_memory_threshold():
            logger.warning("Emergency cache cleanup triggered due to high memory usage")
            # Clear 50% of cache
            cache_size = len(self.segment_cache)
            keys_to_remove = list(self.segment_cache.keys())[:cache_size // 2]
            for key in keys_to_remove:
                del self.segment_cache[key]
            logger.info(f"Emergency cleanup removed {len(keys_to_remove)} segments from cache")
    
    async def _download_segment(self, segment_url: str, headers: Dict[str, str]) -> None:
        """
        Download a single segment and cache it.
        
        Args:
            segment_url (str): URL of the segment to download
            headers (Dict[str, str]): Headers to use for request
        """
        try:
            # Check memory usage before downloading
            memory_percent = self._get_memory_usage_percent()
            if memory_percent > self.max_memory_percent:
                logger.warning(f"Memory usage {memory_percent}% exceeds limit {self.max_memory_percent}%, skipping download")
                return
            
            response = await self.client.get(segment_url, headers=headers)
            response.raise_for_status()
            
            # Cache the segment
            self.segment_cache[segment_url] = response.content
            
            # Check for emergency cleanup
            if self._check_memory_threshold():
                self._emergency_cache_cleanup()
            # Maintain cache size
            elif len(self.segment_cache) > self.max_cache_size:
                # Remove oldest entries (simple FIFO)
                oldest_key = next(iter(self.segment_cache))
                del self.segment_cache[oldest_key]
                
            logger.debug(f"Cached segment: {segment_url}")
            
        except Exception as e:
            logger.warning(f"Failed to download segment {segment_url}: {e}")
    
    async def get_segment(self, segment_url: str, headers: Dict[str, str]) -> Optional[bytes]:
        """
        Get a segment from cache or download it.
        
        Args:
            segment_url (str): URL of the segment
            headers (Dict[str, str]): Headers to use for request
            
        Returns:
            Optional[bytes]: Cached segment data or None if not available
        """
        # Check cache first
        if segment_url in self.segment_cache:
            logger.debug(f"Cache hit for segment: {segment_url}")
            return self.segment_cache[segment_url]
        
        # Check memory usage before downloading
        memory_percent = self._get_memory_usage_percent()
        if memory_percent > self.max_memory_percent:
            logger.warning(f"Memory usage {memory_percent}% exceeds limit {self.max_memory_percent}%, skipping download")
            return None
        
        # Download if not in cache
        try:
            response = await self.client.get(segment_url, headers=headers)
            response.raise_for_status()
            segment_data = response.content
            
            # Cache the segment
            self.segment_cache[segment_url] = segment_data
            
            # Check for emergency cleanup
            if self._check_memory_threshold():
                self._emergency_cache_cleanup()
            # Maintain cache size
            elif len(self.segment_cache) > self.max_cache_size:
                oldest_key = next(iter(self.segment_cache))
                del self.segment_cache[oldest_key]
            
            logger.debug(f"Downloaded and cached segment: {segment_url}")
            return segment_data
            
        except Exception as e:
            logger.warning(f"Failed to get segment {segment_url}: {e}")
            return None
    
    async def prebuffer_next_segments(self, playlist_url: str, current_segment_index: int, headers: Dict[str, str]) -> None:
        """
        Pre-buffer next segments based on current playback position.
        
        Args:
            playlist_url (str): URL of the playlist
            current_segment_index (int): Index of current segment
            headers (Dict[str, str]): Headers to use for requests
        """
        if playlist_url not in self.segment_urls:
            return
        
        segment_urls = self.segment_urls[playlist_url]
        next_segments = segment_urls[current_segment_index + 1:current_segment_index + 1 + self.prebuffer_segments]
        
        if next_segments:
            await self._prebuffer_segments(next_segments, headers)
    
    def clear_cache(self) -> None:
        """Clear the segment cache."""
        self.segment_cache.clear()
        self.segment_urls.clear()
        logger.info("HLS pre-buffer cache cleared")
    
    async def close(self) -> None:
        """Close the pre-buffer system."""
        await self.client.aclose()


# Global pre-buffer instance
hls_prebuffer = HLSPreBuffer() 