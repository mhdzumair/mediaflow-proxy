import logging
import psutil
from typing import Dict, Optional, List
from urllib.parse import urljoin
import xmltodict
from mediaflow_proxy.utils.http_utils import create_httpx_client
from mediaflow_proxy.configs import settings

logger = logging.getLogger(__name__)


class DASHPreBuffer:
    """
    Pre-buffer system for DASH streams to reduce latency and improve streaming performance.
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
        
        # Cache for different types of DASH content
        self.segment_cache: Dict[str, bytes] = {}
        self.init_segment_cache: Dict[str, bytes] = {}
        self.manifest_cache: Dict[str, dict] = {}
        
        # Track segment URLs for each adaptation set
        self.adaptation_segments: Dict[str, List[str]] = {}
        self.client = create_httpx_client()
    
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
            logger.warning("Emergency DASH cache cleanup triggered due to high memory usage")
            
            # Clear 50% of segment cache
            segment_cache_size = len(self.segment_cache)
            segment_keys_to_remove = list(self.segment_cache.keys())[:segment_cache_size // 2]
            for key in segment_keys_to_remove:
                del self.segment_cache[key]
            
            # Clear 50% of init segment cache
            init_cache_size = len(self.init_segment_cache)
            init_keys_to_remove = list(self.init_segment_cache.keys())[:init_cache_size // 2]
            for key in init_keys_to_remove:
                del self.init_segment_cache[key]
            
            logger.info(f"Emergency cleanup removed {len(segment_keys_to_remove)} segments and {len(init_keys_to_remove)} init segments from cache")
    
    async def prebuffer_dash_manifest(self, mpd_url: str, headers: Dict[str, str]) -> None:
        """
        Pre-buffer segments from a DASH manifest.
        
        Args:
            mpd_url (str): URL of the DASH manifest
            headers (Dict[str, str]): Headers to use for requests
        """
        try:
            # Download and parse MPD manifest
            response = await self.client.get(mpd_url, headers=headers)
            response.raise_for_status()
            mpd_content = response.text
            
            # Parse MPD XML
            mpd_dict = xmltodict.parse(mpd_content)
            
            # Store manifest in cache
            self.manifest_cache[mpd_url] = mpd_dict
            
            # Extract initialization segments and first few segments
            await self._extract_and_prebuffer_segments(mpd_dict, mpd_url, headers)
            
            logger.info(f"Pre-buffered DASH manifest: {mpd_url}")
            
        except Exception as e:
            logger.warning(f"Failed to pre-buffer DASH manifest {mpd_url}: {e}")
    
    async def _extract_and_prebuffer_segments(self, mpd_dict: dict, base_url: str, headers: Dict[str, str]) -> None:
        """
        Extract and pre-buffer segments from MPD manifest.
        
        Args:
            mpd_dict (dict): Parsed MPD manifest
            base_url (str): Base URL for resolving relative URLs
            headers (Dict[str, str]): Headers to use for requests
        """
        try:
            # Extract Period and AdaptationSet information
            mpd = mpd_dict.get('MPD', {})
            periods = mpd.get('Period', [])
            if not isinstance(periods, list):
                periods = [periods]
            
            for period in periods:
                adaptation_sets = period.get('AdaptationSet', [])
                if not isinstance(adaptation_sets, list):
                    adaptation_sets = [adaptation_sets]
                
                for adaptation_set in adaptation_sets:
                    # Extract initialization segment
                    init_segment = adaptation_set.get('SegmentTemplate', {}).get('@initialization')
                    if init_segment:
                        init_url = urljoin(base_url, init_segment)
                        await self._download_init_segment(init_url, headers)
                    
                    # Extract segment template
                    segment_template = adaptation_set.get('SegmentTemplate', {})
                    if segment_template:
                        await self._prebuffer_template_segments(segment_template, base_url, headers)
                    
                    # Extract segment list
                    segment_list = adaptation_set.get('SegmentList', {})
                    if segment_list:
                        await self._prebuffer_list_segments(segment_list, base_url, headers)
                        
        except Exception as e:
            logger.warning(f"Failed to extract segments from MPD: {e}")
    
    async def _download_init_segment(self, init_url: str, headers: Dict[str, str]) -> None:
        """
        Download and cache initialization segment.
        
        Args:
            init_url (str): URL of the initialization segment
            headers (Dict[str, str]): Headers to use for request
        """
        try:
            # Check memory usage before downloading
            memory_percent = self._get_memory_usage_percent()
            if memory_percent > self.max_memory_percent:
                logger.warning(f"Memory usage {memory_percent}% exceeds limit {self.max_memory_percent}%, skipping init segment download")
                return
            
            response = await self.client.get(init_url, headers=headers)
            response.raise_for_status()
            
            # Cache the init segment
            self.init_segment_cache[init_url] = response.content
            
            # Check for emergency cleanup
            if self._check_memory_threshold():
                self._emergency_cache_cleanup()
            
            logger.debug(f"Cached init segment: {init_url}")
            
        except Exception as e:
            logger.warning(f"Failed to download init segment {init_url}: {e}")
    
    async def _prebuffer_template_segments(self, segment_template: dict, base_url: str, headers: Dict[str, str]) -> None:
        """
        Pre-buffer segments using segment template.
        
        Args:
            segment_template (dict): Segment template from MPD
            base_url (str): Base URL for resolving relative URLs
            headers (Dict[str, str]): Headers to use for requests
        """
        try:
            media_template = segment_template.get('@media')
            if not media_template:
                return
            
            # Extract template parameters
            start_number = int(segment_template.get('@startNumber', 1))
            duration = float(segment_template.get('@duration', 0))
            timescale = float(segment_template.get('@timescale', 1))
            
            # Pre-buffer first few segments
            for i in range(self.prebuffer_segments):
                segment_number = start_number + i
                segment_url = media_template.replace('$Number$', str(segment_number))
                full_url = urljoin(base_url, segment_url)
                
                await self._download_segment(full_url, headers)
                
        except Exception as e:
            logger.warning(f"Failed to pre-buffer template segments: {e}")
    
    async def _prebuffer_list_segments(self, segment_list: dict, base_url: str, headers: Dict[str, str]) -> None:
        """
        Pre-buffer segments from segment list.
        
        Args:
            segment_list (dict): Segment list from MPD
            base_url (str): Base URL for resolving relative URLs
            headers (Dict[str, str]): Headers to use for requests
        """
        try:
            segments = segment_list.get('SegmentURL', [])
            if not isinstance(segments, list):
                segments = [segments]
            
            # Pre-buffer first few segments
            for segment in segments[:self.prebuffer_segments]:
                segment_url = segment.get('@src')
                if segment_url:
                    full_url = urljoin(base_url, segment_url)
                    await self._download_segment(full_url, headers)
                    
        except Exception as e:
            logger.warning(f"Failed to pre-buffer list segments: {e}")
    
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
                logger.warning(f"Memory usage {memory_percent}% exceeds limit {self.max_memory_percent}%, skipping segment download")
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
                
            logger.debug(f"Cached DASH segment: {segment_url}")
            
        except Exception as e:
            logger.warning(f"Failed to download DASH segment {segment_url}: {e}")
    
    async def get_segment(self, segment_url: str, headers: Dict[str, str]) -> Optional[bytes]:
        """
        Get a segment from cache or download it.
        
        Args:
            segment_url (str): URL of the segment
            headers (Dict[str, str]): Headers to use for request
            
        Returns:
            Optional[bytes]: Cached segment data or None if not available
        """
        # Check segment cache first
        if segment_url in self.segment_cache:
            logger.debug(f"DASH cache hit for segment: {segment_url}")
            return self.segment_cache[segment_url]
        
        # Check init segment cache
        if segment_url in self.init_segment_cache:
            logger.debug(f"DASH cache hit for init segment: {segment_url}")
            return self.init_segment_cache[segment_url]
        
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
            
            # Determine if it's an init segment or regular segment
            if 'init' in segment_url.lower() or segment_url.endswith('.mp4'):
                self.init_segment_cache[segment_url] = segment_data
            else:
                self.segment_cache[segment_url] = segment_data
            
            # Check for emergency cleanup
            if self._check_memory_threshold():
                self._emergency_cache_cleanup()
            # Maintain cache size
            elif len(self.segment_cache) > self.max_cache_size:
                oldest_key = next(iter(self.segment_cache))
                del self.segment_cache[oldest_key]
            
            logger.debug(f"Downloaded and cached DASH segment: {segment_url}")
            return segment_data
            
        except Exception as e:
            logger.warning(f"Failed to get DASH segment {segment_url}: {e}")
            return None
    
    async def get_manifest(self, mpd_url: str, headers: Dict[str, str]) -> Optional[dict]:
        """
        Get MPD manifest from cache or download it.
        
        Args:
            mpd_url (str): URL of the MPD manifest
            headers (Dict[str, str]): Headers to use for request
            
        Returns:
            Optional[dict]: Cached manifest data or None if not available
        """
        # Check cache first
        if mpd_url in self.manifest_cache:
            logger.debug(f"DASH cache hit for manifest: {mpd_url}")
            return self.manifest_cache[mpd_url]
        
        # Download if not in cache
        try:
            response = await self.client.get(mpd_url, headers=headers)
            response.raise_for_status()
            mpd_content = response.text
            mpd_dict = xmltodict.parse(mpd_content)
            
            # Cache the manifest
            self.manifest_cache[mpd_url] = mpd_dict
            
            logger.debug(f"Downloaded and cached DASH manifest: {mpd_url}")
            return mpd_dict
            
        except Exception as e:
            logger.warning(f"Failed to get DASH manifest {mpd_url}: {e}")
            return None
    
    def clear_cache(self) -> None:
        """Clear the DASH cache."""
        self.segment_cache.clear()
        self.init_segment_cache.clear()
        self.manifest_cache.clear()
        self.adaptation_segments.clear()
        logger.info("DASH pre-buffer cache cleared")
    
    async def close(self) -> None:
        """Close the pre-buffer system."""
        await self.client.aclose()


# Global DASH pre-buffer instance
dash_prebuffer = DASHPreBuffer() 
