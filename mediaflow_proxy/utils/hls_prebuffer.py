import asyncio
import logging
import psutil
from typing import Dict, Optional, List
from urllib.parse import urlparse
import httpx
from mediaflow_proxy.utils.http_utils import create_httpx_client
from mediaflow_proxy.configs import settings
from collections import OrderedDict
import time
from urllib.parse import urljoin

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
        from collections import OrderedDict
        import time
        from urllib.parse import urljoin
        self.max_cache_size = max_cache_size or settings.hls_prebuffer_cache_size
        self.prebuffer_segments = prebuffer_segments or settings.hls_prebuffer_segments
        self.max_memory_percent = settings.hls_prebuffer_max_memory_percent
        self.emergency_threshold = settings.hls_prebuffer_emergency_threshold
        # Cache LRU
        self.segment_cache: "OrderedDict[str, bytes]" = OrderedDict()
        # Mappa playlist -> lista segmenti
        self.segment_urls: Dict[str, List[str]] = {}
        # Mappa inversa segmento -> (playlist_url, index)
        self.segment_to_playlist: Dict[str, tuple[str, int]] = {}
        # Stato per playlist: {headers, last_access, refresh_task, target_duration}
        self.playlist_state: Dict[str, dict] = {}
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
            response = await self.client.get(playlist_url, headers=headers)
            response.raise_for_status()
            playlist_content = response.text

            # Se master playlist: prendi la prima variante (fix relativo)
            if "#EXT-X-STREAM-INF" in playlist_content:
                logger.debug(f"Master playlist detected, finding first variant")
                variant_urls = self._extract_variant_urls(playlist_content, playlist_url)
                if variant_urls:
                    first_variant_url = variant_urls[0]
                    logger.debug(f"Pre-buffering first variant: {first_variant_url}")
                    await self.prebuffer_playlist(first_variant_url, headers)
                else:
                    logger.warning("No variants found in master playlist")
                return

            # Media playlist: estrai segmenti, salva stato e lancia refresh loop
            segment_urls = self._extract_segment_urls(playlist_content, playlist_url)
            self.segment_urls[playlist_url] = segment_urls
            # aggiorna mappa inversa
            for idx, u in enumerate(segment_urls):
                self.segment_to_playlist[u] = (playlist_url, idx)

            # prebuffer iniziale
            await self._prebuffer_segments(segment_urls[:self.prebuffer_segments], headers)
            logger.info(f"Pre-buffered {min(self.prebuffer_segments, len(segment_urls))} segments for {playlist_url}")

            # setup refresh loop se non già attivo
            target_duration = self._parse_target_duration(playlist_content) or 6
            st = self.playlist_state.get(playlist_url, {})
            if not st.get("refresh_task") or st["refresh_task"].done():
                task = asyncio.create_task(self._refresh_playlist_loop(playlist_url, headers, target_duration))
                self.playlist_state[playlist_url] = {
                    "headers": headers,
                    "last_access": asyncio.get_event_loop().time(),
                    "refresh_task": task,
                    "target_duration": target_duration,
                }
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
        Estrae le varianti dal master playlist. Corretto per gestire URI relativi:
        prende la riga non-commento successiva a #EXT-X-STREAM-INF e la risolve rispetto a base_url.
        """
        from urllib.parse import urljoin
        variant_urls = []
        lines = [l.strip() for l in playlist_content.split('\n')]
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
        Esegue cleanup LRU rimuovendo il 50% più vecchio.
        """
        if self._check_memory_threshold():
            logger.warning("Emergency cache cleanup triggered due to high memory usage")
            to_remove = max(1, len(self.segment_cache) // 2)
            removed = 0
            while removed < to_remove and self.segment_cache:
                self.segment_cache.popitem(last=False)  # rimuovi LRU
                removed += 1
            logger.info(f"Emergency cleanup removed {removed} segments from cache")
    
    async def _download_segment(self, segment_url: str, headers: Dict[str, str]) -> None:
        """
        Download a single segment and cache it.
        
        Args:
            segment_url (str): URL of the segment to download
            headers (Dict[str, str]): Headers to use for request
        """
        try:
            memory_percent = self._get_memory_usage_percent()
            if memory_percent > self.max_memory_percent:
                logger.warning(f"Memory usage {memory_percent}% exceeds limit {self.max_memory_percent}%, skipping download")
                return

            response = await self.client.get(segment_url, headers=headers)
            response.raise_for_status()

            # Cache LRU
            self.segment_cache[segment_url] = response.content
            self.segment_cache.move_to_end(segment_url, last=True)

            if self._check_memory_threshold():
                self._emergency_cache_cleanup()
            elif len(self.segment_cache) > self.max_cache_size:
                # Evict LRU finché non rientra
                while len(self.segment_cache) > self.max_cache_size:
                    self.segment_cache.popitem(last=False)

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
            # LRU touch
            data = self.segment_cache[segment_url]
            self.segment_cache.move_to_end(segment_url, last=True)
            # aggiorna last_access per la playlist se mappata
            pl = self.segment_to_playlist.get(segment_url)
            if pl:
                st = self.playlist_state.get(pl[0])
                if st:
                    st["last_access"] = asyncio.get_event_loop().time()
            return data

        memory_percent = self._get_memory_usage_percent()
        if memory_percent > self.max_memory_percent:
            logger.warning(f"Memory usage {memory_percent}% exceeds limit {self.max_memory_percent}%, skipping download")
            return None

        try:
            response = await self.client.get(segment_url, headers=headers)
            response.raise_for_status()
            segment_data = response.content

            # Cache LRU
            self.segment_cache[segment_url] = segment_data
            self.segment_cache.move_to_end(segment_url, last=True)

            if self._check_memory_threshold():
                self._emergency_cache_cleanup()
            elif len(self.segment_cache) > self.max_cache_size:
                while len(self.segment_cache) > self.max_cache_size:
                    self.segment_cache.popitem(last=False)

            # aggiorna last_access per playlist
            pl = self.segment_to_playlist.get(segment_url)
            if pl:
                st = self.playlist_state.get(pl[0])
                if st:
                    st["last_access"] = asyncio.get_event_loop().time()

            logger.debug(f"Downloaded and cached segment: {segment_url}")
            return segment_data
        except Exception as e:
            logger.warning(f"Failed to get segment {segment_url}: {e}")
            return None
    
    async def prebuffer_from_segment(self, segment_url: str, headers: Dict[str, str]) -> None:
        """
        Dato un URL di segmento, prebuffer i successivi in base alla playlist e all'indice mappato.
        """
        mapped = self.segment_to_playlist.get(segment_url)
        if not mapped:
            return
        playlist_url, idx = mapped
        # aggiorna access time
        st = self.playlist_state.get(playlist_url)
        if st:
            st["last_access"] = asyncio.get_event_loop().time()
        await self.prebuffer_next_segments(playlist_url, idx, headers)
    
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
        self.segment_to_playlist.clear()
        self.playlist_state.clear()
        logger.info("HLS pre-buffer cache cleared")
    
    async def close(self) -> None:
        """Close the pre-buffer system."""
        await self.client.aclose()


# Global pre-buffer instance
hls_prebuffer = HLSPreBuffer()


class HLSPreBuffer:
    def _parse_target_duration(self, playlist_content: str) -> Optional[int]:
        """
        Parse EXT-X-TARGETDURATION from a media playlist and return duration in seconds.
        Returns None if not present or unparsable.
        """
        for line in playlist_content.splitlines():
            line = line.strip()
            if line.startswith("#EXT-X-TARGETDURATION:"):
                try:
                    value = line.split(":", 1)[1].strip()
                    return int(float(value))
                except Exception:
                    return None
        return None
    
    async def _refresh_playlist_loop(self, playlist_url: str, headers: Dict[str, str], target_duration: int) -> None:
        """
        Aggiorna periodicamente la playlist per seguire la sliding window e mantenere la cache coerente.
        Interrompe e pulisce dopo inattività prolungata.
        """
        sleep_s = max(2, min(15, int(target_duration)))
        inactivity_timeout = 600  # 10 minuti
        while True:
            try:
                st = self.playlist_state.get(playlist_url)
                now = asyncio.get_event_loop().time()
                if not st:
                    return
                if now - st.get("last_access", now) > inactivity_timeout:
                    # cleanup specifico della playlist
                    urls = set(self.segment_urls.get(playlist_url, []))
                    if urls:
                        # rimuovi dalla cache solo i segmenti di questa playlist
                        for u in list(self.segment_cache.keys()):
                            if u in urls:
                                self.segment_cache.pop(u, None)
                        # rimuovi mapping
                        for u in urls:
                            self.segment_to_playlist.pop(u, None)
                    self.segment_urls.pop(playlist_url, None)
                    self.playlist_state.pop(playlist_url, None)
                    logger.info(f"Stopped HLS prebuffer for inactive playlist: {playlist_url}")
                    return

                # refresh manifest
                resp = await self.client.get(playlist_url, headers=headers)
                resp.raise_for_status()
                content = resp.text
                new_target = self._parse_target_duration(content)
                if new_target:
                    sleep_s = max(2, min(15, int(new_target)))

                new_urls = self._extract_segment_urls(content, playlist_url)
                if new_urls:
                    self.segment_urls[playlist_url] = new_urls
                    # rebuild reverse map per gli ultimi N (limita la memoria)
                    for idx, u in enumerate(new_urls[-(self.max_cache_size * 2):]):
                        # rimappiando sovrascrivi eventuali entry
                        real_idx = len(new_urls) - (self.max_cache_size * 2) + idx if len(new_urls) > (self.max_cache_size * 2) else idx
                        self.segment_to_playlist[u] = (playlist_url, real_idx)

                # tenta un prebuffer proattivo: se conosciamo l'ultimo segmento accessibile, anticipa i successivi
                # Non conosciamo l'indice di riproduzione corrente qui, quindi non facciamo nulla di aggressivo.

            except Exception as e:
                logger.debug(f"Playlist refresh error for {playlist_url}: {e}")
            await asyncio.sleep(sleep_s)
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
        Estrae le varianti dal master playlist. Corretto per gestire URI relativi:
        prende la riga non-commento successiva a #EXT-X-STREAM-INF e la risolve rispetto a base_url.
        """
        from urllib.parse import urljoin
        variant_urls = []
        lines = [l.strip() for l in playlist_content.split('\n')]
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
        if variant_urls:
            logger.debug(f"First variant URL: {variant_urls[0]}")
        return variant_urls