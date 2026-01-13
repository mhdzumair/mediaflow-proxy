import asyncio
import fcntl
import hashlib
import json
import logging
import os
import tempfile
import threading
import time
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Union, Any

import aiofiles
import aiofiles.os

from mediaflow_proxy.utils.http_utils import download_file_with_retry, DownloadError
from mediaflow_proxy.utils.mpd_utils import parse_mpd, parse_mpd_dict

logger = logging.getLogger(__name__)


@dataclass
class CacheEntry:
    """Represents a cache entry with metadata."""

    data: bytes
    expires_at: float
    access_count: int = 0
    last_access: float = 0.0
    size: int = 0


class LRUMemoryCache:
    """Thread-safe LRU memory cache with support."""

    def __init__(self, maxsize: int):
        self.maxsize = maxsize
        self._cache: OrderedDict[str, CacheEntry] = OrderedDict()
        self._lock = threading.Lock()
        self._current_size = 0

    def get(self, key: str) -> Optional[CacheEntry]:
        with self._lock:
            if key in self._cache:
                entry = self._cache.pop(key)  # Remove and re-insert for LRU
                if time.time() < entry.expires_at:
                    entry.access_count += 1
                    entry.last_access = time.time()
                    self._cache[key] = entry
                    return entry
                else:
                    # Remove expired entry
                    self._current_size -= entry.size
                    self._cache.pop(key, None)
            return None

    def set(self, key: str, entry: CacheEntry) -> None:
        with self._lock:
            if key in self._cache:
                old_entry = self._cache[key]
                self._current_size -= old_entry.size

            # Check if we need to make space
            while self._current_size + entry.size > self.maxsize and self._cache:
                _, removed_entry = self._cache.popitem(last=False)
                self._current_size -= removed_entry.size

            self._cache[key] = entry
            self._current_size += entry.size

    def remove(self, key: str) -> None:
        with self._lock:
            if key in self._cache:
                entry = self._cache.pop(key)
                self._current_size -= entry.size


class HybridCache:
    """High-performance hybrid cache combining memory and file storage."""

    def __init__(
        self,
        cache_dir_name: str,
        ttl: int,
        max_memory_size: int = 100 * 1024 * 1024,  # 100MB default
        executor_workers: int = 4,
    ):
        self.cache_dir = Path(tempfile.gettempdir()) / cache_dir_name
        self.ttl = ttl
        self.memory_cache = LRUMemoryCache(maxsize=max_memory_size)
        self._executor = ThreadPoolExecutor(max_workers=executor_workers)
        self._lock = asyncio.Lock()

        # Initialize cache directories
        self._init_cache_dirs()

    def _init_cache_dirs(self):
        """Initialize sharded cache directories."""
        os.makedirs(self.cache_dir, exist_ok=True)

    def _get_md5_hash(self, key: str) -> str:
        """Get the MD5 hash of a cache key."""
        return hashlib.md5(key.encode()).hexdigest()

    def _get_file_path(self, key: str) -> Path:
        """Get the file path for a cache key."""
        return self.cache_dir / key

    async def get(self, key: str, default: Any = None) -> Optional[bytes]:
        """
        Get value from cache, trying memory first then file.

        Args:
            key: Cache key
            default: Default value if key not found

        Returns:
            Cached value or default if not found
        """
        key = self._get_md5_hash(key)
        # Try memory cache first
        entry = self.memory_cache.get(key)
        if entry is not None:
            return entry.data

        # Try file cache
        try:
            file_path = self._get_file_path(key)
            async with aiofiles.open(file_path, "rb") as f:
                metadata_size = await f.read(8)
                metadata_length = int.from_bytes(metadata_size, "big")
                metadata_bytes = await f.read(metadata_length)
                metadata = json.loads(metadata_bytes.decode())

                # Check expiration
                if metadata["expires_at"] < time.time():
                    await self.delete(key)
                    return default

                # Read data
                data = await f.read()

                # Update memory cache in background
                entry = CacheEntry(
                    data=data,
                    expires_at=metadata["expires_at"],
                    access_count=metadata["access_count"] + 1,
                    last_access=time.time(),
                    size=len(data),
                )
                self.memory_cache.set(key, entry)

                return data

        except FileNotFoundError:
            return default
        except Exception as e:
            logger.error(f"Error reading from cache: {e}")
            return default

    async def set(self, key: str, data: Union[bytes, bytearray, memoryview], ttl: Optional[int] = None) -> bool:
        """
        Set value in both memory and file cache.

        Args:
            key: Cache key
            data: Data to cache
            ttl: Optional TTL override

        Returns:
            bool: Success status
        """
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise ValueError("Data must be bytes, bytearray, or memoryview")

        ttl_seconds = self.ttl if ttl is None else ttl

        key = self._get_md5_hash(key)

        if ttl_seconds <= 0:
            # Explicit request to avoid caching - remove any previous entry and return success
            self.memory_cache.remove(key)
            try:
                file_path = self._get_file_path(key)
                await aiofiles.os.remove(file_path)
            except FileNotFoundError:
                pass
            except Exception as e:
                logger.error(f"Error removing cache file: {e}")
            return True

        expires_at = time.time() + ttl_seconds

        # Create cache entry
        entry = CacheEntry(data=data, expires_at=expires_at, access_count=0, last_access=time.time(), size=len(data))

        # Update memory cache
        self.memory_cache.set(key, entry)
        file_path = self._get_file_path(key)
        temp_path = file_path.with_suffix(".tmp")

        # Update file cache
        try:
            metadata = {"expires_at": expires_at, "access_count": 0, "last_access": time.time()}
            metadata_bytes = json.dumps(metadata).encode()
            metadata_size = len(metadata_bytes).to_bytes(8, "big")

            async with aiofiles.open(temp_path, "wb") as f:
                await f.write(metadata_size)
                await f.write(metadata_bytes)
                await f.write(data)

            await aiofiles.os.rename(temp_path, file_path)
            return True

        except Exception as e:
            logger.error(f"Error writing to cache: {e}")
            try:
                await aiofiles.os.remove(temp_path)
            except OSError:
                pass
            return False

    async def delete(self, key: str) -> bool:
        """Delete item from both caches."""
        hashed_key = self._get_md5_hash(key)
        self.memory_cache.remove(hashed_key)

        try:
            file_path = self._get_file_path(hashed_key)
            await aiofiles.os.remove(file_path)
            return True
        except FileNotFoundError:
            return True
        except Exception as e:
            logger.error(f"Error deleting from cache: {e}")
            return False

    def clear(self) -> bool:
        """Clear all items from both memory and file caches (synchronous).

        This method is safe to call from multiple processes - if the directory
        was already deleted by another process, it will simply recreate it.
        """
        import shutil

        # Clear memory cache
        with self.memory_cache._lock:
            self.memory_cache._cache.clear()
            self.memory_cache._current_size = 0

        # Clear file cache directory
        try:
            if self.cache_dir.exists():
                shutil.rmtree(self.cache_dir)
                logger.info(f"Cleared cache directory: {self.cache_dir}")
            else:
                logger.debug(f"Cache directory already cleared: {self.cache_dir}")
        except FileNotFoundError:
            # Directory was already deleted by another process (race condition with multiple workers)
            logger.debug(f"Cache directory already cleared by another process: {self.cache_dir}")
        except Exception as e:
            logger.error(f"Error clearing cache directory: {e}")
            return False

        # Recreate the directory
        try:
            self._init_cache_dirs()
        except Exception as e:
            logger.error(f"Error recreating cache directory: {e}")
            return False

        return True


class AsyncMemoryCache:
    """Async wrapper around LRUMemoryCache."""

    def __init__(self, max_memory_size: int):
        self.memory_cache = LRUMemoryCache(maxsize=max_memory_size)

    async def get(self, key: str, default: Any = None) -> Optional[bytes]:
        """Get value from cache."""
        entry = self.memory_cache.get(key)
        return entry.data if entry is not None else default

    async def set(self, key: str, data: Union[bytes, bytearray, memoryview], ttl: Optional[int] = None) -> bool:
        """Set value in cache."""
        try:
            ttl_seconds = 3600 if ttl is None else ttl

            if ttl_seconds <= 0:
                self.memory_cache.remove(key)
                return True

            expires_at = time.time() + ttl_seconds
            entry = CacheEntry(
                data=data, expires_at=expires_at, access_count=0, last_access=time.time(), size=len(data)
            )
            self.memory_cache.set(key, entry)
            return True
        except Exception as e:
            logger.error(f"Error setting cache value: {e}")
            return False

    async def delete(self, key: str) -> bool:
        """Delete item from cache."""
        try:
            self.memory_cache.remove(key)
            return True
        except Exception as e:
            logger.error(f"Error deleting from cache: {e}")
            return False


class CrossProcessLock:
    """
    File-based lock for cross-process coordination.

    Uses fcntl.flock() for cross-process locking, which works across
    multiple uvicorn workers. Each lock is represented by a file in
    the lock directory.
    """

    def __init__(self, lock_dir: Optional[str] = None):
        """
        Initialize the cross-process lock manager.

        Args:
            lock_dir: Directory to store lock files. Defaults to /tmp/mediaflow_locks
        """
        if lock_dir is None:
            lock_dir = os.path.join(tempfile.gettempdir(), "mediaflow_locks")
        self.lock_dir = Path(lock_dir)
        self._init_lock_dir()
        self._open_files: dict[str, Any] = {}  # Track open file handles per key

    def _init_lock_dir(self) -> None:
        """Create lock directory if it doesn't exist."""
        try:
            self.lock_dir.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            logger.error(f"Failed to create lock directory {self.lock_dir}: {e}")
            raise

    def _get_lock_path(self, key: str) -> Path:
        """Get the lock file path for a given key."""
        key_hash = hashlib.md5(key.encode()).hexdigest()
        return self.lock_dir / f"{key_hash}.lock"

    @asynccontextmanager
    async def acquire(self, key: str, timeout: float = 30.0):
        """
        Acquire an exclusive lock for a key.

        This is an async context manager that acquires a file-based lock.
        The lock is released when the context exits.

        Args:
            key: The key to lock (typically a URL)
            timeout: Maximum time to wait for the lock (seconds)

        Yields:
            None when lock is acquired

        Raises:
            asyncio.TimeoutError: If lock cannot be acquired within timeout
        """
        lock_path = self._get_lock_path(key)
        lock_file = None
        acquired = False

        try:
            # Open the lock file (create if doesn't exist)
            loop = asyncio.get_event_loop()

            def _open_lock_file():
                return open(lock_path, "w")

            lock_file = await loop.run_in_executor(None, _open_lock_file)

            # Try to acquire the lock with timeout
            start_time = time.time()
            while time.time() - start_time < timeout:
                try:
                    # Non-blocking lock attempt
                    fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    acquired = True
                    logger.debug(f"[CrossProcessLock] Acquired lock for: {key[:80]}...")
                    break
                except BlockingIOError:
                    # Lock is held by another process, wait a bit
                    await asyncio.sleep(0.05)  # 50ms between retries

            if not acquired:
                raise asyncio.TimeoutError(f"Failed to acquire lock for {key[:80]}... within {timeout}s")

            yield

        finally:
            if lock_file is not None:
                try:
                    if acquired:
                        # Release the lock
                        fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
                        logger.debug(f"[CrossProcessLock] Released lock for: {key[:80]}...")
                    lock_file.close()
                except Exception as e:
                    logger.warning(f"[CrossProcessLock] Error releasing lock: {e}")

    async def cleanup_stale_locks(self, max_age_seconds: int = 300) -> int:
        """
        Remove lock files older than max_age_seconds.

        This should be called periodically to clean up orphaned lock files
        from crashed processes.

        Args:
            max_age_seconds: Maximum age of lock files to keep

        Returns:
            Number of lock files removed
        """
        removed_count = 0
        try:
            current_time = time.time()
            for lock_file in self.lock_dir.glob("*.lock"):
                try:
                    file_age = current_time - lock_file.stat().st_mtime
                    if file_age > max_age_seconds:
                        lock_file.unlink(missing_ok=True)
                        removed_count += 1
                except FileNotFoundError:
                    # File was already deleted
                    pass
                except Exception as e:
                    logger.warning(f"[CrossProcessLock] Error removing stale lock {lock_file}: {e}")
        except Exception as e:
            logger.error(f"[CrossProcessLock] Error during stale lock cleanup: {e}")

        if removed_count > 0:
            logger.info(f"[CrossProcessLock] Cleaned up {removed_count} stale lock files")

        return removed_count


# Global cross-process lock instance for segment downloads
SEGMENT_DOWNLOAD_LOCK = CrossProcessLock()


# Create cache instances
INIT_SEGMENT_CACHE = HybridCache(
    cache_dir_name="init_segment_cache",
    ttl=3600,  # 1 hour
    max_memory_size=500 * 1024 * 1024,  # 500MB for init segments
)

# Cache for processed (DRM-stripped) init segments - memory only for speed
PROCESSED_INIT_CACHE = AsyncMemoryCache(
    max_memory_size=100 * 1024 * 1024,  # 100MB for processed init segments
)

MPD_CACHE = AsyncMemoryCache(
    max_memory_size=100 * 1024 * 1024,  # 100MB for MPD files
)

EXTRACTOR_CACHE = HybridCache(
    cache_dir_name="extractor_cache",
    ttl=5 * 60,  # 5 minutes
    max_memory_size=50 * 1024 * 1024,
)

# Cache for media segments (prebuffer) - file-backed for cross-worker sharing
# Uses HybridCache so segments cached by one worker are available to all workers
SEGMENT_CACHE = HybridCache(
    cache_dir_name="segment_cache",
    ttl=60,  # Short TTL for live streams (60 seconds)
    max_memory_size=200 * 1024 * 1024,  # 200MB memory cache per worker
)


# Specific cache implementations
async def get_cached_init_segment(
    init_url: str,
    headers: dict,
    cache_token: str | None = None,
    ttl: Optional[int] = None,
    byte_range: str | None = None,
) -> Optional[bytes]:
    """Get initialization segment from cache or download it.

    cache_token allows differentiating entries that share the same init_url but
    rely on different DRM keys or initialization payloads (e.g. key rotation).

    ttl overrides the default cache TTL; pass a value <= 0 to skip caching entirely.

    byte_range specifies a byte range for SegmentBase MPDs (e.g., '0-11568').
    """

    use_cache = ttl is None or ttl > 0
    # Include byte_range in cache key for SegmentBase
    cache_key = f"{init_url}|{cache_token}|{byte_range}" if cache_token or byte_range else init_url

    if use_cache:
        cached_data = await INIT_SEGMENT_CACHE.get(cache_key)
        if cached_data is not None:
            return cached_data
    else:
        # Remove any previously cached entry when caching is disabled
        await INIT_SEGMENT_CACHE.delete(cache_key)

    try:
        # Add Range header if byte_range is specified (for SegmentBase MPDs)
        request_headers = dict(headers)
        if byte_range:
            request_headers["Range"] = f"bytes={byte_range}"

        init_content = await download_file_with_retry(init_url, request_headers)
        if init_content and use_cache:
            await INIT_SEGMENT_CACHE.set(cache_key, init_content, ttl=ttl)
        return init_content
    except Exception as e:
        logger.error(f"Error downloading init segment: {e}")
        return None


async def get_cached_mpd(
    mpd_url: str,
    headers: dict,
    parse_drm: bool,
    parse_segment_profile_id: Optional[str] = None,
) -> dict:
    """Get MPD from cache or download and parse it."""
    # Try cache first
    cached_data = await MPD_CACHE.get(mpd_url)
    if cached_data is not None:
        try:
            mpd_dict = json.loads(cached_data)
            return parse_mpd_dict(mpd_dict, mpd_url, parse_drm, parse_segment_profile_id)
        except json.JSONDecodeError:
            await MPD_CACHE.delete(mpd_url)

    # Download and parse if not cached
    try:
        mpd_content = await download_file_with_retry(mpd_url, headers)
        mpd_dict = parse_mpd(mpd_content)
        parsed_dict = parse_mpd_dict(mpd_dict, mpd_url, parse_drm, parse_segment_profile_id)

        # Cache the original MPD dict
        await MPD_CACHE.set(mpd_url, json.dumps(mpd_dict).encode(), ttl=parsed_dict.get("minimumUpdatePeriod"))
        return parsed_dict
    except DownloadError as error:
        logger.error(f"Error downloading MPD: {error}")
        raise error
    except Exception as error:
        logger.exception(f"Error processing MPD: {error}")
        raise error


async def get_cached_extractor_result(key: str) -> Optional[dict]:
    """Get extractor result from cache."""
    cached_data = await EXTRACTOR_CACHE.get(key)
    if cached_data is not None:
        try:
            return json.loads(cached_data)
        except json.JSONDecodeError:
            await EXTRACTOR_CACHE.delete(key)
    return None


async def set_cache_extractor_result(key: str, result: dict) -> bool:
    """Cache extractor result."""
    try:
        return await EXTRACTOR_CACHE.set(key, json.dumps(result).encode())
    except Exception as e:
        logger.error(f"Error caching extractor result: {e}")
        return False


async def get_cached_processed_init(
    init_url: str,
    key_id: str,
) -> Optional[bytes]:
    """Get processed (DRM-stripped) init segment from cache.

    Args:
        init_url: URL of the init segment
        key_id: DRM key ID used for processing

    Returns:
        Processed init segment bytes if cached, None otherwise
    """
    cache_key = f"processed|{init_url}|{key_id}"
    return await PROCESSED_INIT_CACHE.get(cache_key)


async def set_cached_processed_init(
    init_url: str,
    key_id: str,
    processed_content: bytes,
    ttl: Optional[int] = None,
) -> bool:
    """Cache processed (DRM-stripped) init segment.

    Args:
        init_url: URL of the init segment
        key_id: DRM key ID used for processing
        processed_content: The processed init segment bytes
        ttl: Optional TTL override

    Returns:
        True if cached successfully
    """
    cache_key = f"processed|{init_url}|{key_id}"
    try:
        return await PROCESSED_INIT_CACHE.set(cache_key, processed_content, ttl=ttl)
    except Exception as e:
        logger.error(f"Error caching processed init segment: {e}")
        return False


async def get_cached_segment(segment_url: str) -> Optional[bytes]:
    """Get media segment from prebuffer cache.

    Args:
        segment_url: URL of the segment

    Returns:
        Segment bytes if cached, None otherwise
    """
    return await SEGMENT_CACHE.get(segment_url)


async def set_cached_segment(segment_url: str, content: bytes, ttl: int = 60) -> bool:
    """Cache media segment with configurable TTL.

    Args:
        segment_url: URL of the segment
        content: Segment bytes
        ttl: Time to live in seconds (default 60s, configurable via dash_segment_cache_ttl)

    Returns:
        True if cached successfully
    """
    try:
        return await SEGMENT_CACHE.set(segment_url, content, ttl=ttl)
    except Exception as e:
        logger.error(f"Error caching segment: {e}")
        return False
