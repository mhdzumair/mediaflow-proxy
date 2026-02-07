import asyncio
try:
    import fcntl
except ImportError:
    fcntl = None

try:
    import msvcrt
except ImportError:
    msvcrt = None
import hashlib
import json
"""
Cache utilities for mediaflow-proxy.

All caching is now done via Redis for cross-worker sharing.
See redis_utils.py for the underlying Redis operations.
"""

import logging
from typing import Optional

from mediaflow_proxy.utils.http_utils import download_file_with_retry, DownloadError
from mediaflow_proxy.utils.mpd_utils import parse_mpd, parse_mpd_dict
from mediaflow_proxy.utils import redis_utils

logger = logging.getLogger(__name__)


# =============================================================================
# Init Segment Cache
# =============================================================================


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
                    if fcntl:
                        # Unix-style locking
                        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                        acquired = True
                    elif msvcrt:
                        # Windows-style locking
                        # msvcrt.locking(fd, mode, nbytes)
                        # LK_NBLCK is non-blocking lock
                        lock_file.seek(0)
                        msvcrt.locking(lock_file.fileno(), msvcrt.LK_NBLCK, 1)
                        acquired = True
                    else:
                        # No cross-process locking available
                        acquired = True
                    
                    if acquired:
                        logger.debug(f"[CrossProcessLock] Acquired lock for: {key[:80]}...")
                        break
                except (BlockingIOError, PermissionError, IOError):
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
                        if fcntl:
                            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
                        elif msvcrt:
                            lock_file.seek(0)
                            msvcrt.locking(lock_file.fileno(), msvcrt.LK_UNLCK, 1)
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
        cached_data = await redis_utils.get_cached_init_segment(cache_key)
        if cached_data is not None:
            return cached_data

    try:
        # Add Range header if byte_range is specified (for SegmentBase MPDs)
        request_headers = dict(headers)
        if byte_range:
            request_headers["Range"] = f"bytes={byte_range}"

        init_content = await download_file_with_retry(init_url, request_headers)
        if init_content and use_cache:
            cache_ttl = ttl if ttl is not None else redis_utils.DEFAULT_INIT_CACHE_TTL
            await redis_utils.set_cached_init_segment(cache_key, init_content, ttl=cache_ttl)
        return init_content
    except Exception as e:
        logger.error(f"Error downloading init segment: {e}")
        return None


# =============================================================================
# MPD Cache
# =============================================================================


async def get_cached_mpd(
    mpd_url: str,
    headers: dict,
    parse_drm: bool,
    parse_segment_profile_id: Optional[str] = None,
) -> dict:
    """Get MPD from cache or download and parse it."""
    # Try cache first
    cached_data = await redis_utils.get_cached_mpd(mpd_url)
    if cached_data is not None:
        try:
            return parse_mpd_dict(cached_data, mpd_url, parse_drm, parse_segment_profile_id)
        except Exception:
            # Invalid cached data, will re-download
            pass

    # Download and parse if not cached
    try:
        mpd_content = await download_file_with_retry(mpd_url, headers)
        mpd_dict = parse_mpd(mpd_content)
        parsed_dict = parse_mpd_dict(mpd_dict, mpd_url, parse_drm, parse_segment_profile_id)

        # Cache the original MPD dict with TTL from minimumUpdatePeriod
        cache_ttl = parsed_dict.get("minimumUpdatePeriod") or redis_utils.DEFAULT_MPD_CACHE_TTL
        await redis_utils.set_cached_mpd(mpd_url, mpd_dict, ttl=cache_ttl)
        return parsed_dict
    except DownloadError as error:
        logger.error(f"Error downloading MPD: {error}")
        raise error
    except Exception as error:
        logger.exception(f"Error processing MPD: {error}")
        raise error


# =============================================================================
# Extractor Cache
# =============================================================================


async def get_cached_extractor_result(key: str) -> Optional[dict]:
    """Get extractor result from cache."""
    return await redis_utils.get_cached_extractor(key)


async def set_cache_extractor_result(key: str, result: dict) -> bool:
    """Cache extractor result."""
    try:
        await redis_utils.set_cached_extractor(key, result)
        return True
    except Exception as e:
        logger.error(f"Error caching extractor result: {e}")
        return False


# =============================================================================
# Processed Init Segment Cache
# =============================================================================


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
    return await redis_utils.get_cached_processed_init(cache_key)


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
        cache_ttl = ttl if ttl is not None else redis_utils.DEFAULT_PROCESSED_INIT_TTL
        await redis_utils.set_cached_processed_init(cache_key, processed_content, ttl=cache_ttl)
        return True
    except Exception as e:
        logger.error(f"Error caching processed init segment: {e}")
        return False


# =============================================================================
# Segment Cache
# =============================================================================


async def get_cached_segment(segment_url: str) -> Optional[bytes]:
    """Get media segment from prebuffer cache.

    Args:
        segment_url: URL of the segment

    Returns:
        Segment bytes if cached, None otherwise
    """
    return await redis_utils.get_cached_segment(segment_url)


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
        await redis_utils.set_cached_segment(segment_url, content, ttl=ttl)
        return True
    except Exception as e:
        logger.error(f"Error caching segment: {e}")
        return False


async def get_cached_processed_segment(segment_url: str, key_id: str = None, remux: bool = False) -> Optional[bytes]:
    """Get processed (decrypted/remuxed) segment from cache.

    Args:
        segment_url: URL of the segment
        key_id: Optional key ID used for decryption
        remux: Whether remuxing was applied

    Returns:
        Processed segment bytes if cached, None otherwise
    """
    cache_key = f"proc|{segment_url}|{key_id or ''}|{remux}"
    return await SEGMENT_CACHE.get(cache_key)


async def set_cached_processed_segment(
    segment_url: str, content: bytes, key_id: str = None, remux: bool = False, ttl: int = 60
) -> bool:
    """Cache processed (decrypted/remuxed) segment.

    Args:
        segment_url: URL of the segment
        content: Processed segment bytes
        key_id: Optional key ID used for decryption
        remux: Whether remuxing was applied
        ttl: Time to live in seconds

    Returns:
        True if cached successfully
    """
    cache_key = f"proc|{segment_url}|{key_id or ''}|{remux}"
    try:
        return await SEGMENT_CACHE.set(cache_key, content, ttl=ttl)
    except Exception as e:
        logger.error(f"Error caching processed segment: {e}")
        return False
