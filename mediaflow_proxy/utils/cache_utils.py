import asyncio
import json
import logging
import os
import tempfile
import threading
import time
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Union, Any

import aiofiles
import aiofiles.os
from pydantic import ValidationError

from mediaflow_proxy.speedtest.models import SpeedTestTask
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


class CacheStats:
    """Tracks cache performance metrics."""

    def __init__(self):
        self.hits = 0
        self.misses = 0
        self.memory_hits = 0
        self.disk_hits = 0
        self._lock = threading.Lock()

    def record_hit(self, from_memory: bool):
        with self._lock:
            self.hits += 1
            if from_memory:
                self.memory_hits += 1
            else:
                self.disk_hits += 1

    def record_miss(self):
        with self._lock:
            self.misses += 1

    @property
    def hit_rate(self) -> float:
        total = self.hits + self.misses
        return self.hits / total if total > 0 else 0.0

    def __str__(self) -> str:
        return (
            f"Cache Stats: Hits={self.hits} (Memory: {self.memory_hits}, "
            f"Disk: {self.disk_hits}), Misses={self.misses}, "
            f"Hit Rate={self.hit_rate:.2%}"
        )


class AsyncLRUMemoryCache:
    """Thread-safe LRU memory cache with async support."""

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
                    del self._cache[key]
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


class OptimizedHybridCache:
    """High-performance hybrid cache combining memory and file storage."""

    def __init__(
        self,
        cache_dir_name: str,
        ttl: int,
        max_memory_size: int = 100 * 1024 * 1024,  # 100MB default
        file_shards: int = 256,  # Number of subdirectories for sharding
        executor_workers: int = 4,
    ):
        self.cache_dir = Path(tempfile.gettempdir()) / cache_dir_name
        self.ttl = ttl
        self.file_shards = file_shards
        self.memory_cache = AsyncLRUMemoryCache(maxsize=max_memory_size)
        self.stats = CacheStats()
        self._executor = ThreadPoolExecutor(max_workers=executor_workers)
        self._lock = asyncio.Lock()

        # Initialize cache directories
        self._init_cache_dirs()

    def _init_cache_dirs(self):
        """Initialize sharded cache directories."""
        for i in range(self.file_shards):
            shard_dir = self.cache_dir / f"shard_{i:03d}"
            os.makedirs(shard_dir, exist_ok=True)

    def _get_shard_path(self, key: str) -> Path:
        """Get the appropriate shard directory for a key."""
        shard_num = hash(key) % self.file_shards
        return self.cache_dir / f"shard_{shard_num:03d}"

    def _get_file_path(self, key: str) -> Path:
        """Get the file path for a cache key."""
        safe_key = str(hash(key))
        return self._get_shard_path(key) / safe_key

    async def get(self, key: str, default: Any = None) -> Optional[bytes]:
        """
        Get value from cache, trying memory first then file.

        Args:
            key: Cache key
            default: Default value if key not found

        Returns:
            Cached value or default if not found
        """
        # Try memory cache first
        entry = self.memory_cache.get(key)
        if entry is not None:
            self.stats.record_hit(from_memory=True)
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
                    self.stats.record_miss()
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

                self.stats.record_hit(from_memory=False)
                return data

        except FileNotFoundError:
            self.stats.record_miss()
            return default
        except Exception as e:
            logger.error(f"Error reading from cache: {e}")
            self.stats.record_miss()
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

        expires_at = time.time() + (ttl or self.ttl)

        # Create cache entry
        entry = CacheEntry(data=data, expires_at=expires_at, access_count=0, last_access=time.time(), size=len(data))

        # Update memory cache
        self.memory_cache.set(key, entry)

        # Update file cache
        try:
            file_path = self._get_file_path(key)
            temp_path = file_path.with_suffix(".tmp")

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
            except:
                pass
            return False

    async def delete(self, key: str) -> bool:
        """Delete item from both caches."""
        self.memory_cache.remove(key)

        try:
            file_path = self._get_file_path(key)
            await aiofiles.os.remove(file_path)
            return True
        except FileNotFoundError:
            return True
        except Exception as e:
            logger.error(f"Error deleting from cache: {e}")
            return False

    async def cleanup_expired(self):
        """Clean up expired cache entries."""
        current_time = time.time()

        async def check_and_clean_file(file_path: Path):
            try:
                async with aiofiles.open(file_path, "rb") as f:
                    metadata_size = await f.read(8)
                    metadata_length = int.from_bytes(metadata_size, "big")
                    metadata_bytes = await f.read(metadata_length)
                    metadata = json.loads(metadata_bytes.decode())

                    if metadata["expires_at"] < current_time:
                        await aiofiles.os.remove(file_path)
            except Exception as e:
                logger.error(f"Error cleaning up file {file_path}: {e}")

        # Clean up each shard
        for i in range(self.file_shards):
            shard_dir = self.cache_dir / f"shard_{i:03d}"
            try:
                async for entry in aiofiles.os.scandir(shard_dir):
                    if entry.is_file() and not entry.name.endswith(".tmp"):
                        await check_and_clean_file(Path(entry.path))
            except Exception as e:
                logger.error(f"Error scanning shard directory {shard_dir}: {e}")


# Create cache instances
INIT_SEGMENT_CACHE = OptimizedHybridCache(
    cache_dir_name="init_segment_cache",
    ttl=3600,  # 1 hour
    max_memory_size=500 * 1024 * 1024,  # 500MB for init segments
    file_shards=512,  # More shards for better distribution
)

MPD_CACHE = OptimizedHybridCache(
    cache_dir_name="mpd_cache",
    ttl=300,  # 5 minutes
    max_memory_size=100 * 1024 * 1024,  # 100MB for MPD files
    file_shards=128,
)

SPEEDTEST_CACHE = OptimizedHybridCache(
    cache_dir_name="speedtest_cache",
    ttl=3600,  # 1 hour
    max_memory_size=50 * 1024 * 1024,  # 50MB for speed test results
    file_shards=64,
)


# Specific cache implementations
async def get_cached_init_segment(init_url: str, headers: dict) -> Optional[bytes]:
    """Get initialization segment from cache or download it."""
    # Try cache first
    cached_data = await INIT_SEGMENT_CACHE.get(init_url)
    if cached_data is not None:
        return cached_data

    # Download if not cached
    try:
        init_content = await download_file_with_retry(init_url, headers)
        if init_content:
            await INIT_SEGMENT_CACHE.set(init_url, init_content)
        return init_content
    except Exception as e:
        logger.error(f"Error downloading init segment: {e}")
        return None


async def get_cached_mpd(
    mpd_url: str,
    headers: dict,
    parse_drm: bool,
    parse_segment_profile_id: str | None = None,
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
        await MPD_CACHE.set(mpd_url, json.dumps(mpd_dict).encode())
        return parsed_dict
    except DownloadError as error:
        logger.error(f"Error downloading MPD: {error}")
        raise error
    except Exception as error:
        logger.exception(f"Error processing MPD: {e}")
        raise error


async def get_cached_speedtest(task_id: str) -> Optional[SpeedTestTask]:
    """Get speed test results from cache."""
    cached_data = await SPEEDTEST_CACHE.get(task_id)
    if cached_data is not None:
        try:
            return SpeedTestTask.model_validate_json(cached_data.decode())
        except ValidationError as e:
            logger.error(f"Error parsing cached speed test data: {e}")
            await SPEEDTEST_CACHE.delete(task_id)
    return None


async def set_cache_speedtest(task_id: str, task: SpeedTestTask) -> bool:
    """Cache speed test results."""
    try:
        return await SPEEDTEST_CACHE.set(task_id, task.model_dump_json().encode())
    except Exception as e:
        logger.error(f"Error caching speed test data: {e}")
        return False
