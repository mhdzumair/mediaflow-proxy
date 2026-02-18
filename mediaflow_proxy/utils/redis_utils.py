"""
Redis utilities for cross-worker coordination and caching.

Provides:
- Distributed locking (stream gating, generic locks)
- Shared caching (HEAD responses, extractors, MPD, segments, init segments)
- In-flight request deduplication
- Cooldown/throttle tracking

All caches are shared across all uvicorn workers via Redis.

IMPORTANT: Redis is OPTIONAL. If settings.redis_url is None, all functions
gracefully degrade:
- Locks always succeed immediately (no cross-worker coordination)
- Cache operations return None/False (no shared caching)
- Cooldowns always allow (no rate limiting)

This allows single-worker deployments to work without Redis.
"""

import asyncio
import hashlib
import json
import logging
import time
from typing import Optional

from mediaflow_proxy.configs import settings

logger = logging.getLogger(__name__)

# =============================================================================
# Redis Clients (Lazy Singletons)
# =============================================================================
# Two clients: one for text/JSON (decode_responses=True), one for binary data

_redis_client = None
_redis_binary_client = None
_redis_available: Optional[bool] = None  # None = not checked yet


def is_redis_configured() -> bool:
    """Check if Redis URL is configured in settings."""
    return settings.redis_url is not None and settings.redis_url.strip() != ""


async def is_redis_available() -> bool:
    """
    Check if Redis is configured and reachable.

    Caches the result after first successful/failed connection attempt.
    """
    global _redis_available

    if not is_redis_configured():
        return False

    if _redis_available is not None:
        return _redis_available

    # Try to connect
    try:
        import redis.asyncio as redis

        client = redis.from_url(
            settings.redis_url,
            decode_responses=True,
            socket_connect_timeout=2,
            socket_timeout=2,
        )
        await client.ping()
        await client.aclose()
        _redis_available = True
        logger.info(f"Redis is available: {settings.redis_url}")
    except Exception as e:
        _redis_available = False
        logger.warning(f"Redis not available (features will be disabled): {e}")

    return _redis_available


async def get_redis():
    """
    Get or create the Redis connection pool for text/JSON data (lazy singleton).

    The connection pool is shared across all async tasks in a single worker.
    Each worker process has its own pool, but Redis itself coordinates across workers.

    Returns None if Redis is not configured or not available.
    """
    global _redis_client

    if not is_redis_configured():
        return None

    if _redis_client is None:
        import redis.asyncio as redis

        _redis_client = redis.from_url(
            settings.redis_url,
            decode_responses=True,
            socket_connect_timeout=5,
            socket_timeout=5,
        )
        # Test connection
        try:
            await _redis_client.ping()
            logger.info(f"Redis connected (text): {settings.redis_url}")
        except Exception as e:
            logger.error(f"Redis connection failed: {e}")
            _redis_client = None
            return None
    return _redis_client


async def get_redis_binary():
    """
    Get or create the Redis connection pool for binary data (lazy singleton).

    Used for caching segments and init segments without base64 encoding overhead.

    Returns None if Redis is not configured or not available.
    """
    global _redis_binary_client

    if not is_redis_configured():
        return None

    if _redis_binary_client is None:
        import redis.asyncio as redis

        _redis_binary_client = redis.from_url(
            settings.redis_url,
            decode_responses=False,  # Keep bytes as-is
            socket_connect_timeout=5,
            socket_timeout=5,
        )
        # Test connection
        try:
            await _redis_binary_client.ping()
            logger.info(f"Redis connected (binary): {settings.redis_url}")
        except Exception as e:
            logger.error(f"Redis binary connection failed: {e}")
            _redis_binary_client = None
            return None
    return _redis_binary_client


async def close_redis():
    """Close all Redis connection pools (call on shutdown)."""
    global _redis_client, _redis_binary_client, _redis_available
    if _redis_client is not None:
        await _redis_client.aclose()
        _redis_client = None
    if _redis_binary_client is not None:
        await _redis_binary_client.aclose()
        _redis_binary_client = None
    _redis_available = None
    logger.info("Redis connections closed")


# =============================================================================
# Instance Namespace Helper
# =============================================================================
# Some cached data is bound to the outgoing IP of the pod that produced it
# (e.g. extractor results resolved via the pod's egress IP). Sharing these
# entries across pods in a multi-instance deployment causes other pods to serve
# stale/wrong URLs.
#
# Set CACHE_NAMESPACE (env: CACHE_NAMESPACE) to a unique value per pod (e.g.
# pod name, hostname, or any discriminator). Instance-scoped keys are then
# stored under  "<namespace>:<original_key>", while fully-shared keys (MPD,
# init segments, media segments, locks, stream gates) remain unchanged.


def make_instance_key(key: str) -> str:
    """Prefix *key* with the configured instance namespace.

    Use this for cache/coordination keys that must NOT be shared across pods
    because the underlying data is specific to a pod's outgoing IP (e.g.
    extractor results).  Common content (MPD, init/media segments) should
    never be namespaced.

    If ``settings.cache_namespace`` is not set the key is returned unchanged,
    so single-instance deployments are unaffected.
    """
    ns = settings.cache_namespace
    return f"{ns}:{key}" if ns else key


# =============================================================================
# Stream Gate (Distributed Lock)
# =============================================================================
# Serializes upstream connection handshakes per-URL across all workers.
# Uses SET NX EX for atomic acquire with auto-expiry.

GATE_PREFIX = "mfp:stream_gate:"
GATE_TTL = 15  # seconds - auto-expire if worker crashes mid-request


def _gate_key(url: str) -> str:
    """Generate Redis key for a stream gate."""
    url_hash = hashlib.md5(url.encode()).hexdigest()
    return f"{GATE_PREFIX}{url_hash}"


async def acquire_stream_gate(url: str, timeout: float = 15.0) -> bool:
    """
    Try to acquire a per-URL stream gate (distributed lock).

    Only one worker across all processes can hold the gate for a given URL.
    The gate auto-expires after GATE_TTL seconds to prevent deadlocks.

    If Redis is not available, always returns True (no coordination).

    Args:
        url: The upstream URL to gate
        timeout: Maximum time to wait for the gate (seconds)

    Returns:
        True if gate acquired (or Redis unavailable), False if timeout
    """
    r = await get_redis()
    if r is None:
        # No Redis - no cross-worker coordination, always allow
        return True

    key = _gate_key(url)
    deadline = time.time() + timeout

    while time.time() < deadline:
        # SET NX EX is atomic: only succeeds if key doesn't exist
        if await r.set(key, "1", nx=True, ex=GATE_TTL):
            logger.debug(f"[Redis] Acquired stream gate: {key[:50]}...")
            return True
        # Another worker holds the gate, wait and retry
        await asyncio.sleep(0.05)  # 50ms poll interval

    logger.warning(f"[Redis] Gate acquisition timeout ({timeout}s): {key[:50]}...")
    return False


async def release_stream_gate(url: str):
    """
    Release a per-URL stream gate.

    Safe to call even if gate wasn't acquired or already expired.
    No-op if Redis is not available.
    """
    r = await get_redis()
    if r is None:
        return

    key = _gate_key(url)
    await r.delete(key)
    logger.debug(f"[Redis] Released stream gate: {key[:50]}...")


async def extend_stream_gate(url: str, ttl: int = GATE_TTL):
    """
    Extend the TTL of a stream gate to keep it held during long streams.

    Should be called periodically (e.g., every 10s) while streaming.
    No-op if Redis is not available or gate doesn't exist.
    """
    r = await get_redis()
    if r is None:
        return

    key = _gate_key(url)
    await r.expire(key, ttl)
    logger.debug(f"[Redis] Extended stream gate TTL ({ttl}s): {key[:50]}...")


async def is_stream_gate_held(url: str) -> bool:
    """Check if a stream gate is currently held. Returns False if Redis unavailable."""
    r = await get_redis()
    if r is None:
        return False

    key = _gate_key(url)
    return await r.exists(key) > 0


# =============================================================================
# HEAD Response Cache
# =============================================================================
# Caches upstream response headers so repeated HEAD probes (e.g., from ExoPlayer)
# can be served without any upstream connection. Shared across all workers.

HEAD_CACHE_PREFIX = "mfp:head_cache:"
HEAD_CACHE_TTL = 60  # seconds - Vidoza CDN URLs typically expire in minutes


def _head_cache_key(url: str) -> str:
    """Generate Redis key for HEAD cache entry."""
    url_hash = hashlib.md5(url.encode()).hexdigest()
    return f"{HEAD_CACHE_PREFIX}{url_hash}"


async def get_cached_head(url: str) -> Optional[dict]:
    """
    Get cached HEAD response metadata for a URL.

    Args:
        url: The upstream URL

    Returns:
        Dict with 'headers' and 'status' keys, or None if not cached (or Redis unavailable)
    """
    r = await get_redis()
    if r is None:
        return None

    key = _head_cache_key(url)
    data = await r.get(key)
    if data:
        logger.debug(f"[Redis] HEAD cache hit: {key[:50]}...")
        return json.loads(data)
    return None


async def set_cached_head(url: str, headers: dict, status: int):
    """
    Cache HEAD response metadata for a URL.

    No-op if Redis is not available.

    Args:
        url: The upstream URL
        headers: Response headers dict (will be JSON serialized)
        status: HTTP status code (e.g., 200, 206)
    """
    r = await get_redis()
    if r is None:
        return

    key = _head_cache_key(url)
    # Only cache headers that are useful for HEAD responses
    # Filter to avoid caching large or irrelevant headers
    cached_headers = {}
    for k, v in headers.items():
        k_lower = k.lower()
        if k_lower in (
            "content-type",
            "content-length",
            "accept-ranges",
            "content-range",
            "etag",
            "last-modified",
            "cache-control",
        ):
            cached_headers[k_lower] = v

    payload = json.dumps({"headers": cached_headers, "status": status})
    await r.set(key, payload, ex=HEAD_CACHE_TTL)
    logger.debug(f"[Redis] HEAD cache set ({HEAD_CACHE_TTL}s TTL): {key[:50]}...")


# =============================================================================
# Generic Distributed Lock
# =============================================================================
# For cross-worker coordination (e.g., segment downloads, prebuffering)

LOCK_PREFIX = "mfp:lock:"
DEFAULT_LOCK_TTL = 30  # seconds


def _lock_key(key: str) -> str:
    """Generate Redis key for a lock."""
    key_hash = hashlib.md5(key.encode()).hexdigest()
    return f"{LOCK_PREFIX}{key_hash}"


async def acquire_lock(key: str, ttl: int = DEFAULT_LOCK_TTL, timeout: float = 30.0) -> bool:
    """
    Acquire a distributed lock.

    If Redis is not available, always returns True (no coordination).

    Args:
        key: The lock identifier
        ttl: Lock auto-expiry time in seconds (prevents deadlocks)
        timeout: Maximum time to wait for the lock

    Returns:
        True if lock acquired (or Redis unavailable), False if timeout
    """
    r = await get_redis()
    if r is None:
        return True  # No Redis - no coordination

    lock_key = _lock_key(key)
    deadline = time.time() + timeout

    while time.time() < deadline:
        if await r.set(lock_key, "1", nx=True, ex=ttl):
            logger.debug(f"[Redis] Acquired lock: {key[:60]}...")
            return True
        await asyncio.sleep(0.05)

    logger.warning(f"[Redis] Lock timeout ({timeout}s): {key[:60]}...")
    return False


async def release_lock(key: str):
    """Release a distributed lock. No-op if Redis unavailable."""
    r = await get_redis()
    if r is None:
        return

    lock_key = _lock_key(key)
    await r.delete(lock_key)
    logger.debug(f"[Redis] Released lock: {key[:60]}...")


# =============================================================================
# Extractor Cache
# =============================================================================
# Caches extractor results (JSON) across all workers

EXTRACTOR_CACHE_PREFIX = "mfp:extractor:"
EXTRACTOR_CACHE_TTL = 300  # 5 minutes


def _extractor_key(key: str) -> str:
    """Generate Redis key for extractor cache."""
    key_hash = hashlib.md5(key.encode()).hexdigest()
    return f"{EXTRACTOR_CACHE_PREFIX}{key_hash}"


async def get_cached_extractor(key: str) -> Optional[dict]:
    """Get cached extractor result. Returns None if Redis unavailable."""
    r = await get_redis()
    if r is None:
        return None

    redis_key = _extractor_key(key)
    data = await r.get(redis_key)
    if data:
        logger.debug(f"[Redis] Extractor cache hit: {key[:60]}...")
        return json.loads(data)
    return None


async def set_cached_extractor(key: str, data: dict, ttl: int = EXTRACTOR_CACHE_TTL):
    """Cache extractor result. No-op if Redis unavailable."""
    r = await get_redis()
    if r is None:
        return

    redis_key = _extractor_key(key)
    await r.set(redis_key, json.dumps(data), ex=ttl)
    logger.debug(f"[Redis] Extractor cache set ({ttl}s TTL): {key[:60]}...")


# =============================================================================
# MPD Cache
# =============================================================================
# Caches parsed MPD manifests (JSON) across all workers

MPD_CACHE_PREFIX = "mfp:mpd:"
DEFAULT_MPD_CACHE_TTL = 60  # 1 minute


def _mpd_key(key: str) -> str:
    """Generate Redis key for MPD cache."""
    key_hash = hashlib.md5(key.encode()).hexdigest()
    return f"{MPD_CACHE_PREFIX}{key_hash}"


async def get_cached_mpd(key: str) -> Optional[dict]:
    """Get cached MPD manifest. Returns None if Redis unavailable."""
    r = await get_redis()
    if r is None:
        return None

    redis_key = _mpd_key(key)
    data = await r.get(redis_key)
    if data:
        logger.debug(f"[Redis] MPD cache hit: {key[:60]}...")
        return json.loads(data)
    return None


async def set_cached_mpd(key: str, data: dict, ttl: int | float = DEFAULT_MPD_CACHE_TTL):
    """Cache MPD manifest. No-op if Redis unavailable."""
    r = await get_redis()
    if r is None:
        return

    redis_key = _mpd_key(key)
    # Ensure TTL is an integer (Redis requires int for ex parameter)
    ttl_int = max(1, int(ttl))
    await r.set(redis_key, json.dumps(data), ex=ttl_int)
    logger.debug(f"[Redis] MPD cache set ({ttl_int}s TTL): {key[:60]}...")


# =============================================================================
# Segment Cache (Binary)
# =============================================================================
# Caches HLS/DASH segments across all workers

SEGMENT_CACHE_PREFIX = b"mfp:segment:"
DEFAULT_SEGMENT_CACHE_TTL = 60  # 1 minute


def _segment_key(url: str) -> bytes:
    """Generate Redis key for segment cache."""
    url_hash = hashlib.md5(url.encode()).hexdigest()
    return SEGMENT_CACHE_PREFIX + url_hash.encode()


async def get_cached_segment(url: str) -> Optional[bytes]:
    """Get cached segment data. Returns None if Redis unavailable."""
    r = await get_redis_binary()
    if r is None:
        return None

    key = _segment_key(url)
    data = await r.get(key)
    if data:
        logger.debug(f"[Redis] Segment cache hit: {url[:60]}...")
    return data


async def set_cached_segment(url: str, data: bytes, ttl: int = DEFAULT_SEGMENT_CACHE_TTL):
    """Cache segment data. No-op if Redis unavailable."""
    r = await get_redis_binary()
    if r is None:
        return

    key = _segment_key(url)
    await r.set(key, data, ex=ttl)
    logger.debug(f"[Redis] Segment cache set ({ttl}s TTL, {len(data)} bytes): {url[:60]}...")


# =============================================================================
# Init Segment Cache (Binary)
# =============================================================================
# Caches initialization segments across all workers

INIT_CACHE_PREFIX = b"mfp:init:"
DEFAULT_INIT_CACHE_TTL = 3600  # 1 hour


def _init_key(url: str) -> bytes:
    """Generate Redis key for init segment cache."""
    url_hash = hashlib.md5(url.encode()).hexdigest()
    return INIT_CACHE_PREFIX + url_hash.encode()


async def get_cached_init_segment(url: str) -> Optional[bytes]:
    """Get cached init segment data. Returns None if Redis unavailable."""
    r = await get_redis_binary()
    if r is None:
        return None

    key = _init_key(url)
    data = await r.get(key)
    if data:
        logger.debug(f"[Redis] Init segment cache hit: {url[:60]}...")
    return data


async def set_cached_init_segment(url: str, data: bytes, ttl: int = DEFAULT_INIT_CACHE_TTL):
    """Cache init segment data. No-op if Redis unavailable."""
    r = await get_redis_binary()
    if r is None:
        return

    key = _init_key(url)
    await r.set(key, data, ex=ttl)
    logger.debug(f"[Redis] Init segment cache set ({ttl}s TTL, {len(data)} bytes): {url[:60]}...")


# =============================================================================
# Processed Init Segment Cache (Binary)
# =============================================================================
# Caches DRM-stripped/processed init segments across all workers

PROCESSED_INIT_CACHE_PREFIX = b"mfp:processed_init:"
DEFAULT_PROCESSED_INIT_TTL = 3600  # 1 hour


def _processed_init_key(key: str) -> bytes:
    """Generate Redis key for processed init segment cache."""
    key_hash = hashlib.md5(key.encode()).hexdigest()
    return PROCESSED_INIT_CACHE_PREFIX + key_hash.encode()


async def get_cached_processed_init(key: str) -> Optional[bytes]:
    """Get cached processed init segment data. Returns None if Redis unavailable."""
    r = await get_redis_binary()
    if r is None:
        return None

    redis_key = _processed_init_key(key)
    data = await r.get(redis_key)
    if data:
        logger.debug(f"[Redis] Processed init cache hit: {key[:60]}...")
    return data


async def set_cached_processed_init(key: str, data: bytes, ttl: int = DEFAULT_PROCESSED_INIT_TTL):
    """Cache processed init segment data. No-op if Redis unavailable."""
    r = await get_redis_binary()
    if r is None:
        return

    redis_key = _processed_init_key(key)
    await r.set(redis_key, data, ex=ttl)
    logger.debug(f"[Redis] Processed init cache set ({ttl}s TTL, {len(data)} bytes): {key[:60]}...")


# =============================================================================
# In-flight Request Tracking
# =============================================================================
# Prevents duplicate upstream requests across all workers

INFLIGHT_PREFIX = "mfp:inflight:"
DEFAULT_INFLIGHT_TTL = 60  # seconds


def _inflight_key(key: str) -> str:
    """Generate Redis key for in-flight tracking."""
    key_hash = hashlib.md5(key.encode()).hexdigest()
    return f"{INFLIGHT_PREFIX}{key_hash}"


async def mark_inflight(key: str, ttl: int = DEFAULT_INFLIGHT_TTL) -> bool:
    """
    Mark a request as in-flight (being processed by some worker).

    If Redis is not available, always returns True (this worker is "first").

    Args:
        key: The request identifier
        ttl: Auto-expiry time in seconds

    Returns:
        True if this call marked it (first worker), False if already in-flight
    """
    r = await get_redis()
    if r is None:
        return True  # No Redis - always proceed

    inflight_key = _inflight_key(key)
    result = await r.set(inflight_key, "1", nx=True, ex=ttl)
    if result:
        logger.debug(f"[Redis] Marked in-flight: {key[:60]}...")
    return bool(result)


async def is_inflight(key: str) -> bool:
    """Check if a request is currently in-flight. Returns False if Redis unavailable."""
    r = await get_redis()
    if r is None:
        return False

    inflight_key = _inflight_key(key)
    return await r.exists(inflight_key) > 0


async def clear_inflight(key: str):
    """Clear in-flight marker (call when request completes). No-op if Redis unavailable."""
    r = await get_redis()
    if r is None:
        return

    inflight_key = _inflight_key(key)
    await r.delete(inflight_key)
    logger.debug(f"[Redis] Cleared in-flight: {key[:60]}...")


async def wait_for_completion(key: str, timeout: float = 30.0, poll_interval: float = 0.1) -> bool:
    """
    Wait for an in-flight request to complete.

    If Redis is not available, returns True immediately.

    Args:
        key: The request identifier
        timeout: Maximum time to wait
        poll_interval: Time between checks

    Returns:
        True if completed (inflight marker gone), False if timeout
    """
    r = await get_redis()
    if r is None:
        return True  # No Redis - don't wait

    deadline = time.time() + timeout
    while time.time() < deadline:
        if not await is_inflight(key):
            return True
        await asyncio.sleep(poll_interval)
    return False


# =============================================================================
# Cooldown/Throttle Tracking
# =============================================================================
# Prevents rapid repeated operations (e.g., background refresh throttling)

COOLDOWN_PREFIX = "mfp:cooldown:"


def _cooldown_key(key: str) -> str:
    """Generate Redis key for cooldown tracking."""
    key_hash = hashlib.md5(key.encode()).hexdigest()
    return f"{COOLDOWN_PREFIX}{key_hash}"


async def check_and_set_cooldown(key: str, cooldown_seconds: int) -> bool:
    """
    Check if cooldown has elapsed and set new cooldown if so.

    If Redis is not available, always returns True (no rate limiting).

    Args:
        key: The cooldown identifier
        cooldown_seconds: Duration of the cooldown period

    Returns:
        True if cooldown elapsed (and new cooldown set), False if still in cooldown
    """
    r = await get_redis()
    if r is None:
        return True  # No Redis - no rate limiting

    cooldown_key = _cooldown_key(key)
    # SET NX EX: only succeeds if key doesn't exist
    result = await r.set(cooldown_key, "1", nx=True, ex=cooldown_seconds)
    if result:
        logger.debug(f"[Redis] Cooldown set ({cooldown_seconds}s): {key[:60]}...")
        return True
    return False


async def is_in_cooldown(key: str) -> bool:
    """Check if currently in cooldown period. Returns False if Redis unavailable."""
    r = await get_redis()
    if r is None:
        return False

    cooldown_key = _cooldown_key(key)
    return await r.exists(cooldown_key) > 0


# =============================================================================
# HLS Transcode Session (Cross-Worker)
# =============================================================================
# Per-segment HLS transcode caching.
# Each segment is independently transcoded and cached. Segment output metadata
# (video/audio DTS, sequence number) is stored so consecutive segments can
# maintain timeline continuity without a persistent pipeline.

HLS_SEG_PREFIX = b"mfp:hls_seg:"
HLS_INIT_PREFIX = b"mfp:hls_init:"
HLS_SEG_META_PREFIX = "mfp:hls_smeta:"

HLS_SEG_TTL = 60  # 60 s -- short-lived; only for immediate retry/re-request
HLS_INIT_TTL = 3600  # 1 hour -- stable for the viewing session
HLS_SEG_META_TTL = 3600  # 1 hour -- needed for next-segment continuity


def _hls_seg_key(cache_key: str, seg_index: int) -> bytes:
    return HLS_SEG_PREFIX + f"{cache_key}:{seg_index}".encode()


def _hls_init_key(cache_key: str) -> bytes:
    return HLS_INIT_PREFIX + cache_key.encode()


def _hls_seg_meta_key(cache_key: str, seg_index: int) -> str:
    return f"{HLS_SEG_META_PREFIX}{cache_key}:{seg_index}"


async def hls_get_segment(cache_key: str, seg_index: int) -> Optional[bytes]:
    """Get a cached HLS segment from Redis. Returns None if unavailable."""
    r = await get_redis_binary()
    if r is None:
        return None
    try:
        return await r.get(_hls_seg_key(cache_key, seg_index))
    except Exception:
        return None


async def hls_set_segment(cache_key: str, seg_index: int, data: bytes) -> None:
    """Store an HLS segment in Redis with short TTL. No-op if Redis unavailable."""
    r = await get_redis_binary()
    if r is None:
        return
    try:
        await r.set(_hls_seg_key(cache_key, seg_index), data, ex=HLS_SEG_TTL)
    except Exception:
        logger.debug("[Redis] Failed to cache HLS segment %d", seg_index)


async def hls_get_init(cache_key: str) -> Optional[bytes]:
    """Get the cached HLS init segment from Redis."""
    r = await get_redis_binary()
    if r is None:
        return None
    try:
        return await r.get(_hls_init_key(cache_key))
    except Exception:
        return None


async def hls_set_init(cache_key: str, data: bytes) -> None:
    """Store the HLS init segment in Redis."""
    r = await get_redis_binary()
    if r is None:
        return
    try:
        await r.set(_hls_init_key(cache_key), data, ex=HLS_INIT_TTL)
    except Exception:
        logger.debug("[Redis] Failed to cache HLS init segment")


async def hls_get_segment_meta(cache_key: str, seg_index: int) -> Optional[dict]:
    """
    Get per-segment output metadata from Redis.

    Returns a dict with keys like ``video_dts_ms``, ``audio_dts_ms``,
    ``sequence_number``, or None if unavailable.
    """
    r = await get_redis()
    if r is None:
        return None
    try:
        raw = await r.get(_hls_seg_meta_key(cache_key, seg_index))
        if raw:
            return json.loads(raw)
    except Exception:
        pass
    return None


async def hls_set_segment_meta(cache_key: str, seg_index: int, meta: dict) -> None:
    """
    Store per-segment output metadata in Redis.

    ``meta`` should contain keys like ``video_dts_ms``, ``audio_dts_ms``,
    ``sequence_number`` so the next segment can continue the timeline.
    """
    r = await get_redis()
    if r is None:
        return
    try:
        await r.set(
            _hls_seg_meta_key(cache_key, seg_index),
            json.dumps(meta),
            ex=HLS_SEG_META_TTL,
        )
    except Exception:
        logger.debug("[Redis] Failed to set HLS segment meta %d", seg_index)
