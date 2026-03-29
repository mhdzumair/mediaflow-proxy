"""
Acestream session management with cross-process coordination.

This module provides:
- AcestreamSessionManager: Manages acestream sessions per infohash with cross-process coordination
- AcestreamSession: Represents a single acestream session with playback URLs
- AsyncMultiWriter: Fan-out writer for streaming to multiple clients (MPEG-TS mode)

Architecture:
- Uses Redis for cross-worker coordination and session registry
- Each worker can reuse existing session's playback_url (acestream allows multiple connections)
- Session cleanup via command_url?method=stop when all clients disconnect
"""

import asyncio
import hashlib
import json
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List
from uuid import uuid4

import aiohttp

from mediaflow_proxy.configs import settings
from mediaflow_proxy.utils import redis_utils

logger = logging.getLogger(__name__)


@dataclass
class AcestreamResponse:
    """Response from acestream's format=json API."""

    playback_url: str
    stat_url: str
    command_url: str
    infohash: str
    playback_session_id: str
    is_live: bool
    is_encrypted: bool


@dataclass
class AcestreamSession:
    """
    Represents an active acestream session.

    A session is created when the first client requests a stream for an infohash.
    Multiple clients can share the same session (same playback_url).
    """

    infohash: str
    pid: str
    playback_url: str
    command_url: str
    stat_url: str
    playback_session_id: str
    is_live: bool
    created_at: float = field(default_factory=time.time)
    last_access: float = field(default_factory=time.time)
    last_segment_request: float = field(default_factory=time.time)
    client_count: int = 0

    def touch(self) -> None:
        """Update last access time."""
        self.last_access = time.time()

    def touch_segment(self) -> None:
        """Update last segment request time (indicates active playback)."""
        now = time.time()
        self.last_access = now
        self.last_segment_request = now

    def is_actively_streaming(self, timeout: float = 30.0) -> bool:
        """Check if this session has recent segment activity."""
        return (time.time() - self.last_segment_request) < timeout

    def to_dict(self) -> Dict[str, Any]:
        """Convert session to dictionary for file-based registry."""
        return {
            "infohash": self.infohash,
            "pid": self.pid,
            "playback_url": self.playback_url,
            "command_url": self.command_url,
            "stat_url": self.stat_url,
            "playback_session_id": self.playback_session_id,
            "is_live": self.is_live,
            "created_at": self.created_at,
            "last_access": self.last_access,
            "last_segment_request": self.last_segment_request,
            "worker_pid": os.getpid(),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AcestreamSession":
        """Create session from dictionary."""
        return cls(
            infohash=data["infohash"],
            pid=data["pid"],
            playback_url=data["playback_url"],
            command_url=data["command_url"],
            stat_url=data["stat_url"],
            playback_session_id=data["playback_session_id"],
            is_live=data.get("is_live", True),
            created_at=data.get("created_at", time.time()),
            last_access=data.get("last_access", time.time()),
            last_segment_request=data.get("last_segment_request", time.time()),
        )


class AsyncMultiWriter:
    """
    Async multi-writer for fan-out streaming to multiple clients.

    Based on acexy's PMultiWriter but adapted for Python asyncio.
    Writes are done in parallel to all connected writers.
    Writers that fail are automatically removed.
    """

    def __init__(self):
        self._writers: List[asyncio.StreamWriter] = []
        self._lock = asyncio.Lock()

    async def add(self, writer: asyncio.StreamWriter) -> None:
        """Add a writer to the list."""
        async with self._lock:
            if writer not in self._writers:
                self._writers.append(writer)
                logger.debug(f"[AsyncMultiWriter] Added writer, total: {len(self._writers)}")

    async def remove(self, writer: asyncio.StreamWriter) -> None:
        """Remove a writer from the list."""
        async with self._lock:
            if writer in self._writers:
                self._writers.remove(writer)
                logger.debug(f"[AsyncMultiWriter] Removed writer, total: {len(self._writers)}")

    async def write(self, data: bytes) -> int:
        """
        Write data to all connected writers in parallel.

        Writers that fail are automatically removed.

        Returns:
            Number of successful writes.
        """
        if not data:
            return 0

        async with self._lock:
            if not self._writers:
                return 0

            writers_copy = list(self._writers)

        failed_writers = []
        successful = 0

        async def write_to_single(writer: asyncio.StreamWriter) -> bool:
            try:
                writer.write(data)
                await writer.drain()
                return True
            except (ConnectionResetError, BrokenPipeError, ConnectionError) as e:
                logger.debug(f"[AsyncMultiWriter] Writer disconnected: {e}")
                return False
            except Exception as e:
                logger.warning(f"[AsyncMultiWriter] Write error: {e}")
                return False

        # Write to all writers in parallel
        results = await asyncio.gather(
            *[write_to_single(w) for w in writers_copy],
            return_exceptions=True,
        )

        for writer, result in zip(writers_copy, results):
            if result is True:
                successful += 1
            else:
                failed_writers.append(writer)

        # Remove failed writers
        if failed_writers:
            async with self._lock:
                for writer in failed_writers:
                    if writer in self._writers:
                        self._writers.remove(writer)
                        try:
                            writer.close()
                        except Exception:
                            pass

        return successful

    @property
    def count(self) -> int:
        """Number of connected writers."""
        return len(self._writers)

    async def close_all(self) -> None:
        """Close all writers."""
        async with self._lock:
            for writer in self._writers:
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass
            self._writers.clear()


class AcestreamSessionManager:
    """
    Manages acestream sessions with cross-process coordination.

    Features:
    - Per-worker session tracking
    - Redis-based session registry for cross-worker visibility
    - Session creation via acestream's format=json API
    - Session cleanup via command_url?method=stop
    - Session keepalive via periodic stat_url polling
    """

    # Redis key prefixes
    REGISTRY_PREFIX = "mfp:acestream:session:"
    REGISTRY_TTL = 3600  # 1 hour

    def __init__(self):
        # Per-worker session tracking (infohash -> session)
        self._sessions: Dict[str, AcestreamSession] = {}

        # Keepalive task
        self._keepalive_task: Optional[asyncio.Task] = None
        self._cleanup_task: Optional[asyncio.Task] = None

        # HTTP client session
        self._http_session: Optional[aiohttp.ClientSession] = None

        logger.info("[AcestreamSessionManager] Initialized with Redis backend")

    def _get_registry_key(self, infohash: str) -> str:
        """Get the Redis key for an infohash."""
        hash_key = hashlib.md5(infohash.encode()).hexdigest()
        return f"{self.REGISTRY_PREFIX}{hash_key}"

    async def _get_http_session(self) -> aiohttp.ClientSession:
        """Get or create HTTP client session."""
        if self._http_session is None or self._http_session.closed:
            self._http_session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30))
        return self._http_session

    async def _read_registry(self, infohash: str) -> Optional[Dict[str, Any]]:
        """Read session data from Redis registry."""
        try:
            r = await redis_utils.get_redis()
            key = self._get_registry_key(infohash)
            data = await r.get(key)
            if data:
                return json.loads(data)
        except Exception as e:
            logger.warning(f"[AcestreamSessionManager] Error reading registry: {e}")
        return None

    async def _write_registry(self, session: AcestreamSession) -> None:
        """Write session data to Redis registry."""
        try:
            r = await redis_utils.get_redis()
            key = self._get_registry_key(session.infohash)
            await r.set(key, json.dumps(session.to_dict()), ex=self.REGISTRY_TTL)
        except Exception as e:
            logger.warning(f"[AcestreamSessionManager] Error writing registry: {e}")

    async def _delete_registry(self, infohash: str) -> None:
        """Delete session from Redis registry."""
        try:
            r = await redis_utils.get_redis()
            key = self._get_registry_key(infohash)
            await r.delete(key)
        except Exception as e:
            logger.warning(f"[AcestreamSessionManager] Error deleting registry: {e}")

    async def _create_acestream_session(self, infohash: str, content_id: Optional[str] = None) -> AcestreamResponse:
        """
        Create a new acestream session via format=json API.

        Args:
            infohash: The infohash of the content (40-char hex from magnet link)
            content_id: Optional content ID (alternative to infohash)

        Returns:
            AcestreamResponse with playback URLs

        Raises:
            Exception if session creation fails
        """
        base_url = f"http://{settings.acestream_host}:{settings.acestream_port}"
        pid = str(uuid4())

        # Build URL with parameters
        # Acestream uses different parameter names:
        # - 'id' or 'content_id' for content IDs
        # - 'infohash' for magnet link hashes (40-char hex)
        params = {
            "format": "json",
            "pid": pid,
        }

        if content_id:
            # Content ID provided - use 'id' parameter
            params["id"] = content_id
        else:
            # Only infohash provided - use 'infohash' parameter
            params["infohash"] = infohash

        # Use manifest.m3u8 for HLS or getstream for MPEG-TS
        # We'll use manifest.m3u8 as the primary since we leverage HLS infrastructure
        url = f"{base_url}/ace/manifest.m3u8"

        session = await self._get_http_session()
        try:
            async with session.get(url, params=params) as response:
                response.raise_for_status()
                data = await response.json()

                if data.get("error"):
                    raise Exception(f"Acestream error: {data['error']}")

                resp = data.get("response", {})
                return AcestreamResponse(
                    playback_url=resp.get("playback_url", ""),
                    stat_url=resp.get("stat_url", ""),
                    command_url=resp.get("command_url", ""),
                    infohash=resp.get("infohash", infohash),
                    playback_session_id=resp.get("playback_session_id", ""),
                    is_live=bool(resp.get("is_live", 1)),
                    is_encrypted=bool(resp.get("is_encrypted", 0)),
                )
        except aiohttp.ClientError as e:
            logger.error(f"[AcestreamSessionManager] HTTP error creating session: {e}")
            raise

    async def get_or_create_session(
        self,
        infohash: str,
        content_id: Optional[str] = None,
        increment_client: bool = True,
    ) -> AcestreamSession:
        """
        Get an existing session or create a new one.

        Uses Redis locking to coordinate session creation across workers.

        Args:
            infohash: The infohash of the content
            content_id: Optional content ID
            increment_client: Whether to increment client count (False for manifest requests)

        Returns:
            AcestreamSession instance
        """
        # Check if we already have this session in this worker
        if infohash in self._sessions:
            session = self._sessions[infohash]
            session.touch()
            if increment_client:
                session.client_count += 1
            logger.info(
                f"[AcestreamSessionManager] Reusing existing session: {infohash[:16]}... "
                f"(clients: {session.client_count})"
            )
            return session

        # Need to create or fetch session - use Redis lock
        lock_key = f"acestream_session:{infohash}"
        lock_acquired = await redis_utils.acquire_lock(lock_key, ttl=30, timeout=30)

        if not lock_acquired:
            raise Exception(f"Failed to acquire lock for acestream session: {infohash[:16]}...")

        try:
            # Double-check after acquiring lock
            if infohash in self._sessions:
                session = self._sessions[infohash]
                session.touch()
                if increment_client:
                    session.client_count += 1
                return session

            # Check registry for existing session from another worker
            registry_data = await self._read_registry(infohash)

            if registry_data:
                # Validate session is still alive by checking stat_url
                if await self._validate_session(registry_data.get("stat_url", "")):
                    logger.info(f"[AcestreamSessionManager] Using existing session from registry: {infohash[:16]}...")
                    session = AcestreamSession.from_dict(registry_data)
                    session.client_count = 1 if increment_client else 0
                    self._sessions[infohash] = session
                    self._ensure_tasks()
                    return session
                else:
                    # Session is stale, remove from registry
                    await self._delete_registry(infohash)

            # Create new session
            logger.info(f"[AcestreamSessionManager] Creating new session: {infohash[:16]}...")
            try:
                response = await self._create_acestream_session(infohash, content_id)

                session = AcestreamSession(
                    infohash=infohash,
                    pid=str(uuid4()),
                    playback_url=response.playback_url,
                    command_url=response.command_url,
                    stat_url=response.stat_url,
                    playback_session_id=response.playback_session_id,
                    is_live=response.is_live,
                    client_count=1 if increment_client else 0,
                )

                self._sessions[infohash] = session
                await self._write_registry(session)
                self._ensure_tasks()

                logger.info(
                    f"[AcestreamSessionManager] Created session: {infohash[:16]}... "
                    f"playback_url: {response.playback_url}"
                )
                return session

            except Exception as e:
                logger.error(f"[AcestreamSessionManager] Failed to create session: {e}")
                raise
        finally:
            await redis_utils.release_lock(lock_key)

    async def _validate_session(self, stat_url: str) -> bool:
        """Check if a session is still valid by polling stat_url."""
        if not stat_url:
            return False

        try:
            session = await self._get_http_session()
            async with session.get(stat_url, timeout=aiohttp.ClientTimeout(total=5)) as response:
                if response.status == 200:
                    return True
        except Exception as e:
            logger.debug(f"[AcestreamSessionManager] Session validation failed: {e}")
        return False

    async def release_session(self, infohash: str) -> None:
        """
        Release a client's hold on a session.

        Decrements client count. When count reaches 0, the session is closed.

        Args:
            infohash: The infohash of the session to release
        """
        if infohash not in self._sessions:
            return

        session = self._sessions[infohash]
        session.client_count -= 1

        logger.info(
            f"[AcestreamSessionManager] Released client from session: {infohash[:16]}... "
            f"(remaining clients: {session.client_count})"
        )

        if session.client_count <= 0:
            await self._close_session(infohash)

    async def invalidate_session(self, infohash: str) -> None:
        """
        Invalidate a stale session (e.g., when we get 403 from acestream).

        This forces the session to be closed and removed from registry,
        so next request will create a fresh session.

        Args:
            infohash: The infohash of the session to invalidate
        """
        logger.warning(f"[AcestreamSessionManager] Invalidating stale session: {infohash[:16]}...")

        if infohash in self._sessions:
            session = self._sessions.pop(infohash)
            # Try to stop the session gracefully
            if session.command_url:
                try:
                    http_session = await self._get_http_session()
                    url = f"{session.command_url}?method=stop"
                    async with http_session.get(url, timeout=aiohttp.ClientTimeout(total=3)) as response:
                        logger.debug(f"[AcestreamSessionManager] Stop command sent: {response.status}")
                except Exception as e:
                    logger.debug(f"[AcestreamSessionManager] Error stopping stale session: {e}")

        # Always remove from registry
        await self._delete_registry(infohash)
        logger.info(f"[AcestreamSessionManager] Session invalidated: {infohash[:16]}...")

    async def _close_session(self, infohash: str) -> None:
        """
        Close an acestream session.

        Calls command_url?method=stop to properly close the session.
        """
        if infohash not in self._sessions:
            return

        session = self._sessions.pop(infohash)

        lock_key = f"acestream_session:{infohash}"
        lock_acquired = await redis_utils.acquire_lock(lock_key, ttl=10, timeout=10)

        try:
            # Check if this is the last worker using this session
            registry_data = await self._read_registry(infohash)

            # Only close if we're the owner or session is stale
            if registry_data and registry_data.get("worker_pid") == os.getpid():
                # We're the owner, close the session
                if session.command_url:
                    try:
                        http_session = await self._get_http_session()
                        url = f"{session.command_url}?method=stop"
                        async with http_session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as response:
                            logger.info(
                                f"[AcestreamSessionManager] Closed session: {infohash[:16]}... "
                                f"(status: {response.status})"
                            )
                    except Exception as e:
                        logger.warning(f"[AcestreamSessionManager] Error closing session: {e}")

                await self._delete_registry(infohash)
            else:
                # Another worker may still be using this session
                logger.debug(
                    f"[AcestreamSessionManager] Session {infohash[:16]}... owned by another worker, not closing"
                )
        finally:
            if lock_acquired:
                await redis_utils.release_lock(lock_key)

    def _ensure_tasks(self) -> None:
        """Ensure background tasks are running."""
        if self._keepalive_task is None or self._keepalive_task.done():
            self._keepalive_task = asyncio.create_task(self._keepalive_loop())

        if self._cleanup_task is None or self._cleanup_task.done():
            self._cleanup_task = asyncio.create_task(self._cleanup_loop())

    async def _keepalive_loop(self) -> None:
        """Periodically poll stat_url to keep sessions alive with active clients or recent segment activity."""
        while True:
            try:
                await asyncio.sleep(settings.acestream_keepalive_interval)

                for infohash, session in list(self._sessions.items()):
                    # Keepalive sessions with active clients OR recent segment activity
                    # This ensures HLS streams (which don't use client_count) stay alive
                    has_recent_activity = session.is_actively_streaming(timeout=settings.acestream_empty_timeout)

                    if session.client_count <= 0 and not has_recent_activity:
                        logger.debug(
                            f"[AcestreamSessionManager] Skipping keepalive (no clients, no recent segments): "
                            f"{infohash[:16]}..."
                        )
                        continue

                    if session.stat_url:
                        try:
                            http_session = await self._get_http_session()
                            async with http_session.get(
                                session.stat_url,
                                timeout=aiohttp.ClientTimeout(total=5),
                            ) as response:
                                if response.status == 200:
                                    session.touch()
                                    await self._write_registry(session)
                                    logger.debug(
                                        f"[AcestreamSessionManager] Keepalive OK: {infohash[:16]}... "
                                        f"(clients: {session.client_count}, recent_activity: {has_recent_activity})"
                                    )
                                else:
                                    logger.warning(
                                        f"[AcestreamSessionManager] Keepalive failed: {infohash[:16]}... "
                                        f"(status: {response.status})"
                                    )
                        except Exception as e:
                            logger.warning(f"[AcestreamSessionManager] Keepalive error: {infohash[:16]}... - {e}")

            except asyncio.CancelledError:
                return
            except Exception as e:
                logger.warning(f"[AcestreamSessionManager] Keepalive loop error: {e}")

    async def _cleanup_loop(self) -> None:
        """Periodically clean up stale sessions."""
        while True:
            try:
                await asyncio.sleep(15)  # Check every 15 seconds

                now = time.time()
                timeout = settings.acestream_session_timeout
                empty_timeout = settings.acestream_empty_timeout

                for infohash, session in list(self._sessions.items()):
                    idle_time = now - session.last_access
                    segment_idle_time = now - session.last_segment_request

                    # Don't clean up sessions with recent segment activity (active playback)
                    # Use empty_timeout as the threshold for "recent" activity
                    if segment_idle_time < empty_timeout:
                        logger.debug(
                            f"[AcestreamSessionManager] Session has recent segment activity: {infohash[:16]}... "
                            f"(segment idle: {segment_idle_time:.0f}s)"
                        )
                        continue

                    # Clean up sessions with no clients after empty_timeout (faster cleanup)
                    if session.client_count <= 0 and idle_time > empty_timeout:
                        logger.info(
                            f"[AcestreamSessionManager] Cleaning up empty session: {infohash[:16]}... "
                            f"(idle: {idle_time:.0f}s, segment idle: {segment_idle_time:.0f}s)"
                        )
                        await self._close_session(infohash)
                    # Clean up any session after session_timeout regardless of client count
                    elif idle_time > timeout:
                        logger.info(
                            f"[AcestreamSessionManager] Cleaning up stale session: {infohash[:16]}... "
                            f"(idle: {idle_time:.0f}s, segment idle: {segment_idle_time:.0f}s, clients: {session.client_count})"
                        )
                        await self._close_session(infohash)

                # Note: Redis entries expire via TTL, no manual cleanup needed

            except asyncio.CancelledError:
                return
            except Exception as e:
                logger.warning(f"[AcestreamSessionManager] Cleanup loop error: {e}")

    def get_session(self, infohash: str) -> Optional[AcestreamSession]:
        """Get a session by infohash if it exists in this worker."""
        return self._sessions.get(infohash)

    def get_active_sessions(self) -> Dict[str, AcestreamSession]:
        """Get all active sessions in this worker."""
        return dict(self._sessions)

    async def close(self) -> None:
        """Close the session manager and clean up resources."""
        # Cancel background tasks
        if self._keepalive_task:
            self._keepalive_task.cancel()
            try:
                await self._keepalive_task
            except asyncio.CancelledError:
                pass

        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass

        # Close all sessions
        for infohash in list(self._sessions.keys()):
            await self._close_session(infohash)

        # Close HTTP session
        if self._http_session and not self._http_session.closed:
            await self._http_session.close()

        logger.info("[AcestreamSessionManager] Closed")


# Global session manager instance
acestream_manager = AcestreamSessionManager()
