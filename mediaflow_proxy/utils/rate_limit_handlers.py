"""
Rate limit handlers for host-specific rate limiting strategies.

This module provides handler classes that implement specific rate limiting
logic for different streaming hosts (e.g., Vidoza's aggressive 509 rate limiting).

Similar pattern to stream_transformers.py but for rate limiting behavior.
"""

import logging
from typing import Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class RateLimitHandler:
    """
    Base class for rate limit handlers.

    Subclasses should override properties to customize rate limiting behavior.
    """

    @property
    def cooldown_seconds(self) -> int:
        """
        Duration in seconds to wait between upstream connections.
        Default: 0 (no cooldown, allow immediate requests)
        """
        return 0

    @property
    def use_head_cache(self) -> bool:
        """
        Whether to cache HEAD responses to avoid upstream calls.
        Default: False
        """
        return False

    @property
    def use_stream_gate(self) -> bool:
        """
        Whether to use distributed locking to serialize requests.
        Default: False
        """
        return False

    @property
    def exclusive_stream(self) -> bool:
        """
        If True, the stream gate is held for the ENTIRE duration of the stream.
        This prevents any concurrent connections to the same URL.
        Required for hosts that 509 on ANY concurrent streams.
        Default: False (gate released after headers received)
        """
        return False

    @property
    def retry_after_seconds(self) -> int:
        """
        Value for Retry-After header when returning 503.
        Default: 2
        """
        return 2


class VidozaRateLimitHandler(RateLimitHandler):
    """
    Rate limit handler for Vidoza CDN.

    Vidoza aggressively rate-limits (509) if ANY concurrent connections exist
    to the same URL from the same IP. This handler:
    - Uses EXCLUSIVE stream gate: only ONE stream at a time (gate held during entire stream)
    - Caches HEAD responses to serve repeated probes without connections
    - ExoPlayer/clients must wait for the current stream to finish before starting a new one

    WARNING: This means only one client can actively stream at a time. Other clients will
    wait (up to timeout) and eventually get 503 if the current stream is too long.
    """

    @property
    def cooldown_seconds(self) -> int:
        return 0  # No cooldown needed - we use exclusive streaming instead

    @property
    def use_head_cache(self) -> bool:
        return True

    @property
    def use_stream_gate(self) -> bool:
        return True

    @property
    def exclusive_stream(self) -> bool:
        """
        If True, the stream gate is held for the ENTIRE duration of the stream,
        not just at the start. This prevents any concurrent connections.
        Required for hosts like Vidoza that 509 on ANY concurrent connections.
        """
        return True

    @property
    def retry_after_seconds(self) -> int:
        return 5


class AggressiveRateLimitHandler(RateLimitHandler):
    """
    Generic aggressive rate limit handler for hosts with strict rate limiting.

    Use this for hosts that show similar behavior to Vidoza but may have
    different thresholds.
    """

    @property
    def cooldown_seconds(self) -> int:
        return 3

    @property
    def use_head_cache(self) -> bool:
        return True

    @property
    def use_stream_gate(self) -> bool:
        return True

    @property
    def retry_after_seconds(self) -> int:
        return 2


# Registry of available rate limit handlers by ID
RATE_LIMIT_HANDLER_REGISTRY: dict[str, type[RateLimitHandler]] = {
    "vidoza": VidozaRateLimitHandler,
    "aggressive": AggressiveRateLimitHandler,
}

# Auto-detection: hostname patterns to handler IDs
# These patterns are checked against the video URL hostname
#
# NOTE: Vidoza CDN DOES rate limit concurrent connections from the same IP.
# When multiple clients request through the proxy, all requests come from
# the proxy's IP, triggering Vidoza's rate limit (509 errors).
# Stream-level rate limiting serializes requests to avoid this.
#
HOST_PATTERN_TO_HANDLER: dict[str, str] = {
    "vidoza.net": "vidoza",
    "vidoza.org": "vidoza",
    # Add more patterns as needed for hosts that rate-limit CDN streaming:
    # "example-cdn.com": "aggressive",
}


def get_rate_limit_handler(
    handler_id: Optional[str] = None,
    video_url: Optional[str] = None,
) -> RateLimitHandler:
    """
    Get a rate limit handler instance.

    Priority:
    1. Explicit handler_id if provided
    2. Auto-detect from video_url hostname
    3. Default (no rate limiting)

    Args:
        handler_id: Explicit handler identifier (e.g., "vidoza", "aggressive")
        video_url: Video URL for auto-detection based on hostname

    Returns:
        A rate limit handler instance. Returns base RateLimitHandler (no-op) if
        no handler specified and no auto-detection match.
    """
    # 1. Explicit handler ID
    if handler_id:
        handler_class = RATE_LIMIT_HANDLER_REGISTRY.get(handler_id)
        if handler_class:
            logger.debug(f"Using explicit rate limit handler: {handler_id}")
            return handler_class()
        else:
            logger.warning(f"Unknown rate limit handler ID: {handler_id}")

    # 2. Auto-detect from URL hostname
    if video_url:
        try:
            hostname = urlparse(video_url).hostname or ""
            # Check each pattern
            for pattern, detected_handler_id in HOST_PATTERN_TO_HANDLER.items():
                if pattern in hostname:
                    handler_class = RATE_LIMIT_HANDLER_REGISTRY.get(detected_handler_id)
                    if handler_class:
                        logger.info(f"[RateLimit] Auto-detected handler '{detected_handler_id}' for host: {hostname}")
                        return handler_class()
            logger.debug(f"[RateLimit] No handler matched for hostname: {hostname}")
        except Exception as e:
            logger.warning(f"[RateLimit] Error during auto-detection: {e}")

    # 3. Default: no rate limiting
    return RateLimitHandler()


def get_available_handlers() -> list[str]:
    """Get list of available rate limit handler IDs."""
    return list(RATE_LIMIT_HANDLER_REGISTRY.keys())
