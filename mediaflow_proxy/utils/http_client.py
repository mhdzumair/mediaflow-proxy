"""
aiohttp client factory with URL-based SSL verification and proxy routing.

This module provides a centralized HTTP client factory for aiohttp,
allowing per-URL configuration of SSL verification and proxy routing.
"""

import logging
import ssl
import typing
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple
from urllib.parse import urlparse

import aiohttp
from aiohttp import ClientSession, ClientTimeout, TCPConnector

logger = logging.getLogger(__name__)


@dataclass
class RouteMatch:
    """Configuration for a matched route."""

    verify_ssl: bool = True
    proxy_url: Optional[str] = None


@dataclass
class URLRoutingConfig:
    """
    URL-based routing configuration for SSL verification and proxy settings.

    Supports pattern matching:
    - "all://*.example.com" - matches all protocols for *.example.com
    - "https://api.example.com" - matches specific protocol and host
    - "all://" - default fallback for all URLs
    """

    # Pattern -> (verify_ssl, proxy_url)
    routes: Dict[str, Tuple[bool, Optional[str]]] = field(default_factory=dict)

    # Global defaults
    default_verify_ssl: bool = True
    default_proxy_url: Optional[str] = None

    def add_route(
        self,
        pattern: str,
        verify_ssl: bool = True,
        proxy_url: Optional[str] = None,
    ) -> None:
        """
        Add a route configuration.

        Args:
            pattern: URL pattern (e.g., "all://*.example.com", "https://api.example.com")
            verify_ssl: Whether to verify SSL for this pattern
            proxy_url: Proxy URL to use for this pattern (None = no proxy)
        """
        self.routes[pattern] = (verify_ssl, proxy_url)

    def match_url(self, url: str) -> RouteMatch:
        """
        Find the best matching route for a URL.

        Args:
            url: The URL to match

        Returns:
            RouteMatch with SSL and proxy settings
        """
        if not url:
            return RouteMatch(
                verify_ssl=self.default_verify_ssl,
                proxy_url=self.default_proxy_url,
            )

        parsed = urlparse(url)
        scheme = parsed.scheme.lower()
        host = parsed.netloc.lower()

        # Remove port from host for matching
        if ":" in host:
            host = host.split(":")[0]

        best_match: Optional[RouteMatch] = None
        best_specificity = -1

        for pattern, (verify_ssl, proxy_url) in self.routes.items():
            specificity = self._match_pattern(pattern, scheme, host)
            if specificity > best_specificity:
                best_specificity = specificity
                best_match = RouteMatch(verify_ssl=verify_ssl, proxy_url=proxy_url)

        if best_match:
            return best_match

        # Return defaults
        return RouteMatch(
            verify_ssl=self.default_verify_ssl,
            proxy_url=self.default_proxy_url,
        )

    def _match_pattern(self, pattern: str, scheme: str, host: str) -> int:
        """
        Check if a pattern matches the given scheme and host.

        Returns specificity score (higher = more specific match):
        - -1: No match
        - 0: Default match (all://)
        - 1: Scheme match only
        - 2: Wildcard host match
        - 3: Exact host match
        """
        # Parse pattern
        if "://" in pattern:
            pattern_scheme, pattern_host = pattern.split("://", 1)
        else:
            return -1

        # Check scheme
        scheme_matches = pattern_scheme.lower() == "all" or pattern_scheme.lower() == scheme

        if not scheme_matches:
            return -1

        # Empty host = default route
        if not pattern_host:
            return 0

        # Check host with wildcard support
        if pattern_host.startswith("*."):
            # Wildcard subdomain match
            suffix = pattern_host[1:]  # Remove the *
            if host.endswith(suffix) or host == pattern_host[2:]:
                return 2
            return -1
        elif pattern_host == host:
            # Exact match
            return 3
        else:
            return -1


# Global routing configuration - will be initialized from settings
_global_routing_config: Optional[URLRoutingConfig] = None
_routing_initialized = False


def get_routing_config() -> URLRoutingConfig:
    """Get the global URL routing configuration."""
    global _global_routing_config
    if _global_routing_config is None:
        _global_routing_config = URLRoutingConfig()
    return _global_routing_config


def initialize_routing_from_config(transport_config) -> None:
    """
    Initialize the global routing configuration from TransportConfig.

    Args:
        transport_config: The TransportConfig instance from settings
    """
    global _global_routing_config, _routing_initialized

    config = URLRoutingConfig(
        default_verify_ssl=not transport_config.disable_ssl_verification_globally,
        default_proxy_url=transport_config.proxy_url if transport_config.all_proxy else None,
    )

    # Add configured routes
    for pattern, route in transport_config.transport_routes.items():
        global_verify = not transport_config.disable_ssl_verification_globally
        verify_ssl = route.verify_ssl if global_verify else False
        proxy_url = route.proxy_url or transport_config.proxy_url if route.proxy else None
        config.add_route(pattern, verify_ssl=verify_ssl, proxy_url=proxy_url)

    # Hardcoded routes for specific domains (SSL verification disabled)
    hardcoded_domains = [
        "all://jxoplay.xyz",
        "all://dlhd.dad",
        "all://*.newkso.ru",
    ]

    for domain in hardcoded_domains:
        proxy_url = transport_config.proxy_url if transport_config.all_proxy else None
        config.add_route(domain, verify_ssl=False, proxy_url=proxy_url)

    # Default route for global settings
    if transport_config.all_proxy or transport_config.disable_ssl_verification_globally:
        default_proxy = transport_config.proxy_url if transport_config.all_proxy else None
        config.add_route(
            "all://",
            verify_ssl=not transport_config.disable_ssl_verification_globally,
            proxy_url=default_proxy,
        )

    _global_routing_config = config
    _routing_initialized = True

    logger.info(f"Initialized aiohttp routing with {len(config.routes)} routes")


def _ensure_routing_initialized():
    """Ensure routing configuration is initialized from settings."""
    global _routing_initialized
    if not _routing_initialized:
        from mediaflow_proxy.configs import settings

        initialize_routing_from_config(settings.transport_config)


def _get_ssl_context(verify: bool) -> ssl.SSLContext:
    """Get an SSL context with the specified verification setting."""
    if verify:
        return ssl.create_default_context()
    else:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx


def create_proxy_connector(proxy_url: str, verify_ssl: bool = True) -> aiohttp.BaseConnector:
    """
    Create a connector for proxy connections, supporting SOCKS5 and HTTP proxies.

    Args:
        proxy_url: The proxy URL (socks5://..., http://..., https://...)
        verify_ssl: Whether to verify SSL certificates

    Returns:
        Appropriate connector for the proxy type
    """
    parsed = urlparse(proxy_url)
    scheme = parsed.scheme.lower()

    ssl_context = _get_ssl_context(verify_ssl)

    if scheme in ("socks5", "socks5h", "socks4", "socks4a"):
        try:
            from aiohttp_socks import ProxyConnector, ProxyType

            proxy_type_map = {
                "socks5": ProxyType.SOCKS5,
                "socks5h": ProxyType.SOCKS5,
                "socks4": ProxyType.SOCKS4,
                "socks4a": ProxyType.SOCKS4,
            }

            return ProxyConnector(
                proxy_type=proxy_type_map[scheme],
                host=parsed.hostname,
                port=parsed.port or 1080,
                username=parsed.username,
                password=parsed.password,
                rdns=scheme.endswith("h"),  # Remote DNS resolution for socks5h
                ssl=ssl_context if not verify_ssl else None,
            )
        except ImportError:
            logger.warning("aiohttp-socks not installed, SOCKS proxy support unavailable")
            raise
    else:
        # HTTP/HTTPS proxy - use standard connector
        # The proxy URL will be passed to the request method
        return TCPConnector(
            ssl=ssl_context,
            limit=100,
            limit_per_host=10,
        )


def _create_connector(proxy_url: Optional[str], verify_ssl: bool) -> Tuple[aiohttp.BaseConnector, Optional[str]]:
    """
    Create an appropriate connector based on proxy configuration.

    Args:
        proxy_url: The proxy URL or None
        verify_ssl: Whether to verify SSL certificates

    Returns:
        Tuple of (connector, effective_proxy_url)
        For SOCKS proxies, effective_proxy_url is None (handled by connector)
        For HTTP proxies, effective_proxy_url is passed to requests
    """
    if proxy_url:
        parsed_proxy = urlparse(proxy_url)
        if parsed_proxy.scheme in ("socks5", "socks5h", "socks4", "socks4a"):
            # SOCKS proxy - use special connector, proxy handled internally
            connector = create_proxy_connector(proxy_url, verify_ssl)
            return connector, None
        else:
            # HTTP proxy - use standard connector, pass proxy to request
            ssl_ctx = _get_ssl_context(verify_ssl)
            connector = TCPConnector(ssl=ssl_ctx, limit=100, limit_per_host=10)
            return connector, proxy_url
    else:
        ssl_ctx = _get_ssl_context(verify_ssl)
        connector = TCPConnector(ssl=ssl_ctx, limit=100, limit_per_host=10)
        return connector, None


@asynccontextmanager
async def create_aiohttp_session(
    url: str = None,
    timeout: typing.Union[int, float, ClientTimeout] = None,
    headers: typing.Optional[typing.Dict[str, str]] = None,
    verify: typing.Optional[bool] = None,
) -> typing.AsyncGenerator[typing.Tuple[ClientSession, typing.Optional[str]], None]:
    """
    Create an aiohttp ClientSession with configured proxy routing and SSL settings.

    This is the primary way to create HTTP sessions in the application.
    It automatically applies URL-based routing for SSL verification and proxy settings.

    Args:
        url: The URL to configure the session for (used for routing)
        timeout: Request timeout (int/float for total seconds, or ClientTimeout)
        headers: Default headers for the session
        verify: Override SSL verification (None = use routing config)

    Yields:
        Tuple of (session, proxy_url) - proxy_url should be passed to request methods
    """
    _ensure_routing_initialized()

    # Get routing configuration for the URL
    routing_config = get_routing_config()
    route_match = routing_config.match_url(url)

    # Determine SSL verification
    if verify is not None:
        use_verify = verify
    else:
        use_verify = route_match.verify_ssl

    # Create timeout
    if timeout is None:
        from mediaflow_proxy.configs import settings

        timeout_config = ClientTimeout(total=settings.transport_config.timeout)
    elif isinstance(timeout, (int, float)):
        timeout_config = ClientTimeout(total=timeout)
    else:
        timeout_config = timeout

    # Create connector
    connector, effective_proxy_url = _create_connector(route_match.proxy_url, use_verify)

    session = ClientSession(
        connector=connector,
        timeout=timeout_config,
        headers=headers,
    )

    try:
        yield session, effective_proxy_url
    finally:
        await session.close()
