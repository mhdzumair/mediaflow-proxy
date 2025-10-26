from typing import Dict, Literal, Optional, Union

import httpx
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings


class RouteConfig(BaseModel):
    """Configuration for a specific route"""

    proxy: bool = True
    proxy_url: Optional[str] = None
    verify_ssl: bool = True


class TransportConfig(BaseSettings):
    """Main proxy configuration"""

    proxy_url: Optional[str] = Field(
        None, description="Primary proxy URL. Example: socks5://user:pass@proxy:1080 or http://proxy:8080"
    )
    disable_ssl_verification_globally: bool = Field(
        False, description="Disable SSL verification for all requests globally."
    )
    all_proxy: bool = Field(False, description="Enable proxy for all routes by default")
    transport_routes: Dict[str, RouteConfig] = Field(
        default_factory=dict, description="Pattern-based route configuration"
    )
    timeout: int = Field(60, description="Timeout for HTTP requests in seconds")

    def get_mounts(
        self, async_http: bool = True
    ) -> Dict[str, Optional[Union[httpx.HTTPTransport, httpx.AsyncHTTPTransport]]]:
        """
        Get a dictionary of httpx mount points to transport instances.
        """
        mounts = {}
        transport_cls = httpx.AsyncHTTPTransport if async_http else httpx.HTTPTransport
        global_verify = not self.disable_ssl_verification_globally

        # Configure specific routes
        for pattern, route in self.transport_routes.items():
            mounts[pattern] = transport_cls(
                verify=route.verify_ssl if global_verify else False,
                proxy=route.proxy_url or self.proxy_url if route.proxy else None,
            )

        # Hardcoded configuration for jxoplay.xyz domain - SSL verification disabled
        mounts["all://jxoplay.xyz"] = transport_cls(
            verify=False, proxy=self.proxy_url if self.all_proxy else None
        )

        mounts["all://dlhd.dad"] = transport_cls(
            verify=False, proxy=self.proxy_url if self.all_proxy else None
        )
        
        mounts["all://*.newkso.ru"] = transport_cls(
            verify=False, proxy=self.proxy_url if self.all_proxy else None
        )

        # Apply global settings for proxy and SSL
        default_proxy_url = self.proxy_url if self.all_proxy else None
        if default_proxy_url or not global_verify:
            mounts["all://"] = transport_cls(proxy=default_proxy_url, verify=global_verify)

        # Set default proxy for all routes if enabled
        # This part is now handled above to combine proxy and SSL settings
        # if self.all_proxy:
        #     mounts["all://"] = transport_cls(proxy=self.proxy_url)

        return mounts

    class Config:
        env_file = ".env"
        extra = "ignore"


class Settings(BaseSettings):
    api_password: str | None = None  # The password for protecting the API endpoints.
    log_level: str = "INFO"  # The logging level to use.
    transport_config: TransportConfig = Field(default_factory=TransportConfig)  # Configuration for httpx transport.
    enable_streaming_progress: bool = False  # Whether to enable streaming progress tracking.
    disable_home_page: bool = False  # Whether to disable the home page UI.
    disable_docs: bool = False  # Whether to disable the API documentation (Swagger UI).
    disable_speedtest: bool = False  # Whether to disable the speedtest UI.
    stremio_proxy_url: str | None = None  # The Stremio server URL for alternative content proxying.
    m3u8_content_routing: Literal["mediaflow", "stremio", "direct"] = (
        "mediaflow"  # Routing strategy for M3U8 content URLs: "mediaflow", "stremio", or "direct"
    )
    enable_hls_prebuffer: bool = False  # Whether to enable HLS pre-buffering for improved streaming performance.
    hls_prebuffer_segments: int = 5  # Number of segments to pre-buffer ahead.
    hls_prebuffer_cache_size: int = 50  # Maximum number of segments to cache in memory.
    hls_prebuffer_max_memory_percent: int = 80  # Maximum percentage of system memory to use for HLS pre-buffer cache.
    hls_prebuffer_emergency_threshold: int = 90  # Emergency threshold percentage to trigger aggressive cache cleanup.
    enable_dash_prebuffer: bool = False  # Whether to enable DASH pre-buffering for improved streaming performance.
    dash_prebuffer_segments: int = 5  # Number of segments to pre-buffer ahead.
    dash_prebuffer_cache_size: int = 50  # Maximum number of segments to cache in memory.
    dash_prebuffer_max_memory_percent: int = 80  # Maximum percentage of system memory to use for DASH pre-buffer cache.
    dash_prebuffer_emergency_threshold: int = 90  # Emergency threshold percentage to trigger aggressive cache cleanup.
    mpd_live_init_cache_ttl: int = 0  # TTL (seconds) for live init segment cache; 0 disables caching.
    mpd_live_playlist_depth: int = 8  # Number of recent segments to expose per live playlist variant.

    user_agent: str = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36"  # The user agent to use for HTTP requests.
    )

    class Config:
        env_file = ".env"
        extra = "ignore"


settings = Settings()
