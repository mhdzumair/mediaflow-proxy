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
    all_proxy: bool = Field(False, description="Enable proxy for all routes by default")
    transport_routes: Dict[str, RouteConfig] = Field(
        default_factory=dict, description="Pattern-based route configuration"
    )
    timeout: int = Field(30, description="Timeout for HTTP requests in seconds")

    def get_mounts(
        self, async_http: bool = True
    ) -> Dict[str, Optional[Union[httpx.HTTPTransport, httpx.AsyncHTTPTransport]]]:
        """
        Get a dictionary of httpx mount points to transport instances.
        """
        mounts: Dict[str, Optional[Union[httpx.HTTPTransport, httpx.AsyncHTTPTransport]]] = {}
        transport_cls = httpx.AsyncHTTPTransport if async_http else httpx.HTTPTransport

        # Configure specific routes from settings
        for pattern, route in self.transport_routes.items():
            mounts[pattern] = transport_cls(
                verify=route.verify_ssl,
                proxy=route.proxy_url or self.proxy_url if route.proxy else None,
            )

        # Hardcoded configuration for jxoplay.xyz - SSL verification disabled
        mounts["all://jxoplay.xyz"] = transport_cls(
            verify=False, proxy=self.proxy_url if self.all_proxy else None
        )

        # Hardcoded configuration for newkso.ru - SSL verification disabled
        mounts["all://newkso.ru"] = transport_cls(
            verify=False, proxy=self.proxy_url if self.all_proxy else None
        )
        mounts["all://*.newkso.ru"] = transport_cls(
            verify=False, proxy=self.proxy_url if self.all_proxy else None
        )

        # Set default proxy for all routes if enabled
        if self.all_proxy:
            mounts["all://"] = transport_cls(proxy=self.proxy_url)

        return mounts

    class Config:
        env_file = ".env"
        extra = "ignore"


class Settings(BaseSettings):
    api_password: str | None = None
    log_level: str = "INFO"
    transport_config: TransportConfig = Field(default_factory=TransportConfig)
    enable_streaming_progress: bool = False
    disable_home_page: bool = False
    disable_docs: bool = False
    disable_speedtest: bool = False
    stremio_proxy_url: str | None = None
    m3u8_content_routing: Literal["mediaflow", "stremio", "direct"] = "mediaflow"
    enable_hls_prebuffer: bool = False
    hls_prebuffer_segments: int = 5
    hls_prebuffer_cache_size: int = 50
    hls_prebuffer_max_memory_percent: int = 80
    hls_prebuffer_emergency_threshold: int = 90
    enable_dash_prebuffer: bool = False
    dash_prebuffer_segments: int = 5
    dash_prebuffer_cache_size: int = 50
    dash_prebuffer_max_memory_percent: int = 80
    dash_prebuffer_emergency_threshold: int = 90

    user_agent: str = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36"
    )

    class Config:
        env_file = ".env"
        extra = "ignore"


settings = Settings()
