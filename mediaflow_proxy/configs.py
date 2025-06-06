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
        mounts = {}
        transport_cls = httpx.AsyncHTTPTransport if async_http else httpx.HTTPTransport

        # Configure specific routes
        for pattern, route in self.transport_routes.items():
            mounts[pattern] = transport_cls(
                verify=route.verify_ssl, proxy=route.proxy_url or self.proxy_url if route.proxy else None
            )

        # Set default proxy for all routes if enabled
        if self.all_proxy:
            mounts["all://"] = transport_cls(proxy=self.proxy_url)

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

    user_agent: str = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36"  # The user agent to use for HTTP requests.
    )

    class Config:
        env_file = ".env"
        extra = "ignore"


settings = Settings()
