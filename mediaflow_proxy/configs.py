from typing import Dict, Optional

import httpx
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings


class ProxyRoute(BaseModel):
    proxy_url: Optional[str] = None
    verify_ssl: bool = True


class ProxyConfig(BaseSettings):
    default_url: Optional[str] = None
    routes: Dict[str, ProxyRoute] = Field(default_factory=dict)

    def get_mounts(
        self, async_http: bool = True
    ) -> Dict[str, Optional[httpx.HTTPTransport | httpx.AsyncHTTPTransport]]:
        """
        Get a dictionary of httpx mount points to transport instances.
        """
        mounts = {}
        transport_cls = httpx.AsyncHTTPTransport if async_http else httpx.HTTPTransport

        # Add specific routes
        for pattern, route in self.routes.items():
            mounts[pattern] = transport_cls(proxy=route.proxy_url, verify=route.verify_ssl) if route.proxy_url else None

        # Set default proxy if specified
        if self.default_url:
            mounts["all://"] = transport_cls(proxy=self.default_url)

        return mounts

    class Config:
        env_file = ".env"
        env_prefix = "PROXY_"
        extra = "ignore"


class Settings(BaseSettings):
    api_password: str  # The password for accessing the API endpoints.
    proxy_config: ProxyConfig = Field(default_factory=ProxyConfig)  # Configuration for proxying requests.
    enable_streaming_progress: bool = False  # Whether to enable streaming progress tracking.

    user_agent: str = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3"  # The user agent to use for HTTP requests.
    )

    class Config:
        env_file = ".env"
        extra = "ignore"


settings = Settings()
