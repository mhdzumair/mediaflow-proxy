from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    api_password: str  # The password for accessing the API endpoints.
    proxy_url: str | None = None  # The URL of the proxy server to route requests through.
    enable_streaming_progress: bool = False  # Whether to enable streaming progress tracking.

    class Config:
        env_file = ".env"
        extra = "ignore"


settings = Settings()
