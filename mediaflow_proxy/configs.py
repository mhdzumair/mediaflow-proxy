from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    api_password: str  # The password for accessing the API endpoints.
    proxy_url: str | None = None  # The URL of the proxy server to route requests through.
    enable_streaming_progress: bool = False  # Whether to enable streaming progress tracking.

    user_agent: str = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3"  # The user agent to use for HTTP requests.
    )

    class Config:
        env_file = ".env"
        extra = "ignore"


settings = Settings()
