from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    api_password: str  # The password for accessing the API endpoints.
    proxy_url: str | None = None  # The URL of the proxy server to route requests through.
    mpd_live_stream_delay: int = 30  # The delay in seconds for live MPD streams.

    class Config:
        env_file = ".env"
        extra = "ignore"


settings = Settings()
