from typing import Dict, Literal, Optional

from pydantic import BaseModel, Field, SecretStr
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

    class Config:
        env_file = ".env"
        extra = "ignore"


class Settings(BaseSettings):
    api_password: str | None = None  # The password for protecting the API endpoints.
    log_level: str = "INFO"  # The logging level to use.
    transport_config: TransportConfig = Field(default_factory=TransportConfig)  # Configuration for HTTP transport.
    enable_streaming_progress: bool = False  # Whether to enable streaming progress tracking.
    disable_home_page: bool = False  # Whether to disable the home page UI.
    disable_docs: bool = False  # Whether to disable the API documentation (Swagger UI).
    disable_speedtest: bool = False  # Whether to disable the speedtest UI.
    clear_cache_on_startup: bool = (
        False  # Whether to clear all caches (extractor, MPD, etc.) on startup. Useful for development.
    )
    stremio_proxy_url: str | None = None  # The Stremio server URL for alternative content proxying.
    m3u8_content_routing: Literal["mediaflow", "stremio", "direct"] = (
        "mediaflow"  # Routing strategy for M3U8 content URLs: "mediaflow", "stremio", or "direct"
    )
    enable_hls_prebuffer: bool = True  # Whether to enable HLS pre-buffering for improved streaming performance.
    livestream_start_offset: (
        float | None
    ) = -18  # Default start offset for live streams (e.g., -18 to start 18 seconds behind live edge). Applies to HLS and MPD live playlists. Set to None to disable.
    hls_prebuffer_segments: int = 5  # Number of segments to pre-buffer ahead.
    hls_prebuffer_cache_size: int = 50  # Maximum number of segments to cache in memory.
    hls_prebuffer_max_memory_percent: int = 80  # Maximum percentage of system memory to use for HLS pre-buffer cache.
    hls_prebuffer_emergency_threshold: int = 90  # Emergency threshold percentage to trigger aggressive cache cleanup.
    hls_prebuffer_inactivity_timeout: int = 60  # Seconds of inactivity before stopping playlist refresh loop.
    hls_segment_cache_ttl: int = 300  # TTL (seconds) for cached HLS segments; 300s (5min) for VOD, lower for live.
    enable_dash_prebuffer: bool = True  # Whether to enable DASH pre-buffering for improved streaming performance.
    dash_prebuffer_segments: int = 5  # Number of segments to pre-buffer ahead.
    dash_prebuffer_cache_size: int = 50  # Maximum number of segments to cache in memory.
    dash_prebuffer_max_memory_percent: int = 80  # Maximum percentage of system memory to use for DASH pre-buffer cache.
    dash_prebuffer_emergency_threshold: int = 90  # Emergency threshold percentage to trigger aggressive cache cleanup.
    dash_prebuffer_inactivity_timeout: int = 60  # Seconds of inactivity before cleaning up stream state.
    dash_segment_cache_ttl: int = 60  # TTL (seconds) for cached media segments; longer = better for slow playback.
    mpd_live_init_cache_ttl: int = 60  # TTL (seconds) for live init segment cache; 0 disables caching.
    mpd_live_playlist_depth: int = 8  # Number of recent segments to expose per live playlist variant.
    remux_to_ts: bool = False  # Remux fMP4 segments to MPEG-TS for ExoPlayer/VLC compatibility.
    processed_segment_cache_ttl: int = 60  # TTL (seconds) for caching processed (decrypted/remuxed) segments.

    # FlareSolverr settings (for Cloudflare bypass)
    flaresolverr_url: str | None = None  # FlareSolverr service URL. Example: http://localhost:8191
    flaresolverr_timeout: int = 60  # Timeout (seconds) for FlareSolverr requests.

    # Acestream settings
    enable_acestream: bool = False  # Whether to enable Acestream proxy support.
    acestream_host: str = "localhost"  # Acestream engine host.
    acestream_port: int = 6878  # Acestream engine port.
    acestream_buffer_size: int = 4 * 1024 * 1024  # Buffer size for MPEG-TS streaming (4MB default, like acexy).
    acestream_empty_timeout: int = 30  # Timeout (seconds) when no data is received from upstream.
    acestream_session_timeout: int = 60  # Session timeout (seconds) for cleanup of inactive sessions.
    acestream_keepalive_interval: int = 15  # Interval (seconds) for session keepalive polling.

    # Telegram MTProto settings
    enable_telegram: bool = False  # Whether to enable Telegram MTProto proxy support.
    telegram_api_id: int | None = None  # Telegram API ID from https://my.telegram.org/apps
    telegram_api_hash: SecretStr | None = None  # Telegram API hash from https://my.telegram.org/apps
    telegram_session_string: SecretStr | None = None  # Persistent session string (avoids re-authentication).
    telegram_max_connections: int = 8  # Max parallel DC connections for downloads (max 20, careful of floods).
    telegram_request_timeout: int = 30  # Request timeout in seconds.

    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36"  # The user agent to use for HTTP requests.

    # Upstream error resilience settings
    upstream_retry_on_disconnect: bool = True  # Enable/disable retry when upstream disconnects mid-stream.
    upstream_retry_attempts: int = 2  # Number of retry attempts when upstream disconnects during streaming.
    upstream_retry_delay: float = 1.0  # Delay (seconds) between retry attempts.
    graceful_stream_end: bool = True  # Return valid empty playlist instead of error when upstream fails.

    # Redis settings
    redis_url: str | None = None  # Redis URL for distributed locking and caching. None = disabled.

    class Config:
        env_file = ".env"
        extra = "ignore"


settings = Settings()
