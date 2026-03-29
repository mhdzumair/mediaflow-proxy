# Environment variables

Set the following environment variables:

- `API_PASSWORD`: Optional. Protects against unauthorized access and API network abuses.
- `ENABLE_STREAMING_PROGRESS`: Optional. Enable streaming progress logging. Default is `false`.
- `DISABLE_SSL_VERIFICATION_GLOBALLY`: Optional. Disable SSL verification for all requests globally. Default is `false`.
- `DISABLE_HOME_PAGE`: Optional. Disables the home page UI. Returns 403 for the root path and direct access to index.html. Default is `false`.
- `DISABLE_DOCS`: Optional. Disables the API documentation (Swagger UI). Returns 403 for the /docs path. Default is `false`.
- `DISABLE_SPEEDTEST`: Optional. Disables the speedtest UI. Returns 403 for the /speedtest path and direct access to speedtest.html. Default is `false`.
- `CLEAR_CACHE_ON_STARTUP`: Optional. Clears all caches (extractor cache, etc.) when the server starts. Useful for development and testing. Default is `false`.
- `STREMIO_PROXY_URL`: Optional. Stremio server URL for alternative content proxying. Example: `http://127.0.0.1:11470`.
- `M3U8_CONTENT_ROUTING`: Optional. Routing strategy for M3U8 content URLs: `mediaflow` (default), `stremio`, or `direct`.
- `ENABLE_HLS_PREBUFFER`: Optional. Enables HLS pre-buffering for improved streaming performance. Default: `true`. Pre-buffering downloads upcoming segments ahead of playback to reduce buffering. Set to `false` to disable for low-memory environments.
- `HLS_PREBUFFER_SEGMENTS`: Optional. Number of HLS segments to pre-buffer ahead. Default: `5`. Only effective when `ENABLE_HLS_PREBUFFER` is `true`.
- `HLS_PREBUFFER_CACHE_SIZE`: Optional. Maximum number of HLS segments to keep in memory cache. Default: `50`. Only effective when `ENABLE_HLS_PREBUFFER` is `true`.
- `HLS_PREBUFFER_MAX_MEMORY_PERCENT`: Optional. Maximum percentage of system memory to use for HLS pre-buffer cache. Default: `80`. Only effective when `ENABLE_HLS_PREBUFFER` is `true`.
- `HLS_PREBUFFER_EMERGENCY_THRESHOLD`: Optional. Emergency threshold (%) to trigger aggressive HLS cache cleanup. Default: `90`. Only effective when `ENABLE_HLS_PREBUFFER` is `true`.
- `HLS_PREBUFFER_INACTIVITY_TIMEOUT`: Optional. Seconds of inactivity before stopping HLS playlist refresh. Default: `60`. Helps clean up resources when streams are stopped.
- `LIVESTREAM_START_OFFSET`: Optional. Default start offset (in seconds) for live streams (HLS and MPD). Default: `-18`. This injects `#EXT-X-START:TIME-OFFSET` into live media playlists, causing players to start behind the live edge. This creates headroom for prebuffering to work effectively on live streams. Set to empty/unset to disable automatic injection for live streams.
- `ENABLE_DASH_PREBUFFER`: Optional. Enables DASH pre-buffering for improved streaming performance. Default: `true`. Pre-buffering downloads upcoming segments ahead of playback to reduce buffering. Set to `false` to disable for low-memory environments.
- `DASH_PREBUFFER_SEGMENTS`: Optional. Number of DASH segments to pre-buffer ahead. Default: `5`. Only effective when `ENABLE_DASH_PREBUFFER` is `true`.
- `DASH_PREBUFFER_CACHE_SIZE`: Optional. Maximum number of DASH segments to keep in memory cache. Default: `50`. Only effective when `ENABLE_DASH_PREBUFFER` is `true`.
- `DASH_PREBUFFER_MAX_MEMORY_PERCENT`: Optional. Maximum percentage of system memory to use for DASH pre-buffer cache. Default: `80`. Only effective when `ENABLE_DASH_PREBUFFER` is `true`.
- `DASH_PREBUFFER_EMERGENCY_THRESHOLD`: Optional. Emergency threshold (%) to trigger aggressive DASH cache cleanup. Default: `90`. Only effective when `ENABLE_DASH_PREBUFFER` is `true`.
- `DASH_PREBUFFER_INACTIVITY_TIMEOUT`: Optional. Seconds of inactivity before cleaning up DASH stream state. Default: `60`. Helps clean up resources when streams are stopped.
- `DASH_SEGMENT_CACHE_TTL`: Optional. TTL in seconds for cached DASH segments. Default: `60`. Longer values help with slow network playback.
- `FORWARDED_ALLOW_IPS`: Optional. Controls which IP addresses are trusted to provide forwarded headers (X-Forwarded-For, X-Forwarded-Proto, etc.) when MediaFlow Proxy is deployed behind reverse proxies or load balancers. Default: `127.0.0.1`. See [Forwarded Headers Configuration](networking.md#forwarded-headers-configuration) for detailed usage.

