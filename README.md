# MediaFlow Proxy

<div style="text-align: center;">
  <img src="https://cdn.githubraw.com/mhdzumair/mediaflow-proxy/main/mediaflow_proxy/static/logo.png" alt="MediaFlow Proxy Logo" width="200" style="border-radius: 15px;">
</div>

MediaFlow Proxy is a powerful and flexible solution for proxifying various types of media streams. It supports HTTP(S) links, HLS (M3U8) streams, and MPEG-DASH streams, including DRM-protected content. This proxy can convert MPEG-DASH DRM-protected streams to decrypted HLS live streams in real-time, making it one of the fastest live decrypter servers available.

## Features

### Stream Processing
- Convert MPEG-DASH streams (DRM-protected and non-protected) to HLS
- **ClearKey DRM decryption** with support for all CENC encryption modes (see [DASH/MPD Support Status](#dashmpd-support-status))
- Support for **multi-key DRM** streams (different keys for video/audio tracks)
- Support for non-DRM protected DASH live and VOD streams
- Proxy and modify HLS (M3U8) streams in real-time
- **Smart pre-buffering** for both HLS and DASH streams (enabled by default)
- Proxy HTTP/HTTPS links with custom headers

### Proxy & Routing
- Advanced proxy routing system with support for:
  - Domain-based routing rules
  - Protocol-specific routing (HTTP/HTTPS)
  - Subdomain and wildcard patterns
  - Port-specific routing
- Support for HTTP/HTTPS/SOCKS5 proxy forwarding
- Flexible SSL verification control per route
- Support for expired or self-signed SSL certificates
- Public IP address retrieval for Debrid services integration

### Xtream Codes (XC) API Proxy
- **Stateless XC API proxy** for IPTV players
- Support for live streams, VOD, series, and **catch-up/timeshift**
- Compatible with any XC-compatible IPTV player (TiviMate, IPTV Smarters, etc.)
- Automatic URL rewriting for seamless proxying

### Acestream Proxy
- **Acestream P2P stream proxy** - Proxy Acestream content through MediaFlow (inspired by [Acexy](https://github.com/Javinator9889/acexy))
- Support for both **HLS manifest** and **MPEG-TS stream** output formats
- **Stream multiplexing** - Multiple clients can watch the same stream simultaneously
- Automatic **session management** with cross-process coordination
- Works with content IDs (`acestream://...`) and infohashes (magnet links)
- Compatible with any media player that supports HLS or MPEG-TS

### Telegram MTProto Proxy
- **Telegram video streaming** - Stream videos from Telegram channels, groups, and DMs through MediaFlow
- **High-speed parallel downloads** using FastTelethon technique (up to 20+ MB/s)
- **Full range-request support** - Seeking works seamlessly in video players
- Support for **t.me links** and direct file references
- Works with public channels, private channels (if member), groups, and DMs
- Persistent session management with automatic reconnection

### Security
- API password protection against unauthorized access & Network bandwidth abuse prevention
- Parameter encryption to hide sensitive information
- Optional IP-based access control for encrypted URLs
- URL expiration support for encrypted URLs

### On-the-fly Transcoding
- **Universal video/audio transcoding** to browser-compatible fMP4 (H.264 + AAC)
- **GPU hardware acceleration** (NVIDIA NVENC, Apple VideoToolbox, Intel VAAPI/QSV) with automatic CPU fallback
- Supports **any input container** (MKV, MP4, TS, WebM, FLV, etc.) and codec (HEVC, VP8/VP9, MPEG-2, MPEG-4, AC3, EAC3, Vorbis, Opus, etc.)
- **On-the-fly streaming** -- no full-file buffering; pipe-based demuxing for MKV/TS/WebM and moov-atom probing for MP4
- **Smart format detection** -- filename extension hints + magic byte sniffing to avoid wasteful probe attempts
- Available on **all proxy endpoints**: `/proxy/stream`, Telegram, Acestream, and Xtream Codes
- Triggered by `&transcode=true` query parameter with optional `&start=<seconds>` for seeking

### Additional Features
- Built-in speed test for RealDebrid and AllDebrid services
- Custom header injection and modification
- **Response header removal** - Remove problematic headers from upstream responses (e.g., incorrect Content-Length)
- **Resolution selection** - Select specific resolution (e.g., 720p, 1080p) for HLS and DASH streams
- Real-time HLS manifest manipulation
- HLS Key URL modifications for bypassing stream restrictions
- **Base64 URL Support** - Automatic detection and processing of base64 encoded URLs
- **Segment Skipping** - Skip specific time ranges in HLS and DASH streams (intro/outro skipping, ad removal)
- **Stream Transformers** - Handle host-specific stream obfuscation (e.g., PNG-wrapped MPEG-TS segments)

### DASH/MPD Support Status

#### MPD Segment Addressing Types

| Type | Status | Notes |
|------|--------|-------|
| SegmentTemplate (fixed duration) | ✅ Supported | Most common for VOD content |
| SegmentTemplate (SegmentTimeline) | ✅ Supported | Variable duration segments |
| SegmentBase | ✅ Supported | Single file with byte ranges |
| SegmentList | ✅ Supported | Explicit segment URLs in MPD |

#### MPD Presentation Types

| Type | Status | Notes |
|------|--------|-------|
| Static (VOD) | ✅ Supported | Fixed duration content |
| Dynamic (Live) | ✅ Supported | Live streaming with availabilityStartTime |

#### DRM/Encryption Support

**Supported (ClearKey):**

| Mode | Scheme | Status | Notes |
|------|--------|--------|-------|
| AES-CTR (cenc) | Full sample CTR | ✅ Supported | Standard CENC encryption |
| AES-CTR Pattern (cens) | Subsample CTR | ✅ Supported | Pattern encryption with CTR |
| AES-CBC (cbc1) | Full sample CBC | ✅ Supported | Full sample CBC mode |
| AES-CBC Pattern (cbcs) | Subsample CBC | ✅ Supported | Used by Apple FairPlay |

**Not Supported (Commercial DRM):**

| DRM System | Status | Notes |
|------------|--------|-------|
| Widevine | ❌ Not Supported | Requires license server communication |
| PlayReady | ❌ Not Supported | Microsoft's DRM system |
| FairPlay | ❌ Not Supported | Apple's DRM system (keys not extractable) |
| PrimeTime | ❌ Not Supported | Adobe's DRM system |

> **Note**: MediaFlow Proxy only supports **ClearKey** DRM where the decryption keys are provided directly. Commercial DRM systems (Widevine, PlayReady, FairPlay) require license server communication and hardware-backed security that cannot be bypassed by this proxy.

#### IV Size Support

| Size | Status | Notes |
|------|--------|-------|
| 8-byte IV | ✅ Supported | GPAC default |
| 16-byte IV | ✅ Supported | Bento4 default |
| Constant IV | ✅ Supported | Used by CBCS streams |

#### Multi-Key Support

| Feature | Status | Notes |
|---------|--------|-------|
| Single Key (all tracks) | ✅ Supported | Same key for video and audio |
| Multi-Key (per track) | ✅ Supported | Different keys for video/audio tracks |
| Key rotation | ❌ Not Supported | Keys changing mid-stream |

### Pre-buffering (HLS & DASH)

MediaFlow Proxy includes intelligent pre-buffering for both HLS and DASH streams, **enabled by default** to improve playback smoothness and reduce buffering.

#### How Pre-buffering Works

| Feature | HLS | DASH |
|---------|-----|------|
| Enabled by default | ✅ Yes | ✅ Yes |
| Smart variant selection | ✅ Only buffers the variant being played | ✅ Only buffers requested profiles |
| Live stream support | ✅ Buffers from end of playlist | ✅ Buffers from end of playlist |
| VOD support | ✅ Buffers from start | ✅ Buffers from start |
| Inactivity cleanup | ✅ Stops after 60s idle | ✅ Stops after 60s idle |
| Memory management | ✅ Configurable limits | ✅ Configurable limits |

#### Key Behaviors

1. **Smart Variant Selection (HLS)**: When a master playlist is requested, pre-buffering does NOT automatically buffer all quality variants. It only starts buffering when the player actually requests segments from a specific variant, saving bandwidth and memory.

2. **Inactivity Cleanup**: Both HLS and DASH pre-buffers automatically stop refreshing playlists and clean up resources after 60 seconds of inactivity (no segment requests). This prevents memory leaks when streams are stopped.

3. **Live Stream Optimization**: For live streams, segments are buffered from the END of the playlist (most recent) rather than the beginning, ensuring the player has the freshest content available.

4. **Memory Protection**: Pre-buffering respects configurable memory limits and will stop buffering if system memory usage exceeds thresholds.

## Configuration

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
- `FORWARDED_ALLOW_IPS`: Optional. Controls which IP addresses are trusted to provide forwarded headers (X-Forwarded-For, X-Forwarded-Proto, etc.) when MediaFlow Proxy is deployed behind reverse proxies or load balancers. Default: `127.0.0.1`. See [Forwarded Headers Configuration](#forwarded-headers-configuration) for detailed usage.

### Redis Configuration (Optional)

Redis enables cross-worker coordination for rate limiting and caching. This is **recommended** when running with multiple workers (`--workers N`) to prevent CDN rate-limiting issues (e.g., Vidoza 509 errors).

- `REDIS_URL`: Optional. Redis connection URL. Default: `None` (disabled). Example: `redis://localhost:6379` or `redis://user:pass@host:6379/0`.

**When to use Redis:**
- Running multiple uvicorn workers (`--workers 4` or more)
- Streaming from rate-limited CDNs like Vidoza
- Need shared caching across workers (extractor results, HEAD responses, segments)

**Features enabled by Redis:**
- **Rate limiting**: Prevents rapid-fire requests that trigger CDN 509 errors
- **HEAD cache**: Serves repeated HEAD probes (e.g., ExoPlayer) without upstream connections
- **Stream gate**: Serializes initial connections to rate-limited URLs
- **Extractor cache**: Shares extraction results across all workers
- **Segment cache**: Shares downloaded segments across workers

**Docker Compose example with Redis:**
```yaml
services:
  redis:
    image: redis:7-alpine
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 5s
      retries: 5

  mediaflow-proxy:
    image: mhdzumair/mediaflow-proxy:latest
    ports:
      - "8888:8888"
    environment:
      - API_PASSWORD=your_password
      - REDIS_URL=redis://redis:6379
    depends_on:
      redis:
        condition: service_healthy
```

**Note**: If Redis is not configured, MediaFlow Proxy works normally but rate limiting features are disabled. This is fine for single-worker deployments or CDNs that don't rate-limit aggressively.

### Acestream Configuration

MediaFlow Proxy can act as a proxy for Acestream P2P streams, converting them to HLS or MPEG-TS format that any media player can consume.

**Requirements**: You need a running Acestream engine accessible from MediaFlow Proxy.

- `ENABLE_ACESTREAM`: Optional. Enable Acestream proxy support. Default: `false`.
- `ACESTREAM_HOST`: Optional. Acestream engine host. Default: `localhost`.
- `ACESTREAM_PORT`: Optional. Acestream engine port. Default: `6878`.
- `ACESTREAM_SESSION_TIMEOUT`: Optional. Session timeout (seconds) for cleanup of inactive sessions. Default: `60`.
- `ACESTREAM_KEEPALIVE_INTERVAL`: Optional. Interval (seconds) for session keepalive polling. Default: `15`.

#### Acestream Endpoints

| Endpoint | Description |
|----------|-------------|
| `/proxy/acestream/stream` | MPEG-TS stream proxy (recommended) |
| `/proxy/acestream/manifest.m3u8` | HLS manifest proxy |
| `/proxy/acestream/status` | Get session status |

#### Acestream URL Parameters

| Parameter | Description |
|-----------|-------------|
| `id` | Acestream content ID (alternative to infohash) |
| `infohash` | Acestream infohash (40-char hex from magnet link) |
| `transcode` | Set to `true` to transcode to browser-compatible fMP4 (H.264 + AAC) |
| `start` | Seek start time in seconds (used with `transcode=true`) |

**Example URLs:**
```
# MPEG-TS stream (recommended)
https://your-mediaflow/proxy/acestream/stream?id=YOUR_CONTENT_ID&api_password=your_password

# MPEG-TS stream (infohash from magnet)
https://your-mediaflow/proxy/acestream/stream?infohash=b04372b9543d763bd2dbd2a1842d9723fd080076&api_password=your_password

# Transcode to browser-compatible fMP4
https://your-mediaflow/proxy/acestream/stream?id=YOUR_CONTENT_ID&transcode=true&api_password=your_password

# HLS manifest (alternative)
https://your-mediaflow/proxy/acestream/manifest.m3u8?id=YOUR_CONTENT_ID&api_password=your_password
```

#### Docker Compose Example with Acestream

```yaml
services:
  mediaflow-proxy:
    image: mhdzumair/mediaflow-proxy:latest
    ports:
      - "8888:8888"
    environment:
      - API_PASSWORD=your_password
      - ENABLE_ACESTREAM=true
      - ACESTREAM_HOST=acestream
      - ACESTREAM_PORT=6878

  acestream:
    image: ghcr.io/martinbjeldbak/acestream-http-proxy:latest # or build it from https://github.com/sergiomarquezdev/acestream-docker-home
    ports:
      - "6878:6878"
```

### Telegram MTProto Configuration

MediaFlow Proxy can stream Telegram media (videos, documents, photos) through the MTProto protocol, enabling high-speed parallel downloads with full HTTP range request support for seeking.

**Requirements**: 
- Telegram API credentials from [my.telegram.org/apps](https://my.telegram.org/apps)
- A valid session string (generated once, see below)

> **Note**: Telethon and cryptg are included as standard dependencies - no extra installation needed.

#### Configuration

| Environment Variable | Description | Default |
|---------------------|-------------|---------|
| `ENABLE_TELEGRAM` | Enable Telegram proxy support | `false` |
| `TELEGRAM_API_ID` | Telegram API ID from my.telegram.org | Required |
| `TELEGRAM_API_HASH` | Telegram API Hash from my.telegram.org | Required |
| `TELEGRAM_SESSION_STRING` | Persistent session string (see below) | Required |
| `TELEGRAM_MAX_CONNECTIONS` | Max parallel DC connections | `8` |
| `TELEGRAM_REQUEST_TIMEOUT` | Request timeout in seconds | `30` |

#### Generating a Session String

The session string authenticates MediaFlow with Telegram. Generate it using the web UI:

1. Open MediaFlow's URL Generator page at `/url-generator#telegram`
2. Navigate to the **Session String Generator** section
3. Enter your API ID and API Hash (from https://my.telegram.org/apps)
4. Choose authentication method (user account or bot)
5. Complete authentication (phone number + code, or bot token)

Add the generated session string to your configuration:

```env
ENABLE_TELEGRAM=true
TELEGRAM_API_ID=12345678
TELEGRAM_API_HASH=your_api_hash_here
TELEGRAM_SESSION_STRING=your_session_string_here
```

> **Security Note**: The session string is equivalent to a password. Keep it secret!

#### Telegram Endpoints

| Endpoint | Description |
|----------|-------------|
| `/proxy/telegram/stream` | Stream media from t.me link or file_id |
| `/proxy/telegram/stream/{filename}` | Stream with custom filename |
| `/proxy/telegram/transcode/playlist.m3u8` | HLS transcode playlist (recommended for browser playback and smooth seeking) |
| `/proxy/telegram/transcode/init.mp4` | fMP4 init segment for Telegram transcode playlist |
| `/proxy/telegram/transcode/segment.m4s` | fMP4 media segment for Telegram transcode playlist |
| `/proxy/telegram/info` | Get media metadata |
| `/proxy/telegram/status` | Session status and health check |

#### URL Parameters

| Parameter | Description |
|-----------|-------------|
| `d` or `url` | t.me link (e.g., `https://t.me/channel/123`) |
| `chat_id` | Chat/Channel ID (use with `message_id`) - numeric ID or @username |
| `message_id` | Message ID within the chat (use with `chat_id`) |
| `file_id` | Bot API file_id (use with `file_size`) |
| `file_size` | File size in bytes (required when using `file_id`) |
| `transcode` | Set to `true` for direct transcode mode on `/proxy/telegram/stream` (URL Generator defaults to `/proxy/telegram/transcode/playlist.m3u8` when no start time is set) |
| `start` | Seek start time in seconds (direct transcode mode only, used with `transcode=true`) |

#### Supported Input Formats

**Option 1: t.me URLs**
- **Public channels**: `https://t.me/channelname/123`
- **Private channels**: `https://t.me/c/123456789/456`
- **User messages**: `https://t.me/username/123`

**Option 2: Direct IDs**
- `chat_id=-1001234567890&message_id=123` - Private channel/supergroup by numeric ID
- `chat_id=@channelname&message_id=123` - Public channel by username

**Option 3: Bot API file_id**
- `file_id=BQACAgI...&file_size=1048576` - Direct streaming by file_id
- Requires `file_size` parameter for range request support (seeking in video players)
- Get file_id and file_size from Telegram Bot API's `getFile` response

#### Example URLs

```bash
# Stream from public channel using t.me link
mpv "http://localhost:8888/proxy/telegram/stream?d=https://t.me/channelname/123&api_password=your_password"

# Stream using chat_id + message_id
mpv "http://localhost:8888/proxy/telegram/stream?chat_id=-1001234567890&message_id=123&api_password=your_password"

# Stream with username instead of numeric ID
mpv "http://localhost:8888/proxy/telegram/stream?chat_id=@channelname&message_id=456&api_password=your_password"

# Stream using Bot API file_id (requires file_size)
mpv "http://localhost:8888/proxy/telegram/stream?file_id=BQACAgIAAxkBAAI...&file_size=52428800&api_password=your_password"

# Stream with custom filename
mpv "http://localhost:8888/proxy/telegram/stream/movie.mp4?d=https://t.me/channelname/123&api_password=your_password"

# Get media info
curl "http://localhost:8888/proxy/telegram/info?d=https://t.me/channelname/123&api_password=your_password"

# Get media info using chat_id + message_id
curl "http://localhost:8888/proxy/telegram/info?chat_id=-1001234567890&message_id=123&api_password=your_password"

# Get media info using file_id
curl "http://localhost:8888/proxy/telegram/info?file_id=BQACAgIAAxkBAAI...&api_password=your_password"

# Check status
curl "http://localhost:8888/proxy/telegram/status?api_password=your_password"
```

### Transport Configuration

MediaFlow Proxy now supports advanced transport configuration using HTTPX's routing system. You can configure proxy and SSL verification settings for different domains and protocols.

#### Basic Configuration

Enable proxy for all routes:
```env
PROXY_URL=http://proxy:8080
ALL_PROXY=true
```

#### Advanced Routing Configuration

Configure different proxy settings for specific patterns:
```env
PROXY_URL=http://proxy:8080
TRANSPORT_ROUTES='{
    "https://internal.company.com": {
        "proxy": false
    },
    "all://streaming.service.com": {
        "proxy_url": "socks5://streaming-proxy:1080",
        "verify_ssl": false
    }
}'
```

The routing system supports various patterns:
- Domain routing: `"all://example.com"`
- Subdomain routing: `"all://*.example.com"`
- Protocol-specific routing: `"https://example.com"`
- Port-specific routing: `"all://*:1234"`
- Wildcard routing: `"all://"`

#### Route Configuration Options

Each route can have the following settings:
- `proxy`: Boolean to enable/disable proxy for this route (default: true)
- `proxy_url`: Optional specific proxy URL for this route (overrides primary proxy_url)
- `verify_ssl`: Boolean to control SSL verification (default: true)

#### Configuration Examples

1. Simple proxy setup with SSL bypass for internal domain:
    ```env
    PROXY_URL=http://main-proxy:8080
    TRANSPORT_ROUTES='{
        "https://internal.domain.com": {
            "proxy": false,
            "verify_ssl": false
        }
    }'
    ```

2. Different proxies for different services:
    ```env
    PROXY_URL=http://default-proxy:8080
    TRANSPORT_ROUTES='{
        "all://*.streaming.com": {
            "proxy": true,
            "proxy_url": "socks5://streaming-proxy:1080"
        },
        "all://*.internal.com": {
            "proxy": false
        },
        "https://api.service.com": {
            "proxy": true,
            "verify_ssl": false
        }
    }'
    ```

3. Global proxy with exceptions:
    ```env
    PROXY_URL=http://main-proxy:8080
    ALL_PROXY=true
    TRANSPORT_ROUTES='{
        "all://local.network": {
            "proxy": false
        },
        "all://*.trusted-service.com": {
            "proxy": false
        }
    }'
    ```

### Forwarded Headers Configuration

When MediaFlow Proxy is deployed behind reverse proxies, load balancers, or CDNs (such as Nginx, Apache, Cloudflare, AWS ALB, etc.), it needs to properly handle forwarded headers to determine the real client IP address and original request protocol. The `FORWARDED_ALLOW_IPS` environment variable and `--forwarded-allow-ips` uvicorn parameter control which IP addresses are trusted to provide these headers.

#### What are Forwarded Headers?

Forwarded headers are HTTP headers that preserve information about the original client request when it passes through intermediary servers:

- **X-Forwarded-For**: Contains the original client IP address
- **X-Forwarded-Proto**: Contains the original request protocol (http/https)
- **X-Real-IP**: Alternative header for client IP address
- **X-Forwarded-Host**: Contains the original host header

#### Security Importance

Only trusted proxy servers should be allowed to set these headers, as malicious clients could potentially spoof them to bypass IP-based restrictions or logging. MediaFlow Proxy uses these headers for:

- **Client IP Detection**: For IP-based access control in encrypted URLs
- **Protocol Detection**: For generating correct URLs with proper schemes
- **Security Logging**: For accurate request tracking and abuse prevention

#### Configuration Options

**Environment Variable (Docker/Production):**
```env
# Trust only localhost (default - most secure)
FORWARDED_ALLOW_IPS=127.0.0.1

# Trust specific proxy IPs
FORWARDED_ALLOW_IPS=10.0.0.1,192.168.1.100

# Trust all IPs (use with caution)
FORWARDED_ALLOW_IPS=*

```
> **⚠️ Security warning**  
> Setting `FORWARDED_ALLOW_IPS=*` disables IP-spoofing protection and must **only** be used in trusted LAN or dev environments.  
> In production, always list the concrete IPs of your reverse-proxy servers.

**Uvicorn Command Line Parameter:**
```bash
# Trust only localhost (recommended for local development)
uvicorn mediaflow_proxy.main:app --forwarded-allow-ips "127.0.0.1"

# Trust specific proxy servers
uvicorn mediaflow_proxy.main:app --forwarded-allow-ips "10.0.0.1,192.168.1.100"

# Trust all IPs (development only - not recommended for production)
uvicorn mediaflow_proxy.main:app --forwarded-allow-ips "*"
```

#### Common Deployment Scenarios

**1. Direct Internet Access (No Proxy)**
```bash
# Remove --forwarded-allow-ips parameter entirely or use localhost only
uvicorn mediaflow_proxy.main:app --host 0.0.0.0 --port 8888
```

**2. Behind Nginx Reverse Proxy**
```env
# Trust the Nginx server IP
FORWARDED_ALLOW_IPS=127.0.0.1
```

**3. Behind Cloudflare**
```env
# Trust Cloudflare IP ranges (example - check current Cloudflare IPs)
FORWARDED_ALLOW_IPS=173.245.48.0,103.21.244.0,103.22.200.0
```

**4. Behind AWS Application Load Balancer**
```env
# Trust the VPC subnet where ALB is deployed
FORWARDED_ALLOW_IPS=10.0.0.0
```

**5. Docker with Host Network**
```env
# Trust the Docker host
FORWARDED_ALLOW_IPS=172.17.0.1
```

**6. Docker Compose with Nginx in Same Network**
```env
# Trust the Docker network range (when nginx and mediaflow-proxy are in same docker network)
FORWARDED_ALLOW_IPS=172.20.0.0
# Or trust all Docker IPs (less secure but simpler for development)
FORWARDED_ALLOW_IPS=*
```

**7. Kubernetes with Ingress**
```env
# Trust the ingress controller pod network
FORWARDED_ALLOW_IPS=10.244.0.0
```

#### Best Practices

1. **Principle of Least Privilege**: Only trust the specific IP addresses of your proxy servers
2. **Regular Updates**: Keep your trusted IP list updated when infrastructure changes
3. **Monitor Logs**: Watch for unexpected forwarded headers from untrusted sources
4. **Test Configuration**: Verify that client IPs are correctly detected after configuration changes

#### Troubleshooting

**Problem**: Client IP always shows as proxy IP
- **Solution**: Add your proxy server's IP to `FORWARDED_ALLOW_IPS`

**Problem**: Security warnings about untrusted forwarded headers
- **Solution**: Restrict `FORWARDED_ALLOW_IPS` to only include your actual proxy servers

**Problem**: IP-based restrictions not working correctly
- **Solution**: Verify that forwarded headers are being processed by checking the trusted IP configuration

**Problem**: Links return 302 redirects when nginx is in the same Docker network
- **Solution**: Set `FORWARDED_ALLOW_IPS=*` or specify the Docker network (e.g., `FORWARDED_ALLOW_IPS=172.20.0.0`)
- **Note**: When nginx and MediaFlow Proxy run in the same Docker network, you must configure `FORWARDED_ALLOW_IPS` to trust the Docker network IP range, otherwise proxy links will not work correctly

#### Example Nginx Configuration

When using Nginx as a reverse proxy, ensure it's properly setting forwarded headers:

```nginx
server {
    listen 80;
    server_name your-domain.com;
    
    location / {
        proxy_pass http://127.0.0.1:8888;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Then configure MediaFlow Proxy to trust Nginx:
```env
FORWARDED_ALLOW_IPS=127.0.0.1
```

### Reverse Proxy Configuration

MediaFlow Proxy is commonly deployed behind reverse proxies for SSL termination, load balancing, and additional security. Here are detailed configurations for popular reverse proxy solutions.

#### Nginx Configuration

**Basic Nginx Configuration:**

```nginx
server {
    listen 80;
    server_name mediaflow.yourdomain.com;
    
    # Redirect HTTP to HTTPS
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name mediaflow.yourdomain.com;
    
    # SSL Configuration
    ssl_certificate /path/to/your/certificate.crt;
    ssl_certificate_key /path/to/your/private.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    
    # Security Headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    
    # Client settings for streaming
    client_max_body_size 0;
    client_body_timeout 60s;
    client_header_timeout 60s;
    
    location / {
        # Proxy settings
        proxy_pass http://127.0.0.1:8888;
        proxy_http_version 1.1;
        proxy_cache_bypass $http_upgrade;
        
        # Headers for forwarded information
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host $host;
        proxy_set_header X-Forwarded-Port $server_port;
        
        # Headers for streaming support
        proxy_set_header Range $http_range;
        proxy_set_header If-Range $http_if_range;
        proxy_set_header Connection "";
        
        # Timeout settings for streaming
        proxy_connect_timeout 60s;
        proxy_send_timeout 300s;
        proxy_read_timeout 300s;
        
        # Disable buffering for streaming
        proxy_buffering off;
        proxy_request_buffering off;
        proxy_max_temp_file_size 0;
        
        # Handle redirects
        proxy_redirect off;
    }
    
    # Optional: Specific location for streaming endpoints with extended timeouts
    location ~* ^/proxy/(stream|hls|mpd)/ {
        proxy_pass http://127.0.0.1:8888;
        proxy_http_version 1.1;
        
        # Extended timeouts for large streams
        proxy_connect_timeout 60s;
        proxy_send_timeout 600s;
        proxy_read_timeout 600s;
        
        # Streaming optimizations
        proxy_buffering off;
        proxy_request_buffering off;
        proxy_max_temp_file_size 0;
        
        # Forward all necessary headers
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Range $http_range;
        proxy_set_header If-Range $http_if_range;
        proxy_set_header Connection "";
    }
    
    # Access and error logs
    access_log /var/log/nginx/mediaflow_access.log;
    error_log /var/log/nginx/mediaflow_error.log;
}
```

**MediaFlow Proxy Configuration for Nginx:**
```env
# Trust Nginx server
FORWARDED_ALLOW_IPS=127.0.0.1

# Other recommended settings
API_PASSWORD=your_secure_password
```

#### Nginx Proxy Manager Configuration

Nginx Proxy Manager provides a web-based interface for managing Nginx reverse proxy configurations.

**Step 1: Create Proxy Host**

In the Nginx Proxy Manager web interface:

**Details Tab:**
- **Domain Names**: `mediaflow.yourdomain.com`
- **Scheme**: `http`
- **Forward Hostname/IP**: `127.0.0.1` (or MediaFlow Proxy container IP)
- **Forward Port**: `8888`
- **Cache Assets**: ❌ (disabled)
- **Block Common Exploits**: ❌ (disabled)
- **Websockets Support**: ❌ (not required)
- **Access List**: None (unless you need IP restrictions)

**Step 2: SSL Configuration**

**SSL Tab:**
- **SSL Certificate**: Select your certificate (Let's Encrypt recommended)
- **Force SSL**: ✅ (redirect HTTP to HTTPS)
- **HTTP/2 Support**: ✅ (recommended for performance)
- **HSTS Enabled**: ✅ (recommended for security)
- **HSTS Subdomains**: ✅ (if applicable)

**Step 3: Advanced Configuration**

**Advanced Tab - Custom Nginx Configuration:**

```nginx
# Headers for forwarded information
proxy_set_header Host $host;
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Proto $scheme;
proxy_set_header X-Forwarded-Host $host;
proxy_set_header X-Forwarded-Port $server_port;

# Headers for streaming support
proxy_set_header Range $http_range;
proxy_set_header If-Range $http_if_range;
proxy_set_header Connection "";

# Timeout settings for streaming
proxy_connect_timeout 60s;
proxy_send_timeout 300s;
proxy_read_timeout 300s;

# Disable buffering for streaming
proxy_buffering off;
proxy_request_buffering off;
proxy_max_temp_file_size 0;

# Client settings
client_max_body_size 0;
client_body_timeout 60s;
client_header_timeout 60s;

# Handle redirects
proxy_redirect off;

# HTTP version
proxy_http_version 1.1;

# Security headers
add_header X-Frame-Options DENY always;
add_header X-Content-Type-Options nosniff always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;

# Hide server information
proxy_hide_header X-Powered-By;
server_tokens off;
```

**Step 4: MediaFlow Proxy Configuration**

Configure MediaFlow Proxy to trust Nginx Proxy Manager:

**If running on the same server:**
```env
FORWARDED_ALLOW_IPS=127.0.0.1
```

**If running in Docker with custom network:**
```env
# Use the Docker network range
FORWARDED_ALLOW_IPS=172.18.0.0/16
```

**If Nginx Proxy Manager is on a different server:**
```env
# Replace with actual Nginx Proxy Manager IP
FORWARDED_ALLOW_IPS=10.0.0.5
```

**Step 5: Docker Compose Example**

Complete Docker Compose setup with Nginx Proxy Manager:

```yaml
version: '3.8'

services:
  nginx-proxy-manager:
    image: 'jc21/nginx-proxy-manager:latest'
    restart: unless-stopped
    ports:
      - '80:80'
      - '443:443'
      - '81:81'  # Admin interface
    volumes:
      - ./npm-data:/data
      - ./npm-letsencrypt:/etc/letsencrypt
    networks:
      - proxy-network

  mediaflow-proxy:
    image: 'mhdzumair/mediaflow-proxy:latest'
    restart: unless-stopped
    ports:
      - '8888:8888'
    environment:
      - API_PASSWORD=your_secure_password
      - FORWARDED_ALLOW_IPS=172.18.0.0/16
    networks:
      - proxy-network

networks:
  proxy-network:
    driver: bridge
    ipam:
      config:
        - subnet: 172.18.0.0/16
```

#### Important Notes for Nginx Proxy Manager

**Block Common Exploits Setting:**

The "Block Common Exploits" feature in Nginx Proxy Manager provides automatic protection against common web attacks but may occasionally block legitimate streaming URLs that contain special characters. 

**What it blocks:**
- Path traversal attempts (`../`, `..%2F`)
- SQL injection patterns
- XSS attempts
- Suspicious file extensions
- Very long URLs (>2000 characters)
- Base64-like patterns

**Recommendation:**
- **Enable it initially** for security
- **Monitor logs** for false positives
- **Disable only if necessary** for specific streaming services

**If you experience issues with legitimate URLs being blocked:**

1. **Check the logs** in Nginx Proxy Manager for 403 errors
2. **Test problematic URLs** directly
3. **Consider disabling** "Block Common Exploits" if it interferes with streaming
4. **Implement alternative security** measures (Cloudflare WAF, fail2ban, etc.)

#### Troubleshooting Reverse Proxy Issues

**Problem: MediaFlow Proxy shows proxy IP instead of client IP**
- **Solution**: Verify `FORWARDED_ALLOW_IPS` includes your proxy server IP
- **Check**: Ensure proxy is sending `X-Forwarded-For` headers

**Problem: Streaming timeouts or interruptions**
- **Solution**: Increase timeout values in proxy configuration
- **Check**: Disable proxy buffering with `proxy_buffering off`

**Problem: Large file uploads fail**
- **Solution**: Set `client_max_body_size 0` in Nginx configuration
- **Check**: Verify `proxy_request_buffering off` is set

**Problem: SSL/HTTPS issues**
- **Solution**: Ensure `X-Forwarded-Proto` header is properly set
- **Check**: Verify SSL certificates are valid and properly configured

**Problem: 502/504 Gateway errors**
- **Solution**: Check MediaFlow Proxy is running and accessible
- **Check**: Verify network connectivity between proxy and MediaFlow Proxy
- **Check**: Review timeout settings in proxy configuration

### Speed Test Feature

MediaFlow Proxy now includes a built-in speed test feature for testing RealDebrid and AllDebrid network speeds. To access the speed test:

1. Open your browser and navigate to `http://your-server:8888/speedtest.html`
2. The speed test page allows you to:
   - Test download speeds from RealDebrid servers
   - Test download speeds from AllDebrid servers


## Installation

### Option 1: Self-Hosted Deployment

#### Using Docker from Docker Hub

1. Pull & Run the Docker image:
   ```
   docker run -p 8888:8888 -e API_PASSWORD=your_password mhdzumair/mediaflow-proxy
   ```
### Using Docker Compose

1. Set the `API_PASSWORD` and other environment variables in `.env`:

   ```
   echo "API_PASSWORD=your_password" > .env
   ```
2. Bring up the Docker Container:

   ```
   docker compose up --detach
   ```

#### Using pip

> [!IMPORTANT]
> Ensure that you have Python 3.10 or higher installed.

1. Install the package:
   ```
   pip install mediaflow-proxy
   ```

2. Set the `API_PASSWORD` and other environment variables in `.env`:
   ```
   echo "API_PASSWORD=your_password" > .env
   ```

3. Run the MediaFlow Proxy server:
   ```
   mediaflow-proxy
   ```
   You can access the server at `http://localhost:8888`.

4. To run the server with uvicorn options: (Optional)
   ```
   uvicorn mediaflow_proxy.main:app --host 0.0.0.0 --port 8888 --workers 4 --forwarded-allow-ips "*"
   ```

   > **Note**
   > > Omit `--forwarded-allow-ips "*"` when running locally.

#### Using git & uv

> [!IMPORTANT]
> Ensure that you have Python 3.10 or higher and [uv](https://docs.astral.sh/uv/getting-started/installation/) installed.


1. Clone the repository:
   ```
   git clone https://github.com/mhdzumair/mediaflow-proxy.git
   cd mediaflow-proxy
   ```

2. Install dependencies using uv:
   ```
   uv sync
   ```

3. Set the `API_PASSWORD` environment variable in `.env`:
   ```
   echo "API_PASSWORD=your_password" > .env
   ```

4. Run the FastAPI server:
   ```
   uv run uvicorn mediaflow_proxy.main:app --host 0.0.0.0 --port 8888 --workers 4 --forwarded-allow-ips "*"
   ```

   > **Note**
   > > Omit `--forwarded-allow-ips "*"` when running locally.

#### Build and Run Docker Image Locally

1. Build the Docker image:
   ```
   docker build -t mediaflow-proxy .
   ```

2. Run the Docker container:
   ```
   docker run -d -p 8888:8888 -e API_PASSWORD=your_password --restart unless-stopped --name mediaflow-proxy mediaflow-proxy
   ```

### Option 2: Premium Hosted Service (ElfHosted)
<div style="text-align: center;">
  <img src="https://store.elfhosted.com/wp-content/uploads/2024/08/mediaflow-proxy.jpg" alt="ElfHosted Logo" width="200" style="border-radius: 15px;">
</div>
For a hassle-free, high-performance deployment of MediaFlow Proxy, consider the premium hosted service through ElfHosted.

To purchase:
1. Visit [https://store.elfhosted.com/product/mediaflow-proxy](https://store.elfhosted.com/product/mediaflow-proxy)
2. Follow ElfHosted's setup instructions

Benefits:
- Instant setup and automatic updates
- High performance and 24/7 availability
- No server maintenance required

Ideal for users who want a reliable, plug-and-play solution without the technical overhead of self-hosting.

### Option 3: Hugging Face Space Deployment (Guide from a MediaFlow Contributor)
1. Go to this repo and create a fork: https://github.com/UrloMythus/UnHided
2. Sign up or log in to Hugging Face: https://huggingface.co/
3. Create a new space with a random name: https://huggingface.co/new-space. Choose Docker as SDK and blank template and public visibility.
4. Go to the "Settings" tab and create a new secret with the name `API_PASSWORD` and set the value to your desired password.
5. Go to the "Files" tab and create a new file with the name `Dockerfile` and paste the following content. After that, replace `YourUsername/YourRepoName` in the Dockerfile with your username and the name of your fork. Finally, click on "Commit" to save the changes. Remember, your space might get banned if instead of using your fork, you use the main repo.
    ```dockerfile
    FROM python:3.11-slim-bullseye

    WORKDIR /app

    RUN apt-get update && apt-get install -y git

    RUN git clone https://github.com/YourUsername/YourRepoName.git .

    RUN pip install --no-cache-dir -r requirements.txt

    EXPOSE 7860
    CMD ["uvicorn", "run:main_app", "--host", "0.0.0.0", "--port", "7860", "--workers", "4"]
    ```
6. Wait until the space gets built and deployed. Don't panic if you see "Your app is running" instead of the usual mediaflowproxy page. You can still use it as usual. 
7. If the space is deployed successfully, you can click on the three dots in the top right corner and click on "Embed this space" and copy the "Direct URL".
8. To update your proxy to the newest release, go to your GitHub fork and click on Sync. After that, hop on your Hugging Face Space -> Settings and click on Factory Rebuild.
9. Use the above URL and API password on support addons like MediaFusion, MammaMia, Jackettio, etc.

## Usage

### Endpoints

1. `/proxy/hls/manifest.m3u8`: Proxify HLS streams
2. `/proxy/stream`: Proxy generic http video streams
3. `/proxy/mpd/manifest.m3u8`: Process MPD manifests
4. `/proxy/mpd/playlist.m3u8`: Generate HLS playlists from MPD
5. `/proxy/mpd/segment.mp4`: Process and decrypt media segments
6. `/proxy/ip`: Get the public IP address of the MediaFlow Proxy server
7. `/extractor/video`: Extract direct video stream URLs from supported hosts (see below)
8. `/playlist/builder`: Build and customize playlists from multiple sources
9. `/proxy/transcode/playlist.m3u8`: Generate HLS VOD playlist for generic stream transcode
10. `/proxy/transcode/init.mp4`: fMP4 init segment for generic transcode playlist
11. `/proxy/transcode/segment.m4s`: fMP4 media segment for generic transcode playlist
12. `/proxy/telegram/transcode/playlist.m3u8`: Generate HLS VOD playlist for Telegram transcode
13. `/proxy/telegram/transcode/init.mp4`: fMP4 init segment for Telegram transcode playlist
14. `/proxy/telegram/transcode/segment.m4s`: fMP4 media segment for Telegram transcode playlist

Once the server is running, for more details on the available endpoints and their parameters, visit the Swagger UI at `http://localhost:8888/docs`.

### Video Extractor Endpoint

The extractor endpoint extracts direct video stream URLs from various video hosting services. It supports an optional file extension in the URL for better player compatibility.

#### Endpoints

| Endpoint | Description |
|----------|-------------|
| `/extractor/video` | Base endpoint (generic, backward compatible) |
| `/extractor/video.m3u8` | HLS streams - helps ExoPlayer detect HLS |
| `/extractor/video.mp4` | MP4 streams |
| `/extractor/video.mkv` | MKV streams |
| `/extractor/video.ts` | MPEG-TS streams |
| `/extractor/video.webm` | WebM streams |
| `/extractor/video.avi` | AVI streams |

#### Why Use Extensions?

Some video players (notably Android's ExoPlayer used in Stremio) determine the media source type from the URL before making any HTTP requests. Without the correct extension:

- ExoPlayer sees `/extractor/video?...` → Uses `ProgressiveMediaSource`
- ExoPlayer sees `/extractor/video.m3u8?...` → Uses `HlsMediaSource` ✓

For HLS streams, using the `.m3u8` extension ensures the player uses the correct HLS playback pipeline.

#### Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| `host` | Yes | Extractor host name (e.g., `TurboVidPlay`, `Vidoza`) |
| `d` | Yes | Destination URL (the video page URL to extract) |
| `api_password` | Yes* | API password (*if configured) |
| `redirect_stream` | No | If `true`, returns 302 redirect to the proxied stream URL |

#### Example Usage

**Get extraction result as JSON:**
```
GET /extractor/video?host=Vidoza&d=https://videzz.net/example.html&api_password=your_password
```

**Redirect directly to stream (for players):**
```
GET /extractor/video.m3u8?host=TurboVidPlay&d=https://turbovidhls.com/t/abc123&api_password=your_password&redirect_stream=true
```

This redirects to the proxied HLS manifest URL, and because the request URL contains `.m3u8`, players like ExoPlayer will correctly use HLS playback.

### Xtream Codes (XC) API Proxy

MediaFlow Proxy can act as a stateless pass-through proxy for Xtream Codes API, allowing you to proxy streams from XC-compatible IPTV providers through MediaFlow. This is particularly useful for:

- Proxying streams from providers with **Catch Up/Timeshift** support
- Using MediaFlow's features (headers, DRM, etc.) with XC streams
- Routing XC streams through a specific network path

#### Configuration

Configure your IPTV player with the following settings:

| Setting | Value |
|---------|-------|
| **Server URL** | `http://your-mediaflow-server:8888` |
| **Username** | Base64-encoded string (see below) |
| **Password** | Your XC provider password |

#### Username Format (Recommended)

The username should be a **base64-encoded string** containing your provider URL, XC username, and MediaFlow API password. This format is compatible with all IPTV players (TiviMate, IPTV Smarters, OTT Navigator, etc.).

**Format before encoding:**
```
{provider_url}:{xc_username}:{api_password}
```

**Example:**
```
http://provider.com:8080:myusername:my_mediaflow_password
```

After base64 encoding, this becomes a single string like:
```
aHR0cDovL3Byb3ZpZGVyLmNvbTo4MDgwOm15dXNlcm5hbWU6bXlfbWVkaWFmbG93X3Bhc3N3b3Jk
```

**Without MediaFlow API password:**
```
http://provider.com:8080:myusername
```

Encoded:
```
aHR0cDovL3Byb3ZpZGVyLmNvbTo4MDgwOm15dXNlcm5hbWU
```

#### Generating the Username

Use the **URL Generator tool** at `http://your-mediaflow-server:8888/url-generator` (recommended) or manually:

**Using command line:**
```bash
# With API password
echo -n "http://provider.com:8080:myusername:my_api_password" | base64

# Without API password
echo -n "http://provider.com:8080:myusername" | base64
```

**Using Python:**
```python
import base64

# With API password
combined = "http://provider.com:8080:myusername:my_api_password"
encoded = base64.urlsafe_b64encode(combined.encode()).decode().rstrip('=')
print(encoded)

# Without API password
combined = "http://provider.com:8080:myusername"
encoded = base64.urlsafe_b64encode(combined.encode()).decode().rstrip('=')
print(encoded)
```

#### Legacy Format (Still Supported)

The legacy colon-separated format is still supported for backward compatibility:
```
{base64_upstream}:{actual_username}:{api_password}
```

However, some IPTV apps may not handle colons in the username field correctly. The new base64-encoded format is recommended.

#### Supported XC API Endpoints

MediaFlow proxies all standard XC API endpoints:

| Endpoint | Description |
|----------|-------------|
| `/player_api.php` | Main API for categories, streams, VOD, series |
| `/xmltv.php` | EPG/TV Guide data |
| `/get.php` | M3U playlist generation |
| `/panel_api.php` | Panel API (if supported by provider) |
| `/live/{user}/{pass}/{id}.{ext}` | Live stream playback |
| `/movie/{user}/{pass}/{id}.{ext}` | VOD/Movie playback |
| `/series/{user}/{pass}/{id}.{ext}` | Series episode playback |
| `/timeshift/{user}/{pass}/{duration}/{start}/{id}.{ext}` | Catch-up/Timeshift playback |

#### Player Configuration Examples

**TiviMate:**
1. Add Playlist → Xtream Codes Login
2. Server: `http://your-mediaflow-server:8888`
3. Username: Paste the base64-encoded username from the URL Generator
4. Password: Your XC password

**IPTV Smarters:**
1. Add User → Xtream Codes API
2. Any Name: Your choice
3. Username: Paste the base64-encoded username from the URL Generator
4. Password: Your XC password
5. URL: `http://your-mediaflow-server:8888`

**OTT Navigator:**
1. Add Provider → Xtream
2. Portal URL: `http://your-mediaflow-server:8888`
3. Login: Paste the base64-encoded username from the URL Generator
4. Password: Your XC password

### URL Parameters

**`&max_res=true`**  
Forces playback at the highest available quality (maximum resolution) supported by the stream.  
- **Usage:** Add `&max_res=true` to the proxy URL  
- **Effect:** Only the highest quality rendition will be selected and served.  
- **Note:** This parameter is effective with HLS and MPD streams.

**`&resolution=720p`**  
Select a specific resolution stream instead of the highest or default.  
- **Usage:** Add `&resolution=720p` (or `1080p`, `480p`, `360p`, etc.) to the proxy URL  
- **Effect:** Selects the stream matching the specified resolution. Falls back to the closest lower resolution if exact match is not found.  
- **Supported Endpoints:** `/proxy/hls/manifest.m3u8`, `/proxy/mpd/manifest.m3u8`

**`&no_proxy=true`**  
Disables the proxy for the current destination, performing a direct request.  
- **Usage:** Add `&no_proxy=true` to the proxy URL  
- **Effect:** Bypasses all proxy functions for the destination, useful for debugging or testing stream access directly.

**`&skip=0-112,280-300`**  
Skip specific time ranges in HLS and DASH/MPD streams. Useful for skipping intros, outros, credits, or any unwanted content.  
- **Usage:** Add `&skip=start-end,start-end,...` to the proxy URL (times in seconds)  
- **Effect:** Removes segments that overlap with the specified time ranges and inserts `#EXT-X-DISCONTINUITY` markers for seamless playback.  
- **Supported Endpoints:** `/proxy/hls/manifest.m3u8`, `/proxy/mpd/manifest.m3u8`, `/proxy/mpd/playlist.m3u8`  
- **Precision:** Segment-level precision (segments overlapping with skip ranges are removed entirely)  
- **Decimal Support:** Supports decimal values for precise timing (e.g., `skip=0-112.5,120.25-150.75`)  
- **Example:** `&skip=0-90` skips the first 90 seconds (intro), `&skip=0-90,1750-1800` skips intro and outro

**`&start_offset=-18`**  
Inject `#EXT-X-START:TIME-OFFSET` tag into HLS playlists to control playback start position. Particularly useful for live streams to enable prebuffering.  
- **Usage:** Add `&start_offset=-18` to the proxy URL (negative value for live streams)  
- **Effect:** Injects `#EXT-X-START:TIME-OFFSET=-18.0,PRECISE=YES` into the HLS manifest, causing players to start playback behind the live edge.  
- **Supported Endpoints:** `/proxy/hls/manifest.m3u8`, `/proxy/mpd/playlist.m3u8`, `/proxy/acestream/manifest.m3u8`  
- **Use Case:** For live streams, starting behind the live edge creates headroom for the prebuffer system to prefetch upcoming segments, resulting in smoother playback without buffering.  
- **Default:** Can be configured globally via `LIVESTREAM_START_OFFSET` environment variable (default: `-18` for live streams). Set to empty to disable.  
- **Note:** When using the default setting, the offset is only applied to live media playlists (not VOD or master playlists). Explicit `start_offset` parameter overrides this behavior.  
- **Example:** `&start_offset=-18` starts playback 18 seconds behind the live edge

**`&x_headers=content-length,transfer-encoding`**  
Remove specific headers from the proxied response.  
- **Usage:** Add `&x_headers=header1,header2` to the proxy URL (comma-separated list)  
- **Effect:** Removes the specified headers from the upstream response before forwarding to the client.  
- **Use Case:** Useful when upstream servers send incorrect headers (e.g., wrong `Content-Length`) that cause playback issues.  
- **Example:** `&x_headers=content-length` removes the Content-Length header, allowing chunked transfer encoding.

**`&transformer=ts_stream`**  
Apply stream content transformations for specific hosting providers.  
- **Usage:** Add `&transformer=transformer_id` to the proxy URL  
- **Effect:** Processes stream chunks through a transformer that handles host-specific obfuscation or encoding.  
- **Available Transformers:**
  - `ts_stream` - Handles MPEG-TS streams wrapped in fake PNG containers with 0xFF padding (used by TurboVidPlay, StreamWish, FileMoon, etc.)
- **How it works:** Some video hosts disguise their TS segments as PNG images to evade detection. The `ts_stream` transformer:
  1. Detects and strips the fake PNG header (89 50 4E 47...)
  2. Finds and removes the PNG IEND marker
  3. Skips any 0xFF padding bytes
  4. Locates the actual MPEG-TS sync byte (0x47) with packet alignment verification
  5. Outputs clean, playable MPEG-TS data
- **Example:** `&transformer=ts_stream&x_headers=content-length,content-range` for streams with PNG wrappers.
- **Note:** This parameter is automatically set when using extractors for supported hosts.

**`/proxy/transcode/playlist.m3u8` and `/proxy/telegram/transcode/playlist.m3u8` (recommended)**  
Use HLS transcode playlists for smooth browser playback and robust seeking with fMP4 segments.  
- **Usage:** Open the playlist endpoint directly with `d` (or Telegram params), optional `api_password`, and optional `h_*` headers.  
- **Effect:** Generates an HLS VOD playlist that references `init.mp4` + `segment.m4s` endpoints with browser-compatible H.264/AAC output.  
- **URL Generator behavior:** When transcode is enabled and no start time is provided, URL Generator outputs these playlist URLs by default.

**`&transcode=true` (direct mode)**  
Transcode the stream directly to browser-compatible fragmented MP4 (fMP4) with H.264 video and AAC audio.  
- **Usage:** Add `&transcode=true` to `/proxy/stream`, `/proxy/telegram/stream`, `/proxy/acestream/stream`, or Xtream Codes live/movie/series stream URLs.  
- **Effect:** Re-encodes unsupported video codecs (HEVC, VP8/VP9, MPEG-2, MPEG-4, etc.) to H.264 and unsupported audio codecs (AC3, EAC3, Vorbis, Opus, FLAC, DTS, etc.) to AAC. Browser-compatible codecs (H.264 video, AAC audio) are passed through without re-encoding.  
- **GPU Acceleration:** Automatically uses GPU encoding when available (NVIDIA NVENC, Apple VideoToolbox, Intel VAAPI/QSV). Falls back to CPU (libx264) otherwise.  
- **On-the-fly:** Streaming is real-time with pipe-based demuxing. For MP4 inputs, the moov atom is probed and rewritten for immediate playback without downloading the full file.

**`&start=120`**  
Seek to a specific time position before starting transcoded playback.  
- **Usage:** Add `&start=120` (value in seconds) alongside `&transcode=true` in direct transcode mode  
- **Effect:** Starts transcoding from the specified time offset. For indexed containers (MKV cues, MP4 moov), this seeks to the nearest keyframe. For non-indexed formats (TS), this is a byte-estimate seek.  
- **Supported Endpoints:** `/proxy/stream`, `/proxy/telegram/stream`, `/proxy/acestream/stream`, Xtream Codes live/movie/series endpoints  
- **Note:** `start` is not used by `/proxy/transcode/playlist.m3u8` or `/proxy/telegram/transcode/playlist.m3u8` endpoints.
- **Example:** `&transcode=true&start=300` starts playback from 5 minutes into the stream

**`&ratelimit=vidoza`**  
Apply host-specific rate limiting to prevent CDN 509 (Bandwidth Limit Exceeded) errors. Requires Redis to be configured.  
- **Usage:** Add `&ratelimit=handler_id` to the `/proxy/stream` URL  
- **Effect:** Limits the frequency of upstream connections to avoid triggering rate limits on aggressive CDNs.  
- **Auto-detection:** If not specified, rate limiting is automatically applied for known hosts (e.g., Vidoza).  
- **Available Handlers:**
  - `vidoza` - 5-second cooldown between connections, HEAD caching, stream gating (auto-detected for vidoza.net)
  - `aggressive` - 3-second cooldown, suitable for other rate-limited hosts
  - `none` - Explicitly disable rate limiting (use when auto-detection is unwanted)
- **How it works:** When a rate-limited stream is requested:
  1. HEAD responses are cached to serve repeated probes without upstream connections
  2. A cooldown period prevents rapid-fire GET requests
  3. If another request arrives during cooldown, returns `503 Service Unavailable` with `Retry-After` header
  4. Players automatically retry after the cooldown, resulting in smooth playback
- **Requires:** `REDIS_URL` must be configured for rate limiting to function. Without Redis, rate limiting is disabled.
- **Example:** `&ratelimit=vidoza` for Vidoza streams, or `&ratelimit=none` to disable auto-detection.

**`&rp_content-type=video/mp2t`**  
Set response headers that propagate to HLS/DASH segments.  
- **Usage:** Add `&rp_header-name=value` to the proxy URL (rp_ prefix)  
- **Effect:** These headers are applied to segment responses AND propagated to segment URLs in the manifest.  
- **Use Case:** Override content-type for segments disguised as other file types (e.g., PNG files containing video data).  
- **Difference from `r_` prefix:** `r_` headers only apply to the manifest response, while `rp_` headers propagate to all segment requests.  
- **Example:** `&rp_content-type=video/mp2t` sets the content-type to video/mp2t for all segments.

### Examples

#### Proxy HTTPS Stream

```bash
mpv "http://localhost:8888/proxy/stream?d=https://jsoncompare.org/LearningContainer/SampleFiles/Video/MP4/sample-mp4-file.mp4&api_password=your_password"
```

#### Proxy HTTPS self-signed certificate Stream

To bypass SSL verification for a self-signed certificate stream, export the proxy route configuration:
```bash
PROXY_ROUTES='{"https://self-signed.badssl.com": {"proxy_url": null, "verify_ssl": false}}'
```

```bash
mpv "http://localhost:8888/proxy/stream?d=https://self-signed.badssl.com/&api_password=your_password"
```


#### Proxy HLS Stream with Headers

```bash
mpv "http://localhost:8888/proxy/hls/manifest.m3u8?d=https://devstreaming-cdn.apple.com/videos/streaming/examples/img_bipbop_adv_example_fmp4/master.m3u8&h_referer=https://apple.com/&h_origin=https://apple.com&h_user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36&api_password=your_password"
```

#### Proxy M3U/M3U_Plus IPTV Streams with Forced Playlist Proxying

For IPTV m3u/m3u_plus streams where playlist URLs don't have clear keyword indicators, use the `force_playlist_proxy` parameter. This is commonly used with IPTV clients and applications:

```bash
# Example IPTV stream URL for use in IPTV clients like TiviMate, IPTV Smarters, etc.
http://localhost:8888/proxy/hls/manifest.m3u8?d=https://iptv.example.com/playlist.m3u&force_playlist_proxy=true&api_password=your_password

# With custom headers for IPTV providers that require authentication
http://localhost:8888/proxy/hls/manifest.m3u8?d=https://iptv.provider.com/stream&force_playlist_proxy=true&h_user-agent=IPTV-Client&h_referer=https://iptv.provider.com&api_password=your_password
```

**IPTV Use Cases:**
- **M3U Playlists**: When IPTV providers use m3u format without clear file extensions
- **M3U_Plus Playlists**: Extended m3u format with additional metadata
- **Provider-Specific Streams**: IPTV services with custom playlist formats
- **Authentication Required**: Streams that need specific headers or authentication

#### HLS Stream with Resolution Selection

```bash
# Select specific resolution (720p)
mpv "http://localhost:8888/proxy/hls/manifest.m3u8?d=https://devstreaming-cdn.apple.com/videos/streaming/examples/img_bipbop_adv_example_fmp4/master.m3u8&resolution=720p&api_password=your_password"

# Select highest resolution
mpv "http://localhost:8888/proxy/hls/manifest.m3u8?d=https://devstreaming-cdn.apple.com/videos/streaming/examples/img_bipbop_adv_example_fmp4/master.m3u8&max_res=true&api_password=your_password"
```

#### HLS/DASH Stream with Segment Skipping (Intro/Outro Skip)

```bash
# Skip intro (first 90 seconds) in HLS stream
mpv "http://localhost:8888/proxy/hls/manifest.m3u8?d=https://example.com/playlist.m3u8&skip=0-90&api_password=your_password"

# Skip intro and outro in HLS stream
mpv "http://localhost:8888/proxy/hls/manifest.m3u8?d=https://example.com/playlist.m3u8&skip=0-112,1750-1800&api_password=your_password"

# Skip intro in DASH/MPD stream
mpv "http://localhost:8888/proxy/mpd/manifest.m3u8?d=https://example.com/manifest.mpd&skip=0-90&api_password=your_password"

# Skip multiple segments with decimal precision
mpv "http://localhost:8888/proxy/hls/manifest.m3u8?d=https://example.com/playlist.m3u8&skip=0-112.5,1750.25-1800.75&api_password=your_password"
```

#### Live Stream with Start Offset (Prebuffer Support)

```bash
# Start 18 seconds behind the live edge for HLS (allows prebuffer to work effectively)
mpv "http://localhost:8888/proxy/hls/manifest.m3u8?d=https://example.com/live/playlist.m3u8&start_offset=-18&api_password=your_password"

# For live DASH/MPD streams converted to HLS
mpv "http://localhost:8888/proxy/mpd/manifest.m3u8?d=https://example.com/live/manifest.mpd&start_offset=-18&api_password=your_password"

# For Acestream live streams with start offset
mpv "http://localhost:8888/proxy/acestream/manifest.m3u8?id=your_content_id&start_offset=-18&api_password=your_password"
```

**Note:** The `start_offset` parameter is particularly useful for live streams where the prebuffer system cannot prefetch segments when sitting at the live edge. By starting slightly behind (e.g., `-18` seconds), there are future segments available for prebuffering, resulting in smoother playback. This works for both native HLS and DASH/MPD streams converted to HLS.

#### Transcode Stream for Browser Playback

```bash
# Recommended: HLS transcode playlist for generic streams
mpv "http://localhost:8888/proxy/transcode/playlist.m3u8?d=https://example.com/video.mkv&api_password=your_password"

# Recommended: HLS transcode playlist for Telegram streams
mpv "http://localhost:8888/proxy/telegram/transcode/playlist.m3u8?d=https://t.me/channelname/123&api_password=your_password"

# Direct transcode mode with explicit seek start (start at 5 minutes)
mpv "http://localhost:8888/proxy/stream?d=https://example.com/video.mp4&transcode=true&start=300&api_password=your_password"

# Acestream transcode (direct mode)
mpv "http://localhost:8888/proxy/acestream/stream?id=YOUR_CONTENT_ID&transcode=true&api_password=your_password"
```

**Note:** Transcoding uses GPU hardware acceleration when available (NVIDIA, Apple VideoToolbox, Intel). Browser-compatible codecs (H.264 video, AAC audio) are passed through without re-encoding to minimize resource usage.

#### Transcode Performance Benchmarks

Benchmark results for on-the-fly HEVC (H.265) to H.264 transcoding. Source: 4K (3840x2160) 30-second clip at 24fps with EAC3 5.1 audio, from a real movie file.

**MediaFlow Proxy (on-the-fly streaming via PyAV pipeline):**

| Source | Encoder | Wall Clock | Video Frames | Effective FPS | Output |
|--------|---------|-----------|--------------|---------------|--------|
| 4K HEVC MKV (EAC3) | VideoToolbox (GPU) | **11.7s** | 722 | **61.7 fps** | 15.1 MB |
| 4K HEVC MKV (EAC3) | libx264 (CPU) | 26.2s | 722 | 27.6 fps | 15.1 MB |

**Direct FFmpeg CLI baseline (local file, no HTTP proxy):**

| Source | Encoder | Wall Clock | CPU Time | CPU Usage |
|--------|---------|-----------|----------|-----------|
| 4K HEVC MKV | VideoToolbox (GPU) | **11.9s** | 10.7s | 92% |
| 4K HEVC MKV | libx264 (CPU) | 11.4s | 81.7s | 725% |

**Key observations:**
- **GPU MediaFlow matches direct FFmpeg** -- the optimized pipeline adds near-zero overhead (11.7s vs 11.9s)
- GPU **exceeds real-time by 2.5x** for 4K 24fps content (62 fps), meaning no buffering delays
- **GPU uses ~7x less CPU** than software encoding (92% vs 725%), leaving resources free for concurrent streams
- The pipeline optimizations (thread-safe queues, eliminated async round-trips, skip redundant decoder flush) reduced GPU wall-clock from ~17s to ~11.7s (**31% improvement**)
- On servers with NVIDIA GPUs, hardware HEVC decoding (`hevc_cuvid`) would further reduce both wall-clock time and CPU usage

*Tested on Apple Silicon (M4) with PyAV 16.1.0 and FFmpeg 8.0. Results vary by hardware, content complexity, and network conditions.*

#### Stream with Header Removal (Fix Content-Length Issues)

```bash
# Remove content-length header for streams with incorrect content-length
mpv "http://localhost:8888/proxy/stream?d=https://example.com/video.mp4&x_headers=content-length&api_password=your_password"
```

#### Stream with PNG-Wrapped TS Segments (Stream Transformer)

```bash
# Handle streams where TS segments are disguised as PNG files (TurboVidPlay, StreamWish, FileMoon, etc.)
mpv "http://localhost:8888/proxy/hls/manifest.m3u8?d=https://example.com/playlist.m3u8&transformer=ts_stream&x_headers=content-length,content-range&api_password=your_password"

# The transformer strips fake PNG headers and 0xFF padding to extract the actual MPEG-TS data
# Note: When using extractors, the transformer is automatically applied for supported hosts
```

#### Live DASH Stream (Non-DRM Protected)

```bash
mpv -v "http://localhost:8888/proxy/mpd/manifest.m3u8?d=https://livesim.dashif.org/livesim/chunkdur_1/ato_7/testpic4_8s/Manifest.mpd&api_password=your_password"
```

#### VOD DASH Stream (DRM Protected - Single Key)

```bash
mpv -v "http://localhost:8888/proxy/mpd/manifest.m3u8?d=https://media.axprod.net/TestVectors/v7-MultiDRM-SingleKey/Manifest_1080p_ClearKey.mpd&key_id=nrQFDeRLSAKTLifXUIPiZg&key=FmY0xnWCPCNaSpRG-tUuTQ&api_password=your_password"
```

#### VOD DASH Stream (DRM Protected - Multi-Key)

For streams with different keys for video and audio tracks, provide multiple key_id:key pairs separated by commas:

```bash
mpv -v "http://localhost:8888/proxy/mpd/manifest.m3u8?d=https://example.com/multikey.mpd&key_id=video_key_id,audio_key_id&key=video_key,audio_key&api_password=your_password"
```

Note: The `key` and `key_id` parameters are automatically processed if they're not in the correct format. Multi-key support allows decryption of streams where video and audio tracks use different encryption keys.

### URL Encoding

For players like VLC that require properly encoded URLs, use the `encode_mediaflow_proxy_url` function:

```python
from mediaflow_proxy.utils.http_utils import encode_mediaflow_proxy_url

encoded_url = encode_mediaflow_proxy_url(
    mediaflow_proxy_url="http://127.0.0.1:8888",
    endpoint="/proxy/mpd/manifest.m3u8",
    destination_url="https://media.axprod.net/TestVectors/v7-MultiDRM-SingleKey/Manifest_1080p_ClearKey.mpd",
    query_params={
        "key_id": "nrQFDeRLSAKTLifXUIPiZg",
        "key": "FmY0xnWCPCNaSpRG-tUuTQ",
        "api_password": "your_password"
    },
    request_headers={
        "referer": "https://media.axprod.net/",
        "origin": "https://media.axprod.net",
    }
)

print(encoded_url)

# http://127.0.0.1:8888/proxy/mpd/manifest.m3u8?key_id=nrQFDeRLSAKTLifXUIPiZg&key=FmY0xnWCPCNaSpRG-tUuTQ&api_password=your_password&d=https%3A%2F%2Fmedia.axprod.net%2FTestVectors%2Fv7-MultiDRM-SingleKey%2FManifest_1080p_ClearKey.mpd&h_referer=https%3A%2F%2Fmedia.axprod.net%2F&h_origin=https%3A%2F%2Fmedia.axprod.net
```

This will output a properly encoded URL that can be used with players like VLC.

```bash
vlc "http://127.0.0.1:8888/proxy/mpd/manifest.m3u8?key_id=nrQFDeRLSAKTLifXUIPiZg&key=FmY0xnWCPCNaSpRG-tUuTQ&api_password=dedsec&d=https%3A%2F%2Fmedia.axprod.net%2FTestVectors%2Fv7-MultiDRM-SingleKey%2FManifest_1080p_ClearKey.mpd"
```

### Generating URLs

MediaFlow Proxy provides endpoints to generate properly encoded or encrypted URLs for use with media players.
- `/generate_url`: Generate a single encoded or encrypted URL
- `/generate_urls`: Generate multiple URLs with shared common parameters


#### Single URL Generation

To generate a single encoded or encrypted URL:

```python
import requests

url = "http://localhost:8888/generate_url"
data = {
    "mediaflow_proxy_url": "http://localhost:8888",
    "endpoint": "/proxy/stream",
    "destination_url": "https://example.com/video.mp4",
    "query_params": {
        "some_param": "value"
        # Add "api_password" here for encoded (non-encrypted) URLs
        # "api_password": "your_password"
    },
    "request_headers": {
        "referer": "https://example.com/",
        "origin": "https://example.com",
    },
    "response_headers": {
        "cache-control": "no-cache",  # Optional: Add custom response headers (r_ prefix, manifest only)
    },
    "propagate_response_headers": {
        "content-type": "video/mp2t",  # Optional: Headers that propagate to segments (rp_ prefix)
    },
    "remove_response_headers": ["content-length", "content-range"],  # Optional: Remove specific response headers
    "expiration": 3600,  # URL will expire in 1 hour (only for encrypted URLs)
    "ip": "123.123.123.123",  # Optional: Restrict access to this IP (only for encrypted URLs)
    "api_password": "your_password",  # Add here for encrypted URLs
    "filename": "movie.mp4"  # Optional: Preserve filename for media players (only for /proxy/stream endpoint)
}

response = requests.post(url, json=data)
encoded_url = response.json()["url"]
print(encoded_url)
```

> **Important Notes:**
> - If you add `api_password` at the root level of the request, the URL will be **encrypted**.
> - If you add `api_password` inside the `query_params` object, the URL will only be **encoded** (not encrypted).
> - The `filename` parameter is optional and should only be used with the `/proxy/stream` endpoint, not with MPD or HLS proxy endpoints.
> - The `remove_response_headers` parameter is useful when upstream servers send incorrect headers (e.g., wrong `Content-Length`) that cause playback issues.
> - The `response_headers` parameter adds headers to the manifest response only (`r_` prefix in URL).
> - The `propagate_response_headers` parameter adds headers that propagate to segment URLs (`rp_` prefix in URL). Useful for overriding content-type on segments disguised as other file types.
> - The legacy endpoint `/generate_encrypted_or_encoded_url` is still available but deprecated. It's recommended to use `/generate_url` instead.

#### Multiple URLs Generation

To generate multiple URLs with shared common parameters:

```python
import requests

url = "http://localhost:8888/generate_urls"
data = {
    "mediaflow_proxy_url": "http://localhost:8888",
    "api_password": "your_password",
    "expiration": 3600,  # URLs will expire in 1 hour (only for encrypted URLs)
    "ip": "123.123.123.123",  # Optional: Restrict access to this IP (only for encrypted URLs)
    "urls": [
        {
            "destination_url": "https://example.com/video1.mp4",
            "request_headers": {"referer": "https://example.com"},
            "filename": "movie1.mp4",
            "endpoint": "/proxy/stream"
        },
        {
            "destination_url": "https://example.com/video2.mp4",
            "request_headers": {"referer": "https://example.com"},
            "filename": "movie2.mp4",
            "endpoint": "/proxy/stream"
        }
    ]
}

response = requests.post(url, json=data)
encoded_urls = response.json()["urls"]
for url in encoded_urls:
    print(url)
```

#### Filename Preservation for Media Players

MediaFlow Proxy now supports preserving filenames in URLs, which is particularly useful for media players like Infuse that use the filename to fetch metadata. When you include a `filename` parameter in your request, the proxy will ensure this information is preserved and properly passed to the media player.

This feature helps media players display the correct title and fetch appropriate metadata instead of showing generic names like "Stream".

### Using MediaFlow Proxy with Debrid Services and Stremio Addons

MediaFlow Proxy can be particularly useful when working with Debrid services (like Real-Debrid, AllDebrid) and Stremio addons. The `/proxy/ip` endpoint allows you to retrieve the public IP address of the MediaFlow Proxy server, which is crucial for routing Debrid streams correctly.

When a Stremio addon needs to create a video URL for a Debrid service, it typically needs to provide the user's public IP address. However, when routing the Debrid stream through MediaFlow Proxy, you should use the IP address of the MediaFlow Proxy server instead.

Here's how to utilize MediaFlow Proxy in this scenario:

1. If MediaFlow Proxy is accessible over the internet:
   - Use the `/proxy/ip` endpoint to get the MediaFlow Proxy server's public IP.
   - Use this IP when creating Debrid service URLs in your Stremio addon.

2. If MediaFlow Proxy is set up locally:
   - Stremio addons can directly use the client's IP address.

### Using Stremio Server for M3U8 Content Proxy

MediaFlow Proxy supports routing video segments through Stremio server for better performance while keeping playlists through MediaFlow for access control.

#### Configuration

```bash
# Set Stremio server URL
STREMIO_PROXY_URL=http://127.0.0.1:11470

# Choose routing strategy
M3U8_CONTENT_ROUTING=stremio  # or "mediaflow" (default) or "direct"
```

**Routing Options:**
- `mediaflow` (default): All content through MediaFlow
- `stremio`: Video segments through Stremio, playlists through MediaFlow
- `direct`: Video segments served directly, playlists through MediaFlow

**Force Playlist Proxy Parameter:**

For IPTV streams where the playlist format (m3u/m3u_plus) cannot be reliably detected from the URL, you can use the `force_playlist_proxy` parameter to ensure all playlist URLs are proxied through MediaFlow:

```bash
# Force all playlist URLs to be proxied through MediaFlow (for IPTV clients)
http://localhost:8888/proxy/hls/manifest.m3u8?d=https://iptv.provider.com/playlist&force_playlist_proxy=true&api_password=your_password
```

This parameter bypasses URL-based detection and routing strategy, ensuring consistent behavior for IPTV streams that don't have clear format indicators in their URLs.

## Base64 URL Support

MediaFlow Proxy now supports base64 encoded URLs, providing additional flexibility for handling URLs that may be encoded in base64 format.

### Features

#### Automatic Base64 Detection and Decoding

The proxy automatically detects and decodes base64 encoded URLs in all endpoints:

- **Proxy endpoints** (`/proxy/stream`, `/proxy/hls/manifest.m3u8`, etc.)
- **Extractor endpoints** (`/extractor/video`)
- **MPD/DASH endpoints** (`/proxy/mpd/manifest.m3u8`, `/proxy/mpd/playlist.m3u8`)

#### Base64 Utility Endpoints

New endpoints for base64 operations:

**1. Encode URL to Base64**
```http
POST /base64/encode
Content-Type: application/json

{
  "url": "https://example.com/video.mp4"
}
```

Response:
```json
{
  "encoded_url": "aHR0cHM6Ly9leGFtcGxlLmNvbS92aWRlby5tcDQ",
  "original_url": "https://example.com/video.mp4"
}
```

**2. Decode Base64 URL**
```http
POST /base64/decode
Content-Type: application/json

{
  "encoded_url": "aHR0cHM6Ly9leGFtcGxlLmNvbS92aWRlby5tcDQ"
}
```

Response:
```json
{
  "decoded_url": "https://example.com/video.mp4",
  "encoded_url": "aHR0cHM6Ly9leGFtcGxlLmNvbS92aWRlby5tcDQ"
}
```

**3. Check if String is Base64 URL**
```http
GET /base64/check?url=aHR0cHM6Ly9leGFtcGxlLmNvbS92aWRlby5tcDQ
```

Response:
```json
{
  "url": "aHR0cHM6Ly9leGFtcGxlLmNvbS92aWRlby5tcDQ",
  "is_base64": true,
  "decoded_url": "https://example.com/video.mp4"
}
```

#### URL Generation with Base64 Encoding

The `/generate_url` endpoint now supports a `base64_encode_destination` parameter:

```python
import requests

url = "http://localhost:8888/generate_url"
data = {
    "mediaflow_proxy_url": "http://localhost:8888",
    "endpoint": "/proxy/stream",
    "destination_url": "https://example.com/video.mp4",
    "base64_encode_destination": True,  # Encode destination URL in base64
    "api_password": "your_password"
}

response = requests.post(url, json=data)
encoded_url = response.json()["url"]
print(encoded_url)
```

### Usage Examples

#### 1. Using Base64 Encoded URLs Directly

You can now pass base64 encoded URLs directly to any proxy endpoint:

```bash
# Original URL: https://example.com/video.mp4
# Base64 encoded: aHR0cHM6Ly9leGFtcGxlLmNvbS92aWRlby5tcDQ

mpv "http://localhost:8888/proxy/stream?d=aHR0cHM6Ly9leGFtcGxlLmNvbS92aWRlby5tcDQ&api_password=your_password"
```

#### 2. HLS Manifest with Base64 URL

```bash
# Base64 encoded HLS URL
mpv "http://localhost:8888/proxy/hls/manifest.m3u8?d=aHR0cDovL2V4YW1wbGUuY29tL3BsYXlsaXN0Lm0zdTg&api_password=your_password"
```

#### 3. Extractor with Base64 URL

```bash
# Base64 encoded extractor URL
curl "http://localhost:8888/extractor/video?host=Doodstream&d=aHR0cHM6Ly9kb29kc3RyZWFtLmNvbS9lL3NvbWVfaWQ&api_password=your_password"
```

#### 4. DASH Stream with Base64 URL

```bash
# Base64 encoded DASH manifest URL
mpv "http://localhost:8888/proxy/mpd/manifest.m3u8?d=aHR0cHM6Ly9leGFtcGxlLmNvbS9tYW5pZmVzdC5tcGQ&api_password=your_password"
```

### Implementation Details

#### Base64 Detection Algorithm

The system uses several heuristics to detect base64 encoded URLs:

1. **Character Set Check**: Verifies the string contains only valid base64 characters (A-Z, a-z, 0-9, +, /, =)
2. **Protocol Check**: Ensures the string doesn't start with common URL protocols (http://, https://, etc.)
3. **Length Check**: Validates minimum length for meaningful base64 encoded URLs
4. **Decoding Validation**: Attempts to decode and validates the result is a valid URL

#### URL-Safe Base64 Encoding

The system supports both standard and URL-safe base64 encoding:

- **Standard Base64**: Uses `+` and `/` characters
- **URL-Safe Base64**: Uses `-` and `_` characters instead of `+` and `/`
- **Padding**: Automatically handles missing padding (`=` characters)

#### Error Handling

- Invalid base64 strings are treated as regular URLs
- Decoding failures are logged but don't break the request flow
- Malformed URLs after decoding are handled gracefully

### Security Considerations

- Base64 encoding is **not encryption** - it's just encoding
- URLs are still logged in their decoded form for debugging
- All existing security measures (API keys, IP restrictions, etc.) still apply
- Base64 encoded URLs are subject to the same validation as regular URLs

### Backward Compatibility

This feature is fully backward compatible:

- Existing URLs continue to work without changes
- Regular (non-base64) URLs are processed normally
- No configuration changes required
- All existing API endpoints remain unchanged

## Limitations

- **Commercial DRM not supported**: Widevine, PlayReady, and FairPlay DRM systems require license server communication and hardware security modules. These cannot be decrypted by MediaFlow Proxy as they are designed to prevent unauthorized access.
- **Key rotation not supported**: Streams where encryption keys change mid-playback are not supported.
- **Only ClearKey DRM**: The proxy can only decrypt content where you already have the decryption keys (ClearKey/AES-128).

## Acknowledgements and Inspirations

MediaFlow Proxy was developed with inspiration from various projects and resources:

- [Stremio Server](https://github.com/Stremio/stremio-server) for HLS Proxify implementation, which inspired our HLS M3u8 Manifest parsing and redirection proxify support.
- [Comet Debrid proxy](https://github.com/g0ldyy/comet) for the idea of proxifying HTTPS video streams.
- [Acexy](https://github.com/Javinator9889/acexy) for the Acestream proxy implementation inspiration, particularly the stream multiplexing and session management concepts.
- [Bento4 mp4decrypt](https://www.bento4.com/developers/dash/encryption_and_drm/), [GPAC mp4box](https://wiki.gpac.io/xmlformats/Common-Encryption/), [Shaka Packager](https://github.com/shaka-project/shaka-packager), and [devine](https://github.com/devine-dl/devine) for insights on parsing MPD and decrypting CENC/ClearKey DRM protected content across all encryption modes (cenc, cens, cbc1, cbcs).
- Test URLs were sourced from:
  - [OTTVerse MPEG-DASH MPD Examples](https://ottverse.com/free-mpeg-dash-mpd-manifest-example-test-urls/)
  - [OTTVerse HLS M3U8 Examples](https://ottverse.com/free-hls-m3u8-test-urls/)
  - [Bitmovin Stream Test](https://bitmovin.com/demos/stream-test)
  - [Bitmovin DRM Demo](https://bitmovin.com/demos/drm)
  - [DASH-IF Reference Player](http://reference.dashif.org/dash.js/nightly/samples/)
- [HLS Protocol RFC](https://www.rfc-editor.org/rfc/rfc8216) for understanding the HLS protocol specifications.
- Claude 3.5 Sonnet for code assistance and brainstorming.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

[MIT License](LICENSE)


## Disclaimer

This project is for educational purposes only. The developers of MediaFlow Proxy are not responsible for any misuse of this software. Please ensure that you have the necessary permissions to access and use the media streams you are proxying.
