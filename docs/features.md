# Features

## Stream Processing
- Convert MPEG-DASH streams (DRM-protected and non-protected) to HLS
- **ClearKey DRM decryption** with support for all CENC encryption modes (see [DASH/MPD Support Status](#dashmpd-support-status))
- Support for **multi-key DRM** streams (different keys for video/audio tracks)
- Support for non-DRM protected DASH live and VOD streams
- Proxy and modify HLS (M3U8) streams in real-time
- **Smart pre-buffering** for both HLS and DASH streams (enabled by default)
- Proxy HTTP/HTTPS links with custom headers

## Proxy & Routing
- Advanced proxy routing system with support for:
  - Domain-based routing rules
  - Protocol-specific routing (HTTP/HTTPS)
  - Subdomain and wildcard patterns
  - Port-specific routing
- Support for HTTP/HTTPS/SOCKS5 proxy forwarding
- Flexible SSL verification control per route
- Support for expired or self-signed SSL certificates
- Public IP address retrieval for Debrid services integration

## EPG Proxy

- **XMLTV/EPG pass-through proxy** — fetch and serve EPG schedule data from any upstream source
- **Built-in caching** with configurable TTL (default 1 hour via `EPG_CACHE_TTL`) — reduces upstream load
- Compatible with **Channels DVR**, Plex, Emby, Jellyfin, TiviMate, and all XMLTV-based clients
- Supports **custom request headers** (`h_<Name>` params) for protected EPG sources (e.g., `h_Authorization=Bearer token`)
- Accepts plain and **base64-encoded** destination URLs
- Per-request TTL override via `cache_ttl` query parameter
- Returns `X-EPG-Cache: HIT/MISS` header for observability

## Xtream Codes (XC) API Proxy
- **Stateless XC API proxy** for IPTV players
- Support for live streams, VOD, series, and **catch-up/timeshift**
- Compatible with any XC-compatible IPTV player (TiviMate, IPTV Smarters, etc.)
- Automatic URL rewriting for seamless proxying

## Acestream Proxy
- **Acestream P2P stream proxy** - Proxy Acestream content through MediaFlow (inspired by [Acexy](https://github.com/Javinator9889/acexy))
- Support for both **HLS manifest** and **MPEG-TS stream** output formats
- **Stream multiplexing** - Multiple clients can watch the same stream simultaneously
- Automatic **session management** with cross-process coordination
- Works with content IDs (`acestream://...`) and infohashes (magnet links)
- Compatible with any media player that supports HLS or MPEG-TS

## Telegram MTProto Proxy
- **Telegram video streaming** - Stream videos from Telegram channels, groups, and DMs through MediaFlow
- **High-speed parallel downloads** using FastTelethon technique (up to 20+ MB/s)
- **Full range-request support** - Seeking works seamlessly in video players
- Support for **t.me links** and direct file references
- Works with public channels, private channels (if member), groups, and DMs
- Persistent session management with automatic reconnection

## Security
- API password protection against unauthorized access & Network bandwidth abuse prevention
- Parameter encryption to hide sensitive information
- Optional IP-based access control for encrypted URLs
- URL expiration support for encrypted URLs

## On-the-fly Transcoding
- **Universal video/audio transcoding** to browser-compatible fMP4 (H.264 + AAC)
- **GPU hardware acceleration** (NVIDIA NVENC, Apple VideoToolbox, Intel VAAPI/QSV) with automatic CPU fallback
- Supports **any input container** (MKV, MP4, TS, WebM, FLV, etc.) and codec (HEVC, VP8/VP9, MPEG-2, MPEG-4, AC3, EAC3, Vorbis, Opus, etc.)
- **On-the-fly streaming** -- no full-file buffering; pipe-based demuxing for MKV/TS/WebM and moov-atom probing for MP4
- **Smart format detection** -- filename extension hints + magic byte sniffing to avoid wasteful probe attempts
- Available on **all proxy endpoints**: `/proxy/stream`, Telegram, Acestream, and Xtream Codes
- Triggered by `&transcode=true` query parameter with optional `&start=<seconds>` for seeking

## Additional Features
- Built-in speed test for RealDebrid and AllDebrid services
- Custom header injection and modification
- **Response header removal** - Remove problematic headers from upstream responses (e.g., incorrect Content-Length)
- **Resolution selection** - Select specific resolution (e.g., 720p, 1080p) for HLS and DASH streams
- Real-time HLS manifest manipulation
- HLS Key URL modifications for bypassing stream restrictions
- **Base64 URL Support** - Automatic detection and processing of base64 encoded URLs
- **Segment Skipping** - Skip specific time ranges in HLS and DASH streams (intro/outro skipping, ad removal)
- **Stream Transformers** - Handle host-specific stream obfuscation (e.g., PNG-wrapped MPEG-TS segments)

## DASH/MPD Support Status

### MPD Segment Addressing Types

| Type | Status | Notes |
|------|--------|-------|
| SegmentTemplate (fixed duration) | ✅ Supported | Most common for VOD content |
| SegmentTemplate (SegmentTimeline) | ✅ Supported | Variable duration segments |
| SegmentBase | ✅ Supported | Single file with byte ranges |
| SegmentList | ✅ Supported | Explicit segment URLs in MPD |

### MPD Presentation Types

| Type | Status | Notes |
|------|--------|-------|
| Static (VOD) | ✅ Supported | Fixed duration content |
| Dynamic (Live) | ✅ Supported | Live streaming with availabilityStartTime |

### DRM/Encryption Support

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

### IV Size Support

| Size | Status | Notes |
|------|--------|-------|
| 8-byte IV | ✅ Supported | GPAC default |
| 16-byte IV | ✅ Supported | Bento4 default |
| Constant IV | ✅ Supported | Used by CBCS streams |

### Multi-Key Support

| Feature | Status | Notes |
|---------|--------|-------|
| Single Key (all tracks) | ✅ Supported | Same key for video and audio |
| Multi-Key (per track) | ✅ Supported | Different keys for video/audio tracks |
| Key rotation | ❌ Not Supported | Keys changing mid-stream |

## Pre-buffering (HLS & DASH)

MediaFlow Proxy includes intelligent pre-buffering for both HLS and DASH streams, **enabled by default** to improve playback smoothness and reduce buffering.

### How Pre-buffering Works

| Feature | HLS | DASH |
|---------|-----|------|
| Enabled by default | ✅ Yes | ✅ Yes |
| Smart variant selection | ✅ Only buffers the variant being played | ✅ Only buffers requested profiles |
| Live stream support | ✅ Buffers from end of playlist | ✅ Buffers from end of playlist |
| VOD support | ✅ Buffers from start | ✅ Buffers from start |
| Inactivity cleanup | ✅ Stops after 60s idle | ✅ Stops after 60s idle |
| Memory management | ✅ Configurable limits | ✅ Configurable limits |

### Key Behaviors

1. **Smart Variant Selection (HLS)**: When a master playlist is requested, pre-buffering does NOT automatically buffer all quality variants. It only starts buffering when the player actually requests segments from a specific variant, saving bandwidth and memory.

2. **Inactivity Cleanup**: Both HLS and DASH pre-buffers automatically stop refreshing playlists and clean up resources after 60 seconds of inactivity (no segment requests). This prevents memory leaks when streams are stopped.

3. **Live Stream Optimization**: For live streams, segments are buffered from the END of the playlist (most recent) rather than the beginning, ensuring the player has the freshest content available.

4. **Memory Protection**: Pre-buffering respects configurable memory limits and will stop buffering if system memory usage exceeds thresholds.
