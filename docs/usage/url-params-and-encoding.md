# URL parameters, encoding, and URL generation

## URL Parameters

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


## URL Encoding

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

## Generating URLs

MediaFlow Proxy provides endpoints to generate properly encoded or encrypted URLs for use with media players.
- `/generate_url`: Generate a single encoded or encrypted URL
- `/generate_urls`: Generate multiple URLs with shared common parameters


### Single URL Generation

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

### Multiple URLs Generation

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

### Filename Preservation for Media Players

MediaFlow Proxy now supports preserving filenames in URLs, which is particularly useful for media players like Infuse that use the filename to fetch metadata. When you include a `filename` parameter in your request, the proxy will ensure this information is preserved and properly passed to the media player.

This feature helps media players display the correct title and fetch appropriate metadata instead of showing generic names like "Stream".
