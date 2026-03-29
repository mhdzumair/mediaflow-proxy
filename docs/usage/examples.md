# Usage examples

## Examples

### Proxy HTTPS Stream

```bash
mpv "http://localhost:8888/proxy/stream?d=https://jsoncompare.org/LearningContainer/SampleFiles/Video/MP4/sample-mp4-file.mp4&api_password=your_password"
```

### Proxy HTTPS self-signed certificate Stream

To bypass SSL verification for a self-signed certificate stream, export the proxy route configuration:
```bash
PROXY_ROUTES='{"https://self-signed.badssl.com": {"proxy_url": null, "verify_ssl": false}}'
```

```bash
mpv "http://localhost:8888/proxy/stream?d=https://self-signed.badssl.com/&api_password=your_password"
```


### Proxy HLS Stream with Headers

```bash
mpv "http://localhost:8888/proxy/hls/manifest.m3u8?d=https://devstreaming-cdn.apple.com/videos/streaming/examples/img_bipbop_adv_example_fmp4/master.m3u8&h_referer=https://apple.com/&h_origin=https://apple.com&h_user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36&api_password=your_password"
```

### Proxy M3U/M3U_Plus IPTV Streams with Forced Playlist Proxying

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

### HLS Stream with Resolution Selection

```bash
# Select specific resolution (720p)
mpv "http://localhost:8888/proxy/hls/manifest.m3u8?d=https://devstreaming-cdn.apple.com/videos/streaming/examples/img_bipbop_adv_example_fmp4/master.m3u8&resolution=720p&api_password=your_password"

# Select highest resolution
mpv "http://localhost:8888/proxy/hls/manifest.m3u8?d=https://devstreaming-cdn.apple.com/videos/streaming/examples/img_bipbop_adv_example_fmp4/master.m3u8&max_res=true&api_password=your_password"
```

### HLS/DASH Stream with Segment Skipping (Intro/Outro Skip)

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

### Live Stream with Start Offset (Prebuffer Support)

```bash
# Start 18 seconds behind the live edge for HLS (allows prebuffer to work effectively)
mpv "http://localhost:8888/proxy/hls/manifest.m3u8?d=https://example.com/live/playlist.m3u8&start_offset=-18&api_password=your_password"

# For live DASH/MPD streams converted to HLS
mpv "http://localhost:8888/proxy/mpd/manifest.m3u8?d=https://example.com/live/manifest.mpd&start_offset=-18&api_password=your_password"

# For Acestream live streams with start offset
mpv "http://localhost:8888/proxy/acestream/manifest.m3u8?id=your_content_id&start_offset=-18&api_password=your_password"
```

**Note:** The `start_offset` parameter is particularly useful for live streams where the prebuffer system cannot prefetch segments when sitting at the live edge. By starting slightly behind (e.g., `-18` seconds), there are future segments available for prebuffering, resulting in smoother playback. This works for both native HLS and DASH/MPD streams converted to HLS.

### Transcode Stream for Browser Playback

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

### Transcode Performance Benchmarks

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

### Stream with Header Removal (Fix Content-Length Issues)

```bash
# Remove content-length header for streams with incorrect content-length
mpv "http://localhost:8888/proxy/stream?d=https://example.com/video.mp4&x_headers=content-length&api_password=your_password"
```

### Stream with PNG-Wrapped TS Segments (Stream Transformer)

```bash
# Handle streams where TS segments are disguised as PNG files (TurboVidPlay, StreamWish, FileMoon, etc.)
mpv "http://localhost:8888/proxy/hls/manifest.m3u8?d=https://example.com/playlist.m3u8&transformer=ts_stream&x_headers=content-length,content-range&api_password=your_password"

# The transformer strips fake PNG headers and 0xFF padding to extract the actual MPEG-TS data
# Note: When using extractors, the transformer is automatically applied for supported hosts
```

### Live DASH Stream (Non-DRM Protected)

```bash
mpv -v "http://localhost:8888/proxy/mpd/manifest.m3u8?d=https://livesim.dashif.org/livesim/chunkdur_1/ato_7/testpic4_8s/Manifest.mpd&api_password=your_password"
```

### VOD DASH Stream (DRM Protected - Single Key)

```bash
mpv -v "http://localhost:8888/proxy/mpd/manifest.m3u8?d=https://media.axprod.net/TestVectors/v7-MultiDRM-SingleKey/Manifest_1080p_ClearKey.mpd&key_id=nrQFDeRLSAKTLifXUIPiZg&key=FmY0xnWCPCNaSpRG-tUuTQ&api_password=your_password"
```

### VOD DASH Stream (DRM Protected - Multi-Key)

For streams with different keys for video and audio tracks, provide multiple key_id:key pairs separated by commas:

```bash
mpv -v "http://localhost:8888/proxy/mpd/manifest.m3u8?d=https://example.com/multikey.mpd&key_id=video_key_id,audio_key_id&key=video_key,audio_key&api_password=your_password"
```

Note: The `key` and `key_id` parameters are automatically processed if they're not in the correct format. Multi-key support allows decryption of streams where video and audio tracks use different encryption keys.

