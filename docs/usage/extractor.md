# Video extractor endpoint

## Video Extractor Endpoint

The extractor endpoint extracts direct video stream URLs from various video hosting services. It supports an optional file extension in the URL for better player compatibility.

### Supported extractors (`host` parameter)

Use these exact strings as the `host` query parameter. The canonical list is defined in [`mediaflow_proxy/extractors/factory.py`](https://github.com/mhdzumair/mediaflow-proxy/blob/main/mediaflow_proxy/extractors/factory.py) (`ExtractorFactory._extractors`).

The matching is **case-insensitive** — `vidfast`, `VidFast`, and `VIDFAST` are all accepted.

| `host` value | Notes |
|---|---|
| `City` | |
| `Doodstream` | |
| `F16Px` | |
| `Fastream` | |
| `FileLions` | |
| `FileMoon` | |
| `Gupload` | |
| `LiveTV` | |
| `LuluStream` | |
| `Maxstream` | |
| `Mixdrop` | |
| `Okru` | ok.ru / odnoklassniki |
| `Sportsonline` | Sportsonline / Sportzonline live streams |
| `Streamtape` | |
| `StreamWish` | |
| `Supervideo` | |
| `TurboVidPlay` | |
| `Uqload` | |
| `Vavoo` | Vavoo.to streams |
| `VidFast` | vidfast.pro (ythd.org → cloudnestra.com chain) |
| `Vidmoly` | |
| `Vidoza` | |
| `VixCloud` | |
| `Voe` | |

### Endpoints

| Endpoint | Description |
|----------|-------------|
| `/extractor/video` | Base endpoint (generic, backward compatible) |
| `/extractor/video.m3u8` | HLS streams - helps ExoPlayer detect HLS |
| `/extractor/video.mp4` | MP4 streams |
| `/extractor/video.mkv` | MKV streams |
| `/extractor/video.ts` | MPEG-TS streams |
| `/extractor/video.webm` | WebM streams |
| `/extractor/video.avi` | AVI streams |

### Why Use Extensions?

Some video players (notably Android's ExoPlayer used in Stremio) determine the media source type from the URL before making any HTTP requests. Without the correct extension:

- ExoPlayer sees `/extractor/video?...` → Uses `ProgressiveMediaSource`
- ExoPlayer sees `/extractor/video.m3u8?...` → Uses `HlsMediaSource` ✓

For HLS streams, using the `.m3u8` extension ensures the player uses the correct HLS playback pipeline.

### Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| `host` | Yes | Extractor host name (e.g., `TurboVidPlay`, `Vidoza`) |
| `d` | Yes | Destination URL (the video page URL to extract) |
| `api_password` | Yes* | API password (*if configured) |
| `redirect_stream` | No | If `true`, returns 302 redirect to the proxied stream URL |

### Example Usage

**Get extraction result as JSON:**
```
GET /extractor/video?host=Vidoza&d=https://videzz.net/example.html&api_password=your_password
```

**Redirect directly to stream (for players):**
```
GET /extractor/video.m3u8?host=TurboVidPlay&d=https://turbovidhls.com/t/abc123&api_password=your_password&redirect_stream=true
```

This redirects to the proxied HLS manifest URL, and because the request URL contains `.m3u8`, players like ExoPlayer will correctly use HLS playback.
