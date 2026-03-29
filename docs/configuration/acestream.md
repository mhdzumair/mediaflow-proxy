# Acestream configuration

## Acestream Configuration

MediaFlow Proxy can act as a proxy for Acestream P2P streams, converting them to HLS or MPEG-TS format that any media player can consume.

**Requirements**: You need a running Acestream engine accessible from MediaFlow Proxy.

- `ENABLE_ACESTREAM`: Optional. Enable Acestream proxy support. Default: `false`.
- `ACESTREAM_HOST`: Optional. Acestream engine host. Default: `localhost`.
- `ACESTREAM_PORT`: Optional. Acestream engine port. Default: `6878`.
- `ACESTREAM_SESSION_TIMEOUT`: Optional. Session timeout (seconds) for cleanup of inactive sessions. Default: `60`.
- `ACESTREAM_KEEPALIVE_INTERVAL`: Optional. Interval (seconds) for session keepalive polling. Default: `15`.

### Acestream Endpoints

| Endpoint | Description |
|----------|-------------|
| `/proxy/acestream/stream` | MPEG-TS stream proxy (recommended) |
| `/proxy/acestream/manifest.m3u8` | HLS manifest proxy |
| `/proxy/acestream/status` | Get session status |

### Acestream URL Parameters

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

### Docker Compose Example with Acestream

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
