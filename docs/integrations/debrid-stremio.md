# Debrid services and Stremio

## Using MediaFlow Proxy with Debrid Services and Stremio Addons

MediaFlow Proxy can be particularly useful when working with Debrid services (like Real-Debrid, AllDebrid) and Stremio addons. The `/proxy/ip` endpoint allows you to retrieve the public IP address of the MediaFlow Proxy server, which is crucial for routing Debrid streams correctly.

When a Stremio addon needs to create a video URL for a Debrid service, it typically needs to provide the user's public IP address. However, when routing the Debrid stream through MediaFlow Proxy, you should use the IP address of the MediaFlow Proxy server instead.

Here's how to utilize MediaFlow Proxy in this scenario:

1. If MediaFlow Proxy is accessible over the internet:
   - Use the `/proxy/ip` endpoint to get the MediaFlow Proxy server's public IP.
   - Use this IP when creating Debrid service URLs in your Stremio addon.

2. If MediaFlow Proxy is set up locally:
   - Stremio addons can directly use the client's IP address.

## Using Stremio Server for M3U8 Content Proxy

MediaFlow Proxy supports routing video segments through Stremio server for better performance while keeping playlists through MediaFlow for access control.

### Configuration

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
