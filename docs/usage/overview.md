# Usage: overview and endpoints


## Endpoints

1. `/proxy/hls/manifest.m3u8`: Proxify HLS streams
2. `/proxy/stream`: Proxy generic http video streams
3. `/proxy/mpd/manifest.m3u8`: Process MPD manifests
4. `/proxy/mpd/playlist.m3u8`: Generate HLS playlists from MPD
5. `/proxy/mpd/segment.mp4`: Process and decrypt media segments
6. `/proxy/ip`: Get the public IP address of the MediaFlow Proxy server
7. `/extractor/video`: Extract direct video stream URLs from supported hosts (see [Video extractor](extractor.md))
8. `/playlist/builder`: Build and customize playlists from multiple sources
9. `/proxy/epg`: Proxy and cache XMLTV/EPG data (see [EPG Proxy](#epg-proxy) below)
10. `/proxy/transcode/playlist.m3u8`: Generate HLS VOD playlist for generic stream transcode
11. `/proxy/transcode/init.mp4`: fMP4 init segment for generic transcode playlist
12. `/proxy/transcode/segment.m4s`: fMP4 media segment for generic transcode playlist
13. `/proxy/telegram/transcode/playlist.m3u8`: Generate HLS VOD playlist for Telegram transcode
14. `/proxy/telegram/transcode/init.mp4`: fMP4 init segment for Telegram transcode playlist
15. `/proxy/telegram/transcode/segment.m4s`: fMP4 media segment for Telegram transcode playlist

## EPG Proxy

`GET /proxy/epg` — fetch, cache, and serve XMLTV/EPG schedule data from any upstream source.

Designed for **Channels DVR**, Plex, Emby, Jellyfin, TiviMate, and any other XMLTV-compatible client.

> **EPG vs DVR**: EPG (Electronic Program Guide) is the XMLTV XML file that contains TV schedule data. A DVR application like Channels DVR *reads* EPG data to populate its TV guide and schedule recordings. This proxy sits between the DVR/player and the upstream EPG source.

### Parameters

| Parameter | Required | Description |
|---|---|---|
| `d` | Yes | Upstream XMLTV/EPG URL. Plain URLs and base64-encoded URLs are both accepted. |
| `api_password` | Yes* | API password (*if configured) |
| `cache_ttl` | No | Cache lifetime in seconds. `0` disables caching. Default: `3600` (1 hour, configurable via `EPG_CACHE_TTL`). |
| `h_<Name>` | No | Custom upstream request headers. E.g. `h_Authorization=Bearer token` for protected EPG sources. |

### Example

```
GET /proxy/epg?d=http://provider.com/xmltv.php?username=x%26password=y&api_password=secret
```

With a base64-encoded source URL (recommended when the EPG URL contains credentials):

```
GET /proxy/epg?d=aHR0cDovL3Byb3ZpZGVyLmNvbS94bWx0di5waHA_dXNlcm5hbWU9eCZwYXNzd29yZD15&api_password=secret
```

### Channels DVR setup

1. Open Channels DVR → **Sources** → **Add Source** → **Custom Channels**
2. In the EPG/Guide Data section, paste your `/proxy/epg?d=...` URL as the **XMLTV URL**
3. Save and trigger a guide refresh

### Response headers

| Header | Value |
|---|---|
| `Content-Type` | `application/xml; charset=utf-8` |
| `X-EPG-Cache` | `HIT` or `MISS` |
| `Cache-Control` | `public, max-age=<ttl>` |

Once the server is running, for more details on the available endpoints and their parameters, visit the Swagger UI at `http://localhost:8888/docs`.
