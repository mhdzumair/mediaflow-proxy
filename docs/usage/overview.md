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
9. `/proxy/transcode/playlist.m3u8`: Generate HLS VOD playlist for generic stream transcode
10. `/proxy/transcode/init.mp4`: fMP4 init segment for generic transcode playlist
11. `/proxy/transcode/segment.m4s`: fMP4 media segment for generic transcode playlist
12. `/proxy/telegram/transcode/playlist.m3u8`: Generate HLS VOD playlist for Telegram transcode
13. `/proxy/telegram/transcode/init.mp4`: fMP4 init segment for Telegram transcode playlist
14. `/proxy/telegram/transcode/segment.m4s`: fMP4 media segment for Telegram transcode playlist

Once the server is running, for more details on the available endpoints and their parameters, visit the Swagger UI at `http://localhost:8888/docs`.
