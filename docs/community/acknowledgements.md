# Acknowledgements and inspirations


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
