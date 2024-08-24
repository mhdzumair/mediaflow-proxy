# MediaFlow Proxy

MediaFlow Proxy is a powerful and flexible solution for proxifying various types of media streams. It supports HTTP(S) links, HLS (M3U8) streams, and MPEG-DASH streams, including DRM-protected content. This proxy can convert MPEG-DASH DRM-protected streams to decrypted HLS live streams in real-time, making it one of the fastest live decrypter servers available.

## Features

- Convert MPEG-DASH streams (DRM-protected and non-protected) to HLS
- Support for Clear Key DRM-protected MPD DASH streams
- Support for non-DRM protected DASH live and VOD streams
- Proxy HTTP/HTTPS links with custom headers
- Proxy and modify HLS (M3U8) streams in real-time with custom headers and key URL modifications for bypassing some sneaky restrictions.
- Retrieve public IP address of the MediaFlow Proxy server for use with Debrid services
- Support for HTTP/HTTPS/SOCKS5 proxy forwarding
- Protect against unauthorized access and network bandwidth abuses

## Installation


### Using Docker from Docker Hub (Recommended)

1. Pull & Run the Docker image:
   ```
   docker run -p 8888:8888 -e API_PASSWORD=your_password mhdzumair/mediaflow-proxy
   ```


### Using Poetry

1. Clone the repository:
   ```
   git clone https://github.com/mhdzumair/mediaflow-proxy.git
   cd mediaflow-proxy
   ```

2. Install dependencies using Poetry:
   ```
   poetry install
   ```

3. Set the `API_PASSWORD` environment variable in `.env`:
   ```
   echo "API_PASSWORD=your_password" > .env
   ```

4. Run the FastAPI server:
   ```
   poetry run uvicorn mediaflow_proxy.main:app --host 0.0.0.0 --port 8888
   ```


### Build and Run Docker Image Locally

1. Build the Docker image:
   ```
   docker build -t mediaflow-proxy .
   ```

2. Run the Docker container:
   ```
   docker run -p 8888:8888 -e API_PASSWORD=your_password mediaflow-proxy
   ```

## Configuration

Set the following environment variables:

- `API_PASSWORD`: Required. Protects against unauthorized access and API network abuses.
- `PROXY_URL`: Optional. HTTP/HTTPS/SOCKS5 proxy URL for forwarding network requests.
- `MPD_LIVE_STREAM_DELAY`: Optional. Delay in seconds for live DASH streams. This is useful to prevent buffering issues with live streams. Default is `30` seconds.

## Usage

### Endpoints

1. `/proxy/hls`: Proxify HLS streams
2. `/proxy/stream`: Proxy generic http video streams
3. `/proxy/mpd/manifest`: Process MPD manifests
4. `/proxy/mpd/playlist`: Generate HLS playlists from MPD
5. `/proxy/mpd/segment`: Process and decrypt media segments
6. `/proxy/ip`: Get the public IP address of the MediaFlow Proxy server

Once the server is running, for more details on the available endpoints and their parameters, visit the Swagger UI at `http://localhost:8888/docs`.

### Examples

#### Proxy HTTPS Stream

```bash
mpv "http://localhost:8888/proxy/stream?d=https://jsoncompare.org/LearningContainer/SampleFiles/Video/MP4/sample-mp4-file.mp4&api_password=your_password"
```

#### Proxy HLS Stream with Headers

```bash
mpv "http://localhost:8888/proxy/hls?d=https://devstreaming-cdn.apple.com/videos/streaming/examples/img_bipbop_adv_example_fmp4/master.m3u8&h_referer=https://apple.com/&h_origin=https://apple.com&h_user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36&api_password=your_password"
```

#### Live DASH Stream (Non-DRM Protected)

```bash
mpv -v "http://localhost:8888/proxy/mpd/manifest?d=https://livesim.dashif.org/livesim/chunkdur_1/ato_7/testpic4_8s/Manifest.mpd&api_password=your_password"
```

#### VOD DASH Stream (DRM Protected)

```bash
mpv -v "http://localhost:8888/proxy/mpd/manifest?d=https://media.axprod.net/TestVectors/v7-MultiDRM-SingleKey/Manifest_1080p_ClearKey.mpd&key_id=nrQFDeRLSAKTLifXUIPiZg&key=FmY0xnWCPCNaSpRG-tUuTQ&api_password=your_password"
```

Note: The `key` and `key_id` parameters are automatically processed if they're not in the correct format.

### URL Encoding

For players like VLC that require properly encoded URLs, use the `encode_mediaflow_proxy_url` function:

```python
from mediaflow_proxy.utils.http_utils import encode_mediaflow_proxy_url

encoded_url = encode_mediaflow_proxy_url(
    "http://127.0.0.1:8888",
    "/proxy/mpd/manifest",
    "https://media.axprod.net/TestVectors/v7-MultiDRM-SingleKey/Manifest_1080p_ClearKey.mpd",
    {
        "key_id": "nrQFDeRLSAKTLifXUIPiZg",
        "key": "FmY0xnWCPCNaSpRG-tUuTQ",
        "api_password": "your_password"
    }
)

print(encoded_url)
```

This will output a properly encoded URL that can be used with players like VLC.

```bash
vlc "http://127.0.0.1:8888/proxy/mpd/manifest?key_id=nrQFDeRLSAKTLifXUIPiZg&key=FmY0xnWCPCNaSpRG-tUuTQ&api_password=dedsec&d=https%3A%2F%2Fmedia.axprod.net%2FTestVectors%2Fv7-MultiDRM-SingleKey%2FManifest_1080p_ClearKey.mpd"
```

### Using MediaFlow Proxy with Debrid Services and Stremio Addons

MediaFlow Proxy can be particularly useful when working with Debrid services (like Real-Debrid, AllDebrid) and Stremio addons. The `/proxy/ip` endpoint allows you to retrieve the public IP address of the MediaFlow Proxy server, which is crucial for routing Debrid streams correctly.

When a Stremio addon needs to create a video URL for a Debrid service, it typically needs to provide the user's public IP address. However, when routing the Debrid stream through MediaFlow Proxy, you should use the IP address of the MediaFlow Proxy server instead.

Here's how to utilize MediaFlow Proxy in this scenario:

1. If MediaFlow Proxy is accessible over the internet:
   - Use the `/proxy/ip` endpoint to get the MediaFlow Proxy server's public IP.
   - Use this IP when creating Debrid service URLs in your Stremio addon.

2. If MediaFlow Proxy is set up locally:
   - Stremio addons can directly use the client's IP address.


## Future Development

- Add support for Widevine and PlayReady decryption

## Acknowledgements and Inspirations

MediaFlow Proxy was developed with inspiration from various projects and resources:

- [Stremio Server](https://github.com/Stremio/stremio-server) for HLS Proxify implementation, which inspired our HLS M3u8 Manifest parsing and redirection proxify support.
- [Comet Debrid proxy](https://github.com/g0ldyy/comet) for the idea of proxifying HTTPS video streams.
- [mp4decrypt](https://www.bento4.com/developers/dash/encryption_and_drm/), [mp4box](https://wiki.gpac.io/xmlformats/Common-Encryption/), and [devine](https://github.com/devine-dl/devine) for insights on parsing MPD and decrypting Clear Key DRM protected content.
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