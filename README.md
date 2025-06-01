# MediaFlow Proxy

<div style="text-align: center;">
  <img src="https://cdn.githubraw.com/mhdzumair/mediaflow-proxy/main/mediaflow_proxy/static/logo.png" alt="MediaFlow Proxy Logo" width="200" style="border-radius: 15px;">
</div>

MediaFlow Proxy is a powerful and flexible solution for proxifying various types of media streams. It supports HTTP(S) links, HLS (M3U8) streams, and MPEG-DASH streams, including DRM-protected content. This proxy can convert MPEG-DASH DRM-protected streams to decrypted HLS live streams in real-time, making it one of the fastest live decrypter servers available.

## Features

### Stream Processing
- Convert MPEG-DASH streams (DRM-protected and non-protected) to HLS
- Support for Clear Key DRM-protected MPD DASH streams
- Support for non-DRM protected DASH live and VOD streams
- Proxy and modify HLS (M3U8) streams in real-time
- Proxy HTTP/HTTPS links with custom headers

### Proxy & Routing
- Advanced proxy routing system with support for:
  - Domain-based routing rules
  - Protocol-specific routing (HTTP/HTTPS)
  - Subdomain and wildcard patterns
  - Port-specific routing
- Support for HTTP/HTTPS/SOCKS5 proxy forwarding
- Flexible SSL verification control per route
- Support for expired or self-signed SSL certificates
- Public IP address retrieval for Debrid services integration

### Security
- API password protection against unauthorized access & Network bandwidth abuse prevention
- Parameter encryption to hide sensitive information
- Optional IP-based access control for encrypted URLs
- URL expiration support for encrypted URLs

### Additional Features
- Built-in speed test for RealDebrid and AllDebrid services
- Custom header injection and modification
- Real-time HLS manifest manipulation
- HLS Key URL modifications for bypassing stream restrictions


## Configuration

Set the following environment variables:

- `API_PASSWORD`: Optional. Protects against unauthorized access and API network abuses.
- `ENABLE_STREAMING_PROGRESS`: Optional. Enable streaming progress logging. Default is `false`.
- `DISABLE_HOME_PAGE`: Optional. Disables the home page UI. Returns 404 for the root path and direct access to index.html. Default is `false`.
- `DISABLE_DOCS`: Optional. Disables the API documentation (Swagger UI). Returns 404 for the /docs path. Default is `false`.
- `DISABLE_SPEEDTEST`: Optional. Disables the speedtest UI. Returns 404 for the /speedtest path and direct access to speedtest.html. Default is `false`.
- `STREMIO_PROXY_URL`: Optional. Stremio server URL for alternative content proxying. Example: `http://127.0.0.1:11470`.
- `M3U8_CONTENT_ROUTING`: Optional. Routing strategy for M3U8 content URLs: `mediaflow` (default), `stremio`, or `direct`.

### Transport Configuration

MediaFlow Proxy now supports advanced transport configuration using HTTPX's routing system. You can configure proxy and SSL verification settings for different domains and protocols.

#### Basic Configuration

Enable proxy for all routes:
```env
PROXY_URL=http://proxy:8080
ALL_PROXY=true
```

#### Advanced Routing Configuration

Configure different proxy settings for specific patterns:
```env
PROXY_URL=http://proxy:8080
TRANSPORT_ROUTES='{
    "https://internal.company.com": {
        "proxy": false
    },
    "all://streaming.service.com": {
        "proxy_url": "socks5://streaming-proxy:1080",
        "verify_ssl": false
    }
}'
```

The routing system supports various patterns:
- Domain routing: `"all://example.com"`
- Subdomain routing: `"all://*.example.com"`
- Protocol-specific routing: `"https://example.com"`
- Port-specific routing: `"all://*:1234"`
- Wildcard routing: `"all://"`

#### Route Configuration Options

Each route can have the following settings:
- `proxy`: Boolean to enable/disable proxy for this route (default: true)
- `proxy_url`: Optional specific proxy URL for this route (overrides primary proxy_url)
- `verify_ssl`: Boolean to control SSL verification (default: true)

#### Configuration Examples

1. Simple proxy setup with SSL bypass for internal domain:
    ```env
    PROXY_URL=http://main-proxy:8080
    TRANSPORT_ROUTES='{
        "https://internal.domain.com": {
            "proxy": false,
            "verify_ssl": false
        }
    }'
    ```

2. Different proxies for different services:
    ```env
    PROXY_URL=http://default-proxy:8080
    TRANSPORT_ROUTES='{
        "all://*.streaming.com": {
            "proxy": true,
            "proxy_url": "socks5://streaming-proxy:1080"
        },
        "all://*.internal.com": {
            "proxy": false
        },
        "https://api.service.com": {
            "proxy": true,
            "verify_ssl": false
        }
    }'
    ```

3. Global proxy with exceptions:
    ```env
    PROXY_URL=http://main-proxy:8080
    ALL_PROXY=true
    TRANSPORT_ROUTES='{
        "all://local.network": {
            "proxy": false
        },
        "all://*.trusted-service.com": {
            "proxy": false
        }
    }'
    ```

### Speed Test Feature

MediaFlow Proxy now includes a built-in speed test feature for testing RealDebrid and AllDebrid network speeds. To access the speed test:

1. Open your browser and navigate to `http://your-server:8888/speedtest.html`
2. The speed test page allows you to:
   - Test download speeds from RealDebrid servers
   - Test download speeds from AllDebrid servers


## Installation

### Option 1: Self-Hosted Deployment

#### Using Docker from Docker Hub

1. Pull & Run the Docker image:
   ```
   docker run -p 8888:8888 -e API_PASSWORD=your_password mhdzumair/mediaflow-proxy
   ```
### Using Docker Compose

1. Set the `API_PASSWORD` and other environment variables in `.env`:

   ```
   echo "API_PASSWORD=your_password" > .env
   ```
2. Bring up the Docker Container:

   ```
   docker compose up --detach
   ```

#### Using pip

> [!IMPORTANT]
> Ensure that you have Python 3.10 or higher installed.

1. Install the package:
   ```
   pip install mediaflow-proxy
   ```

2. Set the `API_PASSWORD` and other environment variables in `.env`:
   ```
   echo "API_PASSWORD=your_password" > .env
   ```

3. Run the MediaFlow Proxy server:
   ```
   mediaflow-proxy
   ```
   You can access the server at `http://localhost:8888`.

4. To run the server with uvicorn options: (Optional)
   ```
   uvicorn mediaflow_proxy.main:app --host 0.0.0.0 --port 8888 --workers 4
   ```


#### Using git & poetry

> [!IMPORTANT]
> Ensure that you have Python 3.10 or higher installed.


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
   poetry run uvicorn mediaflow_proxy.main:app --host 0.0.0.0 --port 8888 --workers 4
   ```


#### Build and Run Docker Image Locally

1. Build the Docker image:
   ```
   docker build -t mediaflow-proxy .
   ```

2. Run the Docker container:
   ```
   docker run -d -p 8888:8888 -e API_PASSWORD=your_password --restart unless-stopped --name mediaflow-proxy mediaflow-proxy
   ```

### Option 2: Premium Hosted Service (ElfHosted)
<div style="text-align: center;">
  <img src="https://store.elfhosted.com/wp-content/uploads/2024/08/mediaflow-proxy.jpg" alt="ElfHosted Logo" width="200" style="border-radius: 15px;">
</div>
For a hassle-free, high-performance deployment of MediaFlow Proxy, consider the premium hosted service through ElfHosted.

To purchase:
1. Visit [https://store.elfhosted.com/product/mediaflow-proxy](https://store.elfhosted.com/product/mediaflow-proxy)
2. Follow ElfHosted's setup instructions

Benefits:
- Instant setup and automatic updates
- High performance and 24/7 availability
- No server maintenance required

Ideal for users who want a reliable, plug-and-play solution without the technical overhead of self-hosting.

### Option 3: Hugging Face Space Deployment (Guide from a MediaFlow Contributor)
1. Go to this repo and create a fork: https://github.com/UrloMythus/UnHided
2. Sign up or log in to Hugging Face: https://huggingface.co/
3. Create a new space with a random name: https://huggingface.co/new-space. Choose Docker as SDK and blank template and public visibility.
4. Go to the "Settings" tab and create a new secret with the name `API_PASSWORD` and set the value to your desired password.
5. Go to the "Files" tab and create a new file with the name `Dockerfile` and paste the following content. After that, replace `YourUsername/YourRepoName` in the Dockerfile with your username and the name of your fork. Finally, click on "Commit" to save the changes. Remember, your space might get banned if instead of using your fork, you use the main repo.
    ```dockerfile
    FROM python:3.10-slim-buster

    WORKDIR /app

    RUN apt-get update && apt-get install -y git

    RUN git clone https://github.com/YourUsername/YourRepoName.git .

    RUN pip install --no-cache-dir -r requirements.txt

    EXPOSE 7860
    CMD ["uvicorn", "run:main_app", "--host", "0.0.0.0", "--port", "7860", "--workers", "4"]
    ```
6. Wait until the space gets built and deployed.
7. If the space is deployed successfully, you can click on the three dots in the top right corner and click on "Embed this space" and copy the "Direct URL".
8. To update your proxy to the newest release, go to your GitHub fork and click on Sync. After that, hop on your Hugging Face Space -> Settings and click on Factory Rebuild.
9. Use the above URL and API password on support addons like MediaFusion, MammaMia, Jackettio, etc.

## Usage

### Endpoints

1. `/proxy/hls/manifest.m3u8`: Proxify HLS streams
2. `/proxy/stream`: Proxy generic http video streams
3. `/proxy/mpd/manifest.m3u8`: Process MPD manifests
4. `/proxy/mpd/playlist.m3u8`: Generate HLS playlists from MPD
5. `/proxy/mpd/segment.mp4`: Process and decrypt media segments
6. `/proxy/ip`: Get the public IP address of the MediaFlow Proxy server

Once the server is running, for more details on the available endpoints and their parameters, visit the Swagger UI at `http://localhost:8888/docs`.

### Examples

#### Proxy HTTPS Stream

```bash
mpv "http://localhost:8888/proxy/stream?d=https://jsoncompare.org/LearningContainer/SampleFiles/Video/MP4/sample-mp4-file.mp4&api_password=your_password"
```

#### Proxy HTTPS self-signed certificate Stream

To bypass SSL verification for a self-signed certificate stream, export the proxy route configuration:
```bash
PROXY_ROUTES='{"https://self-signed.badssl.com": {"proxy_url": null, "verify_ssl": false}}'
```

```bash
mpv "http://localhost:8888/proxy/stream?d=https://self-signed.badssl.com/&api_password=your_password"
```


#### Proxy HLS Stream with Headers

```bash
mpv "http://localhost:8888/proxy/hls/manifest.m3u8?d=https://devstreaming-cdn.apple.com/videos/streaming/examples/img_bipbop_adv_example_fmp4/master.m3u8&h_referer=https://apple.com/&h_origin=https://apple.com&h_user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36&api_password=your_password"
```

#### Live DASH Stream (Non-DRM Protected)

```bash
mpv -v "http://localhost:8888/proxy/mpd/manifest.m3u8?d=https://livesim.dashif.org/livesim/chunkdur_1/ato_7/testpic4_8s/Manifest.mpd&api_password=your_password"
```

#### VOD DASH Stream (DRM Protected)

```bash
mpv -v "http://localhost:8888/proxy/mpd/manifest.m3u8?d=https://media.axprod.net/TestVectors/v7-MultiDRM-SingleKey/Manifest_1080p_ClearKey.mpd&key_id=nrQFDeRLSAKTLifXUIPiZg&key=FmY0xnWCPCNaSpRG-tUuTQ&api_password=your_password"
```

Note: The `key` and `key_id` parameters are automatically processed if they're not in the correct format.

### URL Encoding

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

### Generating URLs

MediaFlow Proxy provides endpoints to generate properly encoded or encrypted URLs for use with media players.
- `/generate_url`: Generate a single encoded or encrypted URL
- `/generate_urls`: Generate multiple URLs with shared common parameters


#### Single URL Generation

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
> - The legacy endpoint `/generate_encrypted_or_encoded_url` is still available but deprecated. It's recommended to use `/generate_url` instead.

#### Multiple URLs Generation

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

#### Filename Preservation for Media Players

MediaFlow Proxy now supports preserving filenames in URLs, which is particularly useful for media players like Infuse that use the filename to fetch metadata. When you include a `filename` parameter in your request, the proxy will ensure this information is preserved and properly passed to the media player.

This feature helps media players display the correct title and fetch appropriate metadata instead of showing generic names like "Stream".

### Using MediaFlow Proxy with Debrid Services and Stremio Addons

MediaFlow Proxy can be particularly useful when working with Debrid services (like Real-Debrid, AllDebrid) and Stremio addons. The `/proxy/ip` endpoint allows you to retrieve the public IP address of the MediaFlow Proxy server, which is crucial for routing Debrid streams correctly.

When a Stremio addon needs to create a video URL for a Debrid service, it typically needs to provide the user's public IP address. However, when routing the Debrid stream through MediaFlow Proxy, you should use the IP address of the MediaFlow Proxy server instead.

Here's how to utilize MediaFlow Proxy in this scenario:

1. If MediaFlow Proxy is accessible over the internet:
   - Use the `/proxy/ip` endpoint to get the MediaFlow Proxy server's public IP.
   - Use this IP when creating Debrid service URLs in your Stremio addon.

2. If MediaFlow Proxy is set up locally:
   - Stremio addons can directly use the client's IP address.

### Using Stremio Server for M3U8 Content Proxy

MediaFlow Proxy supports routing video segments through Stremio server for better performance while keeping playlists through MediaFlow for access control.

#### Configuration

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
