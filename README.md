# MediaFlow Proxy

<div style="text-align: center;">
  <img src="https://cdn.githubraw.com/mhdzumair/mediaflow-proxy/main/mediaflow_proxy/static/logo.png" alt="MediaFlow Proxy Logo" width="200" style="border-radius: 15px;">
</div>

MediaFlow Proxy is a streaming proxy for HTTP(S), HLS (M3U8), and MPEG-DASH—including **ClearKey** DRM and real-time DASH-to-HLS conversion. It also supports IPTV (Xtream Codes), Acestream, Telegram media, transcoding, and advanced routing.

**Full documentation:** [mhdzumair.github.io/mediaflow-proxy](https://mhdzumair.github.io/mediaflow-proxy/) (built from the [`docs/`](docs/) folder with [MkDocs](https://www.mkdocs.org/) Material).

## Quick start

```bash
docker run -p 8888:8888 -e API_PASSWORD=your_password mhdzumair/mediaflow-proxy
```

## Highlights

- DASH (ClearKey) to HLS, HLS manipulation, generic HTTP(S) proxy with custom headers  
- Xtream Codes API proxy, Acestream, Telegram (MTProto) streaming  
- Optional GPU transcoding (fMP4 H.264/AAC), pre-buffering, segment skip, stream transformers  
- Redis-backed rate limiting, encrypted URL generation, reverse-proxy–friendly forwarded headers  

## Docs and source

| Resource | Link |
|----------|------|
| User & operator manual | [Documentation site](https://mhdzumair.github.io/mediaflow-proxy/) |
| Markdown sources | [`docs/`](docs/) in this repository |
| Build docs locally | `uv sync --group docs` then `uv run mkdocs serve` |

## Contributing

Contributions are welcome! see [Contributing](docs/community/contributing.md) in the docs and open a Pull Request on [GitHub](https://github.com/mhdzumair/mediaflow-proxy).

## License

[MIT License](LICENSE)

## Disclaimer

This project is for educational purposes only. The developers of MediaFlow Proxy are not responsible for any misuse of this software. Please ensure that you have the necessary permissions to access and use the media streams you are proxying.
