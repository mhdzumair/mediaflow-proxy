# MediaFlow Proxy

![MediaFlow Proxy Logo](https://cdn.githubraw.com/mhdzumair/mediaflow-proxy/main/mediaflow_proxy/static/logo.png){ width="200" style="border-radius: 15px; display: block; margin: 0 auto;" }

MediaFlow Proxy is a flexible server for proxifying media streams: HTTP(S), HLS (M3U8), and MPEG-DASH, including **ClearKey** DRM. It can convert DRM-protected DASH to decrypted HLS in real time.

## Quick start

Run with Docker (set a password):

```bash
docker run -p 8888:8888 -e API_PASSWORD=your_password mhdzumair/mediaflow-proxy
```

Then open the interactive API docs at `http://localhost:8888/docs` (unless disabled with `DISABLE_DOCS`).

For install options (Compose, pip, uv, hosted services), see [Installation](installation.md).

## Where to read next

| Topic | Doc |
|-------|-----|
| Capabilities and DASH/MPD support | [Features](features.md) |
| Environment variables and deployment | [Configuration](configuration/environment.md) |
| Endpoints and usage | [Usage overview](usage/overview.md) |
| Debrid / Stremio integration | [Debrid & Stremio](integrations/debrid-stremio.md) |

## High-throughput alternative ⚡

If you need lower memory usage, higher throughput, or are running on constrained hardware (small VPS, NAS, Raspberry Pi), consider **[MediaFlow Proxy Light](https://github.com/mhdzumair/mediaflow-proxy-light)** — a Rust reimplementation that is API-compatible with this proxy and runs on the same endpoints. Benchmarks show 7–8× less memory, 1.7–3.4× less CPU per request, and up to 4× higher throughput. Existing tokens, encrypted URLs, and client integrations work without changes.

## Project links

- [Source on GitHub](https://github.com/mhdzumair/mediaflow-proxy)
- [Package on PyPI](https://pypi.org/project/mediaflow-proxy/)
