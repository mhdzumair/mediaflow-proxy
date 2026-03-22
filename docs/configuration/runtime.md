# Runtime: Docker, Gunicorn, and Redis

## Docker and Gunicorn

The official Docker image runs **Gunicorn** with **Uvicorn workers**. The following environment variables map to Gunicorn’s command-line options (defaults match the previous fixed invocation):

| Variable | Description | Default |
|----------|-------------|---------|
| `PORT` | TCP port when `GUNICORN_BIND` is unset (`0.0.0.0:$PORT`). Also used by the `mediaflow-proxy` CLI and `python -m mediaflow_proxy`. | `8888` |
| `GUNICORN_BIND` | Full `--bind` value (e.g. `0.0.0.0:8889`). If set, overrides the address implied by `PORT`. | *(unset)* |
| `GUNICORN_WORKERS` | Worker count (`-w`). | `4` |
| `WEB_CONCURRENCY` | If set, overrides `GUNICORN_WORKERS` (used by Heroku and similar hosts). | *(unset)* |
| `GUNICORN_WORKER_CLASS` | Worker class (`-k`). | `uvicorn.workers.UvicornWorker` |
| `GUNICORN_TIMEOUT` | Worker timeout in seconds. | `120` |
| `GUNICORN_MAX_REQUESTS` | Restart workers after this many requests. | `500` |
| `GUNICORN_MAX_REQUESTS_JITTER` | Random jitter added to `GUNICORN_MAX_REQUESTS`. | `200` |
| `GUNICORN_ACCESS_LOGFILE` | Access log destination (`-` = stdout). | `-` |
| `GUNICORN_ERROR_LOGFILE` | Error log destination (`-` = stderr). | `-` |
| `GUNICORN_LOG_LEVEL` | Gunicorn log level. | `info` |

**Gluetun:** Gluetun’s built-in HTTP proxy often listens on **8888**, which conflicts with MediaFlow Proxy’s default. Set `PORT` to a free port (for example `8889`) and map that port on the Gluetun service (when using `network_mode: "service:gluetun"`, publish the port on the Gluetun container), or set `GUNICORN_BIND=0.0.0.0:8889` explicitly.

## Redis Configuration (Optional)

Redis enables cross-worker coordination for rate limiting and caching. This is **recommended** when running with multiple workers (`--workers N`) to prevent CDN rate-limiting issues (e.g., Vidoza 509 errors).

- `REDIS_URL`: Optional. Redis connection URL. Default: `None` (disabled). Example: `redis://localhost:6379` or `redis://user:pass@host:6379/0`.

**When to use Redis:**
- Running multiple uvicorn workers (`--workers 4` or more)
- Streaming from rate-limited CDNs like Vidoza
- Need shared caching across workers (extractor results, HEAD responses, segments)

**Features enabled by Redis:**
- **Rate limiting**: Prevents rapid-fire requests that trigger CDN 509 errors
- **HEAD cache**: Serves repeated HEAD probes (e.g., ExoPlayer) without upstream connections
- **Stream gate**: Serializes initial connections to rate-limited URLs
- **Extractor cache**: Shares extraction results across all workers
- **Segment cache**: Shares downloaded segments across workers

**Docker Compose example with Redis:**
```yaml
services:
  redis:
    image: redis:7-alpine
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 5s
      retries: 5

  mediaflow-proxy:
    image: mhdzumair/mediaflow-proxy:latest
    ports:
      - "8888:8888"
    environment:
      - API_PASSWORD=your_password
      - REDIS_URL=redis://redis:6379
    depends_on:
      redis:
        condition: service_healthy
```

**Note**: If Redis is not configured, MediaFlow Proxy works normally but rate limiting features are disabled. This is fine for single-worker deployments or CDNs that don't rate-limit aggressively.
