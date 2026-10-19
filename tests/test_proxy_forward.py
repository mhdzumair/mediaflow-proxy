"""
Tests for /proxy/forward response handling.

aiohttp decompresses gzip bodies automatically, but the endpoint copied the
upstream Content-Encoding and Content-Length headers onto the decompressed
body. The server then aborted the reply ("Too much data for declared
Content-Length"), so gzip-encoded APIs (e.g. TorBox) came back as HTTP 200
with an empty body.
"""

import gzip
import json

import pytest
from aiohttp import web
from starlette.requests import Request

from mediaflow_proxy.routes import proxy as proxy_module
from mediaflow_proxy.utils.http_utils import ProxyRequestHeaders

PAYLOAD = {"success": True, "data": [{"id": i, "name": f"item-{i}"} for i in range(2000)]}


async def _chunked_gzip_handler(request: web.Request) -> web.StreamResponse:
    body = gzip.compress(json.dumps(PAYLOAD).encode())
    resp = web.StreamResponse(
        headers={"Content-Type": "application/json", "Content-Encoding": "gzip", "Content-Length": str(len(body))}
    )
    await resp.prepare(request)
    for i in range(0, len(body), 512):
        await resp.write(body[i : i + 512])
    await resp.write_eof()
    return resp


async def _unknown_encoding_handler(request: web.Request) -> web.Response:
    # aiohttp does not decode this encoding, so the bytes must pass through labelled.
    return web.Response(body=b"opaque-encoded-bytes", headers={"Content-Encoding": "x-custom"})


@pytest.fixture
async def upstream_url(monkeypatch):
    app = web.Application()
    app.router.add_get("/data", _chunked_gzip_handler)
    app.router.add_get("/custom", _unknown_encoding_handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]

    # The SSRF guard rightly blocks 127.0.0.1; this test only covers body handling.
    async def _allow(destination):
        return None

    monkeypatch.setattr(proxy_module, "_check_forward_destination", _allow)
    yield f"http://127.0.0.1:{port}/data"
    await runner.cleanup()


def _make_request() -> Request:
    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    scope = {"type": "http", "method": "GET", "headers": [], "query_string": b"", "path": "/proxy/forward"}
    return Request(scope, receive)


async def test_forward_returns_full_decompressed_gzip_body(upstream_url):
    headers = ProxyRequestHeaders(request={}, response={}, remove=[], propagate={})

    response = await proxy_module.proxy_forward_endpoint(_make_request(), headers, destination=upstream_url)

    assert response.status_code == 200
    assert json.loads(response.body) == PAYLOAD
    # The body is already decompressed, so it must not be labelled as gzip.
    assert "content-encoding" not in {k.lower() for k in response.headers.keys()}
    assert int(response.headers["content-length"]) == len(response.body)


async def test_forward_keeps_encoding_header_aiohttp_does_not_decode(upstream_url):
    headers = ProxyRequestHeaders(request={}, response={}, remove=[], propagate={})
    destination = upstream_url.replace("/data", "/custom")

    response = await proxy_module.proxy_forward_endpoint(_make_request(), headers, destination=destination)

    assert response.body == b"opaque-encoded-bytes"
    assert response.headers["content-encoding"] == "x-custom"
    assert int(response.headers["content-length"]) == len(response.body)
