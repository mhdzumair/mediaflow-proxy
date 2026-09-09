"""Public-IP lookups must follow the same HTTP transport as proxied requests."""

import asyncio
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, Mock

import aiohttp
import pytest
from fastapi import HTTPException
from fastapi.routing import APIRoute
from tenacity import wait_none

from mediaflow_proxy import handlers
from mediaflow_proxy.configs import RouteConfig, TransportConfig, settings
from mediaflow_proxy.main import app, verify_api_key
from mediaflow_proxy.routes import proxy
from mediaflow_proxy.utils import http_client, http_utils
from mediaflow_proxy.utils.http_utils import DownloadError, ProxyRequestHeaders


PROXY_URL = "http://proxy.test:8080"
PUBLIC_IP = "203.0.113.10"


@pytest.fixture(autouse=True)
def isolated_settings(monkeypatch):
    monkeypatch.setattr(settings, "public_ip", None)
    monkeypatch.setattr(
        settings,
        "transport_config",
        TransportConfig(_env_file=None, proxy_url=PROXY_URL, all_proxy=False, transport_routes={}),
    )
    monkeypatch.setattr(http_client, "_global_routing_config", None)
    monkeypatch.setattr(http_client, "_routing_initialized", False)
    # A regression to a bare ClientSession must fail without accessing the network.
    monkeypatch.setattr(
        aiohttp.ClientSession, "_request", AsyncMock(side_effect=AssertionError("Unexpected network IO"))
    )


@pytest.fixture
def transport_request(monkeypatch):
    response = SimpleNamespace(
        text=AsyncMock(return_value=json.dumps({"ip": PUBLIC_IP})),
        read=AsyncMock(return_value=b""),
        raise_for_status=Mock(),
    )
    request = AsyncMock(return_value=response)

    def session_factory(**kwargs):
        async def close():
            await kwargs["connector"].close()

        return SimpleNamespace(request=request, close=close)

    # Keep the real routing and retry code; replace only the network session.
    monkeypatch.setattr(http_client, "ClientSession", session_factory)
    monkeypatch.setattr(http_utils.fetch_with_retry.retry, "wait", wait_none())
    return request


@pytest.mark.parametrize("all_proxy", [False, True])
async def test_public_ip_uses_configured_transport(all_proxy, transport_request):
    settings.transport_config.all_proxy = all_proxy

    assert await proxy.get_public_ip_endpoint() == {"ip": PUBLIC_IP}

    transport_request.assert_awaited_once()
    assert transport_request.call_args.args[:2] == ("GET", handlers.IP_LOOKUP_SERVICES[0]["url"])
    assert transport_request.call_args.kwargs["proxy"] == (PROXY_URL if all_proxy else None)


async def test_public_ip_honors_lookup_service_route(transport_request):
    settings.transport_config.transport_routes = {"all://api.ipify.org": RouteConfig(proxy=True)}

    assert await proxy.get_public_ip_endpoint() == {"ip": PUBLIC_IP}
    assert transport_request.call_args.kwargs["proxy"] == PROXY_URL


@pytest.mark.parametrize("address", [PUBLIC_IP, "2001:db8::10"])
async def test_explicit_public_ip_skips_detection(monkeypatch, address):
    lookup = AsyncMock()
    monkeypatch.setattr(settings, "public_ip", address)
    monkeypatch.setattr(proxy, "get_public_ip", lookup)

    assert await proxy.get_public_ip_endpoint() == {"ip": address}
    lookup.assert_not_awaited()


async def test_public_ip_is_refreshed_after_egress_changes(monkeypatch):
    lookup = AsyncMock(side_effect=[{"ip": PUBLIC_IP}, {"ip": "203.0.113.11"}])
    monkeypatch.setattr(proxy, "get_public_ip", lookup)

    assert await proxy.get_public_ip_endpoint() == {"ip": PUBLIC_IP}
    assert await proxy.get_public_ip_endpoint() == {"ip": "203.0.113.11"}
    assert lookup.await_count == 2


async def test_lookup_failure_returns_503_without_direct_fallback(transport_request):
    settings.transport_config.all_proxy = True
    transport_request.side_effect = aiohttp.ClientConnectionError("Proxy unavailable")

    with pytest.raises(HTTPException) as error:
        await proxy.get_public_ip_endpoint()

    assert error.value.status_code == 503
    assert {call.args[1] for call in transport_request.call_args_list} == {
        service["url"] for service in handlers.IP_LOOKUP_SERVICES
    }
    assert all(call.kwargs["proxy"] == PROXY_URL for call in transport_request.call_args_list)


@pytest.mark.parametrize("error", [RuntimeError("Unexpected error"), asyncio.CancelledError()])
async def test_resolver_does_not_hide_unexpected_errors(monkeypatch, error):
    monkeypatch.setattr(proxy, "get_public_ip", AsyncMock(side_effect=error))

    with pytest.raises(type(error)):
        await proxy._resolve_public_ip()


def test_public_ip_has_one_authenticated_route():
    routes = [
        route
        for route in app.routes
        if isinstance(route, APIRoute) and route.path == "/proxy/ip" and "GET" in route.methods
    ]
    assert len(routes) == 1
    assert any(dependency.call is verify_api_key for dependency in routes[0].dependant.dependencies)


@pytest.mark.parametrize("lookup_fails", [False, True])
async def test_forward_placeholder_uses_shared_resolver(monkeypatch, lookup_fails):
    lookup = AsyncMock(return_value={"ip": PUBLIC_IP})
    if lookup_fails:
        lookup.side_effect = DownloadError(503, "IP lookup unavailable")
    monkeypatch.setattr(proxy, "get_public_ip", lookup)
    request = SimpleNamespace(method="POST", body=AsyncMock(return_value=b"ip={mediaflow_ip}"))
    response = SimpleNamespace(content=SimpleNamespace(read=AsyncMock(return_value=b"ok")), headers={}, status=200)
    session = MagicMock()
    session.request.return_value.__aenter__.return_value = response
    factory = MagicMock()
    factory.return_value.__aenter__.return_value = (session, PROXY_URL)
    monkeypatch.setattr(proxy, "create_aiohttp_session", factory)
    # Only exercise placeholder substitution, not external DNS or destination validation.
    monkeypatch.setattr(proxy, "_check_forward_destination", AsyncMock())

    await proxy.proxy_forward_endpoint(
        request,
        ProxyRequestHeaders(request={}, response={}, remove=[], propagate={}),
        "https://destination.test/?ip={mediaflow_ip}",
    )

    lookup.assert_awaited_once()
    # Preserve the existing forwarding behavior when the lookup fails.
    expected = "{mediaflow_ip}" if lookup_fails else PUBLIC_IP
    assert session.request.call_args.kwargs["url"] == f"https://destination.test/?ip={expected}"
    assert session.request.call_args.kwargs["data"] == f"ip={expected}".encode()
