from fastapi.routing import APIRoute

from mediaflow_proxy.main import app, verify_api_key


def test_playlist_endpoint_requires_api_key_dependency():
    playlist_routes = [
        route
        for route in app.routes
        if isinstance(route, APIRoute) and route.path == "/playlist/playlist" and "GET" in route.methods
    ]

    assert len(playlist_routes) == 1
    assert any(dependency.call is verify_api_key for dependency in playlist_routes[0].dependant.dependencies)
