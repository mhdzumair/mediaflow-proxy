from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from mediaflow_proxy.configs import settings


class UIAccessControlMiddleware(BaseHTTPMiddleware):
    """Middleware that controls access to UI components based on settings."""

    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        # Block access to home page
        if settings.disable_home_page and (path == "/" or path == "/index.html"):
            return Response(status_code=403, content="Forbidden")

        # Block access to API docs
        if settings.disable_docs and (path == "/docs" or path == "/redoc" or path.startswith("/openapi")):
            return Response(status_code=403, content="Forbidden")

        # Block access to speedtest UI
        if settings.disable_speedtest and path.startswith("/speedtest"):
            return Response(status_code=403, content="Forbidden")

        return await call_next(request)
