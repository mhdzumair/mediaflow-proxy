from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware

from mediaflow_proxy.configs import settings


class UIAccessControlMiddleware(BaseHTTPMiddleware):
    """Middleware that controls access to UI components based on settings."""

    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        # Block access to home page
        if settings.disable_home_page and (path == "/" or path == "/index.html"):
            raise HTTPException(status_code=404, detail="Not Found")

        # Block access to API docs
        if settings.disable_docs and (path == "/docs" or path == "/redoc" or path.startswith("/openapi")):
            raise HTTPException(status_code=404, detail="Not Found")

        # Block access to speedtest UI
        if settings.disable_speedtest and path.startswith("/speedtest"):
            raise HTTPException(status_code=404, detail="Not Found")

        return await call_next(request)

