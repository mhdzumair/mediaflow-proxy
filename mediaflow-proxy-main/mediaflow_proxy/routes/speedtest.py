from fastapi import APIRouter, HTTPException
from fastapi.responses import RedirectResponse

from mediaflow_proxy.speedtest.models import (
    BrowserSpeedTestConfig,
    BrowserSpeedTestRequest,
)
from mediaflow_proxy.speedtest.service import SpeedTestService

speedtest_router = APIRouter()

# Initialize service
speedtest_service = SpeedTestService()


@speedtest_router.get("/", summary="Show browser speed test interface")
async def show_speedtest_page():
    """Return the browser-based speed test HTML interface."""
    return RedirectResponse(url="/speedtest.html")


@speedtest_router.post("/config", summary="Get browser speed test configuration")
async def get_browser_speedtest_config(
    test_request: BrowserSpeedTestRequest,
) -> BrowserSpeedTestConfig:
    """Get configuration for browser-based speed test."""
    try:
        provider_impl = speedtest_service.get_provider(test_request.provider, test_request.api_key)

        # Get test URLs and user info
        test_urls, user_info = await provider_impl.get_test_urls()
        config = await provider_impl.get_config()

        return BrowserSpeedTestConfig(
            provider=test_request.provider,
            test_urls=test_urls,
            test_duration=config.test_duration,
            user_info=user_info,
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
