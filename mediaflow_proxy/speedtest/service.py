import logging
import time
from datetime import datetime
from typing import Dict, Optional, Type

from cachetools import TTLCache
from httpx import AsyncClient

from mediaflow_proxy.utils.http_utils import Streamer
from .models import SpeedTestTask, LocationResult, SpeedTestResult, SpeedTestProvider
from .providers.all_debrid import AllDebridSpeedTest
from .providers.base import BaseSpeedTestProvider
from .providers.real_debrid import RealDebridSpeedTest
from ..configs import settings

logger = logging.getLogger(__name__)


class SpeedTestService:
    """Service for managing speed tests across different providers."""

    def __init__(self):
        # Cache for speed test results (1 hour TTL)
        self._cache: TTLCache[str, SpeedTestTask] = TTLCache(maxsize=100, ttl=3600)

        # Provider mapping
        self._providers: Dict[SpeedTestProvider, Type[BaseSpeedTestProvider]] = {
            SpeedTestProvider.REAL_DEBRID: RealDebridSpeedTest,
            SpeedTestProvider.ALL_DEBRID: AllDebridSpeedTest,
        }

    def _get_provider(self, provider: SpeedTestProvider, api_key: Optional[str] = None) -> BaseSpeedTestProvider:
        """Get the appropriate provider implementation."""
        provider_class = self._providers.get(provider)
        if not provider_class:
            raise ValueError(f"Unsupported provider: {provider}")

        if provider == SpeedTestProvider.ALL_DEBRID and not api_key:
            raise ValueError("API key required for AllDebrid")

        return provider_class(api_key) if provider == SpeedTestProvider.ALL_DEBRID else provider_class()

    async def create_test(
        self, task_id: str, provider: SpeedTestProvider, api_key: Optional[str] = None
    ) -> SpeedTestTask:
        """Create a new speed test task."""
        provider_impl = self._get_provider(provider, api_key)

        # Get initial URLs and user info
        urls, user_info = await provider_impl.get_test_urls()

        task = SpeedTestTask(task_id=task_id, provider=provider, started_at=datetime.utcnow(), user_info=user_info)

        self._cache[task_id] = task
        return task

    async def get_test_results(self, task_id: str) -> Optional[SpeedTestTask]:
        """Get results for a specific task."""
        return self._cache.get(task_id)

    async def run_speedtest(self, task_id: str, provider: SpeedTestProvider, api_key: Optional[str] = None):
        """Run the speed test with real-time updates."""
        try:
            task = self._cache.get(task_id)
            if not task:
                raise ValueError(f"Task {task_id} not found")

            provider_impl = self._get_provider(provider, api_key)
            config = await provider_impl.get_config()

            async with AsyncClient(follow_redirects=True, timeout=10, proxy=settings.proxy_url) as client:
                streamer = Streamer(client)

                for location, url in config.test_urls.items():
                    try:
                        task.current_location = location
                        result = await self._test_location(location, url, streamer, config.test_duration, provider_impl)
                        task.results[location] = result
                        self._cache[task_id] = task
                    except Exception as e:
                        logger.error(f"Error testing {location}: {str(e)}")
                        task.results[location] = LocationResult(
                            error=str(e), server_name=location, server_url=config.test_urls[location]
                        )
                        self._cache[task_id] = task

            # Mark task as completed
            task.completed_at = datetime.utcnow()
            task.status = "completed"
            task.current_location = None
            self._cache[task_id] = task

        except Exception as e:
            logger.error(f"Error in speed test task {task_id}: {str(e)}")
            if task := self._cache.get(task_id):
                task.status = "failed"
                self._cache[task_id] = task

    async def _test_location(
        self, location: str, url: str, streamer: Streamer, test_duration: int, provider: BaseSpeedTestProvider
    ) -> LocationResult:
        """Test speed for a specific location."""
        try:
            start_time = time.time()
            total_bytes = 0

            async for chunk in streamer.stream_content(url, headers={}):
                if time.time() - start_time >= test_duration:
                    break
                total_bytes += len(chunk)

            duration = time.time() - start_time
            speed_mbps = (total_bytes * 8) / (duration * 1_000_000)

            # Get server info if available (for AllDebrid)
            server_info = getattr(provider, "servers", {}).get(location)
            server_url = server_info.url if server_info else url

            return LocationResult(
                result=SpeedTestResult(
                    speed_mbps=round(speed_mbps, 2), duration=round(duration, 2), data_transferred=total_bytes
                ),
                server_name=location,
                server_url=server_url,
            )

        except Exception as e:
            logger.error(f"Error testing {location}: {str(e)}")
            raise  # Re-raise to be handled by run_speedtest
