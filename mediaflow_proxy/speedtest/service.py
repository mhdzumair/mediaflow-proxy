import logging
import time
from datetime import datetime, timezone
from typing import Dict, Optional, Type

from mediaflow_proxy.utils.cache_utils import get_cached_speedtest, set_cache_speedtest
from mediaflow_proxy.utils.http_utils import Streamer, create_httpx_client
from .models import SpeedTestTask, LocationResult, SpeedTestResult, SpeedTestProvider
from .providers.all_debrid import AllDebridSpeedTest
from .providers.base import BaseSpeedTestProvider
from .providers.real_debrid import RealDebridSpeedTest

logger = logging.getLogger(__name__)


class SpeedTestService:
    """Service for managing speed tests across different providers."""

    def __init__(self):
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

        task = SpeedTestTask(
            task_id=task_id, provider=provider, started_at=datetime.now(tz=timezone.utc), user_info=user_info
        )

        await set_cache_speedtest(task_id, task)
        return task

    @staticmethod
    async def get_test_results(task_id: str) -> Optional[SpeedTestTask]:
        """Get results for a specific task."""
        return await get_cached_speedtest(task_id)

    async def run_speedtest(self, task_id: str, provider: SpeedTestProvider, api_key: Optional[str] = None):
        """Run the speed test with real-time updates."""
        try:
            task = await get_cached_speedtest(task_id)
            if not task:
                raise ValueError(f"Task {task_id} not found")

            provider_impl = self._get_provider(provider, api_key)
            config = await provider_impl.get_config()

            async with create_httpx_client() as client:
                streamer = Streamer(client)

                for location, url in config.test_urls.items():
                    try:
                        task.current_location = location
                        await set_cache_speedtest(task_id, task)
                        result = await self._test_location(location, url, streamer, config.test_duration, provider_impl)
                        task.results[location] = result
                        await set_cache_speedtest(task_id, task)
                    except Exception as e:
                        logger.error(f"Error testing {location}: {str(e)}")
                        task.results[location] = LocationResult(
                            error=str(e), server_name=location, server_url=config.test_urls[location]
                        )
                        await set_cache_speedtest(task_id, task)

            # Mark task as completed
            task.completed_at = datetime.now(tz=timezone.utc)
            task.status = "completed"
            task.current_location = None
            await set_cache_speedtest(task_id, task)

        except Exception as e:
            logger.error(f"Error in speed test task {task_id}: {str(e)}")
            if task := await get_cached_speedtest(task_id):
                task.status = "failed"
                await set_cache_speedtest(task_id, task)

    async def _test_location(
        self, location: str, url: str, streamer: Streamer, test_duration: int, provider: BaseSpeedTestProvider
    ) -> LocationResult:
        """Test speed for a specific location."""
        try:
            start_time = time.time()
            total_bytes = 0

            await streamer.create_streaming_response(url, headers={})

            async for chunk in streamer.stream_content():
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
