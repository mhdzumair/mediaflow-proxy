import random
from typing import Dict, Tuple, Optional

from mediaflow_proxy.configs import settings
from mediaflow_proxy.speedtest.models import ServerInfo, UserInfo
from mediaflow_proxy.speedtest.providers.base import BaseSpeedTestProvider, SpeedTestProviderConfig
from mediaflow_proxy.utils.http_utils import request_with_retry


class SpeedTestError(Exception):
    pass


class AllDebridSpeedTest(BaseSpeedTestProvider):
    """AllDebrid speed test provider implementation."""

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.servers: Dict[str, ServerInfo] = {}

    async def get_test_urls(self) -> Tuple[Dict[str, str], Optional[UserInfo]]:
        response = await request_with_retry(
            "GET",
            "https://alldebrid.com/internalapi/v4/speedtest",
            headers={"User-Agent": settings.user_agent},
            params={"agent": "service", "version": "1.0-363869a7", "apikey": self.api_key},
        )

        if response.status != 200:
            raise SpeedTestError("Failed to fetch AllDebrid servers")

        data = await response.json()
        if data["status"] != "success":
            raise SpeedTestError("AllDebrid API returned error")

        # Create UserInfo
        user_info = UserInfo(ip=data["data"]["ip"], isp=data["data"]["isp"], country=data["data"]["country"])

        # Store server info
        self.servers = {server["name"]: ServerInfo(**server) for server in data["data"]["servers"]}

        # Generate URLs with random number
        random_number = f"{random.uniform(1, 2):.24f}".replace(".", "")
        urls = {name: f"{server.url}/speedtest/{random_number}" for name, server in self.servers.items()}

        return urls, user_info

    async def get_config(self) -> SpeedTestProviderConfig:
        urls, _ = await self.get_test_urls()
        return SpeedTestProviderConfig(test_duration=10, test_urls=urls)
