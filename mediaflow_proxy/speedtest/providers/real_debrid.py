from typing import Dict, Tuple, Optional
import random

from mediaflow_proxy.speedtest.models import UserInfo
from mediaflow_proxy.speedtest.providers.base import BaseSpeedTestProvider, SpeedTestProviderConfig


class RealDebridSpeedTest(BaseSpeedTestProvider):
    """RealDebrid speed test provider implementation."""

    async def get_test_urls(self) -> Tuple[Dict[str, str], Optional[UserInfo]]:
        urls = {
            "AMS": "https://45.download.real-debrid.com/speedtest/testDefault.rar/",
            "RBX": "https://rbx.download.real-debrid.com/speedtest/test.rar/",
            "LON1": "https://lon1.download.real-debrid.com/speedtest/test.rar/",
            "HKG1": "https://hkg1.download.real-debrid.com/speedtest/test.rar/",
            "SGP1": "https://sgp1.download.real-debrid.com/speedtest/test.rar/",
            "SGPO1": "https://sgpo1.download.real-debrid.com/speedtest/test.rar/",
            "TYO1": "https://tyo1.download.real-debrid.com/speedtest/test.rar/",
            "LAX1": "https://lax1.download.real-debrid.com/speedtest/test.rar/",
            "TLV1": "https://tlv1.download.real-debrid.com/speedtest/test.rar/",
            "MUM1": "https://mum1.download.real-debrid.com/speedtest/test.rar/",
            "JKT1": "https://jkt1.download.real-debrid.com/speedtest/test.rar/",
            "Cloudflare": "https://45.download.real-debrid.cloud/speedtest/testCloudflare.rar/",
        }
        # Add random number to prevent caching
        urls = {location: f"{base_url}{random.uniform(0, 1):.16f}" for location, base_url in urls.items()}
        return urls, None

    async def get_config(self) -> SpeedTestProviderConfig:
        urls, _ = await self.get_test_urls()
        return SpeedTestProviderConfig(test_duration=10, test_urls=urls)
