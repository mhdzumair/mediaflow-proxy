from abc import ABC, abstractmethod
from typing import Dict, Tuple, Optional
from pydantic import BaseModel

from mediaflow_proxy.speedtest.models import UserInfo


class SpeedTestProviderConfig(BaseModel):
    test_duration: int = 10  # seconds
    test_urls: Dict[str, str]


class BaseSpeedTestProvider(ABC):
    """Base class for speed test providers."""

    @abstractmethod
    async def get_test_urls(self) -> Tuple[Dict[str, str], Optional[UserInfo]]:
        """Get list of test URLs for the provider and optional user info."""
        pass

    @abstractmethod
    async def get_config(self) -> SpeedTestProviderConfig:
        """Get provider-specific configuration."""
        pass
