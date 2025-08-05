from typing import Dict, Optional, Type

from .models import SpeedTestProvider
from .providers.all_debrid import AllDebridSpeedTest
from .providers.base import BaseSpeedTestProvider
from .providers.real_debrid import RealDebridSpeedTest


class SpeedTestService:
    """Service for managing speed test provider configurations."""

    def __init__(self):
        # Provider mapping
        self._providers: Dict[SpeedTestProvider, Type[BaseSpeedTestProvider]] = {
            SpeedTestProvider.REAL_DEBRID: RealDebridSpeedTest,
            SpeedTestProvider.ALL_DEBRID: AllDebridSpeedTest,
        }

    def get_provider(self, provider: SpeedTestProvider, api_key: Optional[str] = None) -> BaseSpeedTestProvider:
        """Get the appropriate provider implementation."""
        provider_class = self._providers.get(provider)
        if not provider_class:
            raise ValueError(f"Unsupported provider: {provider}")

        if provider == SpeedTestProvider.ALL_DEBRID and not api_key:
            raise ValueError("API key required for AllDebrid")

        return provider_class(api_key) if provider == SpeedTestProvider.ALL_DEBRID else provider_class()
