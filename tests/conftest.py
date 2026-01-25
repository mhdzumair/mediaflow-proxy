"""
Pytest configuration for extractor integration tests.

Test URLs are loaded from environment variables for privacy.
Locally, add them to your .env file. For CI/CD, configure GitHub Secrets.
"""

import os
from pathlib import Path

import pytest
from dotenv import load_dotenv

# Load .env file from project root
project_root = Path(__file__).parent.parent
load_dotenv(project_root / ".env")


def pytest_configure(config):
    """Configure pytest-asyncio mode."""
    config.addinivalue_line("markers", "asyncio: mark test as async")


@pytest.fixture
def get_test_url():
    """
    Factory fixture that returns a function to get test URLs from environment.

    Usage:
        def test_something(get_test_url):
            url = get_test_url("Voe")
            if url is None:
                pytest.skip("TEST_URL_VOE not set")
    """

    def _get_url(extractor_name: str) -> str | None:
        env_var = f"TEST_URL_{extractor_name.upper()}"
        return os.environ.get(env_var)

    return _get_url
