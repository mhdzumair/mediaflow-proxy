"""
Integration tests for media URL extractors.

Test URLs are loaded from environment variables for privacy:
- Locally: Add TEST_URL_{EXTRACTOR_NAME} to your .env file
- CI/CD: Configure as GitHub Secrets

If an environment variable is not set, the test for that extractor is skipped.
"""

import os

import aiohttp
import pytest

from mediaflow_proxy.extractors.factory import ExtractorFactory

# All extractors registered in the factory
# The env var name is derived from the extractor name (uppercase)
ALL_EXTRACTORS = [
    "DLHD",
    "Doodstream",
    "Fastream",
    "FileLions",
    "FileMoon",
    "F16Px",
    "LiveTV",
    "LuluStream",
    "Maxstream",
    "Mixdrop",
    "Okru",
    "Sportsonline",
    "Streamtape",
    "StreamWish",
    "Supervideo",
    "TurboVidPlay",
    "Uqload",
    "Vavoo",
    "Vidmoly",
    "Vidoza",
    "VixCloud",
    "Voe",
]

# Valid mediaflow endpoints that extractors can return
VALID_ENDPOINTS = [
    "proxy_stream_endpoint",
    "hls_manifest_proxy",
    "hls_key_proxy",
    "mpd_manifest_proxy",
]

# Extractors with ephemeral/single-use URLs that can't be tested twice
EPHEMERAL_URL_EXTRACTORS = [
    "Vavoo",  # web-vod links are single-use
]


def get_test_url(extractor_name: str) -> str | None:
    """Get test URL from environment variable."""
    env_var = f"TEST_URL_{extractor_name.upper()}"
    return os.environ.get(env_var)


@pytest.mark.asyncio
@pytest.mark.parametrize("extractor_name", ALL_EXTRACTORS)
async def test_extractor(extractor_name: str):
    """
    Test that an extractor can successfully extract a media URL.

    This test:
    1. Loads the test URL from TEST_URL_{EXTRACTOR_NAME} env var
    2. Skips if the env var is not set
    3. Runs the extractor against the URL
    4. Validates the response structure
    """
    test_url = get_test_url(extractor_name)

    if test_url is None:
        pytest.skip(f"TEST_URL_{extractor_name.upper()} not set")

    # Create extractor instance with empty request headers
    extractor = ExtractorFactory.get_extractor(extractor_name, {})

    # Run extraction
    result = await extractor.extract(test_url)

    # Validate response structure
    assert isinstance(result, dict), f"Expected dict, got {type(result)}"

    assert "destination_url" in result, "Response missing 'destination_url'"
    assert result["destination_url"], "destination_url is empty"
    assert isinstance(result["destination_url"], str), "destination_url should be a string"

    assert "request_headers" in result, "Response missing 'request_headers'"
    assert isinstance(result["request_headers"], dict), "request_headers should be a dict"

    assert "mediaflow_endpoint" in result, "Response missing 'mediaflow_endpoint'"
    assert result["mediaflow_endpoint"] in VALID_ENDPOINTS, (
        f"Invalid endpoint: {result['mediaflow_endpoint']}. Expected one of: {VALID_ENDPOINTS}"
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("extractor_name", ALL_EXTRACTORS)
async def test_extractor_url_format(extractor_name: str):
    """
    Test that extracted URLs have valid format.

    This is a secondary validation to catch malformed URLs.
    Note: Skipped for extractors with ephemeral/single-use URLs.
    """
    # Skip for extractors with single-use URLs (already tested in test_extractor)
    if extractor_name in EPHEMERAL_URL_EXTRACTORS:
        pytest.skip(f"{extractor_name} uses ephemeral URLs - already tested in test_extractor")

    test_url = get_test_url(extractor_name)

    if test_url is None:
        pytest.skip(f"TEST_URL_{extractor_name.upper()} not set")

    extractor = ExtractorFactory.get_extractor(extractor_name, {})
    result = await extractor.extract(test_url)

    destination_url = result.get("destination_url", "")

    # URL should start with http:// or https://
    assert destination_url.startswith(("http://", "https://")), (
        f"destination_url should start with http:// or https://, got: {destination_url[:50]}..."
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("extractor_name", ALL_EXTRACTORS)
async def test_extractor_stream_accessible(extractor_name: str):
    """
    Test that the extracted stream URL is actually accessible.

    This test verifies:
    1. The destination URL returns HTTP 200
    2. The content-type is appropriate for media (video, HLS, DASH, etc.)

    Note: This test may be slower as it makes real HTTP requests.
    Skipped for extractors with ephemeral URLs.
    """
    # Skip for extractors with single-use URLs
    if extractor_name in EPHEMERAL_URL_EXTRACTORS:
        pytest.skip(f"{extractor_name} uses ephemeral URLs - stream check skipped")

    test_url = get_test_url(extractor_name)

    if test_url is None:
        pytest.skip(f"TEST_URL_{extractor_name.upper()} not set")

    extractor = ExtractorFactory.get_extractor(extractor_name, {})
    result = await extractor.extract(test_url)

    destination_url = result.get("destination_url", "")
    request_headers = result.get("request_headers", {})

    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(
                destination_url,
                headers=request_headers,
                timeout=aiohttp.ClientTimeout(total=30),
                ssl=False,  # Some extractors disable SSL verification
            ) as response:
                # Check HTTP status
                assert response.status == 200, (
                    f"Stream URL returned HTTP {response.status}, expected 200. URL: {destination_url[:100]}..."
                )

                # Check content type
                content_type = response.headers.get("content-type", "").lower().split(";")[0].strip()

                # Read first bytes to verify it's actual content
                content_preview = await response.content.read(1024)
                assert len(content_preview) > 0, "Stream returned empty content"

                # For HLS streams, verify it looks like an m3u8 manifest
                if content_type in ["application/vnd.apple.mpegurl", "application/x-mpegurl", "text/plain"]:
                    content_text = content_preview.decode("utf-8", errors="ignore")
                    # Check if it's an HLS manifest
                    is_hls = "#EXTM3U" in content_text or "#EXT-X-" in content_text
                    # Or if it's a direct segment (binary data)
                    is_binary = content_preview[:3] == b"\x00\x00\x01" or content_preview[:4] == b"G@\x00"

                    assert is_hls or is_binary or content_type == "application/octet-stream", (
                        f"Content doesn't appear to be valid HLS. "
                        f"Content-Type: {content_type}, Preview: {content_text[:100]}..."
                    )

        except aiohttp.ClientError as e:
            pytest.fail(f"Failed to access stream URL: {e}")
