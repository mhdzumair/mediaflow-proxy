from contextlib import asynccontextmanager

import pytest

from mediaflow_proxy.utils import cache_utils, http_utils, mpd_utils


class FakeResponse:
    """Minimal stand-in for an aiohttp response, exposing only `.url` and `.read()`."""

    def __init__(self, content: bytes, url: str):
        """Store the body and the (possibly redirected) final URL."""
        self._content = content
        self.url = url

    async def read(self) -> bytes:
        """Return the canned response body."""
        return self._content


@pytest.mark.asyncio
async def test_download_file_with_retry_returns_final_redirected_url(monkeypatch):
    """With return_url=True, the final (redirected) URL is returned alongside the content."""
    original_url = "https://tv.example.com/proxy/vtmgo/resolve/abc.mpd"
    final_url = "https://live-video.dpgmedia.net/v1/dash/xyz/index.mpd?aws.sessionId=abc"

    @asynccontextmanager
    async def fake_session(*args, **kwargs):
        """Fake replacement for create_aiohttp_session."""
        yield object(), None

    async def fake_fetch_with_retry(session, method, url, headers, proxy=None, **kwargs):
        """Fake replacement for fetch_with_retry that simulates a redirect."""
        assert url == original_url
        return FakeResponse(b"<MPD/>", final_url)

    monkeypatch.setattr(http_utils, "create_aiohttp_session", fake_session)
    monkeypatch.setattr(http_utils, "fetch_with_retry", fake_fetch_with_retry)

    content, resolved_url = await http_utils.download_file_with_retry(original_url, {}, return_url=True)

    assert content == b"<MPD/>"
    assert resolved_url == final_url


@pytest.mark.asyncio
async def test_download_file_with_retry_without_return_url_flag_returns_bytes_only(monkeypatch):
    """Without return_url, the call keeps its original bytes-only return type."""

    @asynccontextmanager
    async def fake_session(*args, **kwargs):
        """Fake replacement for create_aiohttp_session."""
        yield object(), None

    async def fake_fetch_with_retry(session, method, url, headers, proxy=None, **kwargs):
        """Fake replacement for fetch_with_retry."""
        return FakeResponse(b"data", "https://redirected.example.com/index.mpd")

    monkeypatch.setattr(http_utils, "create_aiohttp_session", fake_session)
    monkeypatch.setattr(http_utils, "fetch_with_retry", fake_fetch_with_retry)

    result = await http_utils.download_file_with_retry("https://example.com/x.mpd", {})

    assert result == b"data"


@pytest.mark.asyncio
async def test_get_cached_mpd_parses_against_redirected_url_on_cache_miss(monkeypatch):
    """On a cache miss, the manifest is parsed against the redirected download URL."""
    original_url = "https://tv.example.com/proxy/vtmgo/resolve/abc.mpd"
    redirected_url = "https://live-video.dpgmedia.net/v1/dash/xyz/index.mpd?aws.sessionId=abc"

    async def fake_redis_get_cached_mpd(key):
        """Simulate a cache miss."""
        return None

    async def fake_redis_set_cached_mpd(key, data, ttl=None):
        """Replacement for the cache write that records the payload for inspection."""
        captured["set_cached_mpd_data"] = data

    async def fake_download_file_with_retry(url, headers, return_url=False, **kwargs):
        """Simulate a download that got redirected to a different URL."""
        assert url == original_url
        assert return_url is True
        return b"<MPD/>", redirected_url

    def fake_parse_mpd(content):
        """Fake replacement for parse_mpd."""
        return {"MPD": {}}

    captured = {}

    def fake_parse_mpd_dict(mpd_dict, mpd_url, parse_drm, parse_segment_profile_id=None):
        """Fake replacement for parse_mpd_dict that records the URL it was called with."""
        captured["mpd_url"] = mpd_url
        return {"profiles": [], "drmInfo": {}}

    monkeypatch.setattr(cache_utils.redis_utils, "get_cached_mpd", fake_redis_get_cached_mpd)
    monkeypatch.setattr(cache_utils.redis_utils, "set_cached_mpd", fake_redis_set_cached_mpd)
    monkeypatch.setattr(cache_utils, "download_file_with_retry", fake_download_file_with_retry)
    monkeypatch.setattr(cache_utils, "parse_mpd", fake_parse_mpd)
    monkeypatch.setattr(cache_utils, "parse_mpd_dict", fake_parse_mpd_dict)

    await cache_utils.get_cached_mpd(original_url, headers={}, parse_drm=True)

    assert captured["mpd_url"] == redirected_url
    assert captured["set_cached_mpd_data"]["resolved_url"] == redirected_url


def test_resolve_url_resolves_relative_path_against_redirected_base():
    """A relative path resolves against the base URL's directory."""
    base_url = "https://live-video.dpgmedia.net/v1/dash/xyz/index.mpd"

    resolved = mpd_utils.resolve_url(base_url, "chunk-stream0-00001.m4s")

    assert resolved == "https://live-video.dpgmedia.net/v1/dash/xyz/chunk-stream0-00001.m4s"


def test_resolve_url_resolves_absolute_path_against_redirected_origin():
    """An absolute path resolves against the base URL's origin (scheme + host)."""
    base_url = "https://live-video.dpgmedia.net/v1/dash/xyz/index.mpd"

    resolved = mpd_utils.resolve_url(base_url, "/v1/dash/xyz/chunk-stream0-00001.m4s")

    assert resolved == "https://live-video.dpgmedia.net/v1/dash/xyz/chunk-stream0-00001.m4s"


def test_resolve_url_leaves_absolute_urls_untouched():
    """An already-absolute URL is returned unchanged, ignoring the base URL."""
    base_url = "https://live-video.dpgmedia.net/v1/dash/xyz/index.mpd"

    resolved = mpd_utils.resolve_url(base_url, "https://cdn.other.example.com/seg.m4s")

    assert resolved == "https://cdn.other.example.com/seg.m4s"


def test_extract_drm_info_resolves_relative_la_url_against_redirected_base():
    """A relative ClearKey license URL must resolve against the redirect
    target too, the same as segment/init URLs."""
    mpd_url = "https://live-video.dpgmedia.net/v1/dash/xyz/index.mpd"
    periods = [
        {
            "AdaptationSet": {
                "ContentProtection": {
                    "@schemeIdUri": "urn:uuid:e2719d58-a985-b3c9-781a-b030af78d30e-clearkey",
                    "clearkey:Laurl": {"#text": "license/acquire"},
                }
            }
        }
    ]

    drm_info = mpd_utils.extract_drm_info(periods, mpd_url)

    assert drm_info["laUrl"] == "https://live-video.dpgmedia.net/v1/dash/xyz/license/acquire"


@pytest.mark.asyncio
async def test_get_cached_mpd_falls_back_to_redownload_on_legacy_cache_format(monkeypatch):
    """Cache entries written by pre-fix code store the bare mpd_dict (no
    'resolved_url' wrapper). During a rolling deploy the new code may hit
    such an entry - it must not crash, just treat it as a cache miss."""
    original_url = "https://tv.example.com/proxy/vtmgo/resolve/abc.mpd"
    redirected_url = "https://live-video.dpgmedia.net/v1/dash/xyz/index.mpd?aws.sessionId=abc"

    async def fake_redis_get_cached_mpd(key):
        """Simulate a legacy cache entry: raw xmltodict dict, no wrapper."""
        return {"MPD": {}}

    async def fake_redis_set_cached_mpd(key, data, ttl=None):
        """No-op replacement for the cache write."""
        pass

    async def fake_download_file_with_retry(url, headers, return_url=False, **kwargs):
        """Simulate a download that got redirected to a different URL."""
        assert return_url is True
        return b"<MPD/>", redirected_url

    def fake_parse_mpd(content):
        """Fake replacement for parse_mpd."""
        return {"MPD": {}}

    captured = {}

    def fake_parse_mpd_dict(mpd_dict, mpd_url, parse_drm, parse_segment_profile_id=None):
        """Fake replacement for parse_mpd_dict that records the URL it was called with."""
        captured["mpd_url"] = mpd_url
        return {"profiles": [], "drmInfo": {}}

    monkeypatch.setattr(cache_utils.redis_utils, "get_cached_mpd", fake_redis_get_cached_mpd)
    monkeypatch.setattr(cache_utils.redis_utils, "set_cached_mpd", fake_redis_set_cached_mpd)
    monkeypatch.setattr(cache_utils, "download_file_with_retry", fake_download_file_with_retry)
    monkeypatch.setattr(cache_utils, "parse_mpd", fake_parse_mpd)
    monkeypatch.setattr(cache_utils, "parse_mpd_dict", fake_parse_mpd_dict)

    await cache_utils.get_cached_mpd(original_url, headers={}, parse_drm=True)

    assert captured["mpd_url"] == redirected_url


@pytest.mark.asyncio
async def test_get_cached_mpd_parses_against_stored_resolved_url_on_cache_hit(monkeypatch):
    """On a cache hit, the manifest is parsed against the stored resolved_url, not re-downloaded."""
    original_url = "https://tv.example.com/proxy/vtmgo/resolve/abc.mpd"
    redirected_url = "https://live-video.dpgmedia.net/v1/dash/xyz/index.mpd?aws.sessionId=abc"

    async def fake_redis_get_cached_mpd(key):
        """Simulate a cache hit with the new wrapped format."""
        return {"mpd_dict": {"MPD": {}}, "resolved_url": redirected_url}

    async def fake_download_file_with_retry(*args, **kwargs):
        """Fail the test if a re-download is attempted on a cache hit."""
        raise AssertionError("should not re-download on cache hit")

    captured = {}

    def fake_parse_mpd_dict(mpd_dict, mpd_url, parse_drm, parse_segment_profile_id=None):
        """Fake replacement for parse_mpd_dict that records the URL it was called with."""
        captured["mpd_url"] = mpd_url
        return {"profiles": [], "drmInfo": {}}

    monkeypatch.setattr(cache_utils.redis_utils, "get_cached_mpd", fake_redis_get_cached_mpd)
    monkeypatch.setattr(cache_utils, "download_file_with_retry", fake_download_file_with_retry)
    monkeypatch.setattr(cache_utils, "parse_mpd_dict", fake_parse_mpd_dict)

    await cache_utils.get_cached_mpd(original_url, headers={}, parse_drm=True)

    assert captured["mpd_url"] == redirected_url
