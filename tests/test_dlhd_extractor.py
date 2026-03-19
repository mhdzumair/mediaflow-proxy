import pytest

from mediaflow_proxy.extractors.base import ExtractorError, HttpResponse
from mediaflow_proxy.extractors.dlhd import DLHDExtractor


def _response(url: str, text: str) -> HttpResponse:
    return HttpResponse(
        status=200,
        headers={},
        text=text,
        content=text.encode("utf-8"),
        url=url,
    )


@pytest.mark.asyncio
async def test_dlhd_extracts_proxy_server_flow_from_direct_iframe(monkeypatch):
    extractor = DLHDExtractor({})

    main_url = "https://dlstreams.top/stream/stream-49.php"
    iframe_url = "https://freestyleridesx.lol/premiumtv/daddyhd.php?id=49"
    lookup_url = "https://ai.the-sunmoon.site/server_lookup?channel_id=premium49"

    main_html = '<html><iframe src="https://freestyleridesx.lol/premiumtv/daddyhd.php?id=49"></iframe></html>'
    iframe_html = "const CHANNEL_KEY = 'premium49'; const M3U8_SERVER = 'ai.the-sunmoon.site';"
    lookup_json = '{"server_key":"wind"}'

    async def fake_direct(channel_id: str):
        raise ExtractorError("simulated direct extraction failure")

    async def fake_make_request(url: str, **kwargs):
        if url == main_url:
            return _response(main_url, main_html)
        if url == iframe_url:
            return _response(iframe_url, iframe_html)
        if url == lookup_url:
            return _response(lookup_url, lookup_json)
        raise AssertionError(f"Unexpected URL requested: {url}")

    monkeypatch.setattr(extractor, "_extract_direct_stream", fake_direct)
    monkeypatch.setattr(extractor, "_make_request", fake_make_request)

    result = await extractor.extract(main_url)

    assert result["destination_url"] == "https://ai.the-sunmoon.site/proxy/wind/premium49/mono.css"
    assert result["mediaflow_endpoint"] == "hls_manifest_proxy"
    assert result["force_playlist_proxy"] is True
    assert result["request_headers"]["Referer"] == iframe_url
    assert result["request_headers"]["Origin"] == "https://freestyleridesx.lol"


@pytest.mark.asyncio
async def test_dlhd_player_request_keeps_base_referer(monkeypatch):
    extractor = DLHDExtractor({})

    main_url = "https://dlstreams.top/cast/stream-49.php"
    player_url = "https://dlstreams.top/player/49"
    iframe_url = "https://iframe.test/premiumtv/daddyhd.php?id=49"

    main_html = '<html><button data-url="/player/49">Player 1</button></html>'
    player_html = '<html><iframe src="https://iframe.test/premiumtv/daddyhd.php?id=49"></iframe></html>'
    iframe_html = "const CHANNEL_KEY = 'premium49'; const M3U8_SERVER = 'ai.the-sunmoon.site';"
    lookup_json = '{"server_key":"wind"}'

    calls: list[tuple[str, dict]] = []

    async def fake_direct(channel_id: str):
        raise ExtractorError("simulated direct extraction failure")

    async def fake_make_request(url: str, **kwargs):
        calls.append((url, kwargs.get("headers", {})))
        if url == main_url:
            return _response(main_url, main_html)
        if url == player_url:
            return _response(player_url, player_html)
        if url == iframe_url:
            return _response(iframe_url, iframe_html)
        if url == "https://ai.the-sunmoon.site/server_lookup?channel_id=premium49":
            return _response(url, lookup_json)
        raise AssertionError(f"Unexpected URL requested: {url}")

    monkeypatch.setattr(extractor, "_extract_direct_stream", fake_direct)
    monkeypatch.setattr(extractor, "_make_request", fake_make_request)

    await extractor.extract(main_url)

    player_call = next((headers for url, headers in calls if url == player_url), None)
    assert player_call is not None
    assert player_call["Referer"] == "https://dlstreams.top/"


@pytest.mark.asyncio
async def test_dlhd_recomputes_iframe_domain_after_redirect(monkeypatch):
    extractor = DLHDExtractor({})

    main_url = "https://dlstreams.top/cast/stream-49.php"
    iframe_initial = "https://initial.example/premiumtv/daddyhd.php?id=49"
    iframe_redirected = "https://edge.lovecdn.ru/embed/49"

    main_html = '<html><iframe src="https://initial.example/premiumtv/daddyhd.php?id=49"></iframe></html>'
    iframe_html = "<html>redirected iframe content</html>"

    async def fake_direct(channel_id: str):
        raise ExtractorError("simulated direct extraction failure")

    async def fake_proxy_flow(iframe_url: str, iframe_content: str, headers: dict):
        raise ExtractorError("not proxy flow")

    async def fake_lovecdn(iframe_url: str, iframe_content: str, headers: dict):
        return {
            "destination_url": "https://cdn.example/live.m3u8",
            "request_headers": {"Referer": headers["Referer"]},
            "mediaflow_endpoint": "hls_manifest_proxy",
        }

    async def fake_new_auth(iframe_url: str, iframe_content: str, headers: dict):
        raise AssertionError("new auth flow should not be used for redirected lovecdn iframe")

    async def fake_make_request(url: str, **kwargs):
        if url == main_url:
            return _response(main_url, main_html)
        if url == iframe_initial:
            return _response(iframe_redirected, iframe_html)
        raise AssertionError(f"Unexpected URL requested: {url}")

    monkeypatch.setattr(extractor, "_extract_direct_stream", fake_direct)
    monkeypatch.setattr(extractor, "_extract_proxy_server_flow", fake_proxy_flow)
    monkeypatch.setattr(extractor, "_extract_lovecdn_stream", fake_lovecdn)
    monkeypatch.setattr(extractor, "_extract_new_auth_flow", fake_new_auth)
    monkeypatch.setattr(extractor, "_make_request", fake_make_request)

    result = await extractor.extract(main_url)

    assert result["destination_url"] == "https://cdn.example/live.m3u8"
    assert result["request_headers"]["Referer"] == iframe_redirected


@pytest.mark.asyncio
async def test_dlhd_resolves_relative_player_and_iframe_against_document_url(monkeypatch):
    extractor = DLHDExtractor({})

    main_url = "https://dlstreams.top/cast/stream-49.php"
    player_url = "https://dlstreams.top/cast/player/49"
    iframe_url = "https://dlstreams.top/cast/player/embed/49"
    lookup_url = "https://ai.the-sunmoon.site/server_lookup?channel_id=premium49"

    main_html = '<html><button data-url="player/49">Player 1</button></html>'
    player_html = '<html><iframe src="embed/49"></iframe></html>'
    iframe_html = "const CHANNEL_KEY = 'premium49'; const M3U8_SERVER = 'ai.the-sunmoon.site';"
    lookup_json = '{"server_key":"wind"}'

    called_urls: list[str] = []

    async def fake_direct(channel_id: str):
        raise ExtractorError("simulated direct extraction failure")

    async def fake_make_request(url: str, **kwargs):
        called_urls.append(url)
        if url == main_url:
            return _response(main_url, main_html)
        if url == player_url:
            return _response(player_url, player_html)
        if url == iframe_url:
            return _response(iframe_url, iframe_html)
        if url == lookup_url:
            return _response(lookup_url, lookup_json)
        raise AssertionError(f"Unexpected URL requested: {url}")

    monkeypatch.setattr(extractor, "_extract_direct_stream", fake_direct)
    monkeypatch.setattr(extractor, "_make_request", fake_make_request)

    result = await extractor.extract(main_url)

    assert player_url in called_urls
    assert iframe_url in called_urls
    assert result["destination_url"] == "https://ai.the-sunmoon.site/proxy/wind/premium49/mono.css"
