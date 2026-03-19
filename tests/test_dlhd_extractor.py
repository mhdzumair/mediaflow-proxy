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
