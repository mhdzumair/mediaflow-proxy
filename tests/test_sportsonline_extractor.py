import pytest
from typing import Any, cast

from mediaflow_proxy.extractors.base import HttpResponse
from mediaflow_proxy.extractors.sportsonline import SportsonlineExtractor
from mediaflow_proxy.utils.extractor_helpers import check_and_extract_sportsonline_stream
from mediaflow_proxy.utils.http_utils import ProxyRequestHeaders


def _response(url: str, text: str) -> HttpResponse:
    return HttpResponse(
        status=200,
        headers={},
        text=text,
        content=text.encode("utf-8"),
        url=url,
    )


def test_detect_packed_blocks_extracts_multiple_blocks_from_one_script_tag():
    extractor = SportsonlineExtractor({})

    packed_1 = "eval(function(p,a,c,k,e,d){return p;}('var src=\"/one.m3u8\";',1,1,'x'.split('|'),0,{}))"
    packed_2 = "eval(function(p,a,c,k,e,d){return p;}('var src=\"/two.m3u8\";',1,1,'x'.split('|'),0,{}))"
    html = f"<html><script>{packed_1};var x=1;{packed_2}</script></html>"

    blocks = extractor._detect_packed_blocks(html)

    assert len(blocks) == 2
    assert "/one.m3u8" in blocks[0]
    assert "/two.m3u8" in blocks[1]


def test_extract_m3u8_candidate_skips_non_m3u8_var_src():
    text = 'var src="/player.js"; var file="https://cdn.example.test/live/master.m3u8?token=abc";'

    candidate = SportsonlineExtractor._extract_m3u8_candidate(text)

    assert candidate == "https://cdn.example.test/live/master.m3u8?token=abc"


@pytest.mark.asyncio
async def test_sportsonline_extracts_iframe_with_non_first_src_attr(monkeypatch):
    extractor = SportsonlineExtractor({})
    calls = []

    main_url = "https://sportsonline.st/game-1"
    iframe_url = "https://closethreaten.net/embed/abc123"

    main_html = (
        '<html><iframe allowfullscreen="true" src="//closethreaten.net/embed/abc123" frameborder="0"></iframe></html>'
    )
    iframe_html = "<script>eval(function(p,a,c,k,e,d){return p;}('0',1,1,'x'.split('|'),0,{}))</script>"

    async def fake_make_request(url: str, **kwargs):
        calls.append((url, kwargs.get("headers", {})))
        if url == main_url:
            return _response(main_url, main_html)
        if url == iframe_url:
            return _response(iframe_url, iframe_html)
        raise AssertionError(f"Unexpected URL requested: {url}")

    monkeypatch.setattr(extractor, "_make_request", fake_make_request)
    monkeypatch.setattr(
        "mediaflow_proxy.extractors.sportsonline.unpack",
        lambda _packed: 'var src="/hls/live/index.m3u8?token=abc";',
    )

    result = await extractor.extract(main_url)

    assert calls[0][1]["Origin"] == "https://sportsonline.st"
    assert calls[0][1]["Referer"] == "https://sportsonline.st/"
    assert calls[1][1]["Referer"] == main_url
    assert calls[1][1]["Origin"] == "https://sportsonline.st"
    assert result["destination_url"] == "https://closethreaten.net/hls/live/index.m3u8?token=abc"
    assert result["request_headers"]["Referer"] == iframe_url
    assert result["request_headers"]["Origin"] == "https://closethreaten.net"
    assert result["mediaflow_endpoint"] == "hls_manifest_proxy"


@pytest.mark.asyncio
async def test_sportsonline_fallback_to_direct_m3u8_when_not_packed(monkeypatch):
    extractor = SportsonlineExtractor({})
    calls = []

    main_url = "https://sportsonline.st/game-2"
    iframe_url = "https://closethreaten.net/embed/xyz"

    main_html = '<html><iframe src="https://closethreaten.net/embed/xyz"></iframe></html>'
    iframe_html = '<script>const file="//cdn.example.test/live/stream.m3u8?k=v";</script>'

    async def fake_make_request(url: str, **kwargs):
        calls.append((url, kwargs.get("headers", {})))
        if url == main_url:
            return _response(main_url, main_html)
        if url == iframe_url:
            return _response(iframe_url, iframe_html)
        raise AssertionError(f"Unexpected URL requested: {url}")

    monkeypatch.setattr(extractor, "_make_request", fake_make_request)

    result = await extractor.extract(main_url)

    assert calls[1][1]["Referer"] == main_url
    assert calls[1][1]["Origin"] == "https://sportsonline.st"
    assert result["destination_url"] == "https://cdn.example.test/live/stream.m3u8?k=v"
    assert result["request_headers"]["Referer"] == iframe_url
    assert result["request_headers"]["Origin"] == "https://closethreaten.net"


@pytest.mark.asyncio
async def test_sportsonline_extracts_without_iframe_from_main_html(monkeypatch):
    extractor = SportsonlineExtractor({})
    calls = []

    main_url = "https://sportsonline.st/game-3"
    main_html = '<html><script>const src="/manifest.m3u8";</script></html>'

    async def fake_make_request(url: str, **kwargs):
        calls.append((url, kwargs.get("headers", {})))
        if url == main_url:
            return _response(main_url, main_html)
        raise AssertionError(f"Unexpected URL requested: {url}")

    monkeypatch.setattr(extractor, "_make_request", fake_make_request)

    result = await extractor.extract(main_url)

    assert calls[0][1]["Origin"] == "https://sportsonline.st"
    assert calls[0][1]["Referer"] == "https://sportsonline.st/"
    assert result["destination_url"] == "https://sportsonline.st/manifest.m3u8"
    assert result["request_headers"]["Referer"] == main_url
    assert result["request_headers"]["Origin"] == "https://sportsonline.st"


@pytest.mark.asyncio
async def test_sportsonline_uses_canonical_main_url_after_redirect(monkeypatch):
    extractor = SportsonlineExtractor({})

    requested_main_url = "https://sportsonline.st/game-redirect"
    resolved_main_url = "https://sportzsonline.click/channels/pt/sporttv1.php"
    main_html = '<html><script>const src="/manifest.m3u8";</script></html>'

    async def fake_make_request(url: str, **kwargs):
        if url == requested_main_url:
            return _response(resolved_main_url, main_html)
        raise AssertionError(f"Unexpected URL requested: {url}")

    monkeypatch.setattr(extractor, "_make_request", fake_make_request)

    result = await extractor.extract(requested_main_url)

    assert result["destination_url"] == "https://sportzsonline.click/manifest.m3u8"
    assert result["request_headers"]["Referer"] == resolved_main_url
    assert result["request_headers"]["Origin"] == "https://sportzsonline.click"


@pytest.mark.asyncio
async def test_sportsonline_prefers_iframe_src_over_data_src(monkeypatch):
    extractor = SportsonlineExtractor({})

    main_url = "https://sportsonline.st/game-data-src"
    iframe_url = "https://closethreaten.net/embed/real"
    main_html = '<html><iframe data-src="https://cdn.example.test/placeholder" src="https://closethreaten.net/embed/real"></iframe></html>'
    iframe_html = '<script>const file="https://cdn.example.test/live/final.m3u8";</script>'

    async def fake_make_request(url: str, **kwargs):
        if url == main_url:
            return _response(main_url, main_html)
        if url == iframe_url:
            return _response(iframe_url, iframe_html)
        raise AssertionError(f"Unexpected URL requested: {url}")

    monkeypatch.setattr(extractor, "_make_request", fake_make_request)

    result = await extractor.extract(main_url)

    assert result["destination_url"] == "https://cdn.example.test/live/final.m3u8"
    assert result["request_headers"]["Referer"] == iframe_url


@pytest.mark.asyncio
async def test_sportsonline_uses_resolved_iframe_url_after_redirect(monkeypatch):
    extractor = SportsonlineExtractor({})

    main_url = "https://sportsonline.st/game-iframe-redirect"
    iframe_initial = "https://closethreaten.net/embed/abc123"
    iframe_resolved = "https://closethreaten.net/embed/abc123?stream=1"
    main_html = '<html><iframe src="https://closethreaten.net/embed/abc123"></iframe></html>'
    iframe_html = '<script>const file="/live/edge.m3u8";</script>'

    async def fake_make_request(url: str, **kwargs):
        if url == main_url:
            return _response(main_url, main_html)
        if url == iframe_initial:
            return _response(iframe_resolved, iframe_html)
        raise AssertionError(f"Unexpected URL requested: {url}")

    monkeypatch.setattr(extractor, "_make_request", fake_make_request)

    result = await extractor.extract(main_url)

    assert result["destination_url"] == "https://closethreaten.net/live/edge.m3u8"
    assert result["request_headers"]["Referer"] == iframe_resolved
    assert result["request_headers"]["Origin"] == "https://closethreaten.net"


@pytest.mark.asyncio
async def test_sportsonline_helper_matches_domain_label_case_insensitive(monkeypatch):
    called: dict[str, Any] = {"count": 0}

    class DummyExtractor:
        async def extract(self, destination: str):
            called["count"] += 1
            called["destination"] = destination
            return {
                "destination_url": "https://cdn.example.test/live/final.m3u8",
                "request_headers": {"Referer": "https://example.test/"},
                "mediaflow_endpoint": "hls_manifest_proxy",
            }

    monkeypatch.setattr(
        "mediaflow_proxy.utils.extractor_helpers.ExtractorFactory.get_extractor",
        lambda host, headers: DummyExtractor(),
    )

    proxy_headers = ProxyRequestHeaders(request={}, response={}, remove=[], propagate={})
    result = await check_and_extract_sportsonline_stream(
        request=cast(Any, None),
        destination="https://W1.SPORTZSONLINE.click/channels/pt/sporttv1.php",
        proxy_headers=proxy_headers,
        force_refresh=True,
    )

    assert called["count"] == 1
    assert called["destination"].endswith("/channels/pt/sporttv1.php")
    assert result is not None
    assert result["destination_url"] == "https://cdn.example.test/live/final.m3u8"


@pytest.mark.asyncio
async def test_sportsonline_helper_ignores_non_matching_hostname(monkeypatch):
    called: dict[str, Any] = {"count": 0}

    class DummyExtractor:
        async def extract(self, destination: str):
            called["count"] += 1
            return {"destination_url": destination}

    monkeypatch.setattr(
        "mediaflow_proxy.utils.extractor_helpers.ExtractorFactory.get_extractor",
        lambda host, headers: DummyExtractor(),
    )

    proxy_headers = ProxyRequestHeaders(request={}, response={}, remove=[], propagate={})
    result = await check_and_extract_sportsonline_stream(
        request=cast(Any, None),
        destination="https://notsportzonlineexample.com/channel",
        proxy_headers=proxy_headers,
        force_refresh=True,
    )

    assert result is None
    assert called["count"] == 0
