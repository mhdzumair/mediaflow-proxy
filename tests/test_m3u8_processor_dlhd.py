import pytest
from starlette.datastructures import URL

from mediaflow_proxy.utils.m3u8_processor import M3U8Processor


class DummyRequest:
    def __init__(self, query_params: dict):
        self.headers = {}
        self.query_params = query_params
        self.url = URL("http://localhost/test")

    def url_for(self, name: str, **kwargs):
        if name == "hls_manifest_proxy":
            return URL("http://localhost/proxy/hls/manifest.m3u8")
        raise KeyError(name)


@pytest.mark.asyncio
async def test_process_key_line_resolves_relative_key_uri_for_proxy_encoding():
    request = DummyRequest({"api_password": "devpass"})
    processor = M3U8Processor(request)

    line = '#EXT-X-KEY:METHOD=AES-128,URI="/key/premium49/5913111",IV=0x00'
    base_url = "https://ai.the-sunmoon.site/proxy/wind/premium49/mono.css"

    processed = await processor.process_key_line(line, base_url)

    assert "d=https%3A%2F%2Fai.the-sunmoon.site%2Fkey%2Fpremium49%2F5913111" in processed
    assert "d=%2Fkey%2Fpremium49%2F5913111" not in processed
