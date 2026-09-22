"""Byte-range semantics when an HTTP origin ignores Range."""

from contextlib import asynccontextmanager

import pytest

from mediaflow_proxy.remuxer import media_source


@pytest.mark.parametrize(
    "status,offset,limit,expected",
    [
        (200, 4, 3, b"456"),
        (200, 4, None, b"456789"),
        (200, 0, 0, b""),
        (200, 0, 2, b"01"),
        (206, 4, 3, b"456"),
        (206, 4, None, b"456789"),
    ],
)
async def test_stream_obeys_requested_range(monkeypatch, status, offset, limit, expected):
    """Honor the requested slice, avoid empty requests, and release the response."""
    requests = []
    closed = []

    class Response:
        def __init__(self):
            """Expose this fake response as its own chunked content stream."""
            self.status = status
            self.content = self

        def raise_for_status(self):
            """Accept the successful response statuses used by this fixture."""
            pass

        async def __aenter__(self):
            """Enter the simulated HTTP response context."""
            return self

        async def __aexit__(self, *args):
            """Record closure even when the consumer stops reading early."""
            closed.append(True)

        async def iter_any(self):
            """Split the full or ranged body across deliberately uneven chunks."""
            chunks = (b"012", b"3456", b"789") if status == 200 else (b"45", b"6789")
            for chunk in chunks:
                yield chunk

    class Session:
        def get(self, url, **kwargs):
            """Capture request headers before yielding the configured response."""
            requests.append(kwargs["headers"])
            return Response()

    @asynccontextmanager
    async def session(*args, **kwargs):
        """Provide a transport-free session without a proxy."""
        yield Session(), None

    monkeypatch.setattr(media_source, "create_aiohttp_session", session)
    source = media_source.HTTPMediaSource("https://example.invalid/movie.mp4", headers={"Range": "bytes=9-"})
    actual = b"".join([chunk async for chunk in source.stream(offset, limit)])
    assert actual == expected
    if limit == 0:
        assert requests == []
    else:
        end = "" if limit is None else str(offset + limit - 1)
        assert requests == [{"range": f"bytes={offset}-{end}"}]
        assert closed == [True]
