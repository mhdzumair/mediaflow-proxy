import asyncio
import re
from datetime import datetime, timezone
from urllib.parse import parse_qs, urlparse
from unittest.mock import AsyncMock

import pytest
from Crypto.Cipher import AES
from starlette.datastructures import URL
from starlette.responses import Response

from mediaflow_proxy.configs import settings
from mediaflow_proxy.routes import proxy
from mediaflow_proxy.utils.http_utils import get_proxy_headers
from mediaflow_proxy.utils import m3u8_processor, redis_utils
from mediaflow_proxy.utils.m3u8_processor import M3U8Processor


class Request:
    def __init__(self, params=None):
        """Supply the request fields used by playlist processing."""
        self.query_params = params or {}
        self.headers = {}
        self.url = URL("http://localhost/proxy/hls/manifest.m3u8")

    def url_for(self, name, **kwargs):
        """Return the local proxy endpoint used by URL construction."""
        return self.url


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    """Disable background prebuffering and default playback offsets for deterministic tests."""
    monkeypatch.setattr(settings, "enable_hls_prebuffer", False)
    monkeypatch.setattr(settings, "livestream_start_offset", None)


BASE = "https://media.example/path/list.m3u8"


@pytest.mark.parametrize("mode", ["buffered", "stream"])
async def test_filter_rejects_partial_and_delta_playlists(mode):
    """Filtering must not expose partial media belonging to skipped segments."""
    for tag in (
        '#EXT-X-PART:DURATION=1,URI="part.m4s"',
        '#EXT-X-PRELOAD-HINT:TYPE=PART,URI="next.m4s"',
        "#EXT-X-SKIP:SKIPPED-SEGMENTS=2",
    ):
        text = playlist(f"{tag}\n#EXTINF:4,\na.ts\n#EXTINF:4,\nb.ts")
        with pytest.raises(ValueError, match="Low-latency or delta HLS"):
            await render(text, [(0, 4)], mode)
        # These manifests remain usable when interval filtering is not requested.
        assert tag.split(":")[0] in await render(text, [], mode)


async def test_segment_metadata_stays_with_its_segment():
    """Unknown media tags are not promoted to global playlist headers."""
    text = playlist(
        "#EXT-X-CUE-OUT:4\n#EXTINF:4,\na.ts\n#EXT-X-CUE-IN\n"
        '#EXT-X-DATERANGE:ID="retained",START-DATE="2026-01-01T00:00:04Z"\n'
        "#EXTINF:4,\nb.ts\n#EXT-X-CUSTOM:next\n#EXTINF:4,\nc.ts"
    )
    output = await render(text, [(0, 4)])
    assert "#EXT-X-CUE-OUT" not in output
    assert output.index("#EXT-X-CUE-IN") < output.index("b.ts")
    assert output.index("b.ts") < output.index("#EXT-X-CUSTOM:next") < output.index("c.ts")
    assert output.index("#EXT-X-DATERANGE") < output.index("b.ts")


@pytest.mark.parametrize("offset,expected", [(10, 6), (-2, -2), (6, 4), (-6, -4)])
async def test_start_offset_tracks_retained_timeline(offset, expected):
    """Map both signed start offsets through actual removed segment durations."""
    text = playlist(
        f"#EXT-X-START:TIME-OFFSET={offset},PRECISE=YES\n#EXTINF:4,\na.ts\n#EXTINF:4,\nb.ts\n#EXTINF:4,\nc.ts"
    )
    output = await render(text, [(4.1, 4.2)])
    assert f"#EXT-X-START:TIME-OFFSET={expected},PRECISE=YES" in output


async def test_filtered_byte_ranges_require_version_four():
    """Materialized byte ranges advertise their minimum protocol version."""
    text = playlist("#EXTINF:4,\n#EXT-X-BYTERANGE:10@0\na.ts\n#EXTINF:4,\n#EXT-X-BYTERANGE:10\na.ts").replace(
        "#EXT-X-VERSION:6", "#EXT-X-VERSION:1"
    )
    assert "#EXT-X-VERSION:4" in await render(text, [(0, 4)])


async def test_empty_filtered_playlist_has_no_start_hint():
    """A removed presentation has no remaining preferred playback position."""
    text = playlist("#EXT-X-START:TIME-OFFSET=2\n#EXTINF:4,\na.ts")
    assert "#EXT-X-START" not in await render(text, [(0, 4)])


async def test_method_none_remains_attribute_free():
    """RFC 8216 forbids KEYFORMAT and other attributes on METHOD=NONE."""
    text = playlist(
        '#EXT-X-KEY:METHOD=SAMPLE-AES,URI="key",KEYFORMAT="custom"\n'
        "#EXTINF:4,\na.ts\n#EXT-X-KEY:METHOD=NONE\n#EXTINF:4,\nb.ts"
    )
    output = await render(text, [(0, 4)])
    assert [line for line in output.splitlines() if line.startswith("#EXT-X-KEY:")] == ["#EXT-X-KEY:METHOD=NONE"]


def playlist(body, sequence=40):
    """Build a short VOD media playlist with an explicit source sequence."""
    return (
        "#EXTM3U\n#EXT-X-VERSION:6\n#EXT-X-TARGETDURATION:4\n"
        f"#EXT-X-MEDIA-SEQUENCE:{sequence}\n#EXT-X-PLAYLIST-TYPE:VOD\n" + body + "\n#EXT-X-ENDLIST\n"
    )


async def render(text, intervals, mode="stream", chunk=7, params=None, direct=True):
    """Exercise either processor entry point with configurable source chunking."""
    processor = M3U8Processor(
        Request(params), no_proxy=direct, skip_segments=[{"start": start, "end": end} for start, end in intervals]
    )
    if mode == "buffered":
        return await processor.process_m3u8(text, BASE)

    async def chunks():
        """Split encoded input to exercise incremental UTF-8 decoding."""
        raw = text.encode()
        for index in range(0, len(raw), chunk):
            yield raw[index : index + chunk]

    return "".join([part async for part in processor.process_m3u8_streaming(chunks(), BASE)])


def source_url(uri):
    """Recover the source URL from either a direct or proxied media reference."""
    return parse_qs(urlparse(uri).query).get("d", [uri])[0]


def player_segments(text):
    """Read the effective playback state at each URI, independent of tag placement."""
    sequence = 0
    key = None
    init_map = None
    pending = {}
    records = []
    discontinuities = 0
    discontinuity_base = 0
    for line in text.splitlines():
        if line.startswith("#EXT-X-MEDIA-SEQUENCE:"):
            sequence = int(line.split(":", 1)[1])
        elif line.startswith("#EXT-X-DISCONTINUITY-SEQUENCE:"):
            discontinuity_base = int(line.split(":", 1)[1])
        elif line == "#EXT-X-DISCONTINUITY":
            discontinuities += 1
        elif line.startswith("#EXT-X-KEY:"):
            key = dict((k, v.strip('"')) for k, v in re.findall(r'([A-Z0-9-]+)=("[^"]*"|[^,]+)', line))
        elif line.startswith("#EXT-X-MAP:"):
            init_map = line
        elif line.startswith("#EXTINF:"):
            assert "duration" not in pending, "orphaned EXTINF before the next media segment"
            pending["duration"] = float(line.split(":", 1)[1].split(",")[0])
        elif line.startswith("#EXT-X-BYTERANGE:"):
            assert "range" not in pending, "multiple ranges attached to one media segment"
            pending["range"] = line.split(":", 1)[1]
        elif line.startswith("#EXT-X-PROGRAM-DATE-TIME:"):
            pending["date"] = datetime.fromisoformat(line.split(":", 1)[1].replace("Z", "+00:00"))
        elif line == "#EXT-X-GAP":
            pending["gap"] = True
        elif line and not line.startswith("#"):
            assert "duration" in pending, "media URI without an EXTINF"
            records.append(
                dict(
                    pending,
                    uri=source_url(line),
                    sequence=sequence,
                    key=key,
                    init_map=init_map,
                    discontinuities=discontinuities,
                    discontinuity_sequence=discontinuity_base + discontinuities,
                )
            )
            pending = {}
            sequence += 1
    assert not pending, "orphaned metadata at the end of the playlist"
    return records


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "intervals,expected",
    [
        ([(0, 4)], [1, 2, 3]),
        ([(4, 8)], [0, 2, 3]),
        ([(12, 16)], [0, 1, 2]),
        ([(0, 8), (4, 12)], [3]),
        ([(4, 8), (8, 12)], [0, 3]),
        ([(3.99, 4.01)], [2, 3]),
        ([(0, 16)], []),
    ],
)
async def test_streamed_intervals_keep_original_positions(intervals, expected):
    """Select segments by their original time spans across chunk boundaries."""
    text = playlist("\n".join(f"#EXTINF:4,segment {i}\n{i}.ts" for i in range(4)))
    for chunk in (1, 11, 4096):
        output = await render(text, intervals, chunk=chunk)
        segments = player_segments(output)
        assert [r["uri"].rsplit("/", 1)[1] for r in segments] == [f"{i}.ts" for i in expected]
        assert all(r["duration"] == 4 for r in segments)
        assert output.count("#EXT-X-ENDLIST") == 1


@pytest.mark.asyncio
async def test_both_entry_points_agree_with_fractional_utf8_and_crlf():
    """Preserve fractional durations and Unicode titles across input formats."""
    text = playlist("#EXTINF:1.25,café\na.ts\n#EXTINF:2.5,世界\nb.ts\n#EXTINF:3.75,fin\nc.ts")
    for content in (text, text.replace("\n", "\r\n"), text.rstrip("\n")):
        for mode in ("stream", "buffered"):
            records = player_segments(await render(content, [(1.25, 3.75)], mode=mode, chunk=1))
            assert [(r["uri"].rsplit("/", 1)[1], r["duration"]) for r in records] == [("a.ts", 1.25), ("c.ts", 3.75)]


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["buffered", "stream"])
async def test_implicit_ranges_are_resolved_before_removal(mode):
    """Keep original resource offsets after removing earlier byte ranges."""
    text = playlist(
        "#EXTINF:4,\n#EXT-X-BYTERANGE:80@20\nfile.ts\n"
        "#EXTINF:4,\n#EXT-X-BYTERANGE:120\nfile.ts\n"
        "#EXTINF:4,\n#EXT-X-BYTERANGE:60\nfile.ts\n"
        "#EXTINF:4,\n#EXT-X-BYTERANGE:50@500\nother.ts"
    )
    records = player_segments(await render(text, [(0, 8)], mode))
    assert [r["range"] for r in records] == ["60@220", "50@500"]
    assert records[0]["sequence"] == 42


@pytest.mark.asyncio
async def test_aes_sequence_iv_still_decrypts_original_bytes():
    """Decrypt retained ciphertext using its original sequence-derived IV."""
    text = playlist(
        '#EXT-X-KEY:METHOD=AES-128,URI="key.bin"\n#EXTINF:4,\na.ts\n#EXTINF:4,\nb.ts\n#EXTINF:4,\nc.ts', sequence=100
    )
    records = player_segments(await render(text, [(4, 8)], "buffered"))
    assert len(records) == 2
    key_bytes = bytes(range(16))
    plaintext = b"synthetic-media!"
    for record, source_sequence in zip(records, (100, 102)):
        ciphertext = AES.new(key_bytes, AES.MODE_CBC, source_sequence.to_bytes(16, "big")).encrypt(plaintext)
        effective_iv = int(record["key"]["IV"], 16) if "IV" in record["key"] else record["sequence"]
        assert AES.new(key_bytes, AES.MODE_CBC, effective_iv.to_bytes(16, "big")).decrypt(ciphertext) == plaintext


@pytest.mark.asyncio
async def test_state_changes_on_removed_segments_and_explicit_iv():
    """Carry inherited key and map changes past a removed segment."""
    text = playlist(
        '#EXT-X-KEY:METHOD=AES-128,URI="first.bin",IV=0x123\n'
        '#EXT-X-MAP:URI="init-a.mp4"\n#EXTINF:4,\na.ts\n'
        '#EXT-X-KEY:METHOD=AES-128,URI="second.bin",IV=0x456\n'
        '#EXT-X-MAP:URI="init-b.mp4"\n#EXTINF:4,\nb.ts\n'
        "#EXTINF:4,\nc.ts\n#EXT-X-KEY:METHOD=NONE\n#EXTINF:4,\nd.ts"
    )
    records = player_segments(await render(text, [(0, 8)], "stream"))
    assert [r["uri"].rsplit("/", 1)[1] for r in records] == ["c.ts", "d.ts"]
    assert int(records[0]["key"]["IV"], 16) == 0x456
    assert records[0]["key"]["URI"].endswith("/second.bin")
    assert "init-b.mp4" in records[0]["init_map"]
    assert records[1]["key"]["METHOD"] == "NONE"


@pytest.mark.asyncio
async def test_removed_program_date_anchor_and_gap_do_not_move_to_neighbor():
    """Advance inherited timestamps without transferring a removed gap marker."""
    text = playlist(
        "#EXT-X-PROGRAM-DATE-TIME:2026-01-01T00:00:00Z\n"
        "#EXTINF:4,\n#EXT-X-GAP\na.ts\n#EXTINF:4,\nb.ts\n#EXTINF:4,\nc.ts"
    )
    records = player_segments(await render(text, [(0, 4)], "buffered"))
    assert records[0]["date"] == datetime(2026, 1, 1, 0, 0, 4, tzinfo=timezone.utc)
    assert not any(r.get("gap") for r in records)


@pytest.mark.asyncio
async def test_prefix_discontinuity_sequence_and_internal_boundary():
    """Preserve discontinuity numbering across prefix and internal removal."""
    text = playlist(
        "#EXT-X-DISCONTINUITY-SEQUENCE:7\n#EXTINF:4,\na.ts\n"
        "#EXT-X-DISCONTINUITY\n#EXTINF:4,\nb.ts\n#EXTINF:4,\nc.ts\n"
        "#EXT-X-DISCONTINUITY\n#EXTINF:4,\nd.ts"
    )
    output = await render(text, [(0, 4), (8, 12)], "buffered")
    records = player_segments(output)
    assert records[0]["sequence"] == 41
    assert [r["discontinuity_sequence"] for r in records] == [8, 9]


@pytest.mark.asyncio
async def test_all_removed_has_no_segment_local_or_persistent_state():
    """Leave a valid empty playlist without orphan media metadata."""
    text = playlist(
        '#EXT-X-KEY:METHOD=AES-128,URI="key.bin",IV=0x1\n'
        '#EXT-X-MAP:URI="init.mp4"\n#EXT-X-PROGRAM-DATE-TIME:2026-01-01T00:00:00Z\n'
        "#EXTINF:4,\n#EXT-X-BYTERANGE:100@0\n#EXT-X-GAP\nfile.ts"
    )
    output = await render(text, [(0, 4)], "buffered")
    assert player_segments(output) == []
    assert not any(
        tag in output
        for tag in ("#EXT-X-KEY:", "#EXT-X-MAP:", "#EXT-X-BYTERANGE:", "#EXT-X-PROGRAM-DATE-TIME:", "#EXT-X-GAP")
    )
    assert output.startswith("#EXTM3U") and "#EXT-X-ENDLIST" in output


@pytest.mark.asyncio
async def test_master_variants_survive_buffered_filtering_and_route_as_playlists():
    """Keep master variants and route their URLs as nested playlists."""
    text = (
        '#EXTM3U\n#EXT-X-MEDIA:TYPE=AUDIO,GROUP-ID="a",NAME="English",URI="audio"\n'
        '#EXT-X-STREAM-INF:BANDWIDTH=1000,AUDIO="a"\nvideo?type=video\n'
    )
    output = await render(text, [(0, 4)], "buffered", direct=False, params={"h_referer": "https://player.example"})
    urls = [line for line in output.splitlines() if line and not line.startswith("#")]
    assert len(urls) == 1
    assert urlparse(urls[0]).path.endswith("/hls/manifest.m3u8")
    assert source_url(urls[0]) == "https://media.example/path/video?type=video"
    assert parse_qs(urlparse(urls[0]).query)["h_referer"] == ["https://player.example"]
    assert 'URI="http://localhost/proxy/hls/manifest.m3u8?' in output


@pytest.mark.asyncio
async def test_prefetch_uses_retained_whole_segments_only(monkeypatch):
    """Prefetch retained whole resources while excluding byte-range resources."""
    monkeypatch.setattr(settings, "enable_hls_prebuffer", True)
    registered = AsyncMock()
    monkeypatch.setattr(m3u8_processor.hls_prebuffer, "register_playlist", registered)
    text = playlist(
        "#EXTINF:4,\ndrop.ts\n#EXTINF:4,\nkeep.ts\n"
        "#EXTINF:4,\n#EXT-X-BYTERANGE:100@0\nshared.ts\n"
        "#EXTINF:4,\n#EXT-X-BYTERANGE:100\nshared.ts"
    )
    await render(text, [(0, 4)], "buffered")
    await asyncio.sleep(0)
    registered.assert_awaited_once()
    assert registered.call_args.args[1] == ["https://media.example/path/keep.ts"]


@pytest.mark.asyncio
@pytest.mark.parametrize("header", ["range", "Range", "RANGE"])
async def test_range_response_cannot_be_replaced_by_whole_file_cache(monkeypatch, header):
    """Bypass whole-file cache for ranged requests while keeping ordinary hits."""
    monkeypatch.setattr(settings, "enable_hls_prebuffer", True)
    # Fake storage, leaving cache lookup and range handling implementations intact.
    cached = AsyncMock(side_effect=lambda url: b"0123456789" if url == "https://media.example/file.ts" else None)
    monkeypatch.setattr(redis_utils, "get_cached_segment", cached)
    monkeypatch.setattr(proxy.hls_prebuffer, "_ensure_stats_logging", lambda: None)
    monkeypatch.setattr(proxy.hls_prebuffer, "request_segment", AsyncMock())
    direct = AsyncMock(return_value=Response(b"4567", status_code=206, headers={"Content-Range": "bytes 4-7/10"}))
    monkeypatch.setattr(proxy, "handle_stream_request", direct)
    # Exercise the real dependency that normalizes forwarded header names.
    request = Request({f"h_{header}": "bytes=4-7"})
    headers = get_proxy_headers(request)
    result = await proxy.hls_segment_proxy(request, headers, "ts", "https://media.example/file.ts", None)
    assert result.status_code == 206
    assert result.body == b"4567"
    assert result.headers["content-range"] == "bytes 4-7/10"
    if direct.await_count:
        assert direct.call_args.args[2].request["range"] == "bytes=4-7"
    previous_direct_calls = direct.await_count
    # A correct fix must not disable the useful ordinary cache path.
    ordinary = await proxy.hls_segment_proxy(
        Request(),
        get_proxy_headers(Request()),
        "ts",
        "https://media.example/file.ts",
        None,
    )
    assert ordinary.body == b"0123456789"
    assert direct.await_count == previous_direct_calls
