from datetime import datetime, timezone, timedelta

from starlette.datastructures import URL

from mediaflow_proxy.mpd_processor import build_hls_playlist, _compute_live_playlist_depth
from mediaflow_proxy.utils.mpd_utils import create_segment_data, generate_live_segments


class DummyRequest:
    def __init__(self, query_params: dict):
        self.query_params = query_params
        self.headers = {}
        self.url = URL("http://localhost/proxy/mpd/playlist.m3u8")

    def url_for(self, name: str) -> URL:
        return URL(f"http://localhost/{name}")


def _extract_media_sequence(playlist: str) -> int:
    for line in playlist.splitlines():
        if line.startswith("#EXT-X-MEDIA-SEQUENCE:"):
            return int(line.split(":", 1)[1])
    raise AssertionError("Playlist did not include EXT-X-MEDIA-SEQUENCE")


def _build_profile(profile_id: str, init_url: str, segments: list[dict], nominal_duration: int) -> dict:
    return {
        "id": profile_id,
        "mimeType": "video/mp4",
        "initUrl": init_url,
        "segments": segments,
        "segment_template_start_number": 1,
        "segment_template_start_number_explicit": False,
        "nominal_duration_mpd_timescale": nominal_duration,
    }


def _make_timeline_segments(base_time: int, durations: list[int]) -> list[dict]:
    segments = []
    current_time = base_time
    for index, duration in enumerate(durations, start=1):
        segments.append(
            {
                "media": f"https://cdn.example.com/seg-{current_time}.m4v",
                "number": index,  # Simulates parser reset when @startNumber is omitted
                "time": current_time,
                "duration_mpd_timescale": duration,
                "extinf": duration / 1000,
            }
        )
        current_time += duration
    return segments


def test_live_direct_sequence_advances_without_explicit_start_number():
    request = DummyRequest({"d": "https://cdn.example.com/master.mpd", "profile_id": "video-1"})
    mpd_dict = {"isLive": True}

    durations = [4000] * 12
    profile_a = _build_profile(
        profile_id="video-1",
        init_url="https://cdn.example.com/init.m4i",
        segments=_make_timeline_segments(base_time=100_000, durations=durations),
        nominal_duration=4000,
    )
    profile_b = _build_profile(
        profile_id="video-1",
        init_url="https://cdn.example.com/init.m4i",
        segments=_make_timeline_segments(base_time=104_000, durations=durations),
        nominal_duration=4000,
    )

    playlist_a = build_hls_playlist(mpd_dict, [profile_a], request)
    playlist_b = build_hls_playlist(mpd_dict, [profile_b], request)

    seq_a = _extract_media_sequence(playlist_a)
    seq_b = _extract_media_sequence(playlist_b)
    assert seq_b > seq_a


def test_live_ts_sequence_does_not_regress_with_variable_durations():
    request = DummyRequest(
        {
            "d": "https://cdn.example.com/master.mpd",
            "profile_id": "audio-1",
            "remux_to_ts": "true",
        }
    )
    mpd_dict = {"isLive": True}

    profile_a = _build_profile(
        profile_id="audio-1",
        init_url="https://cdn.example.com/audio-init.m4i",
        segments=_make_timeline_segments(base_time=100_000, durations=[3968] + [4010] * 19),
        nominal_duration=4010,
    )
    profile_b = _build_profile(
        profile_id="audio-1",
        init_url="https://cdn.example.com/audio-init.m4i",
        segments=_make_timeline_segments(base_time=100_100, durations=[4010] * 20),
        nominal_duration=4010,
    )

    seq_a = _extract_media_sequence(build_hls_playlist(mpd_dict, [profile_a], request))
    seq_b = _extract_media_sequence(build_hls_playlist(mpd_dict, [profile_b], request))
    assert seq_b >= seq_a


def test_duration_live_segment_replaces_time_placeholder():
    parsed_dict = {
        "availabilityStartTime": datetime.now(tz=timezone.utc) - timedelta(minutes=5),
        "timeShiftBufferDepth": 16,
    }
    item = {
        "@media": "video-$RepresentationID$-$Time$.m4s",
        "@duration": "4000",
        "@timescale": "1000",
        "@startNumber": "1",
        "@presentationTimeOffset": "120",
    }
    profile = {"id": "video-1", "bandwidth": 1_000_000, "segment_template_start_number": 1}

    segments = generate_live_segments(
        parsed_dict,
        segment_duration_sec=4.0,
        start_number=1,
        duration_mpd_timescale=4000,
        presentation_time_offset=120,
    )
    segment_data = create_segment_data(segments[0], item, profile, "https://cdn.example.com/master.mpd", timescale=1000)

    assert "$Time$" not in segment_data["media"]
    assert str(segments[0]["time"]) in segment_data["media"]
    assert segment_data["duration_mpd_timescale"] == 4000


def test_live_playlist_depth_keeps_headroom_for_direct_mode():
    # With default-style start offset (-18s) and ~4s segments,
    # direct live playlists should keep enough headroom to avoid rapid expiry.
    depth = _compute_live_playlist_depth(
        is_ts_mode=False,
        effective_start_offset=-18.0,
        extinf_values=[4.0] * 8,
    )
    assert depth >= 15
