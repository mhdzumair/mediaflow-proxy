"""Preserve empty-window behavior that already works before the DASH fix."""

import pytest

from tests.test_dash_repeat_windows import freeze_clock, manifest, segments


@pytest.mark.parametrize("offset", [0, 1])
def test_zero_length_period_has_no_segments(offset):
    """Return no references for a zero-duration period despite its offset."""
    assert segments(manifest({"@t": "0", "@d": "4", "@r": "-1"}, duration="PT0S", offset=offset)) == []


@pytest.mark.parametrize("now", [0, 3.9])
def test_live_window_before_first_complete_segment(monkeypatch, now):
    """Return no references until the first live segment completes."""
    freeze_clock(monkeypatch, now)
    assert segments(manifest({"@d": "4", "@r": "-1"}, duration=None, live=True, start_number=7)) == []


def test_expired_period_drops_its_overhanging_final_segment(monkeypatch):
    """Exclude an expired period even when its final segment overhangs."""
    freeze_clock(monkeypatch, 20)
    data = manifest({"@d": "4", "@r": "-1"}, duration=None, period_duration="PT10S", live=True)
    assert segments(data) == []
