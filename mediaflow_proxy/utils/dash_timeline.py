"""Expand DASH segment references within period and availability boundaries."""

import math
from datetime import datetime, timedelta
from fractions import Fraction


def _seconds(value: timedelta) -> Fraction:
    """Avoid floating-point cancellation when sample timestamps are large."""
    return Fraction((value.days * 86400 + value.seconds) * 1_000_000 + value.microseconds, 1_000_000)


def expand_timeline(
    timelines: list[dict],
    start_number: int,
    period_start: datetime,
    presentation_time_offset: int,
    timescale: int,
    *,
    period_duration: float | None = None,
    window_start: datetime | None = None,
    window_end: datetime | None = None,
) -> list[dict]:
    """Preserve source numbering while selecting available segment references.

    Periods select segments by overlap; an availability window additionally
    excludes segments that have not finished yet. Expansion skips expired
    repetitions arithmetically, without allocating an entire live history.
    """
    if timescale <= 0:
        raise ValueError("SegmentTimeline timescale must be positive")
    if period_duration is not None and period_duration < 0:
        raise ValueError("Period duration must not be negative")
    if any(int(entry["@d"]) <= 0 for entry in timelines):
        raise ValueError("SegmentTimeline segment duration must be positive")
    # Reject unbounded runs before allocating any preceding finite runs.
    # DASH-IF explicit addressing defines a negative S@r, not only -1,
    # as repeat-to-end: https://dashif.org/Guidelines-TimingModel/#explicit-addressing
    for index, entry in enumerate(timelines):
        if int(entry.get("@r", 0)) >= 0:
            continue
        if index + 1 < len(timelines):
            if "@t" not in timelines[index + 1]:
                raise ValueError("A repeat-to-end run must be followed by an explicit start time")
        elif period_duration is None and window_end is None:
            raise ValueError("An open SegmentTimeline repeat requires a period or live availability boundary")

    period_end = None
    if period_duration is not None:
        period_end = presentation_time_offset + Fraction(str(period_duration)) * timescale
    lower = Fraction(presentation_time_offset)
    if window_start is not None:
        lower = max(lower, presentation_time_offset + _seconds(window_start - period_start) * timescale)
    available_end = None
    if window_end is not None:
        available_end = presentation_time_offset + _seconds(window_end - period_start) * timescale
    if period_end is not None and lower >= period_end:
        return []

    result = []
    cursor = 0
    number = start_number
    for index, entry in enumerate(timelines):
        duration = int(entry["@d"])
        start = int(entry.get("@t", cursor))
        repeat = int(entry.get("@r", 0))
        if repeat >= 0:
            count = repeat + 1
        else:
            # A following entry supplies the end of a repeat run in sample ticks.
            # A final run instead needs a finite period or live availability end.
            if index + 1 < len(timelines):
                next_entry = timelines[index + 1]
                if "@t" not in next_entry:
                    raise ValueError("A repeat-to-end run must be followed by an explicit start time")
                boundary = Fraction(int(next_entry["@t"]))
                if boundary <= start:
                    raise ValueError("SegmentTimeline repeat boundary must advance time")
            elif period_end is not None:
                boundary = period_end
            elif available_end is not None:
                boundary = available_end
            else:
                raise ValueError("An open SegmentTimeline repeat requires a period or live availability boundary")
            count = max(0, math.ceil((boundary - start) / duration))

        first = max(0, math.floor((lower - start) / duration))
        stop = count
        if period_end is not None:
            stop = min(stop, max(0, math.ceil((period_end - start) / duration)))
        if available_end is not None:
            stop = min(stop, max(0, math.floor((available_end - start) / duration)))

        for offset in range(first, stop):
            time = start + offset * duration
            segment_start = period_start + timedelta(
                seconds=float(Fraction(time - presentation_time_offset, timescale))
            )
            segment_end = period_start + timedelta(
                seconds=float(Fraction(time + duration - presentation_time_offset, timescale))
            )
            result.append(
                {
                    "number": number + offset,
                    "time": time,
                    "duration": duration,
                    "duration_mpd_timescale": duration,
                    "start_time": segment_start,
                    "end_time": segment_end,
                }
            )
        # Counts include references omitted from this playback window.
        number += count
        cursor = start + count * duration
    return result
