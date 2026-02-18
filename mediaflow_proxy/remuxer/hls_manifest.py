"""
HLS VOD playlist generator for on-the-fly fMP4 transcoding.

Produces an M3U8 VOD playlist from an ``MKVCueIndex`` or ``MP4Index``.
Consecutive keyframes that are closer together than the target segment
duration are merged into a single HLS segment, matching the behaviour
of ``ffmpeg -hls_time``.

The init segment is referenced via ``#EXT-X-MAP``.

Requires ``#EXT-X-VERSION:7`` for fMP4 (CMAF) segments.
"""

from __future__ import annotations

import math
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass


def merge_cue_points(
    cue_points: list[tuple[float, int]],
    target_duration_ms: float = 5000.0,
) -> list[tuple[float, int]]:
    """Merge consecutive keyframes into segments of *>= target_duration_ms*.

    This replicates the logic of ``ffmpeg -hls_time``: a new segment
    boundary is created only when a keyframe is encountered **at least**
    ``target_duration_ms`` after the start of the current segment.
    Keyframes that fall within the target window are absorbed into the
    current segment.

    Side-effects:
    * Eliminates duplicate byte-offset entries (previously handled by
      ``deduplicate_cue_points``).
    * Eliminates very short "runt" segments (e.g. 0.3 s).

    Args:
        cue_points: Sorted ``(time_ms, byte_offset)`` list.
        target_duration_ms: Minimum segment duration in milliseconds.

    Returns:
        A reduced list of ``(time_ms, byte_offset)`` tuples representing
        the merged segment boundaries.
    """
    if not cue_points:
        return []

    # Normalize duplicate offsets first: keep the earliest timestamp for each
    # byte offset. Some MKV files expose multiple cue times for the same
    # cluster offset; if we keep a later duplicate, segment start times no
    # longer match the actual bytes and can produce timestamp regressions.
    # Sorting by (time, offset) ensures earliest time wins deterministically.
    by_time = sorted(cue_points, key=lambda x: (x[0], x[1]))
    deduped: list[tuple[float, int]] = []
    seen_offsets: set[int] = set()
    for time_ms, byte_offset in by_time:
        if byte_offset in seen_offsets:
            continue
        seen_offsets.add(byte_offset)
        deduped.append((time_ms, byte_offset))

    if not deduped:
        return []

    merged: list[tuple[float, int]] = [deduped[0]]
    for i in range(1, len(deduped)):
        time_since_last = deduped[i][0] - merged[-1][0]
        if time_since_last >= target_duration_ms:
            merged.append(deduped[i])
    return merged


def generate_vod_playlist(
    cue_points: list[tuple[float, int]],
    duration_ms: float,
    init_url: str,
    segment_url_template: str,
    target_segment_duration_ms: float = 5000.0,
) -> str:
    """Build an HLS VOD M3U8 playlist from cue-point data.

    Consecutive keyframes that are closer than *target_segment_duration_ms*
    are merged into a single segment (matching ``ffmpeg -hls_time``).

    Segment URLs use ``{start_ms}`` and ``{end_ms}`` placeholders that are
    replaced with the segment's time range in milliseconds.

    Args:
        cue_points: Sorted list of ``(time_ms, byte_offset)`` tuples.
        duration_ms: Total media duration in milliseconds.
        init_url: URL for the fMP4 init segment (``#EXT-X-MAP`` URI).
        segment_url_template: URL template containing ``{seg}``,
            ``{start_ms}`` and ``{end_ms}`` placeholders.
        target_segment_duration_ms: Target minimum segment duration.

    Returns:
        Complete M3U8 playlist string.
    """
    if not cue_points:
        return ""

    merged = merge_cue_points(cue_points, target_segment_duration_ms)

    # Build per-segment (start_ms, end_ms, duration_s) list.
    segments: list[tuple[float, float, float]] = []
    for i in range(len(merged)):
        start_ms = merged[i][0]
        end_ms = merged[i + 1][0] if i + 1 < len(merged) else duration_ms
        dur_s = max((end_ms - start_ms) / 1000.0, 0.001)
        segments.append((start_ms, end_ms, dur_s))

    if not segments:
        return ""

    target_duration = math.ceil(max(dur_s for _, _, dur_s in segments))
    target_duration = max(target_duration, 1)

    lines: list[str] = [
        "#EXTM3U",
        "#EXT-X-VERSION:7",
        f"#EXT-X-TARGETDURATION:{target_duration}",
        "#EXT-X-PLAYLIST-TYPE:VOD",
        "#EXT-X-MEDIA-SEQUENCE:0",
        f'#EXT-X-MAP:URI="{init_url}"',
    ]

    for seg_num, (start_ms, end_ms, dur_s) in enumerate(segments):
        lines.append(f"#EXTINF:{dur_s:.3f},")
        url = (
            segment_url_template.replace(
                "{seg}",
                str(seg_num),
            )
            .replace(
                "{start_ms}",
                str(int(start_ms)),
            )
            .replace(
                "{end_ms}",
                str(int(end_ms)),
            )
        )
        lines.append(url)

    lines.append("#EXT-X-ENDLIST")
    lines.append("")  # trailing newline

    return "\n".join(lines)
