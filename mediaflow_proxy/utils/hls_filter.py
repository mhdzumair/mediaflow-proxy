"""Preserve source segment state when removing intervals from an HLS playlist."""

import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from decimal import Decimal
from urllib.parse import urljoin


_GLOBAL_TAGS = {
    "#EXTM3U",
    "#EXT-X-VERSION",
    "#EXT-X-TARGETDURATION",
    "#EXT-X-PLAYLIST-TYPE",
    "#EXT-X-INDEPENDENT-SEGMENTS",
    "#EXT-X-I-FRAMES-ONLY",
    "#EXT-X-START",
    "#EXT-X-DEFINE",
    "#EXT-X-ALLOW-CACHE",
}
_LOW_LATENCY_TAGS = {
    "#EXT-X-PART",
    "#EXT-X-PART-INF",
    "#EXT-X-PRELOAD-HINT",
    "#EXT-X-SERVER-CONTROL",
    "#EXT-X-RENDITION-REPORT",
    "#EXT-X-SKIP",
}


def attributes(line: str) -> dict[str, str]:
    """Read an HLS attribute list without splitting quoted comma-containing values."""
    return dict(re.findall(r'([A-Z0-9-]+)=("[^"]*"|[^,]*)', line.partition(":")[2]))


@dataclass
class Segment:
    """A complete media segment and the source state needed to play it."""

    uri: str
    duration: Decimal
    extinf: str
    tags: list[str]
    keys: dict[str, str]
    init_map: tuple[str, dict[str, str]] | None
    sequence: int
    discontinuities: int
    date: datetime | None
    byte_range: tuple[int, int] | None


def read_segments(content: str, base_url: str) -> tuple[list[str], list[Segment]]:
    """Associate local tags with the next complete segment and resolve inherited state."""
    headers, segments = [], []
    keys = {}
    init_map = None
    sequence = discontinuities = 0
    extinf = None
    tags = []
    date = None
    pending_range = None
    previous_resource = None
    previous_end = None
    for raw in content.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("#EXT-X-MEDIA-SEQUENCE:"):
            sequence = int(line.partition(":")[2])
            headers.append(line)
        elif line.startswith("#EXT-X-DISCONTINUITY-SEQUENCE:"):
            discontinuities = int(line.partition(":")[2])
            headers.append(line)
        elif line == "#EXT-X-DISCONTINUITY":
            discontinuities += 1
        elif line.startswith("#EXT-X-KEY:"):
            attrs = attributes(line)
            if attrs.get("METHOD") == "NONE":
                keys = {"identity": line}
            else:
                keys[attrs.get("KEYFORMAT", '"identity"').strip('"')] = line
        elif line.startswith("#EXT-X-MAP:"):
            init_map = (line, dict(keys))
        elif line.startswith("#EXT-X-PROGRAM-DATE-TIME:"):
            date = datetime.fromisoformat(line.partition(":")[2].replace("Z", "+00:00"))
        elif line.startswith("#EXTINF:"):
            extinf = line
        elif line.startswith("#EXT-X-BYTERANGE:"):
            length, _, offset = line.partition(":")[2].partition("@")
            pending_range = (int(length), int(offset) if offset else None)
        elif line == "#EXT-X-ENDLIST":
            continue
        elif line.partition(":")[0] in _GLOBAL_TAGS:
            headers.append(line)
        elif line.startswith("#"):
            tags.append(line)
        elif extinf:
            duration = Decimal(extinf.partition(":")[2].split(",", 1)[0])
            resource = urljoin(base_url, line)
            byte_range = None
            if pending_range:
                length, offset = pending_range
                if offset is None:
                    if previous_resource != resource or previous_end is None:
                        raise ValueError("Implicit byte range requires a preceding range on the same resource")
                    offset = previous_end
                byte_range = (length, offset)
                previous_end = offset + length
                previous_resource = resource
            else:
                previous_end = previous_resource = None
            segments.append(
                Segment(line, duration, extinf, tags, dict(keys), init_map, sequence, discontinuities, date, byte_range)
            )
            sequence += 1
            if date is not None:
                date += timedelta(microseconds=int(duration * 1_000_000))
            extinf, tags, pending_range = None, [], None
    return headers, segments


def filter_playlist(content: str, ranges: list[dict], base_url: str) -> str:
    """Remove whole segments, preserving their state and remapping the playback start.

    Low-latency and delta playlists cannot be safely filtered from complete-segment
    durations alone. Reject them when filtering is requested rather than leak
    skipped partial media or use an incomplete presentation timeline.
    """
    if not ranges or "#EXT-X-STREAM-INF:" in content or "#EXT-X-I-FRAME-STREAM-INF:" in content:
        return content
    if any(line.strip().partition(":")[0] in _LOW_LATENCY_TAGS for line in content.splitlines()):
        raise ValueError("Low-latency or delta HLS playlists do not support interval filtering")
    headers, segments = read_segments(content, base_url)
    intervals = [(Decimal(str(item["start"])), Decimal(str(item["end"]))) for item in ranges]
    kept = []
    kept_spans = []
    elapsed = Decimal(0)
    for segment in segments:
        end = elapsed + segment.duration
        if not any(elapsed < stop and end > start for start, stop in intervals):
            kept.append(segment)
            kept_spans.append((elapsed, end))
        elapsed = end

    if len(kept) != len(segments):
        remapped_headers = []
        kept_duration = sum((end - start for start, end in kept_spans), Decimal(0))
        for line in headers:
            if line.startswith("#EXT-X-START:"):
                if not kept:
                    continue
                offset = Decimal(attributes(line)["TIME-OFFSET"])
                target = offset if offset >= 0 else elapsed + offset
                mapped = sum((max(Decimal(0), min(target, end) - start) for start, end in kept_spans), Decimal(0))
                if offset < 0:
                    mapped -= kept_duration
                line = re.sub(r"TIME-OFFSET=[^,]*", f"TIME-OFFSET={mapped}", line)
            remapped_headers.append(line)
        headers = remapped_headers

    if kept:
        headers = [
            line
            for line in headers
            if not line.startswith(("#EXT-X-MEDIA-SEQUENCE:", "#EXT-X-DISCONTINUITY-SEQUENCE:"))
        ]
        headers.append(f"#EXT-X-MEDIA-SEQUENCE:{kept[0].sequence}")
        if kept[0].discontinuities:
            headers.append(f"#EXT-X-DISCONTINUITY-SEQUENCE:{kept[0].discontinuities}")
    # Materialized IVs and byte ranges need versions 2 and 4 respectively.
    minimum_version = 4 if any(seg.byte_range for seg in kept) else 1
    if any(attributes(key).get("METHOD") == "AES-128" for seg in kept for key in seg.keys.values()):
        minimum_version = max(2, minimum_version)
    if minimum_version > 1:
        versions = [int(line.partition(":")[2]) for line in headers if line.startswith("#EXT-X-VERSION:")]
        headers = [line for line in headers if not line.startswith("#EXT-X-VERSION:")]
        headers.insert(1, f"#EXT-X-VERSION:{max([minimum_version] + versions)}")
    output = list(headers)
    emitted_keys = {}
    emitted_map = None
    previous = None

    def emit_keys(wanted):
        """Emit only encryption state transitions required by the next resource."""
        nonlocal emitted_keys
        for fmt, line in wanted.items():
            if emitted_keys.get(fmt) != line:
                output.append(line)
        emitted_keys = dict(wanted)

    for segment in kept:
        if previous:
            boundaries = segment.discontinuities - previous.discontinuities
            if segment.sequence != previous.sequence + 1:
                boundaries = max(1, boundaries)
            output.extend(["#EXT-X-DISCONTINUITY"] * boundaries)
        if segment.init_map != emitted_map and segment.init_map is not None:
            map_line, map_keys = segment.init_map
            emit_keys(map_keys)
            output.append(map_line)
            emitted_map = segment.init_map
        segment_keys = dict(segment.keys)
        key = segment_keys.get("identity")
        if key:
            attrs = attributes(key)
            if attrs.get("METHOD") == "AES-128" and "IV" not in attrs:
                segment_keys["identity"] = f"{key},IV=0x{segment.sequence:032x}"
        emit_keys(segment_keys)
        if segment.date is not None:
            output.append(f"#EXT-X-PROGRAM-DATE-TIME:{segment.date.isoformat()}")
        output.extend(segment.tags)
        output.append(segment.extinf)
        if segment.byte_range:
            length, offset = segment.byte_range
            output.append(f"#EXT-X-BYTERANGE:{length}@{offset}")
        output.append(segment.uri)
        previous = segment
    if "#EXT-X-ENDLIST" in content:
        output.append("#EXT-X-ENDLIST")
    return "\n".join(output) + "\n"


def prefetchable_urls(content: str, base_url: str) -> list[str]:
    """Return complete, non-gap resources suitable for the whole-file prebuffer."""
    if "#EXT-X-STREAM-INF:" in content or "#EXT-X-I-FRAME-STREAM-INF:" in content:
        return []
    _, segments = read_segments(content, base_url)
    # Never fetch a whole file that the playlist addresses in byte ranges.
    ranged = {urljoin(base_url, seg.uri) for seg in segments if seg.byte_range}
    return [
        urljoin(base_url, seg.uri)
        for seg in segments
        if urljoin(base_url, seg.uri) not in ranged and "#EXT-X-GAP" not in seg.tags
    ]
