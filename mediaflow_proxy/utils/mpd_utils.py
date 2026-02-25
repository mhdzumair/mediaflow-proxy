import logging
import math
import re
import statistics
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Optional, Union
from urllib.parse import urljoin

import xmltodict

logger = logging.getLogger(__name__)


def resolve_url(base_url: str, relative_url: str) -> str:
    """
    Resolve a relative URL against a base URL.

    Handles three cases:
    1. Absolute URL (starts with http:// or https://) - return as-is
    2. Absolute path (starts with /) - resolve against origin (scheme + host)
    3. Relative path - resolve against base URL directory

    Args:
        base_url: The base URL (typically the MPD URL)
        relative_url: The URL to resolve

    Returns:
        The resolved absolute URL
    """
    if not relative_url:
        return base_url

    # Already absolute URL
    if relative_url.startswith(("http://", "https://")):
        return relative_url

    # Use urljoin which correctly handles:
    # - Absolute paths (starting with /) -> resolves against origin
    # - Relative paths -> resolves against base URL
    return urljoin(base_url, relative_url)


def parse_mpd(mpd_content: Union[str, bytes]) -> dict:
    """
    Parses the MPD content into a dictionary.

    Args:
        mpd_content (Union[str, bytes]): The MPD content to parse.

    Returns:
        dict: The parsed MPD content as a dictionary.
    """
    return xmltodict.parse(mpd_content)


def parse_mpd_dict(
    mpd_dict: dict, mpd_url: str, parse_drm: bool = True, parse_segment_profile_id: Optional[str] = None
) -> dict:
    """
    Parses the MPD dictionary and extracts relevant information.

    Args:
        mpd_dict (dict): The MPD content as a dictionary.
        mpd_url (str): The URL of the MPD manifest.
        parse_drm (bool, optional): Whether to parse DRM information. Defaults to True.
        parse_segment_profile_id (str, optional): The profile ID to parse segments for. Defaults to None.

    Returns:
        dict: The parsed MPD information including profiles and DRM info.

    This function processes the MPD dictionary to extract profiles, DRM information, and other relevant data.
    It handles both live and static MPD manifests.
    """
    profiles = []
    parsed_dict = {}

    is_live = mpd_dict["MPD"].get("@type", "static").lower() == "dynamic"
    parsed_dict["isLive"] = is_live

    media_presentation_duration = mpd_dict["MPD"].get("@mediaPresentationDuration")

    # Parse additional MPD attributes for live streams
    if is_live:
        parsed_dict["minimumUpdatePeriod"] = parse_duration(mpd_dict["MPD"].get("@minimumUpdatePeriod", "PT0S"))
        parsed_dict["timeShiftBufferDepth"] = parse_duration(mpd_dict["MPD"].get("@timeShiftBufferDepth", "PT2M"))
        parsed_dict["availabilityStartTime"] = datetime.fromisoformat(
            mpd_dict["MPD"]["@availabilityStartTime"].replace("Z", "+00:00")
        )
        parsed_dict["publishTime"] = datetime.fromisoformat(
            mpd_dict["MPD"].get("@publishTime", "").replace("Z", "+00:00")
        )

    periods = mpd_dict["MPD"]["Period"]
    periods = periods if isinstance(periods, list) else [periods]

    for period in periods:
        parsed_dict["PeriodStart"] = parse_duration(period.get("@start", "PT0S"))
        adaptation_sets = period["AdaptationSet"]
        adaptation_sets = adaptation_sets if isinstance(adaptation_sets, list) else [adaptation_sets]

        for adaptation in adaptation_sets:
            representations = adaptation["Representation"]
            representations = representations if isinstance(representations, list) else [representations]

            for representation in representations:
                profile = parse_representation(
                    parsed_dict,
                    representation,
                    adaptation,
                    mpd_url,
                    media_presentation_duration,
                    parse_segment_profile_id,
                )
                if profile:
                    profiles.append(profile)
    parsed_dict["profiles"] = profiles

    if parse_drm:
        drm_info = extract_drm_info(periods, mpd_url)
    else:
        drm_info = {}
    parsed_dict["drmInfo"] = drm_info

    return parsed_dict


def pad_base64(encoded_key_id):
    """
    Pads a base64 encoded key ID to make its length a multiple of 4.

    Args:
        encoded_key_id (str): The base64 encoded key ID.

    Returns:
        str: The padded base64 encoded key ID.
    """
    return encoded_key_id + "=" * (4 - len(encoded_key_id) % 4)


def extract_drm_info(periods: List[Dict], mpd_url: str) -> Dict:
    """
    Extracts DRM information from the MPD periods.

    Args:
        periods (List[Dict]): The list of periods in the MPD.
        mpd_url (str): The URL of the MPD manifest.

    Returns:
        Dict: The extracted DRM information.

    This function processes the ContentProtection elements in the MPD to extract DRM system information,
    such as ClearKey, Widevine, and PlayReady.
    """
    drm_info = {"isDrmProtected": False}

    for period in periods:
        adaptation_sets: Union[list[dict], dict] = period.get("AdaptationSet", [])
        if not isinstance(adaptation_sets, list):
            adaptation_sets = [adaptation_sets]

        for adaptation_set in adaptation_sets:
            # Check ContentProtection in AdaptationSet
            process_content_protection(adaptation_set.get("ContentProtection", []), drm_info)

            # Check ContentProtection inside each Representation
            representations: Union[list[dict], dict] = adaptation_set.get("Representation", [])
            if not isinstance(representations, list):
                representations = [representations]

            for representation in representations:
                process_content_protection(representation.get("ContentProtection", []), drm_info)

    # If we have a license acquisition URL, make sure it's absolute
    if "laUrl" in drm_info and not drm_info["laUrl"].startswith(("http://", "https://")):
        drm_info["laUrl"] = urljoin(mpd_url, drm_info["laUrl"])

    return drm_info


def process_content_protection(content_protection: Union[list[dict], dict], drm_info: dict):
    """
    Processes the ContentProtection elements to extract DRM information.

    Args:
        content_protection (Union[list[dict], dict]): The ContentProtection elements.
        drm_info (dict): The dictionary to store DRM information.

    This function updates the drm_info dictionary with DRM system information found in the ContentProtection elements.
    """
    if not isinstance(content_protection, list):
        content_protection = [content_protection]

    for protection in content_protection:
        drm_info["isDrmProtected"] = True
        scheme_id_uri = protection.get("@schemeIdUri", "").lower()

        if "clearkey" in scheme_id_uri:
            drm_info["drmSystem"] = "clearkey"
            if "clearkey:Laurl" in protection:
                la_url = protection["clearkey:Laurl"].get("#text")
                if la_url and "laUrl" not in drm_info:
                    drm_info["laUrl"] = la_url

        elif "widevine" in scheme_id_uri or "edef8ba9-79d6-4ace-a3c8-27dcd51d21ed" in scheme_id_uri:
            drm_info["drmSystem"] = "widevine"
            pssh = protection.get("cenc:pssh", {}).get("#text")
            if pssh:
                drm_info["pssh"] = pssh

        elif "playready" in scheme_id_uri or "9a04f079-9840-4286-ab92-e65be0885f95" in scheme_id_uri:
            drm_info["drmSystem"] = "playready"

        if "@cenc:default_KID" in protection:
            key_id = protection["@cenc:default_KID"].replace("-", "")
            if "keyId" not in drm_info:
                drm_info["keyId"] = key_id

        if "ms:laurl" in protection:
            la_url = protection["ms:laurl"].get("@licenseUrl")
            if la_url and "laUrl" not in drm_info:
                drm_info["laUrl"] = la_url

    return drm_info


def parse_representation(
    parsed_dict: dict,
    representation: dict,
    adaptation: dict,
    mpd_url: str,
    media_presentation_duration: str,
    parse_segment_profile_id: Optional[str],
) -> Optional[dict]:
    """
    Parses a representation and extracts profile information.

    Args:
        parsed_dict (dict): The parsed MPD data.
        representation (dict): The representation data.
        adaptation (dict): The adaptation set data.
        mpd_url (str): The URL of the MPD manifest.
        media_presentation_duration (str): The media presentation duration.
        parse_segment_profile_id (str, optional): The profile ID to parse segments for. Defaults to None.

    Returns:
        Optional[dict]: The parsed profile information or None if not applicable.
    """
    mime_type = _get_key(adaptation, representation, "@mimeType") or (
        "video/mp4" if "avc" in representation["@codecs"] else "audio/mp4"
    )
    if "video" not in mime_type and "audio" not in mime_type:
        return None

    profile = {
        "id": representation.get("@id") or adaptation.get("@id"),
        "mimeType": mime_type,
        "lang": representation.get("@lang") or adaptation.get("@lang"),
        "codecs": representation.get("@codecs") or adaptation.get("@codecs"),
        "bandwidth": int(representation.get("@bandwidth") or adaptation.get("@bandwidth")),
        "startWithSAP": (_get_key(adaptation, representation, "@startWithSAP") or "1") == "1",
        "mediaPresentationDuration": media_presentation_duration,
    }

    if "audio" in profile["mimeType"]:
        profile["audioSamplingRate"] = representation.get("@audioSamplingRate") or adaptation.get("@audioSamplingRate")
        profile["channels"] = representation.get("AudioChannelConfiguration", {}).get("@value", "2")
    else:
        # Handle video-specific attributes, making them optional with sensible defaults
        if "@width" in representation:
            profile["width"] = int(representation["@width"])
        elif "@width" in adaptation:
            profile["width"] = int(adaptation["@width"])
        else:
            profile["width"] = 0  # Default if width is missing

        if "@height" in representation:
            profile["height"] = int(representation["@height"])
        elif "@height" in adaptation:
            profile["height"] = int(adaptation["@height"])
        else:
            profile["height"] = 0  # Default if height is missing

        frame_rate = representation.get("@frameRate") or adaptation.get("@maxFrameRate") or "30000/1001"
        frame_rate = frame_rate if "/" in frame_rate else f"{frame_rate}/1"
        profile["frameRate"] = round(int(frame_rate.split("/")[0]) / int(frame_rate.split("/")[1]), 3)
        profile["sar"] = representation.get("@sar", "1:1")

    # Extract segment template start number for adaptive sequence calculation
    segment_template_data = adaptation.get("SegmentTemplate") or representation.get("SegmentTemplate")
    if segment_template_data:
        profile["segment_template_start_number_explicit"] = "@startNumber" in segment_template_data
        try:
            profile["segment_template_start_number"] = int(segment_template_data.get("@startNumber", 1))
        except (ValueError, TypeError):
            profile["segment_template_start_number"] = 1
        try:
            profile["segment_template_timescale"] = int(segment_template_data.get("@timescale", 1))
        except (ValueError, TypeError):
            profile["segment_template_timescale"] = 1
    else:
        profile["segment_template_start_number"] = 1
        profile["segment_template_start_number_explicit"] = False

    # For SegmentBase profiles, we need to set initUrl even when not parsing segments
    # This is needed for the HLS playlist builder to reference the init URL
    segment_base_data = representation.get("SegmentBase")
    if segment_base_data and "initUrl" not in profile:
        base_url = representation.get("BaseURL", "")
        profile["initUrl"] = resolve_url(mpd_url, base_url)

        # Store initialization range if available
        if "Initialization" in segment_base_data:
            init_range = segment_base_data["Initialization"].get("@range")
            if init_range:
                profile["initRange"] = init_range

    # For SegmentList profiles, we also need to set initUrl even when not parsing segments
    segment_list_data = representation.get("SegmentList") or adaptation.get("SegmentList")
    if segment_list_data and "initUrl" not in profile:
        if "Initialization" in segment_list_data:
            init_data = segment_list_data["Initialization"]
            if "@sourceURL" in init_data:
                init_url = init_data["@sourceURL"]
                profile["initUrl"] = resolve_url(mpd_url, init_url)
            elif "@range" in init_data:
                base_url = representation.get("BaseURL", "")
                profile["initUrl"] = resolve_url(mpd_url, base_url)
                profile["initRange"] = init_data["@range"]

    if parse_segment_profile_id is None or profile["id"] != parse_segment_profile_id:
        return profile

    # Parse segments based on the addressing scheme used
    segment_template = adaptation.get("SegmentTemplate") or representation.get("SegmentTemplate")
    segment_list = adaptation.get("SegmentList") or representation.get("SegmentList")

    # Get BaseURL from representation (can be relative path like "a/b/c/")
    base_url = representation.get("BaseURL", "")

    if segment_template:
        profile["segments"] = parse_segment_template(parsed_dict, segment_template, profile, mpd_url, base_url)
    elif segment_list:
        # Get timescale from SegmentList or default to 1
        timescale = int(segment_list.get("@timescale", 1))
        profile["segments"] = parse_segment_list(adaptation, representation, profile, mpd_url, timescale)
    else:
        profile["segments"] = parse_segment_base(representation, profile, mpd_url)

    return profile


def _get_key(adaptation: dict, representation: dict, key: str) -> Optional[str]:
    """
    Retrieves a key from the representation or adaptation set.

    Args:
        adaptation (dict): The adaptation set data.
        representation (dict): The representation data.
        key (str): The key to retrieve.

    Returns:
        Optional[str]: The value of the key or None if not found.
    """
    return representation.get(key, adaptation.get(key, None))


def parse_segment_template(
    parsed_dict: dict, item: dict, profile: dict, mpd_url: str, base_url: str = ""
) -> List[Dict]:
    """
    Parses a segment template and extracts segment information.

    Args:
        parsed_dict (dict): The parsed MPD data.
        item (dict): The segment template data.
        profile (dict): The profile information.
        mpd_url (str): The URL of the MPD manifest.
        base_url (str): The BaseURL from the representation (optional, for per-representation paths).

    Returns:
        List[Dict]: The list of parsed segments.
    """
    segments = []
    timescale = int(item.get("@timescale", 1))
    profile["segment_template_timescale"] = timescale
    profile["segment_template_start_number_explicit"] = "@startNumber" in item
    try:
        profile["segment_template_start_number"] = int(
            item.get("@startNumber", profile.get("segment_template_start_number", 1))
        )
    except (ValueError, TypeError):
        profile["segment_template_start_number"] = 1

    # Initialization
    if "@initialization" in item:
        media = item["@initialization"]
        media = media.replace("$RepresentationID$", profile["id"])
        media = media.replace("$Bandwidth$", str(profile["bandwidth"]))
        # Combine base_url and media, then resolve against mpd_url
        if base_url:
            media = base_url + media
        profile["initUrl"] = resolve_url(mpd_url, media)

    # Segments
    if "SegmentTimeline" in item:
        segments.extend(parse_segment_timeline(parsed_dict, item, profile, mpd_url, timescale, base_url))
    elif "@duration" in item:
        try:
            profile["nominal_duration_mpd_timescale"] = int(item["@duration"])
        except (ValueError, TypeError):
            pass
        segments.extend(parse_segment_duration(parsed_dict, item, profile, mpd_url, timescale, base_url))

    return segments


def parse_segment_timeline(
    parsed_dict: dict, item: dict, profile: dict, mpd_url: str, timescale: int, base_url: str = ""
) -> List[Dict]:
    """
    Parses a segment timeline and extracts segment information.

    Args:
        parsed_dict (dict): The parsed MPD data.
        item (dict): The segment timeline data.
        profile (dict): The profile information.
        mpd_url (str): The URL of the MPD manifest.
        timescale (int): The timescale for the segments.
        base_url (str): The BaseURL from the representation (optional, for per-representation paths).

    Returns:
        List[Dict]: The list of parsed segments.
    """
    timelines = item["SegmentTimeline"]["S"]
    timelines = timelines if isinstance(timelines, list) else [timelines]
    period_start = parsed_dict.get("availabilityStartTime", datetime.fromtimestamp(0, tz=timezone.utc)) + timedelta(
        seconds=parsed_dict.get("PeriodStart", 0)
    )
    presentation_time_offset = int(item.get("@presentationTimeOffset", 0))
    start_number = int(item.get("@startNumber", 1))

    timeline_segments = preprocess_timeline(timelines, start_number, period_start, presentation_time_offset, timescale)

    nominal_duration = _resolve_nominal_timeline_duration(timeline_segments)
    if nominal_duration:
        profile["nominal_duration_mpd_timescale"] = nominal_duration

    segments = [
        create_segment_data(timeline, item, profile, mpd_url, timescale, base_url) for timeline in timeline_segments
    ]
    return segments


def _resolve_nominal_timeline_duration(timeline_segments: List[Dict]) -> Optional[int]:
    """
    Resolve a stable nominal segment duration from expanded SegmentTimeline entries.

    Live timelines often contain occasional shorter segments; using median keeps
    sequence calculations stable when the window slides.
    """
    durations = []
    for segment in timeline_segments:
        duration = segment.get("duration_mpd_timescale")
        if isinstance(duration, (int, float)) and duration > 0:
            durations.append(int(duration))

    if not durations:
        return None
    return int(statistics.median_low(durations))


def preprocess_timeline(
    timelines: List[Dict], start_number: int, period_start: datetime, presentation_time_offset: int, timescale: int
) -> List[Dict]:
    """
    Preprocesses the segment timeline data.

    Args:
        timelines (List[Dict]): The list of timeline segments.
        start_number (int): The starting segment number.
        period_start (datetime): The start time of the period.
        presentation_time_offset (int): The presentation time offset.
        timescale (int): The timescale for the segments.

    Returns:
        List[Dict]: The list of preprocessed timeline segments.
    """
    processed_data = []
    current_time = 0
    for timeline in timelines:
        repeat = int(timeline.get("@r", 0))
        duration = int(timeline["@d"])
        start_time = int(timeline.get("@t", current_time))

        for _ in range(repeat + 1):
            segment_start_time = period_start + timedelta(seconds=(start_time - presentation_time_offset) / timescale)
            segment_end_time = segment_start_time + timedelta(seconds=duration / timescale)
            processed_data.append(
                {
                    "number": start_number,
                    "start_time": segment_start_time,
                    "end_time": segment_end_time,
                    "duration": duration,
                    "time": start_time,
                    "duration_mpd_timescale": duration,
                }
            )
            start_time += duration
            start_number += 1

        current_time = start_time

    return processed_data


def parse_segment_duration(
    parsed_dict: dict, item: dict, profile: dict, mpd_url: str, timescale: int, base_url: str = ""
) -> List[Dict]:
    """
    Parses segment duration and extracts segment information.
    This is used for static or live MPD manifests.

    Args:
        parsed_dict (dict): The parsed MPD data.
        item (dict): The segment duration data.
        profile (dict): The profile information.
        mpd_url (str): The URL of the MPD manifest.
        timescale (int): The timescale for the segments.
        base_url (str): The BaseURL from the representation (optional, for per-representation paths).

    Returns:
        List[Dict]: The list of parsed segments.
    """
    duration = int(item["@duration"])
    start_number = int(item.get("@startNumber", 1))
    presentation_time_offset = int(item.get("@presentationTimeOffset", 0))
    segment_duration_sec = duration / timescale

    if parsed_dict["isLive"]:
        profile["nominal_duration_mpd_timescale"] = duration
        segments = generate_live_segments(
            parsed_dict,
            segment_duration_sec,
            start_number,
            duration_mpd_timescale=duration,
            presentation_time_offset=presentation_time_offset,
        )
    else:
        segments = generate_vod_segments(profile, duration, timescale, start_number)

    return [create_segment_data(seg, item, profile, mpd_url, timescale, base_url) for seg in segments]


def generate_live_segments(
    parsed_dict: dict,
    segment_duration_sec: float,
    start_number: int,
    duration_mpd_timescale: Optional[int] = None,
    presentation_time_offset: int = 0,
) -> List[Dict]:
    """
    Generates live segments based on the segment duration and start number.
    This is used for live MPD manifests.

    Args:
        parsed_dict (dict): The parsed MPD data.
        segment_duration_sec: The segment duration in seconds.
        start_number: The starting segment number.
        duration_mpd_timescale: Segment duration in MPD timescale units.
        presentation_time_offset: MPD presentationTimeOffset, in timescale units.

    Returns:
        List[Dict]: The list of generated live segments.
    """
    time_shift_buffer_depth = timedelta(seconds=parsed_dict.get("timeShiftBufferDepth", 60))
    segment_count = math.ceil(time_shift_buffer_depth.total_seconds() / segment_duration_sec)
    current_time = datetime.now(tz=timezone.utc)
    earliest_segment_number = max(
        start_number
        + math.floor((current_time - parsed_dict["availabilityStartTime"]).total_seconds() / segment_duration_sec)
        - segment_count,
        start_number,
    )

    segments = []
    for number in range(earliest_segment_number, earliest_segment_number + segment_count):
        start_time = parsed_dict["availabilityStartTime"] + timedelta(
            seconds=(number - start_number) * segment_duration_sec
        )
        segment = {
            "number": number,
            "start_time": start_time,
            "end_time": start_time + timedelta(seconds=segment_duration_sec),
            "duration": duration_mpd_timescale if duration_mpd_timescale is not None else segment_duration_sec,
        }
        if duration_mpd_timescale is not None:
            segment["duration_mpd_timescale"] = duration_mpd_timescale
            segment["time"] = presentation_time_offset + (number - start_number) * duration_mpd_timescale
        segments.append(segment)
    return segments


def generate_vod_segments(profile: dict, duration: int, timescale: int, start_number: int) -> List[Dict]:
    """
    Generates VOD segments based on the segment duration and start number.
    This is used for static MPD manifests.

    Args:
        profile (dict): The profile information.
        duration (int): The segment duration.
        timescale (int): The timescale for the segments.
        start_number (int): The starting segment number.

    Returns:
        List[Dict]: The list of generated VOD segments.
    """
    total_duration = profile.get("mediaPresentationDuration") or 0
    if isinstance(total_duration, str):
        total_duration = parse_duration(total_duration)
    segment_count = math.ceil(total_duration * timescale / duration)

    return [{"number": start_number + i, "duration": duration / timescale} for i in range(segment_count)]


def create_segment_data(
    segment: Dict, item: dict, profile: dict, mpd_url: str, timescale: Optional[int] = None, base_url: str = ""
) -> Dict:
    """
    Creates segment data based on the segment information. This includes the segment URL and metadata.

    Args:
        segment (Dict): The segment information.
        item (dict): The segment template data.
        profile (dict): The profile information.
        mpd_url (str): The URL of the MPD manifest.
        timescale (int, optional): The timescale for the segments. Defaults to None.
        base_url (str): The BaseURL from the representation (optional, for per-representation paths).

    Returns:
        Dict: The created segment data.
    """
    media_template = item["@media"]
    media = media_template.replace("$RepresentationID$", profile["id"])
    media = media.replace("$Number%04d$", f"{segment['number']:04d}")
    media = media.replace("$Number$", str(segment["number"]))
    media = media.replace("$Bandwidth$", str(profile["bandwidth"]))

    if "$Time$" in media and timescale is not None:
        time_value = None
        if "time" in segment:
            time_value = int(segment["time"])
        else:
            duration_mpd_timescale = segment.get("duration_mpd_timescale")
            if duration_mpd_timescale is None:
                try:
                    duration_mpd_timescale = int(item.get("@duration", 0))
                except (TypeError, ValueError):
                    duration_mpd_timescale = 0
            if duration_mpd_timescale:
                try:
                    start_number = int(item.get("@startNumber", profile.get("segment_template_start_number", 1)))
                except (TypeError, ValueError):
                    start_number = profile.get("segment_template_start_number", 1)
                try:
                    presentation_time_offset = int(item.get("@presentationTimeOffset", 0))
                except (TypeError, ValueError):
                    presentation_time_offset = 0
                time_value = presentation_time_offset + (int(segment["number"]) - start_number) * int(
                    duration_mpd_timescale
                )

        if time_value is not None:
            media = media.replace("$Time$", str(time_value))

    if "$Time$" in media:
        logger.warning("Unresolved $Time$ placeholder in segment URL template: %s", media_template)

    # Combine base_url and media, then resolve against mpd_url
    if base_url:
        media = base_url + media
    media = resolve_url(mpd_url, media)

    segment_data = {
        "type": "segment",
        "media": media,
        "number": segment["number"],
    }

    # Add time and duration metadata for adaptive sequence calculation
    if "time" in segment:
        segment_data["time"] = segment["time"]
    if "duration_mpd_timescale" in segment:
        segment_data["duration_mpd_timescale"] = segment["duration_mpd_timescale"]
    elif "time" in segment and "duration" in segment and timescale is not None:
        segment_data["duration_mpd_timescale"] = segment["duration"]

    if "start_time" in segment and "end_time" in segment:
        segment_data.update(
            {
                "start_time": segment["start_time"],
                "end_time": segment["end_time"],
                "extinf": (segment["end_time"] - segment["start_time"]).total_seconds(),
                "program_date_time": segment["start_time"].isoformat() + "Z",
            }
        )
    elif "start_time" in segment and "duration" in segment:
        duration_mpd_timescale = segment.get("duration_mpd_timescale")
        if duration_mpd_timescale is not None and timescale:
            duration_seconds = duration_mpd_timescale / timescale
        elif "time" in segment and timescale:
            # Timeline-based segments store duration in MPD timescale units.
            duration_seconds = segment["duration"] / timescale
        else:
            duration_seconds = segment["duration"]
        segment_data.update(
            {
                "start_time": segment["start_time"],
                "end_time": segment["start_time"] + timedelta(seconds=duration_seconds),
                "extinf": duration_seconds,
                "program_date_time": segment["start_time"].isoformat() + "Z",
            }
        )
    elif "duration" in segment:
        # duration from generate_vod_segments and generate_live_segments is already in seconds
        segment_data["extinf"] = segment["duration"]

    return segment_data


def parse_segment_list(
    adaptation: dict, representation: dict, profile: dict, mpd_url: str, timescale: int
) -> List[Dict]:
    """
    Parses SegmentList element with explicit SegmentURL entries.

    SegmentList MPDs explicitly list each segment URL, unlike SegmentTemplate which uses
    URL patterns. This is less common but used by some packagers.

    Args:
        adaptation (dict): The adaptation set data.
        representation (dict): The representation data.
        profile (dict): The profile information.
        mpd_url (str): The URL of the MPD manifest.
        timescale (int): The timescale for duration calculations.

    Returns:
        List[Dict]: The list of parsed segments.
    """
    # SegmentList can be at AdaptationSet or Representation level
    segment_list = representation.get("SegmentList") or adaptation.get("SegmentList", {})
    segments = []

    # Handle Initialization element
    if "Initialization" in segment_list:
        init_data = segment_list["Initialization"]
        if "@sourceURL" in init_data:
            init_url = init_data["@sourceURL"]
            profile["initUrl"] = resolve_url(mpd_url, init_url)
        elif "@range" in init_data:
            # Initialization by byte range on the BaseURL
            base_url = representation.get("BaseURL", "")
            profile["initUrl"] = resolve_url(mpd_url, base_url)
            profile["initRange"] = init_data["@range"]

    # Get segment duration from SegmentList attributes
    duration = int(segment_list.get("@duration", 0))
    list_timescale = int(segment_list.get("@timescale", timescale or 1))
    segment_duration_sec = duration / list_timescale if list_timescale else 0

    # Parse SegmentURL elements
    segment_urls = segment_list.get("SegmentURL", [])
    if not isinstance(segment_urls, list):
        segment_urls = [segment_urls]

    for i, seg_url in enumerate(segment_urls):
        if seg_url is None:
            continue

        # Get media URL - can be @media attribute or use BaseURL with @mediaRange
        media_url = seg_url.get("@media", "")
        media_range = seg_url.get("@mediaRange")

        if media_url:
            media_url = resolve_url(mpd_url, media_url)
        else:
            # Use BaseURL with byte range
            base_url = representation.get("BaseURL", "")
            media_url = resolve_url(mpd_url, base_url)

        segment_data = {
            "type": "segment",
            "media": media_url,
            "number": i + 1,
            "extinf": segment_duration_sec if segment_duration_sec > 0 else 1.0,
        }

        # Include media range if specified
        if media_range:
            segment_data["mediaRange"] = media_range

        segments.append(segment_data)

    return segments


def parse_segment_base(representation: dict, profile: dict, mpd_url: str) -> List[Dict]:
    """
    Parses segment base information and extracts segment data. This is used for single-segment representations
    (SegmentBase MPDs, typically GPAC-generated on-demand profiles).

    For SegmentBase, the entire media file is treated as a single segment. The initialization data
    is specified by the Initialization element's range, and the segment index (SIDX) is at indexRange.

    Args:
        representation (dict): The representation data.
        profile (dict): The profile information.
        mpd_url (str): The URL of the MPD manifest.

    Returns:
        List[Dict]: The list of parsed segments.
    """
    segment = representation.get("SegmentBase", {})
    base_url = representation.get("BaseURL", "")

    # Build the full media URL
    media_url = resolve_url(mpd_url, base_url)

    # Set initUrl for SegmentBase - this is the URL with the initialization range
    # The initialization segment contains codec/track info needed before playing media
    profile["initUrl"] = media_url

    # For SegmentBase, we need to specify byte ranges for init and media segments
    init_range = None
    if "Initialization" in segment:
        init_range = segment["Initialization"].get("@range")

    # Store initialization range in profile for segment endpoint to use
    if init_range:
        profile["initRange"] = init_range

    # Get the index range which points to SIDX box
    index_range = segment.get("@indexRange", "")

    # Calculate total duration from profile's mediaPresentationDuration
    total_duration = profile.get("mediaPresentationDuration")
    if isinstance(total_duration, str):
        total_duration = parse_duration(total_duration)
    elif total_duration is None:
        total_duration = 0

    # For SegmentBase, we return a single segment representing the entire media
    # The media URL is the same as initUrl but will be accessed with different byte ranges
    return [
        {
            "type": "segment",
            "media": media_url,
            "number": 1,
            "extinf": total_duration if total_duration > 0 else 1.0,
            "indexRange": index_range,
            "initRange": init_range,
        }
    ]


def parse_duration(duration_str: str) -> float:
    """
    Parses a duration ISO 8601 string into seconds.

    Args:
        duration_str (str): The duration string to parse.

    Returns:
        float: The parsed duration in seconds.
    """
    pattern = re.compile(r"P(?:(\d+)Y)?(?:(\d+)M)?(?:(\d+)D)?T?(?:(\d+)H)?(?:(\d+)M)?(?:(\d+(?:\.\d+)?)S)?")
    match = pattern.match(duration_str)
    if not match:
        raise ValueError(f"Invalid duration format: {duration_str}")

    years, months, days, hours, minutes, seconds = [float(g) if g else 0 for g in match.groups()]
    return years * 365 * 24 * 3600 + months * 30 * 24 * 3600 + days * 24 * 3600 + hours * 3600 + minutes * 60 + seconds
