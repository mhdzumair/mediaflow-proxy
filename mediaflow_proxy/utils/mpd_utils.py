import logging
import math
import re
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Optional, Union
from urllib.parse import urljoin

import xmltodict

logger = logging.getLogger(__name__)


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
    source = "/".join(mpd_url.split("/")[:-1])

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
        for adaptation in period["AdaptationSet"]:
            representations = adaptation["Representation"]
            representations = representations if isinstance(representations, list) else [representations]

            for representation in representations:
                profile = parse_representation(
                    parsed_dict,
                    representation,
                    adaptation,
                    source,
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
    source: str,
    media_presentation_duration: str,
    parse_segment_profile_id: Optional[str],
) -> Optional[dict]:
    """
    Parses a representation and extracts profile information.

    Args:
        parsed_dict (dict): The parsed MPD data.
        representation (dict): The representation data.
        adaptation (dict): The adaptation set data.
        source (str): The source URL.
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

    if parse_segment_profile_id is None or profile["id"] != parse_segment_profile_id:
        return profile

    item = adaptation.get("SegmentTemplate") or representation.get("SegmentTemplate")
    if item:
        profile["segments"] = parse_segment_template(parsed_dict, item, profile, source)
    else:
        profile["segments"] = parse_segment_base(representation, source)

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


def parse_segment_template(parsed_dict: dict, item: dict, profile: dict, source: str) -> List[Dict]:
    """
    Parses a segment template and extracts segment information.

    Args:
        parsed_dict (dict): The parsed MPD data.
        item (dict): The segment template data.
        profile (dict): The profile information.
        source (str): The source URL.

    Returns:
        List[Dict]: The list of parsed segments.
    """
    segments = []
    timescale = int(item.get("@timescale", 1))

    # Initialization
    if "@initialization" in item:
        media = item["@initialization"]
        media = media.replace("$RepresentationID$", profile["id"])
        media = media.replace("$Bandwidth$", str(profile["bandwidth"]))
        if not media.startswith("http"):
            media = f"{source}/{media}"
        profile["initUrl"] = media

    # Segments
    if "SegmentTimeline" in item:
        segments.extend(parse_segment_timeline(parsed_dict, item, profile, source, timescale))
    elif "@duration" in item:
        segments.extend(parse_segment_duration(parsed_dict, item, profile, source, timescale))

    return segments


def parse_segment_timeline(parsed_dict: dict, item: dict, profile: dict, source: str, timescale: int) -> List[Dict]:
    """
    Parses a segment timeline and extracts segment information.
    """
    timelines = item["SegmentTimeline"]["S"]
    timelines = timelines if isinstance(timelines, list) else [timelines]
    
    # availabilityStartTime for the current period.
    # parsed_dict["availabilityStartTime"] is the global MPD AST.
    # parsed_dict["PeriodStart"] is the offset of the current period from AST.
    # So, period_start_time is effectively MPD_AST + Period@start.
    period_start_time_abs = parsed_dict.get("availabilityStartTime", datetime.fromtimestamp(0, tz=timezone.utc)) + timedelta(
        seconds=parsed_dict.get("PeriodStart", 0)
    )
    
    presentation_time_offset = int(item.get("@presentationTimeOffset", 0))
    start_number = int(item.get("@startNumber", 1))

    # Pass the main parsed_dict (which contains 'isLive', 'timeShiftBufferDepth' etc.) 
    # to preprocess_timeline
    processed_timeline_entries = preprocess_timeline(
        parsed_dict, # <--- PASSING THE GLOBAL MPD PARSED DICT
        timelines, 
        start_number, 
        period_start_time_abs, # This is the absolute start time of the current period
        presentation_time_offset, 
        timescale
    )
    
    segments = [
        create_segment_data(processed_entry, item, profile, source, timescale) # Use 'timescale' here if S@d was in timescale units
        for processed_entry in processed_timeline_entries
    ]
    return segments


def preprocess_timeline(
    parsed_dict_global: dict, # Renamed from parsed_dict to avoid confusion with local vars if any
    timelines: List[Dict], 
    start_number: int, 
    period_start_abs: datetime, # Absolute start time of the current MPD Period
    presentation_time_offset: int, # From SegmentTemplate, usually 0 if not present
    timescale: int # From SegmentTemplate
) -> List[Dict]:
    processed_data = []
    current_s_time_value_in_timescale_units = 0 
    
    for s_element_index, timeline_entry in enumerate(timelines):
        s_t_value_ts_units = int(timeline_entry.get("@t", current_s_time_value_in_timescale_units))
        s_d_value_ts_units = int(timeline_entry["@d"])
        s_r_value = int(timeline_entry.get("@r", 0))

        segment_duration_seconds = s_d_value_ts_units / float(timescale)

        for i in range(s_r_value + 1):
            # current_segment_t_value_ts_units is the value for $Time$ if media uses $Time$
            # It's relative to the Period start + presentationTimeOffset, in timescale units.
            current_segment_t_value_ts_units = s_t_value_ts_units + (i * s_d_value_ts_units)
            
            # Absolute presentation time for this segment
            # PDT = PeriodStart_abs + ( (S@t + (i*S@d) - PTO) / timescale )
            # Note: S@t values in Sky manifest are very large, suggesting they might be
            # absolute timestamps in some unit (e.g. ms relative to an epoch) rather than
            # relative to period start in 'timescale' units.
            # If S@t is epoch_ms:
            #   segment_pdt_abs = datetime.fromtimestamp(current_segment_t_value_ts_units / 1000.0, tz=timezone.utc)
            #   This was one of the previous hypotheses.
            # If S@t is relative to Period start (after PTO adjustment) in 'timescale' units:
            segment_start_offset_seconds = (current_segment_t_value_ts_units - presentation_time_offset) / float(timescale)
            segment_pdt_abs = period_start_abs + timedelta(seconds=segment_start_offset_seconds)
            
            # This will be used for $Time$ in the segment URL template
            time_for_url = current_segment_t_value_ts_units

            processed_data.append(
                {
                    "number": time_for_url, # Tentatively use this as a unique increasing number; may need refinement for HLS media sequence.
                    "program_date_time": segment_pdt_abs.isoformat().replace("+00:00", "Z"),
                    "extinf": segment_duration_seconds,
                    "time_val": time_for_url, # Value for $Time$ in URL
                    # Storing original S@d in timescale units might be useful
                    "s_d_timescale": s_d_value_ts_units,
                }
            )
        current_s_time_value_in_timescale_units = s_t_value_ts_units + ((s_r_value + 1) * s_d_value_ts_units)

    processed_data.sort(key=lambda x: x["time_val"])

    # Filter out segments that are too old based on timeShiftBufferDepth
    if parsed_dict_global.get("isLive") and processed_data:
        time_shift_buffer_depth_seconds = parsed_dict_global.get("timeShiftBufferDepth", 180.0)
        
        # Use MPD@publishTime if available and more reliable, otherwise fallback to current server time
        # availabilityStartTime is the AST of the whole MPD
        mpd_availability_start_time = parsed_dict_global.get("availabilityStartTime", datetime.now(tz=timezone.utc) - timedelta(seconds=time_shift_buffer_depth_seconds))

        # The actual current live edge can be estimated from MPD publish time or server current time.
        # Let's use a simple method: segments whose PDT is older than (now - buffer_depth) are removed.
        # Consider using MPD@publishTime for 'now' if server clocks can drift.
        # For Sky, `publishTime` is available.
        effective_now = parsed_dict_global.get("publishTime", datetime.now(tz=timezone.utc))

        earliest_allowed_pdt = effective_now - timedelta(seconds=time_shift_buffer_depth_seconds)
        
        final_segments = [
            seg for seg in processed_data 
            if datetime.fromisoformat(seg["program_date_time"].replace("Z", "+00:00")) >= earliest_allowed_pdt
        ]
        
        # If filtering removed everything (e.g., due to clock sync issues or very short buffer),
        # keep a few of the latest segments from the original list to avoid empty playlists.
        if not final_segments and processed_data:
            final_segments = processed_data[-min(5, len(processed_data)):] 
        
        # Refine HLS media sequence numbering for the final list of segments
        if final_segments:
            # A common way is to base EXT-X-MEDIA-SEQUENCE on the timestamp of the first segment.
            # If S@d is constant, media_sequence = floor(S@t / S@d)
            first_segment_s_d_ts = final_segments[0].get("s_d_timescale", timescale * 5) # Default to 5s if not there
            if first_segment_s_d_ts <= 0: first_segment_s_d_ts = timescale * 5 # Avoid division by zero

            base_hls_sequence = int(final_segments[0]["time_val"] / first_segment_s_d_ts)
            
            for idx, seg_data in enumerate(final_segments):
                # This makes hls_media_sequence_num contiguous for the current playlist
                seg_data["hls_media_sequence_num"] = base_hls_sequence + idx
                # 'number' in create_segment_data should use 'time_val' for $Time$
                # but the M3U8 #EXT-X-MEDIA-SEQUENCE tag should use this hls_media_sequence_num
                # from the first segment of the playlist.
        
        return final_segments

    return processed_data


def parse_segment_duration(parsed_dict: dict, item: dict, profile: dict, source: str, timescale: int) -> List[Dict]:
    """
    Parses segment duration and extracts segment information.
    This is used for static or live MPD manifests.

    Args:
        parsed_dict (dict): The parsed MPD data.
        item (dict): The segment duration data.
        profile (dict): The profile information.
        source (str): The source URL.
        timescale (int): The timescale for the segments.

    Returns:
        List[Dict]: The list of parsed segments.
    """
    duration = int(item["@duration"])
    start_number = int(item.get("@startNumber", 1))
    segment_duration_sec = duration / timescale

    if parsed_dict["isLive"]:
        segments = generate_live_segments(parsed_dict, segment_duration_sec, start_number)
    else:
        segments = generate_vod_segments(profile, duration, timescale, start_number)

    return [create_segment_data(seg, item, profile, source, timescale) for seg in segments]


def generate_live_segments(parsed_dict: dict, segment_duration_sec: float, start_number: int) -> List[Dict]:
    """
    Generates live segments based on the segment duration and start number.
    This is used for live MPD manifests.

    Args:
        parsed_dict (dict): The parsed MPD data.
        segment_duration_sec (float): The segment duration in seconds.
        start_number (int): The starting segment number.

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

    return [
        {
            "number": number,
            "start_time": parsed_dict["availabilityStartTime"]
            + timedelta(seconds=(number - start_number) * segment_duration_sec),
            "duration": segment_duration_sec,
        }
        for number in range(earliest_segment_number, earliest_segment_number + segment_count)
    ]


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


# in mediaflow_proxy/utils/mpd_utils.py

def create_segment_data(segment_input: Dict, item: dict, profile: dict, source: str, timescale: Optional[int] = None) -> Dict:
    """
    Creates segment data for HLS playlist, ensuring essential fields like 'extinf' and 'media' URL.
    'segment_input' is the dictionary from preprocess_timeline.
    'item' is the SegmentTemplate dictionary from the MPD.
    'profile' is the profile dictionary.
    'source' is the base URL for resolving relative paths.
    'timescale' is from SegmentTemplate (used if we need to calculate duration from timescale units).
    """
    media_template = item["@media"] # e.g., "$RepresentationID$/$Time$.m4s"
    media = media_template.replace("$RepresentationID$", profile["id"])
    media = media.replace("$Bandwidth$", str(profile["bandwidth"]))

    # $Time$ or $Number$ substitution
    if "$Time$" in media_template and "time_val" in segment_input:
        media = media.replace("$Time$", str(int(segment_input["time_val"])))
    elif "$Number%04d$" in media_template and "hls_media_sequence_num" in segment_input: # Prefer HLS sequence for $Number$
        media = media.replace("$Number%04d$", f"{segment_input['hls_media_sequence_num']:04d}")
    elif "$Number$" in media_template and "hls_media_sequence_num" in segment_input:
        media = media.replace("$Number$", str(segment_input["hls_media_sequence_num"]))
    # Fallback se hls_media_sequence_num non c'è ma number c'è (meno probabile con la logica attuale)
    elif "$Number%04d$" in media_template and "number" in segment_input:
         media = media.replace("$Number%04d$", f"{segment_input['number']:04d}")
    elif "$Number$" in media_template and "number" in segment_input:
         media = media.replace("$Number$", str(segment_input["number"]))


    if not media.startswith("http"):
        media = f"{source}/{media}"

    # Initialize segment_data with values directly from segment_input if they exist
    # This ensures 'extinf', 'program_date_time' from preprocess_timeline are preserved.
    segment_data = {
        "type": "segment", # DASH type, not strictly for HLS but can keep for internal consistency
        "media": media,    # This is the final URL for the HLS segment
        # Copy all relevant pre-calculated HLS data from segment_input
        "extinf": segment_input.get("extinf"),
        "program_date_time": segment_input.get("program_date_time"),
        "number": segment_input.get("number"), # Original number/time_val, useful for debugging
        "hls_media_sequence_num": segment_input.get("hls_media_sequence_num"), # For EXT-X-MEDIA-SEQUENCE
        "time_val": segment_input.get("time_val") # Original $Time$ value
    }

    # Remove keys with None values to keep the dictionary clean, build_hls_playlist will check existence
    segment_data = {k: v for k, v in segment_data.items() if v is not None}

    # The old logic for calculating extinf based on 'range' or 'duration' is not applicable here
    # because preprocess_timeline already provides 'extinf' in seconds.
    # We ensure that 'extinf' from segment_input is used. If it's missing from segment_input,
    # build_hls_playlist will fail, which is correct as extinf is mandatory.

    return segment_data


def parse_segment_base(representation: dict, source: str) -> List[Dict]:
    """
    Parses segment base information and extracts segment data. This is used for single-segment representations.

    Args:
        representation (dict): The representation data.
        source (str): The source URL.

    Returns:
        List[Dict]: The list of parsed segments.
    """
    segment = representation["SegmentBase"]
    start, end = map(int, segment["@indexRange"].split("-"))
    if "Initialization" in segment:
        start, _ = map(int, segment["Initialization"]["@range"].split("-"))

    return [
        {
            "type": "segment",
            "range": f"{start}-{end}",
            "media": f"{source}/{representation['BaseURL']}",
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
