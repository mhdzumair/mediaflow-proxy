import logging
import math
import re
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Optional, Union
from urllib.parse import urljoin

import xmltodict

logger = logging.getLogger(__name__)


def parse_mpd(mpd_content: Union[str, bytes]) -> dict:
    """Parses the MPD content into a dictionary."""
    return xmltodict.parse(mpd_content)


def detect_provider_and_characteristics(mpd_url: str, mpd_dict: dict) -> Dict[str, Union[str, bool]]:
    """
    Rileva automaticamente il provider e le sue caratteristiche basandosi su URL e contenuto MPD.

    Returns:
        Dict con 'provider' e caratteristiche booleane per adattare la logica
    """
    mpd_url_lower = mpd_url.lower()
    characteristics = {
        "provider": "generic",
        "needs_pdt_correction": False,
        "uses_hls_sequence": False,
        "requires_strict_filtering": False,
    }

    # Rilevamento provider basato su URL
    if "skycdn.it" in mpd_url_lower or "sky" in mpd_url_lower:
        characteristics.update({"provider": "sky", "uses_hls_sequence": True, "requires_strict_filtering": True})
    elif "aiv-cdn.net" in mpd_url_lower or "dazn" in mpd_url_lower:
        characteristics.update({"provider": "dazn", "needs_pdt_correction": True})

    # Rilevamento automatico di problemi indipendentemente dal provider
    # Se l'MPD ha timescale molto grandi o valori @t enormi, probabilmente ha problemi di timeline
    try:
        periods = mpd_dict.get("MPD", {}).get("Period", [])
        if not isinstance(periods, list):
            periods = [periods]

        for period in periods:
            adaptations = period.get("AdaptationSet", [])
            if not isinstance(adaptations, list):
                adaptations = [adaptations]

            for adaptation in adaptations:
                representations = adaptation.get("Representation", [])
                if not isinstance(representations, list):
                    representations = [representations]

                for repr in representations:
                    segment_template = adaptation.get("SegmentTemplate") or repr.get("SegmentTemplate")
                    if segment_template and "SegmentTimeline" in segment_template:
                        s_entries = segment_template["SegmentTimeline"].get("S", [])
                        if not isinstance(s_entries, list):
                            s_entries = [s_entries]

                        if s_entries:
                            first_t = int(s_entries[0].get("@t", 0))
                            timescale = int(segment_template.get("@timescale", 1))

                            # Se il primo @t convertito in secondi è molto grande, probabilmente sono timestamp assoluti
                            if first_t / timescale > 365 * 24 * 3600:  # > 1 anno in secondi
                                characteristics["needs_pdt_correction"] = True
                                logger.info(
                                    f"Rilevati possibili timestamp assoluti nel provider {characteristics['provider']}"
                                )
    except Exception as e:
        logger.warning(f"Errore nel rilevamento automatico caratteristiche: {e}")

    return characteristics


def parse_mpd_dict(
    mpd_dict: dict, mpd_url: str, parse_drm: bool = True, parse_segment_profile_id: Optional[str] = None
) -> dict:
    """Parses the MPD dictionary and extracts relevant information with automatic provider detection."""
    profiles = []
    parsed_dict = {}
    source = "/".join(mpd_url.split("/")[:-1])

    # Rilevamento automatico provider e caratteristiche
    provider_info = detect_provider_and_characteristics(mpd_url, mpd_dict)
    parsed_dict.update(provider_info)

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
        if mpd_dict["MPD"].get("@publishTime"):
            parsed_dict["publishTime"] = datetime.fromisoformat(mpd_dict["MPD"]["@publishTime"].replace("Z", "+00:00"))

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


def parse_segment_timeline(parsed_dict: dict, item: dict, profile: dict, source: str, timescale: int) -> List[Dict]:
    """
    Parses a segment timeline with unified logic that automatically adapts to provider characteristics.
    """
    timelines = item["SegmentTimeline"]["S"]
    timelines = timelines if isinstance(timelines, list) else [timelines]

    # Calculate period start time
    period_start_time = parsed_dict.get(
        "availabilityStartTime", datetime.fromtimestamp(0, tz=timezone.utc)
    ) + timedelta(seconds=parsed_dict.get("PeriodStart", 0))

    presentation_time_offset = int(item.get("@presentationTimeOffset", 0))
    start_number = int(item.get("@startNumber", 1))

    # Usa la logica unificata che si adatta automaticamente
    processed_timeline_entries = preprocess_timeline_unified(
        timelines, start_number, period_start_time, presentation_time_offset, timescale, parsed_dict
    )

    segments = [
        create_segment_data_unified(processed_entry, item, profile, source, timescale, parsed_dict)
        for processed_entry in processed_timeline_entries
    ]
    return segments


def preprocess_timeline_unified(
    s_tag_list_from_mpd: List[Dict],
    absolute_start_number_of_template: int,
    mpd_period_wall_clock_start: datetime,
    presentation_time_offset_val: int,
    timescale: int,
    main_mpd_context: dict,
) -> List[Dict]:
    """
    Logica unificata che rileva automaticamente se servono correzioni PDT e applica la strategia appropriata.
    """

    all_segments_generated_from_s_tags = []
    current_mpd_internal_time_for_s_tag = 0
    current_absolute_seg_num = absolute_start_number_of_template

    # Rilevamento automatico della necessità di correzione PDT
    perform_pdt_override = False
    pdt_override_actual_start_time_for_hls_block = None

    # Solo per stream live e se ci sono S tags da processare
    if main_mpd_context.get("isLive") and s_tag_list_from_mpd:
        first_s_tag_t_val = int(s_tag_list_from_mpd[0].get("@t", 0))

        # Calcola il PDT che l'MPD intende per il primo segmento
        original_first_s_tag_pdt_offset_seconds = (first_s_tag_t_val - presentation_time_offset_val) / timescale
        original_first_s_tag_pdt_start_wall_clock = mpd_period_wall_clock_start + timedelta(
            seconds=original_first_s_tag_pdt_offset_seconds
        )

        current_wall_clock_utc = datetime.now(tz=timezone.utc)

        # Rileva automaticamente se i PDT sono troppo nel futuro (indipendentemente dal provider)
        future_threshold_seconds = max(60, 0.1 * main_mpd_context.get("timeShiftBufferDepth", 3600))

        if original_first_s_tag_pdt_start_wall_clock > (
            current_wall_clock_utc + timedelta(seconds=future_threshold_seconds)
        ):
            logger.warning(
                f"Rilevati PDT futuri per provider {main_mpd_context.get('provider', 'unknown')} "
                f"(inizia {original_first_s_tag_pdt_start_wall_clock}). "
                f"Applico correzione automatica PDT."
            )
            perform_pdt_override = True

            # Calcola la durata totale di tutti i segmenti in questo blocco di S-tag
            total_duration_of_this_s_block_seconds = (
                sum((int(s.get("@r", 0)) + 1) * int(s["@d"]) for s in s_tag_list_from_mpd) / timescale
            )

            # Ancoriamo la fine di questo blocco di segmenti HLS vicino all'ora attuale
            live_edge_anchor_time = current_wall_clock_utc - timedelta(
                seconds=main_mpd_context.get("suggestedPresentationDelay", 2.0)
            )

            # Il PDT del primo segmento in questo blocco inizierà a:
            pdt_override_actual_start_time_for_hls_block = live_edge_anchor_time - timedelta(
                seconds=total_duration_of_this_s_block_seconds
            )

    # Tracking del PDT corrente se stiamo sovrascrivendo
    running_pdt_start_if_overridden = pdt_override_actual_start_time_for_hls_block

    for s_tag in s_tag_list_from_mpd:
        repeat_count = int(s_tag.get("@r", 0))
        duration_val_timescale = int(s_tag["@d"])
        start_time_val_timescale = int(s_tag.get("@t", current_mpd_internal_time_for_s_tag))

        for i in range(repeat_count + 1):
            segment_number_for_url = current_absolute_seg_num + i
            time_for_url_template = start_time_val_timescale - presentation_time_offset_val

            if perform_pdt_override:
                # PDT consecutivi a partire dal tempo di override
                pdt_start_for_this_segment = running_pdt_start_if_overridden
                pdt_end_for_this_segment = pdt_start_for_this_segment + timedelta(
                    seconds=duration_val_timescale / timescale
                )
                running_pdt_start_if_overridden = pdt_end_for_this_segment
            else:
                # Calcolo PDT originale basato sulla timeline MPD
                segment_start_offset_seconds_in_period = (
                    start_time_val_timescale - presentation_time_offset_val
                ) / timescale
                pdt_start_for_this_segment = mpd_period_wall_clock_start + timedelta(
                    seconds=segment_start_offset_seconds_in_period
                )
                pdt_end_for_this_segment = pdt_start_for_this_segment + timedelta(
                    seconds=duration_val_timescale / timescale
                )

            all_segments_generated_from_s_tags.append(
                {
                    "number": segment_number_for_url,
                    "start_time": pdt_start_for_this_segment,
                    "end_time": pdt_end_for_this_segment,
                    "duration": duration_val_timescale,
                    "time": time_for_url_template,
                    "s_d_timescale": duration_val_timescale,
                }
            )
            start_time_val_timescale += duration_val_timescale

        current_absolute_seg_num += repeat_count + 1
        current_mpd_internal_time_for_s_tag = start_time_val_timescale

    # Filtraggio per finestra live (adatta automaticamente la strategia)
    if main_mpd_context.get("isLive") and all_segments_generated_from_s_tags:
        all_segments_generated_from_s_tags = apply_live_window_filtering(
            all_segments_generated_from_s_tags, main_mpd_context, timescale
        )

    return all_segments_generated_from_s_tags


def apply_live_window_filtering(segments: List[Dict], main_mpd_context: dict, timescale: int) -> List[Dict]:
    """
    Applica il filtraggio della finestra live adattandosi automaticamente alle caratteristiche del provider.
    """
    if not segments:
        return segments

    first_segment_duration_val = int(segments[0]["duration"]) if segments else 2 * timescale
    avg_segment_duration_seconds = first_segment_duration_val / timescale

    num_segments_in_live_window = math.ceil(
        main_mpd_context.get("timeShiftBufferDepth", 3599) / avg_segment_duration_seconds
    )

    # Se richiede filtraggio rigoroso (es. Sky), usa il publishTime
    if main_mpd_context.get("requires_strict_filtering", False):
        time_shift_buffer_depth_seconds = main_mpd_context.get("timeShiftBufferDepth", 180.0)
        effective_now = main_mpd_context.get("publishTime", datetime.now(tz=timezone.utc))
        earliest_allowed_pdt = effective_now - timedelta(seconds=time_shift_buffer_depth_seconds)

        filtered_segments = [seg for seg in segments if seg["start_time"] >= earliest_allowed_pdt]

        if not filtered_segments and segments:
            filtered_segments = segments[-min(5, len(segments)) :]

        # Aggiungi numerazione HLS per provider che la usano
        if main_mpd_context.get("uses_hls_sequence", False) and filtered_segments:
            first_segment_s_d_ts = filtered_segments[0].get("s_d_timescale", timescale * 5)
            if first_segment_s_d_ts <= 0:
                first_segment_s_d_ts = timescale * 5

            base_hls_sequence = int(filtered_segments[0]["time"] / first_segment_s_d_ts)

            for idx, seg_data in enumerate(filtered_segments):
                seg_data["hls_media_sequence_num"] = base_hls_sequence + idx

        return filtered_segments
    else:
        # Filtraggio semplice per numero di segmenti
        if len(segments) > num_segments_in_live_window:
            logger.info(f"Tronco la lista HLS da {len(segments)} a {num_segments_in_live_window} segmenti.")
            return segments[-num_segments_in_live_window:]

    return segments


def create_segment_data_unified(
    segment_input: Dict,
    item: dict,
    profile: dict,
    source: str,
    timescale: Optional[int] = None,
    provider_context: dict = None,
) -> Dict:
    """
    Crea i dati del segmento adattandosi automaticamente alle caratteristiche del provider.
    """
    media_template = item["@media"]
    media = media_template.replace("$RepresentationID$", profile["id"])
    media = media.replace("$Bandwidth$", str(profile["bandwidth"]))

    # Gestione URL template con logica unificata
    if "$Time$" in media_template and "time" in segment_input:
        media = media.replace("$Time$", str(int(segment_input["time"])))
    elif "$Number" in media_template:
        # Preferisci hls_media_sequence_num se disponibile (per provider che lo usano)
        if "hls_media_sequence_num" in segment_input:
            if "$Number%04d$" in media_template:
                media = media.replace("$Number%04d$", f"{segment_input['hls_media_sequence_num']:04d}")
            else:
                media = media.replace("$Number$", str(segment_input["hls_media_sequence_num"]))
        else:
            # Fallback al numero normale
            if "$Number%04d$" in media_template:
                media = media.replace("$Number%04d$", f"{segment_input['number']:04d}")
            else:
                media = media.replace("$Number$", str(segment_input["number"]))

    if not media.startswith("http"):
        media = f"{source}/{media}"

    # Costruisci i dati del segmento con logica unificata
    segment_data = {
        "type": "segment",
        "media": media,
        "number": segment_input.get("number"),
    }

    # Aggiungi extinf
    if "duration" in segment_input and timescale:
        segment_data["extinf"] = int(segment_input["duration"]) / timescale

    # Aggiungi program_date_time se disponibile
    if "start_time" in segment_input and isinstance(segment_input["start_time"], datetime):
        segment_data["program_date_time"] = segment_input["start_time"].isoformat().replace("+00:00", "Z")

    # Aggiungi campi specifici per provider che li usano
    if "hls_media_sequence_num" in segment_input:
        segment_data["hls_media_sequence_num"] = segment_input["hls_media_sequence_num"]

    if "time" in segment_input:
        segment_data["time_val"] = segment_input["time"]

    # Rimuovi valori None
    segment_data = {k: v for k, v in segment_data.items() if v is not None}
    return segment_data


# Includi tutte le altre funzioni necessarie (extract_drm_info, parse_representation, etc.)
# senza modifiche sostanziali...


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
    """Extracts DRM information from the MPD periods."""
    drm_info = {"isDrmProtected": False}

    for period in periods:
        adaptation_sets: Union[list[dict], dict] = period.get("AdaptationSet", [])
        if not isinstance(adaptation_sets, list):
            adaptation_sets = [adaptation_sets]

        for adaptation_set in adaptation_sets:
            process_content_protection(adaptation_set.get("ContentProtection", []), drm_info)
            representations: Union[list[dict], dict] = adaptation_set.get("Representation", [])
            if not isinstance(representations, list):
                representations = [representations]

            for representation in representations:
                process_content_protection(representation.get("ContentProtection", []), drm_info)

    if "laUrl" in drm_info and not drm_info["laUrl"].startswith(("http://", "https://")):
        drm_info["laUrl"] = urljoin(mpd_url, drm_info["laUrl"])

    return drm_info


def process_content_protection(content_protection: Union[list[dict], dict], drm_info: dict):
    """Processes the ContentProtection elements to extract DRM information."""
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


# Includi le restanti funzioni (parse_representation, parse_duration, etc.) come negli script originali...


def parse_representation(
    parsed_dict: dict,
    representation: dict,
    adaptation: dict,
    source: str,
    media_presentation_duration: str,
    parse_segment_profile_id: Optional[str],
) -> Optional[dict]:
    """Parses a representation and extracts profile information."""
    mime_type = _get_key(adaptation, representation, "@mimeType") or (
        "video/mp4" if "avc" in representation.get("@codecs", "") else "audio/mp4"
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
        profile["width"] = int(representation.get("@width", adaptation.get("@width", 0)))
        profile["height"] = int(representation.get("@height", adaptation.get("@height", 0)))
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
    """Retrieves a key from the representation or adaptation set."""
    return representation.get(key, adaptation.get(key, None))


def parse_segment_template(parsed_dict: dict, item: dict, profile: dict, source: str) -> List[Dict]:
    """Parses a segment template and extracts segment information."""
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


def parse_segment_duration(parsed_dict: dict, item: dict, profile: dict, source: str, timescale: int) -> List[Dict]:
    """Parses segment duration and extracts segment information."""
    duration = int(item["@duration"])
    start_number = int(item.get("@startNumber", 1))
    segment_duration_sec = duration / timescale

    if parsed_dict["isLive"]:
        segments = generate_live_segments(parsed_dict, segment_duration_sec, start_number)
    else:
        segments = generate_vod_segments(profile, duration, timescale, start_number)

    return [create_segment_data_unified(seg, item, profile, source, timescale, parsed_dict) for seg in segments]


def generate_live_segments(parsed_dict: dict, segment_duration_sec: float, start_number: int) -> List[Dict]:
    """Generates live segments based on the segment duration and start number."""
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
    """Generates VOD segments based on the segment duration and start number."""
    total_duration = profile.get("mediaPresentationDuration") or 0
    if isinstance(total_duration, str):
        total_duration = parse_duration(total_duration)
    segment_count = math.ceil(total_duration * timescale / duration)

    return [{"number": start_number + i, "duration": duration / timescale} for i in range(segment_count)]


def parse_segment_base(representation: dict, source: str) -> List[Dict]:
    """Parses segment base information and extracts segment data."""
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
    """Parses a duration ISO 8601 string into seconds."""
    pattern = re.compile(r"P(?:(\d+)Y)?(?:(\d+)M)?(?:(\d+)D)?T?(?:(\d+)H)?(?:(\d+)M)?(?:(\d+(?:\.\d+)?)S)?")
    match = pattern.match(duration_str)
    if not match:
        raise ValueError(f"Invalid duration format: {duration_str}")

    years, months, days, hours, minutes, seconds = [float(g) if g else 0 for g in match.groups()]
    return years * 365 * 24 * 3600 + months * 30 * 24 * 3600 + days * 24 * 3600 + hours * 3600 + minutes * 60 + seconds
