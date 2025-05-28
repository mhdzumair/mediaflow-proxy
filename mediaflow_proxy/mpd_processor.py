import logging
import math
import time
from datetime import datetime, timedelta, timezone

from fastapi import Request, Response, HTTPException

from mediaflow_proxy.drm.decrypter import decrypt_segment
from mediaflow_proxy.utils.crypto_utils import encryption_handler
from mediaflow_proxy.utils.http_utils import encode_mediaflow_proxy_url, get_original_scheme, ProxyRequestHeaders

logger = logging.getLogger(__name__)


async def process_manifest(
    request: Request, mpd_dict: dict, proxy_headers: ProxyRequestHeaders, key_id: str = None, key: str = None
) -> Response:
    """
    Processes the MPD manifest and converts it to an HLS manifest.

    Args:
        request (Request): The incoming HTTP request.
        mpd_dict (dict): The MPD manifest data.
        proxy_headers (ProxyRequestHeaders): The headers to include in the request.
        key_id (str, optional): The DRM key ID. Defaults to None.
        key (str, optional): The DRM key. Defaults to None.

    Returns:
        Response: The HLS manifest as an HTTP response.
    """
    hls_content = build_hls(mpd_dict, request, key_id, key)
    return Response(content=hls_content, media_type="application/vnd.apple.mpegurl", headers=proxy_headers.response)


async def process_playlist(
    request: Request, mpd_dict: dict, profile_id: str, proxy_headers: ProxyRequestHeaders
) -> Response:
    """
    Processes the MPD manifest and converts it to an HLS playlist for a specific profile.

    Args:
        request (Request): The incoming HTTP request.
        mpd_dict (dict): The MPD manifest data.
        profile_id (str): The profile ID to generate the playlist for.
        proxy_headers (ProxyRequestHeaders): The headers to include in the request.

    Returns:
        Response: The HLS playlist as an HTTP response.

    Raises:
        HTTPException: If the profile is not found in the MPD manifest.
    """
    matching_profiles = [p for p in mpd_dict["profiles"] if p["id"] == profile_id]
    if not matching_profiles:
        raise HTTPException(status_code=404, detail="Profile not found")

    hls_content = build_hls_playlist(mpd_dict, matching_profiles, request)
    return Response(content=hls_content, media_type="application/vnd.apple.mpegurl", headers=proxy_headers.response)


async def process_segment(
    init_content: bytes,
    segment_content: bytes,
    mimetype: str,
    proxy_headers: ProxyRequestHeaders,
    key_id: str = None,
    key: str = None,
) -> Response:
    """
    Processes and decrypts a media segment.

    Args:
        init_content (bytes): The initialization segment content.
        segment_content (bytes): The media segment content.
        mimetype (str): The MIME type of the segment.
        proxy_headers (ProxyRequestHeaders): The headers to include in the request.
        key_id (str, optional): The DRM key ID. Defaults to None.
        key (str, optional): The DRM key. Defaults to None.

    Returns:
        Response: The decrypted segment as an HTTP response.
    """
    if key_id and key:
        # For DRM protected content
        now = time.time()
        decrypted_content = decrypt_segment(init_content, segment_content, key_id, key)
        logger.info(f"Decryption of {mimetype} segment took {time.time() - now:.4f} seconds")
    else:
        # For non-DRM protected content, we just concatenate init and segment content
        decrypted_content = init_content + segment_content

    return Response(content=decrypted_content, media_type=mimetype, headers=proxy_headers.response)


def build_hls(mpd_dict: dict, request: Request, key_id: str = None, key: str = None) -> str:
    """
    Builds an HLS manifest from the MPD manifest.

    Args:
        mpd_dict (dict): The MPD manifest data.
        request (Request): The incoming HTTP request.
        key_id (str, optional): The DRM key ID. Defaults to None.
        key (str, optional): The DRM key. Defaults to None.

    Returns:
        str: The HLS manifest as a string.
    """
    hls = ["#EXTM3U", "#EXT-X-VERSION:6"]
    query_params = dict(request.query_params)
    has_encrypted = query_params.pop("has_encrypted", False)

    video_profiles = {}
    audio_profiles = {}

    # Get the base URL for the playlist_endpoint endpoint
    proxy_url = request.url_for("playlist_endpoint")
    proxy_url = str(proxy_url.replace(scheme=get_original_scheme(request)))

    for profile in mpd_dict["profiles"]:
        query_params.update({"profile_id": profile["id"], "key_id": key_id or "", "key": key or ""})
        playlist_url = encode_mediaflow_proxy_url(
            proxy_url,
            query_params=query_params,
            encryption_handler=encryption_handler if has_encrypted else None,
        )

        if "video" in profile["mimeType"]:
            video_profiles[profile["id"]] = (profile, playlist_url)
        elif "audio" in profile["mimeType"]:
            audio_profiles[profile["id"]] = (profile, playlist_url)

    # Add audio streams
    for i, (profile, playlist_url) in enumerate(audio_profiles.values()):
        is_default = "YES" if i == 0 else "NO"  # Set the first audio track as default
        hls.append(
            f'#EXT-X-MEDIA:TYPE=AUDIO,GROUP-ID="audio",NAME="{profile["id"]}",DEFAULT={is_default},AUTOSELECT={is_default},LANGUAGE="{profile.get("lang", "und")}",URI="{playlist_url}"'
        )

    # Add video streams
    for profile, playlist_url in video_profiles.values():
        hls.append(
            f'#EXT-X-STREAM-INF:BANDWIDTH={profile["bandwidth"]},RESOLUTION={profile["width"]}x{profile["height"]},CODECS="{profile["codecs"]}",FRAME-RATE={profile["frameRate"]},AUDIO="audio"'
        )
        hls.append(playlist_url)

    return "\n".join(hls)


def build_hls_playlist(mpd_dict: dict, profiles: list[dict], request: Request) -> str:
    hls = ["#EXTM3U", "#EXT-X-VERSION:6"]
    added_segments = 0

    proxy_url = request.url_for("segment_endpoint")
    proxy_url = str(proxy_url.replace(scheme=get_original_scheme(request)))

    TARGET_HLS_LIVE_SEGMENT_COUNT = 6
    MIN_HLS_LIVE_SEGMENTS = 3
    LIVE_EDGE_TOLERANCE_SECONDS = 10 # Potrebbe essere necessario aggiustarlo, vedi sotto

    for index, profile in enumerate(profiles):
        all_available_segments_from_mpd = profile.get("segments", [])

        if not all_available_segments_from_mpd:
            logger.warning(f"No segments found for profile {profile['id']}")
            continue

        segments_for_this_hls_playlist = []

        if mpd_dict.get("isLive", False):
            #publish_time_str = mpd_dict["MPD"].get("@publishTime") # Già parsato in mpd_dict
            #availability_start_time_str = mpd_dict["MPD"]["@availabilityStartTime"] # Già parsato

            # Usa i datetime objects direttamente da mpd_dict se disponibili
            mpd_publish_time = mpd_dict.get("publishTime") 
            # availability_start_time = mpd_dict.get("availabilityStartTime")

            if not mpd_publish_time:
                logger.warning(f"Profile {profile['id']}: MPD publishTime is missing. Using current time as live edge approximation.")
                live_cutoff_time = datetime.now(timezone.utc)
            else:
                live_cutoff_time = mpd_publish_time
            
            # effective_live_edge serve a includere segmenti che sono appena diventati disponibili
            # o stanno per diventarlo, basandosi sul publishTime dell'MPD.
            effective_live_edge = live_cutoff_time + timedelta(seconds=LIVE_EDGE_TOLERANCE_SECONDS)
            
            # Per alcuni provider, il publishTime potrebbe essere leggermente nel futuro
            # rispetto ai segmenti effettivamente disponibili.
            # In alternativa, considerare i segmenti la cui *fine* è vicina al publishTime.
            # current_time_utc = datetime.now(timezone.utc)
            # logger.info(f"Profile {profile['id']}: Current UTC time: {current_time_utc}")


            logger.info(f"Profile {profile['id']}: Live stream processing.")
            logger.info(f"Profile {profile['id']}: MPD publishTime: {mpd_publish_time}, Calculated live_cutoff_time: {live_cutoff_time}, Effective live_edge: {effective_live_edge}")
            if all_available_segments_from_mpd:
                logger.info(f"Profile {profile['id']}: Total available segments from MPD: {len(all_available_segments_from_mpd)}. First S_time: {all_available_segments_from_mpd[0].get('start_time')}, Last S_time: {all_available_segments_from_mpd[-1].get('start_time')}")

            candidate_live_segments = [
                s for s in all_available_segments_from_mpd if "start_time" in s and s["start_time"] < effective_live_edge
            ]

            # Se il timeShiftBufferDepth è molto grande, candidate_live_segments potrebbe contenere
            # troppi segmenti "vecchi". Vogliamo quelli più vicini al live edge.
            # L'MPD fornito ha timeShiftBufferDepth="PT3599.000S" (1 ora)
            # e S@r="1799" (1800 segmenti di 2s = 3600s = 1 ora).
            # Quindi all_available_segments_from_mpd conterrà sempre l'intera finestra DVR.

            logger.info(f"Profile {profile['id']}: Number of candidate_live_segments (start_time < effective_live_edge): {len(candidate_live_segments)}")
            if candidate_live_segments:
                logger.info(f"Profile {profile['id']}: Last candidate segment start_time: {candidate_live_segments[-1].get('start_time')}, number: {candidate_live_segments[-1].get('number')}")

            if not candidate_live_segments:
                logger.warning(f"Profile {profile['id']}: No candidate segments found before effective_live_edge. Using last {TARGET_HLS_LIVE_SEGMENT_COUNT} from all available.")
                segments_for_this_hls_playlist = all_available_segments_from_mpd[-TARGET_HLS_LIVE_SEGMENT_COUNT:]
            else:
                # Prendiamo gli ultimi segmenti dalla lista dei candidati
                segments_for_this_hls_playlist = candidate_live_segments[-TARGET_HLS_LIVE_SEGMENT_COUNT:]
                
                if len(segments_for_this_hls_playlist) < MIN_HLS_LIVE_SEGMENTS and len(candidate_live_segments) >= MIN_HLS_LIVE_SEGMENTS:
                    logger.info(f"Profile {profile['id']}: HLS window too small ({len(segments_for_this_hls_playlist)}), expanding to {MIN_HLS_LIVE_SEGMENTS} from candidates.")
                    segments_for_this_hls_playlist = candidate_live_segments[-MIN_HLS_LIVE_SEGMENTS:]

            if not segments_for_this_hls_playlist and all_available_segments_from_mpd:
                 logger.warning(f"Profile {profile['id']}: Still no segments for HLS playlist, using absolute last {MIN_HLS_LIVE_SEGMENTS} from MPD.")
                 segments_for_this_hls_playlist = all_available_segments_from_mpd[-MIN_HLS_LIVE_SEGMENTS:]
        else: 
            segments_for_this_hls_playlist = all_available_segments_from_mpd

        if not segments_for_this_hls_playlist:
            logger.warning(f"HLS Playlist: No segments to include for profile {profile['id']} after processing.")
            continue

        extinf_values = [s.get("extinf", 0.0) for s in segments_for_this_hls_playlist if "extinf" in s]
        if not extinf_values:
             logger.warning(f"Profile {profile['id']}: No extinf values found for segments in HLS window. Defaulting target_duration to 3.")
             target_duration = 3.0
        else:
             target_duration = math.ceil(max(extinf_values))
        target_duration = max(1, int(target_duration))

        first_segment_in_window = segments_for_this_hls_playlist[0]
        
        # --- MODIFICA PER EXT-X-MEDIA-SEQUENCE ADATTIVA ---
        # Recupera il startNumber del SegmentTemplate dell'MPD, che abbiamo salvato nel profilo
        mpd_segment_template_start_number = profile.get("segment_template_start_number")
        # Definiamo una soglia per considerare startNumber "significativo" (stile Amazon)
        SIGNIFICANT_START_NUMBER_THRESHOLD = 1000 

        calculated_segment_number = first_segment_in_window.get("number") # Questo è calcolato da mpd_utils

        if mpd_segment_template_start_number is not None and mpd_segment_template_start_number >= SIGNIFICANT_START_NUMBER_THRESHOLD:
            # Caso MPD tipo Amazon: startNumber è grande, usiamo il 'number' del segmento
            # che è startNumber_MPD + offset.
            sequence_number = calculated_segment_number
            if sequence_number is None:
                 logger.error(f"Profile {profile['id']} (Amazon-like): 'number' attribute missing for first segment. Cannot set MEDIA-SEQUENCE.")
                 continue
            logger.info(f"Profile {profile['id']}: Using MPD segment number for HLS MEDIA-SEQUENCE (Amazon-like).")
        else:
            # Caso MPD tipo Sky: startNumber non è significativo o assente.
            # Usiamo la logica time / duration.
            sequence_number_base_val = first_segment_in_window.get("time")
            segment_duration_timescale_units = first_segment_in_window.get("duration_mpd_timescale")

            if sequence_number_base_val is not None and segment_duration_timescale_units and segment_duration_timescale_units > 0:
                sequence_number = math.floor(sequence_number_base_val / segment_duration_timescale_units)
            else:
                logger.warning(f"Profile {profile['id']} (Sky-like): Could not calculate MEDIA-SEQUENCE from time/duration. Falling back to segment 'number'. Time: {sequence_number_base_val}, Duration: {segment_duration_timescale_units}")
                sequence_number = calculated_segment_number # Fallback al numero calcolato
                if sequence_number is None:
                    logger.error(f"Profile {profile['id']} (Sky-like fallback): 'number' attribute missing. Cannot set MEDIA-SEQUENCE.")
                    continue
            logger.info(f"Profile {profile['id']}: Using time/duration for HLS MEDIA-SEQUENCE (Sky-like).")

        if sequence_number is None: # Check finale se tutti i percorsi falliscono
            logger.error(f"Profile {profile['id']}: CRITICAL - Failed to determine a valid sequence_number. Skipping playlist generation for this profile.")
            continue
        # --- FINE MODIFICA ADATTIVA ---


        logger.info(f"Profile {profile['id']}: First segment in HLS window: Number={first_segment_in_window.get('number')}, MPD_StartNumber={mpd_segment_template_start_number}, TimeValue(MPD):{first_segment_in_window.get('time')}, Duration(MPD_timescale):{first_segment_in_window.get('duration_mpd_timescale')}")
        logger.info(f"Profile {profile['id']}: Calculated HLS Media Sequence: {sequence_number}, Target Duration: {target_duration}")

        hls.extend(
            [
                f"#EXT-X-TARGETDURATION:{target_duration}",
                f"#EXT-X-MEDIA-SEQUENCE:{sequence_number}", 
            ]
        )

        if mpd_dict.get("isLive", False):
            pass 
        else: 
            hls.append("#EXT-X-PLAYLIST-TYPE:VOD")
            hls.append("#EXT-X-ENDLIST") 

        init_url = profile.get("initUrl", "")
        if not init_url:
            logger.error(f"Missing initUrl for profile {profile['id']}")

        query_params = dict(request.query_params)
        query_params.pop("profile_id", None)
        query_params.pop("d", None)
        has_encrypted_param = query_params.pop("has_encrypted", False)

        for segment in segments_for_this_hls_playlist:
            if mpd_dict.get("isLive", False) and "program_date_time" in segment:
                hls.append(f'#EXT-X-PROGRAM-DATE-TIME:{segment["program_date_time"]}')
            
            hls.append(f'#EXTINF:{segment.get("extinf", target_duration):.3f},')
            
            segment_media_url = segment.get("media")
            if not segment_media_url:
                logger.error(f"Segment missing 'media' URL: {segment}")
                continue

            current_segment_query_params = query_params.copy()
            current_segment_query_params.update(
                {
                    "init_url": init_url, 
                    "segment_url": segment_media_url, 
                    "mime_type": profile.get("mimeType", "")
                }
            )
            
            hls.append(
                encode_mediaflow_proxy_url(
                    proxy_url,
                    query_params=current_segment_query_params,
                    encryption_handler=encryption_handler if has_encrypted_param else None,
                )
            )
            added_segments += 1

    if added_segments == 0:
        if not mpd_dict.get("isLive", False): 
            logger.warning("Generated an empty HLS playlist for a VOD stream. Adding ENDLIST.")
            hls.append("#EXT-X-ENDLIST") 
        else: 
             logger.warning("Generated an empty HLS playlist for a live stream.")

    logger.info(f"Final HLS build: Added {added_segments} segments. Live: {mpd_dict.get('isLive', False)}")
    return "\n".join(hls)