import asyncio
import logging
import math
import time

from fastapi import Request, Response, HTTPException

from mediaflow_proxy.drm.decrypter import decrypt_segment
from mediaflow_proxy.utils.crypto_utils import encryption_handler
from mediaflow_proxy.utils.http_utils import encode_mediaflow_proxy_url, get_original_scheme, ProxyRequestHeaders
from mediaflow_proxy.utils.dash_prebuffer import dash_prebuffer
from mediaflow_proxy.configs import settings

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
    
    # Start DASH pre-buffering in background if enabled
    if settings.enable_dash_prebuffer:
        # Extract headers for pre-buffering
        headers = {}
        for key, value in request.query_params.items():
            if key.startswith("h_"):
                headers[key[2:]] = value
        
        # Get the original MPD URL from the request
        mpd_url = request.query_params.get("d", "")
        if mpd_url:
            # Start pre-buffering in background
            asyncio.create_task(
                dash_prebuffer.prebuffer_dash_manifest(mpd_url, headers)
            )
    
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
        # Only add AUDIO attribute if there are audio profiles available
        audio_attr = ',AUDIO="audio"' if audio_profiles else ""
        hls.append(
            f'#EXT-X-STREAM-INF:BANDWIDTH={profile["bandwidth"]},RESOLUTION={profile["width"]}x{profile["height"]},CODECS="{profile["codecs"]}",FRAME-RATE={profile["frameRate"]}{audio_attr}'
        )
        hls.append(playlist_url)

    return "\n".join(hls)


def build_hls_playlist(mpd_dict: dict, profiles: list[dict], request: Request) -> str:
    """
    Builds an HLS playlist from the MPD manifest for specific profiles.

    Args:
        mpd_dict (dict): The MPD manifest data.
        profiles (list[dict]): The profiles to include in the playlist.
        request (Request): The incoming HTTP request.

    Returns:
        str: The HLS playlist as a string.
    """
    hls = ["#EXTM3U", "#EXT-X-VERSION:6"]

    # Per i flussi VOD, potremmo dover gestire la paginazione dei segmenti
    # se il player non supporta playlist enormi.
    start_segment_index = int(request.query_params.get("start_segment", 0))
    max_segments_per_playlist = 100  # Limite di segmenti per richiesta
    added_segments = 0

    proxy_url = request.url_for("segment_endpoint")
    proxy_url = str(proxy_url.replace(scheme=get_original_scheme(request)))

    for index, profile in enumerate(profiles):
        segments = profile["segments"]
        if not segments:
            logger.warning(f"No segments found for profile {profile['id']}")
            continue

        total_segments = len(segments)
        paginated_segments = segments[start_segment_index : start_segment_index + max_segments_per_playlist]

        if not paginated_segments:
            logger.warning(f"No segments to process for profile {profile['id']} at start index {start_segment_index}")
            continue

        # Add headers for only the first profile
        if index == 0:
            # Usa il primo segmento della finestra paginata per calcolare la sequenza
            first_segment_in_window = paginated_segments[0]
            extinf_values = [f["extinf"] for f in paginated_segments if "extinf" in f]
            target_duration = math.ceil(max(extinf_values)) if extinf_values else 3

            # Calculate media sequence using adaptive logic for different MPD types
            mpd_start_number = profile.get("segment_template_start_number")
            if mpd_start_number and mpd_start_number >= 1000:
                # Amazon-style: Use absolute segment numbering
                sequence = first_segment_in_window.get("number", mpd_start_number)
            else:
                # Sky-style: Use time-based calculation if available
                time_val = first_segment_in_window.get("time")
                duration_val = first_segment_in_window.get("duration_mpd_timescale")
                if time_val is not None and duration_val and duration_val > 0:
                    calculated_sequence = math.floor(time_val / duration_val)
                    # For live streams with very large sequence numbers, use modulo to keep reasonable range
                    if mpd_dict.get("isLive", False) and calculated_sequence > 100000:
                        sequence = calculated_sequence % 100000
                    else:
                        sequence = calculated_sequence
                else:
                    sequence = first_segment_in_window.get("number", 1) + start_segment_index

            hls.extend(
                [
                    f"#EXT-X-TARGETDURATION:{target_duration}",
                    f"#EXT-X-MEDIA-SEQUENCE:{sequence}",
                ]
            )
            if mpd_dict["isLive"]:
                hls.append("#EXT-X-PLAYLIST-TYPE:EVENT")
            else:
                hls.append("#EXT-X-PLAYLIST-TYPE:VOD")

        init_url = profile["initUrl"]

        query_params = dict(request.query_params)
        query_params.pop("profile_id", None)
        query_params.pop("d", None)
        has_encrypted = query_params.pop("has_encrypted", False)

        for segment in paginated_segments:
            hls.append(f'#EXTINF:{segment["extinf"]:.3f},')
            query_params.update(
                {"init_url": init_url, "segment_url": segment["media"], "mime_type": profile["mimeType"]}
            )
            hls.append(
                encode_mediaflow_proxy_url(
                    proxy_url,
                    query_params=query_params,
                    encryption_handler=encryption_handler if has_encrypted else None,
                )
            )
            added_segments += 1

    # Se è un VOD e ci sono altri segmenti, non aggiungere ENDLIST
    # e il player continuerà a chiedere la playlist.
    # Altrimenti, se è l'ultima pagina o un live, gestisci di conseguenza.
    is_last_page = (start_segment_index + max_segments_per_playlist) >= total_segments

    if mpd_dict.get("isLive", False):
        # Per i live, non aggiungiamo mai ENDLIST
        pass
    elif is_last_page:
        # Se è un VOD e questa è l'ultima pagina di segmenti, chiudi la playlist
        hls.append("#EXT-X-ENDLIST")
    else:
        # Se è un VOD ma ci sono altre pagine, non chiudere la playlist.
        # Il player ricaricherà la playlist. Alcuni player potrebbero non farlo
        # per VOD, ma questo è il miglior compromesso.
        # Non aggiungiamo nulla, il player dovrebbe ricaricare la stessa URL
        # (anche se idealmente dovrebbe chiedere la pagina successiva).
        # Per ora, questo approccio limita la dimensione della playlist iniziale.
        pass

    logger.info(f"Added {added_segments} segments to HLS playlist (start_index: {start_segment_index}, total: {total_segments})")
    return "\n".join(hls)
