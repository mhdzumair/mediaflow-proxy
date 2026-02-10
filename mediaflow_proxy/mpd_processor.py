import asyncio
import logging
import math
import time

from fastapi import Request, Response, HTTPException

from mediaflow_proxy.drm.decrypter import decrypt_segment, process_drm_init_segment
from mediaflow_proxy.utils.crypto_utils import encryption_handler
from mediaflow_proxy.utils.http_utils import (
    encode_mediaflow_proxy_url,
    get_original_scheme,
    ProxyRequestHeaders,
    apply_header_manipulation,
)
from mediaflow_proxy.utils.dash_prebuffer import dash_prebuffer
from mediaflow_proxy.utils.cache_utils import get_cached_processed_init, set_cached_processed_init
from mediaflow_proxy.utils.m3u8_processor import SkipSegmentFilter
from mediaflow_proxy.utils.ts_muxer import remux_fmp4_to_ts
from mediaflow_proxy.configs import settings

logger = logging.getLogger(__name__)


def _resolve_ts_mode(request: Request) -> bool:
    """Resolve the effective TS remux mode from the request query params, falling back to settings."""
    override = request.query_params.get("remux_to_ts")
    if override is not None:
        return override.lower() in ("true", "1", "yes")
    return settings.remux_to_ts


async def process_manifest(
    request: Request,
    mpd_dict: dict,
    proxy_headers: ProxyRequestHeaders,
    key_id: str = None,
    key: str = None,
    resolution: str = None,
    skip_segments: list = None,
) -> Response:
    """
    Processes the MPD manifest and converts it to an HLS manifest.

    Args:
        request (Request): The incoming HTTP request.
        mpd_dict (dict): The MPD manifest data.
        proxy_headers (ProxyRequestHeaders): The headers to include in the request.
        key_id (str, optional): The DRM key ID. Defaults to None.
        key (str, optional): The DRM key. Defaults to None.
        resolution (str, optional): Target resolution (e.g., '1080p', '720p'). Defaults to None.
        skip_segments (list, optional): List of time segments to skip. Each item should have 'start' and 'end' keys.

    Returns:
        Response: The HLS manifest as an HTTP response.
    """
    hls_content = build_hls(mpd_dict, request, key_id, key, resolution, skip_segments)

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
            asyncio.create_task(dash_prebuffer.prebuffer_dash_manifest(mpd_url, headers))

    return Response(content=hls_content, media_type="application/vnd.apple.mpegurl", headers=proxy_headers.response)


async def process_playlist(
    request: Request,
    mpd_dict: dict,
    profile_id: str,
    proxy_headers: ProxyRequestHeaders,
    skip_segments: list = None,
    start_offset: float = None,
) -> Response:
    """
    Processes the MPD manifest and converts it to an HLS playlist for a specific profile.

    Args:
        request (Request): The incoming HTTP request.
        mpd_dict (dict): The MPD manifest data.
        profile_id (str): The profile ID to generate the playlist for.
        proxy_headers (ProxyRequestHeaders): The headers to include in the request.
        skip_segments (list, optional): List of time segments to skip. Each item should have 'start' and 'end' keys.
        start_offset (float, optional): Start offset in seconds for live streams.

    Returns:
        Response: The HLS playlist as an HTTP response.

    Raises:
        HTTPException: If the profile is not found in the MPD manifest.
    """
    matching_profiles = [p for p in mpd_dict["profiles"] if p["id"] == profile_id]
    if not matching_profiles:
        raise HTTPException(status_code=404, detail="Profile not found")

    hls_content = build_hls_playlist(mpd_dict, matching_profiles, request, skip_segments, start_offset)

    # Trigger prebuffering of upcoming segments for live streams
    if settings.enable_dash_prebuffer and mpd_dict.get("isLive", False):
        # Extract headers for pre-buffering
        headers = {}
        for key, value in request.query_params.items():
            if key.startswith("h_"):
                headers[key[2:]] = value

        # Use the new prefetch method for live playlists
        asyncio.create_task(dash_prebuffer.prefetch_for_live_playlist(matching_profiles, headers))

    # Don't include propagate headers for playlists - they should only apply to segments
    response_headers = apply_header_manipulation({}, proxy_headers, include_propagate=False)
    return Response(content=hls_content, media_type="application/vnd.apple.mpegurl", headers=response_headers)


async def process_segment(
    init_content: bytes,
    segment_content: bytes,
    mimetype: str,
    proxy_headers: ProxyRequestHeaders,
    key_id: str = None,
    key: str = None,
    use_map: bool = False,
    remux_ts: bool = None,
) -> Response:
    """
    Processes and decrypts a media segment, optionally remuxing to MPEG-TS.

    Args:
        init_content (bytes): The initialization segment content.
        segment_content (bytes): The media segment content.
        mimetype (str): The MIME type of the segment.
        proxy_headers (ProxyRequestHeaders): The headers to include in the request.
        key_id (str, optional): The DRM key ID. Defaults to None.
        key (str, optional): The DRM key. Defaults to None.
        use_map (bool, optional): If True, init segment is served separately via EXT-X-MAP,
            so don't concatenate init with segment. Defaults to False.
        remux_ts (bool, optional): If True, remux fMP4 to MPEG-TS. Defaults to settings.remux_to_ts.

    Returns:
        Response: The processed segment as an HTTP response.
    """
    if key_id and key:
        # For DRM protected content
        now = time.time()
        decrypted_content = decrypt_segment(init_content, segment_content, key_id, key, include_init=not use_map)
        logger.info(f"Decryption of {mimetype} segment took {time.time() - now:.4f} seconds")
    else:
        # For non-DRM protected content
        if use_map:
            # Init is served separately via EXT-X-MAP
            decrypted_content = segment_content
        else:
            # Concatenate init and segment content
            decrypted_content = init_content + segment_content

    # Check if we should remux to TS
    should_remux = remux_ts if remux_ts is not None else settings.remux_to_ts

    # Remux both video and audio to MPEG-TS for proper HLS TS playback
    if should_remux and ("video" in mimetype or "audio" in mimetype):
        # Remux fMP4 to MPEG-TS for ExoPlayer/VLC compatibility
        now = time.time()
        try:
            # For TS remuxing, we always need init_content for codec config
            # preserve_timestamps=True keeps the original tfdt timestamps from the
            # fMP4 segment, ensuring continuous playback across HLS segments
            ts_content = remux_fmp4_to_ts(
                init_content,
                decrypted_content,
                preserve_timestamps=True,
            )
            decrypted_content = ts_content
            mimetype = "video/mp2t"  # Update MIME type for TS (same for audio-only TS)
            logger.info(f"TS remuxing took {time.time() - now:.4f} seconds")
        except Exception as e:
            logger.warning(f"TS remuxing failed, returning fMP4: {e}")
            # Fall through to return original content

    response_headers = apply_header_manipulation({}, proxy_headers)
    return Response(content=decrypted_content, media_type=mimetype, headers=response_headers)


async def process_init_segment(
    init_content: bytes,
    mimetype: str,
    proxy_headers: ProxyRequestHeaders,
    key_id: str = None,
    key: str = None,
    init_url: str = None,
) -> Response:
    """
    Processes an initialization segment for EXT-X-MAP.

    Args:
        init_content (bytes): The initialization segment content.
        mimetype (str): The MIME type of the segment.
        proxy_headers (ProxyRequestHeaders): The headers to include in the request.
        key_id (str, optional): The DRM key ID. Defaults to None.
        key (str, optional): The DRM key. Defaults to None.
        init_url (str, optional): The init URL for caching. Defaults to None.

    Returns:
        Response: The processed init segment as an HTTP response.
    """
    if key_id and key:
        # Check if we have a cached processed version
        if init_url:
            cached_processed = await get_cached_processed_init(init_url, key_id)
            if cached_processed:
                logger.debug(f"Using cached processed init segment for {init_url}")
                response_headers = apply_header_manipulation({}, proxy_headers)
                return Response(content=cached_processed, media_type=mimetype, headers=response_headers)

        # For DRM protected content, we need to process the init segment
        # to remove encryption-related boxes but keep the moov structure
        now = time.time()
        processed_content = process_drm_init_segment(init_content, key_id, key)
        logger.info(f"Processing of {mimetype} init segment took {time.time() - now:.4f} seconds")

        # Cache the processed init segment
        if init_url:
            await set_cached_processed_init(init_url, key_id, processed_content, ttl=3600)
    else:
        # For non-DRM protected content, just return the init segment as-is
        processed_content = init_content

    response_headers = apply_header_manipulation({}, proxy_headers)
    return Response(content=processed_content, media_type=mimetype, headers=response_headers)


def build_hls(
    mpd_dict: dict,
    request: Request,
    key_id: str = None,
    key: str = None,
    resolution: str = None,
    skip_segments: list = None,
) -> str:
    """
    Builds an HLS manifest from the MPD manifest.

    Args:
        mpd_dict (dict): The MPD manifest data.
        request (Request): The incoming HTTP request.
        key_id (str, optional): The DRM key ID. Defaults to None.
        key (str, optional): The DRM key. Defaults to None.
        resolution (str, optional): Target resolution (e.g., '1080p', '720p'). Defaults to None.
        skip_segments (list, optional): List of time segments to skip. Each item should have 'start' and 'end' keys.

    Returns:
        str: The HLS manifest as a string.
    """
    is_ts_mode = _resolve_ts_mode(request)
    # Use HLS v3 for TS (ExoPlayer compatibility), v6 for fMP4
    version = 3 if is_ts_mode else 6
    hls = ["#EXTM3U", f"#EXT-X-VERSION:{version}"]
    query_params = dict(request.query_params)

    # Preserve skip parameter in query params so it propagates to playlists
    if skip_segments:
        # Convert back to compact format for URL
        skip_str = ",".join(f"{s['start']}-{s['end']}" for s in skip_segments)
        query_params["skip"] = skip_str
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

    # Filter video profiles by resolution if specified
    if resolution and video_profiles:
        video_profiles = _filter_video_profiles_by_resolution(video_profiles, resolution)

    # For TS mode, only expose the highest quality video variant
    # ExoPlayer handles adaptive switching poorly with TS remuxing
    if is_ts_mode and video_profiles:
        max_height = max(p[0].get("height", 0) for p in video_profiles.values())
        video_profiles = {k: v for k, v in video_profiles.items() if v[0].get("height", 0) >= max_height}

    # Add audio streams
    for i, (profile, playlist_url) in enumerate(audio_profiles.values()):
        is_default = "YES" if i == 0 else "NO"  # Set the first audio track as default
        lang = profile.get("lang", "und")
        bandwidth = profile.get("bandwidth", "128000")
        name = f"Audio {lang} ({bandwidth})" if lang != "und" else f"Audio {i + 1} ({bandwidth})"
        hls.append(
            f'#EXT-X-MEDIA:TYPE=AUDIO,GROUP-ID="audio",NAME="{name}",DEFAULT={is_default},AUTOSELECT=YES,LANGUAGE="{lang}",URI="{playlist_url}"'
        )

    # Build combined codecs string (video + audio) for EXT-X-STREAM-INF
    # ExoPlayer requires CODECS to list all codecs when AUDIO group is referenced
    first_audio_codec = None
    if audio_profiles:
        first_audio_profile = next(iter(audio_profiles.values()))[0]
        first_audio_codec = first_audio_profile.get("codecs", "")

    # Add video streams
    for profile, playlist_url in video_profiles.values():
        # Only add AUDIO attribute if there are audio profiles available
        audio_attr = ',AUDIO="audio"' if audio_profiles else ""

        # Build combined codecs: video + audio
        video_codec = profile["codecs"]
        if first_audio_codec and audio_attr:
            combined_codecs = f"{video_codec},{first_audio_codec}"
        else:
            combined_codecs = video_codec

        # Keep full codec strings (e.g., avc1.42C01F, mp4a.40.2) for ALL modes.
        # ExoPlayer's CodecSpecificDataUtil rejects simplified strings like "avc1" or "mp4a"
        # as malformed, which prevents proper codec initialization.

        # Omit FRAME-RATE for TS mode (ExoPlayer compatibility)
        if is_ts_mode:
            hls.append(
                f'#EXT-X-STREAM-INF:BANDWIDTH={profile["bandwidth"]},RESOLUTION={profile["width"]}x{profile["height"]},CODECS="{combined_codecs}"{audio_attr}'
            )
        else:
            hls.append(
                f'#EXT-X-STREAM-INF:BANDWIDTH={profile["bandwidth"]},RESOLUTION={profile["width"]}x{profile["height"]},CODECS="{combined_codecs}",FRAME-RATE={profile["frameRate"]}{audio_attr}'
            )
        hls.append(playlist_url)

    return "\n".join(hls)


def _filter_video_profiles_by_resolution(video_profiles: dict, target_resolution: str) -> dict:
    """
    Filter video profiles to select the one matching the target resolution.
    Falls back to closest lower resolution if exact match not found.

    Args:
        video_profiles: Dictionary of profile_id -> (profile, playlist_url).
        target_resolution: Target resolution string (e.g., '1080p', '720p').

    Returns:
        Filtered dictionary with only the selected profile.
    """
    # Parse target height from "1080p" -> 1080
    target_height = int(target_resolution.rstrip("p"))

    # Convert to list and sort by height descending
    profiles_list = [
        (profile_id, profile, playlist_url)
        for profile_id, (profile, playlist_url) in video_profiles.items()
        if profile.get("height", 0) > 0
    ]

    if not profiles_list:
        logger.warning("No video profiles with valid height found, returning all profiles")
        return video_profiles

    sorted_profiles = sorted(profiles_list, key=lambda x: x[1]["height"], reverse=True)

    # Find exact match or closest lower
    selected = None
    for profile_id, profile, playlist_url in sorted_profiles:
        if profile["height"] <= target_height:
            selected = (profile_id, profile, playlist_url)
            break

    # If all profiles are higher than target, use lowest available
    if selected is None:
        selected = sorted_profiles[-1]

    profile_id, profile, playlist_url = selected
    logger.info(
        f"Selected MPD video profile with resolution {profile['width']}x{profile['height']} for target {target_resolution}"
    )

    return {profile_id: (profile, playlist_url)}


def build_hls_playlist(
    mpd_dict: dict, profiles: list[dict], request: Request, skip_segments: list = None, start_offset: float = None
) -> str:
    """
    Builds an HLS playlist from the MPD manifest for specific profiles.

    Args:
        mpd_dict (dict): The MPD manifest data.
        profiles (list[dict]): The profiles to include in the playlist.
        request (Request): The incoming HTTP request.
        skip_segments (list, optional): List of time segments to skip. Each item should have 'start' and 'end' keys.
        start_offset (float, optional): Start offset in seconds for live streams. Defaults to settings.livestream_start_offset for live.

    Returns:
        str: The HLS playlist as a string.
    """
    # Determine if we're in TS remux mode (per-request override > global setting)
    is_ts_mode = _resolve_ts_mode(request)

    # Use HLS v3 for TS (ExoPlayer compatibility), v6 for fMP4
    version = 3 if is_ts_mode else 6
    hls = ["#EXTM3U", f"#EXT-X-VERSION:{version}"]

    added_segments = 0
    skipped_segments = 0
    is_live = mpd_dict.get("isLive", False)

    # Inject EXT-X-START for live streams (enables prebuffering by starting behind live edge)
    # User-provided start_offset always takes precedence; otherwise use default for live streams only
    if is_ts_mode and is_live and start_offset is None:
        # TS mode needs a larger buffer for ExoPlayer
        effective_start_offset = -30.0
    else:
        effective_start_offset = (
            start_offset if start_offset is not None else (settings.livestream_start_offset if is_live else None)
        )
    if effective_start_offset is not None:
        # ExoPlayer doesn't handle PRECISE=YES well with TS
        precise = "NO" if is_ts_mode else "YES"
        hls.append(f"#EXT-X-START:TIME-OFFSET={effective_start_offset:.1f},PRECISE={precise}")

    # Initialize skip filter if skip_segments provided
    skip_filter = SkipSegmentFilter(skip_segments) if skip_segments else None

    # In TS mode, we don't use EXT-X-MAP because TS segments are self-contained
    # (PAT/PMT/VPS/SPS/PPS are embedded in each segment)
    # Use EXT-X-MAP for live streams, but only for fMP4 (not TS)
    use_map = is_live and not is_ts_mode

    # Select appropriate endpoint based on remux mode
    if is_ts_mode:
        proxy_url = request.url_for("segment_ts_endpoint")  # /mpd/segment.ts
    else:
        proxy_url = request.url_for("segment_endpoint")  # /mpd/segment.mp4
    proxy_url = str(proxy_url.replace(scheme=get_original_scheme(request)))

    # Get init endpoint URL for EXT-X-MAP (only used for fMP4 mode)
    init_proxy_url = request.url_for("init_endpoint")
    init_proxy_url = str(init_proxy_url.replace(scheme=get_original_scheme(request)))

    for index, profile in enumerate(profiles):
        segments = profile["segments"]
        if not segments:
            logger.warning(f"No segments found for profile {profile['id']}")
            continue

        if is_live:
            # TS mode uses deeper playlist for ExoPlayer buffering
            depth = 20 if is_ts_mode else max(settings.mpd_live_playlist_depth, 1)
            trimmed_segments = segments[-depth:]
        else:
            trimmed_segments = segments

        # Add headers for only the first profile
        if index == 0:
            first_segment = trimmed_segments[0]
            extinf_values = [f["extinf"] for f in trimmed_segments if "extinf" in f]

            # TS mode uses int(max)+1 to reduce buffer underruns in ExoPlayer
            if is_ts_mode:
                target_duration = int(max(extinf_values)) + 1 if extinf_values else 10
            else:
                target_duration = math.ceil(max(extinf_values)) if extinf_values else 3

            # Align HLS media sequence with MPD-provided numbering when available
            if is_ts_mode and is_live:
                # For live TS, derive sequence from timeline first for stable continuity
                time_val = first_segment.get("time")
                duration_val = first_segment.get("duration_mpd_timescale")
                if time_val is not None and duration_val and duration_val > 0:
                    sequence = math.floor(time_val / duration_val)
                else:
                    sequence = first_segment.get("number") or profile.get("segment_template_start_number") or 1
            else:
                mpd_start_number = profile.get("segment_template_start_number")
                sequence = first_segment.get("number")

                if sequence is None:
                    # Fallback to MPD template start number
                    if mpd_start_number is not None:
                        sequence = mpd_start_number
                    else:
                        # As a last resort, derive from timeline information
                        time_val = first_segment.get("time")
                        duration_val = first_segment.get("duration_mpd_timescale")
                        if time_val is not None and duration_val and duration_val > 0:
                            sequence = math.floor(time_val / duration_val)
                        else:
                            sequence = 1

            hls.extend(
                [
                    f"#EXT-X-TARGETDURATION:{target_duration}",
                    f"#EXT-X-MEDIA-SEQUENCE:{sequence}",
                ]
            )
            # For live streams, don't set PLAYLIST-TYPE to allow sliding window
            if not is_live:
                hls.append("#EXT-X-PLAYLIST-TYPE:VOD")

        init_url = profile["initUrl"]
        # For SegmentBase profiles, we may have byte range for initialization segment
        init_range = profile.get("initRange")

        query_params = dict(request.query_params)
        query_params.pop("profile_id", None)
        query_params.pop("d", None)
        query_params.pop("remux_to_ts", None)  # per-request override; already resolved into endpoint choice
        has_encrypted = query_params.pop("has_encrypted", False)

        # Add EXT-X-MAP for init segment (for live streams or when beneficial)
        if use_map:
            init_query_params = {
                "init_url": init_url,
                "mime_type": profile["mimeType"],
                "is_live": "true" if is_live else "false",
            }
            if init_range:
                init_query_params["init_range"] = init_range
            # Add key parameters
            if query_params.get("key_id"):
                init_query_params["key_id"] = query_params["key_id"]
            if query_params.get("key"):
                init_query_params["key"] = query_params["key"]
            # Add api_password for authentication
            if query_params.get("api_password"):
                init_query_params["api_password"] = query_params["api_password"]

            init_map_url = encode_mediaflow_proxy_url(
                init_proxy_url,
                query_params=init_query_params,
                encryption_handler=encryption_handler if has_encrypted else None,
            )
            hls.append(f'#EXT-X-MAP:URI="{init_map_url}"')

        need_discontinuity = False
        for segment in trimmed_segments:
            duration = segment["extinf"]

            # Check if this segment should be skipped
            if skip_filter:
                if skip_filter.should_skip_segment(duration):
                    skip_filter.advance_time(duration)
                    skipped_segments += 1
                    need_discontinuity = True
                    continue
                skip_filter.advance_time(duration)

            # Add discontinuity marker after skipped segments
            if need_discontinuity:
                hls.append("#EXT-X-DISCONTINUITY")
                need_discontinuity = False

            # Emit EXT-X-PROGRAM-DATE-TIME only for fMP4 (not TS)
            program_date_time = segment.get("program_date_time")
            if program_date_time and not is_ts_mode:
                hls.append(f"#EXT-X-PROGRAM-DATE-TIME:{program_date_time}")
            hls.append(f"#EXTINF:{duration:.3f},")

            segment_query_params = {
                "init_url": init_url,
                "segment_url": segment["media"],
                "mime_type": profile["mimeType"],
                "is_live": "true" if is_live else "false",
            }

            # Add use_map flag so segment endpoint knows not to include init
            if use_map and not is_ts_mode:
                segment_query_params["use_map"] = "true"
            elif is_ts_mode:
                # TS segments are self-contained; init is always embedded by remuxer
                segment_query_params["use_map"] = "false"

            # Add byte range parameters for SegmentBase
            if init_range:
                segment_query_params["init_range"] = init_range
            # Segment may also have its own range (for SegmentBase)
            if "initRange" in segment:
                segment_query_params["init_range"] = segment["initRange"]

            query_params.update(segment_query_params)
            hls.append(
                encode_mediaflow_proxy_url(
                    proxy_url,
                    query_params=query_params,
                    encryption_handler=encryption_handler if has_encrypted else None,
                )
            )
            added_segments += 1

    if not mpd_dict["isLive"]:
        hls.append("#EXT-X-ENDLIST")

    if skip_filter and skipped_segments > 0:
        logger.info(f"Added {added_segments} segments to HLS playlist (skipped {skipped_segments} segments)")
    else:
        logger.info(f"Added {added_segments} segments to HLS playlist")
    return "\n".join(hls)
