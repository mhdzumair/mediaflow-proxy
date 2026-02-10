import json
import re
from typing import Annotated, Literal, Dict, Any, Optional

from pydantic import BaseModel, Field, IPvAnyAddress, ConfigDict, field_validator


def validate_resolution_format(value: str) -> str:
    """Validate and normalize resolution format (e.g., '1080p', '720p')."""
    if not re.match(r"^\d+p$", value):
        raise ValueError(f"Invalid resolution format '{value}'. Expected format: '1080p', '720p', etc.")
    return value


def parse_skip_segments(skip_str: str) -> list[dict]:
    """
    Parse compact skip segment format into list of segment dicts.

    Format: "start-end,start-end,..." (e.g., "0-112,280-300")

    Args:
        skip_str: Comma-separated list of start-end ranges in seconds.

    Returns:
        List of dicts with 'start' and 'end' keys.

    Raises:
        ValueError: If format is invalid or end <= start.
    """
    if not skip_str or not skip_str.strip():
        return []

    segments = []
    for part in skip_str.split(","):
        part = part.strip()
        if not part:
            continue

        if "-" not in part:
            raise ValueError(f"Invalid segment format '{part}'. Expected 'start-end' (e.g., '0-112')")

        # Handle negative numbers by splitting only on the last hyphen for end
        # But since times are always positive, we can split on first hyphen
        parts = part.split("-", 1)
        if len(parts) != 2:
            raise ValueError(f"Invalid segment format '{part}'. Expected 'start-end' (e.g., '0-112')")

        try:
            start = float(parts[0])
            end = float(parts[1])
        except ValueError:
            raise ValueError(f"Invalid segment format '{part}'. Start and end must be numbers.")

        if start < 0:
            raise ValueError(f"Start time cannot be negative: {start}")
        if end < 0:
            raise ValueError(f"End time cannot be negative: {end}")
        if end <= start:
            raise ValueError(f"End time ({end}) must be greater than start time ({start})")

        segments.append({"start": start, "end": end})

    return segments


class GenerateUrlRequest(BaseModel):
    mediaflow_proxy_url: str = Field(..., description="The base URL for the mediaflow proxy.")
    endpoint: Optional[str] = Field(None, description="The specific endpoint to be appended to the base URL.")
    destination_url: Optional[str] = Field(
        None, description="The destination URL to which the request will be proxied."
    )
    query_params: Optional[dict] = Field(
        default_factory=dict, description="Query parameters to be included in the request."
    )
    request_headers: Optional[dict] = Field(default_factory=dict, description="Headers to be included in the request.")
    response_headers: Optional[dict] = Field(
        default_factory=dict, description="Headers to be included in the response (r_ prefix, manifest only)."
    )
    propagate_response_headers: Optional[dict] = Field(
        default_factory=dict,
        description="Response headers that propagate to segments (rp_ prefix). Useful for overriding content-type on segment requests.",
    )
    remove_response_headers: Optional[list[str]] = Field(
        default_factory=list, description="List of response header names to remove from the proxied response."
    )
    expiration: Optional[int] = Field(
        None, description="Expiration time for the URL in seconds. If not provided, the URL will not expire."
    )
    api_password: Optional[str] = Field(
        None, description="API password for encryption. If not provided, the URL will only be encoded."
    )
    ip: Optional[IPvAnyAddress] = Field(None, description="The IP address to restrict the URL to.")
    filename: Optional[str] = Field(None, description="Filename to be preserved for media players like Infuse.")
    base64_encode_destination: Optional[bool] = Field(
        False, description="Whether to encode the destination URL in base64 format before processing."
    )


class MultiUrlRequestItem(BaseModel):
    endpoint: Optional[str] = Field(None, description="The specific endpoint to be appended to the base URL.")
    destination_url: Optional[str] = Field(
        None, description="The destination URL to which the request will be proxied."
    )
    query_params: Optional[dict] = Field(
        default_factory=dict, description="Query parameters to be included in the request."
    )
    request_headers: Optional[dict] = Field(default_factory=dict, description="Headers to be included in the request.")
    response_headers: Optional[dict] = Field(
        default_factory=dict, description="Headers to be included in the response (r_ prefix, manifest only)."
    )
    propagate_response_headers: Optional[dict] = Field(
        default_factory=dict,
        description="Response headers that propagate to segments (rp_ prefix). Useful for overriding content-type on segment requests.",
    )
    remove_response_headers: Optional[list[str]] = Field(
        default_factory=list, description="List of response header names to remove from the proxied response."
    )
    filename: Optional[str] = Field(None, description="Filename to be preserved for media players like Infuse.")


class GenerateMultiUrlRequest(BaseModel):
    mediaflow_proxy_url: str = Field(..., description="The base URL for the mediaflow proxy.")
    api_password: Optional[str] = Field(
        None, description="API password for encryption. If not provided, the URL will only be encoded."
    )
    expiration: Optional[int] = Field(
        None, description="Expiration time for the URL in seconds. If not provided, the URL will not expire."
    )
    ip: Optional[IPvAnyAddress] = Field(None, description="The IP address to restrict the URL to.")
    urls: list[MultiUrlRequestItem] = Field(..., description="List of URL configurations to generate.")


class GenericParams(BaseModel):
    model_config = ConfigDict(populate_by_name=True)


class HLSManifestParams(GenericParams):
    destination: Annotated[str, Field(description="The URL of the HLS manifest.", alias="d")]
    key_url: Optional[str] = Field(
        None,
        description="The HLS Key URL to replace the original key URL. Defaults to None. (Useful for bypassing some sneaky protection)",
    )
    force_playlist_proxy: Optional[bool] = Field(
        None,
        description="Force all playlist URLs to be proxied through MediaFlow regardless of m3u8_content_routing setting. Useful for IPTV m3u/m3u_plus formats that don't have clear URL indicators.",
    )
    key_only_proxy: Optional[bool] = Field(
        False,
        description="Only proxy the key URL, leaving segment URLs direct.",
    )
    no_proxy: bool = Field(
        False,
        description="If true, returns the manifest content without proxying any internal URLs (segments, keys, playlists).",
    )
    max_res: bool = Field(
        False,
        description="If true, redirects to the highest resolution stream in the manifest.",
    )
    resolution: Optional[str] = Field(
        None,
        description="Select a specific resolution stream (e.g., '1080p', '720p', '480p'). Falls back to closest lower resolution if exact match not found.",
    )
    skip: Optional[str] = Field(
        None,
        description="Time segments to skip, in compact format: 'start-end,start-end,...' (e.g., '0-112,280-300'). Segments are in seconds.",
    )
    start_offset: Optional[float] = Field(
        None,
        description="Injects #EXT-X-START:TIME-OFFSET into the playlist. Use negative values for live streams to start behind the live edge (e.g., -18 to start 18 seconds behind). Enables prebuffer to work on live streams by creating headroom.",
    )
    transformer: Optional[str] = Field(
        None,
        description="Stream transformer ID for host-specific content manipulation (e.g., 'ts_stream' for PNG/padding stripping).",
    )

    @field_validator("resolution", mode="before")
    @classmethod
    def validate_resolution(cls, value: Any) -> Optional[str]:
        if value is None:
            return None
        return validate_resolution_format(str(value))

    def get_skip_segments(self) -> Optional[list[dict]]:
        """Parse and return skip segments as a list of dicts with 'start' and 'end' keys."""
        if self.skip is None:
            return None
        return parse_skip_segments(self.skip)


class MPDManifestParams(GenericParams):
    destination: Annotated[str, Field(description="The URL of the MPD manifest.", alias="d")]
    key_id: Optional[str] = Field(None, description="The DRM key ID (optional).")
    key: Optional[str] = Field(None, description="The DRM key (optional).")
    resolution: Optional[str] = Field(
        None,
        description="Select a specific resolution stream (e.g., '1080p', '720p', '480p'). Falls back to closest lower resolution if exact match not found.",
    )
    skip: Optional[str] = Field(
        None,
        description="Time segments to skip, in compact format: 'start-end,start-end,...' (e.g., '0-112,280-300'). Segments are in seconds.",
    )
    start_offset: Optional[float] = Field(
        None,
        description="Injects #EXT-X-START:TIME-OFFSET into live playlists. Use negative values for live streams to start behind the live edge (e.g., -18 to start 18 seconds behind). Enables prebuffer to work on live streams.",
    )
    remux_to_ts: Optional[bool] = Field(
        None,
        description="Override global REMUX_TO_TS setting per-request. true = force TS remuxing, false = force fMP4 passthrough, omit = use server default.",
    )

    @field_validator("resolution", mode="before")
    @classmethod
    def validate_resolution(cls, value: Any) -> Optional[str]:
        if value is None:
            return None
        return validate_resolution_format(str(value))

    def get_skip_segments(self) -> Optional[list[dict]]:
        """Parse and return skip segments as a list of dicts with 'start' and 'end' keys."""
        if self.skip is None:
            return None
        return parse_skip_segments(self.skip)


class MPDPlaylistParams(GenericParams):
    destination: Annotated[str, Field(description="The URL of the MPD manifest.", alias="d")]
    profile_id: str = Field(..., description="The profile ID to generate the playlist for.")
    key_id: Optional[str] = Field(None, description="The DRM key ID (optional).")
    key: Optional[str] = Field(None, description="The DRM key (optional).")
    skip: Optional[str] = Field(
        None,
        description="Time segments to skip, in compact format: 'start-end,start-end,...' (e.g., '0-112,280-300'). Segments are in seconds.",
    )
    start_offset: Optional[float] = Field(
        None,
        description="Injects #EXT-X-START:TIME-OFFSET into the playlist. Use negative values for live streams to start behind the live edge (e.g., -18 to start 18 seconds behind). Enables prebuffer to work on live streams.",
    )
    remux_to_ts: Optional[bool] = Field(
        None,
        description="Override global REMUX_TO_TS setting per-request. true = force TS remuxing, false = force fMP4 passthrough, omit = use server default.",
    )

    def get_skip_segments(self) -> Optional[list[dict]]:
        """Parse and return skip segments as a list of dicts with 'start' and 'end' keys."""
        if self.skip is None:
            return None
        return parse_skip_segments(self.skip)


class MPDSegmentParams(GenericParams):
    init_url: str = Field(..., description="The URL of the initialization segment.")
    segment_url: str = Field(..., description="The URL of the media segment.")
    mime_type: str = Field(..., description="The MIME type of the segment.")
    key_id: Optional[str] = Field(None, description="The DRM key ID (optional).")
    key: Optional[str] = Field(None, description="The DRM key (optional).")
    is_live: Annotated[
        Optional[bool], Field(default=None, alias="is_live", description="Whether the parent MPD is live.")
    ]
    init_range: Optional[str] = Field(
        None, description="Byte range for the initialization segment (e.g., '0-11568'). Used for SegmentBase MPDs."
    )
    use_map: Optional[bool] = Field(
        False,
        description="Whether EXT-X-MAP is used (init sent separately). If true, don't concatenate init with segment.",
    )


class MPDInitParams(GenericParams):
    init_url: str = Field(..., description="The URL of the initialization segment.")
    mime_type: str = Field(..., description="The MIME type of the segment.")
    key_id: Optional[str] = Field(None, description="The DRM key ID (optional).")
    key: Optional[str] = Field(None, description="The DRM key (optional).")
    is_live: Annotated[
        Optional[bool], Field(default=None, alias="is_live", description="Whether the parent MPD is live.")
    ]
    init_range: Optional[str] = Field(
        None, description="Byte range for the initialization segment (e.g., '0-11568'). Used for SegmentBase MPDs."
    )


class ExtractorURLParams(GenericParams):
    host: Literal[
        "Doodstream",
        "FileLions",
        "FileMoon",
        "F16Px",
        "Mixdrop",
        "Gupload",
        "Uqload",
        "Streamtape",
        "StreamWish",
        "Supervideo",
        "VixCloud",
        "Okru",
        "Maxstream",
        "LiveTV",
        "LuluStream",
        "DLHD",
        "Fastream",
        "TurboVidPlay",
        "Vidmoly",
        "Vidoza",
        "Voe",
        "Sportsonline",
    ] = Field(..., description="The host to extract the URL from.")
    destination: Annotated[str, Field(description="The URL of the stream.", alias="d")]
    redirect_stream: bool = Field(False, description="Whether to redirect to the stream endpoint automatically.")
    extra_params: Dict[str, Any] = Field(
        default_factory=dict,
        description="Additional parameters required for specific extractors (e.g., stream_title for LiveTV)",
    )

    @field_validator("extra_params", mode="before")
    def validate_extra_params(cls, value: Any):
        if isinstance(value, str):
            return json.loads(value)
        return value
