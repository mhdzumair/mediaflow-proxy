import json
import re
from typing import Annotated, Literal, Dict, Any, Optional

from pydantic import BaseModel, Field, IPvAnyAddress, ConfigDict, field_validator


def validate_resolution_format(value: str) -> str:
    """Validate and normalize resolution format (e.g., '1080p', '720p')."""
    if not re.match(r'^\d+p$', value):
        raise ValueError(f"Invalid resolution format '{value}'. Expected format: '1080p', '720p', etc.")
    return value


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
        default_factory=dict, description="Headers to be included in the response."
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
        default_factory=dict, description="Headers to be included in the response."
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

    @field_validator("resolution", mode="before")
    @classmethod
    def validate_resolution(cls, value: Any) -> Optional[str]:
        if value is None:
            return None
        return validate_resolution_format(str(value))


class MPDManifestParams(GenericParams):
    destination: Annotated[str, Field(description="The URL of the MPD manifest.", alias="d")]
    key_id: Optional[str] = Field(None, description="The DRM key ID (optional).")
    key: Optional[str] = Field(None, description="The DRM key (optional).")
    resolution: Optional[str] = Field(
        None,
        description="Select a specific resolution stream (e.g., '1080p', '720p', '480p'). Falls back to closest lower resolution if exact match not found.",
    )

    @field_validator("resolution", mode="before")
    @classmethod
    def validate_resolution(cls, value: Any) -> Optional[str]:
        if value is None:
            return None
        return validate_resolution_format(str(value))


class MPDPlaylistParams(GenericParams):
    destination: Annotated[str, Field(description="The URL of the MPD manifest.", alias="d")]
    profile_id: str = Field(..., description="The profile ID to generate the playlist for.")
    key_id: Optional[str] = Field(None, description="The DRM key ID (optional).")
    key: Optional[str] = Field(None, description="The DRM key (optional).")


class MPDSegmentParams(GenericParams):
    init_url: str = Field(..., description="The URL of the initialization segment.")
    segment_url: str = Field(..., description="The URL of the media segment.")
    mime_type: str = Field(..., description="The MIME type of the segment.")
    key_id: Optional[str] = Field(None, description="The DRM key ID (optional).")
    key: Optional[str] = Field(None, description="The DRM key (optional).")
    is_live: Annotated[Optional[bool], Field(default=None, alias="is_live", description="Whether the parent MPD is live.")]


class ExtractorURLParams(GenericParams):
    host: Literal[
        "Doodstream", "FileLions", "FileMoon", "F16Px", "Mixdrop", "Uqload", "Streamtape", "StreamWish", "Supervideo", "VixCloud", "Okru", "Maxstream", "LiveTV", "LuluStream", "DLHD", "Fastream", "TurboVidPlay", "Vidmoly", "Vidoza", "Voe", "Sportsonline"
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
