from typing import Literal, Dict, Any, Optional

from pydantic import BaseModel, Field, IPvAnyAddress, ConfigDict


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
    expiration: Optional[int] = Field(
        None, description="Expiration time for the URL in seconds. If not provided, the URL will not expire."
    )
    api_password: Optional[str] = Field(
        None, description="API password for encryption. If not provided, the URL will only be encoded."
    )
    ip: Optional[IPvAnyAddress] = Field(None, description="The IP address to restrict the URL to.")


class GenericParams(BaseModel):
    model_config = ConfigDict(populate_by_name=True)


class HLSManifestParams(GenericParams):
    destination: str = Field(..., description="The URL of the HLS manifest.", alias="d")
    key_url: Optional[str] = Field(
        None,
        description="The HLS Key URL to replace the original key URL. Defaults to None. (Useful for bypassing some sneaky protection)",
    )


class ProxyStreamParams(GenericParams):
    destination: str = Field(..., description="The URL of the stream.", alias="d")


class MPDManifestParams(GenericParams):
    destination: str = Field(..., description="The URL of the MPD manifest.", alias="d")
    key_id: Optional[str] = Field(None, description="The DRM key ID (optional).")
    key: Optional[str] = Field(None, description="The DRM key (optional).")


class MPDPlaylistParams(GenericParams):
    destination: str = Field(..., description="The URL of the MPD manifest.", alias="d")
    profile_id: str = Field(..., description="The profile ID to generate the playlist for.")
    key_id: Optional[str] = Field(None, description="The DRM key ID (optional).")
    key: Optional[str] = Field(None, description="The DRM key (optional).")


class MPDSegmentParams(GenericParams):
    init_url: str = Field(..., description="The URL of the initialization segment.")
    segment_url: str = Field(..., description="The URL of the media segment.")
    mime_type: str = Field(..., description="The MIME type of the segment.")
    key_id: Optional[str] = Field(None, description="The DRM key ID (optional).")
    key: Optional[str] = Field(None, description="The DRM key (optional).")


class ExtractorURLParams(GenericParams):
    host: Literal["Doodstream", "Mixdrop", "Uqload", "Streamtape", "Supervideo", "VixCloud", "Okru", "Maxstream", "LiveTV"] = Field(
        ..., description="The host to extract the URL from."
    )
    destination: str = Field(..., description="The URL of the stream.", alias="d")
    redirect_stream: bool = Field(False, description="Whether to redirect to the stream endpoint automatically.")
    extra_params: Dict[str, Any] = Field(
        default_factory=dict,
        description="Additional parameters required for specific extractors (e.g., stream_title for LiveTV)",
    )
