from pydantic import BaseModel, Field, IPvAnyAddress


class GenerateUrlRequest(BaseModel):
    mediaflow_proxy_url: str = Field(..., description="The base URL for the mediaflow proxy.")
    endpoint: str | None = Field(None, description="The specific endpoint to be appended to the base URL.")
    destination_url: str | None = Field(None, description="The destination URL to which the request will be proxied.")
    query_params: dict | None = Field(None, description="Query parameters to be included in the request.")
    request_headers: dict | None = Field(None, description="Headers to be included in the request.")
    response_headers: dict | None = Field(None, description="Headers to be included in the response.")
    expiration: int | None = Field(
        None, description="Expiration time for the URL in seconds. If not provided, the URL will not expire."
    )
    api_password: str | None = Field(
        None, description="API password for encryption. If not provided, the URL will only be encoded."
    )
    ip: IPvAnyAddress | None = Field(None, description="The IP address to restrict the URL to.")
