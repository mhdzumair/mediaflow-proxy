from typing import Annotated

from fastapi import APIRouter, Query, HTTPException, Request, Depends
from fastapi.responses import RedirectResponse

from mediaflow_proxy.configs import settings
from mediaflow_proxy.extractors.factory import ExtractorFactory
from mediaflow_proxy.schemas import ExtractorURLParams
from mediaflow_proxy.utils.http_utils import (
    encode_mediaflow_proxy_url,
    get_original_scheme,
    ProxyRequestHeaders,
    get_proxy_headers,
)

extractor_router = APIRouter()


@extractor_router.get("/video")
async def extract_url(
    extractor_params: Annotated[ExtractorURLParams, Query()],
    request: Request,
    proxy_headers: Annotated[ProxyRequestHeaders, Depends(get_proxy_headers)],
):
    """Extract clean links from various video hosting services."""
    try:
        extractor = ExtractorFactory.get_extractor(extractor_params.host, proxy_headers.request)
        final_url, headers = await extractor.extract(extractor_params.destination)

        if extractor_params.redirect_stream:
            headers.update(proxy_headers.request)
            stream_url = encode_mediaflow_proxy_url(
                str(request.url_for("proxy_stream_endpoint").replace(scheme=get_original_scheme(request))),
                destination_url=final_url,
                query_params={"api_password": settings.api_password},
                request_headers=headers,
                response_headers=proxy_headers.response,
            )
            return RedirectResponse(url=stream_url)

        return {"url": final_url, "headers": headers}

    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Extraction failed: {str(e)}")
