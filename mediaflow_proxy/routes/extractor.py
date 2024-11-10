from typing import Annotated

from fastapi import APIRouter, Query, HTTPException
from fastapi.responses import RedirectResponse

from mediaflow_proxy.configs import settings
from mediaflow_proxy.extractors.factory import ExtractorFactory
from mediaflow_proxy.schemas import ExtractorURLParams

extractor_router = APIRouter()


@extractor_router.get("/video")
async def extract_url(
    extractor_params: Annotated[ExtractorURLParams, Query()],
):
    """Extract clean links from various video hosting services."""
    try:
        extractor = ExtractorFactory.get_extractor(extractor_params.host, extractor_params.use_request_proxy)
        final_url, headers = await extractor.extract(extractor_params.destination)

        if extractor_params.redirect_stream:
            formatted_headers = "&".join(f"h_{k}={v}" for k, v in headers.items())
            stream_url = f"/proxy/stream?api_password={settings.api_password}&d={final_url}&{formatted_headers}"
            return RedirectResponse(url=stream_url)

        return {"url": final_url, "headers": headers}

    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Extraction failed: {str(e)}")
