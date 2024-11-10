from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse, RedirectResponse
from .extractors.doodstream import doodstream_url
from .extractors.uqload import uqload_url
from .extractors.mixdrop import mixdrop_url
from mediaflow_proxy.configs import settings

extractor_router = APIRouter()
host_map = {"Doodstream": doodstream_url, "Mixdrop": mixdrop_url, "Uqload": uqload_url}


@extractor_router.get("/extractor")
async def extract_media_url(
    d: str = Query(..., description="Extract Clean Link from various Hosts"),
    use_request_proxy: bool = Query(False, description="Whether to use the MediaFlow proxy configuration."),
    host: str = Query(
        ..., description='From which Host the URL comes from, here avaiable ones: "Doodstream","Mixdrop","Uqload"'
    ),
    redirect_stream: bool = Query(
        False,
        description="If enabled the response will be redirected to stream endpoint automatically and the stream will be proxied",
    ),
):
    """
    Extract a clean link from DoodStream,Mixdrop,Uqload

    Args: request (Request): The incoming HTTP request

    Returns: The clean link (url) and the headers needed to access the url

    N.B. You can't use a rotating proxy if type is set to "Doodstream"
    """
    try:
        final_url, headers_dict = await host_map[host](d, use_request_proxy)
    except KeyError:
        return JSONResponse(
            status_code=400,
            content={"error": f"Invalid host type. Available hosts: {', '.join(host_map.keys())}"}
        )
    except ValueError as e:
        return JSONResponse(status_code=400, content={"error": str(e)})
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": "Internal server error"})
    if redirect_stream == True:
        formatted_headers = format_headers(headers_dict)
        redirected_stream = f"/proxy/stream?api_password={settings.api_password}&d={final_url}&{formatted_headers}"
        return RedirectResponse(url=redirected_stream)
    elif redirect_stream == False:
        return JSONResponse(content={"url": final_url, "headers": headers_dict})


def format_headers(headers):
    """
    Format the headers dictionary into a query string format with 'h_' prefix.

    Args:
    - headers: A dictionary of headers.

    Returns:
    - A query string formatted string of headers.
    """
    return "&".join(f"h_{key}={value}" for key, value in headers.items())
