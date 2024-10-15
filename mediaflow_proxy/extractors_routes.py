from fastapi import APIRouter,Query
from fastapi.responses import JSONResponse
from .extractors.doodstream import doodstream_url
from .extractors.uqload import uqload_url
from .extractors.mixdrop import mixdrop_url
extractor_router = APIRouter()


@extractor_router.get("/doodstream")
async def doodstream_extractor(d: str = Query(..., description="DoodStream URL"), use_request_proxy: bool = Query(False, description="Whether to use the MediaFlow proxy configuration.")):
    '''
    Extract a clean link from DoodStream URL

    Args: request (Request): The incoming HTTP request

    Returns: The clean link (url) and the headers needed to access the url
    
    N.B. You can't use a rotating proxy for this endpoint
    '''
    final_url = await doodstream_url(d,use_request_proxy)
    headers_dict = {
        "Referer": "https://d000d.com/"
    } #Needed Headers to access the Response
    return JSONResponse(content={"url": final_url,"headers": headers_dict})



@extractor_router.get("/uqload")
async def uqload_extractor(d: str = Query(..., description="Uqload Url"), use_request_proxy: bool = Query(False, description="Whether to use the MediaFlow proxy configuration.")):
    '''
    Extract a clean link from Uqload URL

    Args: request (Request): The incoming HTTP request

    Returns: The clean link (url) and the headers needed to access the url

    '''
    final_url = await uqload_url(d,use_request_proxy)
    headers_dict = {
        "Referer": "https://uqload.to/"
    }
    return JSONResponse(content={"url": final_url,"headers": headers_dict})


@extractor_router.get("/mixdrop")
async def mixdrop_extractor(d: str = Query(..., description="MixDrop URL",), use_request_proxy: bool = Query(False, description="Whether to use the MediaFlow proxy configuration.")):
    '''
    Extract a clean link from MixDrop URL

    Args: request (Request): The incoming HTTP request

    Returns: The clean link (url) and the headers needed to access the url

    '''
    final_url = await mixdrop_url(d,use_request_proxy)
    headers_dict = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.10; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3"
    }
    return JSONResponse(content={"url": final_url,"headers": headers_dict})


