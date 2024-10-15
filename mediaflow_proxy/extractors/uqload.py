import httpx
import re
from mediaflow_proxy.configs import settings


async def uqload_url(d: str, use_request_proxy: bool):
    async with httpx.AsyncClient(proxy=settings.proxy_url if use_request_proxy else None) as client:

        response = await client.get(d, follow_redirects=True)
        video_url_match = re.search(r'sources: \["(.*?)"\]', response.text)
        if video_url_match:
            final_url = video_url_match.group(1)
        return final_url