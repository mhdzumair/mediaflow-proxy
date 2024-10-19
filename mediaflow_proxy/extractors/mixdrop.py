import httpx
import re
import string
from mediaflow_proxy.configs import settings


async def mixdrop_url(d: str, use_request_proxy: bool):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.10; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3",
        "Accept-Language": "en-US,en;q=0.5",
    }
    async with httpx.AsyncClient(proxy=settings.proxy_url if use_request_proxy else None) as client:
        response = await client.get(d, headers=headers, follow_redirects=True, timeout=30)
        [s1, s2] = re.search(r"\}\('(.+)',.+,'(.+)'\.split", response.text).group(1, 2)
        schema = s1.split(";")[2][5:-1]
        terms = s2.split("|")
        charset = string.digits + string.ascii_letters
        d = dict()
        for i in range(len(terms)):
            d[charset[i]] = terms[i] or charset[i]
        final_url = "https:"
        for c in schema:
            final_url += d[c] if c in d else c
        headers_dict = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.10; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3"
        }
    return final_url, headers_dict
