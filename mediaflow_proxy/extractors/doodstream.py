import httpx
import time
import re
from mediaflow_proxy.configs import settings
async def doodstream_url(d: str, use_request_proxy: bool):
    async with httpx.AsyncClient(proxy=settings.proxy_url if use_request_proxy else None) as client:
        headers = {
                "Range": "bytes=0-",
                "Referer": "https://d000d.com/",
            }

        response = await client.get(d,  follow_redirects=True)
        if response.status_code == 200:
            # Get unique timestamp for the request      
            real_time = str(int(time.time()))
            pattern = r"(\/pass_md5\/.*?)'.*(\?token=.*?expiry=)"
            match = re.search(pattern, response.text, re.DOTALL)
            if match:
                url =f'https://d000d.com{match[1]}'
                rebobo = await client.get(url, headers=headers, follow_redirects=True)
                final_url = f'{rebobo.text}123456789{match[2]}{real_time}'
                return final_url