import httpx
import re
from mediaflow_proxy.configs import settings


from typing import Tuple, Dict, Optional

async def uqload_url(d: str, use_request_proxy: bool) -> Tuple[Optional[str], Dict[str, str]]:
    """
    Extract video URL from Uqload.
    
    Args:
        d: The Uqload video URL
        use_request_proxy: Whether to use proxy for the request
    
    Returns:
        Tuple containing the extracted video URL (or None if not found) and headers dictionary
    
    Raises:
        httpx.HTTPError: If the HTTP request fails
    """
    if not d.startswith(('http://', 'https://')):
        raise ValueError("Invalid URL format")

    REFERER = "https://uqload.to/"
    final_url = None

    async with httpx.AsyncClient(proxy=settings.proxy_url if use_request_proxy else None) as client:
        try:
            response = await client.get(d, follow_redirects=True)
            response.raise_for_status()
            
            # Look for video URL in response using a more robust pattern
            video_url_match = re.search(r'sources:\s*\[(["\'])(.*?)\1\]', response.text)
            if video_url_match:
                final_url = video_url_match.group(2)
            
            return final_url, {"Referer": REFERER}
        except httpx.HTTPError as e:
            # Log the error here if logging is available
            raise
