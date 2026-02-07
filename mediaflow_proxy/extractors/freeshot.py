import logging
import re
import urllib.parse
from typing import Dict

from mediaflow_proxy.extractors.base import BaseExtractor, ExtractorError

logger = logging.getLogger(__name__)

class FreeshotExtractor(BaseExtractor):
    """
    Extractor for Freeshot (popcdn.day).
    """
    
    def __init__(self, request_headers: dict):
        super().__init__(request_headers)
        self.mediaflow_endpoint = "hls_proxy"
        self.base_headers.update({
            "Referer": "https://thisnot.business/",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        })

    async def extract(self, url: str, **kwargs) -> Dict:

        channel_code = url
        
        if "go.php?stream=" in url:
            channel_code = url.split("go.php?stream=")[-1].split("&")[0]
        elif "popcdn.day/player/" in url:
            channel_code = url.split("/player/")[-1].split("?")[0].split("/")[0]
        elif url.startswith('http'):
            channel_code = urllib.parse.urlparse(url).path.split("/")[-1]
        
        target_url = f"https://popcdn.day/player/{urllib.parse.quote(channel_code)}"
        logger.info(f"FreeshotExtractor: Risoluzione {target_url} (channel: {channel_code})")
        
        try:
            response = await self._make_request(target_url, headers=self.base_headers)
            body = response.text
        except Exception as e:
            raise ExtractorError(f"Freeshot extraction failed: {str(e)}")
        
        # Token extraction
        match = re.search(r'currentToken:\s*["\']([^"\']+)["\']', body)
        if not match:
            match = re.search(r'frameborder="0"\s+src="([^"]+)"', body, re.IGNORECASE)
            if match:
                iframe_url = match.group(1)
                token_match = re.search(r'token=([^&]+)', iframe_url)
                if token_match:
                    token = token_match.group(1)
                else:
                    raise ExtractorError("Freeshot token not found in iframe")
            else:
                raise ExtractorError("Freeshot token/iframe not found in page content")
        else:
            token = match.group(1)
        
        m3u8_url = f"https://planetary.lovecdn.ru/{channel_code}/tracks-v1a1/mono.m3u8?token={token}"
        logger.info(f"FreeshotExtractor: Risolto -> {m3u8_url}")
        
        return {
            "destination_url": m3u8_url,
            "request_headers": {
                "User-Agent": self.base_headers.get("user-agent"),
                "Referer": "https://popcdn.day/",
                "Origin": "https://popcdn.day"
            },
            "mediaflow_endpoint": self.mediaflow_endpoint
        }
