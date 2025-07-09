import json
import re
from typing import Dict, Any
from urllib.parse import urlparse, parse_qs

from bs4 import BeautifulSoup, SoupStrainer

from mediaflow_proxy.extractors.base import BaseExtractor, ExtractorError


class VixCloudExtractor(BaseExtractor):
    """VixCloud URL extractor."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mediaflow_endpoint = "hls_manifest_proxy"

    async def version(self, site_url: str) -> str:
        """Get version of VixCloud Parent Site."""
        base_url = f"{site_url}/request-a-title"
        response = await self._make_request(
            base_url,
            headers={
                "Referer": f"{site_url}/",
                "Origin": f"{site_url}",
            },
        )
        if response.status_code != 200:
            raise ExtractorError("Outdated Url")
        # Soup the response
        soup = BeautifulSoup(response.text, "lxml", parse_only=SoupStrainer("div", {"id": "app"}))
        if soup:
            # Extract version
            try:
                data = json.loads(soup.find("div", {"id": "app"}).get("data-page"))
                return data["version"]
            except (KeyError, json.JSONDecodeError, AttributeError) as e:
                raise ExtractorError(f"Failed to parse version: {e}")

    async def extract(self, url: str, **kwargs) -> Dict[str, Any]:
        """Extract Vixcloud URL."""
        if "iframe" in url:
            site_url = url.split("/iframe")[0]
            version = await self.version(site_url)
            response = await self._make_request(url, headers={"x-inertia": "true", "x-inertia-version": version})
            soup = BeautifulSoup(response.text, "lxml", parse_only=SoupStrainer("iframe"))
            iframe = soup.find("iframe").get("src")
            response = await self._make_request(iframe, headers={"x-inertia": "true", "x-inertia-version": version})
        elif "movie" in url or "tv" in url:
            response = await self._make_request(url)
        
        if response.status_code != 200:
            raise ExtractorError("Failed to extract URL components, Invalid Request")
        soup = BeautifulSoup(response.text, "lxml", parse_only=SoupStrainer("body"))
        if soup:
            script = soup.find("body").find("script").text
            token = re.search(r"'token':\s*'(\w+)'", script).group(1)
            expires = re.search(r"'expires':\s*'(\d+)'", script).group(1)
            server_url = re.search(r"url:\s*'([^']+)'", script).group(1)
            if "?b=1" in server_url:
                final_url = f'{server_url}&token={token}&expires={expires}'
            else:
                final_url = f"{server_url}?token={token}&expires={expires}"
            if "window.canPlayFHD = true" in script:
                final_url += "&h=1"
            self.base_headers["referer"] = url
            return {
                "destination_url": final_url,
                "request_headers": self.base_headers,
                "mediaflow_endpoint": self.mediaflow_endpoint,
            }
