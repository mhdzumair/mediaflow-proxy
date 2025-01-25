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

    async def version(self, domain: str) -> str:
        """Get version of VixCloud Parent Site."""
        base_url = f"https://streamingcommunity.{domain}/richiedi-un-titolo"
        response = await self._make_request(
            base_url,
            headers={
                "Referer": f"https://streamingcommunity.{domain}/",
                "Origin": f"https://streamingcommunity.{domain}",
            },
        )
        if response.status_code != 200:
            raise ExtractorError("Outdated Domain")
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
        domain = url.split("://")[1].split("/")[0].split(".")[1]
        version = await self.version(domain)
        response = await self._make_request(url, headers={"x-inertia": "true", "x-inertia-version": version})
        soup = BeautifulSoup(response.text, "lxml", parse_only=SoupStrainer("iframe"))
        iframe = soup.find("iframe").get("src")
        parsed_url = urlparse(iframe)
        query_params = parse_qs(parsed_url.query)
        response = await self._make_request(iframe, headers={"x-inertia": "true", "x-inertia-version": version})

        if response.status_code != 200:
            raise ExtractorError("Failed to extract URL components, Invalid Request")
        soup = BeautifulSoup(response.text, "lxml", parse_only=SoupStrainer("body"))
        if soup:
            script = soup.find("body").find("script").text
            token = re.search(r"'token':\s*'(\w+)'", script).group(1)
            expires = re.search(r"'expires':\s*'(\d+)'", script).group(1)
            vixid = iframe.split("/embed/")[1].split("?")[0]
            base_url = iframe.split("://")[1].split("/")[0]
            final_url = f"https://{base_url}/playlist/{vixid}.m3u8?token={token}&expires={expires}"
            if "canPlayFHD" in query_params:
                # canPlayFHD = "h=1"
                final_url += "&h=1"
            if "b" in query_params:
                # b = "b=1"
                final_url += "&b=1"
            self.base_headers["referer"] = url
            return {
                "destination_url": final_url,
                "request_headers": self.base_headers,
                "mediaflow_endpoint": self.mediaflow_endpoint,
            }
