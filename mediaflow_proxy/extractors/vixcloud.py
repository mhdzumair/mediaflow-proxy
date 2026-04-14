import json
import re
from typing import Dict, Any, Optional
from urllib.parse import urlparse, urlunparse

from bs4 import BeautifulSoup

from mediaflow_proxy.extractors.base import BaseExtractor, ExtractorError


def ensure_m3u8(url: str) -> str:
    """Ensure HLS playlist ends in .m3u8 if it's a playlist directory."""
    try:
        parsed = urlparse(url)
        path_parts = parsed.path.split("/")
        if "playlist" in path_parts:
            idx = path_parts.index("playlist")
            if idx < len(path_parts) - 1:
                filename = path_parts[idx + 1]
                if filename and "." not in filename:
                    path_parts[idx + 1] = f"{filename}.m3u8"
                    new_path = "/".join(path_parts)
                    return urlunparse(parsed._replace(path=new_path))
        return url
    except Exception:
        return url


class VixBaseExtractor(BaseExtractor):
    """Base logic for Vix-style extractors."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mediaflow_endpoint = "hls_manifest_proxy"

    async def _extract_from_html(self, html: str, url: str) -> Dict[str, Any]:
        soup = BeautifulSoup(html, "lxml")
        scripts = soup.find_all("script")
        target_script = None

        for s in scripts:
            if s.string and "'token':" in s.string and "'expires':" in s.string:
                target_script = s.string
                break

        if not target_script:
            raise ExtractorError("Player script not found")

        try:
            # Multi-mode regex for ' or "
            token = re.search(r"['\"]token['\"]:\s*['\"]([^'\"]+)['\"]", target_script).group(1)
            expires = re.search(r"['\"]expires['\"]:\s*['\"]([^'\"]+)['\"]", target_script).group(1)
            server_url = re.search(r"url:\s*['\"]([^'\"]+)['\"]", target_script).group(1)
        except (AttributeError, IndexError):
            raise ExtractorError("Failed to parse token, expires, or url")

        # Fix ?b:1 typo
        server_url = server_url.replace("?b:1", "?b=1")

        sep = "&" if "?" in server_url else "?"
        final_url = f"{server_url}{sep}token={token}&expires={expires}&h=1"
        final_url = ensure_m3u8(final_url)

        self.base_headers["referer"] = url
        return {
            "destination_url": final_url,
            "request_headers": self.base_headers,
            "mediaflow_endpoint": self.mediaflow_endpoint,
        }


class VixCloudExtractor(VixBaseExtractor):
    """VixCloud URL extractor."""

    async def version(self, site_url: str) -> str:
        base_url = f"{site_url}/request-a-title"
        response = await self._make_request(
            base_url,
            headers={"Referer": f"{site_url}/", "Origin": site_url},
        )
        try:
            soup = BeautifulSoup(response.text, "lxml")
            app_div = soup.find("div", {"id": "app"})
            data = json.loads(app_div.get("data-page"))
            return data["version"]
        except Exception as e:
            raise ExtractorError(f"Version fetch fail: {e}")

    async def extract(self, url: str, **kwargs) -> Dict[str, Any]:
        headers = {}
        if "iframe" in url:
            site_url = url.split("/iframe")[0]
            v = await self.version(site_url)
            headers.update({"x-inertia": "true", "x-inertia-version": v})

        response = await self._make_request(url, headers=headers)
        return await self._extract_from_html(response.text, url)


class VixSrcExtractor(VixBaseExtractor):
    """VixSrc URL extractor."""

    async def extract(self, url: str, **kwargs) -> Dict[str, Any]:
        response = await self._make_request(
            url,
            headers={
                "Referer": url,
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            },
        )
        return await self._extract_from_html(response.text, url)
