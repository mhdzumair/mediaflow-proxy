import re
import base64
import json
from typing import Dict, Any
from urllib.parse import urlparse

from mediaflow_proxy.extractors.base import BaseExtractor, ExtractorError


class GuploadExtractor(BaseExtractor):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mediaflow_endpoint = "hls_manifest_proxy"

    async def extract(self, url: str) -> Dict[str, Any]:
        parsed = urlparse(url)
        if not parsed.hostname or "gupload.xyz" not in parsed.hostname:
            raise ExtractorError("GUPLOAD: Invalid domain")

        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/144 Safari/537.36"
            ),
            "Referer": "https://gupload.xyz/",
            "Origin": "https://gupload.xyz",
        }

        # --- Fetch embed page ---
        response = await self._make_request(url, headers=headers)
        html = response.text

        # --- Extract base64 payload ---
        match = re.search(r"decodePayload\('([^']+)'\)", html)
        if not match:
            raise ExtractorError("GUPLOAD: Payload not found")

        encoded = match.group(1).strip()

        # --- Decode payload ---
        try:
            decoded = base64.b64decode(encoded).decode("utf-8", "ignore")
            # payload format: <junk>|{json}
            json_part = decoded.split("|", 1)[1]
            payload = json.loads(json_part)
        except Exception:
            raise ExtractorError("GUPLOAD: Payload decode failed")

        # --- Extract HLS URL ---
        hls_url = payload.get("videoUrl")
        if not hls_url:
            raise ExtractorError("GUPLOAD: videoUrl missing")

        # --- Validate stream (prevents client timeout) ---
        test = await self._make_request(hls_url, headers=headers, raise_on_status=False)
        if test.status >= 400:
            raise ExtractorError(f"GUPLOAD: Stream unavailable ({test.status})")

        # Return MASTER playlist
        return {
            "destination_url": hls_url,
            "request_headers": headers,
            "mediaflow_endpoint": self.mediaflow_endpoint,
        }
