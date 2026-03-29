# https://github.com/Gujal00/ResolveURL/blob/55c7f66524ebd65bc1f88650614e627b00167fa0/script.module.resolveurl/lib/resolveurl/plugins/f16px.py

import base64
import json
import re
from typing import Dict, Any
from urllib.parse import urlparse

from mediaflow_proxy.extractors.base import BaseExtractor, ExtractorError
from mediaflow_proxy.utils import python_aesgcm


class F16PxExtractor(BaseExtractor):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mediaflow_endpoint = "hls_manifest_proxy"

    @staticmethod
    def _b64url_decode(value: str) -> bytes:
        # base64url -> base64
        value = value.replace("-", "+").replace("_", "/")
        padding = (-len(value)) % 4
        if padding:
            value += "=" * padding
        return base64.b64decode(value)

    def _join_key_parts(self, parts) -> bytes:
        return b"".join(self._b64url_decode(p) for p in parts)

    async def extract(self, url: str) -> Dict[str, Any]:
        parsed = urlparse(url)
        host = parsed.netloc
        origin = f"{parsed.scheme}://{parsed.netloc}"

        match = re.search(r"/e/([A-Za-z0-9]+)", parsed.path or "")
        if not match:
            raise ExtractorError("F16PX: Invalid embed URL")

        media_id = match.group(1)
        api_url = f"https://{host}/api/videos/{media_id}/embed/playback"

        headers = self.base_headers.copy()
        headers["referer"] = f"https://{host}/"

        resp = await self._make_request(api_url, headers=headers)
        try:
            data = resp.json()
        except Exception:
            raise ExtractorError("F16PX: Invalid JSON response")

        # Case 1: plain sources
        if "sources" in data and data["sources"]:
            src = data["sources"][0].get("url")
            if not src:
                raise ExtractorError("F16PX: Empty source URL")
            return {
                "destination_url": src,
                "request_headers": headers,
                "mediaflow_endpoint": self.mediaflow_endpoint,
            }

        # Case 2: encrypted playback
        pb = data.get("playback")
        if not pb:
            raise ExtractorError("F16PX: No playback data")

        try:
            iv = self._b64url_decode(pb["iv"])  # nonce
            key = self._join_key_parts(pb["key_parts"])  # AES key
            payload = self._b64url_decode(pb["payload"])  # ciphertext + tag

            cipher = python_aesgcm.new(key)
            decrypted = cipher.open(iv, payload)  # AAD = '' like ResolveURL

            if decrypted is None:
                raise ExtractorError("F16PX: GCM authentication failed")

            decrypted_json = json.loads(decrypted.decode("utf-8", "ignore"))

        except ExtractorError:
            raise
        except Exception as e:
            raise ExtractorError(f"F16PX: Decryption failed ({e})")

        sources = decrypted_json.get("sources") or []
        if not sources:
            raise ExtractorError("F16PX: No sources after decryption")

        best = sources[0].get("url")
        if not best:
            raise ExtractorError("F16PX: Empty source URL after decryption")

        self.base_headers.clear()
        self.base_headers["referer"] = f"{origin}/"
        self.base_headers["origin"] = origin
        self.base_headers["Accept-Language"] = "en-US,en;q=0.5"
        self.base_headers["Accept"] = "*/*"
        self.base_headers["user-agent"] = "Mozilla/5.0 (X11; Linux x86_64; rv:138.0) Gecko/20100101 Firefox/138.0"

        return {
            "destination_url": best,
            "request_headers": self.base_headers,
            "mediaflow_endpoint": self.mediaflow_endpoint,
        }
