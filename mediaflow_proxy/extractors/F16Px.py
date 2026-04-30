# https://github.com/Gujal00/ResolveURL/blob/55c7f66524ebd65bc1f88650614e627b00167fa0/script.module.resolveurl/lib/resolveurl/plugins/f16px.py
import base64
import json
import re
import time
import hmac
import hashlib
import os
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
        value = value.replace("-", "+").replace("_", "/")
        padding = (-len(value)) % 4
        if padding:
            value += "=" * padding
        return base64.b64decode(value)

    @staticmethod
    def _b64url_encode(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    def _join_key_parts(self, parts) -> bytes:
        return b"".join(self._b64url_decode(p) for p in parts)

    @staticmethod
    def _pick_best(sources: list) -> str:
        """Return URL of highest-quality source by numeric label."""
        def label_key(s):
            try:
                return int(s.get("label", 0))
            except (ValueError, TypeError):
                return 0
        return sorted(sources, key=label_key, reverse=True)[0]["url"]

    def _make_fingerprint(self) -> dict:
        viewer_id = self._b64url_encode(os.urandom(16))
        device_id = self._b64url_encode(os.urandom(16))
        now = int(time.time())

        token_payload = {
            "viewer_id": viewer_id,
            "device_id": device_id,
            "confidence": 0.93,
            "iat": now,
            "exp": now + 600,
        }
        payload_b64 = self._b64url_encode(
            json.dumps(token_payload, separators=(",", ":")).encode()
        )
        sig = hmac.new(b"", payload_b64.encode(), hashlib.sha256).digest()
        token = f"{payload_b64}.{self._b64url_encode(sig)}"

        return {
            "fingerprint": {
                "token": token,
                "viewer_id": viewer_id,
                "device_id": device_id,
                "confidence": 0.93,
            }
        }

    def _decrypt_playback(self, pb: dict) -> list:
        """Decrypt primary payload, fall back to payload2+decrypt_keys."""
        iv      = self._b64url_decode(pb["iv"])
        key     = self._join_key_parts(pb["key_parts"])
        payload = self._b64url_decode(pb["payload"])

        cipher    = python_aesgcm.new(key)
        decrypted = cipher.open(iv, payload)

        if decrypted is not None:
            sources = json.loads(decrypted.decode("utf-8", "ignore")).get("sources") or []
            if sources:
                return sources

        # Fallback: payload2 + decrypt_keys
        decrypt_keys = pb.get("decrypt_keys") or {}
        iv2  = pb.get("iv2")
        pay2 = pb.get("payload2")
        if iv2 and pay2 and decrypt_keys:
            iv2  = self._b64url_decode(iv2)
            pay2 = self._b64url_decode(pay2)
            for key_b64 in decrypt_keys.values():
                try:
                    key2      = self._b64url_decode(key_b64)
                    cipher2   = python_aesgcm.new(key2)
                    decrypted = cipher2.open(iv2, pay2)
                    if decrypted:
                        sources = json.loads(decrypted.decode("utf-8", "ignore")).get("sources") or []
                        if sources:
                            return sources
                except Exception:
                    continue

        return []

    async def extract(self, url: str) -> Dict[str, Any]:
        parsed   = urlparse(url)
        host     = parsed.netloc
        origin   = f"{parsed.scheme}://{parsed.netloc}"

        match = re.search(r"/e/([A-Za-z0-9]+)", parsed.path or "")
        if not match:
            raise ExtractorError("F16PX: Invalid embed URL")
        media_id = match.group(1)

        api_url = f"https://{host}/api/videos/{media_id}/embed/playback"

        headers = self.base_headers.copy()
        headers["referer"]      = f"https://{host}/e/{media_id}"
        headers["origin"]       = origin
        headers["content-type"] = "application/json"

        resp = await self._make_request(
            api_url,
            headers=headers,
            method="POST",
            json=self._make_fingerprint(),
        )

        try:
            data = resp.json()
        except Exception:
            raise ExtractorError("F16PX: Invalid JSON response")

        # Case 1: plain sources
        if data.get("sources"):
            best = self._pick_best(data["sources"])
            return {
                "destination_url": best,
                "request_headers": headers,
                "mediaflow_endpoint": self.mediaflow_endpoint,
            }

        # Case 2: encrypted playback
        pb = data.get("playback")
        if not pb:
            raise ExtractorError("F16PX: No playback data")

        try:
            sources = self._decrypt_playback(pb)
        except Exception as e:
            raise ExtractorError(f"F16PX: Decryption failed ({e})")

        if not sources:
            raise ExtractorError("F16PX: No sources after decryption")

        best = self._pick_best(sources)

        out_headers = {
            "referer":          f"{origin}/",
            "origin":           origin,
            "Accept-Language":  "en-US,en;q=0.5",
            "Accept":           "*/*",
            "user-agent":       "Mozilla/5.0 (X11; Linux x86_64; rv:138.0) Gecko/20100101 Firefox/138.0",
        }
        return {
            "destination_url":    best,
            "request_headers":    out_headers,
            "mediaflow_endpoint": self.mediaflow_endpoint,
        }
