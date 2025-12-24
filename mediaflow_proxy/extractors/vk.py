import json
import re
from urllib.parse import urlparse
from typing import Dict, Any

from mediaflow_proxy.extractors.base import BaseExtractor, ExtractorError

UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/129.0 Safari/537.36"
)

REFERER = "https://vkvideo.ru/"
ORIGIN = "https://vkvideo.ru"


class VKExtractor(BaseExtractor):
    async def extract(self, url: str, **kwargs) -> Dict[str, Any]:
        embed_url = self._normalize(url)

        response = await self._make_request(
            self._ajax_url(embed_url),
            method="POST",
            data=self._ajax_data(embed_url),
            headers={
                "User-Agent": UA,
                "Referer": REFERER,
                "Origin": ORIGIN,
                "X-Requested-With": "XMLHttpRequest",
            },
        )

        text = response.text.lstrip("<!--")
        try:
            data = json.loads(text)
        except Exception:
            raise ExtractorError("VK: invalid JSON")

        params = self._extract_player_params(data)
        if not params:
            raise ExtractorError("VK: player params not found")

        # ✅ HLS ONLY — matches curl output
        hls_url = (
            params.get("hls")
            or params.get("hls_ondemand")
            or params.get("hls_live")
        )

        if not hls_url:
            raise ExtractorError("VK: HLS not available")

        return {
            "destination_url": hls_url,
            "request_headers": {
                "User-Agent": UA,
                "Referer": REFERER,
                "Origin": ORIGIN,
                "Accept": "*/*",
                "Accept-Encoding": "identity",
            },
            "mediaflow_endpoint": "hls_manifest_proxy",
        }

    # ---------------- helpers ----------------

    def _normalize(self, url: str) -> str:
        if "video_ext.php" in url:
            return url
        m = re.search(r"video(\d+)_(\d+)", url)
        if not m:
            raise ExtractorError("VK: invalid URL")
        return f"https://vkvideo.ru/video_ext.php?oid={m[1]}&id={m[2]}"

    def _ajax_url(self, embed: str) -> str:
        return f"https://{urlparse(embed).netloc}/al_video.php"

    def _ajax_data(self, embed: str) -> Dict[str, str]:
        qs = dict(part.split("=", 1) for part in embed.split("?", 1)[1].split("&"))
        return {"act": "show", "al": "1", "video": f"{qs['oid']}_{qs['id']}"}

    def _extract_player_params(self, data: Any) -> dict | None:
        for item in data.get("payload", []):
            if isinstance(item, list):
                for block in item:
                    if isinstance(block, dict) and block.get("player"):
                        return block["player"]["params"][0]
        return None
