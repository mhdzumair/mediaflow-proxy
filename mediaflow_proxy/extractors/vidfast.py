import re
from typing import Dict, Any
from urllib.parse import urlparse

import aiohttp

from mediaflow_proxy.extractors.base import BaseExtractor, ExtractorError


class VidFastExtractor(BaseExtractor):
    """
    Extractor for vidfast.pro (movies and TV via ythd.org → cloudnestra.com).

    URL formats accepted:
      https://vidfast.pro/movie/{tmdb_id}
      https://vidfast.pro/tv/{tmdb_id}/{season}/{episode}

    Extraction flow:
      1. Parse TMDB ID from the URL path.
      2. Fetch https://ythd.org/embed/{tmdb_id}  →  grab first data-hash.
      3. Fetch https://cloudnestra.com/rcp/{hash} (carrying ythd cookies)
         →  grab /prorcp/ hash from the inline iframe src.
      4. Fetch https://cloudnestra.com/prorcp/{prorcp_hash}
         →  grab Playerjs `file:` parameter (HLS master playlist URL).
      5. Replace the {v1} CDN placeholder with cloudnestra.com and return
         the resolved HLS URL for MediaFlow's hls_manifest_proxy endpoint.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mediaflow_endpoint = "hls_manifest_proxy"

    async def extract(self, url: str, **kwargs) -> Dict[str, Any]:
        parsed = urlparse(url)
        parts = parsed.path.strip("/").split("/")
        if len(parts) < 2:
            raise ExtractorError(f"VidFast: cannot parse TMDB ID from path: {parsed.path!r}")

        tmdb_id = parts[1]
        ua = self.base_headers.get(
            "user-agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        )

        ythd_url = f"https://ythd.org/embed/{tmdb_id}"

        # A single aiohttp session preserves cookies across the three hops.
        cookie_jar = aiohttp.CookieJar()
        timeout = aiohttp.ClientTimeout(total=30)

        async with aiohttp.ClientSession(cookie_jar=cookie_jar, timeout=timeout) as session:
            # ── Step 1: ythd.org embed page ───────────────────────────────
            async with session.get(ythd_url, headers={"User-Agent": ua}) as resp:
                if resp.status >= 400:
                    raise ExtractorError(f"VidFast: ythd.org returned HTTP {resp.status}")
                ythd_html = await resp.text()

            hash_match = re.search(r'data-hash="([^"]+)"', ythd_html)
            if not hash_match:
                raise ExtractorError("VidFast: no data-hash attribute on ythd.org page")
            data_hash = hash_match.group(1)

            # ── Step 2: cloudnestra /rcp/ (needs ythd.org cookies) ────────
            rcp_url = f"https://cloudnestra.com/rcp/{data_hash}"
            async with session.get(
                rcp_url,
                headers={"User-Agent": ua, "Referer": ythd_url},
            ) as resp:
                if resp.status >= 400:
                    raise ExtractorError(f"VidFast: cloudnestra /rcp/ returned HTTP {resp.status}")
                rcp_html = await resp.text()

            prorcp_match = re.search(r"src:\s*'/prorcp/([^']+)'", rcp_html)
            if not prorcp_match:
                raise ExtractorError("VidFast: /prorcp/ hash not found in cloudnestra page")
            prorcp_hash = prorcp_match.group(1)

            # ── Step 3: cloudnestra /prorcp/ (actual player page) ─────────
            prorcp_url = f"https://cloudnestra.com/prorcp/{prorcp_hash}"
            async with session.get(
                prorcp_url,
                headers={"User-Agent": ua, "Referer": rcp_url},
            ) as resp:
                if resp.status >= 400:
                    raise ExtractorError(f"VidFast: cloudnestra /prorcp/ returned HTTP {resp.status}")
                prorcp_html = await resp.text()

        # ── Step 4: extract the HLS URL from Playerjs({…, file:"…"}) ──────
        file_match = re.search(r'file:\s*"(https://[^"]+)"', prorcp_html)
        if not file_match:
            raise ExtractorError("VidFast: Playerjs file URL not found in /prorcp/ page")

        # The file value may contain multiple fallback URLs separated by " or ".
        first_url = file_match.group(1).split(" or ")[0].strip()

        # {v1} is the primary CDN; tmstr4.cloudnestra.com hosts the proxied HLS.
        stream_url = first_url.replace("{v1}", "cloudnestra.com")

        if not stream_url.startswith("https://"):
            raise ExtractorError(f"VidFast: unexpected stream URL: {stream_url[:120]!r}")

        return {
            "destination_url": stream_url,
            "request_headers": {
                "user-agent": ua,
                "referer": "https://cloudnestra.com/",
            },
            "mediaflow_endpoint": self.mediaflow_endpoint,
        }
