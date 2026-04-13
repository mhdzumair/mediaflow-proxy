import logging
import re
import time
from urllib.parse import urlparse, urljoin

import aiohttp
from curl_cffi.requests import AsyncSession

from mediaflow_proxy.extractors.base import BaseExtractor, ExtractorError
from mediaflow_proxy.configs import settings

logger = logging.getLogger(__name__)

_DOOD_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)


class DoodStreamExtractor(BaseExtractor):
    """
    DoodStream / PlayMogo extractor.

    All DoodStream mirror domains (dsvplay.com, myvidplay.com, dood.to, …) now
    redirect to playmogo.com which sits behind Cloudflare and may require a
    Turnstile CAPTCHA before serving the pass_md5 URL.

    Extraction order:
    1. Byparr  — set BYPARR_URL (Firefox/Camoufox → Turnstile auto-validates,
                 not blocked by DisableDevtool.js)
    2. curl_cffi — Chrome impersonation; works when Turnstile is not triggered,
                   raises a descriptive error if captcha is detected.
    """

    async def extract(self, url: str, **kwargs):
        parsed = urlparse(url)
        video_id = parsed.path.rstrip("/").split("/")[-1]
        if not video_id:
            raise ExtractorError("Invalid DoodStream URL: no video ID found")

        if settings.byparr_url:
            try:
                return await self._extract_via_byparr(url, video_id)
            except ExtractorError:
                raise

        return await self._extract_via_curl_cffi(url, video_id)

    # ------------------------------------------------------------------
    # Path 1 – Byparr (Firefox/Camoufox → Turnstile auto-validates)
    # ------------------------------------------------------------------

    async def _extract_via_byparr(self, url: str, video_id: str) -> dict:
        """
        Use Byparr to bypass Cloudflare protection on the DoodStream embed page.

        Strategy: fetch the embed page without any injected script. Byparr's
        Firefox/Camoufox browser auto-passes Cloudflare's bot checks and often
        bypasses the Turnstile CAPTCHA gate directly, returning the embed HTML
        with pass_md5.  If the response doesn't contain pass_md5, reuse the CF
        cookies + UA from Byparr in a follow-up curl_cffi request (which avoids
        re-triggering the bot check).
        """
        endpoint = f"{settings.byparr_url.rstrip('/')}/v1"
        embed_url = url if "/e/" in url else f"https://{urlparse(url).netloc}/e/{video_id}"
        payload = {
            "cmd": "request.get",
            "url": embed_url,
            "maxTimeout": settings.byparr_timeout * 1000,
        }

        async with aiohttp.ClientSession() as session:
            async with session.post(
                endpoint,
                json=payload,
                timeout=aiohttp.ClientTimeout(total=settings.byparr_timeout + 15),
            ) as resp:
                if resp.status != 200:
                    raise ExtractorError(f"Byparr HTTP {resp.status}")
                data = await resp.json()

        if data.get("status") != "ok":
            raise ExtractorError(f"Byparr: {data.get('message', 'unknown error')}")

        solution = data.get("solution", {})
        final_url = solution.get("url", embed_url)
        if not final_url.startswith("http"):
            final_url = embed_url
        base_url = f"https://{urlparse(final_url).netloc}"
        html = solution.get("response", "")

        if "pass_md5" not in html:
            # Byparr may not have the pass_md5 in the initial response.
            # Try two recovery strategies in order:
            #
            # 1. Cookie reuse — if Byparr collected CF clearance cookies before
            #    the page loaded fully, inject them into a curl_cffi request.
            # 2. Plain curl_cffi — Chrome TLS impersonation without JS execution.
            raw_cookies = solution.get("cookies", [])
            cookies = {c["name"]: c["value"] for c in raw_cookies}
            ua = solution.get("userAgent", _DOOD_UA)

            if cookies:
                cf_domain = (
                    next(
                        (c.get("domain", "").lstrip(".") for c in raw_cookies if c.get("name") == "cf_clearance"),
                        None,
                    )
                    or "playmogo.com"
                )
                retry_url = f"https://{cf_domain}/e/{video_id}"
                logger.debug(
                    "Byparr response lacked pass_md5 (final_url=%s); retrying %s with CF cookies via curl_cffi",
                    final_url,
                    retry_url,
                )
                proxy = self._get_proxy(retry_url)
                async with AsyncSession() as s:
                    r = await s.get(
                        retry_url,
                        impersonate="chrome",
                        cookies=cookies,
                        headers={"User-Agent": ua, "Referer": f"https://{cf_domain}/"},
                        timeout=20,
                        **({"proxy": proxy} if proxy else {}),
                    )
                    html = r.text
                    final_url = str(r.url)
                    base_url = f"https://{urlparse(final_url).netloc}"

            if "pass_md5" not in html:
                logger.debug("Byparr cookie reuse also failed; falling back to curl_cffi for %s", embed_url)
                return await self._extract_via_curl_cffi(embed_url, video_id)

        return await self._parse_embed_html(html, base_url)

    # ------------------------------------------------------------------
    # Path 2 – curl_cffi (bypasses CF bot protection; Turnstile may block)
    # ------------------------------------------------------------------

    async def _extract_via_curl_cffi(self, url: str, video_id: str) -> dict:
        proxy = self._get_proxy(url)
        async with AsyncSession() as s:
            r = await s.get(
                url,
                impersonate="chrome",
                headers={"Referer": f"https://{urlparse(url).netloc}/"},
                timeout=30,
                allow_redirects=True,
                **({"proxy": proxy} if proxy else {}),
            )
        final_url = str(r.url)
        html = r.text
        base_url = f"https://{urlparse(final_url).netloc}"

        if "pass_md5" not in html:
            if "turnstile" in html.lower() or "captcha_l" in html:
                raise ExtractorError(
                    "DoodStream: site is serving a Turnstile CAPTCHA that requires "
                    "browser interaction — cannot be bypassed automatically from this "
                    "network location. Try a residential IP or a VPN/proxy."
                )
            raise ExtractorError(f"DoodStream: pass_md5 not found in embed HTML ({final_url})")

        return await self._parse_embed_html(html, base_url)

    # ------------------------------------------------------------------
    # Common HTML parser
    # ------------------------------------------------------------------

    async def _parse_embed_html(self, html: str, base_url: str) -> dict:
        pass_match = re.search(r"(/pass_md5/[^'\"<>\s]+)", html)
        if not pass_match:
            raise ExtractorError("DoodStream: pass_md5 path not found in embed HTML")

        pass_url = urljoin(base_url, pass_match.group(1))
        ua = self.base_headers.get("user-agent") or _DOOD_UA
        headers = {
            "user-agent": ua,
            "referer": f"{base_url}/",
        }

        proxy = self._get_proxy(pass_url)
        async with AsyncSession() as s:
            r = await s.get(
                pass_url,
                impersonate="chrome",
                headers=headers,
                timeout=20,
                **({"proxy": proxy} if proxy else {}),
            )

        base_stream = r.text.strip()
        if not base_stream or "RELOAD" in base_stream:
            raise ExtractorError(
                "DoodStream: pass_md5 endpoint returned no stream URL "
                "(captcha session may have expired). "
                "Ensure BYPARR_URL is set for reliable extraction."
            )

        token_match = re.search(r"token=([^&\s'\"]+)", html)
        if not token_match:
            raise ExtractorError("DoodStream: token not found in embed HTML")

        token = token_match.group(1)
        expiry = int(time.time())
        final_url = f"{base_stream}123456789?token={token}&expiry={expiry}"

        return {
            "destination_url": final_url,
            "request_headers": headers,
            "mediaflow_endpoint": "proxy_stream_endpoint",
        }
