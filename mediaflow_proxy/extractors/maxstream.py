"""Maxstream URL extractor — full uprot bypass pipeline.

Solves the problem of `uprot.net` redirects on `/msf/`, `/msfi/` and
`/msfld/` paths used by Italian aggregators (CB01, EuroStreaming, etc).

Key features:
  1. TLS-fingerprint-resistant fetch via curl_cffi (chrome131 impersonation)
  2. 4-digit captcha solver with multi-engine OCR ensemble:
       ddddocr (primary) → tesseract (fallback) → CF Workers AI (3rd, opt-in)
  3. Honeypot URL filtering on the post-captcha page
  4. uprots/uprotem → maxstream redirect chain follow with cookie continuity
  5. /msfld/ folder picker (season + episode kwargs from MFP route)
  6. Optional persistent URL cache (when paired with services/uprot_warmer.py)

All advanced features are guarded by lazy imports — if `curl_cffi`,
`pytesseract`, `Pillow` or `ddddocr` are not installed the extractor
falls back to the previous behaviour for `/msf/` URLs and skips
`/msfld/` cleanly.

Activation:
  CF_WORKER_OCR_URL    e.g. https://easyproxy-ocr.user.workers.dev
  CF_WORKER_OCR_AUTH   Worker AUTH_TOKEN

Credits: pipeline ported from NelloStream
(https://github.com/vitouchiha/nello-stream) — `workers/cfworker.js`
functions `_uprotBypassWithCookies`, `_extractMaxstreamVideo`,
`_aiOcrDigits`, `_handleScheduledUprotRefresh`. All credit to Nello.
"""

import asyncio
import logging
import os
import re
from typing import Any, Dict, Optional
from urllib.parse import urljoin, urlparse, urlencode

from bs4 import BeautifulSoup

from mediaflow_proxy.extractors.base import BaseExtractor, ExtractorError

logger = logging.getLogger(__name__)


class MaxstreamExtractor(BaseExtractor):
    """Maxstream URL extractor with full uprot bypass pipeline."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mediaflow_endpoint = "hls_manifest_proxy"
        # Persistent cookie jar across the uprot → maxstream redirect chain.
        # PHPSESSID + captcha hash + uprot_session must travel together for
        # the post-captcha redirect to be honoured by the maxstream WAF.
        self.cookies: Dict[str, str] = {}
        self._last_solve_text: Optional[str] = None

    # ───────────────────────── HTTP layer ──────────────────────────────

    async def _curl_cffi_fetch(
        self,
        url: str,
        method: str = "GET",
        data: Optional[Any] = None,
        headers: Optional[Dict[str, str]] = None,
        allow_redirects: bool = True,
        timeout: int = 30,
    ) -> Optional[Dict[str, Any]]:
        """Browser-impersonated fetch via curl_cffi.

        uprot.net inspects TLS fingerprints; aiohttp's JA3 is recognised as
        a bot within a few requests and served captcha pages or 503 even
        from clean residential IPs. curl_cffi with `impersonate="chrome131"`
        replays a real Chrome JA3 + ALPN order, so uprot serves the real
        redirect link or the (legitimately-protected) captcha page.

        Returns None if curl_cffi is not installed (caller falls back to
        BaseExtractor._make_request for the simpler legacy /msf/ path).
        """
        try:
            from curl_cffi import requests as cffi_requests
        except ImportError:
            logger.debug("curl_cffi not installed — uprot bypass disabled")
            return None

        merged_headers = dict(self.base_headers)
        if headers:
            merged_headers.update(headers)
        if method.upper() == "POST" and isinstance(data, (str, bytes)):
            merged_headers.setdefault("content-type", "application/x-www-form-urlencoded")

        proxy = self._get_proxy(url)
        proxies_arg = {"http": proxy, "https": proxy} if proxy else None

        loop = asyncio.get_running_loop()

        def _do_request():
            try:
                req_cookies = dict(self.cookies) if self.cookies else None
                r = cffi_requests.request(
                    method,
                    url,
                    headers=merged_headers,
                    data=data,
                    cookies=req_cookies,
                    proxies=proxies_arg,
                    impersonate="chrome131",
                    timeout=timeout,
                    allow_redirects=allow_redirects,
                )
                cookies = {}
                try:
                    cookies = {c.name: c.value for c in r.cookies.jar}
                except Exception:
                    cookies = dict(r.cookies) if r.cookies else {}
                return {
                    "ok": r.status_code < 400,
                    "status": r.status_code,
                    "text": r.text,
                    "content": r.content,
                    "url": str(r.url),
                    "headers": dict(r.headers),
                    "cookies": cookies,
                }
            except Exception as e:
                return {"ok": False, "status": 0, "text": "", "content": b"", "url": url, "headers": {}, "cookies": {}, "error": str(e)}

        result = await loop.run_in_executor(None, _do_request)
        if result.get("cookies"):
            self.cookies.update(result["cookies"])
        return result

    # ─────────────────────── Honeypot filter ───────────────────────────

    @staticmethod
    def _strip_uprot_honeypots(html: str) -> str:
        """Remove uprot's anti-bot honeypot blocks before URL extraction.

        The post-captcha success page intentionally hides decoy URLs in:
          1. HTML comments  (<!-- … -->)
          2. <div style="display:none">…</div> blocks containing fake
             "Continue" buttons that point to placeholder URLs like
             `maxstream.video/uprots/123456789012` (12 sequential digits).

        A naive regex grabs the FIRST match (the honeypot). Strip both
        before parsing so the regex/BS4 see only the visible-to-user DOM.
        """
        no_comments = re.sub(r"<!--[\s\S]*?-->", "", html)
        no_hidden = re.sub(
            r"<div[^>]*style=[\"'][^\"']*display\s*:\s*none[^\"']*[\"'][^>]*>[\s\S]*?</div>",
            "",
            no_comments,
            flags=re.IGNORECASE,
        )
        return no_hidden

    # ─────────────────────── Redirect parser ───────────────────────────

    def _parse_uprot_html(self, text: str) -> Optional[str]:
        """Parse a uprot success page and return the next-hop URL.

        Strategy mirrored from NelloStream `_uprotBypassWithCookies`:
          1. Strip honeypot blocks first
          2. Prefer explicit `id="buttok"` CONTINUE button (uprot marker)
          3. Fallback: <a><button>Continue</button></a> (case+spacing tolerant)
          4. Last resort: a `/uprots/` or `/uprotem/` URL appearing exactly
             once in the cleaned HTML (uprot scatters multiple decoys)
          5. Generic stayonline.pro / maxstream.video regex with honeypot
             literal filter
          6. window.location / meta refresh / BS4 button fallbacks
        """
        cleaned = self._strip_uprot_honeypots(text).replace("\\/", "/")

        def _valid(c):
            if not c:
                return None
            try:
                p = urlparse(c)
                if p.netloc and "maxstream.video" in p.netloc and p.path.startswith("/cdn-cgi/"):
                    return None
            except Exception:
                pass
            return c

        # 1. id="buttok" CONTINUE button
        m = re.search(
            r'href=["\'](https?://[^"\']+)["\'][^>]*>\s*<button[^>]*id=["\']buttok["\'][^>]*>\s*C\s*O\s*N\s*T\s*I\s*N\s*U\s*E',
            cleaned,
            re.IGNORECASE,
        )
        if m and _valid(m.group(1)):
            return m.group(1)

        # 2. Generic <a><button>Continue</button></a>
        m = re.search(
            r'href=["\'](https?://[^"\']+)["\'][^>]*>\s*<button[^>]*>\s*[Cc]\s*[Oo]\s*[Nn]\s*[Tt]\s*[Ii]\s*[Nn]\s*[Uu]\s*[Ee]',
            cleaned,
        )
        if m and _valid(m.group(1)):
            return m.group(1)

        # 3. Unique uprots/uprotem URL
        all_uprots = re.findall(
            r'href=["\'](https?://[^"\']*uprot(?:s|em)/[^"\']+)["\']',
            cleaned,
            re.IGNORECASE,
        )
        if all_uprots:
            counts: Dict[str, int] = {}
            for u in all_uprots:
                counts[u] = counts.get(u, 0) + 1
            unique = [u for u, c in counts.items() if c == 1]
            if unique and _valid(unique[0]):
                return unique[0]

        # 4. Generic stayonline / maxstream regex
        m = re.search(
            r'https?://(?:www\.)?(?:stayonline\.pro|maxstream\.video)[^"\'\s<>\\ ]+',
            cleaned,
        )
        if m and "/uprots/123456789012" not in m.group(0) and _valid(m.group(0)):
            return m.group(0)

        # 5. window.location / meta refresh
        m = re.search(r'window\.location(?:\.href)?\s*=\s*["\']([^"\']+)["\']', cleaned)
        if m and _valid(m.group(1)):
            return m.group(1)
        m = re.search(r'content=["\']0;\s*url=([^"\']+)["\']', cleaned, re.I)
        if m and _valid(m.group(1)):
            return m.group(1)

        # 6. BS4 buttons / forms (rare paths)
        soup = BeautifulSoup(cleaned, "lxml")
        for btn in soup.find_all(["a", "button"]):
            t = btn.get_text().strip().lower()
            if "continue" in t or "continua" in t or "vai al" in t:
                href = btn.get("href")
                if not href and btn.parent and btn.parent.name == "a":
                    href = btn.parent.get("href")
                if href and "uprot.net" not in href and _valid(href):
                    return href
        return None

    def _parse_uprot_folder(self, text: str, season, episode) -> Optional[str]:
        """Parse a /msfld/ folder HTML and return the /msfi/ link for S{ss}E{ee}."""
        try:
            s_int = int(season)
            e_int = int(episode)
        except (TypeError, ValueError):
            return None
        s_pad = f"{s_int:02d}"
        e_pad = f"{e_int:02d}"
        patterns = [
            rf"S{s_pad}E{e_pad}",
            rf"\b0*{s_int}x0*{e_int}\b",
            rf"\b0*{s_int}&#215;0*{e_int}\b",
            rf"\b0*{s_int}×0*{e_int}\b",
        ]
        for pat in patterns:
            m = re.search(
                rf"{pat}[\s\S]{{0,500}}?href=['\"]([^'\"]+/msfi/[^'\"]+)['\"]",
                text,
                re.I,
            )
            if m:
                return m.group(1)
        return None

    # ─────────────────────── OCR backends ──────────────────────────────

    @staticmethod
    def _preprocess_captcha_png(img_bytes: bytes) -> bytes:
        """Binarize + denoise the captcha PNG to boost ddddocr accuracy."""
        try:
            from PIL import Image, ImageFilter
            import io
            img = Image.open(io.BytesIO(img_bytes)).convert("L")
            img = img.point(lambda p: 255 if p >= 140 else 0, mode="L")
            img = img.filter(ImageFilter.MaxFilter(3))
            img = img.filter(ImageFilter.MinFilter(3))
            out = io.BytesIO()
            img.save(out, format="PNG")
            return out.getvalue()
        except Exception:
            return img_bytes

    @staticmethod
    def _tesseract_classify(img_bytes: bytes) -> str:
        try:
            import pytesseract
            from PIL import Image, ImageFilter
            import io
            img = Image.open(io.BytesIO(img_bytes)).convert("L")
            img = img.point(lambda p: 255 if p >= 140 else 0, mode="L")
            img = img.filter(ImageFilter.MaxFilter(3))
            img = img.filter(ImageFilter.MinFilter(3))
            return pytesseract.image_to_string(
                img, config="--psm 7 -c tessedit_char_whitelist=0123456789"
            ).strip()
        except Exception:
            return ""

    @staticmethod
    async def _cf_worker_ocr(img_bytes: bytes, expected_digits: int = 4) -> str:
        """Optional 3rd OCR backend: Cloudflare Workers AI vision LLM.

        ddddocr + tesseract top out at ~50-65% on uprot's noisy captcha.
        A vision LLM (Llama 4 Scout / Gemma 3 / LLaVA) gets ~80-90%.
        POSTs the captcha PNG to a user-deployed CF Worker (see
        docs/MAXSTREAM_UPROT.md for setup).

        Activated only when both env vars are set:
          CF_WORKER_OCR_URL
          CF_WORKER_OCR_AUTH
        Returns "" on any failure — caller falls through gracefully.
        """
        base = (os.getenv("CF_WORKER_OCR_URL") or "").strip().rstrip("/")
        if not base:
            return ""
        auth = (os.getenv("CF_WORKER_OCR_AUTH") or "").strip()
        try:
            import aiohttp
            headers = {"content-type": "image/png"}
            if auth:
                headers["x-worker-auth"] = auth
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=20)) as s:
                async with s.post(
                    f"{base}/?ocr=1&digits={expected_digits}",
                    data=img_bytes,
                    headers=headers,
                ) as resp:
                    if resp.status != 200:
                        return ""
                    data = await resp.json()
                    return (data.get("digits") or "").strip()
        except Exception as e:
            logger.debug(f"CF Worker OCR failed: {e}")
            return ""

    # ─────────────────── Captcha solver loop ───────────────────────────

    async def _solve_uprot_captcha_once(
        self, text: str, original_url: str, preprocess: bool = False
    ) -> Optional[str]:
        try:
            import ddddocr
        except ImportError:
            logger.debug("ddddocr not installed — skipping captcha solve")
            return None

        soup = BeautifulSoup(text, "lxml")
        img_tag = soup.find("img", src=re.compile(r"data:image/|/captcha|/image/|captcha\.php"))
        img_url = img_tag.get("src") if img_tag else None
        if not img_url:
            m = re.search(
                r'<img[^>]+src=["\']([^"\']*(?:data:image/|captcha|image)[^"\']*)["\']',
                text,
            )
            img_url = m.group(1) if m else None
        if not img_url:
            return None

        form = soup.find("form")
        form_action = form.get("action") if form else ""
        if not form_action or form_action == "#":
            form_action = original_url
        elif form_action.startswith("/"):
            p = urlparse(original_url)
            form_action = f"{p.scheme}://{p.netloc}{form_action}"

        # Download captcha image
        if img_url.startswith("data:"):
            try:
                import base64
                _, b64 = img_url.split(",", 1)
                img_data = base64.b64decode(b64)
            except Exception:
                return None
        else:
            full_url = img_url
            if full_url.startswith("/"):
                p = urlparse(original_url)
                full_url = f"{p.scheme}://{p.netloc}{full_url}"
            res = await self._curl_cffi_fetch(full_url)
            if not res or not res.get("ok"):
                return None
            img_data = res.get("content") or b""

        ocr_input = self._preprocess_captcha_png(img_data) if preprocess else img_data

        if not hasattr(self, "_ocr_engine"):
            self._ocr_engine = ddddocr.DdddOcr(show_ad=False)
        res_str = self._ocr_engine.classification(ocr_input)
        res_digits = "".join(c for c in str(res_str) if c.isdigit())

        # Accept 3-or-4 digit answers (uprot uses 4 today; legacy 3 still seen)
        def _ok(n):
            return 3 <= n <= 4

        if not _ok(len(res_digits)):
            tess = self._tesseract_classify(ocr_input)
            tess_digits = "".join(c for c in str(tess) if c.isdigit())
            if _ok(len(tess_digits)):
                res_digits = tess_digits
            else:
                cf = await self._cf_worker_ocr(ocr_input, expected_digits=4)
                cf_digits = "".join(c for c in str(cf) if c.isdigit())
                if _ok(len(cf_digits)):
                    res_digits = cf_digits
                else:
                    return None

        # Prepare POST data
        captcha_input = soup.find("input", {"name": re.compile(r"captcha|code|val", re.I)})
        if captcha_input and captcha_input.get("name"):
            field_name = captcha_input["name"]
        else:
            m = re.search(r'name=["\'](captcha|code|val|captch5)[^"\']*["\']', text, re.I)
            field_name = m.group(1) if m else "captcha"

        post_data = {field_name: res_digits}
        if form:
            for inp in form.find_all(["input", "button", "select"]):
                n = inp.get("name")
                v = inp.get("value", "")
                if n and n not in post_data:
                    post_data[n] = v

        headers = {**self.base_headers, "referer": original_url}
        result = await self._curl_cffi_fetch(
            form_action, method="POST", data=urlencode(post_data), headers=headers
        )
        if not result:
            return None
        solved_text = result.get("text") or ""
        self._last_solve_text = solved_text if isinstance(solved_text, str) else None
        return self._parse_uprot_html(solved_text)

    async def _solve_uprot_captcha(
        self, text: str, original_url: str, max_attempts: int = 4
    ) -> Optional[str]:
        """Solve the captcha with retries on fresh images.

        Each wrong submit triggers uprot to serve a brand-new captcha
        image; we feed that fresh page back into the next attempt instead
        of OCRing the same image with different preprocessing.
        """
        current = text
        for attempt in range(1, max_attempts + 1):
            preprocess = (attempt % 2 == 0)
            result = await self._solve_uprot_captcha_once(current, original_url, preprocess=preprocess)
            if result:
                return result
            new_text = self._last_solve_text
            if new_text and new_text != current:
                current = new_text
        return None

    # ──────────────────── Redirect chain ───────────────────────────────

    async def _follow_uprots_chain(self, url: str, max_hops: int = 10) -> str:
        """Walk the uprots/uprotem → maxstream redirect chain manually.

        After captcha, the URL we extract is usually
        `maxstream.video/uprots/<token>` whose WAF only honours the token
        when reached via the proper redirect chain (Referer + cookie
        continuity from uprot.net). Direct GET → Error 131.

        Walks hop-by-hop preserving cookies until landing on
        `maxsun{N}.online/watchfree/...` or `maxstream.video/emvvv/<id>`,
        then converts watchfree → emvvv so the existing packer extraction
        works.
        """
        if "/uprots/" not in url and "/uprotem/" not in url:
            return url

        current = url
        for _ in range(max_hops):
            res = await self._curl_cffi_fetch(
                current,
                headers={**self.base_headers, "referer": "https://uprot.net/"},
                allow_redirects=False,
                timeout=15,
            )
            if not res:
                break
            loc = (res.get("headers") or {}).get("location") or (res.get("headers") or {}).get("Location")
            if not loc:
                current = res.get("url") or current
                break
            current = urljoin(current, loc)
            if "/uprots/" not in current and "/uprotem/" not in current:
                break

        if "watchfree/" in current:
            try:
                tail = current.split("watchfree/", 1)[1]
                segments = [s for s in tail.split("/") if s]
                if len(segments) >= 2:
                    current = f"https://maxstream.video/emvvv/{segments[1]}"
            except Exception:
                pass

        return current

    # ─────────────────────── Public flow ───────────────────────────────

    async def get_uprot(self, link: str, season=None, episode=None) -> str:
        """Resolve a uprot URL to its maxstream destination.

        Supports:
          - /msf/{id}    single movie (legacy alias /mse/)
          - /msfi/{id}   single episode
          - /msfld/{id}  folder of episodes (requires season + episode)
        """
        # Map only the modern /msf/ single-video path to its legacy /mse/
        # alias. A naive str.replace("msf", "mse") corrupts /msfld/ into
        # /mseld/ (404) and /msfi/ into /msei/ (deprecated 500 on new IDs).
        link = re.sub(r"/msf/", "/mse/", link)

        # Try curl_cffi first; fall back to BaseExtractor._make_request if
        # curl_cffi isn't installed (legacy /msf/ path may still work).
        cffi = await self._curl_cffi_fetch(link)
        if cffi and cffi.get("ok"):
            text = cffi["text"]
        else:
            response = await self._make_request(link)
            text = response.text

        if "/msfld/" in link:
            if season is None or episode is None:
                raise ExtractorError("msfld folder URL requires 'season' and 'episode' parameters")
            episode_link = self._parse_uprot_folder(text, season, episode)
            if not episode_link:
                raise ExtractorError(f"Episode S{season}E{episode} not found in msfld folder")
            link = episode_link
            cffi = await self._curl_cffi_fetch(link)
            if cffi and cffi.get("ok"):
                text = cffi["text"]
            else:
                response = await self._make_request(link)
                text = response.text

        # 1. Direct parse — works on legacy uprot pages without captcha
        res = self._parse_uprot_html(text)
        if res:
            return res

        # 2. Captcha solver
        res = await self._solve_uprot_captcha(text, link)
        if res:
            return res

        raise ExtractorError("Redirect link not found in uprot page")

    async def extract(self, url: str, **kwargs) -> Dict[str, Any]:
        """Extract Maxstream URL.

        For /msfld/ folder URLs, callers must pass season=N&episode=M as
        query parameters (forwarded by MFP routes as kwargs).

        Optional persistent cache: if `mediaflow_proxy.services.uprot_url_cache`
        is importable, cache hits skip captcha+chain entirely (<100ms).
        """
        season = kwargs.get("season")
        episode = kwargs.get("episode")

        cached = None
        try:
            from mediaflow_proxy.services import uprot_url_cache  # type: ignore
            cached = uprot_url_cache.get(url, season=season, episode=episode)
        except Exception:
            pass

        if cached:
            logger.debug(f"uprot cache HIT: {url[:80]}")
            maxstream_url = cached
        else:
            maxstream_url = await self.get_uprot(url, season=season, episode=episode)
            maxstream_url = await self._follow_uprots_chain(maxstream_url)

        # Fetch the maxstream embed page
        cffi = await self._curl_cffi_fetch(
            maxstream_url,
            headers={**self.base_headers, "referer": "https://uprot.net/", "accept-language": "en-US,en;q=0.5"},
        )
        if cffi and cffi.get("ok"):
            text = cffi["text"]
        else:
            response = await self._make_request(
                maxstream_url, headers={"accept-language": "en-US,en;q=0.5"}
            )
            text = response.text

        if not cached:
            try:
                from mediaflow_proxy.services import uprot_url_cache  # type: ignore
                uprot_url_cache.put(url, maxstream_url, season=season, episode=episode)
            except Exception:
                pass

        # Direct sources check
        m = re.search(r'sources:\s*\[\{src:\s*"([^"]+)"', text)
        if m:
            return {
                "destination_url": m.group(1),
                "request_headers": {**self.base_headers, "referer": maxstream_url},
                "mediaflow_endpoint": self.mediaflow_endpoint,
            }

        # Packer fallback
        m = re.search(r"\}\('(.+)',.+,'(.+)'\.split", text)
        if not m:
            m = re.search(r"eval\(function\(p,a,c,k,e,d\).+?\}\('(.+?)',.+?,'(.+?)'\.split", text, re.S)
        if not m:
            raise ExtractorError("Failed to extract URL components")

        terms = m.group(2).split("|")
        try:
            urlset_index = terms.index("urlset")
            hls_index = terms.index("hls")
            sources_index = terms.index("sources")
        except ValueError as e:
            raise ExtractorError(f"Missing components in packer: {e}")

        result_parts = terms[urlset_index + 1 : hls_index]
        reversed_elements = result_parts[::-1]
        first_part_terms = terms[hls_index + 1 : sources_index]
        reversed_first_part = first_part_terms[::-1]

        first_url_part = ""
        for fp in reversed_first_part:
            if "0" in fp:
                first_url_part += fp
            else:
                first_url_part += fp + "-"

        base_url = f"https://{first_url_part.rstrip('-')}.host-cdn.net/hls/"
        if len(reversed_elements) == 1:
            final_url = base_url + "," + reversed_elements[0] + ".urlset/master.m3u8"
        else:
            final_url = base_url
            for element in reversed_elements:
                final_url += element + ","
            final_url = final_url.rstrip(",") + ".urlset/master.m3u8"

        self.base_headers["referer"] = url
        return {
            "destination_url": final_url,
            "request_headers": self.base_headers,
            "mediaflow_endpoint": self.mediaflow_endpoint,
        }
