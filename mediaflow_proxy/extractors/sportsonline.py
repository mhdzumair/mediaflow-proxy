import re
import logging
from typing import Any, Dict
from urllib.parse import urljoin, urlparse

from mediaflow_proxy.extractors.base import BaseExtractor, ExtractorError
from mediaflow_proxy.utils.packed import unpack

logger = logging.getLogger(__name__)


class SportsonlineExtractor(BaseExtractor):
    """Sportsonline/Sportzonline URL extractor for M3U8 streams.

    Strategy:
    1. Fetch page -> find first <iframe src="...">
    2. Fetch iframe with dynamic source-page Referer/Origin
    3. Collect packed eval blocks; if >=2 use second (index 1) else first.
    4. Unpack P.A.C.K.E.R. and search var src="...m3u8".
    5. Return final m3u8 with referer header.

    Notes:
    - Multi-domain support for sportzonline.(st|bz|cc|top) and sportsonline.(si|sn)
    - Uses P.A.C.K.E.R. unpacking from utils.packed module
    - Returns streams suitable for hls_manifest_proxy endpoint
    """

    def __init__(self, request_headers: dict):
        super().__init__(request_headers)
        self.mediaflow_endpoint = "hls_manifest_proxy"

    def _detect_packed_blocks(self, html: str) -> list[str]:
        """
        Detect and extract packed eval blocks from HTML.
        """
        raw_matches: list[str] = []
        strict_eval_pattern = re.compile(r"eval\(function\(p,a,c,k,e,.*?\}\(.*?\)\)", re.DOTALL)
        relaxed_eval_pattern = re.compile(r"eval\(function\(p,a,c,k,e,[dr]\).*?\}\(.*?\)\)", re.DOTALL)

        # Prefer script-body extraction first. This is more resilient when the packed
        # code has nested parentheses/semicolons that are hard to capture with a
        # single regex.
        script_pattern = re.compile(r"<script[^>]*>(.*?)</script>", re.IGNORECASE | re.DOTALL)
        for script_body in script_pattern.findall(html):
            if "eval(function(p,a,c,k,e" in script_body:
                strict_matches = strict_eval_pattern.findall(script_body)
                if strict_matches:
                    raw_matches.extend(strict_matches)
                    continue

                relaxed_matches = relaxed_eval_pattern.findall(script_body)
                if relaxed_matches:
                    raw_matches.extend(relaxed_matches)

        if raw_matches:
            return raw_matches

        # Fallback: direct eval(...) extraction from raw HTML.
        raw_matches = strict_eval_pattern.findall(html)

        # If no matches with the strict pattern, try a more relaxed one
        if not raw_matches:
            raw_matches = relaxed_eval_pattern.findall(html)

        return raw_matches

    @staticmethod
    def _extract_m3u8_candidate(text: str) -> str | None:
        patterns = [
            r"var\s+src\s*=\s*[\"']([^\"']+\.m3u8[^\"']*)[\"']",
            r"src\s*=\s*[\"']([^\"']+\.m3u8[^\"']*)[\"']",
            r"file\s*:\s*[\"']([^\"']+\.m3u8[^\"']*)[\"']",
            r"[\"']([^\"']*https?://[^\"']+\.m3u8[^\"']*)[\"']",
            r"(https?://[^\s\"'>]+\.m3u8[^\s\"'>]*)",
            r"(//[^\s\"'>]+\.m3u8[^\s\"'>]*)",
            r"(/[^\s\"'>]+\.m3u8[^\s\"'>]*)",
        ]

        for pattern in patterns:
            match = re.search(pattern, text)
            if match:
                return match.group(1)

        return None

    @staticmethod
    def _normalize_stream_url(stream_url: str, base_url: str) -> str:
        cleaned = stream_url.strip().strip("\"'").replace("\\/", "/")
        if cleaned.startswith("//"):
            parsed_base = urlparse(base_url)
            return f"{parsed_base.scheme or 'https'}:{cleaned}"
        if not urlparse(cleaned).scheme:
            return urljoin(base_url, cleaned)
        return cleaned

    async def extract(self, url: str, **kwargs) -> Dict[str, Any]:
        """Main extraction flow: fetch page, extract iframe, unpack and find m3u8."""
        try:
            parsed_source = urlparse(url)
            source_origin = f"{parsed_source.scheme}://{parsed_source.netloc}"
            source_referer = self.base_headers.get("Referer") or self.base_headers.get("referer") or f"{source_origin}/"
            user_agent = self.base_headers.get("User-Agent") or self.base_headers.get("user-agent") or "Mozilla/5.0"

            # Step 1: Fetch main page
            logger.info(f"Fetching main page: {url}")
            main_response = await self._make_request(
                url,
                headers={
                    "Referer": source_referer,
                    "Origin": source_origin,
                    "User-Agent": user_agent,
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.9,it;q=0.8",
                    "Cache-Control": "no-cache",
                },
                timeout=15,
            )
            main_html = main_response.text
            parsed_main = urlparse(main_response.url)
            main_origin = f"{parsed_main.scheme}://{parsed_main.netloc}"

            # Extract first iframe (src can appear in any attribute order)
            iframe_match = re.search(r'<iframe[^>]+(?<!data-)src=["\']([^"\']+)["\']', main_html, re.IGNORECASE)
            iframe_url = main_response.url
            iframe_html = main_html

            if iframe_match:
                iframe_url = self._normalize_stream_url(iframe_match.group(1), main_response.url)
                logger.info(f"Found iframe URL: {iframe_url}")

                # Step 2: Fetch iframe with source page as referer
                iframe_headers = {
                    "Referer": main_response.url,
                    "Origin": main_origin,
                    "User-Agent": user_agent,
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.9,it;q=0.8",
                    "Cache-Control": "no-cache",
                }

                iframe_response = await self._make_request(iframe_url, headers=iframe_headers, timeout=15)
                iframe_html = iframe_response.text
                iframe_url = iframe_response.url
                logger.debug(f"Iframe HTML length: {len(iframe_html)}")
            else:
                logger.warning("No iframe found on page, attempting extraction from main HTML")

            parsed_iframe = urlparse(iframe_url)
            playback_headers = {
                "Referer": iframe_url,
                "Origin": f"{parsed_iframe.scheme}://{parsed_iframe.netloc}",
                "User-Agent": user_agent,
            }

            # Step 3: Detect packed blocks
            packed_blocks = self._detect_packed_blocks(iframe_html)

            logger.info(f"Found {len(packed_blocks)} packed blocks")

            if not packed_blocks:
                logger.warning("No packed blocks found, trying direct m3u8 search")
                # Fallback: try direct m3u8 search
                direct_match = self._extract_m3u8_candidate(iframe_html)
                if direct_match:
                    m3u8_url = self._normalize_stream_url(direct_match, iframe_url)
                    logger.info(f"Found direct m3u8 URL: {m3u8_url}")

                    return {
                        "destination_url": m3u8_url,
                        "request_headers": playback_headers,
                        "mediaflow_endpoint": self.mediaflow_endpoint,
                    }
                else:
                    raise ExtractorError("No packed blocks or direct m3u8 URL found")

            # Choose block: if >=2 use second (index 1), else first (index 0)
            chosen_idx = 1 if len(packed_blocks) > 1 else 0
            m3u8_url = None
            unpacked_code = None

            logger.info(f"Chosen packed block index: {chosen_idx}")

            # Try to unpack chosen block
            try:
                unpacked_code = unpack(packed_blocks[chosen_idx])
                logger.info(f"Successfully unpacked block {chosen_idx}")
                logger.debug(f"Unpacked code preview: {unpacked_code[:500] if unpacked_code else 'empty'}")
            except Exception as e:
                logger.warning(f"Failed to unpack block {chosen_idx}: {e}")

            # Search for var src="...m3u8" with multiple patterns
            if unpacked_code:
                m3u8_url = self._extract_m3u8_candidate(unpacked_code)

            # If not found, try all other blocks
            if not m3u8_url:
                logger.info("m3u8 not found in chosen block, trying all blocks")
                for i, block in enumerate(packed_blocks):
                    if i == chosen_idx:
                        continue
                    try:
                        unpacked_code = unpack(block)
                        m3u8_url = self._extract_m3u8_candidate(unpacked_code)
                        if m3u8_url:
                            logger.info(f"Found m3u8 in block {i}")
                            break
                    except Exception as e:
                        logger.debug(f"Failed to process block {i}: {e}")
                        continue

            if not m3u8_url:
                fallback_candidate = self._extract_m3u8_candidate(iframe_html)
                if fallback_candidate:
                    m3u8_url = fallback_candidate

            if not m3u8_url:
                raise ExtractorError("Could not extract m3u8 URL from packed code")

            m3u8_url = self._normalize_stream_url(m3u8_url, iframe_url)

            logger.info(f"Successfully extracted m3u8 URL: {m3u8_url}")

            # Return stream configuration
            return {
                "destination_url": m3u8_url,
                "request_headers": playback_headers,
                "mediaflow_endpoint": self.mediaflow_endpoint,
            }

        except ExtractorError:
            raise
        except Exception as e:
            logger.exception(f"Sportsonline extraction failed for {url}")
            raise ExtractorError(f"Extraction failed: {str(e)}")
