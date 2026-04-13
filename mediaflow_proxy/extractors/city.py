import re
import json
import base64
from typing import Dict, Any
from urllib.parse import urlparse, parse_qs
from bs4 import BeautifulSoup

from mediaflow_proxy.extractors.base import BaseExtractor, ExtractorError


class CityExtractor(BaseExtractor):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mediaflow_endpoint = "hls_manifest_proxy"

    def atob_fixed(self, data: str) -> str:
        try:
            return base64.b64decode(data).decode("utf-8", errors="ignore")
        except Exception:
            return ""

    def extract_json_array(self, decoded: str):
        start = decoded.find("file:")
        if start == -1:
            start = decoded.find("sources:")
        if start == -1:
            return None

        start = decoded.find("[", start)
        if start == -1:
            return None

        depth = 0
        for i in range(start, len(decoded)):
            if decoded[i] == "[":
                depth += 1
            elif decoded[i] == "]":
                depth -= 1
            if depth == 0:
                return decoded[start : i + 1]

        return None

    def pick_stream(self, file_data, season: int = 1, episode: int = 1):

        if isinstance(file_data, str):
            return file_data

        if isinstance(file_data, list):
            if all(isinstance(x, dict) and "file" in x for x in file_data):
                idx = max(0, episode - 1)
                return file_data[idx]["file"]

            selected_season = None
            for s in file_data:
                if not isinstance(s, dict):
                    continue
                folder = s.get("folder")
                if not folder:
                    continue
                title = (s.get("title") or "").lower()
                if re.search(rf"(season|s)\s*0*{season}\b", title):
                    selected_season = folder
                    break

            if not selected_season:
                for s in file_data:
                    folder = s.get("folder")
                    if folder:
                        selected_season = folder
                        break

            if not selected_season:
                return None

            idx = max(0, episode - 1)
            return selected_season[idx].get("file") if idx < len(selected_season) else selected_season[0].get("file")

        return None

    async def extract(self, url: str, season: int = 1, episode: int = 1, **kwargs) -> Dict[str, Any]:
        """Main extraction entry point"""

        parsed = urlparse(url)
        query = parse_qs(parsed.query)
        if "s" in query:
            try:
                season = int(query["s"][0])
            except Exception:
                pass
        if "e" in query:
            try:
                episode = int(query["e"][0])
            except Exception:
                pass

        clean_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        cookie_b64 = "ZGxlX3VzZXJfaWQ9MzI3Mjk7IGRsZV9wYXNzd29yZD04OTQxNzFjNmE4ZGFiMThlZTU5NGQ1YzY1MjAwOWEzNTs="
        cookie = base64.b64decode(cookie_b64).decode()

        headers = {
            "User-Agent": self.base_headers.get("user-agent"),
            "Referer": clean_url,
            "Cookie": cookie,
        }

        response = await self._make_request(clean_url, headers=headers)
        if response.status != 200:
            raise ExtractorError("Failed to load City page")

        soup = BeautifulSoup(response.text, "lxml")
        file_data = None

        for script in soup.find_all("script"):
            if file_data:
                break

            script_html = script.string or script.text or ""
            if "atob" not in script_html:
                continue

            matches = re.finditer(r'atob\(\s*[\'"](.*?)[\'"]\s*\)', script_html)
            for match in matches:
                encoded = match.group(1)
                decoded = self.atob_fixed(encoded)
                if not decoded:
                    continue

                raw_json = self.extract_json_array(decoded)
                if raw_json:
                    try:
                        raw_json = re.sub(r"\\(.)", r"\1", raw_json)
                        file_data = json.loads(raw_json)
                    except Exception:
                        file_data = raw_json
                    break

                file_match = re.search(r'file\s*:\s*[\'"](.*?)[\'"]', decoded, re.S)
                if file_match:
                    file_data = file_match.group(1)
                    break

        if not file_data:
            raise ExtractorError("No stream found")

        stream_url = self.pick_stream(file_data, season=season, episode=episode)
        if not stream_url:
            raise ExtractorError("Stream extraction failed")

        return {
            "destination_url": stream_url,
            "request_headers": {
                "Referer": clean_url,
                "User-Agent": self.base_headers.get("user-agent"),
            },
            "mediaflow_endpoint": self.mediaflow_endpoint,
        }
