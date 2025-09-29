import base64
import re
from typing import Dict, Any
from urllib.parse import urljoin

from mediaflow_proxy.extractors.base import BaseExtractor, ExtractorError


class VoeExtractor(BaseExtractor):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mediaflow_endpoint = "hls_manifest_proxy"

    async def extract(self, url: str, redirected: bool = False, **kwargs) -> Dict[str, Any]:
        response = await self._make_request(url)

        # See https://github.com/Gujal00/ResolveURL/blob/master/script.module.resolveurl/lib/resolveurl/plugins/voesx.py
        redirect_pattern = r'''window\.location\.href\s*=\s*'([^']+)'''
        redirect_match = re.search(redirect_pattern, response.text, re.DOTALL)
        if redirect_match:
            if redirected:
                raise ExtractorError("VOE: too many redirects")

            return await self.extract(redirect_match.group(1))

        code_and_script_pattern = r'json">\["([^"]+)"]</script>\s*<script\s*src="([^"]+)'
        code_and_script_match = re.search(code_and_script_pattern, response.text, re.DOTALL)
        if not code_and_script_match:
            raise ExtractorError("VOE: unable to locate obfuscated payload or external script URL")

        script_response = await self._make_request(urljoin(url, code_and_script_match.group(2)))

        luts_pattern = r"(\[(?:'\W{2}'[,\]]){1,9})"
        luts_match = re.search(luts_pattern, script_response.text, re.DOTALL)
        if not luts_match:
            raise ExtractorError("VOE: unable to locate LUTs in external script")

        data = self.voe_decode(code_and_script_match.group(1), luts_match.group(1))

        final_url = data.get('source')
        if not final_url:
            raise ExtractorError("VOE: failed to extract video URL")

        self.base_headers["referer"] = url
        return {
            "destination_url": final_url,
            "request_headers": self.base_headers,
            "mediaflow_endpoint": self.mediaflow_endpoint,
        }

    @staticmethod
    def voe_decode(ct: str, luts: str) -> Dict[str, Any]:
        import json
        lut = [''.join([('\\' + x) if x in '.*+?^${}()|[]\\' else x for x in i]) for i in luts[2:-2].split("','")]
        txt = ''
        for i in ct:
            x = ord(i)
            if 64 < x < 91:
                x = (x - 52) % 26 + 65
            elif 96 < x < 123:
                x = (x - 84) % 26 + 97
            txt += chr(x)
        for i in lut:
            txt = re.sub(i, '', txt)
        ct = base64.b64decode(txt).decode('utf-8')
        txt = ''.join([chr(ord(i) - 3) for i in ct])
        txt = base64.b64decode(txt[::-1]).decode('utf-8')
        return json.loads(txt)
