import json
import logging
import urllib.parse
from typing import Iterator, Dict, Optional
from fastapi import APIRouter, Request, HTTPException, Query
from fastapi.responses import StreamingResponse
from starlette.responses import RedirectResponse
import httpx
from mediaflow_proxy.configs import settings
from mediaflow_proxy.utils.http_utils import get_original_scheme
import asyncio

logger = logging.getLogger(__name__)
playlist_builder_router = APIRouter()


def rewrite_m3u_links_streaming(m3u_lines_iterator: Iterator[str], base_url: str, api_password: Optional[str]) -> Iterator[str]:
    """
    Riscrive i link da un iteratore di linee M3U secondo le regole specificate,
    includendo gli headers da #EXTVLCOPT e #EXTHTTP. Yields rewritten lines.
    """
    current_ext_headers: Dict[str, str] = {}  # Dizionario per conservare gli headers dalle direttive
    
    for line_with_newline in m3u_lines_iterator:
        line_content = line_with_newline.rstrip('\n')
        logical_line = line_content.strip()
        
        is_header_tag = False
        if logical_line.startswith('#EXTVLCOPT:'):
            is_header_tag = True
            try:
                option_str = logical_line.split(':', 1)[1]
                if '=' in option_str:
                    key_vlc, value_vlc = option_str.split('=', 1)
                    key_vlc = key_vlc.strip()
                    value_vlc = value_vlc.strip()
 
                    # Gestione speciale per http-header che contiene "Key: Value"
                    if key_vlc == 'http-header' and ':' in value_vlc:
                        header_key, header_value = value_vlc.split(':', 1)
                        header_key = header_key.strip()
                        header_value = header_value.strip()
                        current_ext_headers[header_key] = header_value
                    elif key_vlc.startswith('http-'):
                        # Gestisce http-user-agent, http-referer etc.
                        header_key = '-'.join(word.capitalize() for word in key_vlc[len('http-'):].split('-'))
                        current_ext_headers[header_key] = value_vlc
            except Exception as e:
                logger.error(f"⚠️ Error parsing #EXTVLCOPT '{logical_line}': {e}")
        
        elif logical_line.startswith('#EXTHTTP:'):
            is_header_tag = True
            try:
                json_str = logical_line.split(':', 1)[1]
                # Sostituisce tutti gli header correnti con quelli del JSON
                current_ext_headers = json.loads(json_str)
            except Exception as e:
                logger.error(f"⚠️ Error parsing #EXTHTTP '{logical_line}': {e}")
                current_ext_headers = {}  # Resetta in caso di errore

        if is_header_tag:
            yield line_with_newline
            continue
        
        if logical_line and not logical_line.startswith('#') and \
           ('http://' in logical_line or 'https://' in logical_line):
            
            processed_url_content = logical_line
            
            # Non modificare link pluto.tv
            if 'pluto.tv' in logical_line:
                processed_url_content = logical_line
            elif 'vavoo.to' in logical_line:
                encoded_url = urllib.parse.quote(logical_line, safe='')
                processed_url_content = f"{base_url}/proxy/hls/manifest.m3u8?d={encoded_url}"
            elif 'vixsrc.to' in logical_line:
                encoded_url = urllib.parse.quote(logical_line, safe='')
                processed_url_content = f"{base_url}/extractor/video?host=VixCloud&redirect_stream=true&d={encoded_url}"
            elif '.m3u8' in logical_line:
                encoded_url = urllib.parse.quote(logical_line, safe='')
                processed_url_content = f"{base_url}/proxy/hls/manifest.m3u8?d={encoded_url}"
            elif '.mpd' in logical_line:
                # Estrai parametri DRM dall'URL MPD se presenti
                from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
                
                # Parse dell'URL per estrarre parametri
                parsed_url = urlparse(logical_line)
                query_params = parse_qs(parsed_url.query)
                
                # Estrai key_id e key se presenti
                key_id = query_params.get('key_id', [None])[0]
                key = query_params.get('key', [None])[0]
                
                # Rimuovi key_id e key dai parametri originali
                clean_params = {k: v for k, v in query_params.items() if k not in ['key_id', 'key']}
                
                # Ricostruisci l'URL senza i parametri DRM
                clean_query = urlencode(clean_params, doseq=True) if clean_params else ''
                clean_url = urlunparse((
                    parsed_url.scheme,
                    parsed_url.netloc,
                    parsed_url.path,
                    parsed_url.params,
                    clean_query,
                    parsed_url.fragment
                ))
                
                # Encode the MPD URL like other URL types
                clean_url_for_param = urllib.parse.quote(clean_url, safe='')

                # Costruisci l'URL MediaFlow con parametri DRM separati
                processed_url_content = f"{base_url}/proxy/mpd/manifest.m3u8?d={clean_url_for_param}"
                
                # Aggiungi parametri DRM se presenti
                if key_id:
                    processed_url_content += f"&key_id={key_id}"
                if key:
                    processed_url_content += f"&key={key}"
            elif '.php' in logical_line:
                encoded_url = urllib.parse.quote(logical_line, safe='')
                processed_url_content = f"{base_url}/proxy/hls/manifest.m3u8?d={encoded_url}"
            else:
                # Per tutti gli altri link senza estensioni specifiche, trattali come .m3u8 con codifica
                encoded_url = urllib.parse.quote(logical_line, safe='')
                processed_url_content = f"{base_url}/proxy/hls/manifest.m3u8?d={encoded_url}"
            
            # Applica gli header raccolti prima di api_password
            if current_ext_headers:
                header_params_str = "".join([f"&h_{urllib.parse.quote(key)}={urllib.parse.quote(value)}" for key, value in current_ext_headers.items()])
                processed_url_content += header_params_str
                current_ext_headers = {}
            
            # Aggiungi api_password sempre alla fine
            if api_password:
                processed_url_content += f"&api_password={api_password}"
            
            yield processed_url_content + '\n'
        else:
            yield line_with_newline


async def async_download_m3u_playlist(url: str) -> list[str]:
    """Scarica una playlist M3U in modo asincrono e restituisce le righe."""
    headers = {
        'User-Agent': settings.user_agent,
        'Accept': '*/*',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'keep-alive'
    }
    lines = []
    try:
         async with httpx.AsyncClient(verify=True, timeout=30) as client:
             async with client.stream('GET', url, headers=headers) as response:
                response.raise_for_status()
                async for line_bytes in response.aiter_lines():
                    if isinstance(line_bytes, bytes):
                        decoded_line = line_bytes.decode('utf-8', errors='replace')
                    else:
                        decoded_line = str(line_bytes)
                    lines.append(decoded_line + '\n' if decoded_line else '')
    except Exception as e:
        logger.error(f"Error downloading playlist (async): {str(e)}")
        raise
    return lines

async def async_generate_combined_playlist(playlist_definitions: list[str], base_url: str, api_password: Optional[str]):
    """Genera una playlist combinata da multiple definizioni, scaricando in parallelo."""
    # Prepara gli URL
    playlist_urls = []
    for definition in playlist_definitions:
        if '&' in definition:
            parts = definition.split('&', 1)
            playlist_url_str = parts[1] if len(parts) > 1 else parts[0]
        else:
            playlist_url_str = definition
        playlist_urls.append(playlist_url_str)

    # Scarica tutte le playlist in parallelo
    results = await asyncio.gather(*[async_download_m3u_playlist(url) for url in playlist_urls], return_exceptions=True)

    first_playlist_header_handled = False
    for idx, lines in enumerate(results):
        if isinstance(lines, Exception):
            yield f"# ERROR processing playlist {playlist_urls[idx]}: {str(lines)}\n"
            continue
        playlist_lines: list[str] = lines  # type: ignore
        current_playlist_had_lines = False
        first_line_of_this_segment = True
        lines_processed_for_current_playlist = 0
        rewritten_lines_iter = rewrite_m3u_links_streaming(iter(playlist_lines), base_url, api_password)
        for line in rewritten_lines_iter:
            current_playlist_had_lines = True
            is_extm3u_line = line.strip().startswith('#EXTM3U')
            lines_processed_for_current_playlist += 1
            if not first_playlist_header_handled:
                yield line
                if is_extm3u_line:
                    first_playlist_header_handled = True
            else:
                if first_line_of_this_segment and is_extm3u_line:
                    pass
                else:
                    yield line
            first_line_of_this_segment = False
        if current_playlist_had_lines and not first_playlist_header_handled:
            first_playlist_header_handled = True


@playlist_builder_router.get("/playlist")
async def proxy_handler(
    request: Request,
    d: str = Query(..., description="Query string con le definizioni delle playlist", alias="d"),
    api_password: Optional[str] = Query(None, description="Password API per MFP"),
):
    """
    Endpoint per il proxy delle playlist M3U con supporto MFP.
    
    Formato query string: playlist1&url1;playlist2&url2
    Esempio: https://mfp.com:pass123&http://provider.com/playlist.m3u
    """
    try:
        if not d:
            raise HTTPException(status_code=400, detail="Query string mancante")

        if not d.strip():
            raise HTTPException(status_code=400, detail="Query string cannot be empty")

        # Validate that we have at least one valid definition
        playlist_definitions = [def_.strip() for def_ in d.split(';') if def_.strip()]
        if not playlist_definitions:
            raise HTTPException(status_code=400, detail="No valid playlist definitions found")
        
        # Costruisci base_url con lo schema corretto
        original_scheme = get_original_scheme(request)
        base_url = f"{original_scheme}://{request.url.netloc}"
        
        # Estrai base_url dalla prima definizione se presente
        if playlist_definitions and '&' in playlist_definitions[0]:
            parts = playlist_definitions[0].split('&', 1)
            if ':' in parts[0] and not parts[0].startswith('http'):
                # Estrai base_url dalla prima parte se contiene password
                base_url_part = parts[0].rsplit(':', 1)[0]
                if base_url_part.startswith('http'):
                    base_url = base_url_part

        async def generate_response():
            async for line in async_generate_combined_playlist(playlist_definitions, base_url, api_password):
                yield line

        return StreamingResponse(
            generate_response(),
            media_type='application/vnd.apple.mpegurl',
            headers={
                'Content-Disposition': 'attachment; filename="playlist.m3u"',
                'Access-Control-Allow-Origin': '*'
            }
        )
        
    except Exception as e:
        logger.error(f"General error in playlist handler: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}") from e


@playlist_builder_router.get("/builder")
async def url_builder():
    """
    Pagina con un'interfaccia per generare l'URL del proxy MFP.
    """
    return RedirectResponse(url="/playlist_builder.html")
