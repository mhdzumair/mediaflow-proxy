import json
import logging
import urllib.parse
from typing import Iterator, Dict, Optional
from fastapi import APIRouter, Request, HTTPException, Query
from fastapi.responses import StreamingResponse
from starlette.responses import RedirectResponse

from mediaflow_proxy.configs import settings
from mediaflow_proxy.utils.http_utils import get_original_scheme
from mediaflow_proxy.utils.http_client import create_aiohttp_session
import asyncio

logger = logging.getLogger(__name__)
playlist_builder_router = APIRouter()


def rewrite_m3u_links_streaming(
    m3u_lines_iterator: Iterator[str], base_url: str, api_password: Optional[str]
) -> Iterator[str]:
    """
    Rewrites links from an M3U line iterator according to the specified rules,
    including headers from #EXTVLCOPT and #EXTHTTP. Yields rewritten lines.
    """
    current_ext_headers: Dict[str, str] = {}  # Dictionary to store headers from directives
    current_kodi_props: Dict[str, str] = {}  # Dictionary to store KODI properties

    for line_with_newline in m3u_lines_iterator:
        line_content = line_with_newline.rstrip("\n")
        logical_line = line_content.strip()

        is_header_tag = False
        if logical_line.startswith("#EXTVLCOPT:"):
            # Yield the original line to preserve it
            yield line_with_newline

            is_header_tag = True
            try:
                option_str = logical_line.split(":", 1)[1]
                if "=" in option_str:
                    key_vlc, value_vlc = option_str.split("=", 1)
                    key_vlc = key_vlc.strip()
                    value_vlc = value_vlc.strip()

                    # Gestione speciale per http-header che contiene "Key: Value"
                    if key_vlc == "http-header" and ":" in value_vlc:
                        header_key, header_value = value_vlc.split(":", 1)
                        header_key = header_key.strip()
                        header_value = header_value.strip()
                        current_ext_headers[header_key] = header_value
                    elif key_vlc.startswith("http-"):
                        # Handle http-user-agent, http-referer, etc.
                        header_key = key_vlc[len("http-") :]
                        current_ext_headers[header_key] = value_vlc
            except Exception as e:
                logger.error(f"Error parsing #EXTVLCOPT '{logical_line}': {e}")

        elif logical_line.startswith("#EXTHTTP:"):
            # Yield the original line to preserve it
            yield line_with_newline

            is_header_tag = True
            try:
                json_str = logical_line.split(":", 1)[1]
                # Replace all current headers with those from the JSON
                current_ext_headers = json.loads(json_str)
            except Exception as e:
                logger.error(f"Error parsing #EXTHTTP '{logical_line}': {e}")
                current_ext_headers = {}  # Reset on error

        elif logical_line.startswith("#KODIPROP:"):
            # Yield the original line to preserve it
            yield line_with_newline

            is_header_tag = True
            try:
                prop_str = logical_line.split(":", 1)[1]
                if "=" in prop_str:
                    key_kodi, value_kodi = prop_str.split("=", 1)
                    current_kodi_props[key_kodi.strip()] = value_kodi.strip()
            except Exception as e:
                logger.error(f"Error parsing #KODIPROP '{logical_line}': {e}")

        if is_header_tag:
            continue

        if (
            logical_line
            and not logical_line.startswith("#")
            and ("http://" in logical_line or "https://" in logical_line)
        ):
            processed_url_content = logical_line

            # Non modificare link pluto.tv
            if "pluto.tv" in logical_line:
                processed_url_content = logical_line
            elif "vavoo.to" in logical_line:
                encoded_url = urllib.parse.quote(logical_line, safe="")
                processed_url_content = f"{base_url}/proxy/hls/manifest.m3u8?d={encoded_url}"
            elif "vixsrc.to" in logical_line:
                encoded_url = urllib.parse.quote(logical_line, safe="")
                processed_url_content = f"{base_url}/extractor/video?host=VixCloud&redirect_stream=true&d={encoded_url}&max_res=true&no_proxy=true"
            elif ".m3u8" in logical_line:
                encoded_url = urllib.parse.quote(logical_line, safe="")
                processed_url_content = f"{base_url}/proxy/hls/manifest.m3u8?d={encoded_url}"
            elif ".mpd" in logical_line:
                # Estrai parametri DRM dall'URL MPD se presenti (es. &key_id=...&key=...)
                from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

                # Parse dell'URL per estrarre parametri
                parsed_url = urlparse(logical_line)
                query_params = parse_qs(parsed_url.query)

                # Estrai key_id e key se presenti nei parametri della query
                key_id = query_params.get("key_id", [None])[0]
                key = query_params.get("key", [None])[0]

                # Rimuovi key_id e key dai parametri originali
                clean_query_params = {k: v for k, v in query_params.items() if k not in ["key_id", "key"]}

                # Ricostruisci l'URL senza i parametri DRM
                clean_query = urlencode(clean_query_params, doseq=True)
                clean_url = urlunparse(
                    (
                        parsed_url.scheme,
                        parsed_url.netloc,
                        parsed_url.path,
                        parsed_url.params,
                        clean_query,
                        "",  # Rimuovi il frammento per evitare problemi
                    )
                )

                # Codifica l'URL pulito per il parametro 'd'
                encoded_clean_url = urllib.parse.quote(clean_url, safe="")

                # Costruisci l'URL MediaFlow con parametri DRM separati
                processed_url_content = f"{base_url}/proxy/mpd/manifest.m3u8?d={encoded_clean_url}"

                # Aggiungi i parametri DRM all'URL di MediaFlow se sono stati trovati
                if key_id:
                    processed_url_content += f"&key_id={key_id}"
                if key:
                    processed_url_content += f"&key={key}"

            elif ".php" in logical_line:
                encoded_url = urllib.parse.quote(logical_line, safe="")
                processed_url_content = f"{base_url}/proxy/hls/manifest.m3u8?d={encoded_url}"
            else:
                # Per tutti gli altri link senza estensioni specifiche, trattali come .m3u8 con codifica
                encoded_url = urllib.parse.quote(logical_line, safe="")
                processed_url_content = f"{base_url}/proxy/hls/manifest.m3u8?d={encoded_url}"

            # Aggiungi chiavi da #KODIPROP se presenti
            license_key = current_kodi_props.get("inputstream.adaptive.license_key")
            if license_key and ":" in license_key:
                key_id_kodi, key_kodi = license_key.split(":", 1)
                # Aggiungi key_id e key solo se non sono già stati aggiunti (es. dall'URL MPD)
                if "&key_id=" not in processed_url_content:
                    processed_url_content += f"&key_id={key_id_kodi}"
                if "&key=" not in processed_url_content:
                    processed_url_content += f"&key={key_kodi}"

            # Applica gli header raccolti prima di api_password
            if current_ext_headers:
                header_params_str = "".join(
                    [
                        f"&h_{urllib.parse.quote(key)}={urllib.parse.quote(value)}"
                        for key, value in current_ext_headers.items()
                    ]
                )
                processed_url_content += header_params_str
                current_ext_headers = {}

            # Reset KODI properties after using them
            current_kodi_props = {}

            # Always append api_password at the end
            if api_password:
                processed_url_content += f"&api_password={api_password}"

            yield processed_url_content + "\n"
        else:
            yield line_with_newline


async def async_download_m3u_playlist(url: str) -> list[str]:
    """Scarica una playlist M3U in modo asincrono e restituisce le righe."""
    headers = {
        "User-Agent": settings.user_agent,
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
    }
    lines = []
    try:
        async with create_aiohttp_session(url, timeout=30) as (session, proxy_url):
            response = await session.get(url, headers=headers, proxy=proxy_url)
            response.raise_for_status()
            content = await response.text()
            # Split content into lines
            for line in content.splitlines():
                lines.append(line + "\n" if line else "")
    except Exception as e:
        logger.error(f"Error downloading playlist (async): {str(e)}")
        raise
    return lines


def parse_channel_entries(lines: list[str]) -> list[list[str]]:
    """
    Parse the lines of an M3U playlist and group them into channel entries.
    Each entry is a list of lines that make up a single channel
    (from #EXTINF to the URL, including intermediate lines).
    """
    entries = []
    current_entry = []
    for line in lines:
        stripped_line = line.strip()
        if stripped_line.startswith("#EXTINF:"):
            if current_entry:  # In case of #EXTINF without a preceding URL
                logger.warning(
                    f"Found a new #EXTINF tag before a URL was found for the previous entry. Discarding: {current_entry}"
                )
            current_entry = [line]
        elif current_entry:
            current_entry.append(line)
            if stripped_line and not stripped_line.startswith("#"):
                entries.append(current_entry)
                current_entry = []
    return entries


async def async_generate_combined_playlist(playlist_definitions: list[str], base_url: str, api_password: Optional[str]):
    """Genera una playlist combinata da multiple definizioni, scaricando in parallelo."""
    # Prepara i task di download
    download_tasks = []
    for definition in playlist_definitions:
        should_proxy = True
        playlist_url_str = definition
        should_sort = False

        if definition.startswith("sort:"):
            should_sort = True
            definition = definition[len("sort:") :]

        if definition.startswith("no_proxy:"):  # Can be combined with sort:
            should_proxy = False
            playlist_url_str = definition[len("no_proxy:") :]
        else:
            playlist_url_str = definition

        download_tasks.append({"url": playlist_url_str, "proxy": should_proxy, "sort": should_sort})

    # Download all playlists in parallel
    results = await asyncio.gather(
        *[async_download_m3u_playlist(task["url"]) for task in download_tasks], return_exceptions=True
    )

    # Raggruppa le playlist da ordinare e quelle da non ordinare
    channel_entries_to_sort = []
    unsorted_playlists_data = []

    for idx, result in enumerate(results):
        task_info = download_tasks[idx]
        if isinstance(result, Exception):
            # Aggiungi errore come playlist non ordinata
            unsorted_playlists_data.append(
                {"lines": [f"# ERROR processing playlist {task_info['url']}: {str(result)}\n"], "proxy": False}
            )
            continue

        if task_info.get("sort", False):
            # Se la playlist deve essere ordinata, estraiamo i canali e li mettiamo nel pool globale da ordinare
            entries = parse_channel_entries(result)
            for entry_lines in entries:
                channel_entries_to_sort.append((entry_lines, task_info["proxy"]))
        else:
            unsorted_playlists_data.append({"lines": result, "proxy": task_info["proxy"]})

    # Gestione dell'header #EXTM3U
    first_playlist_header_handled = False

    def yield_header_once(lines_iter):
        nonlocal first_playlist_header_handled
        has_header = False
        for line in lines_iter:
            is_extm3u = line.strip().startswith("#EXTM3U")
            if is_extm3u:
                has_header = True
                if not first_playlist_header_handled:
                    first_playlist_header_handled = True
                    yield line
            else:
                yield line
        if has_header and not first_playlist_header_handled:
            first_playlist_header_handled = True

    # 1. Processa e ordina le playlist marcate con 'sort'
    if channel_entries_to_sort:
        # Sort all entries from ALL sorted playlists together by channel name (from #EXTINF)
        # The first line of each entry is always #EXTINF
        channel_entries_to_sort.sort(key=lambda x: x[0][0].split(",")[-1].strip().lower())

        # Handle the header only once for the sorted block
        if not first_playlist_header_handled:
            yield "#EXTM3U\n"
            first_playlist_header_handled = True

        # Apply link rewriting selectively
        for entry_lines, should_proxy in channel_entries_to_sort:
            # The URL is the last line of the entry
            url = entry_lines[-1]
            # Yield tutte le righe prima dell'URL
            for line in entry_lines[:-1]:
                yield line

            if should_proxy:
                # Usa un iteratore fittizio per processare una sola linea
                rewritten_url_iter = rewrite_m3u_links_streaming(iter([url]), base_url, api_password)
                yield next(rewritten_url_iter, url)  # Prende l'URL riscritto, con fallback all'originale
            else:
                yield url  # Lascia l'URL invariato

    # 2. Accoda le playlist non ordinate
    for playlist_data in unsorted_playlists_data:
        lines_iterator = iter(playlist_data["lines"])
        if playlist_data["proxy"]:
            lines_iterator = rewrite_m3u_links_streaming(lines_iterator, base_url, api_password)

        for line in yield_header_once(lines_iterator):
            yield line


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
        playlist_definitions = [def_.strip() for def_ in d.split(";") if def_.strip()]
        if not playlist_definitions:
            raise HTTPException(status_code=400, detail="No valid playlist definitions found")

        # Costruisci base_url con lo schema corretto
        original_scheme = get_original_scheme(request)
        base_url = f"{original_scheme}://{request.url.netloc}"

        # Estrai base_url dalla prima definizione se presente
        if playlist_definitions and "&" in playlist_definitions[0]:
            parts = playlist_definitions[0].split("&", 1)
            if ":" in parts[0] and not parts[0].startswith("http"):
                # Estrai base_url dalla prima parte se contiene password
                base_url_part = parts[0].rsplit(":", 1)[0]
                if base_url_part.startswith("http"):
                    base_url = base_url_part

        async def generate_response():
            async for line in async_generate_combined_playlist(playlist_definitions, base_url, api_password):
                yield line

        return StreamingResponse(
            generate_response(),
            media_type="application/vnd.apple.mpegurl",
            headers={"Content-Disposition": 'attachment; filename="playlist.m3u"', "Access-Control-Allow-Origin": "*"},
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
