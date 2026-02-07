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

import re

logger = logging.getLogger(__name__)
playlist_builder_router = APIRouter()


def natural_sort_key(s: str):
    """
    Genera una chiave per l'ordinamento naturale (es. Channel 2 prima di Channel 10).
    """
    return [int(text) if text.isdigit() else text.lower() for text in re.split("([0-9]+)", s)]


def rewrite_m3u_links_streaming(
    m3u_lines_iterator: Iterator[str], base_url: str, api_password: Optional[str]
) -> Iterator[str]:
    """
    Riscrive i link da un iteratore di linee M3U secondo le regole specificate,
    includendo gli headers da #EXTVLCOPT e #EXTHTTP. Yields rewritten lines.
    """
    current_ext_headers: Dict[str, str] = {}  # Dizionario per conservare gli headers dalle direttive
    current_kodi_props: Dict[str, str] = {}  # Dizionario per conservare le proprietà KODI

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
                        # Gestisce http-user-agent, http-referer etc.
                        header_key = key_vlc[len("http-") :]
                        current_ext_headers[header_key] = value_vlc
            except Exception as e:
                logger.error(f"⚠️ Error parsing #EXTVLCOPT '{logical_line}': {e}")

        elif logical_line.startswith("#EXTHTTP:"):
            # Yield the original line to preserve it
            yield line_with_newline

            is_header_tag = True
            try:
                json_str = logical_line.split(":", 1)[1]
                # Sostituisce tutti gli header correnti con quelli del JSON
                current_ext_headers = json.loads(json_str)
            except Exception as e:
                logger.error(f"⚠️ Error parsing #EXTHTTP '{logical_line}': {e}")
                current_ext_headers = {}  # Resetta in caso di errore

        elif logical_line.startswith("#KODIPROP:"):
            try:
                prop_str = logical_line.split(":", 1)[1]
                if "=" in prop_str:
                    key_kodi, value_kodi = prop_str.split("=", 1)
                    key_kodi = key_kodi.strip()
                    value_kodi = value_kodi.strip()
                    current_kodi_props[key_kodi] = value_kodi

                    # Se è una delle proprietà DRM/Manifest che stiamo gestendo, non fare lo yield
                    if key_kodi in [
                        "inputstream.adaptive.manifest_type",
                        "inputstream.adaptive.license_type",
                        "inputstream.adaptive.license_key",
                    ]:
                        is_header_tag = True
            except Exception as e:
                logger.error(f"⚠️ Error parsing #KODIPROP '{logical_line}': {e}")

            if not is_header_tag:
                yield line_with_newline
                is_header_tag = True

        if is_header_tag:
            continue

        if (
            logical_line
            and not logical_line.startswith("#")
            and ("http://" in logical_line or "https://" in logical_line)
        ):
            original_url = logical_line

            # Determine if it's a special case or needs proxying
            if "pluto.tv" in original_url:
                processed_url_content = original_url
            elif "vavoo.to" in original_url:
                encoded_url = urllib.parse.quote(original_url, safe="")
                processed_url_content = f"{base_url}/proxy/hls/manifest.m3u8?d={encoded_url}"
            elif "vixsrc.to" in original_url:
                encoded_url = urllib.parse.quote(original_url, safe="")
                processed_url_content = (
                    f"{base_url}/extractor/video?host=VixCloud&redirect_stream=true&d={encoded_url}&max_res=true&no_proxy=true"
                )
            else:
                # Handle MPD or HLS (default)
                from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

                is_mpd = ".mpd" in original_url
                endpoint = "/proxy/mpd/manifest.m3u8" if is_mpd else "/proxy/hls/manifest.m3u8"

                # Parse the original URL to extract parameters
                parsed_url = urlparse(original_url)
                query_params = parse_qs(parsed_url.query)

                # Extract DRM keys from URL parameters
                key_id = query_params.get("key_id", [None])[0]
                key = query_params.get("key", [None])[0]

                # Extract DRM keys from KODIPROP if present
                license_key = current_kodi_props.get("inputstream.adaptive.license_key")
                if license_key:
                    # Support multi-key: "KID1:KEY1,KID2:KEY2"
                    kids = []
                    keys = []
                    pairs = license_key.split(",")
                    for pair in pairs:
                        if ":" in pair:
                            k_id, k_val = pair.split(":", 1)
                            kids.append(k_id.strip())
                            keys.append(k_val.strip())

                    if kids and keys:
                        # Se avevamo già key_id/key dall'URL, li aggiungiamo alla lista se non presenti
                        current_kid_list = key_id.split(",") if key_id else []
                        current_key_list = key.split(",") if key else []

                        for kid_val, k_val in zip(kids, keys):
                            if kid_val not in current_kid_list:
                                current_kid_list.append(kid_val)
                                current_key_list.append(k_val)

                        key_id = ",".join(current_kid_list)
                        key = ",".join(current_key_list)

                # Clean the original URL from DRM parameters to avoid duplication
                clean_query_params = {k: v for k, v in query_params.items() if k not in ["key_id", "key"]}
                clean_query = urlencode(clean_query_params, doseq=True)
                clean_url = urlunparse(
                    (
                        parsed_url.scheme,
                        parsed_url.netloc,
                        parsed_url.path,
                        parsed_url.params,
                        clean_query,
                        "",  # Remove fragment
                    )
                )

                # Encode the cleaned URL for the 'd' parameter
                encoded_clean_url = urllib.parse.quote(clean_url, safe="")
                processed_url_content = f"{base_url}{endpoint}?d={encoded_clean_url}"

                # Append DRM keys to the MediaFlow Proxy URL
                if key_id:
                    processed_url_content += f"&key_id={key_id}"
                if key:
                    processed_url_content += f"&key={key}"

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

            # Resetta le proprietà KODI dopo averle usate
            current_kodi_props = {}

            # Aggiungi api_password sempre alla fine
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
    Analizza le linee di una playlist M3U e le raggruppa in entry di canali.
    Ogni entry è una lista di linee che compongono un singolo canale
    (da #EXTINF fino all'URL, incluse le righe intermedie).
    """
    entries = []
    current_entry = []
    for line in lines:
        stripped_line = line.strip()
        if stripped_line.startswith("#EXTINF:"):
            if current_entry:  # In caso di #EXTINF senza URL precedente
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

        if definition.startswith("no_proxy:"):  # Può essere combinato con sort:
            should_proxy = False
            playlist_url_str = definition[len("no_proxy:") :]
        else:
            playlist_url_str = definition

        download_tasks.append({"url": playlist_url_str, "proxy": should_proxy, "sort": should_sort})

    # Scarica tutte le playlist in parallelo
    results = await asyncio.gather(
        *[async_download_m3u_playlist(task["url"]) for task in download_tasks], return_exceptions=True
    )

    # Raggruppa le playlist da ordinare e quelle da non ordinare
    sorted_playlist_lines = []
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
            sorted_playlist_lines.extend(result)
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
    if sorted_playlist_lines:
        # Estrai le entry dei canali
        # Modifica: Estrai le entry e mantieni l'informazione sul proxy
        channel_entries_with_proxy_info = []
        for idx, result in enumerate(results):
            task_info = download_tasks[idx]
            if task_info.get("sort") and isinstance(result, list):
                entries = parse_channel_entries(result)  # result è la lista di linee della playlist
                for entry_lines in entries:
                    # L'opzione proxy si applica a tutto il blocco del canale
                    channel_entries_with_proxy_info.append((entry_lines, task_info["proxy"]))

        # Ordina le entry in base al nome del canale (da #EXTINF)
        # La prima riga di ogni entry è sempre #EXTINF o un tag precedente (#EXTVLCOPT etc.)
        def get_channel_name(entry_lines):
            for line in entry_lines:
                if line.strip().startswith("#EXTINF:"):
                    parts = line.split(",", 1)
                    if len(parts) > 1:
                        return parts[1].strip()
            return ""

        channel_entries_with_proxy_info.sort(key=lambda x: natural_sort_key(get_channel_name(x[0])))

        # Gestisci l'header una sola volta per il blocco ordinato
        if not first_playlist_header_handled:
            yield "#EXTM3U\n"
            first_playlist_header_handled = True

        # Applica la riscrittura dei link in modo selettivo
        for entry_lines, should_proxy in channel_entries_with_proxy_info:
            if should_proxy:
                # Passa l'intero blocco del canale a rewrite_m3u_links_streaming
                # per gestire correttamente #EXTVLCOPT, #KODIPROP etc.
                for rewritten_line in rewrite_m3u_links_streaming(iter(entry_lines), base_url, api_password):
                    yield rewritten_line
            else:
                for line in entry_lines:
                    yield line

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
