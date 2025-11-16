import re
import requests

def extract_vidmoly_best(url: str):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "Referer": "https://vidmoly.net/",
        "Sec-Fetch-Dest": "iframe"
    }

    r = requests.get(url, headers=headers, timeout=10)
    if r.status_code != 200:
        return {"error": f"HTTP {r.status_code}"}

    # Extract initial m3u8 URL
    match = re.search(r'sources\s*:\s*\[\{file:"([^"]+)"', r.text)
    if not match:
        return {"error": "stream URL not found"}

    master_url = match.group(1)

    # Fetch master playlist
    r2 = requests.get(master_url, headers=headers, timeout=10)
    if r2.status_code != 200:
        return {"error": "failed to fetch master playlist"}

    playlist_text = r2.text

    # Parse all variant streams
    variants = re.findall(r'#EXT-X-STREAM-INF:.*BANDWIDTH=(\d+).*?\n([^\n]+)', playlist_text)
    if not variants:
        # No variants, use master URL as-is
        return {"streams": [{"quality": "default", "type": "hls", "url": master_url}]}

    # Pick highest bandwidth
    variants.sort(key=lambda x: int(x[0]), reverse=True)
    best_url = variants[0][1]

    # If the variant URL is relative, join with master base URL
    if not best_url.startswith("http"):
        from urllib.parse import urljoin
        best_url = urljoin(master_url, best_url)

    return {
        "streams": [
            {"quality": "best", "type": "hls", "url": best_url}
        ]
    }
