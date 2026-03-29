# Base64 URL support


MediaFlow Proxy now supports base64 encoded URLs, providing additional flexibility for handling URLs that may be encoded in base64 format.

## Features

### Automatic Base64 Detection and Decoding

The proxy automatically detects and decodes base64 encoded URLs in all endpoints:

- **Proxy endpoints** (`/proxy/stream`, `/proxy/hls/manifest.m3u8`, etc.)
- **Extractor endpoints** (`/extractor/video`)
- **MPD/DASH endpoints** (`/proxy/mpd/manifest.m3u8`, `/proxy/mpd/playlist.m3u8`)

### Base64 Utility Endpoints

New endpoints for base64 operations:

**1. Encode URL to Base64**
```http
POST /base64/encode
Content-Type: application/json

{
  "url": "https://example.com/video.mp4"
}
```

Response:
```json
{
  "encoded_url": "aHR0cHM6Ly9leGFtcGxlLmNvbS92aWRlby5tcDQ",
  "original_url": "https://example.com/video.mp4"
}
```

**2. Decode Base64 URL**
```http
POST /base64/decode
Content-Type: application/json

{
  "encoded_url": "aHR0cHM6Ly9leGFtcGxlLmNvbS92aWRlby5tcDQ"
}
```

Response:
```json
{
  "decoded_url": "https://example.com/video.mp4",
  "encoded_url": "aHR0cHM6Ly9leGFtcGxlLmNvbS92aWRlby5tcDQ"
}
```

**3. Check if String is Base64 URL**
```http
GET /base64/check?url=aHR0cHM6Ly9leGFtcGxlLmNvbS92aWRlby5tcDQ
```

Response:
```json
{
  "url": "aHR0cHM6Ly9leGFtcGxlLmNvbS92aWRlby5tcDQ",
  "is_base64": true,
  "decoded_url": "https://example.com/video.mp4"
}
```

### URL Generation with Base64 Encoding

The `/generate_url` endpoint now supports a `base64_encode_destination` parameter:

```python
import requests

url = "http://localhost:8888/generate_url"
data = {
    "mediaflow_proxy_url": "http://localhost:8888",
    "endpoint": "/proxy/stream",
    "destination_url": "https://example.com/video.mp4",
    "base64_encode_destination": True,  # Encode destination URL in base64
    "api_password": "your_password"
}

response = requests.post(url, json=data)
encoded_url = response.json()["url"]
print(encoded_url)
```

## Usage Examples

### 1. Using Base64 Encoded URLs Directly

You can now pass base64 encoded URLs directly to any proxy endpoint:

```bash
# Original URL: https://example.com/video.mp4
# Base64 encoded: aHR0cHM6Ly9leGFtcGxlLmNvbS92aWRlby5tcDQ

mpv "http://localhost:8888/proxy/stream?d=aHR0cHM6Ly9leGFtcGxlLmNvbS92aWRlby5tcDQ&api_password=your_password"
```

### 2. HLS Manifest with Base64 URL

```bash
# Base64 encoded HLS URL
mpv "http://localhost:8888/proxy/hls/manifest.m3u8?d=aHR0cDovL2V4YW1wbGUuY29tL3BsYXlsaXN0Lm0zdTg&api_password=your_password"
```

### 3. Extractor with Base64 URL

```bash
# Base64 encoded extractor URL
curl "http://localhost:8888/extractor/video?host=Doodstream&d=aHR0cHM6Ly9kb29kc3RyZWFtLmNvbS9lL3NvbWVfaWQ&api_password=your_password"
```

### 4. DASH Stream with Base64 URL

```bash
# Base64 encoded DASH manifest URL
mpv "http://localhost:8888/proxy/mpd/manifest.m3u8?d=aHR0cHM6Ly9leGFtcGxlLmNvbS9tYW5pZmVzdC5tcGQ&api_password=your_password"
```

## Implementation Details

### Base64 Detection Algorithm

The system uses several heuristics to detect base64 encoded URLs:

1. **Character Set Check**: Verifies the string contains only valid base64 characters (A-Z, a-z, 0-9, +, /, =)
2. **Protocol Check**: Ensures the string doesn't start with common URL protocols (http://, https://, etc.)
3. **Length Check**: Validates minimum length for meaningful base64 encoded URLs
4. **Decoding Validation**: Attempts to decode and validates the result is a valid URL

### URL-Safe Base64 Encoding

The system supports both standard and URL-safe base64 encoding:

- **Standard Base64**: Uses `+` and `/` characters
- **URL-Safe Base64**: Uses `-` and `_` characters instead of `+` and `/`
- **Padding**: Automatically handles missing padding (`=` characters)

### Error Handling

- Invalid base64 strings are treated as regular URLs
- Decoding failures are logged but don't break the request flow
- Malformed URLs after decoding are handled gracefully

## Security Considerations

- Base64 encoding is **not encryption** - it's just encoding
- URLs are still logged in their decoded form for debugging
- All existing security measures (API keys, IP restrictions, etc.) still apply
- Base64 encoded URLs are subject to the same validation as regular URLs

## Backward Compatibility

This feature is fully backward compatible:

- Existing URLs continue to work without changes
- Regular (non-base64) URLs are processed normally
- No configuration changes required
- All existing API endpoints remain unchanged
