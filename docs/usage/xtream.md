# Xtream Codes (XC) API proxy

## Xtream Codes (XC) API Proxy

MediaFlow Proxy can act as a stateless pass-through proxy for Xtream Codes API, allowing you to proxy streams from XC-compatible IPTV providers through MediaFlow. This is particularly useful for:

- Proxying streams from providers with **Catch Up/Timeshift** support
- Using MediaFlow's features (headers, DRM, etc.) with XC streams
- Routing XC streams through a specific network path

### Configuration

Configure your IPTV player with the following settings:

| Setting | Value |
|---------|-------|
| **Server URL** | `http://your-mediaflow-server:8888` |
| **Username** | Base64-encoded string (see below) |
| **Password** | Your XC provider password |

### Username Format (Recommended)

The username should be a **base64-encoded string** containing your provider URL, XC username, and MediaFlow API password. This format is compatible with all IPTV players (TiviMate, IPTV Smarters, OTT Navigator, etc.).

**Format before encoding:**
```
{provider_url}:{xc_username}:{api_password}
```

**Example:**
```
http://provider.com:8080:myusername:my_mediaflow_password
```

After base64 encoding, this becomes a single string like:
```
aHR0cDovL3Byb3ZpZGVyLmNvbTo4MDgwOm15dXNlcm5hbWU6bXlfbWVkaWFmbG93X3Bhc3N3b3Jk
```

**Without MediaFlow API password:**
```
http://provider.com:8080:myusername
```

Encoded:
```
aHR0cDovL3Byb3ZpZGVyLmNvbTo4MDgwOm15dXNlcm5hbWU
```

### Generating the Username

Use the **URL Generator tool** at `http://your-mediaflow-server:8888/url-generator` (recommended) or manually:

**Using command line:**
```bash
# With API password
echo -n "http://provider.com:8080:myusername:my_api_password" | base64

# Without API password
echo -n "http://provider.com:8080:myusername" | base64
```

**Using Python:**
```python
import base64

# With API password
combined = "http://provider.com:8080:myusername:my_api_password"
encoded = base64.urlsafe_b64encode(combined.encode()).decode().rstrip('=')
print(encoded)

# Without API password
combined = "http://provider.com:8080:myusername"
encoded = base64.urlsafe_b64encode(combined.encode()).decode().rstrip('=')
print(encoded)
```

### Legacy Format (Still Supported)

The legacy colon-separated format is still supported for backward compatibility:
```
{base64_upstream}:{actual_username}:{api_password}
```

However, some IPTV apps may not handle colons in the username field correctly. The new base64-encoded format is recommended.

### Supported XC API Endpoints

MediaFlow proxies all standard XC API endpoints:

| Endpoint | Description |
|----------|-------------|
| `/player_api.php` | Main API for categories, streams, VOD, series |
| `/xmltv.php` | EPG/TV Guide data |
| `/get.php` | M3U playlist generation |
| `/panel_api.php` | Panel API (if supported by provider) |
| `/live/{user}/{pass}/{id}.{ext}` | Live stream playback |
| `/movie/{user}/{pass}/{id}.{ext}` | VOD/Movie playback |
| `/series/{user}/{pass}/{id}.{ext}` | Series episode playback |
| `/timeshift/{user}/{pass}/{duration}/{start}/{id}.{ext}` | Catch-up/Timeshift playback |

### Player Configuration Examples

**TiviMate:**
1. Add Playlist → Xtream Codes Login
2. Server: `http://your-mediaflow-server:8888`
3. Username: Paste the base64-encoded username from the URL Generator
4. Password: Your XC password

**IPTV Smarters:**
1. Add User → Xtream Codes API
2. Any Name: Your choice
3. Username: Paste the base64-encoded username from the URL Generator
4. Password: Your XC password
5. URL: `http://your-mediaflow-server:8888`

**OTT Navigator:**
1. Add Provider → Xtream
2. Portal URL: `http://your-mediaflow-server:8888`
3. Login: Paste the base64-encoded username from the URL Generator
4. Password: Your XC password
