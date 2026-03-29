# Telegram MTProto configuration

## Telegram MTProto Configuration

MediaFlow Proxy can stream Telegram media (videos, documents, photos) through the MTProto protocol, enabling high-speed parallel downloads with full HTTP range request support for seeking.

**Requirements**: 
- Telegram API credentials from [my.telegram.org/apps](https://my.telegram.org/apps)
- A valid session string (generated once, see below)

> **Note**: Telethon and cryptg are included as standard dependencies - no extra installation needed.

### Configuration

| Environment Variable | Description | Default |
|---------------------|-------------|---------|
| `ENABLE_TELEGRAM` | Enable Telegram proxy support | `false` |
| `TELEGRAM_API_ID` | Telegram API ID from my.telegram.org | Required |
| `TELEGRAM_API_HASH` | Telegram API Hash from my.telegram.org | Required |
| `TELEGRAM_SESSION_STRING` | Persistent session string (see below) | Required |
| `TELEGRAM_MAX_CONNECTIONS` | Max parallel DC connections | `8` |
| `TELEGRAM_REQUEST_TIMEOUT` | Request timeout in seconds | `30` |

### Generating a Session String

The session string authenticates MediaFlow with Telegram. Generate it using the web UI:

1. Open MediaFlow's URL Generator page at `/url-generator#telegram`
2. Navigate to the **Session String Generator** section
3. Enter your API ID and API Hash (from https://my.telegram.org/apps)
4. Choose authentication method (user account or bot)
5. Complete authentication (phone number + code, or bot token)

Add the generated session string to your configuration:

```env
ENABLE_TELEGRAM=true
TELEGRAM_API_ID=12345678
TELEGRAM_API_HASH=your_api_hash_here
TELEGRAM_SESSION_STRING=your_session_string_here
```

> **Security Note**: The session string is equivalent to a password. Keep it secret!

### Telegram Endpoints

| Endpoint | Description |
|----------|-------------|
| `/proxy/telegram/stream` | Stream media from t.me link, chat IDs, document_id, or file_id |
| `/proxy/telegram/stream/{filename}` | Stream with custom filename |
| `/proxy/telegram/transcode/playlist.m3u8` | HLS transcode playlist (recommended for browser playback and smooth seeking) |
| `/proxy/telegram/transcode/init.mp4` | fMP4 init segment for Telegram transcode playlist |
| `/proxy/telegram/transcode/segment.m4s` | fMP4 media segment for Telegram transcode playlist |
| `/proxy/telegram/info` | Get media metadata |
| `/proxy/telegram/status` | Session status and health check |

### URL Parameters

| Parameter | Description |
|-----------|-------------|
| `d` or `url` | t.me link (e.g., `https://t.me/channel/123`) |
| `chat_id` | Chat/Channel ID (use with `message_id` or `document_id`) - numeric ID or @username |
| `message_id` | Message ID within the chat (use with `chat_id`) |
| `document_id` | Telegram document ID (use with `chat_id`, optionally add `file_size` to enforce size match while resolving) |
| `file_id` | Bot API file_id (use with `file_size`) |
| `file_size` | File size in bytes (required when using `file_id`) |
| `transcode` | Set to `true` for direct transcode mode on `/proxy/telegram/stream` (URL Generator defaults to `/proxy/telegram/transcode/playlist.m3u8` when no start time is set) |
| `start` | Seek start time in seconds (direct transcode mode only, used with `transcode=true`) |

### Supported Input Formats

**Option 1: t.me URLs**
- **Public channels**: `https://t.me/channelname/123`
- **Private channels**: `https://t.me/c/123456789/456`
- **User messages**: `https://t.me/username/123`

**Option 2: Direct IDs**
- `chat_id=-1001234567890&message_id=123` - Private channel/supergroup by numeric ID
- `chat_id=@channelname&message_id=123` - Public channel by username

**Option 3: chat_id + document_id**
- `chat_id=-1001234567890&document_id=6743210987654321` - Resolves by scanning recent chat messages
- Optional: add `file_size=52428800` to require both document ID and size to match

**Option 4: Bot API file_id**
- `file_id=BQACAgI...&file_size=1048576` - Direct streaming by file_id
- `chat_id=-1001234567890&file_id=BQACAgI...&file_size=1048576` - If the file reference is stale, server can resolve by scanning this chat
- Requires `file_size` parameter for range request support (seeking in video players)
- Get file_id and file_size from Telegram Bot API's `getFile` response

### Example URLs

```bash
# Stream from public channel using t.me link
mpv "http://localhost:8888/proxy/telegram/stream?d=https://t.me/channelname/123&api_password=your_password"

# Stream using chat_id + message_id
mpv "http://localhost:8888/proxy/telegram/stream?chat_id=-1001234567890&message_id=123&api_password=your_password"

# Stream with username instead of numeric ID
mpv "http://localhost:8888/proxy/telegram/stream?chat_id=@channelname&message_id=456&api_password=your_password"

# Stream using Bot API file_id (requires file_size)
mpv "http://localhost:8888/proxy/telegram/stream?file_id=BQACAgIAAxkBAAI...&file_size=52428800&api_password=your_password"

# Stream using chat_id + document_id (server scans recent messages)
mpv "http://localhost:8888/proxy/telegram/stream?chat_id=-1001234567890&document_id=6743210987654321&api_password=your_password"

# Stream with custom filename
mpv "http://localhost:8888/proxy/telegram/stream/movie.mp4?d=https://t.me/channelname/123&api_password=your_password"

# Get media info
curl "http://localhost:8888/proxy/telegram/info?d=https://t.me/channelname/123&api_password=your_password"

# Get media info using chat_id + message_id
curl "http://localhost:8888/proxy/telegram/info?chat_id=-1001234567890&message_id=123&api_password=your_password"

# Get media info using file_id
curl "http://localhost:8888/proxy/telegram/info?file_id=BQACAgIAAxkBAAI...&api_password=your_password"

# Check status
curl "http://localhost:8888/proxy/telegram/status?api_password=your_password"
```
