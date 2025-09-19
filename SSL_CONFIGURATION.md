# SSL Configuration for HLS Proxy Endpoints

## Overview

This document explains how to configure SSL verification for HLS proxy endpoints to resolve SSL certificate verification errors.

## Problem

You may encounter SSL certificate verification errors like:
```
Error creating streaming response: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1028)
```

## Solution

A new configuration variable `disable_ssl_verification_for_hls` has been added to disable SSL verification for HLS proxy endpoints.

## Configuration

### Method 1: Environment Variable

Set the environment variable:
```bash
export DISABLE_SSL_VERIFICATION_FOR_HLS=true
```

### Method 2: .env File

Add to your `.env` file:
```
disable_ssl_verification_for_hls=true
```

### Method 3: Docker Environment

In your `docker-compose.yml`:
```yaml
services:
  mediaflow-proxy:
    environment:
      - DISABLE_SSL_VERIFICATION_FOR_HLS=true
```

## Default Behavior

- **Default**: SSL verification is **enabled** (`disable_ssl_verification_for_hls=false`)
- **When enabled**: SSL certificates are verified (secure but may fail with invalid certificates)
- **When disabled**: SSL certificates are not verified (less secure but works with invalid certificates)

## Security Considerations

⚠️ **Warning**: Disabling SSL verification reduces security as it makes the connection vulnerable to man-in-the-middle attacks. Only disable SSL verification if you trust the network and understand the security implications.

## Affected Endpoints

This setting affects the following HLS-specific endpoints:
- `/proxy/hls/manifest.m3u8`
- `/proxy/hls/segment`
- `/proxy/mpd/manifest.m3u8`
- `/proxy/mpd/playlist.m3u8`
- `/proxy/mpd/segment.mp4`

**Note**: The `/proxy/stream` endpoint maintains SSL verification for security reasons.

## Implementation Details

The SSL verification setting is applied to:
- HTTP client creation in `create_httpx_client()`
- Stream handling in `handle_hls_stream_proxy()`
- Segment downloads in `download_file_with_retry()`
- MPD manifest downloads in `get_cached_mpd()`
- Init segment downloads in `get_cached_init_segment()`

## Testing

To test if the configuration is working:

1. Set the environment variable:
   ```bash
   export DISABLE_SSL_VERIFICATION_FOR_HLS=true
   ```

2. Start the mediaflow-proxy server

3. Try accessing an HLS stream that previously failed with SSL errors

4. Check the logs - SSL certificate errors should no longer appear

## Troubleshooting

If you're still experiencing SSL errors:

1. Verify the environment variable is set correctly
2. Restart the mediaflow-proxy service
3. Check the logs for any configuration errors
4. Ensure you're accessing the correct HLS proxy endpoints