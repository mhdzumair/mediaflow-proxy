# Generic HTTP Forward Proxy (`/proxy/forward`)

## Overview

`/proxy/forward` is a transparent HTTP relay endpoint. It forwards any HTTP request — any method, any body, any headers — to a destination URL using **MediaFlow's outbound IP**, then returns the upstream response verbatim.

**Primary use cases:**

- **Debrid IP binding** — Route debrid API calls (RealDebrid, AllDebrid, TorBox, etc.) through MediaFlow so the debrid service records MediaFlow's IP as the TCP source, not the addon server's IP. Combine with the `{mediaflow_ip}` placeholder to keep the `ip=` parameter consistent.
- **Extractor POST requests** — Send JSON or form POST to a video host's extraction endpoint from MediaFlow's IP (resolves [issue #271](https://github.com/mhdzumair/mediaflow-proxy/issues/271)).
- **Any IP-bound API call** — Any HTTP API that must appear to come from the same IP that later fetches the stream.

---

## Endpoint

```
ANY /proxy/forward
    ?d=<destination_url>
    &api_password=<password>          # required (or encrypted token)
    [&h_<header-name>=<value>]        # set outbound request header (repeatable)
    [&r_<header-name>=<value>]        # override response header (repeatable)
```

### Methods

`GET`, `HEAD`, `POST`, `PUT`, `PATCH`, `DELETE`, `OPTIONS`

### Parameters

| Parameter | Required | Description |
|---|---|---|
| `d` | Yes | Destination URL. Must be `http://` or `https://`. |
| `api_password` | Yes* | API password (*if `API_PASSWORD` is configured). |
| `h_<name>` | No | Set a request header sent to the destination. E.g. `h_Authorization=Bearer tok`. |
| `r_<name>` | No | Override a response header returned to the caller. |

### Request body

The incoming request body is forwarded to the destination as-is. No base64, no envelope.

### Response

The upstream HTTP status, headers (minus hop-by-hop), and body are returned verbatim.

---

## `{mediaflow_ip}` placeholder

Embed the literal string `{mediaflow_ip}` anywhere in the destination URL or request body. MediaFlow substitutes it with its own public IP before forwarding.

This keeps the `ip=` parameter that debrid services use for CDN URL binding consistent with the TCP source of the API call.

**Example — RealDebrid `ip=` binding:**

```
GET /proxy/forward
    ?d=https://api.real-debrid.com/rest/1.0/torrents/instantAvailability/{hash}%3Fip%3D{mediaflow_ip}
    &api_password=secret
    &h_Authorization=Bearer <rd_token>
```

MediaFlow replaces `{mediaflow_ip}` with e.g. `1.2.3.4` before calling RealDebrid.

---

## Public IP endpoint

```
GET /proxy/ip?api_password=<password>
```

Returns `{"ip": "<public-ip>"}` — MediaFlow's outbound IP. Useful when you need to retrieve MediaFlow's IP before making a separate request (e.g. appending `ip=` to a CDN URL).

Configure a static value with the `PUBLIC_IP` environment variable to skip the auto-detection request.

Auto-detection uses the configured HTTP transport, including `ALL_PROXY` and the
`TRANSPORT_ROUTES` rules matching the IP lookup services. The result is refreshed
on each lookup so a changed proxy/VPN address is not retained until restart.
With destination-specific routing, the lookup services and the forwarded request
must use the same egress for the detected address to match; auto-detection does
not determine a separate public IP for every destination.

---

## Safety controls

| Control | Default | Description |
|---|---|---|
| SSRF guard | Always on | Requests to loopback (`127.x`, `::1`) and RFC-1918 private addresses are blocked with `403`. |
| Allowlist | Empty (allow all) | Set `FORWARD_ALLOWED_HOSTS` to restrict forwarding to specific hostnames. |
| Denylist | Empty | Set `FORWARD_DENIED_HOSTS` to block additional hostnames. |
| Request body limit | 50 MB | Set `FORWARD_MAX_REQUEST_BODY_BYTES`. Blocks at the limit with `413`. |
| Response body limit | 10 MB | Set `FORWARD_MAX_RESPONSE_BODY_BYTES`. Returns `502` if exceeded. |
| Auth required | Always | `api_password` or a valid encrypted token is mandatory. |

### IP-disclosure header stripping

The following headers are stripped from the outbound request before forwarding so the caller's IP is never leaked:

`X-Forwarded-For`, `X-Real-IP`, `X-Client-IP`, `True-Client-IP`, `Forwarded`, `CF-Connecting-IP`, `X-Original-Forwarded-For`, `X-Cluster-Client-IP`

---

## Examples

### GET — API call through MediaFlow's IP

```bash
curl "http://localhost:8888/proxy/forward\
?d=https://api.real-debrid.com/rest/1.0/user\
&api_password=secret\
&h_Authorization=Bearer%20YOUR_RD_TOKEN"
```

### POST JSON — extractor endpoint

```bash
curl -X POST \
  "http://localhost:8888/proxy/forward\
?d=https://example.com/api/videos/abc123/playback\
&api_password=secret\
&h_Referer=https%3A%2F%2Fexample.com%2F\
&h_Content-Type=application%2Fjson" \
  -d '{"fingerprint":{"userAgent":"Mozilla/5.0"}}'
```

### POST form — debrid API

```bash
curl -X POST \
  "http://localhost:8888/proxy/forward\
?d=https://api.real-debrid.com/rest/1.0/torrents/addMagnet\
&api_password=secret\
&h_Authorization=Bearer%20YOUR_RD_TOKEN\
&h_Content-Type=application%2Fx-www-form-urlencoded" \
  --data-urlencode "magnet=magnet:?xt=urn:btih:..."
```

### DELETE — remove a torrent

```bash
curl -X DELETE \
  "http://localhost:8888/proxy/forward\
?d=https://api.real-debrid.com/rest/1.0/torrents/delete/TORRENT_ID\
&api_password=secret\
&h_Authorization=Bearer%20YOUR_RD_TOKEN"
```

### Get MediaFlow's public IP

```bash
curl "http://localhost:8888/proxy/ip?api_password=secret"
# {"ip":"1.2.3.4"}
```

---

## Configuration

New settings added to support `/proxy/forward`. All are optional.

| Environment variable | Default | Description |
|---|---|---|
| `PUBLIC_IP` | *(auto-detected)* | Static public IP returned by `/proxy/ip` and substituted for `{mediaflow_ip}`. Skips auto-detection requests. |
| `FORWARD_ALLOWED_HOSTS` | `[]` | Comma-separated allowlist of hostnames. Empty = allow any host. |
| `FORWARD_DENIED_HOSTS` | `[]` | Comma-separated denylist of hostnames (in addition to the built-in private-IP guard). |
| `FORWARD_MAX_REQUEST_BODY_BYTES` | `52428800` (50 MB) | Maximum incoming request body size. Allows NZB/torrent file uploads. |
| `FORWARD_MAX_RESPONSE_BODY_BYTES` | `10485760` (10 MB) | Maximum upstream response body size. |

---

## Comparison with `/proxy/stream`

| Feature | `/proxy/stream` | `/proxy/forward` |
|---|---|---|
| Methods | `GET`, `HEAD` | Any (`GET`, `POST`, `PUT`, `PATCH`, `DELETE`, …) |
| Request body | No | Yes (forwarded verbatim) |
| Range / partial content | Yes | No |
| HLS / DASH rewriting | Yes | No |
| IP binding (`{mediaflow_ip}`) | No | Yes |
| Response size limit | No | Yes (10 MB default) |
| Intended use | Video streaming | API calls, extractor POSTs |
