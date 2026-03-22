# Networking: transport, forwarded headers, reverse proxies

## Transport Configuration

MediaFlow Proxy now supports advanced transport configuration using HTTPX's routing system. You can configure proxy and SSL verification settings for different domains and protocols.

### Basic Configuration

Enable proxy for all routes:
```env
PROXY_URL=http://proxy:8080
ALL_PROXY=true
```

### Advanced Routing Configuration

Configure different proxy settings for specific patterns:
```env
PROXY_URL=http://proxy:8080
TRANSPORT_ROUTES='{
    "https://internal.company.com": {
        "proxy": false
    },
    "all://streaming.service.com": {
        "proxy_url": "socks5://streaming-proxy:1080",
        "verify_ssl": false
    }
}'
```

The routing system supports various patterns:
- Domain routing: `"all://example.com"`
- Subdomain routing: `"all://*.example.com"`
- Protocol-specific routing: `"https://example.com"`
- Port-specific routing: `"all://*:1234"`
- Wildcard routing: `"all://"`

### Route Configuration Options

Each route can have the following settings:
- `proxy`: Boolean to enable/disable proxy for this route (default: true)
- `proxy_url`: Optional specific proxy URL for this route (overrides primary proxy_url)
- `verify_ssl`: Boolean to control SSL verification (default: true)

### Configuration Examples

1. Simple proxy setup with SSL bypass for internal domain:
    ```env
    PROXY_URL=http://main-proxy:8080
    TRANSPORT_ROUTES='{
        "https://internal.domain.com": {
            "proxy": false,
            "verify_ssl": false
        }
    }'
    ```

2. Different proxies for different services:
    ```env
    PROXY_URL=http://default-proxy:8080
    TRANSPORT_ROUTES='{
        "all://*.streaming.com": {
            "proxy": true,
            "proxy_url": "socks5://streaming-proxy:1080"
        },
        "all://*.internal.com": {
            "proxy": false
        },
        "https://api.service.com": {
            "proxy": true,
            "verify_ssl": false
        }
    }'
    ```

3. Global proxy with exceptions:
    ```env
    PROXY_URL=http://main-proxy:8080
    ALL_PROXY=true
    TRANSPORT_ROUTES='{
        "all://local.network": {
            "proxy": false
        },
        "all://*.trusted-service.com": {
            "proxy": false
        }
    }'
    ```

## Forwarded Headers Configuration

When MediaFlow Proxy is deployed behind reverse proxies, load balancers, or CDNs (such as Nginx, Apache, Cloudflare, AWS ALB, etc.), it needs to properly handle forwarded headers to determine the real client IP address and original request protocol. The `FORWARDED_ALLOW_IPS` environment variable and `--forwarded-allow-ips` uvicorn parameter control which IP addresses are trusted to provide these headers.

### What are Forwarded Headers?

Forwarded headers are HTTP headers that preserve information about the original client request when it passes through intermediary servers:

- **X-Forwarded-For**: Contains the original client IP address
- **X-Forwarded-Proto**: Contains the original request protocol (http/https)
- **X-Real-IP**: Alternative header for client IP address
- **X-Forwarded-Host**: Contains the original host header

### Security Importance

Only trusted proxy servers should be allowed to set these headers, as malicious clients could potentially spoof them to bypass IP-based restrictions or logging. MediaFlow Proxy uses these headers for:

- **Client IP Detection**: For IP-based access control in encrypted URLs
- **Protocol Detection**: For generating correct URLs with proper schemes
- **Security Logging**: For accurate request tracking and abuse prevention

### Configuration Options

**Environment Variable (Docker/Production):**
```env
# Trust only localhost (default - most secure)
FORWARDED_ALLOW_IPS=127.0.0.1

# Trust specific proxy IPs
FORWARDED_ALLOW_IPS=10.0.0.1,192.168.1.100

# Trust all IPs (use with caution)
FORWARDED_ALLOW_IPS=*

```
> **⚠️ Security warning**  
> Setting `FORWARDED_ALLOW_IPS=*` disables IP-spoofing protection and must **only** be used in trusted LAN or dev environments.  
> In production, always list the concrete IPs of your reverse-proxy servers.

**Uvicorn Command Line Parameter:**
```bash
# Trust only localhost (recommended for local development)
uvicorn mediaflow_proxy.main:app --forwarded-allow-ips "127.0.0.1"

# Trust specific proxy servers
uvicorn mediaflow_proxy.main:app --forwarded-allow-ips "10.0.0.1,192.168.1.100"

# Trust all IPs (development only - not recommended for production)
uvicorn mediaflow_proxy.main:app --forwarded-allow-ips "*"
```

### Common Deployment Scenarios

**1. Direct Internet Access (No Proxy)**
```bash
# Remove --forwarded-allow-ips parameter entirely or use localhost only
uvicorn mediaflow_proxy.main:app --host 0.0.0.0 --port 8888
```

**2. Behind Nginx Reverse Proxy**
```env
# Trust the Nginx server IP
FORWARDED_ALLOW_IPS=127.0.0.1
```

**3. Behind Cloudflare**
```env
# Trust Cloudflare IP ranges (example - check current Cloudflare IPs)
FORWARDED_ALLOW_IPS=173.245.48.0,103.21.244.0,103.22.200.0
```

**4. Behind AWS Application Load Balancer**
```env
# Trust the VPC subnet where ALB is deployed
FORWARDED_ALLOW_IPS=10.0.0.0
```

**5. Docker with Host Network**
```env
# Trust the Docker host
FORWARDED_ALLOW_IPS=172.17.0.1
```

**6. Docker Compose with Nginx in Same Network**
```env
# Trust the Docker network range (when nginx and mediaflow-proxy are in same docker network)
FORWARDED_ALLOW_IPS=172.20.0.0
# Or trust all Docker IPs (less secure but simpler for development)
FORWARDED_ALLOW_IPS=*
```

**7. Kubernetes with Ingress**
```env
# Trust the ingress controller pod network
FORWARDED_ALLOW_IPS=10.244.0.0
```

### Best Practices

1. **Principle of Least Privilege**: Only trust the specific IP addresses of your proxy servers
2. **Regular Updates**: Keep your trusted IP list updated when infrastructure changes
3. **Monitor Logs**: Watch for unexpected forwarded headers from untrusted sources
4. **Test Configuration**: Verify that client IPs are correctly detected after configuration changes

### Troubleshooting

**Problem**: Client IP always shows as proxy IP
- **Solution**: Add your proxy server's IP to `FORWARDED_ALLOW_IPS`

**Problem**: Security warnings about untrusted forwarded headers
- **Solution**: Restrict `FORWARDED_ALLOW_IPS` to only include your actual proxy servers

**Problem**: IP-based restrictions not working correctly
- **Solution**: Verify that forwarded headers are being processed by checking the trusted IP configuration

**Problem**: Links return 302 redirects when nginx is in the same Docker network
- **Solution**: Set `FORWARDED_ALLOW_IPS=*` or specify the Docker network (e.g., `FORWARDED_ALLOW_IPS=172.20.0.0`)
- **Note**: When nginx and MediaFlow Proxy run in the same Docker network, you must configure `FORWARDED_ALLOW_IPS` to trust the Docker network IP range, otherwise proxy links will not work correctly

### Example Nginx Configuration

When using Nginx as a reverse proxy, ensure it's properly setting forwarded headers:

```nginx
server {
    listen 80;
    server_name your-domain.com;
    
    location / {
        proxy_pass http://127.0.0.1:8888;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Then configure MediaFlow Proxy to trust Nginx:
```env
FORWARDED_ALLOW_IPS=127.0.0.1
```

## Reverse Proxy Configuration

MediaFlow Proxy is commonly deployed behind reverse proxies for SSL termination, load balancing, and additional security. Here are detailed configurations for popular reverse proxy solutions.

### Nginx Configuration

**Basic Nginx Configuration:**

```nginx
server {
    listen 80;
    server_name mediaflow.yourdomain.com;
    
    # Redirect HTTP to HTTPS
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name mediaflow.yourdomain.com;
    
    # SSL Configuration
    ssl_certificate /path/to/your/certificate.crt;
    ssl_certificate_key /path/to/your/private.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    
    # Security Headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    
    # Client settings for streaming
    client_max_body_size 0;
    client_body_timeout 60s;
    client_header_timeout 60s;
    
    location / {
        # Proxy settings
        proxy_pass http://127.0.0.1:8888;
        proxy_http_version 1.1;
        proxy_cache_bypass $http_upgrade;
        
        # Headers for forwarded information
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host $host;
        proxy_set_header X-Forwarded-Port $server_port;
        
        # Headers for streaming support
        proxy_set_header Range $http_range;
        proxy_set_header If-Range $http_if_range;
        proxy_set_header Connection "";
        
        # Timeout settings for streaming
        proxy_connect_timeout 60s;
        proxy_send_timeout 300s;
        proxy_read_timeout 300s;
        
        # Disable buffering for streaming
        proxy_buffering off;
        proxy_request_buffering off;
        proxy_max_temp_file_size 0;
        
        # Handle redirects
        proxy_redirect off;
    }
    
    # Optional: Specific location for streaming endpoints with extended timeouts
    location ~* ^/proxy/(stream|hls|mpd)/ {
        proxy_pass http://127.0.0.1:8888;
        proxy_http_version 1.1;
        
        # Extended timeouts for large streams
        proxy_connect_timeout 60s;
        proxy_send_timeout 600s;
        proxy_read_timeout 600s;
        
        # Streaming optimizations
        proxy_buffering off;
        proxy_request_buffering off;
        proxy_max_temp_file_size 0;
        
        # Forward all necessary headers
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Range $http_range;
        proxy_set_header If-Range $http_if_range;
        proxy_set_header Connection "";
    }
    
    # Access and error logs
    access_log /var/log/nginx/mediaflow_access.log;
    error_log /var/log/nginx/mediaflow_error.log;
}
```

**MediaFlow Proxy Configuration for Nginx:**
```env
# Trust Nginx server
FORWARDED_ALLOW_IPS=127.0.0.1

# Other recommended settings
API_PASSWORD=your_secure_password
```

### Nginx Proxy Manager Configuration

Nginx Proxy Manager provides a web-based interface for managing Nginx reverse proxy configurations.

**Step 1: Create Proxy Host**

In the Nginx Proxy Manager web interface:

**Details Tab:**
- **Domain Names**: `mediaflow.yourdomain.com`
- **Scheme**: `http`
- **Forward Hostname/IP**: `127.0.0.1` (or MediaFlow Proxy container IP)
- **Forward Port**: `8888`
- **Cache Assets**: ❌ (disabled)
- **Block Common Exploits**: ❌ (disabled)
- **Websockets Support**: ❌ (not required)
- **Access List**: None (unless you need IP restrictions)

**Step 2: SSL Configuration**

**SSL Tab:**
- **SSL Certificate**: Select your certificate (Let's Encrypt recommended)
- **Force SSL**: ✅ (redirect HTTP to HTTPS)
- **HTTP/2 Support**: ✅ (recommended for performance)
- **HSTS Enabled**: ✅ (recommended for security)
- **HSTS Subdomains**: ✅ (if applicable)

**Step 3: Advanced Configuration**

**Advanced Tab - Custom Nginx Configuration:**

```nginx
# Headers for forwarded information
proxy_set_header Host $host;
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Proto $scheme;
proxy_set_header X-Forwarded-Host $host;
proxy_set_header X-Forwarded-Port $server_port;

# Headers for streaming support
proxy_set_header Range $http_range;
proxy_set_header If-Range $http_if_range;
proxy_set_header Connection "";

# Timeout settings for streaming
proxy_connect_timeout 60s;
proxy_send_timeout 300s;
proxy_read_timeout 300s;

# Disable buffering for streaming
proxy_buffering off;
proxy_request_buffering off;
proxy_max_temp_file_size 0;

# Client settings
client_max_body_size 0;
client_body_timeout 60s;
client_header_timeout 60s;

# Handle redirects
proxy_redirect off;

# HTTP version
proxy_http_version 1.1;

# Security headers
add_header X-Frame-Options DENY always;
add_header X-Content-Type-Options nosniff always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;

# Hide server information
proxy_hide_header X-Powered-By;
server_tokens off;
```

**Step 4: MediaFlow Proxy Configuration**

Configure MediaFlow Proxy to trust Nginx Proxy Manager:

**If running on the same server:**
```env
FORWARDED_ALLOW_IPS=127.0.0.1
```

**If running in Docker with custom network:**
```env
# Use the Docker network range
FORWARDED_ALLOW_IPS=172.18.0.0/16
```

**If Nginx Proxy Manager is on a different server:**
```env
# Replace with actual Nginx Proxy Manager IP
FORWARDED_ALLOW_IPS=10.0.0.5
```

**Step 5: Docker Compose Example**

Complete Docker Compose setup with Nginx Proxy Manager:

```yaml
version: '3.8'

services:
  nginx-proxy-manager:
    image: 'jc21/nginx-proxy-manager:latest'
    restart: unless-stopped
    ports:
      - '80:80'
      - '443:443'
      - '81:81'  # Admin interface
    volumes:
      - ./npm-data:/data
      - ./npm-letsencrypt:/etc/letsencrypt
    networks:
      - proxy-network

  mediaflow-proxy:
    image: 'mhdzumair/mediaflow-proxy:latest'
    restart: unless-stopped
    ports:
      - '8888:8888'
    environment:
      - API_PASSWORD=your_secure_password
      - FORWARDED_ALLOW_IPS=172.18.0.0/16
    networks:
      - proxy-network

networks:
  proxy-network:
    driver: bridge
    ipam:
      config:
        - subnet: 172.18.0.0/16
```

### Important Notes for Nginx Proxy Manager

**Block Common Exploits Setting:**

The "Block Common Exploits" feature in Nginx Proxy Manager provides automatic protection against common web attacks but may occasionally block legitimate streaming URLs that contain special characters. 

**What it blocks:**
- Path traversal attempts (`../`, `..%2F`)
- SQL injection patterns
- XSS attempts
- Suspicious file extensions
- Very long URLs (>2000 characters)
- Base64-like patterns

**Recommendation:**
- **Enable it initially** for security
- **Monitor logs** for false positives
- **Disable only if necessary** for specific streaming services

**If you experience issues with legitimate URLs being blocked:**

1. **Check the logs** in Nginx Proxy Manager for 403 errors
2. **Test problematic URLs** directly
3. **Consider disabling** "Block Common Exploits" if it interferes with streaming
4. **Implement alternative security** measures (Cloudflare WAF, fail2ban, etc.)

### Troubleshooting Reverse Proxy Issues

**Problem: MediaFlow Proxy shows proxy IP instead of client IP**
- **Solution**: Verify `FORWARDED_ALLOW_IPS` includes your proxy server IP
- **Check**: Ensure proxy is sending `X-Forwarded-For` headers

**Problem: Streaming timeouts or interruptions**
- **Solution**: Increase timeout values in proxy configuration
- **Check**: Disable proxy buffering with `proxy_buffering off`

**Problem: Large file uploads fail**
- **Solution**: Set `client_max_body_size 0` in Nginx configuration
- **Check**: Verify `proxy_request_buffering off` is set

**Problem: SSL/HTTPS issues**
- **Solution**: Ensure `X-Forwarded-Proto` header is properly set
- **Check**: Verify SSL certificates are valid and properly configured

**Problem: 502/504 Gateway errors**
- **Solution**: Check MediaFlow Proxy is running and accessible
- **Check**: Verify network connectivity between proxy and MediaFlow Proxy
- **Check**: Review timeout settings in proxy configuration

