# T1 Agentics - HTTPS Setup Guide

**Enable secure HTTPS connections for production deployment**

---

## Quick Setup Options

### Option 1: Self-Signed Certificate (Development/Testing)
 Quick (5 minutes)
 Browser warnings
 Good for local testing

### Option 2: Let's Encrypt (Production)
 Free and automated
 Trusted by browsers
 15 minutes setup

### Option 3: Custom Certificate (Enterprise)
 Your own CA
 Full control
 Requires existing cert

---

## Option 1: Self-Signed Certificate (Quick Start)

### Generate Certificate

```bash
# Create certs directory
mkdir -p /opt/t1agentics/certs
cd /opt/t1agentics/certs

# Generate self-signed certificate (valid 365 days)
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
 -keyout server.key \
 -out server.crt \
 -subj "/C=US/ST=State/L=City/O=T1Agentics/CN=localhost"

# Set permissions
chmod 600 server.key
chmod 644 server.crt

echo " Self-signed certificate created"
```

### Update docker-compose.yml

```yaml
services:
 backend:
 volumes:
 # Add certificate volume
- ./certs:/certs:ro
 environment:
 # Enable HTTPS
- ENABLE_HTTPS=true
- SSL_CERT_FILE=/certs/server.crt
- SSL_KEY_FILE=/certs/server.key
 ports:
 # Add HTTPS port
- "8443:8443" # HTTPS
- "8000:8000" # HTTP (for health checks)

 frontend:
 environment:
 # Update API URL to HTTPS
- REACT_APP_API_URL=https://localhost:8443
 ports:
- "3443:443" # HTTPS
- "3000:80" # HTTP fallback
```

### Update Backend Code

**File:** `backend/app.py`

Add near the top:
```python
import os
import ssl

# HTTPS configuration
ENABLE_HTTPS = os.getenv('ENABLE_HTTPS', 'false').lower() == 'true'
SSL_CERT_FILE = os.getenv('SSL_CERT_FILE', '/certs/server.crt')
SSL_KEY_FILE = os.getenv('SSL_KEY_FILE', '/certs/server.key')
```

At the bottom (replace `uvicorn.run`):
```python
if __name__ == "__main__":
 import uvicorn

 ssl_context = None
 if ENABLE_HTTPS:
 ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
 ssl_context.load_cert_chain(SSL_CERT_FILE, SSL_KEY_FILE)
 print(f" HTTPS enabled on port 8443")

 uvicorn.run(
 app,
 host="0.0.0.0",
 port=8443 if ENABLE_HTTPS else 8000,
 ssl_keyfile=SSL_KEY_FILE if ENABLE_HTTPS else None,
 ssl_certfile=SSL_CERT_FILE if ENABLE_HTTPS else None,
 )
```

### Update Frontend Dev Config

**File:** `frontend/.env.development`
```bash
REACT_APP_API_URL=https://localhost:8443
PORT=3000
BROWSER=none
FAST_REFRESH=true
HTTPS=false # Keep frontend on HTTP in dev, proxy to HTTPS backend
```

### Restart Services

```bash
# Rebuild and restart
sudo docker compose down
sudo docker compose build --no-cache backend
sudo docker compose up -d

# Verify HTTPS
curl -k https://localhost:8443/api/v1/health
# Should return: {"status":"ok"}
```

### Access Frontend

```
https://localhost:3443 # Docker frontend
http://localhost:3000 # npm dev server (proxies to HTTPS backend)
```

**Note:** Browser will show "Not Secure" warning - click "Advanced" → "Proceed" (self-signed cert)

---

## Option 2: Let's Encrypt (Production)

**Requirements:**
- Public domain name
- Port 80/443 accessible from internet
- DNS pointing to your server

### Install Certbot

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install certbot python3-certbot-nginx

# Generate certificate
sudo certbot certonly --standalone \
 -d t1agentics.yourdomain.com \
 --agree-tos \
 --email admin@yourdomain.com

# Certificates saved to:
# /etc/letsencrypt/live/t1agentics.yourdomain.com/fullchain.pem
# /etc/letsencrypt/live/t1agentics.yourdomain.com/privkey.pem
```

### Update docker-compose.yml

```yaml
services:
 backend:
 volumes:
 # Mount Let's Encrypt certificates
- /etc/letsencrypt/live/t1agentics.yourdomain.com:/certs:ro
 environment:
- ENABLE_HTTPS=true
- SSL_CERT_FILE=/certs/fullchain.pem
- SSL_KEY_FILE=/certs/privkey.pem
- ALLOWED_ORIGINS=https://t1agentics.yourdomain.com
 ports:
- "443:8443" # HTTPS on standard port
```

### Auto-Renewal

```bash
# Test renewal
sudo certbot renew --dry-run

# Set up cron job (runs twice daily)
echo "0 0,12 * * * root certbot renew --quiet && docker compose restart backend" | sudo tee -a /etc/crontab
```

### Update DNS

```
A record: t1agentics.yourdomain.com → YOUR_SERVER_IP
```

### Access

```
https://t1agentics.yourdomain.com
```

**No browser warnings**

---

## Option 3: Custom Certificate (Enterprise)

If you have your own certificate from a CA:

### Copy Certificates

```bash
# Copy your cert files
sudo cp /path/to/your-cert.crt /opt/t1agentics/certs/server.crt
sudo cp /path/to/your-key.key /opt/t1agentics/certs/server.key
sudo cp /path/to/your-ca.crt /opt/t1agentics/certs/ca.crt

# Set permissions
sudo chmod 600 /opt/t1agentics/certs/server.key
sudo chmod 644 /opt/t1agentics/certs/*.crt
```

### Update docker-compose.yml

```yaml
services:
 backend:
 volumes:
- ./certs:/certs:ro
 environment:
- ENABLE_HTTPS=true
- SSL_CERT_FILE=/certs/server.crt
- SSL_KEY_FILE=/certs/server.key
- SSL_CA_FILE=/certs/ca.crt
```

---

## Frontend HTTPS Configuration

### For Docker Frontend

**Create Nginx config:**

```nginx
# Create: frontend/nginx-https.conf
server {
 listen 443 ssl http2;
 server_name localhost;

 ssl_certificate /certs/server.crt;
 ssl_certificate_key /certs/server.key;
 ssl_protocols TLSv1.2 TLSv1.3;
 ssl_ciphers HIGH:!aNULL:!MD5;

 root /usr/share/nginx/html;
 index index.html;

 location / {
 try_files $uri $uri/ /index.html;
 }

 location /api {
 proxy_pass https://backend:8443;
 proxy_ssl_verify off;
 proxy_set_header Host $host;
 proxy_set_header X-Real-IP $remote_addr;
 proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
 proxy_set_header X-Forwarded-Proto $scheme;
 }
}
```

**Update Dockerfile:**

```dockerfile
# frontend/Dockerfile
FROM node:18-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
RUN npm run build

FROM nginx:alpine
COPY --from=build /app/build /usr/share/nginx/html
COPY nginx-https.conf /etc/nginx/conf.d/default.conf
EXPOSE 443
CMD ["nginx", "-g", "daemon off;"]
```

### For npm Dev Server

**Enable HTTPS in dev:**

```bash
# frontend/.env.development
HTTPS=true
SSL_CRT_FILE=../certs/server.crt
SSL_KEY_FILE=../certs/server.key
REACT_APP_API_URL=https://localhost:8443
```

**Or use proxy (recommended):**

```bash
# Keep frontend HTTP, proxy to HTTPS backend
HTTPS=false
REACT_APP_API_URL=https://localhost:8443
```

---

## Security Best Practices

### 1. Strong Cipher Suites

**Nginx config:**
```nginx
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers 'ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256';
ssl_prefer_server_ciphers on;
```

### 2. HSTS (Force HTTPS)

**Backend middleware:**
```python
# backend/middleware/security_headers.py
@app.middleware("http")
async def add_security_headers(request, call_next):
 response = await call_next(request)
 response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
 return response
```

### 3. Redirect HTTP → HTTPS

**Nginx:**
```nginx
server {
 listen 80;
 server_name localhost;
 return 301 https://$server_name$request_uri;
}
```

### 4. Certificate Monitoring

**Check expiration:**
```bash
# Check cert expiration
openssl x509 -in /opt/t1agentics/certs/server.crt -noout -enddate

# Alert if < 30 days
echo "0 0 * * * /usr/local/bin/check-cert-expiry.sh" | sudo crontab -
```

---

## Testing HTTPS Setup

### Backend

```bash
# Test HTTPS endpoint
curl -k https://localhost:8443/api/v1/health

# Should return: {"status":"ok"}

# Check certificate
openssl s_client -connect localhost:8443 -showcerts
```

### Frontend

```bash
# Test frontend HTTPS
curl -k https://localhost:3443

# Should return HTML

# Check SSL grade
# https://www.ssllabs.com/ssltest/
```

### Full End-to-End

1. Open `https://localhost:3443` (or your domain)
2. Login: admin / admin123
3. Check browser lock icon (green padlock)
4. View certificate: Click lock → Certificate
5. Verify all API calls use HTTPS (Network tab)

---

## Troubleshooting

### "Certificate Not Trusted"

**Self-signed cert:**
- Expected behavior
- Click "Advanced" → "Proceed"
- Or add cert to browser trust store

**Let's Encrypt:**
- Check DNS pointing to server
- Verify port 80/443 accessible
- Check certbot logs: `sudo journalctl -u certbot`

### "Connection Reset" or "ERR_SSL_PROTOCOL_ERROR"

```bash
# Check backend listening on HTTPS port
sudo docker compose logs backend | grep "8443"

# Check certificate files exist
sudo docker compose exec backend ls -l /certs/

# Check file permissions
sudo docker compose exec backend cat /certs/server.crt
```

### Mixed Content Warnings

**Problem:** HTTPS page loading HTTP resources

**Fix:** Update all URLs to HTTPS
```javascript
// frontend/src/utils/api.js
export const API_BASE_URL = process.env.REACT_APP_API_URL || 'https://localhost:8443';
```

### CORS with HTTPS

**Update ALLOWED_ORIGINS:**
```yaml
backend:
 environment:
- ALLOWED_ORIGINS=https://localhost:3443,https://yourdomain.com
```

---

## Quick Setup Script

Save as `setup-https.sh`:

```bash
#!/bin/bash
# Quick HTTPS Setup

set -e

echo " T1 Agentics - HTTPS Setup"
echo "============================"
echo ""

# Create certs directory
mkdir -p certs
cd certs

# Generate self-signed cert
echo " Generating self-signed certificate..."
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
 -keyout server.key \
 -out server.crt \
 -subj "/C=US/ST=State/L=City/O=T1Agentics/CN=localhost" \
 2>/dev/null

chmod 600 server.key
chmod 644 server.crt

echo " Certificate created"
echo ""
echo "Next steps:"
echo "1. Update docker-compose.yml (add ENABLE_HTTPS=true)"
echo "2. Restart: sudo docker compose restart backend"
echo "3. Access: https://localhost:8443"
echo ""
echo "See: docs/changes-2026-01-12/HTTPS_SETUP.md"
```

Run:
```bash
chmod +x setup-https.sh
./setup-https.sh
```

---

## Production Checklist

- [ ] Use Let's Encrypt or valid CA certificate
- [ ] Enable HSTS
- [ ] Force HTTPS redirect
- [ ] Strong cipher suites (TLS 1.2+)
- [ ] Certificate auto-renewal
- [ ] Monitoring and alerts
- [ ] Update ALLOWED_ORIGINS
- [ ] Test SSL grade (ssllabs.com)
- [ ] Verify no mixed content warnings
- [ ] Document cert renewal process

---

## Quick Commands

```bash
# Generate self-signed cert
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
 -keyout certs/server.key -out certs/server.crt \
 -subj "/C=US/ST=State/L=City/O=T1Agentics/CN=localhost"

# Test HTTPS
curl -k https://localhost:8443/api/v1/health

# Check certificate
openssl x509 -in certs/server.crt -noout -text

# Check expiration
openssl x509 -in certs/server.crt -noout -enddate

# Restart with HTTPS
sudo docker compose restart backend
```

---

**Version:** 1.0
**Date:** 2026-01-12
