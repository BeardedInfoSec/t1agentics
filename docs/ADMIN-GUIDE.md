# T1 Agentics - Administrator Guide

This guide covers platform administration, deployment, configuration, and maintenance.

---

## Table of Contents

1. [System Requirements](#system-requirements)
2. [Installation](#installation)
3. [Configuration](#configuration)
4. [User Management](#user-management)
5. [AI Provider Setup](#ai-provider-setup)
6. [Email & Notifications](#email--notifications)
7. [Threat Feed Management](#threat-feed-management)
8. [License Management](#license-management)
9. [Security Hardening](#security-hardening)
10. [Backup & Recovery](#backup--recovery)
11. [Monitoring & Health Checks](#monitoring--health-checks)
12. [Maintenance & Updates](#maintenance--updates)
13. [Troubleshooting](#troubleshooting)

---

## System Requirements

### Minimum Requirements

| Component | Specification |
|-----------|---------------|
| **CPU** | 4 cores |
| **RAM** | 8 GB |
| **Disk** | 50 GB SSD |
| **OS** | Ubuntu 22.04+, Windows 10+ (Docker Desktop), macOS 13+ |
| **Docker** | Docker Engine 24+ or Docker Desktop 4+ |
| **Network** | Ports 80, 443, 8000, 5432 |

### Recommended (Production)

| Component | Specification |
|-----------|---------------|
| **CPU** | 8+ cores |
| **RAM** | 16+ GB |
| **Disk** | 200+ GB SSD |
| **GPU** | NVIDIA GPU with 16+ GB VRAM (for local AI inference) |
| **OS** | Ubuntu 24.04 LTS |

---

## Installation

### Quick Start (Development)

```bash
# Clone the repository
git clone https://github.com/t1-agentics/t1agentics.git
cd t1agentics

# Copy environment template
cp .env.example .env

# Start all services
docker compose up -d

# Wait for services to initialize (~30 seconds)
# Access: http://localhost:3000
# Login: admin / admin123
```

### Production Deployment (DigitalOcean/Linux)

```bash
# 1. Set up the server
ssh root@your-server-ip
mkdir -p /opt/t1agentics && cd /opt/t1agentics

# 2. Clone the repository
git clone https://github.com/t1-agentics/t1agentics.git .

# 3. Create production environment file
cp .env.production.template .env.production

# 4. Generate strong secrets
# JWT Secret:
openssl rand -hex 32

# Fernet encryption key:
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

# Database password:
openssl rand -base64 24 | tr -d '/+='

# 5. Edit .env.production with your generated secrets
nano .env.production

# 6. Set up SSL certificates
mkdir -p /opt/t1agentics/certs
# For self-signed (temporary):
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
 -keyout certs/privkey.pem -out certs/fullchain.pem \
 -subj "/CN=your-server-ip"

# For Let's Encrypt (recommended):
# certbot certonly --standalone -d yourdomain.com
# ln -s /etc/letsencrypt/live/yourdomain.com/fullchain.pem certs/fullchain.pem
# ln -s /etc/letsencrypt/live/yourdomain.com/privkey.pem certs/privkey.pem

# 7. Start production services
docker compose -f docker-compose.yml --env-file .env.production up -d

# 8. Verify all services are running
docker compose -f docker-compose.yml ps
```

### Post-Installation Steps

1. **Change the admin password** immediately after first login
2. **Configure SMTP** for email notifications (Settings > Notifications)
3. **Enable threat feeds** (Settings > Threat Feeds)
4. **Set up AI provider** (Settings > AI Providers)
5. **Create user accounts** for your team
6. **Set up automated backups** (see Backup section)

---

## Configuration

### Environment Variables

All configuration is managed through environment variables. Key variables:

#### Security (MUST CHANGE for production)

| Variable | Description | How to Generate |
|----------|-------------|-----------------|
| `ADMIN_PASSWORD` | Admin account password | Choose a strong password (16+ chars) |
| `JWT_SECRET_KEY` | JWT signing key | `openssl rand -hex 32` |
| `PLATFORM_JWT_SECRET` | Platform admin JWT key | `openssl rand -hex 32` |
| `POSTGRES_PASSWORD` | Database password | `openssl rand -base64 24` |
| `CREDENTIALS_ENCRYPTION_KEY` | Fernet key for credential vault | `python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"` |

#### SMTP Configuration

| Variable | Description | Example |
|----------|-------------|---------|
| `SMTP_HOST` | SMTP server hostname | `smtp.gmail.com` |
| `SMTP_PORT` | SMTP port | `587` |
| `SMTP_USERNAME` | SMTP login username | `admin@yourdomain.com` |
| `SMTP_PASSWORD` | SMTP password / app password | Google App Password |
| `SMTP_FROM_EMAIL` | Sender email address | `admin@yourdomain.com` |
| `SMTP_FROM_NAME` | Sender display name | `T1 Agentics` |
| `SMTP_USE_TLS` | Enable STARTTLS | `true` |

#### AI Provider

| Variable | Description | Example |
|----------|-------------|---------|
| `AI_PROVIDER` | AI backend type | `vllm`, or any supported provider key |
| `VLLM_URL` | vLLM server URL | `http://host.docker.internal:8001` |
| `VLLM_MODEL` | Default model name | `<your-model-identifier>` |
| `AI_API_KEY` | API key for hosted LLM providers (if used) | `sk-...` |

See your `.env.example` for the full list of supported provider keys.

---

## User Management

### Roles

| Role | Permissions |
|------|------------|
| **admin** | Full access - manage users, settings, all features |
| **analyst** | View and manage alerts, investigations, playbooks |
| **readonly** | View-only access to alerts and dashboards |

### Creating Users

**Via UI**: Settings > User Management > Create User

**Via API**:
```bash
curl -X POST https://your-server/api/v1/admin/users \
 -H "Content-Type: application/json" \
 -b "session_cookie" \
 -d '{
 "username": "john.doe",
 "email": "john@company.com",
 "password": "SecureP@ssw0rd123",
 "role": "analyst"
 }'
```

### Password Policy

Passwords must meet these requirements:
- Minimum 12 characters
- At least 1 uppercase letter (A-Z)
- At least 1 lowercase letter (a-z)
- At least 1 digit (0-9)
- At least 1 special character (!@#$%^&*...)

### Account Lockout

- **3 failed login attempts** triggers a 10-minute lockout
- To unlock manually (as admin):
 ```sql
 -- Connect to PostgreSQL
 docker exec -it t1agentics-postgres psql -U agentcore -d agentcore

 -- Unlock the user
 UPDATE users SET failed_login_attempts = 0, locked_until = NULL
 WHERE username = 'locked_user';
 ```

---

## AI Provider Setup

The platform supports any LLM inference endpoint that follows the common
chat-completions API shape, including self-hosted inference servers (vLLM,
LM Studio, Ollama, etc.) and hosted LLM APIs.

### Option 1: Self-hosted Inference (Recommended for Production)

A self-hosted inference server on a GPU host typically provides the lowest
per-token cost and keeps data on-premises.

```bash
# Example: start a self-hosted inference server on a GPU host
# (substitute your preferred inference server and model)

# Set in .env:
AI_PROVIDER=vllm
VLLM_URL=http://gpu-server:8001
VLLM_MODEL=<your-model-identifier>
```

### Option 2: Hosted LLM API

Point the platform at any hosted LLM API by configuring `AI_PROVIDER`, the API
base URL, and `AI_API_KEY` in your `.env` file.

### Option 3: Multiple Providers

Configure additional providers through the UI: Settings > AI Providers > Add Provider.

Any LLM endpoint exposing a standard chat-completions interface can be added,
including self-hosted inference servers and hosted LLM APIs.

---

## Email & Notifications

### Configuring SMTP

**Via Environment Variables** (recommended for production):
Set the `SMTP_*` variables in your `.env` file (see Configuration section above).

**Via UI**: Settings > Notifications > SMTP Configuration

After configuring, click **"Test Connection"** to verify.

### Gmail / Google Workspace Setup

1. Go to Google Account > Security > App Passwords
2. Generate a new app password for "Mail"
3. Use these settings:
- Host: `smtp.gmail.com`
- Port: `587`
- TLS: `true`
- Username: your full Gmail address
- Password: the generated app password

### Notification Rules

Create rules to automatically notify your team:

1. Navigate to Settings > Notifications > Rules
2. Click "Add Rule"
3. Configure:
- **Event Types**: alert_created, alert_escalated, investigation_closed, etc.
- **Severity Filter**: Only notify for critical/high alerts
- **Recipients**: Email addresses to notify
- **Channels**: Email, Slack, Teams, Webex, Discord

### Webhook Integration

For Slack, Teams, Webex, or Discord:
1. Settings > Notifications > Webhook Channels
2. Add a new channel with the webhook URL
3. Reference it in your notification rules

---

## Threat Feed Management

### Enabling Preconfigured Feeds

1. Navigate to Settings > Threat Feeds
2. Toggle feeds on/off with the enable switch
3. Available feeds include:
- AlienVault OTX
- Abuse.ch (URLhaus, MalwareBazaar, ThreatFox, Feodo Tracker)
- EmergingThreats
- Blocklist.de
- And more...

### Adding Custom Feeds

1. Settings > Threat Feeds > Add Custom Feed
2. Supported formats: STIX/TAXII, CSV, plain text (one IOC per line), JSON
3. Configure polling interval and authentication if needed

### Feed Limits by License

| License Tier | Max Feeds | Max IOCs | Overflow Policy |
|-------------|-----------|----------|-----------------|
| Community | 3 | 50,000 | Oldest removed (FIFO) |
| Trial/POC | 10 | 250,000 | Oldest removed (FIFO) |
| Professional | Unlimited | 500,000 | Oldest removed (FIFO), addon available |
| Enterprise | Unlimited | Unlimited | - |
| Enterprise Plus | Unlimited | Unlimited | - |

---

## License Management

### License Tiers

| Tier | Alerts/Day | Playbooks | Users | IOCs | AI Queries/Day |
|------|-----------|-----------|-------|------|---------------|
| **Community** | 50 | 5 | 3 | 50K | 25 |
| **Trial/POC** | 250 | 10 | 5 | 250K | 100 |
| **Professional** | 250 | 10 | 10 | 500K | 200 |
| **Enterprise** | 1,000 | 100 | 50 | Unlimited | 1,000 |
| **Enterprise Plus** | Unlimited | Unlimited | Unlimited | Unlimited | Unlimited |

### Activating a License

**Via UI**: Settings > License > Enter License Key

**Via API**:
```bash
curl -X POST https://your-server/api/v1/admin/license/activate \
 -H "Content-Type: application/json" \
 -b "session_cookie" \
 -d '{"license_key": "T1A-PRO-abc123-1234567890-abcdef"}'
```

---

## Security Hardening

### Production Checklist

- [ ] Change all default passwords (admin, database, JWT secrets)
- [ ] Enable HTTPS with valid TLS certificates
- [ ] Set `ALLOWED_ORIGINS` to your specific domain (not `*`)
- [ ] Enable MFA for all admin accounts
- [ ] Configure account lockout policy
- [ ] Set up automated backups
- [ ] Enable structured logging
- [ ] Configure firewall rules (only expose ports 80, 443)
- [ ] Set up health check monitoring
- [ ] Review and rotate credentials quarterly

### Firewall Rules (UFW)

```bash
# Allow only essential ports
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp # SSH
ufw allow 80/tcp # HTTP (redirects to HTTPS)
ufw allow 443/tcp # HTTPS
ufw allow 5514/tcp # Syslog ingestion (if needed)
ufw enable
```

### TLS Configuration

The production nginx config enforces:
- TLS 1.2 and 1.3 only
- Strong cipher suites
- HSTS with 1-year max-age
- X-Frame-Options, X-Content-Type-Options, CSP headers

---

## Backup & Recovery

### Automated Backups

Set up daily automated backups:

```bash
# Install the backup cron job
chmod +x scripts/setup-cron.sh
./scripts/setup-cron.sh
```

This installs:
- **Database backup**: Daily at 2 AM UTC (`scripts/backup-db.sh`)
- **Health checks**: Every 5 minutes (`scripts/healthcheck.sh`)
- **Docker cleanup**: Weekly on Sundays

### Manual Backup

```bash
# Backup the database
./scripts/backup-db.sh

# Backups are stored in /opt/t1agentics/backups/
ls -la /opt/t1agentics/backups/
```

### Restoring from Backup

```bash
# List available backups
ls /opt/t1agentics/backups/

# Restore a specific backup
./scripts/restore-db.sh /opt/t1agentics/backups/t1agentics_20260212_020000.sql.gz
```

### What's Backed Up

| Data | Method | Frequency |
|------|--------|-----------|
| PostgreSQL database | pg_dump + gzip | Daily |
| Configuration files | .env, docker-compose | Manual (version controlled) |
| SSL certificates | /opt/t1agentics/certs/ | Manual |
| Docker volumes | Database backup covers this | Daily |

---

## Monitoring & Health Checks

### Health Endpoint

The backend exposes a health check endpoint:

```bash
curl http://localhost:8000/api/v1/health
# Returns: {"status": "healthy", "services": {...}}

curl http://localhost:8000/api/v1/health/detailed
# Returns detailed status of all subsystems
```

### Automated Monitoring

The health check script (`scripts/healthcheck.sh`) checks:
- Backend API responsiveness
- PostgreSQL connectivity
- Disk space usage (alerts at 90%)
- Container running status

### Container Logs

```bash
# View backend logs
docker logs t1agentics-backend --tail 100 -f

# View all service logs
docker compose -f docker-compose.yml logs --tail 50

# View specific service
docker compose -f docker-compose.yml logs backend --tail 100
```

---

## Maintenance & Updates

### Updating the Platform

```bash
cd /opt/t1agentics

# Pull latest changes
git pull origin main

# Rebuild and restart
docker compose -f docker-compose.yml down
docker compose -f docker-compose.yml build --no-cache
docker compose -f docker-compose.yml up -d

# Clean up old images
docker system prune -f
```

### Database Migrations

New schema changes are applied automatically via `init-db.sql` on fresh installs. For existing databases, check the `backend/migrations/` directory:

```bash
# Apply a specific migration
docker exec -i t1agentics-postgres psql -U agentcore -d agentcore \
 < backend/migrations/add_mfa_columns.sql
```

### Credential Rotation

Rotate secrets periodically using the provided script:

```bash
./scripts/rotate-secrets.sh
```

This generates new values for:
- JWT secrets
- Database password
- Encryption keys

**Important**: After rotation, restart all services and update any stored credentials.

---

## Troubleshooting

### Service Won't Start

```bash
# Check container status
docker compose -f docker-compose.yml ps

# Check logs for errors
docker logs t1agentics-backend 2>&1 | tail -50

# Restart a specific service
docker compose -f docker-compose.yml restart backend
```

### Database Connection Issues

```bash
# Test PostgreSQL connectivity
docker exec t1agentics-postgres pg_isready -U agentcore -d agentcore

# Connect to database directly
docker exec -it t1agentics-postgres psql -U agentcore -d agentcore
```

### Login Issues

- **Locked account**: See Account Lockout section above
- **Corrupted password**: Reset via direct database update using Python bcrypt inside the container (do NOT use shell escaping with psql)

### AI Not Working

```bash
# Check if AI provider is reachable
curl http://localhost:8001/v1/models # For vLLM

# Check backend logs for AI errors
docker logs t1agentics-backend 2>&1 | grep -i "llm\|vllm\|ai_provider\|model"
```

### Memory Issues

```bash
# Check container resource usage
docker stats

# If PostgreSQL is using too much memory
docker compose -f docker-compose.yml restart postgres
```

---

*T1 Agentics - Autonomous Security Operations*
*Licensed under the Apache License, Version 2.0. See the root LICENSE file.*
