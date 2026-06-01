# T1 Agentics - Security Architecture

**Security is embedded in the platform fabric, not bolted on.**

This document outlines security best practices, hardening guidelines, and compliance features built into T1 Agentics.

---

## Security Principles

1. **Defense in Depth** - Multiple security layers (auth, RBAC, encryption, audit)
2. **Least Privilege** - Users/agents only get minimum required permissions
3. **Audit Everything** - Immutable action logs for compliance
4. **Encrypt Sensitive Data** - API keys, credentials, PII protection
5. **Secure by Default** - Production-ready security out of the box

---

## Authentication & Authorization

### JWT Token Security

**Implementation:** [backend/services/auth.py](backend/services/auth.py)

```python
# Token expiration
JWT_EXPIRE_MINUTES = 1440 # 24 hours (configurable)

# Strong secret key (MUST change in production)
JWT_SECRET_KEY = env("JWT_SECRET_KEY") # Set via .env file

# Token rotation
- Refresh tokens supported
- Automatic expiration
- Session invalidation on logout
```

**Best Practices:**
- Never hardcode JWT secret
- Use strong random key (32+ characters)
- Rotate keys periodically (quarterly)
- Short expiration for high-privilege accounts

### Role-Based Access Control (RBAC)

**Roles:** [backend/middleware/auth_middleware.py](backend/middleware/auth_middleware.py)

| Role | Permissions |
|------|-------------|
| **admin** | Full access: manage users, agents, integrations, settings |
| **analyst** | Investigate alerts, create investigations, run triage |
| **read_only** | View-only: alerts, investigations, dashboards |

**Permission Matrix:**
```python
# Example: Require admin role
@require_role(["admin"])
async def delete_integration():
 pass

# Example: Allow analyst or admin
@require_role(["admin", "analyst"])
async def create_investigation():
 pass
```

**Agent Authority Levels:**
```
OBSERVE - Read-only (no external calls)
INVESTIGATE - Query integrations (VirusTotal, Shodan)
RESPOND - Execute low-risk actions (isolate endpoint)
PRE_APPROVED - Execute pre-approved playbooks only
```

### Multi-Factor Authentication (MFA)

**Status:** Planned
**Priority:** High (production requirement)

Roadmap:
- TOTP (Time-based One-Time Password)
- SMS backup codes
- Hardware key support (FIDO2)

---

## Data Protection

### Encryption at Rest

**Credentials Vault:** [backend/services/credentials_service.py](backend/services/credentials_service.py)

```python
# All API keys/tokens encrypted with Fernet
CREDENTIALS_ENCRYPTION_KEY = env("CREDENTIALS_ENCRYPTION_KEY")

# Key requirements:
- 32 bytes base64-encoded
- Unique per environment
- Never in source control
- Rotated annually
```

**Generate encryption key:**
```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

**Database Encryption:**
- PostgreSQL supports TLS connections
- Enable `sslmode=require` in production
- Consider PostgreSQL Transparent Data Encryption (TDE)

### PII Obfuscation

**Implementation:** [backend/services/pii_obfuscation.py](backend/services/pii_obfuscation.py)

Automatically masks sensitive data:
- Credit card numbers → `**** **** **** 1234`
- Social Security Numbers → `***-**-1234`
- Email addresses → `u***@domain.com`
- API keys → `sk_live_***abc`

**Configurable patterns:**
```python
# Add custom PII patterns
await pii_service.add_pattern(
 name="Employee ID",
 regex=r"EMP-\d{6}",
 replacement="EMP-***"
)
```

### Encryption in Transit

**TLS/SSL Configuration:**

```yaml
# docker-compose.yml (production)
services:
 backend:
 environment:
- SSL_CERT_FILE=/certs/server.crt
- SSL_KEY_FILE=/certs/server.key
```

**Enforce HTTPS:**
```python
# backend/middleware/security_headers.py
app.add_middleware(HTTPSRedirectMiddleware)
```

---

## Network Security

### Security Headers

**Implementation:** [backend/middleware/security_headers.py](backend/middleware/security_headers.py)

```python
# Automatically added to all responses
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Strict-Transport-Security: max-age=31536000; includeSubDomains
Content-Security-Policy: default-src 'self'
```

### Rate Limiting

**Implementation:** [backend/middleware/rate_limiter.py](backend/middleware/rate_limiter.py)

```python
# Per-endpoint limits
@router.post("/login")
@rate_limit(max_requests=5, window_seconds=60) # 5 attempts/min
async def login():
 pass

# Global API limit
@rate_limit(max_requests=1000, window_seconds=60) # 1000 req/min
```

**Account Lockout:**
```python
# After 5 failed login attempts
- Account locked for 15 minutes
- Admin notification sent
- Audit log entry created
```

### CORS Policy

**Configuration:** [backend/app.py](backend/app.py)

```python
# Only allow frontend origin
ALLOWED_ORIGINS = [
 "http://localhost:3000",
 "https://t1agentics.company.com"
]

# No wildcards in production
```

---

## Audit & Compliance

### Immutable Action Log

**Table:** `agent_action_log`
**Purpose:** Immutable audit trail for all agent actions

```sql
CREATE TABLE agent_action_log (
 id SERIAL PRIMARY KEY,
 timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 agent_id TEXT NOT NULL,
 action_type TEXT NOT NULL,
 target TEXT,
 success BOOLEAN,
 metadata JSONB,
 user_id INT, -- Human who triggered action
 -- No UPDATE or DELETE allowed
);

-- Prevent modifications
REVOKE UPDATE, DELETE ON agent_action_log FROM all;
```

**Query examples:**
```sql
-- All actions by specific agent
SELECT * FROM agent_action_log WHERE agent_id = 'riggs' ORDER BY timestamp DESC;

-- Failed actions requiring review
SELECT * FROM agent_action_log WHERE success = false;

-- Actions in specific time range
SELECT * FROM agent_action_log WHERE timestamp BETWEEN '2024-01-01' AND '2024-01-31';
```

### Audit Logs UI

**Component:** [frontend/src/components/AuditLogs.js](frontend/src/components/AuditLogs.js)

Features:
- Real-time log streaming
- Advanced filtering (user, action, date)
- Export to CSV/JSON
- Search with highlighting

### Compliance Features

**SOC 2 Type II:**
- Audit logging (all actions)
- Access controls (RBAC)
- Encryption (at rest, in transit)
- Change management (git-based)
- MFA (planned)

**PCI-DSS:**
- PII obfuscation
- Encryption keys rotated
- Access logs retained
- Network segmentation

**HIPAA:**
- Audit trail (immutable)
- Data encryption
- Access controls
- BAA support (planned)

---

## Integration Security

### API Key Storage

**Never store keys in:**
- Source code
- Environment variables (logged)
- Database plaintext

**Always use:**
- Credentials vault (encrypted)
- Secret management service (AWS Secrets Manager, HashiCorp Vault)
- Environment-specific .env files (not in git)

### Circuit Breaker

**Implementation:** [backend/integrations/policies/circuit_breaker.py](backend/integrations/policies/circuit_breaker.py)

Prevents cascading failures:
```python
# After 5 failures in 60s
- Circuit opens (blocks requests)
- Returns cached data or error
- Auto-retry after cooldown (60s)
```

### OAuth2 Token Refresh

**Support:** API keys, OAuth2, SAML

```python
# Automatic token refresh
if token_expires_in < 300: # 5 minutes
 token = await refresh_oauth_token()
```

---

## Agent Security

### Guardrails

**Implementation:** [backend/reasoning_engine/tool_broker.py](backend/reasoning_engine/tool_broker.py)

```python
# Authority-based tool access
OBSERVE: read_ioc, search_logs
INVESTIGATE: query_virustotal, enrich_ip
RESPOND: isolate_endpoint # Requires approval
PRE_APPROVED: block_ip # From approved list only
```

### Action Approval Workflow

**High-risk actions require human approval:**
- Isolate endpoint
- Block network traffic
- Disable user account
- Delete data

**Approval flow:**
```
Agent recommends action → Creates approval request → Analyst reviews → Approve/Reject
```

**Timeout:**
- Pending approvals expire after 1 hour
- Auto-reject if no response

### Confidence Thresholds

**Stall detection:** [backend/reasoning_engine/confidence_gate.py](backend/reasoning_engine/confidence_gate.py)

```python
# Require high confidence for auto-actions
if confidence < 0.85:
 escalate_to_human()

# Multiple low-confidence cycles = stall
if consecutive_low_confidence >= 3:
 escalate_to_human("Agent stalled, needs help")
```

---

## Secrets Management

### Environment Variables

**Required secrets (.env file):**
```bash
# Authentication
JWT_SECRET_KEY=<32+ char random string>

# Database
POSTGRES_PASSWORD=<strong password>

# Encryption
CREDENTIALS_ENCRYPTION_KEY=<Fernet key>

# Admin Account
ADMIN_PASSWORD=<strong password> # No default!

# Integrations (optional)
VIRUSTOTAL_API_KEY=<key>
SHODAN_API_KEY=<key>
CROWDSTRIKE_CLIENT_ID=<id>
CROWDSTRIKE_CLIENT_SECRET=<secret>
```

**Never commit .env to git:**
```bash
# .gitignore
.env
.env.*
*.key
*.pem
```

### Production Secrets

**Recommended: External secret manager**

```python
# AWS Secrets Manager
import boto3
secrets = boto3.client('secretsmanager')
jwt_key = secrets.get_secret_value(SecretId='t1agentics/jwt-key')

# HashiCorp Vault
import hvac
vault = hvac.Client(url='https://vault.company.com')
jwt_key = vault.secrets.kv.v2.read_secret_version(path='t1agentics/jwt-key')
```

---

## Security Checklist

### Pre-Production

- [ ] Change all default passwords
- [ ] Generate unique JWT secret key
- [ ] Generate encryption key for credentials vault
- [ ] Enable TLS/SSL (HTTPS only)
- [ ] Configure CORS (no wildcards)
- [ ] Enable rate limiting
- [ ] Configure backup encryption
- [ ] Set up secret manager (not .env file)
- [ ] Review audit log retention policy
- [ ] Enable database connection encryption
- [ ] Configure firewall rules
- [ ] Set up monitoring/alerting
- [ ] Run vulnerability scan
- [ ] Perform security review
- [ ] Document incident response plan

### Monthly

- [ ] Review audit logs
- [ ] Check for failed login attempts
- [ ] Update dependencies (patch security issues)
- [ ] Rotate API keys (if policy requires)
- [ ] Review user access (remove inactive accounts)

### Quarterly

- [ ] Rotate JWT secret key
- [ ] Update encryption keys
- [ ] Run penetration test
- [ ] Review RBAC permissions
- [ ] Audit integration credentials

### Annually

- [ ] Full security audit
- [ ] External penetration test
- [ ] Compliance certification (SOC 2)
- [ ] Disaster recovery drill
- [ ] Incident response tabletop exercise

---

**Last Updated:** 2026-01-12
**Version:** 1.0
