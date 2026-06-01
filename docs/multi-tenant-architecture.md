# T1 Agentics Multi-Tenant Architecture

## Overview

This document defines the multi-tenant architecture for T1 Agentics, enabling secure data isolation across customers while sharing infrastructure for cost efficiency.

---

## Tenancy Model

```

 T1 Agentics Platform 
 
 
 Shared Infrastructure 
 
 
 ALB ECS Redis S3 
 (shared) (shared) (shared) (shared) 
 
 
 
 
 
 
 PostgreSQL with Row-Level Security 
 
 
 Tenant A Tenant B Tenant C 
 (Acme Corp) (BigBank) (TechStart) 
 
 alerts alerts alerts 
 playbooks playbooks playbooks 
 users users users 
 integrations integrations integrations 
 
 
 Every row has tenant_id. RLS policies enforce isolation. 
 
 

```

---

## Core Principles

1. **Tenant ID Everywhere** - Every data row belongs to exactly one tenant
2. **Defense in Depth** - Multiple layers of isolation (app + database + storage)
3. **Fail Closed** - Missing tenant context = request denied
4. **Audit Everything** - Log all tenant context switches and access attempts
5. **No Cross-Tenant Queries** - Application code cannot bypass isolation

---

## Implementation Phases

### Phase 1: Database Schema & RLS (Foundation)
### Phase 2: Tenant Context Middleware
### Phase 3: Storage Isolation (S3)
### Phase 4: Tenant Management API
### Phase 5: Billing & Usage Tracking
### Phase 6: Tenant Onboarding Automation

---

## Phase 1: Database Schema & Row-Level Security

### 1.1 Tenants Table

```sql
-- Core tenant registry
CREATE TABLE tenants (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
 slug VARCHAR(50) UNIQUE NOT NULL, -- acme-corp, bigbank
 name VARCHAR(255) NOT NULL, -- Acme Corporation

 -- Plan & Limits
 plan VARCHAR(50) NOT NULL DEFAULT 'community', -- community, professional, enterprise
 license_key VARCHAR(255),

 -- Limits (override defaults if set)
 alerts_per_day_limit INTEGER,
 playbooks_limit INTEGER,
 integrations_limit INTEGER,
 users_limit INTEGER,
 retention_days INTEGER,

 -- Status
 status VARCHAR(20) NOT NULL DEFAULT 'active', -- active, suspended, cancelled
 suspended_at TIMESTAMP WITH TIME ZONE,
 suspended_reason TEXT,

 -- Billing
 stripe_customer_id VARCHAR(255),
 billing_email VARCHAR(255),

 -- Metadata
 settings JSONB DEFAULT '{}',
 created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
 updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

 -- Constraints
 CONSTRAINT valid_plan CHECK (plan IN ('community', 'professional', 'enterprise')),
 CONSTRAINT valid_status CHECK (status IN ('active', 'suspended', 'cancelled', 'pending'))
);

CREATE INDEX idx_tenants_slug ON tenants(slug);
CREATE INDEX idx_tenants_status ON tenants(status);
```

### 1.2 Add tenant_id to All Tables

```sql
-- Example: alerts table
ALTER TABLE alerts ADD COLUMN tenant_id UUID NOT NULL REFERENCES tenants(id);
CREATE INDEX idx_alerts_tenant_id ON alerts(tenant_id);

-- Apply to ALL tables that store customer data:
-- alerts, investigations, playbooks, playbook_executions, playbook_node_results,
-- users, integrations, integration_instances, credentials, iocs, threat_intel,
-- audit_logs, chat_messages, attachments, webhooks, edl_lists, etc.
```

### 1.3 Row-Level Security Policies

```sql
-- Enable RLS on all tenant-scoped tables
ALTER TABLE alerts ENABLE ROW LEVEL SECURITY;
ALTER TABLE investigations ENABLE ROW LEVEL SECURITY;
ALTER TABLE playbooks ENABLE ROW LEVEL SECURITY;
ALTER TABLE playbook_executions ENABLE ROW LEVEL SECURITY;
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE integrations ENABLE ROW LEVEL SECURITY;
ALTER TABLE credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;
-- ... all other tenant tables

-- Create RLS policy for each table
-- Uses current_setting('app.current_tenant_id') set by application

CREATE POLICY tenant_isolation_alerts ON alerts
 USING (tenant_id = current_setting('app.current_tenant_id')::uuid);

CREATE POLICY tenant_isolation_investigations ON investigations
 USING (tenant_id = current_setting('app.current_tenant_id')::uuid);

CREATE POLICY tenant_isolation_playbooks ON playbooks
 USING (tenant_id = current_setting('app.current_tenant_id')::uuid);

-- ... repeat for all tables

-- Admin bypass policy (for platform admins only)
CREATE POLICY admin_bypass_alerts ON alerts
 USING (current_setting('app.is_platform_admin', true)::boolean = true);
```

### 1.4 Migration Script

```python
# backend/migrations/add_multitenancy.py

TABLES_TO_UPDATE = [
 "alerts",
 "investigations",
 "investigation_findings",
 "playbooks",
 "playbook_executions",
 "playbook_node_results",
 "users",
 "user_sessions",
 "integration_instances",
 "credentials",
 "iocs",
 "audit_logs",
 "chat_messages",
 "chat_sessions",
 "attachments",
 "webhooks",
 "webhook_deliveries",
 "edl_lists",
 "edl_entries",
 "threat_feeds",
 "threat_feed_entries",
 "approval_requests",
 "notification_settings",
]

async def migrate():
 # 1. Create tenants table
 # 2. Create default tenant for existing data
 # 3. Add tenant_id column to all tables
 # 4. Backfill tenant_id with default tenant
 # 5. Make tenant_id NOT NULL
 # 6. Enable RLS on all tables
 # 7. Create RLS policies
```

---

## Phase 2: Tenant Context Middleware

### 2.1 Tenant Resolution Flow

```
Request → Extract Tenant → Validate → Set Context → Execute → Clear Context


 Tenant Resolution 
 
 1. JWT Token → tenant_id claim 
 2. API Key → lookup tenant from api_keys table 
 3. Subdomain → acme.t1agentics.com → tenant_id 
 4. Header → X-Tenant-ID (for internal services) 
 

```

### 2.2 Tenant Middleware Implementation

```python
# backend/middleware/tenant_middleware.py

from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from contextvars import ContextVar
from typing import Optional
import logging

logger = logging.getLogger(__name__)

# Context variable for current tenant (thread-safe)
current_tenant_id: ContextVar[Optional[str]] = ContextVar('current_tenant_id', default=None)
current_tenant: ContextVar[Optional[dict]] = ContextVar('current_tenant', default=None)

# Routes that don't require tenant context
TENANT_EXEMPT_ROUTES = {
 "/health",
 "/api/v1/admin/login",
 "/api/v1/license/status",
 "/docs",
 "/openapi.json",
 "/api/v1/platform/tenants", # Platform admin routes
}


class TenantMiddleware(BaseHTTPMiddleware):
 """
 Resolves tenant context from request and sets it for the request lifecycle.
 """

 async def dispatch(self, request: Request, call_next):
 path = request.url.path

 # Skip exempt routes
 if self._is_exempt(path):
 return await call_next(request)

 # Resolve tenant
 tenant_id, tenant = await self._resolve_tenant(request)

 if not tenant_id:
 return JSONResponse(
 status_code=401,
 content={"error": "tenant_required", "message": "Tenant context required"}
 )

 if not tenant:
 return JSONResponse(
 status_code=404,
 content={"error": "tenant_not_found", "message": "Tenant does not exist"}
 )

 if tenant.get("status") != "active":
 return JSONResponse(
 status_code=403,
 content={
 "error": "tenant_suspended",
 "message": f"Tenant is {tenant.get('status')}",
 "reason": tenant.get("suspended_reason")
 }
 )

 # Set context for this request
 current_tenant_id.set(tenant_id)
 current_tenant.set(tenant)

 # Store in request state for easy access
 request.state.tenant_id = tenant_id
 request.state.tenant = tenant

 try:
 response = await call_next(request)
 return response
 finally:
 # Clear context after request
 current_tenant_id.set(None)
 current_tenant.set(None)

 def _is_exempt(self, path: str) -> bool:
 for exempt in TENANT_EXEMPT_ROUTES:
 if path.startswith(exempt):
 return True
 return False

 async def _resolve_tenant(self, request: Request) -> tuple:
 """
 Resolve tenant from multiple sources in priority order.
 Returns (tenant_id, tenant_dict) or (None, None).
 """
 tenant_id = None

 # 1. From JWT claims (most common)
 auth_header = request.headers.get("Authorization", "")
 if auth_header.startswith("Bearer "):
 tenant_id = await self._tenant_from_jwt(auth_header[7:])

 # 2. From API key
 if not tenant_id:
 api_key = request.headers.get("X-API-Key")
 if api_key:
 tenant_id = await self._tenant_from_api_key(api_key)

 # 3. From subdomain (for web app)
 if not tenant_id:
 host = request.headers.get("Host", "")
 tenant_id = await self._tenant_from_subdomain(host)

 # 4. From header (internal services)
 if not tenant_id:
 tenant_id = request.headers.get("X-Tenant-ID")

 if not tenant_id:
 return None, None

 # Load tenant details
 tenant = await self._load_tenant(tenant_id)
 return tenant_id, tenant

 async def _tenant_from_jwt(self, token: str) -> Optional[str]:
 try:
 import jwt
 from services.auth import SECRET_KEY, ALGORITHM
 payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
 return payload.get("tenant_id")
 except:
 return None

 async def _tenant_from_api_key(self, api_key: str) -> Optional[str]:
 from services.postgres_db import postgres_db
 if not postgres_db.connected:
 return None
 async with postgres_db.pool.acquire() as conn:
 row = await conn.fetchrow(
 "SELECT tenant_id FROM api_keys WHERE key_hash = $1 AND revoked = false",
 hash_api_key(api_key)
 )
 return str(row["tenant_id"]) if row else None

 async def _tenant_from_subdomain(self, host: str) -> Optional[str]:
 # acme.t1agentics.com → acme
 if ".t1agentics.com" in host:
 subdomain = host.split(".")[0]
 if subdomain not in ("www", "app", "api"):
 from services.postgres_db import postgres_db
 if postgres_db.connected:
 async with postgres_db.pool.acquire() as conn:
 row = await conn.fetchrow(
 "SELECT id FROM tenants WHERE slug = $1",
 subdomain
 )
 return str(row["id"]) if row else None
 return None

 async def _load_tenant(self, tenant_id: str) -> Optional[dict]:
 from services.postgres_db import postgres_db
 if not postgres_db.connected:
 return None
 async with postgres_db.pool.acquire() as conn:
 row = await conn.fetchrow(
 "SELECT * FROM tenants WHERE id = $1",
 tenant_id
 )
 return dict(row) if row else None


def get_current_tenant_id() -> str:
 """Get current tenant ID. Raises if not set."""
 tenant_id = current_tenant_id.get()
 if not tenant_id:
 raise RuntimeError("No tenant context. Ensure TenantMiddleware is active.")
 return tenant_id


def get_current_tenant() -> dict:
 """Get current tenant details. Raises if not set."""
 tenant = current_tenant.get()
 if not tenant:
 raise RuntimeError("No tenant context. Ensure TenantMiddleware is active.")
 return tenant
```

### 2.3 Database Connection with Tenant Context

```python
# backend/services/tenant_db.py

from contextlib import asynccontextmanager
from services.postgres_db import postgres_db
from middleware.tenant_middleware import get_current_tenant_id

@asynccontextmanager
async def tenant_connection():
 """
 Get a database connection with tenant context set.
 All queries through this connection are automatically filtered by tenant.
 """
 tenant_id = get_current_tenant_id()

 async with postgres_db.pool.acquire() as conn:
 # Set tenant context for RLS
 await conn.execute(
 "SET app.current_tenant_id = $1",
 str(tenant_id)
 )

 try:
 yield conn
 finally:
 # Clear tenant context
 await conn.execute("RESET app.current_tenant_id")


# Usage in routes/services:
async def get_alerts(limit: int = 100):
 async with tenant_connection() as conn:
 # RLS automatically filters by tenant_id
 rows = await conn.fetch(
 "SELECT * FROM alerts ORDER BY created_at DESC LIMIT $1",
 limit
 )
 return [dict(row) for row in rows]
```

---

## Phase 3: Storage Isolation (S3)

### 3.1 S3 Bucket Structure

```
s3://t1a-attachments-prod/
 tenants/
 {tenant_id_1}/
 attachments/
 {alert_id}/{filename}
 ...
 exports/
 {export_id}.json
 ...
 evidence/
 ...
 {tenant_id_2}/
 ...
 ...
 platform/ (shared assets, not tenant-specific)
 integration-logos/
 templates/
```

### 3.2 Tenant-Scoped Storage Service

```python
# backend/services/tenant_storage.py

import boto3
from middleware.tenant_middleware import get_current_tenant_id

class TenantStorage:
 def __init__(self, bucket: str):
 self.bucket = bucket
 self.s3 = boto3.client('s3')

 def _tenant_prefix(self) -> str:
 tenant_id = get_current_tenant_id()
 return f"tenants/{tenant_id}"

 async def upload_file(self, key: str, data: bytes, content_type: str = None) -> str:
 """Upload file to tenant's namespace."""
 full_key = f"{self._tenant_prefix()}/{key}"

 extra_args = {}
 if content_type:
 extra_args['ContentType'] = content_type

 self.s3.put_object(
 Bucket=self.bucket,
 Key=full_key,
 Body=data,
 **extra_args
 )

 return full_key

 async def get_file(self, key: str) -> bytes:
 """Get file from tenant's namespace."""
 full_key = f"{self._tenant_prefix()}/{key}"

 response = self.s3.get_object(Bucket=self.bucket, Key=full_key)
 return response['Body'].read()

 async def delete_file(self, key: str):
 """Delete file from tenant's namespace."""
 full_key = f"{self._tenant_prefix()}/{key}"
 self.s3.delete_object(Bucket=self.bucket, Key=full_key)

 async def list_files(self, prefix: str = "") -> list:
 """List files in tenant's namespace."""
 full_prefix = f"{self._tenant_prefix()}/{prefix}"

 response = self.s3.list_objects_v2(
 Bucket=self.bucket,
 Prefix=full_prefix
 )

 # Strip tenant prefix from returned keys
 tenant_prefix = self._tenant_prefix()
 return [
 obj['Key'].replace(f"{tenant_prefix}/", "", 1)
 for obj in response.get('Contents', [])
 ]

 def get_presigned_url(self, key: str, expires_in: int = 3600) -> str:
 """Get presigned URL for direct download."""
 full_key = f"{self._tenant_prefix()}/{key}"

 return self.s3.generate_presigned_url(
 'get_object',
 Params={'Bucket': self.bucket, 'Key': full_key},
 ExpiresIn=expires_in
 )
```

---

## Phase 4: Tenant Management API

### 4.1 Platform Admin Routes

```python
# backend/routes/platform_admin.py

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, EmailStr
from typing import Optional, List
from services.tenant_service import TenantService

router = APIRouter(prefix="/api/v1/platform/tenants", tags=["platform-admin"])


class CreateTenantRequest(BaseModel):
 slug: str
 name: str
 plan: str = "community"
 billing_email: EmailStr
 admin_email: EmailStr
 admin_name: str


class UpdateTenantRequest(BaseModel):
 name: Optional[str]
 plan: Optional[str]
 status: Optional[str]
 alerts_per_day_limit: Optional[int]
 playbooks_limit: Optional[int]
 users_limit: Optional[int]


@router.post("/")
async def create_tenant(
 request: CreateTenantRequest,
 admin: dict = Depends(require_platform_admin)
):
 """Create a new tenant with initial admin user."""
 service = TenantService()
 tenant = await service.create_tenant(
 slug=request.slug,
 name=request.name,
 plan=request.plan,
 billing_email=request.billing_email,
 admin_email=request.admin_email,
 admin_name=request.admin_name
 )
 return tenant


@router.get("/")
async def list_tenants(
 status: Optional[str] = None,
 plan: Optional[str] = None,
 admin: dict = Depends(require_platform_admin)
):
 """List all tenants."""
 service = TenantService()
 return await service.list_tenants(status=status, plan=plan)


@router.get("/{tenant_id}")
async def get_tenant(
 tenant_id: str,
 admin: dict = Depends(require_platform_admin)
):
 """Get tenant details."""
 service = TenantService()
 tenant = await service.get_tenant(tenant_id)
 if not tenant:
 raise HTTPException(status_code=404, detail="Tenant not found")
 return tenant


@router.patch("/{tenant_id}")
async def update_tenant(
 tenant_id: str,
 request: UpdateTenantRequest,
 admin: dict = Depends(require_platform_admin)
):
 """Update tenant settings."""
 service = TenantService()
 return await service.update_tenant(tenant_id, request.dict(exclude_unset=True))


@router.post("/{tenant_id}/suspend")
async def suspend_tenant(
 tenant_id: str,
 reason: str,
 admin: dict = Depends(require_platform_admin)
):
 """Suspend a tenant."""
 service = TenantService()
 return await service.suspend_tenant(tenant_id, reason)


@router.post("/{tenant_id}/reactivate")
async def reactivate_tenant(
 tenant_id: str,
 admin: dict = Depends(require_platform_admin)
):
 """Reactivate a suspended tenant."""
 service = TenantService()
 return await service.reactivate_tenant(tenant_id)


@router.delete("/{tenant_id}")
async def delete_tenant(
 tenant_id: str,
 confirm: bool = False,
 admin: dict = Depends(require_platform_admin)
):
 """Delete a tenant and all their data. Requires confirm=true."""
 if not confirm:
 raise HTTPException(
 status_code=400,
 detail="Must confirm deletion with confirm=true"
 )
 service = TenantService()
 return await service.delete_tenant(tenant_id)


@router.get("/{tenant_id}/usage")
async def get_tenant_usage(
 tenant_id: str,
 admin: dict = Depends(require_platform_admin)
):
 """Get tenant usage statistics."""
 service = TenantService()
 return await service.get_tenant_usage(tenant_id)
```

### 4.2 Tenant Service

```python
# backend/services/tenant_service.py

class TenantService:
 """Manages tenant lifecycle and operations."""

 async def create_tenant(
 self,
 slug: str,
 name: str,
 plan: str,
 billing_email: str,
 admin_email: str,
 admin_name: str
 ) -> dict:
 """
 Create a new tenant with:
 1. Tenant record
 2. Initial admin user
 3. Default integrations
 4. Welcome email
 """
 async with postgres_db.pool.acquire() as conn:
 async with conn.transaction():
 # Create tenant
 tenant = await conn.fetchrow("""
 INSERT INTO tenants (slug, name, plan, billing_email, status)
 VALUES ($1, $2, $3, $4, 'active')
 RETURNING *
 """, slug, name, plan, billing_email)

 tenant_id = tenant['id']

 # Create admin user
 from services.auth import hash_password
 temp_password = generate_temp_password()

 await conn.execute("""
 INSERT INTO users (tenant_id, email, name, password_hash, role)
 VALUES ($1, $2, $3, $4, 'admin')
 """, tenant_id, admin_email, admin_name, hash_password(temp_password))

 # Create default webhook for alert ingestion
 webhook_token = generate_webhook_token()
 await conn.execute("""
 INSERT INTO webhooks (tenant_id, name, token, enabled)
 VALUES ($1, 'Default Ingest Webhook', $2, true)
 """, tenant_id, webhook_token)

 # Send welcome email
 await send_welcome_email(
 email=admin_email,
 name=admin_name,
 tenant_name=name,
 temp_password=temp_password,
 webhook_token=webhook_token
 )

 return {
 "tenant": dict(tenant),
 "admin_email": admin_email,
 "webhook_url": f"https://api.t1agentics.com/webhook/{webhook_token}"
 }

 async def get_tenant_usage(self, tenant_id: str) -> dict:
 """Get comprehensive usage stats for a tenant."""
 async with postgres_db.pool.acquire() as conn:
 # Temporarily set tenant context for RLS
 await conn.execute("SET app.current_tenant_id = $1", tenant_id)

 stats = {}

 # Alert counts
 stats['alerts'] = await conn.fetchrow("""
 SELECT
 COUNT(*) as total,
 COUNT(*) FILTER (WHERE created_at > NOW() - INTERVAL '1 day') as today,
 COUNT(*) FILTER (WHERE created_at > NOW() - INTERVAL '30 days') as last_30_days
 FROM alerts
 """)

 # Other counts
 stats['playbooks'] = await conn.fetchval("SELECT COUNT(*) FROM playbooks")
 stats['playbook_executions'] = await conn.fetchval(
 "SELECT COUNT(*) FROM playbook_executions WHERE started_at > NOW() - INTERVAL '30 days'"
 )
 stats['users'] = await conn.fetchval("SELECT COUNT(*) FROM users")
 stats['integrations'] = await conn.fetchval(
 "SELECT COUNT(*) FROM integration_instances WHERE enabled = true"
 )

 # Storage (S3)
 stats['storage_mb'] = await self._get_s3_usage(tenant_id)

 await conn.execute("RESET app.current_tenant_id")

 return stats
```

---

## Phase 5: Billing & Usage Tracking

### 5.1 Usage Events

```python
# backend/services/usage_tracking.py

from enum import Enum
from datetime import datetime, timezone

class UsageEventType(Enum):
 ALERT_INGESTED = "alert_ingested"
 PLAYBOOK_EXECUTED = "playbook_executed"
 AI_QUERY = "ai_query"
 ENRICHMENT_CALL = "enrichment_call"
 INTEGRATION_CALL = "integration_call"
 STORAGE_UPLOAD = "storage_upload"


class UsageTracker:
 """Tracks billable usage per tenant."""

 async def record_event(
 self,
 tenant_id: str,
 event_type: UsageEventType,
 quantity: int = 1,
 metadata: dict = None
 ):
 """Record a usage event for billing."""
 async with postgres_db.pool.acquire() as conn:
 await conn.execute("""
 INSERT INTO usage_events
 (tenant_id, event_type, quantity, metadata, recorded_at)
 VALUES ($1, $2, $3, $4, $5)
 """, tenant_id, event_type.value, quantity, metadata, datetime.now(timezone.utc))

 async def get_usage_summary(
 self,
 tenant_id: str,
 start_date: datetime,
 end_date: datetime
 ) -> dict:
 """Get usage summary for billing period."""
 async with postgres_db.pool.acquire() as conn:
 rows = await conn.fetch("""
 SELECT
 event_type,
 SUM(quantity) as total,
 COUNT(*) as event_count
 FROM usage_events
 WHERE tenant_id = $1
 AND recorded_at >= $2
 AND recorded_at < $3
 GROUP BY event_type
 """, tenant_id, start_date, end_date)

 return {row['event_type']: row['total'] for row in rows}

 async def check_limit(
 self,
 tenant_id: str,
 event_type: UsageEventType
 ) -> tuple[bool, str]:
 """Check if tenant has exceeded their limit."""
 tenant = await self._get_tenant(tenant_id)

 # Get today's usage
 today_start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0)
 usage = await self.get_usage_summary(tenant_id, today_start, datetime.now(timezone.utc))

 current = usage.get(event_type.value, 0)

 # Get limit based on plan
 limits = PLAN_LIMITS[tenant['plan']]
 limit = limits.get(event_type.value, -1)

 if limit == -1: # Unlimited
 return True, "OK"

 if current >= limit:
 return False, f"Daily limit of {limit} {event_type.value} exceeded"

 return True, "OK"
```

### 5.2 Usage Events Table

```sql
CREATE TABLE usage_events (
 id BIGSERIAL PRIMARY KEY,
 tenant_id UUID NOT NULL REFERENCES tenants(id),
 event_type VARCHAR(50) NOT NULL,
 quantity INTEGER NOT NULL DEFAULT 1,
 metadata JSONB,
 recorded_at TIMESTAMP WITH TIME ZONE NOT NULL,

 -- Partition by month for efficient queries
 created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
) PARTITION BY RANGE (recorded_at);

-- Create monthly partitions
CREATE TABLE usage_events_2024_01 PARTITION OF usage_events
 FOR VALUES FROM ('2024-01-01') TO ('2024-02-01');
-- ... create partitions for each month

CREATE INDEX idx_usage_events_tenant_type ON usage_events(tenant_id, event_type, recorded_at);
```

---

## Phase 6: Tenant Onboarding Automation

### 6.1 Self-Service Signup Flow

```
1. User visits t1agentics.com/signup
2. Enters: email, company name, desired subdomain
3. System creates:
- Tenant record (status: pending)
- Admin user (unverified)
- Sends verification email
4. User verifies email
5. System activates tenant:
- Status → active
- Creates default webhook
- Creates sample playbook
- Sends onboarding email with:
- Dashboard URL: {subdomain}.t1agentics.com
- Webhook URL for alert ingestion
- Getting started guide
```

### 6.2 Onboarding API

```python
# backend/routes/onboarding.py

@router.post("/signup")
async def signup(request: SignupRequest):
 """Self-service tenant signup."""
 service = OnboardingService()

 # Validate subdomain availability
 if await service.subdomain_taken(request.subdomain):
 raise HTTPException(400, "Subdomain not available")

 # Create pending tenant
 tenant = await service.create_pending_tenant(
 subdomain=request.subdomain,
 company_name=request.company_name,
 admin_email=request.email,
 admin_name=request.name
 )

 # Send verification email
 await service.send_verification_email(tenant['id'], request.email)

 return {"message": "Verification email sent", "tenant_id": tenant['id']}


@router.post("/verify/{token}")
async def verify_email(token: str):
 """Verify email and activate tenant."""
 service = OnboardingService()

 tenant = await service.verify_and_activate(token)

 return {
 "message": "Account activated",
 "dashboard_url": f"https://{tenant['slug']}.t1agentics.com",
 "webhook_url": tenant['webhook_url']
 }
```

---

## Security Checklist

### Database Level
- [ ] RLS enabled on all tenant tables
- [ ] RLS policies tested (can't read other tenant's data)
- [ ] Admin bypass policy restricted to platform admins
- [ ] tenant_id NOT NULL on all tables
- [ ] Foreign key to tenants table on all tables

### Application Level
- [ ] TenantMiddleware on all routes
- [ ] tenant_id in JWT claims
- [ ] API key → tenant lookup
- [ ] No raw SQL without tenant_connection()
- [ ] Request logging includes tenant_id

### Storage Level
- [ ] S3 keys prefixed with tenant_id
- [ ] Presigned URLs include tenant validation
- [ ] No cross-tenant file access possible

### Audit Level
- [ ] All tenant access logged
- [ ] Cross-tenant attempts logged as security events
- [ ] Tenant creation/suspension logged
- [ ] Admin actions logged with actor

---

## Testing Multi-Tenancy

### Test Cases

```python
# tests/test_multitenancy.py

async def test_tenant_isolation():
 """Verify tenant A cannot see tenant B's data."""
 # Create two tenants
 tenant_a = await create_test_tenant("tenant-a")
 tenant_b = await create_test_tenant("tenant-b")

 # Create alert in tenant A
 async with tenant_context(tenant_a):
 alert_a = await create_alert(title="Tenant A Alert")

 # Verify tenant B cannot see it
 async with tenant_context(tenant_b):
 alerts = await get_alerts()
 assert alert_a['id'] not in [a['id'] for a in alerts]


async def test_rls_enforcement():
 """Verify RLS blocks direct SQL bypass attempts."""
 tenant_a = await create_test_tenant("tenant-a")

 # Try to query without setting tenant context
 async with postgres_db.pool.acquire() as conn:
 # Should return 0 rows due to RLS
 rows = await conn.fetch("SELECT * FROM alerts")
 assert len(rows) == 0


async def test_missing_tenant_rejected():
 """Verify requests without tenant context are rejected."""
 response = await client.get(
 "/api/v1/alerts",
 headers={"Authorization": "Bearer <token-without-tenant>"}
 )
 assert response.status_code == 401
 assert response.json()["error"] == "tenant_required"
```

---

## Implementation Order

```
Week 1: Database Schema
 Create tenants table
 Add tenant_id to all tables
 Backfill existing data
 Enable RLS policies

Week 2: Middleware & Context
 TenantMiddleware
 tenant_connection() helper
 Update all database calls
 JWT tenant claims

Week 3: Storage & APIs
 S3 tenant prefixing
 Platform admin routes
 Tenant CRUD operations
 Usage tracking

Week 4: Onboarding & Testing
 Self-service signup
 Email verification
 Integration tests
 Security audit
```
