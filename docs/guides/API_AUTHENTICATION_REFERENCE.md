# API Authentication Reference

## Overview

T1 Agentics uses JWT (JSON Web Token) based authentication for all API endpoints. This document describes the authentication flow, role-based access control, and endpoint protection requirements.

## Authentication Flow

```
 POST /api/v1/auth/login 
 Client > Backend 
 {username, password} 
 < 
 {access_token, token_type} 
 
 GET /api/v1/protected 
 Authorization: Bearer <token> 
 > 
 < 
 {data...} 
 
```

## JWT Token Structure

```json
{
 "sub": "username",
 "user_id": "uuid",
 "role": "admin|analyst|viewer",
 "exp": 1736553600,
 "iat": 1736467200
}
```

## Roles and Permissions

| Role | Description | Permissions |
|------|-------------|-------------|
| `admin` | System administrator | Full access to all endpoints |
| `analyst` | Security analyst | Read/write cases, alerts, chat |
| `viewer` | Read-only user | Read-only access to dashboards |

## Authentication Dependencies

### `get_current_user`

Validates the JWT token and returns user information.

```python
from dependencies.auth import get_current_user

@router.get("/endpoint")
async def handler(current_user: dict = Depends(get_current_user)):
 username = current_user.get("username")
 role = current_user.get("role")
 user_id = current_user.get("user_id")
```

**Returns**: `{"username": str, "role": str, "user_id": str}`

**Raises**: `HTTPException(401)` if token is missing or invalid

### `require_admin`

Ensures the authenticated user has admin role.

```python
from dependencies.auth import require_admin

@router.post("/admin-endpoint")
async def admin_handler(admin_user: str = Depends(require_admin)):
 # admin_user is the username
```

**Returns**: `str` (username)

**Raises**: `HTTPException(403)` if user is not admin

## Endpoint Protection Matrix

### Public Endpoints (No Auth Required)

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/v1/auth/login` | POST | User login |
| `/api/v1/auth/register` | POST | New user registration |
| `/api/v1/health` | GET | Health check |
| `/docs` | GET | API documentation |

### Standard Authenticated Endpoints

These require a valid JWT token (`get_current_user`):

| Route File | Endpoints |
|------------|-----------|
| `alerts.py` | All alert CRUD operations |
| `cases.py` | All case CRUD operations |
| `chat.py` | Chat sessions, messages |
| `knowledge_base.py` | KB articles CRUD |
| `token_usage.py` | View usage statistics |
| `work_queue.py` | View/claim work items |
| `telemetry.py` | View telemetry data |
| `notifications.py` | User notifications |

### Admin-Only Endpoints

These require admin role (`require_admin`):

| Route File | Endpoint | Purpose |
|------------|----------|---------|
| `admin.py` | `GET /users` | List all users |
| `admin.py` | `POST /users` | Create user |
| `admin.py` | `PUT /users/{id}` | Update user |
| `admin.py` | `DELETE /users/{id}` | Delete user |
| `admin.py` | `POST /users/{id}/reset-password` | Reset password |
| `admin.py` | `GET /scripts` | List scripts |
| `admin.py` | `POST /scripts` | Create script |
| `admin.py` | `DELETE /scripts/{id}` | Delete script |
| `admin.py` | `POST /python/install_package` | Install package |
| `admin.py` | `DELETE /python/uninstall_package` | Uninstall package |
| `agents.py` | `POST /ops/emergency-stop` | Emergency stop |
| `agents.py` | `POST /ops/emergency-resume` | Resume agents |
| `agents.py` | `POST /ops/scheduler/start` | Start scheduler |
| `agents.py` | `POST /ops/scheduler/stop` | Stop scheduler |
| `discovery.py` | `POST /import` | Import discovered API |
| `discovery.py` | `DELETE /{id}` | Delete discovery |
| `chat.py` | `GET /analytics/summary` | System analytics |
| `chat.py` | `GET /analytics/users` | All user stats |
| `token_usage.py` | `DELETE /reset` | Reset usage data |
| `work_queue.py` | `POST /auto-assign` | Auto-assign work |

### Self-Service with Admin Override

Users can access their own data, admins can access anyone's:

```python
@router.get("/analytics/users/{user_id}")
async def get_user_statistics(
 user_id: str,
 current_user: dict = Depends(get_current_user)
):
 username = current_user.get("username")
 role = current_user.get("role")

 # Users can only view their own stats
 if user_id != username and role != "admin":
 raise HTTPException(status_code=403, detail="Can only view your own statistics")
```

## Request Headers

### Required Headers

```http
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

### Optional Headers

```http
X-Request-ID: uuid # For request tracing
X-Tenant-ID: tenant-name # For multi-tenant deployments
```

## Error Responses

### 401 Unauthorized

```json
{
 "detail": "Not authenticated"
}
```

Causes:
- Missing Authorization header
- Invalid/expired JWT token
- Malformed token

### 403 Forbidden

```json
{
 "detail": "Admin access required"
}
```

Causes:
- User does not have required role
- Resource belongs to another user (non-admin)

## Code Examples

### Python (requests)

```python
import requests

# Login
response = requests.post(
 "http://localhost:8000/api/v1/auth/login",
 json={"username": "admin", "password": "secret"}
)
token = response.json()["access_token"]

# Authenticated request
headers = {"Authorization": f"Bearer {token}"}
response = requests.get(
 "http://localhost:8000/api/v1/cases",
 headers=headers
)
```

### JavaScript (fetch)

```javascript
// Login
const loginResponse = await fetch('/api/v1/auth/login', {
 method: 'POST',
 headers: { 'Content-Type': 'application/json' },
 body: JSON.stringify({ username: 'admin', password: 'secret' })
});
const { access_token } = await loginResponse.json();

// Authenticated request
const response = await fetch('/api/v1/cases', {
 headers: { 'Authorization': `Bearer ${access_token}` }
});
```

### cURL

```bash
# Login
TOKEN=$(curl -s -X POST http://localhost:8000/api/v1/auth/login \
 -H "Content-Type: application/json" \
 -d '{"username":"admin","password":"secret"}' \
 | jq -r '.access_token')

# Authenticated request
curl -H "Authorization: Bearer $TOKEN" \
 http://localhost:8000/api/v1/cases
```

## Security Best Practices

1. **Token Storage**: Store tokens securely (httpOnly cookies or secure storage)
2. **Token Refresh**: Implement refresh token rotation for long sessions
3. **HTTPS Only**: Always use HTTPS in production
4. **Short Expiry**: Access tokens should expire within 1-24 hours
5. **Logout**: Clear tokens on logout, consider token blacklisting

## Middleware Stack

```
Request
 
 

 Security Headers (X-Frame-Options, CSP, etc.)

 
 

 Rate Limiter (Per IP/User limits)

 
 

 Auth Middleware (JWT validation)

 
 

 Route Handler (Business logic)

```

## Related Documentation

- [SECURITY_AUDIT_2026-01-10.md](SECURITY_AUDIT_2026-01-10.md) - Security audit findings
- [API-REFERENCE.md](../API-REFERENCE.md) - Full API reference
- [PROJECT-OVERVIEW.md](../PROJECT-OVERVIEW.md) - System architecture

---

**Last Updated**: January 10, 2026
