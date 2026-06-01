# Security Developer Guide

Quick reference for implementing secure endpoints in T1 Agentics.

## Adding Authentication to New Endpoints

### Step 1: Import Dependencies

```python
from dependencies.auth import get_current_user, require_admin
from fastapi import Depends
```

### Step 2: Choose Protection Level

#### Standard Authentication (any logged-in user)

```python
@router.get("/my-endpoint")
async def my_endpoint(current_user: dict = Depends(get_current_user)):
 username = current_user.get("username")
 # Your logic here
```

#### Admin Only

```python
@router.post("/admin-endpoint")
async def admin_endpoint(admin_user: str = Depends(require_admin)):
 # admin_user is the username of the admin
 # Your logic here
```

#### Self-Service with Admin Override

```python
@router.get("/users/{user_id}/data")
async def get_user_data(
 user_id: str,
 current_user: dict = Depends(get_current_user)
):
 username = current_user.get("username")
 role = current_user.get("role")

 if user_id != username and role != "admin":
 raise HTTPException(status_code=403, detail="Access denied")

 # Fetch and return user data
```

## Security Checklist for New Endpoints

- [ ] Added `get_current_user` or `require_admin` dependency
- [ ] Validated all user input with Pydantic models
- [ ] Added rate limiting for expensive operations
- [ ] Logged sensitive actions (create, update, delete)
- [ ] No sensitive data in logs or error messages
- [ ] SQL queries use parameterized statements
- [ ] File paths are validated (no path traversal)
- [ ] External URLs are validated (no SSRF)

## Common Security Patterns

### Input Validation

```python
from pydantic import BaseModel, Field, validator

class UserInput(BaseModel):
 name: str = Field(..., min_length=1, max_length=100)
 email: str = Field(..., regex=r'^[\w\.-]+@[\w\.-]+\.\w+$')
 count: int = Field(..., ge=1, le=1000)

 @validator('name')
 def sanitize_name(cls, v):
 # Remove potential XSS
 return v.replace('<', '&lt;').replace('>', '&gt;')
```

### SQL Injection Prevention

```python
# WRONG - SQL Injection vulnerable
query = f"SELECT * FROM users WHERE id = '{user_id}'"

# CORRECT - Parameterized query
query = "SELECT * FROM users WHERE id = $1"
result = await db.fetch_one(query, user_id)
```

### Path Traversal Prevention

```python
import os

def safe_file_path(user_input: str, base_dir: str) -> str:
 # Normalize and resolve the path
 requested_path = os.path.normpath(os.path.join(base_dir, user_input))

 # Ensure it's within the base directory
 if not requested_path.startswith(os.path.normpath(base_dir)):
 raise HTTPException(status_code=400, detail="Invalid path")

 return requested_path
```

### SSRF Prevention

```python
from urllib.parse import urlparse
import ipaddress

BLOCKED_HOSTS = ['localhost', '127.0.0.1', '0.0.0.0']
BLOCKED_NETWORKS = [
 ipaddress.ip_network('10.0.0.0/8'),
 ipaddress.ip_network('172.16.0.0/12'),
 ipaddress.ip_network('192.168.0.0/16'),
]

def validate_external_url(url: str) -> bool:
 parsed = urlparse(url)

 if parsed.hostname in BLOCKED_HOSTS:
 return False

 try:
 ip = ipaddress.ip_address(parsed.hostname)
 for network in BLOCKED_NETWORKS:
 if ip in network:
 return False
 except ValueError:
 pass # Not an IP, hostname is fine

 return True
```

### Sensitive Data Handling

```python
# WRONG - Exposing internal data
return {"user": user, "password_hash": user.password_hash}

# CORRECT - Use response models
class UserResponse(BaseModel):
 id: str
 username: str
 email: str
 # No password_hash field

@router.get("/users/{id}", response_model=UserResponse)
async def get_user(id: str):
 user = await get_user_by_id(id)
 return user # Only fields in UserResponse are returned
```

### Audit Logging

```python
import logging

logger = logging.getLogger(__name__)

@router.delete("/users/{user_id}")
async def delete_user(
 user_id: str,
 admin_user: str = Depends(require_admin)
):
 # Log BEFORE the action
 logger.info(f"AUDIT: User deletion initiated - target={user_id}, admin={admin_user}")

 result = await user_service.delete_user(user_id)

 # Log AFTER success
 logger.info(f"AUDIT: User deleted - target={user_id}, admin={admin_user}")

 return {"status": "deleted"}
```

## Error Handling Best Practices

### Don't Expose Internal Errors

```python
# WRONG
@router.get("/data")
async def get_data():
 try:
 result = await db.fetch()
 except Exception as e:
 raise HTTPException(status_code=500, detail=str(e)) # Exposes internals!

# CORRECT
@router.get("/data")
async def get_data():
 try:
 result = await db.fetch()
 except Exception as e:
 logger.error(f"Database error: {e}") # Log internally
 raise HTTPException(status_code=500, detail="Internal server error")
```

### Use Consistent Error Format

```python
from fastapi import HTTPException

# Standard error responses
def not_found(resource: str):
 raise HTTPException(status_code=404, detail=f"{resource} not found")

def forbidden(action: str):
 raise HTTPException(status_code=403, detail=f"Not authorized to {action}")

def bad_request(reason: str):
 raise HTTPException(status_code=400, detail=reason)
```

## Rate Limiting

For expensive operations, add rate limiting:

```python
from middleware.rate_limiter import rate_limit

@router.post("/expensive-operation")
@rate_limit(requests=10, window=60) # 10 requests per minute
async def expensive_operation(current_user: dict = Depends(get_current_user)):
 # Your logic
```

## Testing Security

### Unit Test Authentication

```python
import pytest
from fastapi.testclient import TestClient

def test_endpoint_requires_auth(client: TestClient):
 # No token
 response = client.get("/api/v1/protected")
 assert response.status_code == 401

def test_endpoint_requires_admin(client: TestClient, user_token: str):
 # Non-admin token
 response = client.post(
 "/api/v1/admin/users",
 headers={"Authorization": f"Bearer {user_token}"}
 )
 assert response.status_code == 403

def test_admin_can_access(client: TestClient, admin_token: str):
 response = client.get(
 "/api/v1/admin/users",
 headers={"Authorization": f"Bearer {admin_token}"}
 )
 assert response.status_code == 200
```

## Quick Reference

| Need | Use |
|------|-----|
| Any authenticated user | `Depends(get_current_user)` |
| Admin only | `Depends(require_admin)` |
| User's own data | Check `user_id == current_user["username"]` |
| Validate input | Pydantic models with constraints |
| Prevent SQL injection | Parameterized queries |
| Prevent path traversal | `os.path.normpath` + prefix check |
| Prevent SSRF | URL validation + IP blocklist |
| Log security events | `logger.info(f"AUDIT: ...")` |

---

**Last Updated**: January 10, 2026
