# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Authentication Dependencies for FastAPI Routes
Shared auth helpers that can be used across all route files.
"""

import os
import jwt
import logging
from fastapi import Header, HTTPException, Request, Depends
from typing import Optional, Dict, List
from utils.auth_tokens import get_auth_token

logger = logging.getLogger(__name__)

# JWT Configuration
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")
if not JWT_SECRET_KEY:
    raise RuntimeError("CRITICAL: JWT_SECRET_KEY environment variable is not set. Cannot start without a secret key.")
JWT_ALGORITHM = "HS256"


def decode_jwt_token(token: str) -> Optional[Dict]:
    """Decode and validate a JWT token."""
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        logger.debug("Token expired")
        return None
    except jwt.InvalidTokenError as e:
        logger.debug(f"Invalid token: {e}")
        return None


async def get_current_user(request: Request, authorization: str = Header(None)) -> Dict:
    """
    FastAPI dependency that extracts and validates user from JWT token.
    Raises HTTPException if not authenticated.

    Usage:
        @router.get("/protected")
        async def protected_route(user: Dict = Depends(get_current_user)):
            return {"username": user["username"]}
    """
    token, _source = get_auth_token(request, authorization)
    if not token:
        raise HTTPException(
            status_code=401,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"}
        )

    payload = decode_jwt_token(token)

    if not payload:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"}
        )

    # Check token blacklist for revoked tokens/sessions (DB-backed with memory cache)
    try:
        from services.token_blacklist import get_token_blacklist
        blacklist = get_token_blacklist()

        # Check if specific token (by JTI) has been revoked
        jti = payload.get("jti", "")
        if jti and await blacklist.is_revoked_async(jti):
            raise HTTPException(status_code=401, detail="Token has been revoked")

        # Check if all user sessions before a certain time have been revoked
        username = payload.get("sub", "")
        iat = payload.get("iat")
        if username and iat is not None:
            # iat may be a datetime or a timestamp
            if isinstance(iat, (int, float)):
                iat_ts = float(iat)
            else:
                import calendar
                iat_ts = calendar.timegm(iat.timetuple())
            if await blacklist.is_user_revoked_async(username, iat_ts):
                raise HTTPException(status_code=401, detail="Session has been revoked")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Token blacklist check failed (denying request): {e}")
        raise HTTPException(status_code=401, detail="Authentication check failed")

    # Get user from database to ensure they still exist and aren't disabled
    try:
        from services.postgres_db import postgres_db
        if postgres_db.connected:
            user = await postgres_db.get_user_by_username(payload.get("sub"))
            if not user:
                raise HTTPException(status_code=401, detail="User not found")
            if user.get("disabled"):
                raise HTTPException(status_code=401, detail="User account is disabled")

            return {
                "id": str(user.get("id")) if user.get("id") else None,
                "username": user["username"],
                "role": user.get("role", "user"),
                "email": user.get("email"),
                "full_name": user.get("full_name"),
                "tenant_id": str(user.get("tenant_id")) if user.get("tenant_id") else None
            }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching user from database: {e}")
        raise HTTPException(
            status_code=503,
            detail="Authentication service temporarily unavailable"
        )


async def get_current_username(request: Request, authorization: str = Header(None)) -> str:
    """
    Simplified auth dependency that returns just the username.

    Usage:
        @router.post("/action")
        async def perform_action(username: str = Depends(get_current_username)):
            return {"performed_by": username}
    """
    user = await get_current_user(request, authorization)
    return user["username"]


async def require_admin(request: Request, authorization: str = Header(None)) -> Dict:
    """
    FastAPI dependency that requires admin role.
    Raises HTTPException if not admin.

    Usage:
        @router.delete("/sensitive")
        async def delete_sensitive(admin: Dict = Depends(require_admin)):
            return {"deleted_by": admin["username"]}
    """
    user = await get_current_user(request, authorization)

    if user.get("role") != "admin":
        raise HTTPException(
            status_code=403,
            detail="Admin access required"
        )

    return user


def require_role(required_roles: list):
    """
    Factory function to create a dependency that requires specific roles.

    Usage:
        @router.post("/investigate")
        async def investigate(user: Dict = Depends(require_role(["admin", "analyst"]))):
            return {"user": user["username"]}
    """
    async def role_checker(request: Request, authorization: str = Header(None)) -> Dict:
        user = await get_current_user(request, authorization)

        if user.get("role") not in required_roles:
            raise HTTPException(
                status_code=403,
                detail=f"Access denied. Required role: {', '.join(required_roles)}"
            )

        return user

    return role_checker


async def optional_auth(request: Request, authorization: str = Header(None)) -> Optional[Dict]:
    """
    Optional authentication - returns user if authenticated, None otherwise.
    Useful for routes that behave differently for authenticated users.

    Usage:
        @router.get("/public-data")
        async def get_data(user: Optional[Dict] = Depends(optional_auth)):
            if user:
                return {"data": "full", "user": user["username"]}
            return {"data": "limited"}
    """
    token, _source = get_auth_token(request, authorization)
    if not token:
        return None

    payload = decode_jwt_token(token)

    if not payload:
        return None

    return {
        "username": payload.get("sub"),
        "role": payload.get("role", "user")
    }


def _get_role_permissions(role: str) -> List[str]:
    """Look up permissions for a role from DEFAULT_ROLES."""
    from platform_core.rbac_defaults import DEFAULT_ROLES
    role_def = DEFAULT_ROLES.get(role) or DEFAULT_ROLES.get(role.capitalize())
    if not role_def:
        return []
    return role_def.get("permissions", [])


def _has_permission(role: str, permission: str) -> bool:
    """Check if a role has a specific permission (supports '*' wildcard)."""
    perms = _get_role_permissions(role)
    if "*" in perms:
        return True
    return permission in perms


def require_permission(permission: str):
    """
    Factory function to create a dependency that requires a specific permission.
    Resolves the user's role to a permission set via DEFAULT_ROLES.

    Usage:
        @router.get("/playbooks")
        async def list_playbooks(user: Dict = Depends(require_permission("playbook:view"))):
            ...
    """
    async def permission_checker(request: Request, authorization: str = Header(None)) -> Dict:
        user = await get_current_user(request, authorization)
        role = user.get("role", "user")
        if not _has_permission(role, permission):
            raise HTTPException(
                status_code=403,
                detail=f"Permission denied. Required: {permission}"
            )
        return user

    return permission_checker


def require_any_permission(permissions: List[str]):
    """
    Factory function requiring at least one of the listed permissions.

    Usage:
        @router.put("/instance")
        async def update(user: Dict = Depends(require_any_permission(["integration:configure", "integration:manage"]))):
            ...
    """
    async def permission_checker(request: Request, authorization: str = Header(None)) -> Dict:
        user = await get_current_user(request, authorization)
        role = user.get("role", "user")
        if not any(_has_permission(role, p) for p in permissions):
            raise HTTPException(
                status_code=403,
                detail=f"Permission denied. Required one of: {permissions}"
            )
        return user

    return permission_checker


async def get_current_user_or_api_key(
    request: Request,
    authorization: Optional[str] = Header(None)
):
    """
    DB-backed authentication: try JWT first, then API key.
    Returns (user, api_key) tuple where user is a services.auth.User model
    and api_key is a services.auth.APIKey model (or None).
    """
    from services.auth import User, APIKey, UserRole, verify_api_key

    # Try JWT token first
    token, _source = get_auth_token(request, authorization)
    if token:
        payload = decode_jwt_token(token)
        if payload:
            try:
                from services.postgres_db import postgres_db
                if postgres_db.connected:
                    db_user = await postgres_db.get_user_by_username(payload.get("sub"))
                    if db_user and not db_user.get("disabled"):
                        user = User(
                            username=db_user["username"],
                            email=db_user.get("email") or "unknown@t1agentics.ai",
                            full_name=db_user.get("full_name"),
                            role=UserRole(db_user.get("role", "user")),
                            tenant_id=str(db_user.get("tenant_id") or ""),
                        )
                        return user, None
            except Exception as e:
                logger.error(f"DB user lookup failed in get_current_user_or_api_key: {e}")

    # Try API key
    if authorization:
        try:
            api_key_obj = verify_api_key(authorization)
            if api_key_obj:
                user = User(
                    username=f"api_key_{api_key_obj.key_id}",
                    email="api@key.local",
                    role=api_key_obj.role,
                )
                return user, api_key_obj
        except Exception:
            pass

    return None, None


# Re-export auth model types so route files can import from dependencies.auth
# instead of the legacy services.auth module.
from services.auth import User, APIKey, UserRole, Permission, ROLE_PERMISSIONS  # noqa: F401

# Convenience aliases for common use cases
RequireAuth = Depends(get_current_user)
RequireAdmin = Depends(require_admin)
GetUsername = Depends(get_current_username)
OptionalAuth = Depends(optional_auth)
