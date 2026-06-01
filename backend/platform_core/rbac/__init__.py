# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
RBAC Enforcement Utilities

Server-side RBAC enforcement for FastAPI.
UI is NOT trusted - all permissions are checked at the API layer.
"""

from functools import wraps
from typing import List, Optional, Set, Callable, Any
from uuid import UUID
from dataclasses import dataclass, field
from datetime import datetime
import logging

from fastapi import Request, HTTPException, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_

logger = logging.getLogger(__name__)


@dataclass
class TenantContext:
    """
    Tenant context for the current request.
    Loaded from JWT/session at the start of each request.
    """
    tenant_id: UUID
    tenant_name: str
    tenant_status: str


@dataclass
class UserContext:
    """
    User context for the current request.
    """
    user_id: UUID
    email: str
    display_name: Optional[str]
    status: str
    roles: Set[str] = field(default_factory=set)
    permissions: Set[str] = field(default_factory=set)
    is_admin: bool = False


@dataclass
class RequestContext:
    """
    Full request context including tenant, user, and request metadata.
    """
    tenant: TenantContext
    user: Optional[UserContext]
    request_id: UUID
    correlation_id: Optional[UUID]
    ip_address: Optional[str]
    user_agent: Optional[str]
    timestamp: datetime = field(default_factory=datetime.utcnow)
    
    def has_permission(self, permission: str) -> bool:
        """Check if the user has a specific permission."""
        if self.user is None:
            return False
        if self.user.is_admin:
            return True
        if '*' in self.user.permissions:
            return True
        return permission in self.user.permissions
    
    def has_any_permission(self, permissions: List[str]) -> bool:
        """Check if the user has any of the specified permissions."""
        return any(self.has_permission(p) for p in permissions)
    
    def has_all_permissions(self, permissions: List[str]) -> bool:
        """Check if the user has all of the specified permissions."""
        return all(self.has_permission(p) for p in permissions)
    
    def has_role(self, role: str) -> bool:
        """Check if the user has a specific role."""
        if self.user is None:
            return False
        return role in self.user.roles


class RBACError(Exception):
    """Base exception for RBAC errors."""
    pass


class PermissionDeniedError(RBACError):
    """Raised when a user lacks required permissions."""
    def __init__(self, required_permissions: List[str], user_id: Optional[UUID] = None):
        self.required_permissions = required_permissions
        self.user_id = user_id
        super().__init__(f"Permission denied. Required: {required_permissions}")


class TenantMismatchError(RBACError):
    """Raised when accessing a resource from a different tenant."""
    def __init__(self, resource_tenant_id: UUID, user_tenant_id: UUID):
        self.resource_tenant_id = resource_tenant_id
        self.user_tenant_id = user_tenant_id
        super().__init__("Cross-tenant access denied")


class IntegrationActionDeniedError(RBACError):
    """Raised when an integration action is not allowed."""
    def __init__(self, integration_key: str, action_key: str):
        self.integration_key = integration_key
        self.action_key = action_key
        super().__init__(f"Action {integration_key}:{action_key} is not allowed")


# Request context storage (per-request using Starlette state)
_context_key = "request_context"


async def get_request_context(request: Request) -> RequestContext:
    """
    Get the current request context.
    This is set by the RBAC middleware at the start of each request.
    """
    ctx = getattr(request.state, _context_key, None)
    if ctx is None:
        raise HTTPException(
            status_code=401,
            detail="Authentication required"
        )
    return ctx


def require_auth(func: Callable) -> Callable:
    """
    Decorator to require authentication.
    """
    @wraps(func)
    async def wrapper(*args, request: Request, **kwargs):
        ctx = await get_request_context(request)
        if ctx.user is None:
            raise HTTPException(
                status_code=401,
                detail="Authentication required"
            )
        return await func(*args, request=request, **kwargs)
    return wrapper


def require_permissions(permissions: List[str], require_all: bool = True):
    """
    Decorator factory to require specific permissions.
    
    Args:
        permissions: List of required permissions
        require_all: If True, all permissions are required. If False, any one is sufficient.
    
    Usage:
        @require_permissions(['investigation:read'])
        async def get_investigation(...):
            ...
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, request: Request, **kwargs):
            ctx = await get_request_context(request)
            
            if ctx.user is None:
                raise HTTPException(
                    status_code=401,
                    detail="Authentication required"
                )
            
            if require_all:
                has_access = ctx.has_all_permissions(permissions)
            else:
                has_access = ctx.has_any_permission(permissions)
            
            if not has_access:
                logger.warning(
                    f"Permission denied: user={ctx.user.user_id}, "
                    f"required={permissions}, has={ctx.user.permissions}"
                )
                raise HTTPException(
                    status_code=403,
                    detail=f"Permission denied. Required: {permissions}"
                )
            
            return await func(*args, request=request, **kwargs)
        return wrapper
    return decorator


def require_roles(roles: List[str], require_all: bool = False):
    """
    Decorator factory to require specific roles.
    
    Args:
        roles: List of required roles
        require_all: If True, all roles are required. If False, any one is sufficient.
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, request: Request, **kwargs):
            ctx = await get_request_context(request)
            
            if ctx.user is None:
                raise HTTPException(
                    status_code=401,
                    detail="Authentication required"
                )
            
            if require_all:
                has_access = all(ctx.has_role(r) for r in roles)
            else:
                has_access = any(ctx.has_role(r) for r in roles)
            
            if not has_access:
                logger.warning(
                    f"Role check failed: user={ctx.user.user_id}, "
                    f"required={roles}, has={ctx.user.roles}"
                )
                raise HTTPException(
                    status_code=403,
                    detail=f"Role required: {roles}"
                )
            
            return await func(*args, request=request, **kwargs)
        return wrapper
    return decorator


def require_admin(func: Callable) -> Callable:
    """
    Decorator to require admin role.
    """
    @wraps(func)
    async def wrapper(*args, request: Request, **kwargs):
        ctx = await get_request_context(request)
        
        if ctx.user is None:
            raise HTTPException(
                status_code=401,
                detail="Authentication required"
            )
        
        if not ctx.user.is_admin:
            logger.warning(f"Admin required: user={ctx.user.user_id}")
            raise HTTPException(
                status_code=403,
                detail="Admin access required"
            )
        
        return await func(*args, request=request, **kwargs)
    return wrapper


def check_tenant_access(ctx: RequestContext, resource_tenant_id: UUID) -> None:
    """
    Verify that the resource belongs to the user's tenant.
    Raises TenantMismatchError if cross-tenant access is attempted.
    
    This MUST be called before returning any resource to ensure tenant isolation.
    """
    if resource_tenant_id != ctx.tenant.tenant_id:
        logger.error(
            f"Cross-tenant access attempt: "
            f"user_tenant={ctx.tenant.tenant_id}, resource_tenant={resource_tenant_id}"
        )
        raise TenantMismatchError(resource_tenant_id, ctx.tenant.tenant_id)


async def check_integration_action_allowed(
    ctx: RequestContext,
    integration_key: str,
    action_key: str,
    db: AsyncSession
) -> bool:
    """
    Check if an integration action is allowed for the tenant and user.
    
    Checks both:
    1. RBAC permission: integration:execute:<integration_key>:<action_key>
    2. Integration action allowlist: is_allowed = True
    
    Returns True if allowed, raises exception if denied.
    """
    from .database import Integration, IntegrationAction
    
    # 1. Check RBAC permission
    permission = f"integration:execute:{integration_key}:{action_key}"
    if not ctx.has_permission(permission) and not ctx.has_permission('action:execute'):
        raise PermissionDeniedError([permission])
    
    # 2. Check if action is allowlisted
    result = await db.execute(
        select(IntegrationAction)
        .join(Integration)
        .where(
            and_(
                Integration.tenant_id == ctx.tenant.tenant_id,
                Integration.integration_key == integration_key,
                IntegrationAction.action_key == action_key,
                IntegrationAction.is_allowed == True,
                Integration.is_enabled == True
            )
        )
    )
    action = result.scalar_one_or_none()
    
    if action is None:
        raise IntegrationActionDeniedError(integration_key, action_key)
    
    return True


# Permission dependency for FastAPI
class PermissionChecker:
    """
    FastAPI dependency for permission checking.
    
    Usage:
        @router.get("/investigations")
        async def list_investigations(
            _: None = Depends(PermissionChecker(['investigation:read']))
        ):
            ...
    """
    def __init__(self, permissions: List[str], require_all: bool = True):
        self.permissions = permissions
        self.require_all = require_all
    
    async def __call__(self, request: Request) -> RequestContext:
        ctx = await get_request_context(request)
        
        if ctx.user is None:
            raise HTTPException(status_code=401, detail="Authentication required")
        
        if self.require_all:
            has_access = ctx.has_all_permissions(self.permissions)
        else:
            has_access = ctx.has_any_permission(self.permissions)
        
        if not has_access:
            raise HTTPException(
                status_code=403,
                detail=f"Permission denied. Required: {self.permissions}"
            )
        
        return ctx


# Tenant-scoped query helper
def tenant_filter(model, tenant_id: UUID):
    """
    Create a tenant filter for queries.
    ALWAYS use this when querying tenant-scoped tables.
    
    Usage:
        query = select(Investigation).where(tenant_filter(Investigation, ctx.tenant.tenant_id))
    """
    return model.tenant_id == tenant_id
