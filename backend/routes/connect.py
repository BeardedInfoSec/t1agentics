# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
T1 Connect API Routes

Single router for the entire T1 Connect integration system.
Handles marketplace browsing, connector instances, credentials,
custom connector building, action management, submissions,
platform admin operations, and action execution.

All business logic is delegated to ConnectService.
All endpoints require authentication (JWT or API key).
"""

from fastapi import APIRouter, HTTPException, Query, Depends, Request, Header
from typing import Optional, List, Dict, Any, Union
from pydantic import BaseModel
import logging

from dependencies.auth import (
    get_current_user as _get_current_user_dict,
    _has_permission,
)
from services.connect_service import get_connect_service
from config.constants import PLATFORM_OWNER_TENANT_ID

logger = logging.getLogger(__name__)

PLATFORM_TENANT_ID = PLATFORM_OWNER_TENANT_ID


# ============================================================================
# Auth Dependencies (permission-based)
# ============================================================================

class _ConnectUser:
    """Lightweight user object for Connect routes (attribute access on DB dict)."""
    def __init__(self, data: dict, tenant_id: Optional[str] = None):
        self.username = data.get("username", "")
        self.role = data.get("role", "")
        self.email = data.get("email", "")
        self.tenant_id = tenant_id or data.get("tenant_id")


def _build_connect_user(request: Request, user_dict: dict) -> _ConnectUser:
    tenant_id = getattr(request.state, "tenant_id", None) or user_dict.get("tenant_id")
    return _ConnectUser(user_dict, tenant_id)


async def require_integration_view(request: Request, authorization: Optional[str] = Header(None)) -> _ConnectUser:
    """Require integration:view — browse marketplace, list instances, health."""
    user_dict = await _get_current_user_dict(request, authorization)
    if not _has_permission(user_dict.get("role", ""), "integration:view"):
        raise HTTPException(status_code=403, detail="Permission denied. Required: integration:view")
    return _build_connect_user(request, user_dict)


async def require_integration_install(request: Request, authorization: Optional[str] = Header(None)) -> _ConnectUser:
    """Require integration:install — install or remove connector instances."""
    user_dict = await _get_current_user_dict(request, authorization)
    if not _has_permission(user_dict.get("role", ""), "integration:install"):
        raise HTTPException(status_code=403, detail="Permission denied. Required: integration:install")
    return _build_connect_user(request, user_dict)


async def require_integration_configure(request: Request, authorization: Optional[str] = Header(None)) -> _ConnectUser:
    """Require integration:configure — credentials, toggle, test, update."""
    user_dict = await _get_current_user_dict(request, authorization)
    if not _has_permission(user_dict.get("role", ""), "integration:configure"):
        raise HTTPException(status_code=403, detail="Permission denied. Required: integration:configure")
    return _build_connect_user(request, user_dict)


async def require_integration_manage(request: Request, authorization: Optional[str] = Header(None)) -> _ConnectUser:
    """Require integration:manage — custom connectors, export/import, submissions."""
    user_dict = await _get_current_user_dict(request, authorization)
    if not _has_permission(user_dict.get("role", ""), "integration:manage"):
        raise HTTPException(status_code=403, detail="Permission denied. Required: integration:manage")
    return _build_connect_user(request, user_dict)


async def require_action_execute(request: Request, authorization: Optional[str] = Header(None)) -> _ConnectUser:
    """Require action:execute — run connector actions."""
    user_dict = await _get_current_user_dict(request, authorization)
    if not _has_permission(user_dict.get("role", ""), "action:execute"):
        raise HTTPException(status_code=403, detail="Permission denied. Required: action:execute")
    return _build_connect_user(request, user_dict)


async def require_tenant_admin(request: Request, authorization: Optional[str] = Header(None)) -> _ConnectUser:
    """Require tenant admin role — for sensitive operations like auto-response."""
    user_dict = await _get_current_user_dict(request, authorization)
    if user_dict.get("role") not in ("admin", "platform_owner"):
        raise HTTPException(status_code=403, detail="Admin access required for this operation")
    return _build_connect_user(request, user_dict)


async def require_platform_admin(request: Request, authorization: Optional[str] = Header(None)) -> _ConnectUser:
    """Require platform admin (T1 tenant) for global operations."""
    user_dict = await _get_current_user_dict(request, authorization)
    if user_dict.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    user = _build_connect_user(request, user_dict)
    if str(user.tenant_id) != PLATFORM_TENANT_ID:
        raise HTTPException(status_code=403, detail="Platform admin access required")
    return user


# ============================================================================
# Request Models
# ============================================================================

class InstallConnectorRequest(BaseModel):
    connector_id: str
    display_name: Optional[str] = None
    credential_id: Optional[str] = None
    config: Optional[Dict[str, Any]] = None


class UpdateInstanceRequest(BaseModel):
    config: Optional[Dict[str, Any]] = None
    display_name: Optional[str] = None
    credential_id: Optional[str] = None


class CreateCredentialRequest(BaseModel):
    name: str
    auth_type: str
    secret_data: Dict[str, str]
    metadata: Optional[Dict[str, Any]] = None
    tags: Optional[List[str]] = None


class TestAuthRequest(BaseModel):
    base_url: str
    auth_type: str
    auth_config: Dict[str, Any] = {}
    temp_credential: Dict[str, str]


class TestActionRequest(BaseModel):
    base_url: str
    auth_type: str
    auth_config: Dict[str, Any] = {}
    temp_credential: Dict[str, str]
    action: Dict[str, Any]
    test_value: str


class CreateConnectorRequest(BaseModel):
    name: str
    vendor: Optional[str] = None
    category: str
    description: Optional[str] = None
    auth_type: str = "api_key"
    auth_config: Dict[str, Any] = {}
    base_url: str = ""
    actions: List[Dict[str, Any]] = []


class AddActionRequest(BaseModel):
    name: str
    method: str = "GET"
    endpoint: str
    observable_type: Optional[str] = None
    description: Optional[str] = None
    request_body: Optional[str] = None


class UpdateActionRequest(BaseModel):
    name: Optional[str] = None
    method: Optional[str] = None
    endpoint: Optional[str] = None
    observable_type: Optional[str] = None
    description: Optional[str] = None
    request_body: Optional[str] = None


class RejectSubmissionRequest(BaseModel):
    review_notes: str


class AutoResponseToggleRequest(BaseModel):
    enabled: bool
    action_type: Optional[str] = None


class ExecuteActionRequest(BaseModel):
    params: Dict[str, Any] = {}


class ImportConnectorRequest(BaseModel):
    definition: Dict[str, Any]


# ============================================================================
# Router
# ============================================================================

router = APIRouter(prefix="/api/v1/connect", tags=["connect"])


# ============================================================================
# Marketplace Endpoints (any authenticated user)
# ============================================================================

@router.get("/marketplace")
async def list_marketplace(
    search: Optional[str] = Query(None, description="Search term"),
    category: Optional[str] = Query(None, description="Filter by category"),
    page: int = Query(1, ge=1, description="Page number"),
    per_page: int = Query(50, ge=1, le=100, description="Items per page"),
    user: _ConnectUser = Depends(require_integration_view),
):
    """Browse the connector marketplace."""
    try:
        service = get_connect_service()
        result = await service.get_marketplace(
            tenant_id=str(user.tenant_id),
            search=search,
            category=category,
            page=page,
            per_page=per_page,
        )
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to list marketplace: {e}")
        raise HTTPException(status_code=500, detail="Failed to list marketplace connectors")


@router.get("/marketplace/{connector_id}")
async def get_marketplace_connector(
    connector_id: str,
    user: _ConnectUser = Depends(require_integration_view),
):
    """Get connector definition detail from the marketplace."""
    try:
        service = get_connect_service()
        result = await service.get_connector_detail(
            connector_id=connector_id,
            tenant_id=str(user.tenant_id),
        )
        if not result:
            raise HTTPException(status_code=404, detail="Connector not found")
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get marketplace connector {connector_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to get connector details")


# ============================================================================
# Instance Endpoints (read: any user, write: admin only)
# ============================================================================

@router.get("/instances")
async def list_instances(
    user: _ConnectUser = Depends(require_integration_view),
):
    """List installed connector instances for the tenant."""
    try:
        service = get_connect_service()
        result = await service.get_instances(tenant_id=str(user.tenant_id))
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to list instances: {e}")
        raise HTTPException(status_code=500, detail="Failed to list connector instances")


@router.get("/instances/{instance_id}")
async def get_instance(
    instance_id: str,
    user: _ConnectUser = Depends(require_integration_view),
):
    """Get single instance detail with connector info."""
    try:
        service = get_connect_service()
        result = await service.get_instance(
            tenant_id=str(user.tenant_id),
            instance_id=instance_id,
        )
        if not result:
            raise HTTPException(status_code=404, detail="Instance not found")
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get instance {instance_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to get instance details")


@router.post("/instances", status_code=201)
async def create_instance(
    body: InstallConnectorRequest,
    request: Request,
    user: _ConnectUser = Depends(require_integration_install),
):
    """Install a connector instance. Requires integration:install."""
    try:
        service = get_connect_service()
        result = await service.install_connector(
            tenant_id=str(user.tenant_id),
            connector_id=body.connector_id,
            display_name=body.display_name,
            credential_id=body.credential_id,
            config=body.config,
            created_by=user.username,
        )
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to create instance: {e}")
        raise HTTPException(status_code=500, detail="Failed to create connector instance")


@router.put("/instances/{instance_id}")
async def update_instance(
    instance_id: str,
    body: UpdateInstanceRequest,
    user: _ConnectUser = Depends(require_integration_configure),
):
    """Update a connector instance. Requires integration:configure."""
    try:
        service = get_connect_service()
        result = await service.update_instance(
            tenant_id=str(user.tenant_id),
            instance_id=instance_id,
            config=body.config,
            display_name=body.display_name,
            credential_id=body.credential_id,
        )
        if not result:
            raise HTTPException(status_code=404, detail="Instance not found")
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update instance {instance_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to update connector instance")


@router.delete("/instances/{instance_id}")
async def delete_instance(
    instance_id: str,
    user: _ConnectUser = Depends(require_integration_install),
):
    """Delete a connector instance. Requires integration:install."""
    try:
        service = get_connect_service()
        await service.delete_instance(
            tenant_id=str(user.tenant_id),
            instance_id=instance_id,
        )
        return {"message": "Instance deleted"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete instance {instance_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to delete connector instance")


@router.post("/instances/{instance_id}/toggle")
async def toggle_instance(
    instance_id: str,
    user: _ConnectUser = Depends(require_integration_configure),
):
    """Toggle a connector instance enabled/disabled. Requires integration:configure."""
    try:
        service = get_connect_service()
        result = await service.toggle_instance(
            tenant_id=str(user.tenant_id),
            instance_id=instance_id,
        )
        if not result:
            raise HTTPException(status_code=404, detail="Instance not found")
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to toggle instance {instance_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to toggle connector instance")


@router.patch("/instances/{instance_id}/auto-response")
async def toggle_auto_response(
    instance_id: str,
    body: AutoResponseToggleRequest,
    user: _ConnectUser = Depends(require_tenant_admin),
):
    """Toggle auto-response for a connector instance or a specific action type.
    ADMIN ONLY -- auto-response controls are restricted to tenant admins.

    If body.action_type is provided, updates the per-action setting.
    Otherwise, updates the global auto_response_enabled on the instance.
    """
    try:
        from services.postgres_db import postgres_db
        import uuid as _uuid

        if body.action_type:
            # Per-action toggle: upsert into auto_response_settings
            # First verify the instance belongs to this tenant
            async with postgres_db.tenant_acquire() as conn:
                instance = await conn.fetchrow(
                    """
                    SELECT id FROM connect_instances
                    WHERE id = $1::uuid AND tenant_id = $2::uuid
                    """,
                    _uuid.UUID(instance_id),
                    _uuid.UUID(str(user.tenant_id)),
                )
                if not instance:
                    raise HTTPException(status_code=404, detail="Instance not found")

                row = await conn.fetchrow(
                    """
                    INSERT INTO auto_response_settings (instance_id, action_type, enabled)
                    VALUES ($1::uuid, $2, $3)
                    ON CONFLICT (instance_id, action_type)
                    DO UPDATE SET enabled = $3, updated_at = NOW()
                    RETURNING id, instance_id, action_type, enabled
                    """,
                    _uuid.UUID(instance_id),
                    body.action_type,
                    body.enabled,
                )

            return {
                "instance_id": instance_id,
                "action_type": row["action_type"],
                "enabled": row["enabled"],
            }
        else:
            # Global toggle (existing behavior)
            async with postgres_db.tenant_acquire() as conn:
                row = await conn.fetchrow(
                    """
                    UPDATE connect_instances
                    SET auto_response_enabled = $3, updated_at = NOW()
                    WHERE id = $1::uuid AND tenant_id = $2::uuid
                    RETURNING id, auto_response_enabled
                    """,
                    _uuid.UUID(instance_id),
                    _uuid.UUID(str(user.tenant_id)),
                    body.enabled,
                )

            if not row:
                raise HTTPException(status_code=404, detail="Instance not found")

            return {
                "instance_id": str(row["id"]),
                "auto_response_enabled": row["auto_response_enabled"],
            }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to toggle auto-response for instance {instance_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to toggle auto-response")


@router.get("/instances/{instance_id}/auto-response")
async def get_auto_response_settings(
    instance_id: str,
    user: _ConnectUser = Depends(require_integration_view),
):
    """Get all per-action auto-response settings for an instance."""
    try:
        from services.postgres_db import postgres_db
        import uuid as _uuid

        async with postgres_db.tenant_acquire() as conn:
            # Verify instance belongs to tenant and get global setting
            instance = await conn.fetchrow(
                """
                SELECT id, auto_response_enabled FROM connect_instances
                WHERE id = $1::uuid AND tenant_id = $2::uuid
                """,
                _uuid.UUID(instance_id),
                _uuid.UUID(str(user.tenant_id)),
            )
            if not instance:
                raise HTTPException(status_code=404, detail="Instance not found")

            # Get all per-action settings
            rows = await conn.fetch(
                """
                SELECT action_type, enabled FROM auto_response_settings
                WHERE instance_id = $1::uuid
                ORDER BY action_type
                """,
                _uuid.UUID(instance_id),
            )

        action_settings = {row["action_type"]: row["enabled"] for row in rows}

        return {
            "instance_id": instance_id,
            "auto_response_enabled": instance["auto_response_enabled"],
            "action_settings": action_settings,
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get auto-response settings for instance {instance_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to get auto-response settings")


@router.post("/instances/{instance_id}/test")
async def test_instance(
    instance_id: str,
    user: _ConnectUser = Depends(require_integration_configure),
):
    """Test an instance connection. Requires integration:configure."""
    try:
        service = get_connect_service()
        result = await service.test_instance(
            tenant_id=str(user.tenant_id),
            instance_id=instance_id,
        )
        if not result:
            raise HTTPException(status_code=404, detail="Instance not found")
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to test instance {instance_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to test connector instance")


# ============================================================================
# Credential Endpoints (admin only)
# ============================================================================

@router.get("/credentials")
async def list_credentials(
    user: _ConnectUser = Depends(require_integration_configure),
):
    """List credentials (metadata only, no secrets). Requires integration:configure."""
    try:
        service = get_connect_service()
        result = await service.get_credentials(tenant_id=str(user.tenant_id))
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to list credentials: {e}")
        raise HTTPException(status_code=500, detail="Failed to list credentials")


@router.post("/credentials", status_code=201)
async def create_credential(
    body: CreateCredentialRequest,
    user: _ConnectUser = Depends(require_integration_configure),
):
    """Create a credential. Requires integration:configure."""
    try:
        service = get_connect_service()
        result = await service.create_credential(
            tenant_id=str(user.tenant_id),
            name=body.name,
            auth_type=body.auth_type,
            secret_data=body.secret_data,
            metadata=body.metadata,
            tags=body.tags,
            created_by=user.username,
        )
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to create credential: {e}")
        raise HTTPException(status_code=500, detail="Failed to create credential")


@router.delete("/credentials/{credential_id}")
async def delete_credential(
    credential_id: str,
    user: _ConnectUser = Depends(require_integration_configure),
):
    """Delete a credential and unlink from instances. Requires integration:configure."""
    try:
        service = get_connect_service()
        await service.delete_credential(
            tenant_id=str(user.tenant_id),
            credential_id=credential_id,
        )
        return {"message": "Credential deleted"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete credential {credential_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to delete credential")


@router.post("/credentials/{credential_id}/link/{instance_id}")
async def link_credential(
    credential_id: str,
    instance_id: str,
    user: _ConnectUser = Depends(require_integration_configure),
):
    """Link a credential to a connector instance. Requires integration:configure."""
    try:
        service = get_connect_service()
        result = await service.link_credential_to_instance(
            tenant_id=str(user.tenant_id),
            instance_id=instance_id,
            credential_id=credential_id,
        )
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to link credential {credential_id} to instance {instance_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to link credential to instance")


# ============================================================================
# Testing Endpoints (admin only, no save required)
# ============================================================================

@router.post("/test-auth")
async def test_auth(
    body: TestAuthRequest,
    user: _ConnectUser = Depends(require_integration_configure),
):
    """Test auth configuration without saving. Requires integration:configure."""
    try:
        service = get_connect_service()
        result = await service.test_auth(
            base_url=body.base_url,
            auth_type=body.auth_type,
            auth_config=body.auth_config,
            temp_credential=body.temp_credential,
        )
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to test auth: {e}")
        raise HTTPException(status_code=500, detail="Failed to test authentication")


@router.post("/test-action")
async def test_action(
    body: TestActionRequest,
    user: _ConnectUser = Depends(require_integration_configure),
):
    """Test a single action without saving. Requires integration:configure."""
    try:
        service = get_connect_service()
        result = await service.test_action(
            connector_def={
                "base_url": body.base_url,
                "auth_type": body.auth_type,
                "auth_config": body.auth_config,
            },
            temp_credential=body.temp_credential,
            action=body.action,
            test_value=body.test_value,
        )
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to test action: {e}")
        raise HTTPException(status_code=500, detail="Failed to test action")


# ============================================================================
# Custom Connector Endpoints (admin only)
# ============================================================================

@router.post("/connectors", status_code=201)
async def create_connector(
    body: CreateConnectorRequest,
    user: _ConnectUser = Depends(require_integration_manage),
):
    """Create a private connector for the tenant. Requires integration:manage."""
    try:
        service = get_connect_service()
        result = await service.create_custom_connector(
            tenant_id=str(user.tenant_id),
            data={
                "name": body.name,
                "vendor": body.vendor,
                "category": body.category,
                "description": body.description,
                "auth_type": body.auth_type,
                "auth_config": body.auth_config,
                "base_url": body.base_url,
                "actions": body.actions,
            },
            created_by=user.username,
        )
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to create connector: {e}")
        raise HTTPException(status_code=500, detail="Failed to create connector")


@router.put("/connectors/{connector_id}")
async def update_connector(
    connector_id: str,
    body: Dict[str, Any],
    user: _ConnectUser = Depends(require_integration_manage),
):
    """Update a private connector. Requires integration:manage."""
    try:
        service = get_connect_service()
        result = await service.update_custom_connector(
            tenant_id=str(user.tenant_id),
            connector_id=connector_id,
            data=body,
        )
        if not result:
            raise HTTPException(status_code=404, detail="Connector not found")
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update connector {connector_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to update connector")


@router.delete("/connectors/{connector_id}")
async def delete_connector(
    connector_id: str,
    user: _ConnectUser = Depends(require_integration_manage),
):
    """Delete a private connector. Requires integration:manage."""
    try:
        service = get_connect_service()
        await service.delete_custom_connector(
            tenant_id=str(user.tenant_id),
            connector_id=connector_id,
        )
        return {"message": "Connector deleted"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete connector {connector_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to delete connector")


@router.get("/connectors/{connector_id}/export")
async def export_connector(
    connector_id: str,
    user: _ConnectUser = Depends(require_integration_manage),
):
    """Export a connector definition as JSON. Requires integration:manage."""
    try:
        service = get_connect_service()
        result = await service.export_connector(
            tenant_id=str(user.tenant_id),
            connector_id=connector_id,
        )
        if not result:
            raise HTTPException(status_code=404, detail="Connector not found")
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to export connector {connector_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to export connector")


@router.post("/connectors/import", status_code=201)
async def import_connector(
    body: ImportConnectorRequest,
    user: _ConnectUser = Depends(require_integration_manage),
):
    """Import a connector definition as a private connector. Requires integration:manage."""
    try:
        service = get_connect_service()
        result = await service.import_connector(
            tenant_id=str(user.tenant_id),
            data=body.definition,
            created_by=user.username,
        )
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to import connector: {e}")
        raise HTTPException(status_code=500, detail="Failed to import connector")


# ============================================================================
# Action Management Endpoints (admin only, on private connectors)
# ============================================================================

@router.post("/connectors/{connector_id}/actions", status_code=201)
async def add_action(
    connector_id: str,
    body: AddActionRequest,
    user: _ConnectUser = Depends(require_integration_manage),
):
    """Add a custom action to a private connector. Requires integration:manage."""
    try:
        service = get_connect_service()
        result = await service.add_action(
            tenant_id=str(user.tenant_id),
            connector_id=connector_id,
            action_data={
                "name": body.name,
                "method": body.method,
                "endpoint": body.endpoint,
                "observable_type": body.observable_type,
                "description": body.description,
                "request_body": body.request_body,
            },
        )
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to add action to connector {connector_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to add action")


@router.put("/connectors/{connector_id}/actions/{action_id}")
async def update_action(
    connector_id: str,
    action_id: str,
    body: UpdateActionRequest,
    user: _ConnectUser = Depends(require_integration_manage),
):
    """Update a cloned/custom action. Rejects builtin actions. Requires integration:manage."""
    try:
        service = get_connect_service()
        updates = body.dict(exclude_none=True)
        if not updates:
            raise HTTPException(status_code=400, detail="No fields to update")
        result = await service.update_action(
            tenant_id=str(user.tenant_id),
            connector_id=connector_id,
            action_id=action_id,
            action_data=updates,
        )
        if not result:
            raise HTTPException(status_code=404, detail="Action not found")
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update action {action_id} on connector {connector_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to update action")


@router.delete("/connectors/{connector_id}/actions/{action_id}")
async def delete_action(
    connector_id: str,
    action_id: str,
    user: _ConnectUser = Depends(require_integration_manage),
):
    """Remove a cloned/custom action. Rejects builtin actions. Requires integration:manage."""
    try:
        service = get_connect_service()
        await service.remove_action(
            tenant_id=str(user.tenant_id),
            connector_id=connector_id,
            action_id=action_id,
        )
        return {"message": "Action deleted"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete action {action_id} on connector {connector_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to delete action")


@router.post("/connectors/{connector_id}/actions/{action_id}/clone", status_code=201)
async def clone_action(
    connector_id: str,
    action_id: str,
    user: _ConnectUser = Depends(require_integration_manage),
):
    """Clone any action (including builtin) for customization. Requires integration:manage."""
    try:
        service = get_connect_service()
        result = await service.clone_action(
            tenant_id=str(user.tenant_id),
            connector_id=connector_id,
            action_id=action_id,
        )
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to clone action {action_id} on connector {connector_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to clone action")


# ============================================================================
# Submission Endpoints (tenant admins submit, platform admin reviews)
# ============================================================================

@router.post("/connectors/{connector_id}/submit")
async def submit_connector(
    connector_id: str,
    user: _ConnectUser = Depends(require_integration_manage),
):
    """Submit a private connector to the marketplace for review. Requires integration:manage."""
    try:
        service = get_connect_service()
        result = await service.submit_to_marketplace(
            tenant_id=str(user.tenant_id),
            connector_id=connector_id,
            submitted_by=user.username,
        )
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to submit connector {connector_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to submit connector")


@router.get("/submissions")
async def list_submissions(
    user: _ConnectUser = Depends(require_integration_manage),
):
    """List submissions. Requires integration:manage."""
    try:
        service = get_connect_service()
        is_platform_admin = str(user.tenant_id) == PLATFORM_TENANT_ID
        result = await service.get_submissions(
            tenant_id=str(user.tenant_id) if not is_platform_admin else None,
        )
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to list submissions: {e}")
        raise HTTPException(status_code=500, detail="Failed to list submissions")


@router.post("/admin/submissions/{submission_id}/approve")
async def approve_submission(
    submission_id: str,
    user: _ConnectUser = Depends(require_platform_admin),
):
    """Approve a marketplace submission. Platform admin only."""
    try:
        service = get_connect_service()
        result = await service.approve_submission(
            submission_id=submission_id,
            reviewed_by=user.username,
        )
        if not result:
            raise HTTPException(status_code=404, detail="Submission not found")
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to approve submission {submission_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to approve submission")


@router.post("/admin/submissions/{submission_id}/reject")
async def reject_submission(
    submission_id: str,
    body: RejectSubmissionRequest,
    user: _ConnectUser = Depends(require_platform_admin),
):
    """Reject a marketplace submission with notes. Platform admin only."""
    try:
        service = get_connect_service()
        result = await service.reject_submission(
            submission_id=submission_id,
            review_notes=body.review_notes,
            reviewed_by=user.username,
        )
        if not result:
            raise HTTPException(status_code=404, detail="Submission not found")
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to reject submission {submission_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to reject submission")


# ============================================================================
# Platform Admin Connector Management
# ============================================================================

@router.post("/admin/connectors", status_code=201)
async def create_builtin_connector(
    body: Dict[str, Any],
    user: _ConnectUser = Depends(require_platform_admin),
):
    """Add a builtin connector to the marketplace. Platform admin only."""
    try:
        service = get_connect_service()
        result = await service.admin_add_connector(
            data=body,
            created_by=user.username,
        )
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to create builtin connector: {e}")
        raise HTTPException(status_code=500, detail="Failed to create builtin connector")


@router.put("/admin/connectors/{connector_id}")
async def update_builtin_connector(
    connector_id: str,
    body: Dict[str, Any],
    user: _ConnectUser = Depends(require_platform_admin),
):
    """Update a builtin connector. Platform admin only."""
    try:
        service = get_connect_service()
        result = await service.admin_update_connector(
            connector_id=connector_id,
            data=body,
        )
        if not result:
            raise HTTPException(status_code=404, detail="Connector not found")
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update builtin connector {connector_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to update builtin connector")


@router.delete("/admin/connectors/{connector_id}")
async def delete_builtin_connector(
    connector_id: str,
    user: _ConnectUser = Depends(require_platform_admin),
):
    """Remove a builtin/community connector. Platform admin only."""
    try:
        service = get_connect_service()
        await service.admin_delete_connector(connector_id=connector_id)
        return {"message": "Connector deleted"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete builtin connector {connector_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to delete builtin connector")


# ============================================================================
# Health Endpoint
# ============================================================================

@router.get("/health")
async def get_health(
    user: _ConnectUser = Depends(require_integration_view),
):
    """Get connector health summary for the tenant."""
    try:
        service = get_connect_service()
        result = await service.get_health_summary(tenant_id=str(user.tenant_id))
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get health summary: {e}")
        raise HTTPException(status_code=500, detail="Failed to get connector health summary")


# ============================================================================
# Execution Endpoint (for Riggs/enrichment and direct API use)
# ============================================================================

@router.post("/instances/{instance_id}/execute/{action_id}")
async def execute_action(
    instance_id: str,
    action_id: str,
    body: ExecuteActionRequest,
    user: _ConnectUser = Depends(require_action_execute),
):
    """Execute an action on an installed connector instance. Requires action:execute."""
    try:
        service = get_connect_service()
        result = await service.execute_action(
            tenant_id=str(user.tenant_id),
            instance_id=instance_id,
            action_id=action_id,
            params=body.params,
            executed_by=user.username,
        )
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to execute action {action_id} on instance {instance_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to execute action")
