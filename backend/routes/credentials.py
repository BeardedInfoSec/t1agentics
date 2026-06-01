# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Credentials API Routes

Secure credential management endpoints:
- Create, read, update, delete credentials
- Test credentials
- Link credentials to integrations

All endpoints require authentication (JWT or API key).
"""

from fastapi import APIRouter, HTTPException, Header, Query, Depends, Request
from typing import Optional, List
from pydantic import BaseModel

from services.credentials_service import (
    get_credentials_service,
    CredentialCreate,
    CredentialUpdate,
    StoredCredential,
    AuthType
)
from dependencies.auth import (
    get_current_user_or_api_key,
    User,
    APIKey,
    UserRole,
    Permission,
    ROLE_PERMISSIONS,
)

import logging
import json
from datetime import datetime

logger = logging.getLogger(__name__)


async def audit_credential_operation(
    action: str,
    user: User,
    credential_id: str = None,
    credential_name: str = None,
    details: dict = None
):
    """
    Log credential operations to the audit_log table.

    Actions:
    - CREDENTIAL_CREATED
    - CREDENTIAL_UPDATED
    - CREDENTIAL_DELETED
    - CREDENTIAL_ACCESSED
    - CREDENTIAL_LINKED
    - CREDENTIAL_UNLINKED
    - CREDENTIAL_TEST_SUCCESS
    - CREDENTIAL_TEST_FAILED
    """
    try:
        from services.postgres_db import postgres_db

        if not postgres_db.connected or not postgres_db.pool:
            logger.warning("Cannot audit credential operation - database not connected")
            return

        audit_details = {
            "credential_id": credential_id,
            "credential_name": credential_name,
            "timestamp": datetime.utcnow().isoformat(),
            **(details or {})
        }

        async with postgres_db.tenant_acquire() as conn:
            await conn.execute('''
                INSERT INTO audit_log (username, action, resource_type, resource_id, details, tenant_id)
                VALUES ($1, $2, $3, $4, $5, $6)
            ''',
                user.username,
                action,
                'credential',
                credential_id or 'N/A',
                json.dumps(audit_details),
                str(user.tenant_id) if user.tenant_id else None
            )

        logger.info(f"AUDIT: {action} - credential={credential_name or credential_id} by user={user.username}")

    except Exception as e:
        logger.error(f"Failed to audit credential operation: {e}")
        # Don't raise - audit failure shouldn't block the operation


async def require_auth(request: Request, authorization: Optional[str] = Header(None)) -> User:
    """Require authentication for credentials endpoints"""
    user, api_key = await get_current_user_or_api_key(request, authorization)
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Authentication required. Provide a valid JWT token or API key."
        )
    return user


async def require_admin(request: Request, authorization: Optional[str] = Header(None)) -> User:
    """Require admin role for sensitive operations"""
    user = await require_auth(request, authorization)
    if user.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=403,
            detail="Admin role required for this operation"
        )
    return user

router = APIRouter(prefix="/api/v1/credentials", tags=["credentials"])


# Response models
class CredentialListResponse(BaseModel):
    credentials: List[StoredCredential]
    total: int


class CredentialTestResult(BaseModel):
    success: bool
    message: Optional[str] = None
    error: Optional[str] = None
    status_code: Optional[int] = None


# Routes

# NOTE: Debug endpoint /debug/vault-status REMOVED for security
# Use admin dashboard or logs for debugging credential storage


@router.get("/auth-types")
async def list_auth_types(user: User = Depends(require_auth)):
    """List all supported authentication types (requires auth)"""
    return {
        "auth_types": [
            {
                "id": "api_key",
                "name": "API Key",
                "description": "API key sent in header or query parameter",
                "fields": ["api_key", "api_key_header", "api_key_prefix", "api_key_location"]
            },
            {
                "id": "bearer",
                "name": "Bearer Token",
                "description": "OAuth2/JWT bearer token",
                "fields": ["bearer_token"]
            },
            {
                "id": "basic",
                "name": "Basic Auth",
                "description": "Username and password authentication",
                "fields": ["username", "password"]
            },
            {
                "id": "oauth2_client",
                "name": "OAuth2 Client Credentials",
                "description": "OAuth2 client credentials flow (machine-to-machine)",
                "fields": ["client_id", "client_secret", "token_url", "scope"]
            },
            {
                "id": "oauth2_token",
                "name": "OAuth2 Token",
                "description": "Pre-obtained OAuth2 access token",
                "fields": ["access_token", "refresh_token"]
            },
            {
                "id": "aws",
                "name": "AWS Signature",
                "description": "AWS Signature Version 4 authentication",
                "fields": ["aws_access_key_id", "aws_secret_access_key", "aws_region", "aws_service"]
            },
            {
                "id": "custom_header",
                "name": "Custom Headers",
                "description": "Custom authentication headers",
                "fields": ["custom_headers"]
            },
            {
                "id": "none",
                "name": "No Authentication",
                "description": "No authentication required",
                "fields": []
            }
        ]
    }


@router.get("/")
async def list_credentials(
    auth_type: Optional[AuthType] = Query(None, description="Filter by auth type"),
    integration_id: Optional[str] = Query(None, description="Filter by linked integration"),
    tag: Optional[str] = Query(None, description="Filter by tag"),
    user: User = Depends(require_auth)
):
    """
    List all credentials (requires auth)

    Returns credentials without sensitive values (secrets are never exposed via API).
    """
    service = get_credentials_service()
    
    tags = [tag] if tag else None
    credentials = await service.list(
        auth_type=auth_type,
        integration_id=integration_id,
        tags=tags
    )
    
    # Convert to dicts for response
    creds_list = []
    for c in credentials:
        creds_list.append({
            "credential_id": c.credential_id,
            "name": c.name,
            "description": c.description,
            "auth_type": c.auth_type.value,
            "username": c.username,
            "client_id": c.client_id,
            "tags": c.tags,
            "integration_ids": c.integration_ids,
            "created_by": c.created_by,
            "created_at": c.created_at.isoformat() if c.created_at else None,
            "updated_at": c.updated_at.isoformat() if c.updated_at else None,
            "last_used_at": c.last_used_at.isoformat() if c.last_used_at else None,
            "has_secret": c.has_secret
        })
    
    return {
        "credentials": creds_list,
        "total": len(creds_list)
    }


@router.get("/{credential_id}", response_model=StoredCredential)
async def get_credential(
    credential_id: str,
    user: User = Depends(require_auth)
):
    """
    Get a credential by ID (requires auth)

    Returns credential without sensitive values.
    """
    service = get_credentials_service()
    credential = await service.get(credential_id)
    
    if not credential:
        raise HTTPException(status_code=404, detail="Credential not found")
    
    return credential


@router.post("/")
async def create_credential(
    credential: CredentialCreate,
    user: User = Depends(require_admin)
):
    """
    Create a new credential (requires admin)

    Sensitive values are encrypted before storage.
    The response does not include sensitive values.
    """
    logger.info(f"Creating credential: {credential.name} (auth_type: {credential.auth_type})")

    service = get_credentials_service()

    # Use authenticated user's username
    created_by = user.username

    try:
        result = await service.create(credential, created_by)
        logger.info(f"Credential created: {result.credential_id}")

        # Audit log the creation
        await audit_credential_operation(
            action='CREDENTIAL_CREATED',
            user=user,
            credential_id=result.credential_id,
            credential_name=result.name,
            details={
                "auth_type": result.auth_type.value,
                "tags": result.tags,
                "description": result.description
            }
        )

        # Return as dict to avoid serialization issues
        return {
            "credential_id": result.credential_id,
            "name": result.name,
            "description": result.description,
            "auth_type": result.auth_type.value,
            "tags": result.tags,
            "created_by": result.created_by,
            "created_at": result.created_at.isoformat(),
            "has_secret": result.has_secret,
            "success": True
        }
    except Exception as e:
        logger.error(f"Failed to create credential: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to create credential: {str(e)}")


@router.put("/{credential_id}", response_model=StoredCredential)
async def update_credential(
    credential_id: str,
    updates: CredentialUpdate,
    user: User = Depends(require_admin)
):
    """
    Update a credential (requires admin)

    Only provided fields are updated. Sensitive values are re-encrypted.
    """
    service = get_credentials_service()

    # Get existing credential for audit log
    existing = await service.get(credential_id)

    result = await service.update(credential_id, updates)
    if not result:
        raise HTTPException(status_code=404, detail="Credential not found")

    # Audit log the update
    await audit_credential_operation(
        action='CREDENTIAL_UPDATED',
        user=user,
        credential_id=credential_id,
        credential_name=result.name,
        details={
            "fields_updated": [k for k, v in updates.dict(exclude_none=True).items() if v is not None],
            "has_secret_update": updates.password is not None or updates.api_key is not None or updates.bearer_token is not None
        }
    )

    return result


@router.delete("/{credential_id}")
async def delete_credential(
    credential_id: str,
    user: User = Depends(require_admin)
):
    """Delete a credential (requires admin)"""
    service = get_credentials_service()

    # Get credential info before deletion for audit log
    existing = await service.get(credential_id)
    cred_name = existing.name if existing else 'unknown'

    success = await service.delete(credential_id)
    if not success:
        raise HTTPException(status_code=404, detail="Credential not found")

    # Audit log the deletion
    await audit_credential_operation(
        action='CREDENTIAL_DELETED',
        user=user,
        credential_id=credential_id,
        credential_name=cred_name,
        details={"permanently_deleted": True}
    )

    return {"success": True, "message": f"Credential {credential_id} deleted"}


@router.post("/{credential_id}/test", response_model=CredentialTestResult)
async def test_credential(
    credential_id: str,
    test_url: Optional[str] = Query(None, description="URL to test credential against"),
    user: User = Depends(require_auth)
):
    """
    Test a credential (requires auth)

    If test_url is provided, makes a request to that URL with the credential.
    Otherwise, just validates that auth headers can be generated.
    """
    service = get_credentials_service()

    result = await service.test_credential(credential_id, test_url)

    # Audit log the test
    await audit_credential_operation(
        action='CREDENTIAL_TEST_SUCCESS' if result.get('success') else 'CREDENTIAL_TEST_FAILED',
        user=user,
        credential_id=credential_id,
        details={
            "test_url": test_url,
            "success": result.get('success'),
            "error": result.get('error')
        }
    )

    return CredentialTestResult(**result)


@router.post("/{credential_id}/link/{integration_id}")
async def link_to_integration(
    credential_id: str,
    integration_id: str,
    user: User = Depends(require_admin)
):
    """Link a credential to an integration (requires admin)"""
    service = get_credentials_service()

    credential = await service.get(credential_id)
    if not credential:
        raise HTTPException(status_code=404, detail="Credential not found")

    # Add integration ID if not already linked
    integration_ids = list(credential.integration_ids)
    if integration_id not in integration_ids:
        integration_ids.append(integration_id)
        await service.update(credential_id, CredentialUpdate(integration_ids=integration_ids))

    import logging
    logger = logging.getLogger(__name__)

    # Also update the integration to point to this credential
    try:
        from integrations.registry.integration_registry import get_registry
        registry = get_registry()
        integration = registry.get(integration_id)
        if integration:
            integration.credential_id = credential_id
    except Exception as e:
        logger.warning(f"Could not update integration credential_id: {e}")

    # Update integration_state in database
    try:
        from services.postgres_db import postgres_db
        if postgres_db.connected and postgres_db.pool:
            async with postgres_db.tenant_acquire() as conn:
                await conn.execute('''
                    UPDATE integration_state
                    SET credential_id = $1, enabled = true, updated_at = CURRENT_TIMESTAMP
                    WHERE integration_id = $2
                ''', credential_id, integration_id)
                logger.info(f"Linked credential {credential_id} to integration {integration_id}")
    except Exception as e:
        logger.warning(f"Could not update integration_state: {e}")

    # Audit log the link operation
    await audit_credential_operation(
        action='CREDENTIAL_LINKED',
        user=user,
        credential_id=credential_id,
        credential_name=credential.name,
        details={"integration_id": integration_id}
    )

    return {"success": True, "message": f"Credential linked to integration {integration_id}"}


@router.delete("/{credential_id}/link/{integration_id}")
async def unlink_from_integration(
    credential_id: str,
    integration_id: str,
    user: User = Depends(require_admin)
):
    """Unlink a credential from an integration (requires admin)"""
    service = get_credentials_service()

    credential = await service.get(credential_id)
    if not credential:
        raise HTTPException(status_code=404, detail="Credential not found")

    # Remove integration ID if linked
    integration_ids = [id for id in credential.integration_ids if id != integration_id]
    await service.update(credential_id, CredentialUpdate(integration_ids=integration_ids))

    # Audit log the unlink operation
    await audit_credential_operation(
        action='CREDENTIAL_UNLINKED',
        user=user,
        credential_id=credential_id,
        credential_name=credential.name,
        details={"integration_id": integration_id}
    )

    return {"success": True, "message": f"Credential unlinked from integration {integration_id}"}


# Internal endpoint for getting auth headers (used by execution engine)
@router.get("/{credential_id}/headers")
async def get_auth_headers(
    credential_id: str,
    user: User = Depends(require_auth)
):
    """
    Get authentication headers for a credential (requires auth)

    This endpoint is intended for internal use by the execution engine.
    Returns header names only (not the actual secret values).
    """
    service = get_credentials_service()

    headers = await service.get_auth_headers(credential_id)
    if not headers:
        raise HTTPException(status_code=404, detail="Credential not found or no headers generated")

    # Don't return actual secret values in response
    # Just return header names for verification
    return {
        "headers": list(headers.keys()),
        "count": len(headers)
    }
