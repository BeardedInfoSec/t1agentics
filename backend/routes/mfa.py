# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
MFA (Multi-Factor Authentication) API Routes

Endpoints for:
- Setting up TOTP
- Verifying TOTP setup
- Verifying TOTP during login
- Disabling TOTP
- Checking MFA status
"""

import logging
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, Field

from dependencies.auth import get_current_user
from services.totp_service import get_totp_manager

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/mfa", tags=["MFA"])


class VerifyCodeRequest(BaseModel):
    code: str = Field(..., min_length=6, max_length=8, description="TOTP or recovery code")


@router.post("/setup")
async def setup_mfa(current_user: dict = Depends(get_current_user)):
    """Begin MFA setup. Returns secret and QR code URI."""
    manager = get_totp_manager()
    try:
        # get_current_user returns dict with 'id' field (UUID from users table)
        result = await manager.setup_totp(current_user['id'])
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/verify-setup")
async def verify_mfa_setup(
    request: VerifyCodeRequest,
    current_user: dict = Depends(get_current_user)
):
    """Verify TOTP setup with first code. Enables MFA on success."""
    manager = get_totp_manager()
    try:
        result = await manager.verify_setup(current_user['id'], request.code)
        if not result['success']:
            raise HTTPException(status_code=400, detail=result['message'])
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.delete("/disable")
async def disable_mfa(current_user: dict = Depends(get_current_user)):
    """Disable MFA for the current user."""
    manager = get_totp_manager()
    result = await manager.disable_totp(current_user['id'])
    return result


@router.get("/status")
async def get_mfa_status(current_user: dict = Depends(get_current_user)):
    """Get current MFA status for the user."""
    from services.postgres_db import postgres_db
    async with postgres_db.tenant_acquire() as conn:
        user = await conn.fetchrow(
            "SELECT mfa_enabled, totp_verified FROM users WHERE id = $1",
            current_user['id']
        )

    return {
        "mfa_enabled": user['mfa_enabled'] if user else False,
        "totp_configured": user['totp_verified'] if user else False,
    }
