# Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0

"""
Affiliate / Referral Program Routes

GET  /api/v1/affiliate/code          - Get (or create) the caller's referral code
GET  /api/v1/affiliate/stats         - Referral stats + banked discount status
GET  /api/v1/affiliate/validate/{code} - Public: validate a code before signup
"""

import random
import string
import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from dependencies.auth import get_current_user
from services.postgres_db import postgres_db

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/affiliate", tags=["affiliate"])

BASE_URL = "https://t1agentics.ai"


def _generate_code() -> str:
    """Generate a unique referral code in the format T1-XXXXXX."""
    chars = string.ascii_uppercase + string.digits
    suffix = "".join(random.choices(chars, k=6))
    return f"T1-{suffix}"


async def _get_or_create_code(tenant_id: str, conn) -> dict:
    """Return existing code for tenant, or create a new one."""
    row = await conn.fetchrow(
        "SELECT code, total_referrals, total_conversions FROM affiliate_codes "
        "WHERE tenant_id = $1::uuid AND is_active = true",
        tenant_id,
    )
    if row:
        return dict(row)

    # Generate a unique code
    for _ in range(10):
        code = _generate_code()
        existing = await conn.fetchval(
            "SELECT 1 FROM affiliate_codes WHERE code = $1", code
        )
        if not existing:
            await conn.execute(
                """
                INSERT INTO affiliate_codes (tenant_id, code)
                VALUES ($1::uuid, $2)
                """,
                tenant_id,
                code,
            )
            return {"code": code, "total_referrals": 0, "total_conversions": 0}

    raise HTTPException(status_code=500, detail="Could not generate unique referral code")


@router.get("/code")
async def get_referral_code(current_user: dict = Depends(get_current_user)):
    """Get (or lazily create) this tenant's referral code and link."""
    tenant_id = current_user.get("tenant_id")
    async with postgres_db.tenant_acquire() as conn:
        data = await _get_or_create_code(tenant_id, conn)

    return {
        "code": data["code"],
        "referral_url": f"{BASE_URL}/register?ref={data['code']}",
        "total_referrals": data["total_referrals"],
        "total_conversions": data["total_conversions"],
    }


@router.get("/stats")
async def get_referral_stats(current_user: dict = Depends(get_current_user)):
    """Return referral list and any banked/active discount state."""
    tenant_id = current_user.get("tenant_id")
    async with postgres_db.tenant_acquire() as conn:
        code_row = await _get_or_create_code(tenant_id, conn)

        # Referral list (mask email: show first char + *** + @domain)
        rows = await conn.fetch(
            """
            SELECT referred_email, status, created_at, converted_at
            FROM referrals
            WHERE referrer_tenant_id = $1::uuid
            ORDER BY created_at DESC
            LIMIT 50
            """,
            tenant_id,
        )

        def mask_email(email: Optional[str]) -> str:
            if not email or "@" not in email:
                return "***"
            local, domain = email.split("@", 1)
            return local[0] + "***@" + domain

        referrals = [
            {
                "email": mask_email(r["referred_email"]),
                "status": r["status"],
                "signed_up": r["created_at"].isoformat() if r["created_at"] else None,
                "converted_at": r["converted_at"].isoformat() if r["converted_at"] else None,
            }
            for r in rows
        ]

        # Discount state
        tenant_row = await conn.fetchrow(
            """
            SELECT
                referrer_discount_applied,
                referrer_discount_expires_at,
                referrer_discount_pending,
                referrer_discount_pending_expires_at
            FROM tenants WHERE id = $1::uuid
            """,
            tenant_id,
        )

        discount_info = {}
        if tenant_row:
            discount_info = {
                "discount_applied": tenant_row["referrer_discount_applied"] or False,
                "discount_expires_at": (
                    tenant_row["referrer_discount_expires_at"].isoformat()
                    if tenant_row["referrer_discount_expires_at"]
                    else None
                ),
                "discount_pending": tenant_row["referrer_discount_pending"] or False,
                "discount_pending_expires_at": (
                    tenant_row["referrer_discount_pending_expires_at"].isoformat()
                    if tenant_row["referrer_discount_pending_expires_at"]
                    else None
                ),
            }

    return {
        "code": code_row["code"],
        "referral_url": f"{BASE_URL}/register?ref={code_row['code']}",
        "total_referrals": code_row["total_referrals"],
        "total_conversions": code_row["total_conversions"],
        "referrals": referrals,
        **discount_info,
    }


@router.get("/validate/{code}")
async def validate_referral_code(code: str):
    """
    Public endpoint — no auth required.
    Returns whether the code is valid and the referring org name.
    Called from the registration page on blur.
    """
    code = code.upper().strip()
    # Public endpoint — use platform admin context to bypass RLS
    if not postgres_db.pool:
        return {"valid": False, "referrer_org": None}
    async with postgres_db.pool.acquire() as conn:
        await conn.execute("SET app.is_platform_admin = 'true'")
        row = await conn.fetchrow(
            """
            SELECT ac.code, t.name AS org_name
            FROM affiliate_codes ac
            JOIN tenants t ON t.id = ac.tenant_id
            WHERE ac.code = $1 AND ac.is_active = true
            """,
            code,
        )

    if not row:
        return {"valid": False, "referrer_org": None}

    return {"valid": True, "referrer_org": row["org_name"]}
