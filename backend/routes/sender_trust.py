# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Sender Trust API Routes

Manages trusted sender allowlist and phishing test patterns.
"""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime

from dependencies.auth import get_current_user


router = APIRouter(prefix="/api/v1/sender-trust", tags=["sender-trust"])


# ==================== Pydantic Models ====================

class TrustedSenderCreate(BaseModel):
    domain: str = Field(..., description="Domain to trust (e.g., 'discord.com')")
    sender_pattern: Optional[str] = Field(None, description="Optional sender pattern")
    trust_level: str = Field("trusted", description="Trust level: verified, trusted, known")
    organization: Optional[str] = Field(None, description="Organization name")
    category: Optional[str] = Field(None, description="Category (e.g., 'social_media')")
    reason: Optional[str] = Field(None, description="Reason for adding")
    requires_whois: bool = Field(False, description="Require WHOIS validation")
    min_domain_age_days: int = Field(365, description="Minimum domain age in days")


class PhishingTestCreate(BaseModel):
    sender_pattern: str = Field(..., description="Sender pattern to match")
    subject_pattern: str = Field(..., description="Subject pattern to match")
    match_type: str = Field("contains", description="Match type: exact, contains, regex")
    test_name: Optional[str] = Field(None, description="Test name/identifier")
    vendor: Optional[str] = Field(None, description="Test vendor (e.g., 'KnowBe4')")
    auto_close: bool = Field(True, description="Auto-close matching alerts")
    skip_enrichment: bool = Field(True, description="Skip IOC enrichment")
    disposition: str = Field("BENIGN_POSITIVE", description="Disposition for matched alerts")
    valid_until: Optional[datetime] = Field(None, description="Expiry date")


# ==================== Trusted Sender Routes ====================

@router.get("/trusted-senders")
async def list_trusted_senders(
    include_inactive: bool = False,
    current_user: dict = Depends(get_current_user)
):
    """List all trusted sender domains"""
    from services.sender_trust_service import get_sender_trust_service
    service = get_sender_trust_service()

    try:
        tenant_id = current_user.get("tenant_id")
        senders = await service.list_trusted_senders(include_inactive=include_inactive, tenant_id=tenant_id)
        return {
            "trusted_senders": senders,
            "count": len(senders)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/trusted-senders")
async def add_trusted_sender(
    sender: TrustedSenderCreate,
    current_user: dict = Depends(get_current_user)
):
    """Add a trusted sender domain"""
    from services.sender_trust_service import get_sender_trust_service
    service = get_sender_trust_service()

    if sender.trust_level not in ['verified', 'trusted', 'known']:
        raise HTTPException(
            status_code=400,
            detail="trust_level must be 'verified', 'trusted', or 'known'"
        )

    try:
        result = await service.add_trusted_sender(
            domain=sender.domain,
            sender_pattern=sender.sender_pattern,
            trust_level=sender.trust_level,
            organization=sender.organization,
            category=sender.category,
            reason=sender.reason,
            requires_whois=sender.requires_whois,
            min_domain_age_days=sender.min_domain_age_days,
            added_by=current_user.get('username', 'unknown'),
            tenant_id=current_user.get('tenant_id')
        )
        return {"success": True, "trusted_sender": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/trusted-senders/{sender_id}")
async def remove_trusted_sender(
    sender_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Remove a trusted sender (deactivate)"""
    from services.sender_trust_service import get_sender_trust_service
    service = get_sender_trust_service()

    try:
        success = await service.remove_trusted_sender(sender_id, tenant_id=current_user.get('tenant_id'))
        if not success:
            raise HTTPException(status_code=404, detail="Trusted sender not found")
        return {"success": True, "message": "Trusted sender removed"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/trusted-senders/check")
async def check_trusted_sender(
    email: str,
    current_user: dict = Depends(get_current_user)
):
    """Check if an email address is from a trusted sender"""
    from services.sender_trust_service import get_sender_trust_service
    service = get_sender_trust_service()

    try:
        result = await service.check_trusted_sender(email)
        return {
            "email": email,
            "is_trusted": result.is_trusted,
            "trust_level": result.trust_level,
            "organization": result.organization,
            "category": result.category,
            "reason": result.reason
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ==================== Phishing Test Routes ====================

@router.get("/phishing-tests")
async def list_phishing_tests(
    include_inactive: bool = False,
    current_user: dict = Depends(get_current_user)
):
    """List all phishing test patterns"""
    from services.sender_trust_service import get_sender_trust_service
    service = get_sender_trust_service()

    try:
        tenant_id = current_user.get("tenant_id")
        tests = await service.list_phishing_tests(include_inactive=include_inactive, tenant_id=tenant_id)
        return {
            "phishing_tests": tests,
            "count": len(tests)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/phishing-tests")
async def add_phishing_test(
    test: PhishingTestCreate,
    current_user: dict = Depends(get_current_user)
):
    """Add a phishing test pattern"""
    from services.sender_trust_service import get_sender_trust_service
    service = get_sender_trust_service()

    if test.match_type not in ['exact', 'contains', 'regex']:
        raise HTTPException(
            status_code=400,
            detail="match_type must be 'exact', 'contains', or 'regex'"
        )

    try:
        result = await service.add_phishing_test(
            sender_pattern=test.sender_pattern,
            subject_pattern=test.subject_pattern,
            match_type=test.match_type,
            test_name=test.test_name,
            vendor=test.vendor,
            auto_close=test.auto_close,
            skip_enrichment=test.skip_enrichment,
            disposition=test.disposition,
            valid_until=test.valid_until,
            added_by=current_user.get('username', 'unknown'),
            tenant_id=current_user.get('tenant_id')
        )
        return {"success": True, "phishing_test": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/phishing-tests/{test_id}")
async def remove_phishing_test(
    test_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Remove a phishing test pattern (deactivate)"""
    from services.sender_trust_service import get_sender_trust_service
    service = get_sender_trust_service()

    try:
        success = await service.remove_phishing_test(test_id)
        if not success:
            raise HTTPException(status_code=404, detail="Phishing test not found")
        return {"success": True, "message": "Phishing test removed"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/phishing-tests/check")
async def check_phishing_test(
    sender: str,
    subject: str,
    current_user: dict = Depends(get_current_user)
):
    """Check if an email matches a phishing test pattern"""
    from services.sender_trust_service import get_sender_trust_service
    service = get_sender_trust_service()

    try:
        result = await service.check_phishing_test(sender, subject)
        return {
            "sender": sender,
            "subject": subject,
            "is_phishing_test": result.is_phishing_test,
            "test_name": result.test_name,
            "vendor": result.vendor,
            "auto_close": result.auto_close,
            "disposition": result.disposition
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
