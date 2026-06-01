# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
PII Obfuscation Settings API
Allows configuration of how PII is detected and obfuscated for PCI compliance
"""

from fastapi import APIRouter, HTTPException, Header, Request
from pydantic import BaseModel
from typing import List, Dict, Optional
from enum import Enum

from services.pii_obfuscation import (
    get_pii_service, PIIType, ObfuscationMode, PIIConfig
)
from routes.admin import require_admin

router = APIRouter(prefix="/api/v1/pii", tags=["pii-settings"])


# ==================== MODELS ====================

class PIITypeConfig(BaseModel):
    """Configuration for a single PII type"""
    type: str  # credit_card, ssn, etc.
    enabled: bool
    mode: str  # mask, redact, hash, tokenize


class PIISettingsResponse(BaseModel):
    """Current PII settings"""
    enabled: bool
    default_mode: str
    types: List[PIITypeConfig]
    stats: Dict


class PIISettingsUpdate(BaseModel):
    """Update PII settings"""
    enabled: Optional[bool] = None
    default_mode: Optional[str] = None  # mask, redact, hash, tokenize
    type_settings: Optional[Dict[str, Dict]] = None  # {type: {enabled: bool, mode: str}}


# ==================== ENDPOINTS ====================

@router.get("/settings", response_model=PIISettingsResponse)
async def get_pii_settings(request: Request, authorization: str = Header(None)):
    """Get current PII obfuscation settings"""
    await require_admin(request, authorization)

    service = get_pii_service()
    config = service.config

    # Build type list
    types = []
    for pii_type in PIIType:
        is_enabled = pii_type in config.obfuscate_types
        mode = config.type_modes.get(pii_type, config.default_mode)
        types.append(PIITypeConfig(
            type=pii_type.value,
            enabled=is_enabled,
            mode=mode.value if isinstance(mode, ObfuscationMode) else str(mode)
        ))

    return PIISettingsResponse(
        enabled=config.enabled,
        default_mode=config.default_mode.value,
        types=types,
        stats=service.get_stats()
    )


@router.put("/settings", response_model=PIISettingsResponse)
async def update_pii_settings(
    request: Request,
    settings: PIISettingsUpdate,
    authorization: str = Header(None)
):
    """
    Update PII obfuscation settings.

    Example:
    {
        "enabled": true,
        "default_mode": "mask",
        "type_settings": {
            "ssn": {"enabled": true, "mode": "mask"},
            "credit_card": {"enabled": true, "mode": "mask"},
            "email": {"enabled": false},
            "phone": {"enabled": false}
        }
    }

    Modes:
    - mask: Partial masking (****1234, ***-**-6789)
    - redact: Full redaction ([SSN_REDACTED])
    - hash: SHA-256 hash ([HASH:abc123...])
    - tokenize: Reversible token ([TOK_abc123])
    """
    await require_admin(request, authorization)

    service = get_pii_service()
    config = service.config

    # Update global enabled
    if settings.enabled is not None:
        config.enabled = settings.enabled

    # Update default mode
    if settings.default_mode:
        try:
            config.default_mode = ObfuscationMode(settings.default_mode)
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid mode: {settings.default_mode}. Must be: mask, redact, hash, tokenize"
            )

    # Update type-specific settings
    if settings.type_settings:
        for type_name, type_config in settings.type_settings.items():
            try:
                pii_type = PIIType(type_name)
            except ValueError:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid PII type: {type_name}"
                )

            # Enable/disable type
            if 'enabled' in type_config:
                if type_config['enabled']:
                    config.obfuscate_types.add(pii_type)
                else:
                    config.obfuscate_types.discard(pii_type)

            # Set mode for type
            if 'mode' in type_config:
                try:
                    mode = ObfuscationMode(type_config['mode'])
                    config.type_modes[pii_type] = mode
                except ValueError:
                    raise HTTPException(
                        status_code=400,
                        detail=f"Invalid mode for {type_name}: {type_config['mode']}"
                    )

    # Reinitialize the obfuscator with new config
    service.obfuscator.config = config
    service.obfuscator.detector.config = config

    # Return updated settings
    return await get_pii_settings(request, authorization)


@router.get("/types")
async def get_pii_types(request: Request, authorization: str = Header(None)):
    """Get available PII types and obfuscation modes"""
    await require_admin(request, authorization)

    return {
        "types": [
            {"value": t.value, "description": _get_type_description(t)}
            for t in PIIType
        ],
        "modes": [
            {"value": m.value, "description": _get_mode_description(m)}
            for m in ObfuscationMode
        ]
    }


@router.post("/test")
async def test_pii_obfuscation(
    request: Request,
    text: str,
    authorization: str = Header(None)
):
    """Test PII detection and obfuscation on sample text"""
    await require_admin(request, authorization)

    service = get_pii_service()
    obfuscated, matches = service.obfuscate_text(text)

    return {
        "original": text,
        "obfuscated": obfuscated,
        "matches": matches
    }


@router.get("/stats")
async def get_pii_stats(request: Request, authorization: str = Header(None)):
    """Get PII obfuscation statistics"""
    await require_admin(request, authorization)

    service = get_pii_service()
    return service.get_stats()


@router.post("/stats/reset")
async def reset_pii_stats(request: Request, authorization: str = Header(None)):
    """Reset PII statistics"""
    await require_admin(request, authorization)

    service = get_pii_service()
    service.reset_stats()

    return {"success": True, "message": "Statistics reset"}


# ==================== HELPERS ====================

def _get_type_description(pii_type: PIIType) -> str:
    """Get description for a PII type"""
    descriptions = {
        PIIType.CREDIT_CARD: "Credit/Debit card numbers (PCI-DSS)",
        PIIType.SSN: "Social Security Numbers",
        PIIType.EMAIL: "Email addresses",
        PIIType.PHONE: "Phone numbers",
        PIIType.IP_ADDRESS: "IP addresses",
        PIIType.NAME: "Personal names",
        PIIType.ADDRESS: "Physical addresses",
        PIIType.DOB: "Dates of birth",
        PIIType.PASSPORT: "Passport numbers",
        PIIType.DRIVER_LICENSE: "Driver's license numbers",
        PIIType.BANK_ACCOUNT: "Bank account numbers",
    }
    return descriptions.get(pii_type, pii_type.value)


def _get_mode_description(mode: ObfuscationMode) -> str:
    """Get description for an obfuscation mode"""
    descriptions = {
        ObfuscationMode.MASK: "Partial masking - shows last 4 digits (****1234)",
        ObfuscationMode.REDACT: "Full redaction - replaces with [TYPE_REDACTED]",
        ObfuscationMode.HASH: "SHA-256 hash - for correlation without revealing data",
        ObfuscationMode.TOKENIZE: "Reversible token - can be decoded with key",
    }
    return descriptions.get(mode, mode.value)
