# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
License Generator Service

Generates, validates, and manages license keys.
Supports both hosted (database) and BYOC (signed JWT) modes.
"""

import os
import jwt
import json
import secrets
import hashlib
import logging
from datetime import datetime, timedelta
from typing import Dict, Optional, Any
from dataclasses import asdict

from .models import (
    License,
    LicenseTier,
    Entitlements,
)
from .default_plans import get_default_entitlements

logger = logging.getLogger(__name__)

# License signing configuration
LICENSE_SECRET_KEY = os.getenv("LICENSE_SECRET_KEY", "license-secret-change-in-production")
LICENSE_ALGORITHM = "HS256"
LICENSE_ISSUER = "T1 Agentics"


class LicenseGenerator:
    """
    Generates and validates license keys.

    Supports two modes:
    1. Hosted: License stored in database, key is just an ID
    2. BYOC: License is a signed JWT containing all entitlements
    """

    def __init__(self, secret_key: str = None):
        self.secret_key = secret_key or LICENSE_SECRET_KEY

    # =========================================================================
    # LICENSE KEY GENERATION
    # =========================================================================

    def generate_license_id(self) -> str:
        """Generate a unique license ID"""
        return f"lic_{secrets.token_urlsafe(24)}"

    def generate_license_key(self) -> str:
        """
        Generate a human-readable license key.
        Format: XXXX-XXXX-XXXX-XXXX-XXXX
        """
        chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # No I, O, 0, 1 for readability
        segments = []
        for _ in range(5):
            segment = "".join(secrets.choice(chars) for _ in range(4))
            segments.append(segment)
        return "-".join(segments)

    def hash_license_key(self, key: str) -> str:
        """Hash a license key for storage"""
        return hashlib.sha256(key.encode()).hexdigest()

    def validate_license_key_format(self, key: str) -> bool:
        """
        Validate license key format.
        Expected: XXXX-XXXX-XXXX-XXXX-XXXX (5 groups of 4 chars)
        """
        import re
        pattern = r"^[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$"
        return bool(re.match(pattern, key.upper()))

    # =========================================================================
    # HOSTED MODE: Database-backed licenses
    # =========================================================================

    def create_license(
        self,
        tenant_id: str,
        tier: LicenseTier,
        valid_days: int = 365,
        is_trial: bool = False,
        trial_days: int = 14,
        overrides: Dict[str, Any] = None,
        created_by: str = "system",
        notes: str = "",
    ) -> tuple[License, str]:
        """
        Create a new license for a tenant.

        Returns:
            Tuple of (License object, raw license key)
        """
        now = datetime.utcnow()
        license_id = self.generate_license_id()
        license_key = self.generate_license_key()

        # Get base entitlements for tier
        entitlements = get_default_entitlements(tier)

        # Apply any overrides
        if overrides:
            entitlements = self._apply_overrides(entitlements, overrides)

        license = License(
            license_id=license_id,
            tenant_id=tenant_id,
            tier=tier,
            entitlements=entitlements,
            issued_at=now,
            valid_from=now,
            valid_until=now + timedelta(days=valid_days) if valid_days > 0 else None,
            is_active=True,
            is_trial=is_trial,
            trial_ends_at=now + timedelta(days=trial_days) if is_trial else None,
            overrides=overrides or {},
            notes=notes,
            created_by=created_by,
        )

        logger.info(f"Created license {license_id} for tenant {tenant_id}, tier={tier.value}")
        return license, license_key

    def _apply_overrides(self, entitlements: Entitlements, overrides: Dict[str, Any]) -> Entitlements:
        """Apply overrides to base entitlements"""
        ent_dict = entitlements.to_dict()

        for key, value in overrides.items():
            if "." in key:
                # Nested key like "agents.seats_tier3"
                parts = key.split(".")
                target = ent_dict
                for part in parts[:-1]:
                    if part in target:
                        target = target[part]
                if parts[-1] in target:
                    target[parts[-1]] = value
            else:
                if key in ent_dict:
                    ent_dict[key] = value

        return Entitlements.from_dict(ent_dict)

    # =========================================================================
    # BYOC MODE: Signed JWT licenses
    # =========================================================================

    def generate_signed_license(
        self,
        tenant_id: str,
        tier: LicenseTier,
        valid_days: int = 365,
        overrides: Dict[str, Any] = None,
    ) -> str:
        """
        Generate a signed JWT license for BYOC deployments.

        The JWT contains all entitlements, allowing offline validation.
        """
        now = datetime.utcnow()
        license_id = self.generate_license_id()

        # Get entitlements
        entitlements = get_default_entitlements(tier)
        if overrides:
            entitlements = self._apply_overrides(entitlements, overrides)

        payload = {
            "iss": LICENSE_ISSUER,
            "sub": tenant_id,
            "lic": license_id,
            "tier": tier.value,
            "ent": entitlements.to_dict(),
            "iat": int(now.timestamp()),
            "nbf": int(now.timestamp()),
            "exp": int((now + timedelta(days=valid_days)).timestamp()) if valid_days > 0 else None,
        }

        token = jwt.encode(payload, self.secret_key, algorithm=LICENSE_ALGORITHM)
        logger.info(f"Generated signed license {license_id} for tenant {tenant_id}")
        return token

    def validate_signed_license(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Validate a signed JWT license.

        Returns:
            License payload if valid, None if invalid
        """
        try:
            payload = jwt.decode(
                token,
                self.secret_key,
                algorithms=[LICENSE_ALGORITHM],
                issuer=LICENSE_ISSUER,
            )
            return payload
        except jwt.ExpiredSignatureError:
            logger.warning("License token has expired")
            return None
        except jwt.InvalidTokenError as e:
            logger.warning(f"Invalid license token: {e}")
            return None

    def decode_signed_license(self, token: str) -> Optional[License]:
        """
        Decode a signed license into a License object.
        """
        payload = self.validate_signed_license(token)
        if not payload:
            return None

        return License(
            license_id=payload["lic"],
            tenant_id=payload["sub"],
            tier=LicenseTier(payload["tier"]),
            entitlements=Entitlements.from_dict(payload["ent"]),
            issued_at=datetime.fromtimestamp(payload["iat"]),
            valid_from=datetime.fromtimestamp(payload["nbf"]),
            valid_until=datetime.fromtimestamp(payload["exp"]) if payload.get("exp") else None,
            is_active=True,
        )

    # =========================================================================
    # LICENSE MODIFICATION
    # =========================================================================

    def upgrade_license(
        self,
        current_license: License,
        new_tier: LicenseTier,
        additional_overrides: Dict[str, Any] = None,
    ) -> License:
        """
        Upgrade a license to a new tier while preserving overrides.
        """
        # Get new tier's entitlements
        new_entitlements = get_default_entitlements(new_tier)

        # Merge existing overrides with any new ones
        merged_overrides = {**current_license.overrides}
        if additional_overrides:
            merged_overrides.update(additional_overrides)

        # Apply overrides
        if merged_overrides:
            new_entitlements = self._apply_overrides(new_entitlements, merged_overrides)

        # Create upgraded license
        upgraded = License(
            license_id=current_license.license_id,
            tenant_id=current_license.tenant_id,
            tier=new_tier,
            entitlements=new_entitlements,
            issued_at=current_license.issued_at,
            valid_from=current_license.valid_from,
            valid_until=current_license.valid_until,
            is_active=True,
            is_trial=False,  # Upgrades are never trials
            overrides=merged_overrides,
            notes=f"Upgraded from {current_license.tier.value} to {new_tier.value}",
            created_by=current_license.created_by,
        )

        logger.info(f"Upgraded license {current_license.license_id} from {current_license.tier.value} to {new_tier.value}")
        return upgraded

    def add_override(
        self,
        license: License,
        override_key: str,
        override_value: Any,
    ) -> License:
        """
        Add a single override to an existing license.
        """
        new_overrides = {**license.overrides, override_key: override_value}
        new_entitlements = self._apply_overrides(
            get_default_entitlements(license.tier),
            new_overrides
        )

        license.overrides = new_overrides
        license.entitlements = new_entitlements

        logger.info(f"Added override {override_key}={override_value} to license {license.license_id}")
        return license

    # =========================================================================
    # LICENSE INFO
    # =========================================================================

    def get_license_summary(self, license: License) -> Dict[str, Any]:
        """Get a summary of a license for display"""
        now = datetime.utcnow()

        # Calculate days remaining
        days_remaining = None
        if license.valid_until:
            days_remaining = (license.valid_until - now).days

        trial_days_remaining = None
        if license.is_trial and license.trial_ends_at:
            trial_days_remaining = (license.trial_ends_at - now).days

        return {
            "license_id": license.license_id,
            "tenant_id": license.tenant_id,
            "tier": license.tier.value,
            "is_active": license.is_active,
            "is_trial": license.is_trial,
            "days_remaining": days_remaining,
            "trial_days_remaining": trial_days_remaining,
            "issued_at": license.issued_at.isoformat() if license.issued_at else None,
            "valid_until": license.valid_until.isoformat() if license.valid_until else None,
            "has_overrides": bool(license.overrides),
            "entitlements_summary": {
                "investigations_per_month": license.entitlements.investigations_per_month,
                "automation_runs_per_month": license.entitlements.automation_runs_per_month,
                "max_users": license.entitlements.max_users,
                "data_retention_days": license.entitlements.data_retention_days,
            },
        }


# Global instance
_license_generator: Optional[LicenseGenerator] = None


def get_license_generator() -> LicenseGenerator:
    """Get or create the global license generator instance"""
    global _license_generator
    if _license_generator is None:
        _license_generator = LicenseGenerator()
    return _license_generator
