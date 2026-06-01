# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
License Manager

Handles license validation, activation, and usage tracking.
Supports tiered licensing: Community, POC, Professional, Enterprise, Enterprise Plus.

License Key Format:
    T1A-{TIER}-{TIMESTAMP}-{SIGNATURE}
    Example: T1A-PRO-1738800000-a1b2c3d4e5f6

Tiers:
    - COMMUNITY: Free, 50 alerts/day, 5 playbooks, 10 integrations, 50k IOCs, 3 feeds
    - POC: Proof of Concept, 30 days, 250 alerts/day, 10 playbooks, 250k IOCs, 10 feeds
    - PROFESSIONAL: $2,499/mo, 250 alerts/day, 10 playbooks, 40 integrations, 500k IOCs (add-on available), unlimited feeds
    - ENTERPRISE: Custom pricing, 1000 alerts/day, 100 playbooks, 50 users, unlimited IOCs, unlimited feeds
    - ENTERPRISE_PLUS: Custom pricing, unlimited everything, dedicated support, unlimited IOCs, unlimited feeds
"""

import hashlib
import hmac
import json
import logging
import os
import time
from dataclasses import dataclass, asdict
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Any, Dict, Optional, Tuple
from pathlib import Path

logger = logging.getLogger(__name__)

# License signing key - MUST be kept secret
LICENSE_SECRET_KEY = os.environ.get(
    "LICENSE_SECRET_KEY",
    "T1-AGENTICS-LICENSE-KEY-CHANGE-IN-PRODUCTION"
)

# License file location
LICENSE_FILE_PATH = os.environ.get(
    "LICENSE_FILE_PATH",
    str(Path(__file__).parent.parent / "license.key")
)


class LicenseTier(str, Enum):
    """License tier levels."""
    COMMUNITY = "community"
    POC = "poc"
    PROFESSIONAL = "professional"
    ENTERPRISE = "enterprise"
    ENTERPRISE_PLUS = "enterprise_plus"
    INVALID = "invalid"


@dataclass
class LicenseLimits:
    """Limits for each license tier."""
    alerts_per_day: int
    playbooks_max: int
    integrations_max: int
    users_max: int
    ai_queries_per_day: int
    retention_days: int
    iocs_max: int  # Max IOCs stored; -1 = unlimited. Oldest evicted when cap reached.
    feeds_max: int  # Max enabled threat feeds; -1 = unlimited.
    support_level: str
    features: list


# Define limits for each tier
TIER_LIMITS: Dict[LicenseTier, LicenseLimits] = {
    LicenseTier.COMMUNITY: LicenseLimits(
        alerts_per_day=10,
        playbooks_max=2,
        integrations_max=-1,  # Unlimited
        users_max=5,
        ai_queries_per_day=5,
        retention_days=30,
        iocs_max=10_000,
        feeds_max=1,
        support_level="community",
        features=["basic_alerts", "basic_playbooks", "basic_enrichment"]
    ),
    LicenseTier.POC: LicenseLimits(
        # POC: Mid-tier features for 30-day evaluation
        alerts_per_day=250,
        playbooks_max=10,
        integrations_max=10,
        users_max=5,
        ai_queries_per_day=100,
        retention_days=30,
        iocs_max=250_000,
        feeds_max=10,
        support_level="email",
        features=[
            "basic_alerts", "basic_playbooks", "basic_enrichment",
            "advanced_playbooks", "custom_integrations", "api_access",
            "scheduled_playbooks", "approval_workflows"
        ]
    ),
    LicenseTier.PROFESSIONAL: LicenseLimits(
        # Professional: $2,499/mo
        alerts_per_day=500,
        playbooks_max=-1,  # Unlimited
        integrations_max=-1,  # Unlimited
        users_max=25,
        ai_queries_per_day=5_000,
        retention_days=365,
        iocs_max=500_000,
        feeds_max=-1,  # Unlimited feeds
        support_level="email",
        features=[
            "basic_alerts", "basic_playbooks", "basic_enrichment",
            "advanced_playbooks", "custom_integrations", "api_access",
            "scheduled_playbooks", "approval_workflows",
            "sso", "audit_logs", "sla"
        ]
    ),
    LicenseTier.ENTERPRISE: LicenseLimits(
        # Enterprise: $7,499/mo
        alerts_per_day=2_500,
        playbooks_max=-1,  # Unlimited
        integrations_max=-1,  # Unlimited integrations
        users_max=100,
        ai_queries_per_day=25_000,
        retention_days=365,
        iocs_max=-1,  # Unlimited IOCs
        feeds_max=-1,  # Unlimited feeds
        support_level="priority",
        features=[
            "basic_alerts", "basic_playbooks", "basic_enrichment",
            "advanced_playbooks", "custom_integrations", "api_access",
            "scheduled_playbooks", "approval_workflows",
            "sso", "audit_logs", "sla_guarantee"
        ]
    ),
    LicenseTier.ENTERPRISE_PLUS: LicenseLimits(
        # Enterprise Plus: $19,999/mo ($240K/yr)
        alerts_per_day=10_000,
        playbooks_max=-1,  # Unlimited
        integrations_max=-1,
        users_max=-1,  # Unlimited
        ai_queries_per_day=100_000,
        retention_days=365,
        iocs_max=-1,  # Unlimited IOCs
        feeds_max=-1,  # Unlimited feeds
        support_level="dedicated",
        features=[
            "basic_alerts", "basic_playbooks", "basic_enrichment",
            "advanced_playbooks", "custom_integrations", "api_access",
            "scheduled_playbooks", "approval_workflows",
            "multi_tenant", "sso", "audit_logs", "custom_branding",
            "dedicated_support", "sla_guarantee", "onprem_deployment",
            "white_label"
        ]
    ),
    LicenseTier.INVALID: LicenseLimits(
        alerts_per_day=0,
        playbooks_max=0,
        integrations_max=0,
        users_max=0,
        ai_queries_per_day=0,
        retention_days=0,
        iocs_max=0,
        feeds_max=0,
        support_level="none",
        features=[]
    )
}


@dataclass
class License:
    """License information."""
    tier: LicenseTier
    organization: str
    email: str
    issued_at: datetime
    expires_at: Optional[datetime]
    license_key: str
    limits: LicenseLimits
    is_valid: bool
    validation_message: str
    ioc_addon_capacity: int = 0  # Additional IOC capacity purchased as add-on


@dataclass
class UsageStats:
    """Current usage statistics."""
    alerts_today: int
    playbooks_count: int
    integrations_count: int
    users_count: int
    ai_queries_today: int
    iocs_count: int = 0
    feeds_count: int = 0
    date: str = ""


class LicenseManager:
    """
    Manages license validation and usage tracking.
    """

    def __init__(self):
        self._license: Optional[License] = None
        self._usage: Optional[UsageStats] = None
        self._usage_file = Path(__file__).parent.parent / ".usage_stats.json"
        self._load_license()
        self._load_usage()

    def _load_license(self) -> None:
        """Load license from file."""
        try:
            license_path = Path(LICENSE_FILE_PATH)
            if license_path.exists():
                license_key = license_path.read_text().strip()
                self._license = self._validate_license_key(license_key)
                if self._license.is_valid:
                    logger.info(f"License loaded: {self._license.tier.value} tier for {self._license.organization}")
                else:
                    logger.warning(f"Invalid license: {self._license.validation_message}")
            else:
                # No license file - use community tier
                self._license = self._create_community_license()
                logger.info("No license file found. Using Community license.")
        except Exception as e:
            logger.error(f"Error loading license: {e}")
            self._license = self._create_community_license()

    def _load_usage(self) -> None:
        """Load usage stats from file."""
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        try:
            if self._usage_file.exists():
                data = json.loads(self._usage_file.read_text())
                if data.get("date") == today:
                    self._usage = UsageStats(**data)
                else:
                    # New day, reset counters
                    self._usage = self._create_empty_usage(today)
            else:
                self._usage = self._create_empty_usage(today)
        except Exception as e:
            logger.error(f"Error loading usage stats: {e}")
            self._usage = self._create_empty_usage(today)

    def _create_empty_usage(self, date: str) -> UsageStats:
        """Create empty usage stats for today."""
        return UsageStats(
            alerts_today=0,
            playbooks_count=0,
            integrations_count=0,
            users_count=0,
            ai_queries_today=0,
            iocs_count=0,
            feeds_count=0,
            date=date
        )

    def _save_usage(self) -> None:
        """Save usage stats to file."""
        try:
            self._usage_file.write_text(json.dumps(asdict(self._usage), indent=2))
        except Exception as e:
            logger.error(f"Error saving usage stats: {e}")

    def _create_community_license(self) -> License:
        """Create a default community license."""
        now = datetime.now(timezone.utc)
        return License(
            tier=LicenseTier.COMMUNITY,
            organization="Community User",
            email="",
            issued_at=now,
            expires_at=None,  # Community never expires
            license_key="",
            limits=TIER_LIMITS[LicenseTier.COMMUNITY],
            is_valid=True,
            validation_message="Community license active"
        )

    def _validate_license_key(self, license_key: str) -> License:
        """Validate a license key and return License object."""
        try:
            # License format: T1A-{TIER}-{ORG_HASH}-{EXPIRY}-{SIGNATURE}
            parts = license_key.strip().split("-")
            if len(parts) < 5 or parts[0] != "T1A":
                return self._invalid_license("Invalid license format")

            tier_code = parts[1].upper()
            org_hash = parts[2]
            expiry_ts = int(parts[3])
            signature = parts[4]

            # Map tier code
            tier_map = {
                "COM": LicenseTier.COMMUNITY,
                "POC": LicenseTier.POC,
                "PRO": LicenseTier.PROFESSIONAL,
                "ENT": LicenseTier.ENTERPRISE,
                "ENP": LicenseTier.ENTERPRISE_PLUS
            }
            tier = tier_map.get(tier_code)
            if not tier:
                return self._invalid_license("Unknown license tier")

            # Verify signature
            message = f"T1A-{tier_code}-{org_hash}-{expiry_ts}"
            expected_sig = hmac.new(
                LICENSE_SECRET_KEY.encode(),
                message.encode(),
                hashlib.sha256
            ).hexdigest()[:16]

            if not hmac.compare_digest(signature.lower(), expected_sig.lower()):
                return self._invalid_license("Invalid license signature")

            # Check expiry
            now = datetime.now(timezone.utc)
            expires_at = datetime.fromtimestamp(expiry_ts, tz=timezone.utc)
            if now > expires_at:
                return self._invalid_license(f"License expired on {expires_at.strftime('%Y-%m-%d')}")

            return License(
                tier=tier,
                organization=f"Licensed ({org_hash[:8]})",
                email="",
                issued_at=now,
                expires_at=expires_at,
                license_key=license_key,
                limits=TIER_LIMITS[tier],
                is_valid=True,
                validation_message=f"{tier.value.title()} license valid until {expires_at.strftime('%Y-%m-%d')}"
            )

        except Exception as e:
            logger.error(f"License validation error: {e}")
            return self._invalid_license(f"License validation failed: {str(e)}")

    def _invalid_license(self, message: str) -> License:
        """Create an invalid license response."""
        now = datetime.now(timezone.utc)
        return License(
            tier=LicenseTier.INVALID,
            organization="",
            email="",
            issued_at=now,
            expires_at=None,
            license_key="",
            limits=TIER_LIMITS[LicenseTier.INVALID],
            is_valid=False,
            validation_message=message
        )

    # =========================================================================
    # Public API
    # =========================================================================

    def get_license(self) -> License:
        """Get current license information."""
        if self._license is None:
            self._load_license()
        return self._license

    def get_usage(self) -> UsageStats:
        """Get current usage statistics."""
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        if self._usage is None or self._usage.date != today:
            self._load_usage()
        return self._usage

    def activate_license(self, license_key: str) -> Tuple[bool, str]:
        """
        Activate a new license key.

        Returns:
            Tuple of (success, message)
        """
        license_obj = self._validate_license_key(license_key)

        if not license_obj.is_valid:
            return False, license_obj.validation_message

        # Save to file
        try:
            Path(LICENSE_FILE_PATH).write_text(license_key.strip())
            self._license = license_obj
            logger.info(f"License activated: {license_obj.tier.value} for {license_obj.organization}")
            return True, f"License activated: {license_obj.tier.value.title()} tier"
        except Exception as e:
            logger.error(f"Error saving license: {e}")
            return False, f"Failed to save license: {str(e)}"

    def check_limit(self, resource: str, increment: int = 0) -> Tuple[bool, str]:
        """
        Check if a resource limit allows the operation.

        Args:
            resource: One of 'alerts', 'playbooks', 'integrations', 'users', 'ai_queries', 'feeds', 'iocs'
            increment: Amount to add (for creating new resources)

        Returns:
            Tuple of (allowed, message)
        """
        license_obj = self.get_license()
        usage = self.get_usage()

        if not license_obj.is_valid:
            return False, "No valid license. Please activate a license to continue."

        limits = license_obj.limits

        if resource == "alerts":
            limit = limits.alerts_per_day
            current = usage.alerts_today + increment
            if limit != -1 and current > limit:
                return False, f"Daily alert limit reached ({limit}/day). Upgrade to process more alerts."

        elif resource == "playbooks":
            limit = limits.playbooks_max
            current = usage.playbooks_count + increment
            if limit != -1 and current > limit:
                return False, f"Playbook limit reached ({limit} max). Upgrade to create more playbooks."

        elif resource == "integrations":
            limit = limits.integrations_max
            current = usage.integrations_count + increment
            if limit != -1 and current > limit:
                return False, f"Integration limit reached ({limit} max). Upgrade to add more integrations."

        elif resource == "users":
            limit = limits.users_max
            current = usage.users_count + increment
            if limit != -1 and current > limit:
                return False, f"User limit reached ({limit} max). Upgrade to add more users."

        elif resource == "ai_queries":
            limit = limits.ai_queries_per_day
            current = usage.ai_queries_today + increment
            if limit != -1 and current > limit:
                return False, f"Daily AI query limit reached ({limit}/day). Upgrade for more AI capabilities."

        elif resource == "feeds":
            limit = limits.feeds_max
            current = usage.feeds_count + increment
            if limit != -1 and current > limit:
                return False, f"Feed limit reached ({limit} max). Upgrade to enable more threat feeds."

        elif resource == "iocs":
            # IOC limit includes add-on capacity
            effective_limit = limits.iocs_max
            if effective_limit != -1:
                effective_limit += license_obj.ioc_addon_capacity
            current = usage.iocs_count + increment
            if effective_limit != -1 and current > effective_limit:
                return False, f"IOC limit reached ({effective_limit} max). Upgrade or purchase an IOC add-on for more capacity."

        return True, "OK"

    def record_usage(self, resource: str, count: int = 1) -> None:
        """Record resource usage."""
        usage = self.get_usage()

        if resource == "alerts":
            usage.alerts_today += count
        elif resource == "playbooks":
            usage.playbooks_count += count
        elif resource == "integrations":
            usage.integrations_count += count
        elif resource == "users":
            usage.users_count += count
        elif resource == "ai_queries":
            usage.ai_queries_today += count
        elif resource == "feeds":
            usage.feeds_count += count
        elif resource == "iocs":
            usage.iocs_count += count

        self._save_usage()

    def update_counts(self, playbooks: int = None, integrations: int = None,
                       users: int = None, feeds: int = None, iocs: int = None) -> None:
        """Update absolute counts (called periodically to sync with DB)."""
        usage = self.get_usage()
        if playbooks is not None:
            usage.playbooks_count = playbooks
        if integrations is not None:
            usage.integrations_count = integrations
        if users is not None:
            usage.users_count = users
        if feeds is not None:
            usage.feeds_count = feeds
        if iocs is not None:
            usage.iocs_count = iocs
        self._save_usage()

    def set_ioc_addon(self, additional_capacity: int) -> None:
        """
        Set additional IOC capacity purchased as an add-on.

        This is primarily used for the Professional tier where customers
        can purchase additional IOC capacity beyond the base 500k limit.

        Args:
            additional_capacity: Number of additional IOCs allowed (e.g. 500_000 for +500k)
        """
        license_obj = self.get_license()
        license_obj.ioc_addon_capacity = additional_capacity
        logger.info(f"IOC add-on capacity set to {additional_capacity:,} "
                     f"(effective limit: {license_obj.limits.iocs_max + additional_capacity:,})")

    def has_feature(self, feature: str) -> bool:
        """Check if current license includes a feature."""
        license_obj = self.get_license()
        return feature in license_obj.limits.features

    def get_status(self) -> Dict[str, Any]:
        """Get full license status for API response."""
        license_obj = self.get_license()
        usage = self.get_usage()

        return {
            "license": {
                "tier": license_obj.tier.value,
                "organization": license_obj.organization,
                "is_valid": license_obj.is_valid,
                "message": license_obj.validation_message,
                "expires_at": license_obj.expires_at.isoformat() if license_obj.expires_at else None,
            },
            "limits": asdict(license_obj.limits),
            "usage": asdict(usage),
            "features": license_obj.limits.features
        }


# Generate license key (for admin use only)
def generate_license_key(
    tier: LicenseTier,
    organization: str,
    days_valid: int = 365
) -> str:
    """
    Generate a signed license key.

    This function should only be called by T1 Agentics licensing system.
    """
    tier_codes = {
        LicenseTier.COMMUNITY: "COM",
        LicenseTier.POC: "POC",
        LicenseTier.PROFESSIONAL: "PRO",
        LicenseTier.ENTERPRISE: "ENT",
        LicenseTier.ENTERPRISE_PLUS: "ENP"
    }

    tier_code = tier_codes[tier]
    org_hash = hashlib.sha256(organization.encode()).hexdigest()[:12]
    expiry_ts = int((datetime.now(timezone.utc) + timedelta(days=days_valid)).timestamp())

    message = f"T1A-{tier_code}-{org_hash}-{expiry_ts}"
    signature = hmac.new(
        LICENSE_SECRET_KEY.encode(),
        message.encode(),
        hashlib.sha256
    ).hexdigest()[:16]

    return f"{message}-{signature}"


# Singleton instance
_license_manager: Optional[LicenseManager] = None


def get_license_manager() -> LicenseManager:
    """Get singleton license manager instance."""
    global _license_manager
    if _license_manager is None:
        _license_manager = LicenseManager()
    return _license_manager
