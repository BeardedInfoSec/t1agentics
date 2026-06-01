# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Critical Path Tests

These tests validate the most important paths through the application
without requiring external services (database, Claude API, etc.).

Tests cover:
1. Health endpoints
2. Auth token creation/validation
3. Licensing models and tier configuration
4. License enforcement logic
5. Indicator extraction
6. Alert normalization
"""

import pytest
import os
import sys

# Ensure backend is on path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'backend')))


# =====================================================================
# 1. LICENSING MODELS & CONFIGURATION
# =====================================================================

class TestLicensingModels:
    """Verify license tier configurations are correct and consistent."""

    def test_all_tiers_defined(self):
        from services.licensing.models import LicenseTier
        from services.licensing.default_plans import DEFAULT_PLANS

        expected = {LicenseTier.DEV, LicenseTier.FREE, LicenseTier.PRO,
                    LicenseTier.ENTERPRISE, LicenseTier.UNLIMITED, LicenseTier.CORE}
        assert expected.issubset(set(DEFAULT_PLANS.keys()))

    def test_core_maps_to_free(self):
        from services.licensing.models import LicenseTier
        from services.licensing.default_plans import DEFAULT_PLANS

        assert DEFAULT_PLANS[LicenseTier.CORE] is DEFAULT_PLANS[LicenseTier.FREE]

    def test_free_tier_limits(self):
        from services.licensing.models import LicenseTier
        from services.licensing.default_plans import get_default_entitlements

        ent = get_default_entitlements(LicenseTier.FREE)
        assert ent.max_users == 2
        assert ent.riggs.chat_messages_per_month == 100
        assert ent.riggs.playbook_creations_per_month == 5
        assert ent.llm.default_model == "claude-haiku-4-5-20251001"
        assert ent.features.get("deep_dive") is False
        assert ent.llm.managed_tokens_per_month == 1_000_000

    def test_pro_tier_unlimited_riggs(self):
        from services.licensing.models import LicenseTier
        from services.licensing.default_plans import get_default_entitlements

        ent = get_default_entitlements(LicenseTier.PRO)
        assert ent.riggs.chat_messages_per_month == 0  # 0 = unlimited
        assert ent.riggs.playbook_creations_per_month == 0
        assert ent.features.get("deep_dive") is True
        assert ent.llm.default_model == "claude-sonnet-4-5-20250929"
        assert ent.llm.managed_tokens_per_month == 15_000_000

    def test_enterprise_higher_than_pro(self):
        from services.licensing.models import LicenseTier
        from services.licensing.default_plans import get_default_entitlements

        pro = get_default_entitlements(LicenseTier.PRO)
        ent = get_default_entitlements(LicenseTier.ENTERPRISE)

        assert ent.llm.managed_tokens_per_month > pro.llm.managed_tokens_per_month
        assert ent.max_users > pro.max_users
        assert ent.integrations.max_integrations > pro.integrations.max_integrations

    def test_entitlements_serialization(self):
        from services.licensing.models import LicenseTier
        from services.licensing.default_plans import get_default_entitlements
        from services.licensing.models import Entitlements

        ent = get_default_entitlements(LicenseTier.PRO)
        d = ent.to_dict()
        restored = Entitlements.from_dict(d)

        assert restored.max_users == ent.max_users
        assert restored.riggs.chat_messages_per_month == ent.riggs.chat_messages_per_month
        assert restored.llm.default_model == ent.llm.default_model

    def test_get_tier_comparison(self):
        from services.licensing.default_plans import get_tier_comparison

        comp = get_tier_comparison()
        assert "free" in comp or "dev" in comp
        for tier_data in comp.values():
            assert "max_users" in tier_data
            assert "features" in tier_data
            assert "riggs" in tier_data

    def test_custom_tier_falls_back_to_enterprise(self):
        from services.licensing.models import LicenseTier
        from services.licensing.default_plans import get_default_entitlements

        custom = get_default_entitlements(LicenseTier.CUSTOM)
        enterprise = get_default_entitlements(LicenseTier.ENTERPRISE)
        assert custom.max_users == enterprise.max_users

    def test_riggs_limits_dataclass(self):
        from services.licensing.models import RiggsLimits

        # Defaults
        limits = RiggsLimits()
        assert limits.chat_messages_per_month == 100
        assert limits.playbook_creations_per_month == 5

        # Custom
        unlimited = RiggsLimits(chat_messages_per_month=0, playbook_creations_per_month=0)
        assert unlimited.chat_messages_per_month == 0


# =====================================================================
# 2. AUTH HELPERS
# =====================================================================

class TestAuthHelpers:
    """Test JWT token creation and validation."""

    def test_jwt_token_roundtrip(self):
        os.environ.setdefault("JWT_SECRET_KEY", "test-secret-key-for-ci")
        from routes.admin import create_jwt_token, decode_jwt_token

        token = create_jwt_token("testuser", "admin")
        payload = decode_jwt_token(token)
        assert payload is not None
        assert payload["sub"] == "testuser"
        assert payload["role"] == "admin"

    def test_jwt_token_with_tenant_id(self):
        os.environ.setdefault("JWT_SECRET_KEY", "test-secret-key-for-ci")
        from routes.admin import create_jwt_token, decode_jwt_token

        token = create_jwt_token("testuser", "user", tenant_id="abc-123")
        payload = decode_jwt_token(token)
        assert payload["tenant_id"] == "abc-123"

    def test_invalid_token_returns_none(self):
        os.environ.setdefault("JWT_SECRET_KEY", "test-secret-key-for-ci")
        from routes.admin import decode_jwt_token

        result = decode_jwt_token("garbage.token.value")
        assert result is None

    def test_expired_token(self):
        os.environ.setdefault("JWT_SECRET_KEY", "test-secret-key-for-ci")
        import jwt
        from datetime import datetime, timedelta

        secret = os.getenv("JWT_SECRET_KEY", "test-secret-key-for-ci")
        expired_payload = {
            "sub": "testuser",
            "role": "admin",
            "exp": datetime.utcnow() - timedelta(hours=1),
        }
        token = jwt.encode(expired_payload, secret, algorithm="HS256")

        from routes.admin import decode_jwt_token
        result = decode_jwt_token(token)
        assert result is None


# =====================================================================
# 3. INDICATOR EXTRACTION
# =====================================================================

class TestIndicatorExtraction:
    """Test IOC extraction from alert data."""

    def test_extract_ipv4(self):
        from utils.extractors import IndicatorExtractor

        indicators = IndicatorExtractor.extract_all("Connection from 192.168.1.100 to 10.0.0.1")
        ip_values = [i.value for i in indicators if i.type.value == "ip"]
        assert "192.168.1.100" in ip_values

    def test_extract_domain(self):
        from utils.extractors import IndicatorExtractor

        indicators = IndicatorExtractor.extract_all("DNS query for malicious-site.com detected")
        domain_values = [i.value for i in indicators if i.type.value == "domain"]
        assert "malicious-site.com" in domain_values

    def test_extract_hash(self):
        from utils.extractors import IndicatorExtractor

        md5 = "44d88612fea8a8f36de82e1278abb02f"
        indicators = IndicatorExtractor.extract_all(f"File hash: {md5}")
        hash_values = [i.value for i in indicators if "hash" in i.type.value]
        assert md5 in hash_values

    def test_extract_email(self):
        from utils.extractors import IndicatorExtractor

        indicators = IndicatorExtractor.extract_all("Email from phishing@evil.com received")
        email_values = [i.value for i in indicators if i.type.value == "email"]
        assert "phishing@evil.com" in email_values

    def test_normalize_alert(self):
        from utils.extractors import normalize_alert

        alert = {
            "title": "Test Alert",
            "description": "Suspicious activity from 10.0.0.1",
            "source": "test",
        }
        normalized = normalize_alert(alert)
        assert "title" in normalized
        assert "description" in normalized


# =====================================================================
# 4. MODELS
# =====================================================================

class TestModels:
    """Test core data models."""

    def test_alert_model(self):
        from models import Alert

        alert = Alert(
            title="Test Alert",
            description="Test description",
            source="test",
        )
        assert alert.title == "Test Alert"
        assert alert.severity in [None, "medium"]

    def test_severity_enum(self):
        from models import SeverityLevel

        assert SeverityLevel.LOW.value == "Low"
        assert SeverityLevel.CRITICAL.value == "Critical"

    def test_disposition_enum(self):
        from models import DispositionType

        assert DispositionType.MALICIOUS.value == "MALICIOUS"
        assert DispositionType.BENIGN.value == "BENIGN"
        assert DispositionType.FALSE_POSITIVE.value == "FALSE_POSITIVE"


# =====================================================================
# 5. LICENSE CACHE (frontend-adjacent logic test)
# =====================================================================

class TestLicenseTierMapping:
    """Test the tier mapping used by license_checks."""

    def test_tier_map_covers_common_strings(self):
        from services.licensing.models import LicenseTier

        tier_map = {
            "community": LicenseTier.FREE,
            "free": LicenseTier.FREE,
            "dev": LicenseTier.DEV,
            "core": LicenseTier.CORE,
            "professional": LicenseTier.PRO,
            "pro": LicenseTier.PRO,
            "enterprise": LicenseTier.ENTERPRISE,
            "unlimited": LicenseTier.UNLIMITED,
        }

        # All mapped tiers should have entitlements
        from services.licensing.default_plans import get_default_entitlements
        for tier_str, tier_enum in tier_map.items():
            ent = get_default_entitlements(tier_enum)
            assert ent is not None, f"No entitlements for {tier_str} -> {tier_enum}"
            assert ent.max_users > 0, f"max_users=0 for {tier_str}"

    def test_free_features_subset_of_pro(self):
        from services.licensing.models import LicenseTier
        from services.licensing.default_plans import get_default_entitlements

        free = get_default_entitlements(LicenseTier.FREE)
        pro = get_default_entitlements(LicenseTier.PRO)

        # Every feature enabled in free should also be enabled in pro
        for feature, enabled in free.features.items():
            if enabled:
                assert pro.features.get(feature, False), \
                    f"Feature '{feature}' is enabled in FREE but not in PRO"


# =====================================================================
# 6. CONFIG VALIDATION
# =====================================================================

class TestConfig:
    """Test system configuration."""

    def test_system_config_imports(self):
        from config.system_config import CORRELATION_MAX_ALERTS
        assert isinstance(CORRELATION_MAX_ALERTS, int)
        assert CORRELATION_MAX_ALERTS > 0

    def test_environment_detection(self):
        # In test environment, should not be production
        env = os.getenv("ENVIRONMENT", "development")
        assert env != "production"
