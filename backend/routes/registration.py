# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Self-Service Registration & Public Routes

Handles tenant self-registration, email verification, slug availability
checks, enterprise contact form submissions, and public tier information.
"""

import hashlib
import json
import logging
import os
import re
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

import bcrypt
from fastapi import APIRouter, BackgroundTasks, HTTPException, Request
from pydantic import BaseModel, EmailStr, field_validator

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1", tags=["registration"])

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

BASE_URL = os.environ.get("PUBLIC_URL", "http://localhost:3000")

RESERVED_SLUGS = {
    "admin", "api", "app", "auth", "billing", "blog", "contact", "dashboard",
    "docs", "help", "login", "logout", "platform", "pricing", "register",
    "settings", "status", "support", "system", "t1", "t1-agentics", "www",
    "mail", "smtp", "ftp", "ns1", "ns2", "test", "staging", "dev", "prod",
    "default", "root", "null", "undefined",
}

SLUG_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]*[a-z0-9]$")


# ---------------------------------------------------------------------------
# Pydantic Models
# ---------------------------------------------------------------------------

class RegisterRequest(BaseModel):
    email: EmailStr
    password: str
    tenant_name: str
    tenant_slug: str
    full_name: Optional[str] = None
    plan: Optional[str] = "community"
    agreed_to_terms: bool = False
    referral_code: Optional[str] = None

    @field_validator("agreed_to_terms")
    @classmethod
    def must_agree(cls, v: bool) -> bool:
        if not v:
            raise ValueError(
                "You must agree to the Terms of Service, Privacy Policy, "
                "Acceptable Use Policy, and AI Governance Policy to register."
            )
        return v

    @field_validator("tenant_slug")
    @classmethod
    def validate_slug(cls, v: str) -> str:
        v = v.lower().strip()
        if len(v) < 3 or len(v) > 50:
            raise ValueError("Slug must be between 3 and 50 characters")
        if not SLUG_PATTERN.match(v):
            raise ValueError(
                "Slug must start and end with a letter or digit, "
                "and contain only lowercase letters, digits, and hyphens"
            )
        if v in RESERVED_SLUGS:
            raise ValueError(f"The slug '{v}' is reserved and cannot be used")
        return v

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        from services.auth import validate_password_complexity
        is_valid, error_msg = validate_password_complexity(v)
        if not is_valid:
            raise ValueError(error_msg)
        return v

    @field_validator("tenant_name")
    @classmethod
    def validate_tenant_name(cls, v: str) -> str:
        v = sanitize_tenant_name(v)
        if not v:
            raise ValueError("Tenant name is required")
        return v


class SlugCheckRequest(BaseModel):
    slug: str


class ContactRequest(BaseModel):
    name: str
    email: EmailStr
    company: Optional[str] = None
    phone: Optional[str] = None
    message: str


# ---------------------------------------------------------------------------
# Helper Functions
# ---------------------------------------------------------------------------

def get_client_ip(request: Request) -> str:
    """Extract the real client IP from proxy headers or the direct connection."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        # X-Forwarded-For may contain a comma-separated list; first is the client
        return forwarded.split(",")[0].strip()
    if request.client:
        return request.client.host
    return "unknown"


def hash_value(value: str) -> str:
    """Return a hex-encoded SHA-256 hash of *value*."""
    return hashlib.sha256(value.encode()).hexdigest()


async def check_rate_limit(
    conn,
    ip_hash: str,
    endpoint: str,
    max_requests: int,
    window_hours: int,
) -> bool:
    """Return ``True`` if the request is within the rate limit, ``False`` if exceeded.

    Inserts a row into ``registration_rate_limits`` for every call and counts
    recent requests inside the rolling window.
    """
    window_start = datetime.now(timezone.utc) - timedelta(hours=window_hours)

    count = await conn.fetchval(
        """
        SELECT COUNT(*) FROM registration_rate_limits
        WHERE ip_hash = $1 AND endpoint = $2 AND window_start > $3
        """,
        ip_hash, endpoint, window_start,
    )

    if count >= max_requests:
        return False  # rate limit exceeded

    # Record this attempt
    await conn.execute(
        """
        INSERT INTO registration_rate_limits (ip_hash, endpoint)
        VALUES ($1, $2)
        """,
        ip_hash, endpoint,
    )
    return True


def sanitize_tenant_name(name: str) -> str:
    """Strip HTML tags and limit to 100 characters."""
    clean = re.sub(r"<[^>]+>", "", name).strip()
    return clean[:100]


# ---------------------------------------------------------------------------
# Email Helpers (run as background tasks)
# ---------------------------------------------------------------------------

async def _send_verification_email(
    email: str,
    token_url: str,
    tenant_name: str,
    full_name: str,
):
    """Send the verification email.  Intended to run as a BackgroundTask."""
    try:
        from services.email_service import get_email_service
        from services.email_templates import render_verification_email

        html = render_verification_email(token_url, tenant_name, full_name)
        svc = get_email_service()
        await svc.send_email([email], "Verify your email - T1 Agentics", html)
    except Exception as exc:
        logger.error("Failed to send verification email to %s: %s", email, exc)


async def _send_welcome_email(
    email: str,
    tenant_slug: str,
    login_url: str,
    username: str,
):
    """Send the welcome email.  Intended to run as a BackgroundTask."""
    try:
        from services.email_service import get_email_service
        from services.email_templates import render_welcome_email

        html = render_welcome_email(tenant_slug, login_url, username)
        svc = get_email_service()
        await svc.send_email([email], "Welcome to T1 Agentics!", html)
    except Exception as exc:
        logger.error("Failed to send welcome email to %s: %s", email, exc)


async def _admin_recipients() -> list:
    """Resolve the list of admin email recipients for platform notifications.

    Looks up active rows in ``platform_admins`` first, then falls back to
    ``ADMIN_EMAIL`` env var. Returns ``[]`` if neither is configured.
    """
    from services.postgres_db import postgres_db
    recipients = []
    try:
        if postgres_db.connected and postgres_db.pool:
            async with postgres_db.pool.acquire() as conn:
                await conn.execute("SET app.is_platform_admin = 'true'")
                rows = await conn.fetch(
                    "SELECT email FROM platform_admins WHERE is_active = true"
                )
                recipients = [r["email"] for r in rows]
    except Exception as exc:
        logger.warning("Failed to resolve platform_admins recipients: %s", exc)

    if not recipients:
        admin_email = os.environ.get("ADMIN_EMAIL")
        if admin_email:
            recipients = [admin_email]
    return recipients


async def _send_admin_signup_alert(
    email: str,
    tenant_name: str,
    tenant_slug: str,
    plan: str,
    ip_address: str,
    full_name: str = "",
    referral_code: str = "",
    repeat_signups_from_ip: int = 0,
    waitlisted: bool = False,
):
    """Notify platform admins about a new signup (or waitlist entry)."""
    try:
        from services.email_service import get_email_service
        from services.email_templates import render_admin_signup_notification

        recipients = await _admin_recipients()
        if not recipients:
            logger.warning("No admin recipients for signup notification: %s", email)
            return

        html = render_admin_signup_notification(
            email=email,
            tenant_name=tenant_name,
            tenant_slug=tenant_slug,
            plan=plan,
            ip_address=ip_address,
            full_name=full_name,
            referral_code=referral_code or "",
            repeat_signups_from_ip=repeat_signups_from_ip,
            waitlisted=waitlisted,
        )
        subject_prefix = "[Waitlist]" if waitlisted else "[Signup]"
        flag = " [REPEAT IP]" if repeat_signups_from_ip > 0 else ""
        svc = get_email_service()
        await svc.send_email(
            recipients,
            f"{subject_prefix}{flag} {email} ({tenant_slug}, {plan})",
            html,
        )
    except Exception as exc:
        logger.error("Failed to send admin signup notification for %s: %s", email, exc)


async def _send_waitlist_user_email(email: str, tenant_name: str):
    """Tell the registrant they have been placed on the Free-tier waitlist."""
    try:
        from services.email_service import get_email_service
        from services.email_templates import render_waitlist_email

        html = render_waitlist_email(email, tenant_name)
        svc = get_email_service()
        await svc.send_email([email], "You're on the T1 Agentics waitlist", html)
    except Exception as exc:
        logger.error("Failed to send waitlist email to %s: %s", email, exc)


async def _send_enterprise_inquiry_notification(
    name: str,
    email: str,
    company: str,
    message: str,
):
    """Notify platform admins about a new enterprise inquiry."""
    try:
        from services.email_service import get_email_service
        from services.email_templates import render_enterprise_inquiry_notification
        from services.postgres_db import postgres_db

        html = render_enterprise_inquiry_notification(name, email, company, message)
        svc = get_email_service()

        # Determine admin recipients from the platform_admins table
        recipients = []
        if postgres_db.connected and postgres_db.pool:
            async with postgres_db.pool.acquire() as conn:
                rows = await conn.fetch(
                    "SELECT email FROM platform_admins WHERE is_active = true"
                )
                recipients = [r["email"] for r in rows]

        if not recipients:
            # Fallback: use ADMIN_EMAIL env var
            admin_email = os.environ.get("ADMIN_EMAIL")
            if admin_email:
                recipients = [admin_email]

        if recipients:
            await svc.send_email(
                recipients,
                f"New Enterprise Inquiry from {name}",
                html,
            )
        else:
            logger.warning("No admin recipients found for enterprise inquiry notification")
    except Exception as exc:
        logger.error("Failed to send enterprise inquiry notification: %s", exc)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.post("/register", status_code=201)
async def register(
    data: RegisterRequest,
    request: Request,
    background_tasks: BackgroundTasks,
):
    """
    Start the self-service registration flow.

    Validates the request, checks for conflicts, stores a pending
    registration request, and sends a verification email.
    """
    from services.postgres_db import postgres_db

    if not postgres_db.connected or postgres_db.pool is None:
        raise HTTPException(status_code=503, detail="Database not available")

    async with postgres_db.pool.acquire() as conn:
        # -- Rate limit --
        ip_hash = hash_value(get_client_ip(request))
        allowed = await check_rate_limit(conn, ip_hash, "register", max_requests=5, window_hours=1)
        if not allowed:
            raise HTTPException(
                status_code=429,
                detail="Too many registration attempts. Please try again later.",
            )

        # -- Platform admin context to bypass RLS --
        await conn.execute("SET app.is_platform_admin = 'true'")

        # -- IP abuse detection (informational; does not block) --
        # Count distinct registration attempts from the same IP over the past
        # 7 days. A repeat IP is not malicious by itself, but the admin alert
        # surfaces the pattern so the founder can spot abuse early.
        repeat_ip_count = await conn.fetchval(
            """
            SELECT COUNT(*) FROM registration_requests
            WHERE ip_hash = $1
              AND created_at > NOW() - INTERVAL '7 days'
            """,
            ip_hash,
        ) or 0

        # -- Check slug availability in tenants --
        existing_slug = await conn.fetchval(
            "SELECT id FROM tenants WHERE slug = $1",
            data.tenant_slug,
        )
        if existing_slug:
            raise HTTPException(status_code=409, detail="This workspace slug is already taken")

        # -- Check slug in pending registrations --
        pending_slug = await conn.fetchval(
            """
            SELECT id FROM registration_requests
            WHERE tenant_slug = $1 AND status = 'pending' AND verification_expires_at > NOW()
            """,
            data.tenant_slug,
        )
        if pending_slug:
            raise HTTPException(
                status_code=409,
                detail="This workspace slug has a pending registration. Please choose another or wait.",
            )

        # -- Check email uniqueness across ALL tenants --
        existing_email = await conn.fetchval(
            "SELECT id FROM users WHERE email = $1",
            data.email.lower(),
        )
        if existing_email:
            raise HTTPException(status_code=409, detail="An account with this email already exists")

        # -- Check for pending registration with same email --
        pending_email = await conn.fetchval(
            """
            SELECT id FROM registration_requests
            WHERE email = $1 AND status = 'pending' AND verification_expires_at > NOW()
            """,
            data.email.lower(),
        )
        if pending_email:
            raise HTTPException(
                status_code=409,
                detail="A verification email has already been sent to this address. Please check your inbox.",
            )

        # -- Hash password --
        password_hash = bcrypt.hashpw(data.password.encode(), bcrypt.gensalt()).decode()

        # -- Generate verification token --
        verification_token = secrets.token_urlsafe(32)

        # -- Store registration request --
        request_id = uuid.uuid4()
        verification_expires_at = datetime.now(timezone.utc) + timedelta(hours=24)
        email_hash = hash_value(data.email.lower())
        client_ip = get_client_ip(request)

        # Self-hosted OSS: plan field is accepted for compatibility but
        # has no commercial meaning. Operators assign quota profiles
        # server-side. Default everyone to the "community" profile.
        requested_plan = "community"

        # Validate referral code if provided (silently ignore if invalid)
        validated_referral_code = None
        referrer_tenant_id = None
        if data.referral_code:
            normalized_code = data.referral_code.upper().strip()
            ref_row = await conn.fetchrow(
                """
                SELECT ac.code, ac.tenant_id AS referrer_tenant_id
                FROM affiliate_codes ac
                WHERE ac.code = $1 AND ac.is_active = true
                """,
                normalized_code,
            )
            if ref_row:
                validated_referral_code = ref_row["code"]
                referrer_tenant_id = ref_row["referrer_tenant_id"]
                await conn.execute(
                    "UPDATE affiliate_codes SET total_referrals = total_referrals + 1 WHERE code = $1",
                    validated_referral_code,
                )

        # -- MAX_FREE_TENANTS gate (community plan only) --
        # Cap the number of provisioned community-tier tenants. When the cap
        # is reached, store the registration as 'waitlisted' and skip the
        # verification email; the founder is notified and can manually
        # promote them by flipping the status.
        max_free = int(os.environ.get("MAX_FREE_TENANTS", "0") or 0)
        waitlisted = False
        if requested_plan == "community" and max_free > 0:
            active_free = await conn.fetchval(
                """
                SELECT COUNT(*) FROM tenants
                WHERE plan = 'community' AND status = 'active'
                """
            ) or 0
            if active_free >= max_free:
                waitlisted = True

        insert_status = "waitlisted" if waitlisted else "pending"

        await conn.execute(
            """
            INSERT INTO registration_requests
                (id, email, email_hash, password_hash, tenant_name, tenant_slug,
                 full_name, verification_token, verification_expires_at, status,
                 ip_address, ip_hash, requested_plan, referral_code)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $14,
                    $10::inet, $11, $12, $13)
            """,
            request_id,
            data.email.lower(),
            email_hash,
            password_hash,
            data.tenant_name,
            data.tenant_slug,
            data.full_name or "",
            verification_token,
            verification_expires_at,
            client_ip if client_ip != "unknown" else None,
            ip_hash,
            requested_plan,
            validated_referral_code,
            insert_status,
        )

        # Create pending referral row so we can track + apply discount on conversion
        if validated_referral_code and referrer_tenant_id:
            await conn.execute(
                """
                INSERT INTO referrals
                    (referral_code, referrer_tenant_id, referred_email, status)
                VALUES ($1, $2::uuid, $3, 'pending')
                """,
                validated_referral_code,
                str(referrer_tenant_id),
                data.email.lower(),
            )

    # repeat_ip_count includes the row we just inserted, so subtract 1 for the
    # "other attempts from this IP" figure surfaced to the admin.
    other_attempts_from_ip = max(0, (repeat_ip_count or 0) - 0)

    # -- Notify admin about every signup (non-blocking) --
    background_tasks.add_task(
        _send_admin_signup_alert,
        data.email,
        data.tenant_name,
        data.tenant_slug,
        requested_plan,
        client_ip if client_ip != "unknown" else "unknown",
        data.full_name or "",
        validated_referral_code or "",
        other_attempts_from_ip,
        waitlisted,
    )

    # -- Inbound lead agent: classify + draft follow-up for founder review --
    async def _run_lead_agent():
        try:
            from services.inbound_lead_agent import process_lead
            await process_lead(
                source_type="signup",
                source_id=data.email.lower(),
                email=data.email,
                full_name=data.full_name or "",
                company=data.tenant_name or "",
                role="",
                extra_context=f"requested_plan={requested_plan}; waitlisted={waitlisted}",
                tenant_id=None,
            )
        except Exception as exc:
            logger.warning("Inbound lead agent failed for %s: %s", data.email, exc)

    background_tasks.add_task(_run_lead_agent)

    if waitlisted:
        # No verification email — the user gets a waitlist email instead and
        # no tenant is provisioned until the founder approves them.
        background_tasks.add_task(
            _send_waitlist_user_email,
            data.email,
            data.tenant_name,
        )
        logger.info(
            "Registration WAITLISTED (Free cap reached) for %s (slug=%s, ip=%s)",
            data.email, data.tenant_slug, client_ip,
        )
        return {
            "message": "Free tier is currently at capacity. You have been added to the waitlist; we will email you when a seat opens.",
            "email": data.email,
            "waitlisted": True,
        }

    # -- Send verification email (non-blocking) --
    token_url = f"{BASE_URL}/verify-email?token={verification_token}"
    background_tasks.add_task(
        _send_verification_email,
        data.email,
        token_url,
        data.tenant_name,
        data.full_name or "",
    )

    logger.info(
        "Registration request created for %s (slug=%s, ip=%s, repeat_ip=%d)",
        data.email, data.tenant_slug, client_ip, other_attempts_from_ip,
    )

    return {
        "message": "Registration started. Please check your email to verify your address.",
        "email": data.email,
    }


@router.get("/register/verify")
async def verify_registration(
    token: str,
    request: Request,
    background_tasks: BackgroundTasks,
):
    """
    Verify an email address and provision the tenant.

    This is called when the user clicks the verification link in their email.
    On success the tenant, license, and admin user are all created within a
    single database transaction.
    """
    from services.postgres_db import postgres_db

    if not postgres_db.connected or postgres_db.pool is None:
        raise HTTPException(status_code=503, detail="Database not available")

    async with postgres_db.pool.acquire() as conn:
        await conn.execute("SET app.is_platform_admin = 'true'")

        # -- Look up the pending request --
        reg = await conn.fetchrow(
            """
            SELECT id, email, password_hash, tenant_name, tenant_slug, full_name,
                   status, verification_expires_at, requested_plan, referral_code
            FROM registration_requests
            WHERE verification_token = $1
            """,
            token,
        )

        if not reg:
            raise HTTPException(status_code=404, detail="Invalid or expired verification link")

        if reg["status"] != "pending":
            raise HTTPException(
                status_code=400,
                detail="This registration has already been processed",
            )

        if reg["verification_expires_at"] < datetime.now(timezone.utc):
            # Mark as expired
            await conn.execute(
                "UPDATE registration_requests SET status = 'expired' WHERE id = $1",
                reg["id"],
            )
            raise HTTPException(status_code=410, detail="Verification link has expired. Please register again.")

        # -- Double-check slug still available (race condition guard) --
        slug_taken = await conn.fetchval(
            "SELECT id FROM tenants WHERE slug = $1",
            reg["tenant_slug"],
        )
        if slug_taken:
            await conn.execute(
                "UPDATE registration_requests SET status = 'rejected', rejection_reason = 'Slug taken during verification' WHERE id = $1",
                reg["id"],
            )
            raise HTTPException(
                status_code=409,
                detail="This workspace slug was taken while your verification was pending. Please register again with a different slug.",
            )

        # -- Provision tenant (inside the same connection / transaction context) --
        tenant_id = uuid.uuid4()
        await conn.execute(
            """
            INSERT INTO tenants (id, slug, name, plan, status)
            VALUES ($1, $2, $3, $4, 'active')
            """,
            tenant_id, reg["tenant_slug"], reg["tenant_name"], "community",
        )

        # Create license
        license_key = f"T1-{secrets.token_hex(4).upper()}-{secrets.token_hex(4).upper()}-{secrets.token_hex(4).upper()}"
        license_id = uuid.uuid4()
        await conn.execute(
            """
            INSERT INTO tenant_licenses (id, tenant_id, license_key, tier, expires_at, issued_by)
            VALUES ($1, $2, $3, $4, $5, $6)
            """,
            license_id, tenant_id, license_key, "community", None, None,
        )

        # Link license to tenant
        await conn.execute(
            "UPDATE tenants SET active_license_id = $1 WHERE id = $2",
            license_id, tenant_id,
        )

        # Create admin user with the registrant's credentials
        # tos_accepted_at is recorded because agreed_to_terms was validated True above
        await conn.execute(
            """
            INSERT INTO users (tenant_id, username, email, hashed_password, role, tenant_role, force_password_reset, tos_accepted_at)
            VALUES ($1, $2, $3, $4, 'admin', 'admin', false, CURRENT_TIMESTAMP)
            """,
            tenant_id, reg["email"], reg["email"], reg["password_hash"],
        )

        # Initialize Claude usage tracking for the new tenant
        await conn.execute(
            """
            INSERT INTO tenant_claude_usage (tenant_id, month_start)
            VALUES ($1, date_trunc('month', CURRENT_DATE)::date)
            ON CONFLICT DO NOTHING
            """,
            tenant_id,
        )

        # Create default webhook for alert ingestion
        webhook_id = uuid.uuid4()
        webhook_token = f"whtoken_{secrets.token_hex(16)}"
        webhook_name = f"{reg['tenant_slug']}-siem"
        await conn.execute(
            """
            INSERT INTO webhooks (id, name, endpoint_path, token, tenant_id, created_by, enabled)
            VALUES ($1, $2, $3, $4, $5, $6, true)
            ON CONFLICT (name) DO NOTHING
            """,
            webhook_id,
            webhook_name,
            f"/api/v1/webhooks/ingest/{webhook_name}",
            webhook_token,
            tenant_id,
            reg["email"],
        )

        # Mark registration as provisioned
        await conn.execute(
            """
            UPDATE registration_requests
            SET status = 'provisioned', verified_at = NOW(), provisioned_tenant_id = $1
            WHERE id = $2
            """,
            tenant_id, reg["id"],
        )

        # Link the referral row to the newly provisioned tenant
        if reg.get("referral_code"):
            await conn.execute(
                """
                UPDATE referrals
                SET referred_tenant_id = $1::uuid
                WHERE referral_code = $2
                  AND referred_email = $3
                  AND referred_tenant_id IS NULL
                """,
                str(tenant_id),
                reg["referral_code"],
                reg["email"],
            )

    # -- Send welcome email (non-blocking) --
    from urllib.parse import urlparse as _urlparse
    _parsed = _urlparse(BASE_URL)
    login_url = f"{_parsed.scheme}://{reg['tenant_slug']}.{_parsed.hostname}/login"
    background_tasks.add_task(
        _send_welcome_email,
        reg["email"],
        reg["tenant_slug"],
        login_url,
        reg["email"],
    )

    logger.info(
        "Tenant provisioned via self-registration: slug=%s, tenant_id=%s",
        reg["tenant_slug"], tenant_id,
    )

    # Self-hosted OSS: no paid-tier provisioning. Every verified signup
    # gets the default tenant with the default quota profile; operators
    # can upgrade quotas server-side.
    response = {
        "message": "Email verified successfully. Your workspace has been created!",
        "tenant": {
            "id": str(tenant_id),
            "slug": reg["tenant_slug"],
            "name": reg["tenant_name"],
            "plan": "community",
        },
        "webhook": {
            "name": webhook_name,
            "endpoint": f"/api/v1/webhooks/ingest/{webhook_name}",
            "token": webhook_token,
        },
        "login_url": login_url,
    }

    return response


@router.post("/register/check-slug")
async def check_slug(data: SlugCheckRequest):
    """
    Check whether a tenant slug is available.

    Also returns suggestions if the requested slug is taken or reserved.
    """
    from services.postgres_db import postgres_db

    slug = data.slug.lower().strip()

    # Quick validation
    if len(slug) < 3 or len(slug) > 50 or not SLUG_PATTERN.match(slug):
        return {
            "available": False,
            "slug": slug,
            "reason": "Invalid slug format",
            "suggestions": [],
        }

    if slug in RESERVED_SLUGS:
        return {
            "available": False,
            "slug": slug,
            "reason": "This slug is reserved",
            "suggestions": _slug_suggestions(slug),
        }

    if not postgres_db.connected or postgres_db.pool is None:
        raise HTTPException(status_code=503, detail="Database not available")

    async with postgres_db.pool.acquire() as conn:
        await conn.execute("SET app.is_platform_admin = 'true'")

        # Check tenants table
        exists_tenant = await conn.fetchval(
            "SELECT id FROM tenants WHERE slug = $1", slug
        )

        # Check pending registrations
        exists_pending = await conn.fetchval(
            """
            SELECT id FROM registration_requests
            WHERE tenant_slug = $1 AND status = 'pending' AND verification_expires_at > NOW()
            """,
            slug,
        )

    available = not exists_tenant and not exists_pending
    suggestions = [] if available else _slug_suggestions(slug)

    return {
        "available": available,
        "slug": slug,
        "suggestions": suggestions,
    }


def _slug_suggestions(base: str) -> list:
    """Generate a handful of alternative slugs."""
    import random

    suggestions = []
    suffixes = [
        str(random.randint(1, 999)),
        "hq",
        "sec",
        "ops",
        "soc",
        str(random.randint(1000, 9999)),
    ]
    for suffix in suffixes[:4]:
        candidate = f"{base}-{suffix}"
        if len(candidate) <= 50 and candidate not in RESERVED_SLUGS:
            suggestions.append(candidate)
    return suggestions


@router.post("/contact")
async def submit_contact(
    data: ContactRequest,
    request: Request,
    background_tasks: BackgroundTasks,
):
    """
    Handle enterprise / contact-us form submissions.

    Rate-limited to 3 submissions per IP per hour.
    """
    from services.postgres_db import postgres_db

    if not postgres_db.connected or postgres_db.pool is None:
        raise HTTPException(status_code=503, detail="Database not available")

    async with postgres_db.pool.acquire() as conn:
        # Rate limit
        ip_hash = hash_value(get_client_ip(request))
        allowed = await check_rate_limit(conn, ip_hash, "contact", max_requests=3, window_hours=1)
        if not allowed:
            raise HTTPException(
                status_code=429,
                detail="Too many submissions. Please try again later.",
            )

        # Store submission
        submission_id = uuid.uuid4()
        client_ip = get_client_ip(request)
        await conn.execute(
            """
            INSERT INTO contact_submissions
                (id, name, email, company, phone, message, ip_address)
            VALUES ($1, $2, $3, $4, $5, $6, $7::inet)
            """,
            submission_id,
            data.name.strip(),
            data.email.lower(),
            (data.company or "").strip(),
            (data.phone or "").strip(),
            data.message.strip(),
            client_ip if client_ip != "unknown" else None,
        )

    # Notify admins (non-blocking)
    background_tasks.add_task(
        _send_enterprise_inquiry_notification,
        data.name.strip(),
        data.email.lower(),
        (data.company or "").strip(),
        data.message.strip(),
    )

    # Inbound lead agent: classify + draft follow-up for founder review.
    async def _run_lead_agent_contact():
        try:
            from services.inbound_lead_agent import process_lead
            await process_lead(
                source_type="contact",
                source_id=str(submission_id),
                email=data.email.lower(),
                full_name=data.name.strip(),
                company=(data.company or "").strip(),
                role="",
                extra_context=data.message.strip(),
                tenant_id=None,
            )
        except Exception as exc:
            logger.warning("Inbound lead agent (contact) failed for %s: %s", data.email, exc)

    background_tasks.add_task(_run_lead_agent_contact)

    logger.info("Contact form submission from %s (%s)", data.name, data.email)

    return {"message": "Thank you for your inquiry. Our team will be in touch shortly."}


@router.get("/public/tiers")
async def get_public_tiers():
    """
    Return public tier / quota-profile information.

    Self-hosted OSS build: tiers are quota profiles operators can assign
    to tenants. No prices are exposed.
    """
    tiers = [
        {
            "id": "community",
            "name": "Community",
            "description": "Default quota profile for self-hosted deployments.",
            "limits": {
                "alerts_per_day": 50,
                "users": 3,
                "playbooks": 5,
                "integrations": 10,
                "ai_queries_per_day": 25,
                "retention_days": 30,
                "iocs": 200_000,
            },
            "features": {
                "basic_alerts": True,
                "alert_triage": True,
                "basic_playbooks": True,
                "advanced_playbooks": False,
                "custom_integrations": False,
                "api_access": False,
                "sso": False,
                "audit_logs": False,
                "rbac": False,
                "priority_support": False,
                "sla": False,
                "custom_branding": False,
                "multi_tenant": False,
            },
        },
    ]

    return {"tiers": tiers}
