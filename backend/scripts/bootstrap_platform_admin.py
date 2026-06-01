"""
Bootstrap the first platform admin for T1 Agentics OSS.

Reads ADMIN_EMAIL and ADMIN_PASSWORD from the environment, ensures the
platform-owner tenant exists, then creates (or no-ops on) the corresponding
admin user and the platform_admins row that gates the platform-admin UI.

Idempotent: safe to re-run. Designed to be invoked from install.sh:
    docker compose exec backend python scripts/bootstrap_platform_admin.py

Reuses the same helpers the rest of the codebase uses:
  - services.postgres_db.postgres_db   (asyncpg pool, schema_migrations)
  - passlib.hash.bcrypt                (same algorithm as init_default_users)
  - backend.config.constants.PLATFORM_OWNER_TENANT_ID
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import uuid
from pathlib import Path

# Make `backend/` importable when run as `python scripts/bootstrap_platform_admin.py`
BACKEND_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_DIR))


def _log(msg: str) -> None:
    print(f"[bootstrap-admin] {msg}", flush=True)


async def _ensure_tenant(conn, tenant_id: uuid.UUID, slug: str, name: str) -> None:
    """Create the platform-owner tenant if it isn't there yet."""
    row = await conn.fetchrow("SELECT id FROM tenants WHERE id = $1", tenant_id)
    if row:
        _log(f"tenant {slug} already exists ({tenant_id})")
        return

    await conn.execute(
        """
        INSERT INTO tenants (id, slug, name, plan, status, settings)
        VALUES ($1, $2, $3, 'enterprise', 'active', $4::jsonb)
        ON CONFLICT (slug) DO UPDATE SET
            settings = tenants.settings || EXCLUDED.settings
        """,
        tenant_id,
        slug,
        name,
        json.dumps({"is_platform_owner": True}),
    )
    _log(f"created tenant {slug} ({tenant_id})")


async def _ensure_user(
    conn, tenant_id: uuid.UUID, email: str, password_hash: str, full_name: str
) -> uuid.UUID:
    """Create or update the admin user row inside the platform-owner tenant."""
    row = await conn.fetchrow(
        "SELECT id FROM users WHERE email = $1",
        email.lower(),
    )
    if row:
        # Reset the password to whatever is currently in the env. This matches
        # the user's expectation that re-running the installer with a new
        # ADMIN_PASSWORD actually rotates the password.
        await conn.execute(
            """
            UPDATE users
               SET hashed_password = $2,
                   role = 'admin',
                   disabled = FALSE,
                   force_password_reset = FALSE,
                   failed_login_attempts = 0,
                   locked_until = NULL
             WHERE id = $1
            """,
            row["id"],
            password_hash,
        )
        _log(f"user {email} already existed - password reset, role=admin")
        return row["id"]

    user_id = uuid.uuid4()
    # Username column is NOT NULL and unique; derive from the email local-part
    # but guarantee uniqueness via the UUID suffix if needed.
    username = email.split("@", 1)[0].lower()
    exists = await conn.fetchval("SELECT 1 FROM users WHERE username = $1", username)
    if exists:
        username = f"{username}-{user_id.hex[:6]}"

    await conn.execute(
        """
        INSERT INTO users (
            id, username, email, hashed_password, full_name, role,
            tenant_id, disabled, force_password_reset
        ) VALUES ($1, $2, $3, $4, $5, 'admin', $6, FALSE, FALSE)
        """,
        user_id,
        username,
        email.lower(),
        password_hash,
        full_name,
        tenant_id,
    )
    _log(f"created admin user {email} (id={user_id}, username={username})")
    return user_id


async def _ensure_platform_admin(
    conn, user_id: uuid.UUID, email: str, password_hash: str, full_name: str
) -> None:
    """Ensure a row exists in platform_admins for the platform-admin UI."""
    existing = await conn.fetchrow(
        "SELECT id FROM platform_admins WHERE email = $1", email.lower()
    )
    permissions = json.dumps(
        ["read", "write", "manage_tenants", "manage_licenses", "manage_admins"]
    )

    if existing:
        await conn.execute(
            """
            UPDATE platform_admins
               SET password_hash = $2,
                   is_active = TRUE,
                   permissions = $3::jsonb
             WHERE id = $1
            """,
            existing["id"],
            password_hash,
            permissions,
        )
        _log(f"platform_admins row for {email} already existed - refreshed")
        return

    admin_id = uuid.uuid4()
    await conn.execute(
        """
        INSERT INTO platform_admins (
            id, user_id, email, name, password_hash, permissions, is_active
        ) VALUES ($1, $2, $3, $4, $5, $6::jsonb, TRUE)
        """,
        admin_id,
        user_id,
        email.lower(),
        full_name,
        password_hash,
        permissions,
    )
    try:
        await conn.execute(
            """
            INSERT INTO platform_audit_log (admin_id, action, details)
            VALUES ($1, 'admin_created', $2::jsonb)
            """,
            admin_id,
            json.dumps({"email": email, "via": "bootstrap_platform_admin.py"}),
        )
    except Exception as exc:
        # platform_audit_log is created by migration 014; if it isn't there
        # yet for some reason, that's not fatal.
        _log(f"audit-log insert skipped: {exc}")
    _log(f"created platform_admins row for {email}")


async def main() -> int:
    email = (os.environ.get("ADMIN_EMAIL") or "").strip()
    password = os.environ.get("ADMIN_PASSWORD") or ""
    full_name = os.environ.get("ADMIN_NAME") or "Platform Admin"

    if not email or not password:
        _log("ADMIN_EMAIL and ADMIN_PASSWORD must both be set in the environment.")
        return 2

    # Local imports so a missing dep produces a clearer message than ImportError
    # at module load.
    try:
        from passlib.hash import bcrypt
    except Exception as exc:  # pragma: no cover
        _log(f"passlib unavailable inside the backend image: {exc}")
        return 3

    try:
        from services.postgres_db import postgres_db
    except Exception as exc:  # pragma: no cover
        _log(f"failed to import postgres_db: {exc}")
        return 3

    try:
        from config.constants import PLATFORM_OWNER_TENANT_ID
    except Exception:
        PLATFORM_OWNER_TENANT_ID = "00000000-0000-0000-0000-000000000001"

    tenant_id = uuid.UUID(str(PLATFORM_OWNER_TENANT_ID))
    tenant_slug = os.environ.get("PLATFORM_TENANT_SLUG", "platform")
    tenant_name = os.environ.get("PLATFORM_TENANT_NAME", "Platform")

    password_hash = bcrypt.hash(password)

    _log("connecting to PostgreSQL...")
    await postgres_db.connect()
    if not postgres_db.connected or postgres_db.pool is None:
        _log("could not establish a database connection")
        return 4

    try:
        async with postgres_db.pool.acquire() as conn:
            # Bypass RLS - we are bootstrapping the platform-owner tenant.
            await conn.execute(
                "SELECT set_config('app.current_tenant_id', $1, false)",
                str(tenant_id),
            )
            await conn.execute(
                "SELECT set_config('app.is_platform_admin', 'true', false)"
            )

            await _ensure_tenant(conn, tenant_id, tenant_slug, tenant_name)
            user_id = await _ensure_user(
                conn, tenant_id, email, password_hash, full_name
            )
            await _ensure_platform_admin(
                conn, user_id, email, password_hash, full_name
            )

        _log("done.")
        return 0
    finally:
        try:
            await postgres_db.disconnect()
        except Exception:
            pass


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
