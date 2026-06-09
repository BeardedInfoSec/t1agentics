# Copyright (c) 2025-2026 T1 Agentics LLC. SPDX-License-Identifier: Apache-2.0

"""
Config-file loader for self-hosted T1 Agentics.

A single YAML file (default: /app/t1.config.yaml, mounted read-only) describes
the whole-app configuration: org identity, license tier, AI chat/embeddings
provider, the platform admin, triage taxonomy, and SMTP. On every backend
startup `apply_config_file()` reads that file and IDEMPOTENTLY upserts each
section into the database via the *same* services/tables the UI and REST API
already use — never a parallel store. This lets a self-hoster configure the
entire platform by editing one file and restarting the backend.

Design contract:
  * Absent file        -> skip cleanly (no-op), log once.
  * Partial file       -> apply only the sections that are present.
  * Re-run every boot  -> upserts only; no duplicate inserts, no errors.

`${ENV_VAR}` references inside string values are expanded from the process
environment, so secrets (API keys, admin password) live in `.env` and are
only referenced from the YAML — never stored in it.

Section -> destination mapping (study the existing code before changing):
  * org          -> tenants (name, slug) for the platform-owner tenant.
  * license.tier -> tenants.plan + an active tenant_licenses row.
  * ai.chat /
    ai.embeddings-> BOTH ai_providers (agent executor / Riggs default
                    provider) AND tenant_ai_config (claude_service BYO path,
                    keys encrypted via CredentialsVault).
  * admin        -> users (+ platform_admins), mirroring
                    scripts/bootstrap_platform_admin.py. Password from
                    ${ADMIN_PASSWORD}; never stored in the YAML.
  * triage.*     -> config.system_config in-memory store (the same store the
                    /api/v1/config endpoints read/write).
  * smtp         -> email_config table (id='smtp'), the DB-first source that
                    email_service.get_smtp_config() reads before env fallback.
"""

from __future__ import annotations

import logging
import os
import re
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Where the file is mounted inside the backend container. Overridable so the
# native (no-Docker) runner and tests can point elsewhere.
DEFAULT_CONFIG_PATH = os.getenv("T1_CONFIG_FILE", "/app/t1.config.yaml")

# Friendly license tier (what a self-hoster writes) -> DB tier/plan string.
# The DB enforces these via the `valid_tier` / `valid_plan` CHECK constraints.
# `platform` is the self-hosted "unlimited" tier; we keep it as the canonical
# self-host value and also accept the `unlimited` alias for it.
_TIER_ALIASES = {
    "free": "community",
    "community": "community",
    "starter": "starter",
    "pro": "professional",
    "professional": "professional",
    "enterprise": "enterprise",
    "enterprise_plus": "enterprise_plus",
    "platform": "platform",
    "unlimited": "platform",
    "poc": "poc",
    "trial": "trial",
}
# tenants.plan does not allow 'trial'; collapse it to the nearest valid plan.
_PLAN_FALLBACK = {"trial": "poc"}

_ENV_REF = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


# ---------------------------------------------------------------------------
# Parsing + ${ENV} expansion
# ---------------------------------------------------------------------------
def _expand_env(value: Any) -> Any:
    """Recursively expand ${ENV_VAR} refs inside string values."""
    if isinstance(value, str):
        def repl(m: "re.Match[str]") -> str:
            return os.environ.get(m.group(1), "")
        return _ENV_REF.sub(repl, value)
    if isinstance(value, list):
        return [_expand_env(v) for v in value]
    if isinstance(value, dict):
        return {k: _expand_env(v) for k, v in value.items()}
    return value


def load_config_file(path: str) -> Optional[Dict[str, Any]]:
    """Read + parse the YAML, expanding ${ENV} refs. None if file is absent."""
    p = Path(path)
    if not p.is_file():
        return None
    import yaml  # pyyaml — pinned in backend/requirements.txt
    with p.open("r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh) or {}
    if not isinstance(raw, dict):
        raise ValueError("t1.config.yaml top level must be a mapping")
    return _expand_env(raw)


def _clean_str(value: Any) -> Optional[str]:
    """Treat empty / whitespace-only strings (often an unset ${ENV}) as None."""
    if value is None:
        return None
    s = str(value).strip()
    return s or None


# ---------------------------------------------------------------------------
# Section appliers — each is idempotent and self-contained.
# ---------------------------------------------------------------------------
async def _apply_org(conn, tenant_id: str, org: Dict[str, Any]) -> str:
    name = _clean_str(org.get("name"))
    slug = _clean_str(org.get("slug"))
    if not name and not slug:
        return "org: nothing to apply"
    # Ensure the platform tenant exists, then update name/slug in place.
    await conn.execute(
        """
        INSERT INTO tenants (id, slug, name, plan, status, settings)
        VALUES ($1::uuid, COALESCE($2, 'platform'), COALESCE($3, 'Platform'),
                'platform', 'active', '{"is_platform_owner": true}'::jsonb)
        ON CONFLICT (id) DO UPDATE SET
            name = COALESCE($3, tenants.name),
            slug = COALESCE($2, tenants.slug)
        """,
        tenant_id, slug, name,
    )
    return f"org: name={name!r} slug={slug!r}"


async def _apply_license(conn, tenant_id: str, lic: Dict[str, Any]) -> str:
    raw_tier = _clean_str(lic.get("tier"))
    if not raw_tier:
        return "license: nothing to apply"
    key = raw_tier.lower()
    if key not in _TIER_ALIASES:
        raise ValueError(
            f"license.tier {raw_tier!r} is not valid. "
            f"Allowed: {sorted(set(_TIER_ALIASES))}"
        )
    tier = _TIER_ALIASES[key]                       # tenant_licenses.tier
    plan = _PLAN_FALLBACK.get(tier, tier)           # tenants.plan

    # Idempotent: if the active license already has this tier, only refresh the
    # plan column. Otherwise supersede the old active license with a new one,
    # mirroring routes/platform_admin.py.
    active = await conn.fetchrow(
        "SELECT id, tier FROM tenant_licenses "
        "WHERE tenant_id = $1::uuid AND is_active = true "
        "ORDER BY issued_at DESC LIMIT 1",
        tenant_id,
    )
    if active and active["tier"] == tier:
        license_id = active["id"]
    else:
        if active:
            await conn.execute(
                "UPDATE tenant_licenses SET is_active = false, revoked_at = NOW(), "
                "revoke_reason = 'Superseded by t1.config.yaml' "
                "WHERE tenant_id = $1::uuid AND is_active = true",
                tenant_id,
            )
        license_id = uuid.uuid4()
        license_key = f"SELFHOST-{uuid.uuid4().hex}"
        await conn.execute(
            "INSERT INTO tenant_licenses (id, tenant_id, license_key, tier, is_active) "
            "VALUES ($1, $2::uuid, $3, $4, true)",
            license_id, tenant_id, license_key, tier,
        )
    await conn.execute(
        "UPDATE tenants SET active_license_id = $1, plan = $2 WHERE id = $3::uuid",
        license_id, plan, tenant_id,
    )
    return f"license: tier={tier} plan={plan}"


def _base_url_no_v1(url: Optional[str]) -> Optional[str]:
    """ai_providers.base_url is stored WITHOUT a trailing /v1 (the resolver
    appends it). tenant_ai_config keeps whatever the user typed."""
    if not url:
        return url
    return re.sub(r"/v1/?$", "", url.rstrip("/"))


async def _apply_ai(conn, tenant_id: str, ai: Dict[str, Any], vault) -> str:
    chat = ai.get("chat") or {}
    embed = ai.get("embeddings") or {}
    msgs: List[str] = []

    chat_model = _clean_str(chat.get("model"))
    chat_base_url = _clean_str(chat.get("base_url"))
    chat_key = _clean_str(chat.get("api_key"))
    chat_provider = _clean_str(chat.get("provider"))          # self_hosted/anthropic/openai
    chat_api_style = _clean_str(chat.get("api_style"))        # openai/anthropic
    chat_max_tokens = chat.get("max_tokens")

    embed_provider = _clean_str(embed.get("provider"))        # openai/self_hosted/disabled
    embed_base_url = _clean_str(embed.get("base_url"))
    embed_model = _clean_str(embed.get("model"))
    embed_key = _clean_str(embed.get("api_key"))

    # ---- ai_providers (agent executor / Riggs default provider) ----
    # Only manage the chat provider here; it's the default inference endpoint.
    if chat_base_url or chat_model:
        prov_base = _base_url_no_v1(chat_base_url) or ""
        enc_key = vault.encrypt(chat_key) if chat_key else ""
        # Single default openai_compatible provider keyed by base_url so a
        # re-run updates the same row instead of inserting a duplicate.
        existing = await conn.fetchrow(
            "SELECT id FROM ai_providers WHERE base_url = $1 ORDER BY is_default DESC LIMIT 1",
            prov_base,
        )
        # Make this provider the sole default.
        await conn.execute("UPDATE ai_providers SET is_default = false WHERE is_default = true")
        if existing:
            await conn.execute(
                "UPDATE ai_providers SET provider_type = 'openai_compatible', "
                "selected_model = $2, chat_model = $2, api_key = '', "
                "api_key_encrypted = $3, is_default = true, enabled = true "
                "WHERE id = $1",
                existing["id"], chat_model or "", enc_key,
            )
        else:
            await conn.execute(
                "INSERT INTO ai_providers "
                "(name, provider_type, base_url, api_key, api_key_encrypted, "
                " models, selected_model, chat_model, is_default, enabled, created_at) "
                "VALUES ($1, 'openai_compatible', $2, '', $3, '[]'::jsonb, $4, $4, true, true, NOW())",
                "Configured Provider", prov_base, enc_key, chat_model or "",
            )
        msgs.append(f"ai_providers: base_url={prov_base!r} model={chat_model!r}")

    # ---- tenant_ai_config (claude_service BYO path) ----
    # Build a COALESCE-friendly upsert that mirrors upsert_tenant_config.
    set_cols: Dict[str, Any] = {"byo_allowed": True, "byo_enabled": True}
    if chat_provider:
        set_cols["chat_provider"] = chat_provider
    if chat_api_style:
        set_cols["chat_api_style"] = chat_api_style
    if chat_model:
        set_cols["chat_model"] = chat_model
    if chat_base_url:
        set_cols["chat_base_url"] = chat_base_url
    if chat_max_tokens is not None:
        set_cols["chat_max_tokens"] = int(chat_max_tokens)
    if chat_key:
        set_cols["chat_api_key_encrypted"] = vault.encrypt(chat_key)
    if embed_provider:
        set_cols["embed_provider"] = embed_provider
    if embed_base_url:
        set_cols["embed_base_url"] = embed_base_url
    if embed_model:
        set_cols["embed_model"] = embed_model
    if embed_key:
        set_cols["embed_api_key_encrypted"] = vault.encrypt(embed_key)

    cols = list(set_cols.keys())
    placeholders = ", ".join(f"${i + 2}" for i in range(len(cols)))
    update_clause = ", ".join(f"{c} = EXCLUDED.{c}" for c in cols)
    await conn.execute(
        f"INSERT INTO tenant_ai_config (tenant_id, {', '.join(cols)}, updated_at) "
        f"VALUES ($1::uuid, {placeholders}, NOW()) "
        f"ON CONFLICT (tenant_id) DO UPDATE SET {update_clause}, updated_at = NOW()",
        tenant_id, *[set_cols[c] for c in cols],
    )
    msgs.append(f"tenant_ai_config: chat_provider={chat_provider!r} chat_model={chat_model!r}")
    return "ai: " + "; ".join(msgs)


async def _apply_admin(conn, tenant_id: str, admin: Dict[str, Any]) -> str:
    email = _clean_str(admin.get("email"))
    username = _clean_str(admin.get("username"))
    if not email:
        return "admin: skipped (no email)"
    password = os.environ.get("ADMIN_PASSWORD") or ""
    full_name = _clean_str(admin.get("name")) or os.environ.get("ADMIN_NAME") or "Platform Admin"
    if not password:
        return "admin: skipped (ADMIN_PASSWORD not set in environment)"

    from passlib.hash import bcrypt
    password_hash = bcrypt.hash(password)
    email_l = email.lower()
    if not username:
        username = email_l.split("@", 1)[0]

    # users upsert by email (mirrors bootstrap_platform_admin._ensure_user)
    row = await conn.fetchrow("SELECT id FROM users WHERE email = $1", email_l)
    if row:
        user_id = row["id"]
        await conn.execute(
            "UPDATE users SET hashed_password = $2, role = 'admin', disabled = FALSE, "
            "force_password_reset = FALSE, failed_login_attempts = 0, locked_until = NULL "
            "WHERE id = $1",
            user_id, password_hash,
        )
    else:
        user_id = uuid.uuid4()
        # username is unique+NOT NULL; suffix on collision.
        if await conn.fetchval("SELECT 1 FROM users WHERE username = $1", username):
            username = f"{username}-{user_id.hex[:6]}"
        await conn.execute(
            "INSERT INTO users (id, username, email, hashed_password, full_name, role, "
            "tenant_id, disabled, force_password_reset) "
            "VALUES ($1, $2, $3, $4, $5, 'admin', $6::uuid, FALSE, FALSE)",
            user_id, username, email_l, password_hash, full_name, tenant_id,
        )

    # platform_admins upsert by email (mirrors _ensure_platform_admin)
    import json
    permissions = json.dumps(["read", "write", "manage_tenants", "manage_licenses", "manage_admins"])
    existing = await conn.fetchrow("SELECT id FROM platform_admins WHERE email = $1", email_l)
    if existing:
        await conn.execute(
            "UPDATE platform_admins SET password_hash = $2, is_active = TRUE, "
            "permissions = $3::jsonb WHERE id = $1",
            existing["id"], password_hash, permissions,
        )
    else:
        await conn.execute(
            "INSERT INTO platform_admins (id, user_id, email, name, password_hash, permissions, is_active) "
            "VALUES ($1, $2, $3, $4, $5, $6::jsonb, TRUE)",
            uuid.uuid4(), user_id, email_l, full_name, password_hash, permissions,
        )
    return f"admin: user+platform_admin upserted for {email_l} (username={username})"


def _apply_triage(triage: Dict[str, Any]) -> str:
    """Apply dispositions / severity_levels / priorities into the in-memory
    config.system_config store — the same store /api/v1/config reads. Replaces
    the `custom` lists wholesale (idempotent across reboots), leaving the
    built-in `enabled` lists untouched."""
    from config import system_config as sc

    msgs: List[str] = []

    def _norm_disp(d: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "value": str(d.get("value", "")).upper(),
            "label": d.get("label", d.get("value", "")),
            "color": d.get("color", "#6b7280"),
            "description": d.get("description", ""),
        }

    def _norm_sev(d: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "value": str(d.get("value", "")).lower(),
            "label": d.get("label", d.get("value", "")),
            "color": d.get("color", "#6b7280"),
            "threshold": int(d.get("threshold", 50)),
        }

    def _norm_prio(d: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "value": str(d.get("value", "")).upper(),
            "label": d.get("label", d.get("value", "")),
            "sla_hours": int(d.get("sla_hours", 24)),
            "color": d.get("color", "#6b7280"),
        }

    builtin_disp = {d["value"] for d in sc.DEFAULT_CONFIG["dispositions"]["enabled"]}
    builtin_sev = {d["value"] for d in sc.DEFAULT_CONFIG["severity_levels"]["enabled"]}
    builtin_prio = {d["value"] for d in sc.DEFAULT_CONFIG["priorities"]["enabled"]}

    if isinstance(triage.get("dispositions"), list):
        custom = [_norm_disp(d) for d in triage["dispositions"]
                  if str(d.get("value", "")).upper() not in builtin_disp]
        sc._config["dispositions"]["custom"] = custom
        msgs.append(f"dispositions(+{len(custom)} custom)")

    if isinstance(triage.get("severity_levels"), list):
        custom = [_norm_sev(d) for d in triage["severity_levels"]
                  if str(d.get("value", "")).lower() not in builtin_sev]
        sc._config["severity_levels"]["custom"] = custom
        msgs.append(f"severity_levels(+{len(custom)} custom)")

    if isinstance(triage.get("priorities"), list):
        provided = [_norm_prio(d) for d in triage["priorities"]]
        # Apply SLA overrides to built-ins; collect new ones as custom.
        by_value = {p["value"]: p for p in provided}
        for p in sc._config["priorities"]["enabled"]:
            if p["value"] in by_value:
                p["sla_hours"] = by_value[p["value"]]["sla_hours"]
        custom = [p for p in provided if p["value"] not in builtin_prio]
        sc._config["priorities"]["custom"] = custom
        msgs.append(f"priorities(+{len(custom)} custom)")

    if not msgs:
        return "triage: nothing to apply"
    return "triage: " + ", ".join(msgs)


async def _apply_smtp(conn, smtp: Dict[str, Any]) -> str:
    host = _clean_str(smtp.get("host"))
    if not host:
        return "smtp: skipped (no host — stays env-driven)"
    port = int(smtp.get("port") or 587)
    username = _clean_str(smtp.get("username")) or ""
    password = _clean_str(smtp.get("password")) or ""
    from_email = _clean_str(smtp.get("from_email")) or username
    from_name = _clean_str(smtp.get("from_name")) or "T1 Agentics SOC"
    use_tls = bool(smtp.get("use_tls", True))
    use_ssl = bool(smtp.get("use_ssl", False))
    enabled = bool(smtp.get("enabled", True))

    await conn.execute(
        """
        INSERT INTO email_config
            (id, smtp_host, smtp_port, smtp_username, smtp_password,
             use_tls, use_ssl, from_email, from_name, enabled, updated_at)
        VALUES ('smtp', $1, $2, $3, $4, $5, $6, $7, $8, $9, CURRENT_TIMESTAMP)
        ON CONFLICT (id) DO UPDATE SET
            smtp_host = $1, smtp_port = $2, smtp_username = $3, smtp_password = $4,
            use_tls = $5, use_ssl = $6, from_email = $7, from_name = $8,
            enabled = $9, updated_at = CURRENT_TIMESTAMP
        """,
        host, port, username, password, use_tls, use_ssl, from_email, from_name, enabled,
    )
    return f"smtp: host={host}:{port} enabled={enabled}"


# ---------------------------------------------------------------------------
# Public entry point — called from app.py lifespan after the pool is ready.
# ---------------------------------------------------------------------------
async def apply_config_file(path: Optional[str] = None) -> Dict[str, Any]:
    """
    Read the config file and idempotently apply each present section.

    Safe when the file is absent (skips), partial (applies present sections),
    and re-runnable on every boot (upserts only). Never raises out to the
    caller — a bad file logs an error and is treated as a no-op so a typo
    can't wedge startup.
    """
    path = path or DEFAULT_CONFIG_PATH
    result: Dict[str, Any] = {"applied": [], "skipped": [], "path": path}

    try:
        cfg = load_config_file(path)
    except Exception as e:
        logger.error(f"[config-file] failed to parse {path}: {e}")
        result["error"] = str(e)
        return result

    if cfg is None:
        logger.info(f"[config-file] {path} not present — skipping (no-op)")
        result["skipped"].append("file-absent")
        return result

    from config.constants import PLATFORM_OWNER_TENANT_ID
    tenant_id = str(PLATFORM_OWNER_TENANT_ID)

    # Triage is a pure in-memory apply — no DB needed.
    if isinstance(cfg.get("triage"), dict):
        try:
            result["applied"].append(_apply_triage(cfg["triage"]))
        except Exception as e:
            logger.error(f"[config-file] triage apply failed: {e}")
            result["skipped"].append(f"triage:{e}")

    # Everything else needs the DB.
    from services.postgres_db import postgres_db
    if not postgres_db.connected or postgres_db.pool is None:
        logger.warning("[config-file] DB not connected — DB-backed sections skipped")
        result["skipped"].append("db-unavailable")
        for line in result["applied"]:
            logger.info(f"[config-file] applied {line}")
        return result

    from services.credentials_service import CredentialsVault
    vault = CredentialsVault()

    async with postgres_db.pool.acquire() as conn:
        # Bootstrap-style RLS bypass: act as platform admin on the owner tenant.
        await conn.execute("SELECT set_config('app.current_tenant_id', $1, false)", tenant_id)
        await conn.execute("SELECT set_config('app.is_platform_admin', 'true', false)")

        # Order matters: org/license before admin (tenant must exist).
        section_appliers = [
            ("org", lambda: _apply_org(conn, tenant_id, cfg["org"])),
            ("license", lambda: _apply_license(conn, tenant_id, cfg["license"])),
            ("ai", lambda: _apply_ai(conn, tenant_id, cfg["ai"], vault)),
            ("admin", lambda: _apply_admin(conn, tenant_id, cfg["admin"])),
            ("smtp", lambda: _apply_smtp(conn, cfg["smtp"])),
        ]
        for name, fn in section_appliers:
            if not isinstance(cfg.get(name), dict):
                result["skipped"].append(f"{name}:absent")
                continue
            try:
                msg = await fn()
                result["applied"].append(msg)
            except Exception as e:
                logger.error(f"[config-file] {name} apply failed: {e}")
                result["skipped"].append(f"{name}:{e}")

    for line in result["applied"]:
        logger.info(f"[config-file] applied {line}")
    for line in result["skipped"]:
        logger.info(f"[config-file] skipped {line}")
    return result
