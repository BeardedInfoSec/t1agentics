# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
T1 Connect Service - Integration Marketplace & Execution Engine

Single service powering the entire T1 Connect system:
- Connector catalog / marketplace (builtin, community, private)
- Instance management (install, configure, enable/disable)
- Credential management with Fernet encryption
- Live auth & action testing
- Custom connector builder with action CRUD
- Export / import of connector definitions
- Community submission & approval workflow
- Platform admin operations
- Health monitoring
- Action execution for Riggs / enrichment pipelines
"""

import os
import re
import json
import uuid
import time
import base64
import secrets
import logging
import aiohttp
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List, Tuple

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from services.postgres_db import postgres_db

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Path to the builtin integration catalog shipped with the backend image
# ---------------------------------------------------------------------------
_CATALOG_ROOT = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "integration-store-output",
    "integrations",
)


# ============================================================================
# ConnectService
# ============================================================================

class ConnectService:
    """
    Unified service for the T1 Connect integration marketplace.

    All database access goes through ``postgres_db.pool`` (asyncpg).
    Encryption mirrors the CredentialsVault pattern from credentials_service.
    """

    def __init__(self):
        self._fernet: Optional[Fernet] = None
        self._init_encryption()

    # ------------------------------------------------------------------
    # Encryption
    # ------------------------------------------------------------------

    def _init_encryption(self):
        key_env = os.environ.get("CREDENTIALS_ENCRYPTION_KEY")
        if key_env:
            try:
                self._fernet = Fernet(key_env.encode())
                logger.info("[ConnectService] Using encryption key from environment")
                return
            except Exception as e:
                logger.warning(f"[ConnectService] Invalid encryption key: {e}")
        # Derive a key from salt + password
        salt = os.environ.get("CREDENTIALS_SALT", "T1 Agentics-default-salt").encode()
        password = os.environ.get("CREDENTIALS_PASSWORD", secrets.token_hex(32)).encode()
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=480000)
        key = base64.urlsafe_b64encode(kdf.derive(password))
        self._fernet = Fernet(key)
        logger.info("[ConnectService] Derived encryption key (set CREDENTIALS_ENCRYPTION_KEY for production)")

    def _encrypt(self, plaintext: str) -> str:
        if not plaintext:
            return ""
        return self._fernet.encrypt(plaintext.encode()).decode()

    def _decrypt(self, ciphertext: str) -> str:
        if not ciphertext:
            return ""
        try:
            return self._fernet.decrypt(ciphertext.encode()).decode()
        except Exception as e:
            logger.error(f"[ConnectService] Decryption failed: {e}")
            return ""

    def _encrypt_dict(self, data: dict) -> str:
        if not data:
            return ""
        return self._encrypt(json.dumps(data))

    def _decrypt_dict(self, ciphertext: str) -> dict:
        if not ciphertext:
            return {}
        try:
            return json.loads(self._decrypt(ciphertext))
        except Exception:
            return {}

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _slugify(name: str) -> str:
        """Convert a human name to a URL-safe slug for use as an ID."""
        s = name.lower().strip()
        s = re.sub(r"[^a-z0-9]+", "_", s)
        s = s.strip("_")
        return s or "connector"

    @staticmethod
    def _now() -> datetime:
        return datetime.now(timezone.utc)

    @staticmethod
    def _row_to_dict(row) -> dict:
        """Convert an asyncpg Record to a plain dict, serialising special types."""
        d = dict(row)
        for k, v in d.items():
            if isinstance(v, datetime):
                d[k] = v.isoformat()
            elif isinstance(v, uuid.UUID):
                d[k] = str(v)
        return d

    # ------------------------------------------------------------------
    # HTTP helpers
    # ------------------------------------------------------------------

    def _build_auth_headers(
        self,
        auth_type: str,
        auth_config: dict,
        secret_data: dict,
    ) -> Dict[str, str]:
        """
        Build HTTP auth headers from auth_type, auth_config, and decrypted
        secret_data.  Supports api_key, bearer, basic, custom_header.
        """
        headers: Dict[str, str] = {}
        at = (auth_type or "").lower()

        if at == "api_key":
            key_value = (secret_data.get("api_key") or secret_data.get("token")
                         or secret_data.get("bearer_token") or "")
            ac = auth_config or {}
            # location == "query" means the key rides in the URL query string,
            # which headers can't carry; the execution engine handles that
            # separately (query-param connectors: enrichment support pending).
            if key_value and ac.get("location") != "query":
                header_name = ac.get("header_name", "X-API-Key")
                prefix = ac.get("prefix", "")
                headers[header_name] = f"{prefix}{key_value}"

        elif at == "bearer":
            token = secret_data.get("token", "") or secret_data.get("bearer_token", "")
            if token:
                headers["Authorization"] = f"Bearer {token}"

        elif at == "basic":
            username = secret_data.get("username", "")
            password = secret_data.get("password", "")
            if username and password:
                encoded = base64.b64encode(f"{username}:{password}".encode()).decode()
                headers["Authorization"] = f"Basic {encoded}"

        elif at == "custom_header":
            for hdr_name, hdr_val in secret_data.items():
                headers[hdr_name] = hdr_val

        return headers

    async def _make_request(
        self,
        method: str,
        url: str,
        headers: Dict[str, str],
        params: Optional[dict] = None,
        body: Optional[Any] = None,
        timeout: int = 30,
    ) -> Dict[str, Any]:
        """
        Make an HTTP request via aiohttp.
        Returns {status_code, headers, body, duration_ms}.
        """
        start = time.monotonic()
        try:
            tm = aiohttp.ClientTimeout(total=timeout)
            async with aiohttp.ClientSession(timeout=tm) as session:
                kwargs: dict = {"headers": headers}
                if params:
                    kwargs["params"] = params
                if body is not None:
                    kwargs["json"] = body

                async with session.request(method.upper(), url, ssl=False, **kwargs) as resp:
                    duration = int((time.monotonic() - start) * 1000)
                    resp_body = None
                    content_type = resp.headers.get("Content-Type", "")
                    if "json" in content_type:
                        try:
                            resp_body = await resp.json()
                        except Exception:
                            resp_body = await resp.text()
                    else:
                        resp_body = await resp.text()
                    return {
                        "status_code": resp.status,
                        "headers": dict(resp.headers),
                        "body": resp_body,
                        "duration_ms": duration,
                    }
        except aiohttp.ClientError as e:
            duration = int((time.monotonic() - start) * 1000)
            return {
                "status_code": 0,
                "headers": {},
                "body": None,
                "duration_ms": duration,
                "error": str(e),
            }
        except Exception as e:
            duration = int((time.monotonic() - start) * 1000)
            return {
                "status_code": 0,
                "headers": {},
                "body": None,
                "duration_ms": duration,
                "error": str(e),
            }

    # ======================================================================
    # 1. Catalog / Marketplace
    # ======================================================================

    async def load_builtin_catalog(self) -> int:
        """
        Walk integration-store-output/integrations/ and upsert every
        integration.json into connector_definitions with source='builtin'.
        Returns the number of connectors loaded.
        """
        from services.postgres_db import set_platform_admin_mode

        # Enable platform admin mode — this runs at startup without HTTP
        # request context, so RLS would block all writes otherwise.
        set_platform_admin_mode(True)
        try:
            return await self._load_builtin_catalog_inner()
        finally:
            set_platform_admin_mode(False)

    async def _load_builtin_catalog_inner(self) -> int:
        """Inner implementation (runs with platform admin mode)."""
        if not os.path.isdir(_CATALOG_ROOT):
            logger.warning(f"[ConnectService] Catalog root not found: {_CATALOG_ROOT}")
            return 0

        loaded = 0
        loaded_ids: set = set()
        for dirpath, _dirnames, filenames in os.walk(_CATALOG_ROOT):
            if "integration.json" not in filenames:
                continue
            filepath = os.path.join(dirpath, "integration.json")
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    data = json.load(f)
            except Exception as e:
                logger.error(f"[ConnectService] Failed to read {filepath}: {e}")
                continue

            connector_id = data.get("id")
            if not connector_id:
                continue
            loaded_ids.add(connector_id)

            # Check for a logo file next to integration.json
            logo_url = None
            for ext in ("png", "svg", "jpg"):
                candidate = os.path.join(dirpath, f"logo.{ext}")
                if os.path.exists(candidate):
                    logo_url = f"/static/integrations/{data.get('category', 'misc')}/{connector_id}/logo.{ext}"
                    break

            async with postgres_db.tenant_acquire() as conn:
                await conn.execute(
                    """
                    INSERT INTO connector_definitions (
                        id, tenant_id, source, name, vendor, category,
                        description, logo_url, auth_type, auth_config,
                        base_url, actions, version, enabled,
                        documentation_url, setup_instructions,
                        created_by, created_at, updated_at
                    ) VALUES (
                        $1, NULL, 'builtin', $2, $3, $4,
                        $5, $6, $7, $8::jsonb,
                        $9, $10::jsonb, $11, TRUE,
                        $12, $13,
                        'system', NOW(), NOW()
                    )
                    ON CONFLICT (id, COALESCE(tenant_id, '00000000-0000-0000-0000-000000000000'::uuid))
                    DO UPDATE SET
                        name               = EXCLUDED.name,
                        vendor             = EXCLUDED.vendor,
                        category           = EXCLUDED.category,
                        description        = EXCLUDED.description,
                        logo_url           = EXCLUDED.logo_url,
                        auth_type          = EXCLUDED.auth_type,
                        auth_config        = EXCLUDED.auth_config,
                        base_url           = EXCLUDED.base_url,
                        actions            = EXCLUDED.actions,
                        version            = EXCLUDED.version,
                        documentation_url  = EXCLUDED.documentation_url,
                        setup_instructions = EXCLUDED.setup_instructions,
                        updated_at         = NOW()
                    """,
                    connector_id,
                    data.get("name", connector_id),
                    data.get("vendor"),
                    data.get("category"),
                    data.get("description"),
                    logo_url,
                    data.get("auth_type"),
                    json.dumps(data.get("auth_config") or {}),
                    data.get("base_url"),
                    json.dumps(data.get("actions") or []),
                    data.get("version", "1.0.0"),
                    data.get("documentation_url"),
                    data.get("setup_instructions"),
                )
            loaded += 1

        logger.info(f"[ConnectService] Loaded {loaded} builtin connectors from catalog")

        # Clean up orphaned builtin connectors that no longer exist in the catalog
        if loaded_ids:
            try:
                async with postgres_db.tenant_acquire() as conn:
                    result = await conn.execute(
                        """
                        DELETE FROM connector_definitions
                        WHERE source = 'builtin' AND tenant_id IS NULL
                          AND id != ALL($1::text[])
                        """,
                        list(loaded_ids),
                    )
                    # result is e.g. "DELETE 12"
                    deleted = int(result.split()[-1]) if result else 0
                    if deleted:
                        logger.info(f"[ConnectService] Purged {deleted} orphaned builtin connectors")
            except Exception as e:
                logger.warning(f"[ConnectService] Orphan cleanup failed: {e}")

        return loaded

    async def get_marketplace(
        self,
        tenant_id: str,
        search: Optional[str] = None,
        category: Optional[str] = None,
        page: int = 1,
        per_page: int = 50,
    ) -> Dict[str, Any]:
        """
        Return connectors visible to *tenant_id*: builtin, community, or
        private connectors owned by the tenant.
        """
        tid = uuid.UUID(tenant_id)
        conditions = [
            "(source IN ('builtin', 'community') OR tenant_id = $1)"
        ]
        params: list = [tid]
        idx = 2

        if search:
            # Only search name, vendor, and category — NOT description.
            # Description matching causes irrelevant results (e.g., "splunk"
            # matching 22 connectors whose descriptions merely mention Splunk).
            conditions.append(
                f"(name ILIKE ${idx} OR vendor ILIKE ${idx} OR category ILIKE ${idx})"
            )
            params.append(f"%{search}%")
            idx += 1

        if category:
            conditions.append(f"LOWER(category) = LOWER(${idx})")
            params.append(category)
            idx += 1

        where = " AND ".join(conditions)

        async with postgres_db.tenant_acquire() as conn:
            total = await conn.fetchval(
                f"SELECT COUNT(*) FROM connector_definitions WHERE {where} AND enabled = TRUE AND (deprecated IS NULL OR deprecated = FALSE)",
                *params,
            )
            offset = (page - 1) * per_page

            # When searching, rank by relevance: name prefix > name contains >
            # vendor match > description match. Without search, sort by name.
            if search:
                search_param_idx = 2  # $2 is always the search param
                order_clause = f"""
                ORDER BY
                  CASE WHEN name ILIKE ${search_param_idx} THEN 0 ELSE 1 END,
                  CASE WHEN LOWER(name) = LOWER(TRIM(${search_param_idx}, '%')) THEN 0
                       WHEN name ILIKE TRIM(${search_param_idx}, '%') || '%' THEN 1
                       WHEN name ILIKE ${search_param_idx} THEN 2
                       WHEN vendor ILIKE ${search_param_idx} THEN 3
                       ELSE 4 END,
                  name ASC"""
            else:
                order_clause = "ORDER BY name ASC"

            rows = await conn.fetch(
                f"""
                SELECT * FROM connector_definitions
                WHERE {where} AND enabled = TRUE AND (deprecated IS NULL OR deprecated = FALSE)
                {order_clause}
                LIMIT ${idx} OFFSET ${idx + 1}
                """,
                *params,
                per_page,
                offset,
            )

        items = [self._row_to_dict(r) for r in rows]
        # Parse JSONB fields that asyncpg may return as strings
        for item in items:
            if isinstance(item.get("auth_config"), str):
                item["auth_config"] = json.loads(item["auth_config"])
            if isinstance(item.get("actions"), str):
                item["actions"] = json.loads(item["actions"])

        import math
        return {"items": items, "total": total, "page": page, "per_page": per_page, "total_pages": math.ceil(total / per_page) if per_page else 1}

    async def get_connector_detail(
        self, connector_id: str, tenant_id: str
    ) -> Optional[dict]:
        """Get a single connector visible to this tenant."""
        tid = uuid.UUID(tenant_id)
        async with postgres_db.tenant_acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT * FROM connector_definitions
                WHERE id = $1 AND (tenant_id IS NULL OR tenant_id = $2)
                """,
                connector_id,
                tid,
            )
        if not row:
            return None
        d = self._row_to_dict(row)
        if isinstance(d.get("auth_config"), str):
            d["auth_config"] = json.loads(d["auth_config"])
        if isinstance(d.get("actions"), str):
            d["actions"] = json.loads(d["actions"])
        return d

    # ======================================================================
    # 2. Instances (installed connectors)
    # ======================================================================

    async def install_connector(
        self,
        tenant_id: str,
        connector_id: str,
        display_name: Optional[str] = None,
        credential_id: Optional[str] = None,
        config: Optional[dict] = None,
        created_by: Optional[str] = None,
    ) -> dict:
        """Install a connector for a tenant (create connect_instances row)."""
        import json as _json
        tid = uuid.UUID(tenant_id)
        cred_id = uuid.UUID(credential_id) if credential_id else None
        config_json = _json.dumps(config) if config else '{}'

        # Verify connector is visible
        connector = await self.get_connector_detail(connector_id, tenant_id)
        if not connector:
            raise ValueError(f"Connector '{connector_id}' not found or not visible to tenant")

        instance_id = uuid.uuid4()
        name = display_name or connector.get("name", connector_id)

        async with postgres_db.tenant_acquire() as conn:
            await conn.execute(
                """
                INSERT INTO connect_instances (
                    id, tenant_id, connector_id, credential_id, display_name,
                    config, enabled, health_status,
                    total_requests, success_requests, failed_requests,
                    created_by, created_at, updated_at
                ) VALUES (
                    $1, $2, $3, $4, $5,
                    $6::jsonb, TRUE, 'unknown',
                    0, 0, 0,
                    $7, NOW(), NOW()
                )
                """,
                instance_id,
                tid,
                connector_id,
                cred_id,
                name,
                config_json,
                created_by,
            )
            # Also update credential with linked instance
            if cred_id:
                await conn.execute(
                    "UPDATE connect_credentials SET linked_instance_id = $1, updated_at = NOW() WHERE id = $2 AND tenant_id = $3",
                    instance_id, cred_id, tid,
                )
            row = await conn.fetchrow(
                "SELECT * FROM connect_instances WHERE id = $1", instance_id
            )

        # Auto-run health check so the instance doesn't start as "unknown / never"
        try:
            await self.test_instance(tenant_id, str(instance_id))
        except Exception:
            pass  # non-fatal — instance is still created

        # Re-fetch after health check
        async with postgres_db.tenant_acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM connect_instances WHERE id = $1", instance_id
            )
        return self._row_to_dict(row)

    async def get_instances(self, tenant_id: str) -> List[dict]:
        """Get all instances for a tenant, joined with connector info."""
        tid = uuid.UUID(tenant_id)
        async with postgres_db.tenant_acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT i.*, c.name AS connector_name, c.vendor, c.category,
                       c.logo_url, c.auth_type, c.auth_config, c.base_url,
                       c.actions AS connector_actions, c.description AS connector_description,
                       c.documentation_url, c.setup_instructions
                FROM connect_instances i
                JOIN connector_definitions c
                  ON c.id = i.connector_id
                  AND (c.tenant_id IS NULL OR c.tenant_id = i.tenant_id)
                WHERE i.tenant_id = $1
                ORDER BY i.created_at DESC
                """,
                tid,
            )
        items = [self._row_to_dict(r) for r in rows]
        for item in items:
            for key in ("auth_config", "connector_actions", "config"):
                if isinstance(item.get(key), str):
                    item[key] = json.loads(item[key])
        return items

    async def get_instance(self, tenant_id: str, instance_id: str) -> Optional[dict]:
        tid = uuid.UUID(tenant_id)
        iid = uuid.UUID(instance_id)
        async with postgres_db.tenant_acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT i.*, c.name AS connector_name, c.vendor, c.category,
                       c.logo_url, c.auth_type, c.auth_config, c.base_url,
                       c.actions AS connector_actions, c.description AS connector_description,
                       c.documentation_url, c.setup_instructions
                FROM connect_instances i
                JOIN connector_definitions c
                  ON c.id = i.connector_id
                  AND (c.tenant_id IS NULL OR c.tenant_id = i.tenant_id)
                WHERE i.id = $1 AND i.tenant_id = $2
                """,
                iid,
                tid,
            )
        if not row:
            return None
        d = self._row_to_dict(row)
        for key in ("auth_config", "connector_actions", "config"):
            if isinstance(d.get(key), str):
                d[key] = json.loads(d[key])
        return d

    async def update_instance(
        self,
        tenant_id: str,
        instance_id: str,
        config: Optional[dict] = None,
        display_name: Optional[str] = None,
        credential_id: Optional[str] = None,
    ) -> Optional[dict]:
        tid = uuid.UUID(tenant_id)
        iid = uuid.UUID(instance_id)
        sets: list = []
        params: list = [iid, tid]
        idx = 3

        if config is not None:
            sets.append(f"config = ${idx}::jsonb")
            params.append(json.dumps(config))
            idx += 1
        if display_name is not None:
            sets.append(f"display_name = ${idx}")
            params.append(display_name)
            idx += 1
        if credential_id is not None:
            cred_val = uuid.UUID(credential_id) if credential_id else None
            sets.append(f"credential_id = ${idx}")
            params.append(cred_val)
            idx += 1

        if not sets:
            return await self.get_instance(tenant_id, instance_id)

        sets.append("updated_at = NOW()")
        sql = f"UPDATE connect_instances SET {', '.join(sets)} WHERE id = $1 AND tenant_id = $2"

        async with postgres_db.tenant_acquire() as conn:
            await conn.execute(sql, *params)
        return await self.get_instance(tenant_id, instance_id)

    async def delete_instance(self, tenant_id: str, instance_id: str) -> bool:
        tid = uuid.UUID(tenant_id)
        iid = uuid.UUID(instance_id)
        async with postgres_db.tenant_acquire() as conn:
            # Unlink any credential that points to this instance
            await conn.execute(
                "UPDATE connect_credentials SET linked_instance_id = NULL WHERE linked_instance_id = $1 AND tenant_id = $2",
                iid, tid,
            )
            result = await conn.execute(
                "DELETE FROM connect_instances WHERE id = $1 AND tenant_id = $2",
                iid, tid,
            )
        return "DELETE 1" in result

    async def toggle_instance(self, tenant_id: str, instance_id: str) -> Optional[dict]:
        tid = uuid.UUID(tenant_id)
        iid = uuid.UUID(instance_id)
        async with postgres_db.tenant_acquire() as conn:
            await conn.execute(
                """
                UPDATE connect_instances
                SET enabled = NOT enabled, updated_at = NOW()
                WHERE id = $1 AND tenant_id = $2
                """,
                iid, tid,
            )
        return await self.get_instance(tenant_id, instance_id)

    # ======================================================================
    # 3. Credentials
    # ======================================================================

    async def create_credential(
        self,
        tenant_id: str,
        name: str,
        auth_type: str,
        secret_data: dict,
        metadata: Optional[dict] = None,
        tags: Optional[List[str]] = None,
        created_by: Optional[str] = None,
    ) -> dict:
        """Encrypt *secret_data* and store in connect_credentials.

        If a credential with the same (tenant_id, name) already exists,
        update it in place instead of failing on the unique constraint.
        """
        tid = uuid.UUID(tenant_id)
        cred_id = uuid.uuid4()
        encrypted = self._encrypt_dict(secret_data)

        async with postgres_db.tenant_acquire() as conn:
            row = await conn.fetchrow(
                """
                INSERT INTO connect_credentials (
                    id, tenant_id, name, auth_type, encrypted_data,
                    metadata, tags, created_by, created_at, updated_at
                ) VALUES (
                    $1, $2, $3, $4, $5,
                    $6::jsonb, $7, $8, NOW(), NOW()
                )
                ON CONFLICT (tenant_id, name) DO UPDATE SET
                    auth_type = EXCLUDED.auth_type,
                    encrypted_data = EXCLUDED.encrypted_data,
                    metadata = EXCLUDED.metadata,
                    tags = EXCLUDED.tags,
                    updated_at = NOW()
                RETURNING *
                """,
                cred_id,
                tid,
                name,
                auth_type,
                encrypted,
                json.dumps(metadata or {}),
                tags or [],
                created_by,
            )
        d = self._row_to_dict(row)
        d.pop("encrypted_data", None)  # never expose
        return d

    async def get_credentials(self, tenant_id: str) -> List[dict]:
        """List credentials for a tenant -- never returns encrypted_data."""
        tid = uuid.UUID(tenant_id)
        async with postgres_db.tenant_acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT id, tenant_id, name, auth_type, metadata,
                       linked_instance_id, tags, created_by,
                       created_at, updated_at, last_used_at
                FROM connect_credentials
                WHERE tenant_id = $1
                ORDER BY created_at DESC
                """,
                tid,
            )
        items = [self._row_to_dict(r) for r in rows]
        for item in items:
            if isinstance(item.get("metadata"), str):
                item["metadata"] = json.loads(item["metadata"])
        return items

    async def get_credential_decrypted(
        self, tenant_id: str, credential_id: str
    ) -> Optional[dict]:
        """Return the credential with decrypted secret_data. Internal use only."""
        tid = uuid.UUID(tenant_id)
        cid = uuid.UUID(credential_id)
        async with postgres_db.tenant_acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM connect_credentials WHERE id = $1 AND tenant_id = $2",
                cid, tid,
            )
        if not row:
            return None
        d = self._row_to_dict(row)
        d["secret_data"] = self._decrypt_dict(d.pop("encrypted_data", ""))
        if isinstance(d.get("metadata"), str):
            d["metadata"] = json.loads(d["metadata"])
        return d

    async def delete_credential(self, tenant_id: str, credential_id: str) -> bool:
        tid = uuid.UUID(tenant_id)
        cid = uuid.UUID(credential_id)
        async with postgres_db.tenant_acquire() as conn:
            # Unlink from any instance
            await conn.execute(
                "UPDATE connect_instances SET credential_id = NULL, updated_at = NOW() WHERE credential_id = $1 AND tenant_id = $2",
                cid, tid,
            )
            result = await conn.execute(
                "DELETE FROM connect_credentials WHERE id = $1 AND tenant_id = $2",
                cid, tid,
            )
        return "DELETE 1" in result

    async def link_credential_to_instance(
        self, tenant_id: str, instance_id: str, credential_id: str
    ) -> None:
        tid = uuid.UUID(tenant_id)
        iid = uuid.UUID(instance_id)
        cid = uuid.UUID(credential_id)
        async with postgres_db.tenant_acquire() as conn:
            await conn.execute(
                "UPDATE connect_instances SET credential_id = $1, updated_at = NOW() WHERE id = $2 AND tenant_id = $3",
                cid, iid, tid,
            )
            await conn.execute(
                "UPDATE connect_credentials SET linked_instance_id = $1, updated_at = NOW() WHERE id = $2 AND tenant_id = $3",
                iid, cid, tid,
            )

    # ======================================================================
    # 4. Testing
    # ======================================================================

    async def _test_smtp_auth(self, base_url: str, temp_credential: dict) -> Dict[str, Any]:
        """Test SMTP connection and authentication."""
        import smtplib
        import ssl as ssl_module
        from urllib.parse import urlparse
        import asyncio

        parsed = urlparse(base_url)
        host = parsed.hostname or 'localhost'
        port = parsed.port or (465 if base_url.startswith('smtps://') else 587)
        use_ssl = base_url.startswith('smtps://')
        username = temp_credential.get('username', '')
        password = temp_credential.get('password', '')

        def _connect():
            if use_ssl:
                ctx = ssl_module.create_default_context()
                with smtplib.SMTP_SSL(host, port, context=ctx, timeout=10) as server:
                    server.login(username, password)
            else:
                with smtplib.SMTP(host, port, timeout=10) as server:
                    server.ehlo()
                    server.starttls()
                    server.ehlo()
                    server.login(username, password)

        try:
            await asyncio.get_event_loop().run_in_executor(None, _connect)
            return {"success": True, "message": f"SMTP authentication successful ({host}:{port})"}
        except smtplib.SMTPAuthenticationError:
            return {"success": False, "message": "Authentication failed — check username and password. If MFA is enabled, use an App Password."}
        except smtplib.SMTPConnectError as e:
            return {"success": False, "message": f"Connection refused — verify host and port ({host}:{port})"}
        except Exception as e:
            return {"success": False, "message": f"Connection failed: {str(e)}"}

    async def _test_imap_auth(self, base_url: str, temp_credential: dict) -> Dict[str, Any]:
        """Test IMAP connection and authentication."""
        import imaplib
        from urllib.parse import urlparse
        import asyncio

        parsed = urlparse(base_url)
        host = parsed.hostname or 'localhost'
        port = parsed.port or (993 if base_url.startswith('imaps://') else 143)
        use_ssl = base_url.startswith('imaps://')
        username = temp_credential.get('username', '')
        password = temp_credential.get('password', '')

        def _connect():
            if use_ssl:
                imap = imaplib.IMAP4_SSL(host, port)
            else:
                imap = imaplib.IMAP4(host, port)
            try:
                imap.login(username, password)
                imap.logout()
            except Exception:
                try:
                    imap.logout()
                except Exception:
                    pass
                raise

        try:
            await asyncio.get_event_loop().run_in_executor(None, _connect)
            return {"success": True, "message": f"IMAP authentication successful ({host}:{port})"}
        except imaplib.IMAP4.error as e:
            return {"success": False, "message": f"Authentication failed — check username and password. If MFA is enabled, use an App Password."}
        except Exception as e:
            return {"success": False, "message": f"Connection failed: {str(e)}"}

    async def test_auth(
        self,
        base_url: str,
        auth_type: str,
        auth_config: dict,
        temp_credential: dict,
    ) -> Dict[str, Any]:
        """
        Test authentication without persisting anything.
        *temp_credential* is a dict of raw (unencrypted) secret values.
        """
        # Handle non-HTTP protocols
        if base_url.startswith(('smtp://', 'smtps://')):
            return await self._test_smtp_auth(base_url, temp_credential)
        if base_url.startswith(('imap://', 'imaps://')):
            return await self._test_imap_auth(base_url, temp_credential)

        headers = self._build_auth_headers(auth_type, auth_config, temp_credential)
        result = await self._make_request("HEAD", base_url, headers, timeout=15)
        # Fall back to GET if HEAD not supported or root not found
        if result.get("status_code") in (404, 405, 0):
            result = await self._make_request("GET", base_url, headers, timeout=15)

        status = result.get("status_code") or 0

        # 401/403 = definite auth failure
        if status in (401, 403):
            return {
                "success": False,
                "status_code": status,
                "duration_ms": result.get("duration_ms"),
                "message": "Authentication failed — invalid credentials" if status == 401 else "Authentication failed — access denied",
            }

        # 200-399 = definite success
        if 200 <= status < 400:
            return {
                "success": True,
                "status_code": status,
                "duration_ms": result.get("duration_ms"),
                "message": "Authentication successful",
            }

        # 404 = server reachable, auth wasn't rejected (many APIs don't serve root)
        if status == 404:
            return {
                "success": True,
                "status_code": status,
                "duration_ms": result.get("duration_ms"),
                "message": "Server reachable — credentials accepted",
            }

        # Connection failure
        if status == 0:
            return {
                "success": False,
                "status_code": 0,
                "duration_ms": result.get("duration_ms"),
                "message": result.get("error") or "Connection failed — check the base URL",
            }

        # Other errors (5xx, etc.)
        return {
            "success": False,
            "status_code": status,
            "duration_ms": result.get("duration_ms"),
            "message": f"Server returned HTTP {status}",
        }

    async def test_action(
        self,
        connector_def: dict,
        temp_credential: dict,
        action: dict,
        test_value: str,
    ) -> Dict[str, Any]:
        """
        Test a single action with a sample value.
        *connector_def*: {base_url, auth_type, auth_config}
        *action*: {http_method / method, endpoint, observable_type}
        """
        auth_type = connector_def.get("auth_type", "")
        auth_config = connector_def.get("auth_config") or {}
        base_url = (connector_def.get("base_url") or "").rstrip("/")
        headers = self._build_auth_headers(auth_type, auth_config, temp_credential)

        method = action.get("http_method") or action.get("method", "GET")
        endpoint = action.get("endpoint", "")

        # Substitute path params with test_value
        url = base_url + endpoint
        # Replace any {placeholder} with the test value
        url = re.sub(r"\{[^}]+\}", test_value, url)

        params = None
        obs_type = action.get("observable_type", "")
        # For GET endpoints with query params, add the observable as a query param
        if method.upper() == "GET" and "{" not in action.get("endpoint", "") and obs_type:
            params = {obs_type: test_value}

        # Parse request_body template if provided (for POST/PUT/PATCH actions)
        request_body = None
        raw_body = action.get("request_body")
        if raw_body and raw_body.strip() and method.upper() not in ("GET", "DELETE"):
            try:
                request_body = json.loads(raw_body)
            except (json.JSONDecodeError, TypeError):
                # If it's not valid JSON, send as-is (string)
                request_body = raw_body

        result = await self._make_request(method, url, headers, params=params, body=request_body, timeout=30)
        success = 200 <= (result.get("status_code") or 0) < 400
        # Truncate response for preview
        body = result.get("body")
        preview = None
        if body is not None:
            if isinstance(body, dict):
                preview = json.dumps(body)[:2000]
            else:
                preview = str(body)[:2000]

        return {
            "success": success,
            "status_code": result.get("status_code"),
            "duration_ms": result.get("duration_ms"),
            "response_preview": preview,
            "headers": result.get("headers"),
        }

    async def test_instance(
        self, tenant_id: str, instance_id: str
    ) -> Dict[str, Any]:
        """Test an installed instance using its saved credential."""
        inst = await self.get_instance(tenant_id, instance_id)
        if not inst:
            return {"success": False, "message": "Instance not found"}

        cred_id = inst.get("credential_id")
        if not cred_id:
            return {"success": False, "message": "No credential linked to this instance"}

        cred = await self.get_credential_decrypted(tenant_id, str(cred_id))
        if not cred:
            return {"success": False, "message": "Credential not found"}

        auth_type = inst.get("auth_type", "")
        auth_config = inst.get("auth_config") or {}
        # Instance config can override the connector definition's base_url
        inst_config = inst.get("config") or {}
        base_url = inst_config.get("base_url") or inst.get("base_url", "")
        secret_data = cred.get("secret_data", {})
        headers = self._build_auth_headers(auth_type, auth_config, secret_data)

        result = await self._make_request("HEAD", base_url, headers, timeout=15)
        if result.get("status_code") in (404, 405, 0):
            result = await self._make_request("GET", base_url, headers, timeout=15)

        status = result.get("status_code") or 0
        # 401/403 = auth failure, 404 = server reachable (root not found is OK)
        success = (200 <= status < 400) or status == 404
        health = "healthy" if success else "down"

        # Update health
        iid = uuid.UUID(instance_id)
        async with postgres_db.tenant_acquire() as conn:
            await conn.execute(
                "UPDATE connect_instances SET health_status = $1, health_checked = NOW(), updated_at = NOW() WHERE id = $2",
                health, iid,
            )

        if success:
            msg = "Instance healthy" if status != 404 else "Server reachable — credentials accepted"
        else:
            msg = result.get("error") or f"HTTP {status}"

        # Notify on unhealthy integration
        if health == "down":
            try:
                from routes.notifications import create_notification
                inst_name = inst.get("name") or inst.get("connector_id", "Unknown")
                await create_notification(
                    tenant_id=tenant_id,
                    title=f"Integration '{inst_name}' is Down",
                    message=msg,
                    category="integration",
                    severity="high",
                    link="/workbench/connect",
                )
            except Exception:
                pass

        return {
            "success": success,
            "status_code": status,
            "duration_ms": result.get("duration_ms"),
            "health_status": health,
            "message": msg,
        }

    # ======================================================================
    # 5. Custom Connectors (Private)
    # ======================================================================

    async def create_custom_connector(
        self, tenant_id: str, data: dict, created_by: Optional[str] = None
    ) -> dict:
        tid = uuid.UUID(tenant_id)
        connector_id = self._slugify(data.get("name", "custom"))
        actions = data.get("actions") or []
        for action in actions:
            action.setdefault("origin", "custom")
            if not action.get("id"):
                action["id"] = self._slugify(action.get("name", "action"))

        async with postgres_db.tenant_acquire() as conn:
            await conn.execute(
                """
                INSERT INTO connector_definitions (
                    id, tenant_id, source, name, vendor, category,
                    description, auth_type, auth_config, base_url,
                    actions, version, enabled,
                    created_by, created_at, updated_at
                ) VALUES (
                    $1, $2, 'private', $3, $4, $5,
                    $6, $7, $8::jsonb, $9,
                    $10::jsonb, '1.0.0', TRUE,
                    $11, NOW(), NOW()
                )
                """,
                connector_id,
                tid,
                data.get("name"),
                data.get("vendor"),
                data.get("category"),
                data.get("description"),
                data.get("auth_type"),
                json.dumps(data.get("auth_config") or {}),
                data.get("base_url"),
                json.dumps(actions),
                created_by,
            )
        return await self.get_connector_detail(connector_id, tenant_id) or {"id": connector_id}

    async def update_custom_connector(
        self, tenant_id: str, connector_id: str, data: dict
    ) -> Optional[dict]:
        tid = uuid.UUID(tenant_id)
        sets: list = []
        params: list = [connector_id, tid]
        idx = 3

        for field in ("name", "vendor", "category", "description", "auth_type", "base_url"):
            if field in data:
                sets.append(f"{field} = ${idx}")
                params.append(data[field])
                idx += 1
        if "auth_config" in data:
            sets.append(f"auth_config = ${idx}::jsonb")
            params.append(json.dumps(data["auth_config"]))
            idx += 1
        if "actions" in data:
            sets.append(f"actions = ${idx}::jsonb")
            params.append(json.dumps(data["actions"]))
            idx += 1

        if not sets:
            return await self.get_connector_detail(connector_id, tenant_id)

        sets.append("updated_at = NOW()")
        sql = f"UPDATE connector_definitions SET {', '.join(sets)} WHERE id = $1 AND tenant_id = $2 AND source = 'private'"
        async with postgres_db.tenant_acquire() as conn:
            await conn.execute(sql, *params)
        return await self.get_connector_detail(connector_id, tenant_id)

    async def delete_custom_connector(
        self, tenant_id: str, connector_id: str
    ) -> bool:
        tid = uuid.UUID(tenant_id)
        async with postgres_db.tenant_acquire() as conn:
            result = await conn.execute(
                "DELETE FROM connector_definitions WHERE id = $1 AND tenant_id = $2 AND source = 'private'",
                connector_id, tid,
            )
        return "DELETE 1" in result

    # ======================================================================
    # 6. Action Management on Custom / Installed Connectors
    # ======================================================================

    async def _get_actions(self, connector_id: str, tenant_id: str) -> Tuple[Optional[list], Optional[uuid.UUID]]:
        """Fetch the actions JSONB array for a private connector. Returns (actions_list, tenant_uuid)."""
        tid = uuid.UUID(tenant_id)
        async with postgres_db.tenant_acquire() as conn:
            row = await conn.fetchrow(
                "SELECT actions, tenant_id FROM connector_definitions WHERE id = $1 AND tenant_id = $2 AND source = 'private'",
                connector_id, tid,
            )
        if not row:
            return None, None
        actions = row["actions"]
        if isinstance(actions, str):
            actions = json.loads(actions)
        return actions, tid

    async def _save_actions(self, connector_id: str, tid: uuid.UUID, actions: list):
        async with postgres_db.tenant_acquire() as conn:
            await conn.execute(
                "UPDATE connector_definitions SET actions = $1::jsonb, updated_at = NOW() WHERE id = $2 AND tenant_id = $3",
                json.dumps(actions), connector_id, tid,
            )

    async def add_action(
        self, tenant_id: str, connector_id: str, action_data: dict
    ) -> dict:
        actions, tid = await self._get_actions(connector_id, tenant_id)
        if actions is None:
            raise ValueError("Private connector not found")

        action_id = self._slugify(action_data.get("name", "action"))
        new_action = {
            "id": action_id,
            "name": action_data.get("name"),
            "http_method": action_data.get("method") or action_data.get("http_method", "GET"),
            "endpoint": action_data.get("endpoint", ""),
            "observable_type": action_data.get("observable_type"),
            "description": action_data.get("description"),
            "request_body": action_data.get("request_body"),
            "read_only": action_data.get("read_only", True),
            "cacheable": action_data.get("cacheable", False),
            "origin": "custom",
        }
        actions.append(new_action)
        await self._save_actions(connector_id, tid, actions)
        return new_action

    async def remove_action(
        self, tenant_id: str, connector_id: str, action_id: str
    ) -> bool:
        actions, tid = await self._get_actions(connector_id, tenant_id)
        if actions is None:
            raise ValueError("Private connector not found")

        original_len = len(actions)
        actions = [
            a for a in actions
            if not (a.get("id") == action_id and a.get("origin", "builtin") in ("custom", "cloned"))
        ]
        if len(actions) == original_len:
            raise ValueError(f"Action '{action_id}' not found or is a builtin action that cannot be removed")
        await self._save_actions(connector_id, tid, actions)
        return True

    async def clone_action(
        self, tenant_id: str, connector_id: str, action_id: str
    ) -> dict:
        actions, tid = await self._get_actions(connector_id, tenant_id)
        if actions is None:
            raise ValueError("Private connector not found")

        source_action = next((a for a in actions if a.get("id") == action_id), None)
        if not source_action:
            raise ValueError(f"Action '{action_id}' not found")

        suffix = secrets.token_hex(3)
        cloned = dict(source_action)
        cloned["id"] = f"{action_id}_clone_{suffix}"
        cloned["name"] = f"{source_action.get('name', action_id)} (Copy)"
        cloned["origin"] = "cloned"
        cloned["cloned_from"] = action_id
        actions.append(cloned)
        await self._save_actions(connector_id, tid, actions)
        return cloned

    async def update_action(
        self, tenant_id: str, connector_id: str, action_id: str, action_data: dict
    ) -> dict:
        actions, tid = await self._get_actions(connector_id, tenant_id)
        if actions is None:
            raise ValueError("Private connector not found")

        for i, a in enumerate(actions):
            if a.get("id") == action_id:
                if a.get("origin", "builtin") == "builtin":
                    raise ValueError("Cannot edit a builtin action. Clone it first.")
                for field in ("name", "http_method", "method", "endpoint", "observable_type", "description", "request_body", "read_only", "cacheable"):
                    if field in action_data:
                        key = "http_method" if field == "method" else field
                        actions[i][key] = action_data[field]
                await self._save_actions(connector_id, tid, actions)
                return actions[i]

        raise ValueError(f"Action '{action_id}' not found")

    # ======================================================================
    # 7. Export / Import
    # ======================================================================

    async def export_connector(self, tenant_id: str, connector_id: str) -> dict:
        detail = await self.get_connector_detail(connector_id, tenant_id)
        if not detail:
            raise ValueError("Connector not found or not visible")
        # Strip internal fields
        for key in ("created_at", "updated_at", "created_by", "enabled", "deprecated", "tenant_id"):
            detail.pop(key, None)
        detail["t1_connector"] = "1.0"
        return detail

    async def import_connector(
        self, tenant_id: str, data: dict, created_by: Optional[str] = None
    ) -> dict:
        if data.get("t1_connector") is None:
            raise ValueError("Invalid connector format: missing t1_connector version marker")
        # Strip the marker and import as private
        data.pop("t1_connector", None)
        data.pop("source", None)
        data.pop("tenant_id", None)
        return await self.create_custom_connector(tenant_id, data, created_by=created_by)

    # ======================================================================
    # 8. Submissions (Community Marketplace Workflow)
    # ======================================================================

    async def submit_to_marketplace(
        self, tenant_id: str, connector_id: str, submitted_by: Optional[str] = None
    ) -> dict:
        tid = uuid.UUID(tenant_id)
        # Verify ownership
        async with postgres_db.tenant_acquire() as conn:
            exists = await conn.fetchval(
                "SELECT 1 FROM connector_definitions WHERE id = $1 AND tenant_id = $2 AND source = 'private'",
                connector_id, tid,
            )
            if not exists:
                raise ValueError("Only private connectors owned by your tenant can be submitted")

            sub_id = uuid.uuid4()
            await conn.execute(
                """
                INSERT INTO connector_submissions (
                    id, tenant_id, connector_id, status,
                    submitted_by, submitted_at
                ) VALUES ($1, $2, $3, 'pending', $4, NOW())
                """,
                sub_id, tid, connector_id, submitted_by,
            )
            row = await conn.fetchrow(
                "SELECT * FROM connector_submissions WHERE id = $1", sub_id
            )
        return self._row_to_dict(row)

    async def get_submissions(
        self,
        tenant_id: Optional[str] = None,
        status_filter: Optional[str] = None,
    ) -> List[dict]:
        conditions: list = []
        params: list = []
        idx = 1

        if tenant_id:
            conditions.append(f"tenant_id = ${idx}")
            params.append(uuid.UUID(tenant_id))
            idx += 1
        if status_filter:
            conditions.append(f"status = ${idx}")
            params.append(status_filter)
            idx += 1

        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        async with postgres_db.tenant_acquire() as conn:
            rows = await conn.fetch(
                f"SELECT * FROM connector_submissions {where} ORDER BY submitted_at DESC",
                *params,
            )
        return [self._row_to_dict(r) for r in rows]

    async def approve_submission(
        self, submission_id: str, reviewed_by: Optional[str] = None
    ) -> dict:
        sid = uuid.UUID(submission_id)
        async with postgres_db.tenant_acquire() as conn:
            sub = await conn.fetchrow(
                "SELECT * FROM connector_submissions WHERE id = $1", sid
            )
            if not sub:
                raise ValueError("Submission not found")
            if sub["status"] != "pending":
                raise ValueError(f"Submission is already '{sub['status']}'")

            # Copy the private connector as community
            orig = await conn.fetchrow(
                "SELECT * FROM connector_definitions WHERE id = $1 AND tenant_id = $2",
                sub["connector_id"], sub["tenant_id"],
            )
            if not orig:
                raise ValueError("Original connector not found")

            await conn.execute(
                """
                INSERT INTO connector_definitions (
                    id, tenant_id, source, name, vendor, category,
                    description, logo_url, auth_type, auth_config,
                    base_url, actions, version, enabled,
                    created_by, created_at, updated_at
                ) VALUES (
                    $1, NULL, 'community', $2, $3, $4,
                    $5, $6, $7, $8,
                    $9, $10, $11, TRUE,
                    $12, NOW(), NOW()
                )
                ON CONFLICT (id, COALESCE(tenant_id, '00000000-0000-0000-0000-000000000000'::uuid))
                DO UPDATE SET
                    name = EXCLUDED.name,
                    vendor = EXCLUDED.vendor,
                    category = EXCLUDED.category,
                    description = EXCLUDED.description,
                    auth_type = EXCLUDED.auth_type,
                    auth_config = EXCLUDED.auth_config,
                    base_url = EXCLUDED.base_url,
                    actions = EXCLUDED.actions,
                    version = EXCLUDED.version,
                    updated_at = NOW()
                """,
                orig["id"],
                orig["name"],
                orig["vendor"],
                orig["category"],
                orig["description"],
                orig["logo_url"],
                orig["auth_type"],
                orig["auth_config"] if not isinstance(orig["auth_config"], str) else orig["auth_config"],
                orig["base_url"],
                orig["actions"] if not isinstance(orig["actions"], str) else orig["actions"],
                orig["version"],
                reviewed_by,
            )

            # Update submission
            await conn.execute(
                """
                UPDATE connector_submissions
                SET status = 'approved', reviewed_by = $1, reviewed_at = NOW()
                WHERE id = $2
                """,
                reviewed_by, sid,
            )
            row = await conn.fetchrow(
                "SELECT * FROM connector_submissions WHERE id = $1", sid
            )
        return self._row_to_dict(row)

    async def reject_submission(
        self, submission_id: str, review_notes: str, reviewed_by: Optional[str] = None
    ) -> dict:
        sid = uuid.UUID(submission_id)
        async with postgres_db.tenant_acquire() as conn:
            await conn.execute(
                """
                UPDATE connector_submissions
                SET status = 'rejected', review_notes = $1, reviewed_by = $2, reviewed_at = NOW()
                WHERE id = $3
                """,
                review_notes, reviewed_by, sid,
            )
            row = await conn.fetchrow(
                "SELECT * FROM connector_submissions WHERE id = $1", sid
            )
        if not row:
            raise ValueError("Submission not found")
        return self._row_to_dict(row)

    # ======================================================================
    # 9. Platform Admin
    # ======================================================================

    async def admin_add_connector(
        self, data: dict, created_by: Optional[str] = None
    ) -> dict:
        connector_id = data.get("id") or self._slugify(data.get("name", "connector"))
        actions = data.get("actions") or []
        async with postgres_db.tenant_acquire() as conn:
            await conn.execute(
                """
                INSERT INTO connector_definitions (
                    id, tenant_id, source, name, vendor, category,
                    description, logo_url, auth_type, auth_config,
                    base_url, actions, version, enabled,
                    created_by, created_at, updated_at
                ) VALUES (
                    $1, NULL, 'builtin', $2, $3, $4,
                    $5, $6, $7, $8::jsonb,
                    $9, $10::jsonb, $11, TRUE,
                    $12, NOW(), NOW()
                )
                """,
                connector_id,
                data.get("name"),
                data.get("vendor"),
                data.get("category"),
                data.get("description"),
                data.get("logo_url"),
                data.get("auth_type"),
                json.dumps(data.get("auth_config") or {}),
                data.get("base_url"),
                json.dumps(actions),
                data.get("version", "1.0.0"),
                created_by,
            )
            row = await conn.fetchrow(
                "SELECT * FROM connector_definitions WHERE id = $1 AND tenant_id IS NULL",
                connector_id,
            )
        d = self._row_to_dict(row)
        if isinstance(d.get("auth_config"), str):
            d["auth_config"] = json.loads(d["auth_config"])
        if isinstance(d.get("actions"), str):
            d["actions"] = json.loads(d["actions"])
        return d

    async def admin_update_connector(
        self, connector_id: str, data: dict, updated_by: Optional[str] = None
    ) -> Optional[dict]:
        sets: list = []
        params: list = [connector_id]
        idx = 2

        for field in ("name", "vendor", "category", "description", "logo_url", "auth_type", "base_url", "version"):
            if field in data:
                sets.append(f"{field} = ${idx}")
                params.append(data[field])
                idx += 1
        if "auth_config" in data:
            sets.append(f"auth_config = ${idx}::jsonb")
            params.append(json.dumps(data["auth_config"]))
            idx += 1
        if "actions" in data:
            sets.append(f"actions = ${idx}::jsonb")
            params.append(json.dumps(data["actions"]))
            idx += 1
        if "enabled" in data:
            sets.append(f"enabled = ${idx}")
            params.append(data["enabled"])
            idx += 1

        if not sets:
            return None
        sets.append("updated_at = NOW()")
        sql = f"UPDATE connector_definitions SET {', '.join(sets)} WHERE id = $1 AND tenant_id IS NULL"
        async with postgres_db.tenant_acquire() as conn:
            await conn.execute(sql, *params)
            row = await conn.fetchrow(
                "SELECT * FROM connector_definitions WHERE id = $1 AND tenant_id IS NULL",
                connector_id,
            )
        if not row:
            return None
        d = self._row_to_dict(row)
        if isinstance(d.get("auth_config"), str):
            d["auth_config"] = json.loads(d["auth_config"])
        if isinstance(d.get("actions"), str):
            d["actions"] = json.loads(d["actions"])
        return d

    async def admin_delete_connector(self, connector_id: str) -> bool:
        async with postgres_db.tenant_acquire() as conn:
            result = await conn.execute(
                "DELETE FROM connector_definitions WHERE id = $1 AND tenant_id IS NULL AND source IN ('builtin', 'community')",
                connector_id,
            )
        return "DELETE 1" in result

    # ======================================================================
    # 10. Health
    # ======================================================================

    async def check_instance_health(
        self, tenant_id: str, instance_id: str
    ) -> Dict[str, Any]:
        """Hit the external API and update health_status."""
        return await self.test_instance(tenant_id, instance_id)

    async def get_health_summary(self, tenant_id: str) -> Dict[str, int]:
        tid = uuid.UUID(tenant_id)
        async with postgres_db.tenant_acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT health_status, COUNT(*) AS cnt
                FROM connect_instances
                WHERE tenant_id = $1
                GROUP BY health_status
                """,
                tid,
            )
        summary = {"healthy": 0, "degraded": 0, "down": 0, "unknown": 0, "total": 0}
        for row in rows:
            status = row["health_status"] or "unknown"
            summary[status] = summary.get(status, 0) + int(row["cnt"])
            summary["total"] += int(row["cnt"])
        return summary

    # ======================================================================
    # 11. Execution (for Riggs / enrichment)
    # ======================================================================

    async def execute_action(
        self,
        tenant_id: str,
        instance_id: str,
        action_id: str,
        params: Optional[dict] = None,
        executed_by: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Execute an integration action end-to-end:
        1. Resolve instance + connector definition
        2. Decrypt credential
        3. Build auth headers
        4. Substitute URL path params and make HTTP call
        5. Log execution and update stats
        6. Return response data
        """
        inst = await self.get_instance(tenant_id, instance_id)
        if not inst:
            raise ValueError("Instance not found")
        if not inst.get("enabled"):
            raise ValueError("Instance is disabled")

        connector_id = inst.get("connector_id")
        cred_id = inst.get("credential_id")
        if not cred_id:
            raise ValueError("No credential linked to this instance")

        cred = await self.get_credential_decrypted(tenant_id, str(cred_id))
        if not cred:
            raise ValueError("Credential not found")

        # Find the action in the connector definition
        actions_list = inst.get("connector_actions") or []
        action = next((a for a in actions_list if a.get("id") == action_id), None)
        if not action:
            raise ValueError(f"Action '{action_id}' not found on connector '{connector_id}'")

        # Build request
        auth_type = inst.get("auth_type", "")
        auth_config = inst.get("auth_config") or {}
        secret_data = cred.get("secret_data", {})
        headers = self._build_auth_headers(auth_type, auth_config, secret_data)
        headers["Accept"] = "application/json"

        # Instance config can override the connector definition's base_url
        inst_config = inst.get("config") or {}
        base_url = (inst_config.get("base_url") or inst.get("base_url") or "").rstrip("/")
        endpoint = action.get("endpoint", "")
        method = action.get("http_method", "GET")

        url = base_url + endpoint
        params = params or {}

        # Substitute path placeholders like {ip}, {hash} from params
        for key, val in params.items():
            url = url.replace(f"{{{key}}}", str(val))

        # Any remaining placeholders? Try filling with first param value
        if re.search(r"\{[^}]+\}", url) and params:
            first_val = str(list(params.values())[0])
            url = re.sub(r"\{[^}]+\}", first_val, url)

        # For GET with query params (if endpoint has no path placeholders originally)
        query_params = None
        body = None
        if method.upper() == "GET":
            # Collect remaining params that were not path-substituted as query params
            query_params = {k: v for k, v in params.items() if f"{{{k}}}" not in action.get("endpoint", "")}
            if not query_params:
                query_params = None
        elif method.upper() in ("POST", "PUT", "PATCH"):
            # Use stored request_body template as default, merge with runtime params
            raw_body = action.get("request_body")
            if raw_body and raw_body.strip():
                try:
                    body = json.loads(raw_body)
                    # Merge runtime params on top of the template
                    if params and isinstance(body, dict):
                        body.update(params)
                except (json.JSONDecodeError, TypeError):
                    body = params
            else:
                body = params

        # Execute
        result = await self._make_request(method, url, headers, params=query_params, body=body, timeout=30)

        success = 200 <= (result.get("status_code") or 0) < 400
        duration = result.get("duration_ms", 0)
        error_msg = result.get("error") if not success else None

        # Update credential last_used_at
        cid = uuid.UUID(str(cred_id))
        tid = uuid.UUID(tenant_id)
        iid = uuid.UUID(instance_id)

        async with postgres_db.tenant_acquire() as conn:
            await conn.execute(
                "UPDATE connect_credentials SET last_used_at = NOW() WHERE id = $1",
                cid,
            )
            # Log execution
            await conn.execute(
                """
                INSERT INTO connect_execution_log (
                    id, tenant_id, instance_id, connector_id, action_id,
                    success, status_code, duration_ms, error_message,
                    executed_by, executed_at
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW())
                """,
                uuid.uuid4(), tid, iid, connector_id, action_id,
                success, result.get("status_code"), duration, error_msg,
                executed_by,
            )
            # Update instance stats
            stat_col = "success_requests" if success else "failed_requests"
            await conn.execute(
                f"""
                UPDATE connect_instances
                SET total_requests = total_requests + 1,
                    {stat_col} = {stat_col} + 1,
                    updated_at = NOW()
                WHERE id = $1
                """,
                iid,
            )

        return {
            "success": success,
            "status_code": result.get("status_code"),
            "duration_ms": duration,
            "data": result.get("body"),
            "error": error_msg,
        }


# ============================================================================
# Singleton
# ============================================================================

_connect_service: Optional[ConnectService] = None


def get_connect_service() -> ConnectService:
    """Get or create the global ConnectService singleton."""
    global _connect_service
    if _connect_service is None:
        _connect_service = ConnectService()
    return _connect_service
