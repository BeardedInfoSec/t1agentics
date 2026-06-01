# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Playbook Integration Bridge

A thin bridge between the playbook engine and integration definitions.
Has exactly 3 responsibilities:
1. Load integration definition + credentials (from DB or registry)
2. Resolve params (including context/data-path resolution)
3. Execute HTTP call + return normalized envelope

This file contains NO business logic for branching, retries, error routing, or approvals.
That logic stays in playbook_engine.py.
"""

import json
import logging
import os
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from uuid import UUID

import httpx

logger = logging.getLogger(__name__)

# Encryption key for credential decryption — must be a valid Fernet key in production
INTEGRATION_ENCRYPTION_KEY = os.environ.get(
    'INTEGRATION_ENCRYPTION_KEY',
    os.environ.get('SECRET_KEY', 'CHANGE-ME-IN-PRODUCTION-32-CHARS')
)


def _is_valid_uuid(value: str) -> bool:
    """Return True if value is a valid UUID string."""
    try:
        UUID(str(value))
        return True
    except (ValueError, AttributeError):
        return False


class PlaybookIntegrationBridge:
    """
    Bridge between playbook engine and integration HTTP execution.
    Handles both T1 Connect (UUID instance IDs) and legacy (string IDs) integrations.
    """

    # --------------------------------------------------------------------------
    # Public API
    # --------------------------------------------------------------------------

    async def execute_action(
        self,
        integration_instance_id: str,
        endpoint_id: str,
        params: Dict[str, Any],
        context: Dict[str, Any],
        tenant_id: str = "default"
    ) -> Dict[str, Any]:
        """
        Execute an integration action endpoint.

        Returns normalized envelope:
        {
            "ok": True/False,
            "integration_instance_id": "...",
            "endpoint_id": "...",
            "started_at": "...",
            "ended_at": "...",
            "duration_ms": 1234,
            "inputs": {"resolved_params": {...}},
            "outputs": {"raw": {...}, "mapped": {...}},
            "error": None or "error message",
            "meta": {"rate_limited": False, "cached": False, "attempt": 1}
        }
        """
        started_at = datetime.now(timezone.utc)
        envelope = {
            "ok": False,
            "integration_instance_id": integration_instance_id,
            "endpoint_id": endpoint_id,
            "started_at": started_at.isoformat(),
            "ended_at": None,
            "duration_ms": 0,
            "inputs": {"resolved_params": {}},
            "outputs": {"raw": {}, "mapped": {}},
            "error": None,
            "meta": {"rate_limited": False, "cached": False, "attempt": 1}
        }

        try:
            # 1. Resolve params from context
            resolved_params = self._resolve_params(params, context)
            envelope["inputs"]["resolved_params"] = self._sanitize_for_log(resolved_params)

            # 2. Load definition and credentials
            definition, credentials = await self._load_definition_and_credentials(
                integration_instance_id, tenant_id
            )

            if not definition:
                envelope["error"] = f"Integration not found: {integration_instance_id}"
                return self._finalize_envelope(envelope, started_at)

            # 3. Find the action
            action = self._find_action(definition, endpoint_id)
            if not action:
                int_name = definition.get("name", integration_instance_id)
                envelope["error"] = (
                    f"Action '{endpoint_id}' not found in integration '{int_name}'. "
                    f"Available: {[a.get('id') for a in definition.get('actions', [])]}"
                )
                return self._finalize_envelope(envelope, started_at)

            # 4. Execute HTTP
            result = await self._execute_http_action(
                definition, action, resolved_params, credentials
            )

            envelope["ok"] = result["ok"]
            envelope["outputs"]["raw"] = result.get("raw", {})
            envelope["outputs"]["mapped"] = result.get("data", {})
            if not result["ok"]:
                envelope["error"] = result.get("error", "Unknown error")

        except Exception as e:
            logger.error(f"Integration bridge execution error: {e}", exc_info=True)
            envelope["error"] = str(e)

        return self._finalize_envelope(envelope, started_at)

    async def enrich_observable(
        self,
        observable_type: str,
        observable_value: str,
        integration_instance_ids: List[str],
        context: Dict[str, Any],
        tenant_id: str = "default"
    ) -> Dict[str, Any]:
        """
        Enrich an observable using multiple integrations.
        Returns normalized envelope with per-integration results in outputs.results[].
        """
        started_at = datetime.now(timezone.utc)
        envelope = {
            "ok": True,
            "observable_type": observable_type,
            "observable_value": observable_value,
            "started_at": started_at.isoformat(),
            "ended_at": None,
            "duration_ms": 0,
            "inputs": {"observable_type": observable_type, "observable_value": observable_value},
            "outputs": {"results": [], "verdicts": [], "aggregated_verdict": None},
            "error": None,
            "meta": {
                "total_integrations": len(integration_instance_ids),
                "successful": 0,
                "failed": 0
            }
        }

        try:
            any_success = False
            verdicts = []

            for instance_id in integration_instance_ids:
                endpoint_id = self._get_enrichment_endpoint(observable_type)
                result = await self.execute_action(
                    integration_instance_id=instance_id,
                    endpoint_id=endpoint_id,
                    params={observable_type: observable_value, "value": observable_value},
                    context=context,
                    tenant_id=tenant_id
                )

                integration_result = {
                    "instance_id": instance_id,
                    "ok": result.get("ok", False),
                    "data": result.get("outputs", {}).get("mapped", {}),
                    "error": result.get("error")
                }
                envelope["outputs"]["results"].append(integration_result)

                if result.get("ok"):
                    any_success = True
                    envelope["meta"]["successful"] += 1
                    verdict = result.get("outputs", {}).get("mapped", {}).get("verdict")
                    if verdict:
                        verdicts.append(verdict)
                else:
                    envelope["meta"]["failed"] += 1

            envelope["ok"] = any_success
            envelope["outputs"]["verdicts"] = verdicts

            if verdicts:
                severity_order = ["malicious", "suspicious", "clean", "unknown"]
                for sev in severity_order:
                    if any(v.lower() == sev for v in verdicts):
                        envelope["outputs"]["aggregated_verdict"] = sev
                        break

        except Exception as e:
            logger.error(f"Enrichment bridge error: {e}", exc_info=True)
            envelope["ok"] = False
            envelope["error"] = str(e)

        return self._finalize_envelope(envelope, started_at)

    # --------------------------------------------------------------------------
    # Definition + credential loading
    # --------------------------------------------------------------------------

    async def _load_definition_and_credentials(
        self,
        instance_id: str,
        tenant_id: str
    ) -> Tuple[Optional[Dict], Optional[Dict]]:
        """
        Load integration definition and (optionally) credentials.

        Returns: (definition, credentials)
          definition = {name, base_url, auth_type, auth_config, actions: [...]}
          credentials = {auth_type, encrypted_data, metadata} or None
        """
        # T1 Connect path: UUID → connect_instances + connector_definitions + connect_credentials
        if _is_valid_uuid(instance_id):
            definition, credentials = await self._load_connect_instance(instance_id, tenant_id)
            if definition:
                return definition, credentials

        # Legacy/string path: try connector_definitions table, then in-memory registry,
        # then direct JSON file scan
        definition, credentials = await self._load_by_connector_id(instance_id)
        if definition:
            return definition, credentials

        definition, credentials = self._load_from_json_files(instance_id)
        return definition, credentials

    async def _load_connect_instance(
        self,
        instance_id: str,
        tenant_id: str
    ) -> Tuple[Optional[Dict], Optional[Dict]]:
        """Load T1 Connect instance + connector definition + credentials from DB."""
        try:
            from services.postgres_db import postgres_db
            if not postgres_db.connected or not postgres_db.pool:
                return None, None

            async with postgres_db.tenant_acquire() as conn:
                row = await conn.fetchrow("""
                    SELECT
                        i.connector_id,
                        i.config        AS instance_config,
                        d.name, d.base_url, d.auth_type, d.auth_config, d.actions,
                        c.auth_type     AS cred_auth_type,
                        c.encrypted_data,
                        c.metadata      AS cred_metadata
                    FROM connect_instances i
                    JOIN connector_definitions d ON i.connector_id = d.id
                    LEFT JOIN connect_credentials c ON i.credential_id = c.id
                    WHERE i.id = $1::uuid
                """, instance_id)

            if not row:
                return None, None

            r = dict(row)

            # asyncpg may return JSONB columns as strings — parse them all defensively
            def _parse_jsonb(val, default):
                if val is None:
                    return default
                if isinstance(val, str):
                    try:
                        return json.loads(val)
                    except Exception:
                        return default
                return val

            actions = _parse_jsonb(r.get("actions"), [])
            if not isinstance(actions, list):
                actions = []

            instance_config = _parse_jsonb(r.get("instance_config"), {})
            auth_config = _parse_jsonb(r.get("auth_config"), {})
            cred_metadata = _parse_jsonb(r.get("cred_metadata"), {})

            definition = {
                "name": r.get("name", ""),
                "base_url": (instance_config.get("base_url") if isinstance(instance_config, dict) else None)
                            or r.get("base_url") or "",
                "auth_type": r.get("auth_type", "none"),
                "auth_config": auth_config if isinstance(auth_config, dict) else {},
                "actions": actions,
            }

            credentials = None
            if r.get("encrypted_data"):
                credentials = {
                    "auth_type": r.get("cred_auth_type"),
                    "encrypted_data": r["encrypted_data"],
                    "metadata": cred_metadata if isinstance(cred_metadata, dict) else {},
                }

            return definition, credentials

        except Exception as e:
            logger.warning(f"DB lookup for instance {instance_id} failed: {e}", exc_info=True)
            return None, None

    async def _load_by_connector_id(
        self,
        connector_id: str
    ) -> Tuple[Optional[Dict], Optional[Dict]]:
        """
        Load connector definition by string ID.
        Tries: DB connector_definitions table → in-memory registry.
        """
        # 1. Try connector_definitions table (builtin connectors have tenant_id IS NULL)
        try:
            from services.postgres_db import postgres_db
            if postgres_db.connected and postgres_db.pool:
                async with postgres_db.pool.acquire() as conn:
                    row = await conn.fetchrow("""
                        SELECT name, base_url, auth_type, auth_config, actions
                        FROM connector_definitions
                        WHERE id = $1
                          AND (tenant_id IS NULL OR source = 'builtin')
                        LIMIT 1
                    """, connector_id)

                if row:
                    r = dict(row)
                    actions = r.get("actions", [])
                    if isinstance(actions, str):
                        try:
                            actions = json.loads(actions)
                        except Exception:
                            actions = []
                    if not isinstance(actions, list):
                        actions = []

                    raw_auth_config = r.get("auth_config")
                    if isinstance(raw_auth_config, str):
                        try:
                            raw_auth_config = json.loads(raw_auth_config)
                        except Exception:
                            raw_auth_config = {}

                    definition = {
                        "name": r.get("name", ""),
                        "base_url": r.get("base_url") or "",
                        "auth_type": r.get("auth_type", "none"),
                        "auth_config": raw_auth_config if isinstance(raw_auth_config, dict) else {},
                        "actions": actions,
                    }
                    return definition, None

        except Exception as e:
            logger.debug(f"DB connector_definitions lookup for '{connector_id}' failed: {e}")

        # 2. Try in-memory registry (loaded from JSON files at startup)
        try:
            from integrations.registry.integration_registry import get_registry
            registry = get_registry()
            integration = registry.get(connector_id)
            if integration:
                definition = {
                    "name": integration.name,
                    "base_url": integration.base_url,
                    "auth_type": (
                        integration.auth_type.value
                        if hasattr(integration.auth_type, "value")
                        else str(integration.auth_type)
                    ),
                    "auth_config": integration.auth_config or {},
                    "actions": [
                        {
                            "id": a.id,
                            "name": a.name,
                            "http_method": a.http_method,
                            "endpoint": a.endpoint,
                            "parameters": a.parameters or [],
                            "requires_auth": a.requires_auth,
                        }
                        for a in integration.actions
                    ],
                }
                return definition, None
        except Exception as e:
            logger.debug(f"Registry lookup for '{connector_id}' failed: {e}")

        return None, None

    def _load_from_json_files(
        self,
        connector_id: str
    ) -> Tuple[Optional[Dict], Optional[Dict]]:
        """
        Last-resort fallback: scan integration-store-output JSON files for connector_id.
        Searches all category subdirectories.
        """
        try:
            backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            base_dir = os.path.join(backend_dir, "integration-store-output", "integrations")

            if not os.path.isdir(base_dir):
                return None, None

            for category_name in os.listdir(base_dir):
                category_path = os.path.join(base_dir, category_name)
                if not os.path.isdir(category_path):
                    continue

                integration_file = os.path.join(category_path, connector_id, "integration.json")
                if os.path.isfile(integration_file):
                    with open(integration_file, "r", encoding="utf-8") as f:
                        data = json.load(f)

                    definition = {
                        "name": data.get("name", connector_id),
                        "base_url": data.get("base_url", ""),
                        "auth_type": data.get("auth_type", "none"),
                        "auth_config": data.get("auth_config") or {},
                        "actions": data.get("actions", []),
                    }
                    logger.info(f"[BRIDGE] Loaded '{connector_id}' from JSON files ({category_name})")
                    return definition, None

        except Exception as e:
            logger.warning(f"JSON file lookup for '{connector_id}' failed: {e}")

        return None, None

    # --------------------------------------------------------------------------
    # HTTP execution
    # --------------------------------------------------------------------------

    def _find_action(self, definition: Dict, endpoint_id: str) -> Optional[Dict]:
        """Find action definition by id or name."""
        for action in definition.get("actions", []):
            if isinstance(action, dict):
                if action.get("id") == endpoint_id or action.get("name") == endpoint_id:
                    return action
        return None

    def _decrypt_credentials(self, encrypted_data: str) -> Dict:
        """Decrypt Fernet-encrypted credential JSON blob from connect_credentials."""
        try:
            from cryptography.fernet import Fernet
            key = INTEGRATION_ENCRYPTION_KEY
            if isinstance(key, str):
                key = key.encode()
            f = Fernet(key)
            decrypted = f.decrypt(encrypted_data.encode()).decode()
            return json.loads(decrypted)
        except Exception as e:
            logger.error(f"Failed to decrypt credentials: {e}")
            return {}

    async def _execute_http_action(
        self,
        definition: Dict,
        action: Dict,
        resolved_params: Dict,
        credentials: Optional[Dict]
    ) -> Dict:
        """
        Execute an HTTP action. Returns {ok, raw, data, error}.
        """
        base_url = (definition.get("base_url") or "").rstrip("/")
        endpoint = action.get("endpoint", "")
        http_method = action.get("http_method", "GET").upper()
        auth_type = (definition.get("auth_type") or "none").lower()
        auth_config = definition.get("auth_config") or {}

        if not base_url:
            return {"ok": False, "raw": {}, "data": {}, "error": "Integration has no base_url configured"}

        # Substitute {param} path placeholders
        url = base_url + endpoint
        path_used: set = set()
        for key, value in resolved_params.items():
            placeholder = "{" + key + "}"
            if placeholder in url:
                url = url.replace(placeholder, str(value))
                path_used.add(key)

        # Params not used as path vars
        remaining_params = {k: v for k, v in resolved_params.items() if k not in path_used}

        headers: Dict[str, str] = {
            "Accept": "application/json",
            "User-Agent": "T1-Agentics/1.0",
        }
        query_params: Dict[str, str] = {}

        # --- Apply authentication ---
        if auth_type not in ("none", ""):
            if credentials and credentials.get("encrypted_data"):
                # Decrypt and apply stored credentials
                decrypted = self._decrypt_credentials(credentials["encrypted_data"])
                self._apply_auth(auth_type, auth_config, decrypted, headers, query_params)
            else:
                # No stored credentials — try environment variable fallback
                self._apply_env_auth(auth_type, auth_config, definition.get("name", ""), headers, query_params)

        # --- Make request ---
        try:
            async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
                if http_method == "GET":
                    # For GET, remaining params become additional query params
                    for k, v in remaining_params.items():
                        if k not in query_params:
                            query_params[k] = str(v)
                    response = await client.get(url, headers=headers, params=query_params)

                elif http_method == "POST":
                    response = await client.post(
                        url, headers=headers, params=query_params, json=remaining_params
                    )

                elif http_method == "PUT":
                    response = await client.put(
                        url, headers=headers, params=query_params, json=remaining_params
                    )

                elif http_method == "PATCH":
                    response = await client.patch(
                        url, headers=headers, params=query_params, json=remaining_params
                    )

                elif http_method == "DELETE":
                    response = await client.delete(url, headers=headers, params=query_params)

                else:
                    response = await client.request(
                        http_method, url, headers=headers,
                        params=query_params, json=remaining_params
                    )

            # Parse response
            try:
                data = response.json()
            except Exception:
                data = {"raw_text": response.text[:4096]}

            if response.is_success:
                return {"ok": True, "raw": data, "data": data}
            else:
                return {
                    "ok": False,
                    "raw": data,
                    "data": {},
                    "error": f"HTTP {response.status_code}",
                }

        except httpx.TimeoutException:
            return {"ok": False, "raw": {}, "data": {}, "error": "Request timed out (30s)"}
        except httpx.ConnectError as e:
            return {"ok": False, "raw": {}, "data": {}, "error": f"Connection failed: {e}"}
        except Exception as e:
            return {"ok": False, "raw": {}, "data": {}, "error": str(e)}

    def _apply_auth(
        self,
        auth_type: str,
        auth_config: Dict,
        decrypted: Dict,
        headers: Dict,
        query_params: Dict
    ) -> None:
        """Apply decrypted credentials to headers/query_params in-place."""
        if auth_type == "bearer_token":
            token = (
                decrypted.get("bearer_token")
                or decrypted.get("token")
                or decrypted.get("access_token", "")
            )
            prefix = auth_config.get("prefix", "Bearer").rstrip()
            header_name = auth_config.get("header_name", "Authorization")
            headers[header_name] = f"{prefix} {token}".strip()

        elif auth_type in ("api_key", "api_key_header"):
            api_key = decrypted.get("api_key", "")
            location = auth_config.get("location", auth_config.get("key_location", "header"))
            header_name = auth_config.get("header_name", auth_config.get("key_name", "X-API-Key"))
            if location == "query":
                query_params[header_name] = api_key
            else:
                headers[header_name] = api_key

        elif auth_type == "basic_auth":
            import base64
            username = decrypted.get("username", "")
            password = decrypted.get("password", "")
            encoded = base64.b64encode(f"{username}:{password}".encode()).decode()
            headers["Authorization"] = f"Basic {encoded}"

        elif auth_type == "custom_header":
            for k, v in decrypted.items():
                if k not in ("auth_type", "credential_id"):
                    headers[k] = str(v)

    def _apply_env_auth(
        self,
        auth_type: str,
        auth_config: Dict,
        integration_name: str,
        headers: Dict,
        query_params: Dict
    ) -> None:
        """
        Fallback: look for API token in environment variables.
        Checks {NAME}_TOKEN, {NAME}_API_KEY, {NAME}_KEY, {NAME}_SECRET.
        """
        env_prefix = re.sub(r"[^A-Z0-9]", "_", integration_name.upper())
        token = ""
        for suffix in ("_TOKEN", "_API_KEY", "_KEY", "_SECRET"):
            token = os.environ.get(f"{env_prefix}{suffix}", "")
            if token:
                break

        if not token:
            return

        if auth_type == "bearer_token":
            prefix = auth_config.get("prefix", "Bearer").rstrip()
            header_name = auth_config.get("header_name", "Authorization")
            headers[header_name] = f"{prefix} {token}".strip()

        elif auth_type in ("api_key", "api_key_header"):
            location = auth_config.get("location", auth_config.get("key_location", "header"))
            header_name = auth_config.get("header_name", auth_config.get("key_name", "X-API-Key"))
            if location == "query":
                query_params[header_name] = token
            else:
                headers[header_name] = token

    # --------------------------------------------------------------------------
    # Parameter resolution (unchanged)
    # --------------------------------------------------------------------------

    def _resolve_params(self, params: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Resolve parameter values from context using data paths.
        If a param value starts with "$.", it's treated as a JSONPath into context.
        """
        resolved = {}
        for key, value in params.items():
            if isinstance(value, str) and value.startswith("$."):
                resolved[key] = self._extract_json_path(context, value)
            else:
                resolved[key] = value
        return resolved

    def _extract_json_path(self, data: Any, path: str) -> Any:
        """Extract value from data using JSONPath-like syntax."""
        if not path or not path.startswith("$"):
            return data

        path = path[2:] if path.startswith("$.") else path[1:]
        if not path:
            return data

        parts = self._parse_json_path(path)
        current = data

        for part in parts:
            if current is None:
                return None
            if part == "*":
                return current if isinstance(current, list) else None
            elif part.isdigit():
                idx = int(part)
                if isinstance(current, list) and idx < len(current):
                    current = current[idx]
                else:
                    return None
            else:
                if isinstance(current, dict):
                    current = current.get(part)
                else:
                    return None

        return current

    def _parse_json_path(self, path: str) -> List[str]:
        """Parse JSONPath string into a list of keys/indices."""
        parts = []
        current = ""
        i = 0
        while i < len(path):
            char = path[i]
            if char == ".":
                if current:
                    parts.append(current)
                    current = ""
            elif char == "[":
                if current:
                    parts.append(current)
                    current = ""
                j = path.find("]", i)
                if j > i:
                    parts.append(path[i + 1:j])
                    i = j
            else:
                current += char
            i += 1
        if current:
            parts.append(current)
        return parts

    # --------------------------------------------------------------------------
    # Utility methods (unchanged)
    # --------------------------------------------------------------------------

    def _get_enrichment_endpoint(self, observable_type: str) -> str:
        """Map observable type to endpoint ID."""
        mapping = {
            "ip": "lookup_ip",
            "domain": "lookup_domain",
            "hash": "lookup_hash",
            "url": "lookup_url",
            "email": "lookup_email",
            "file_hash": "lookup_hash",
            "md5": "lookup_hash",
            "sha256": "lookup_hash",
            "sha1": "lookup_hash",
        }
        return mapping.get(observable_type.lower(), "lookup")

    def _sanitize_for_log(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Mask sensitive values before logging."""
        sensitive_keys = {"password", "token", "api_key", "apikey", "secret", "credential", "auth"}
        sanitized = {}
        for key, value in data.items():
            if any(s in key.lower() for s in sensitive_keys):
                sanitized[key] = "***REDACTED***"
            elif isinstance(value, dict):
                sanitized[key] = self._sanitize_for_log(value)
            else:
                sanitized[key] = value
        return sanitized

    def _finalize_envelope(self, envelope: Dict[str, Any], started_at: datetime) -> Dict[str, Any]:
        """Add timing info and return finalized envelope."""
        ended_at = datetime.now(timezone.utc)
        envelope["ended_at"] = ended_at.isoformat()
        envelope["duration_ms"] = (ended_at - started_at).total_seconds() * 1000
        return envelope


# Singleton instance
_bridge: Optional[PlaybookIntegrationBridge] = None


def get_integration_bridge() -> PlaybookIntegrationBridge:
    """Get singleton bridge instance."""
    global _bridge
    if _bridge is None:
        _bridge = PlaybookIntegrationBridge()
    return _bridge
