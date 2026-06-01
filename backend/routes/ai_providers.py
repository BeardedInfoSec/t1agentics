# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
AI Provider Routes

REST API endpoints for managing AI providers (LM Studio, Anthropic, OpenAI, etc.)
"""

from fastapi import APIRouter, HTTPException, Depends
from typing import Optional, List
from pydantic import BaseModel
import logging
import uuid
import json
import httpx
from datetime import datetime
from dependencies.auth import require_admin
from services.credentials_service import CredentialsVault

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/ai-providers", tags=["AI Providers"], dependencies=[Depends(require_admin)])

# Singleton vault so we don't redo the PBKDF2 derivation on every request.
_provider_vault: Optional[CredentialsVault] = None


def _get_vault() -> CredentialsVault:
    global _provider_vault
    if _provider_vault is None:
        _provider_vault = CredentialsVault()
    return _provider_vault


def _provider_plaintext_key(row: dict) -> str:
    """
    Resolve a provider row's API key — prefer the encrypted column.
    Falls back to legacy plaintext `api_key` for rows that haven't been
    backfilled yet.
    """
    enc = row.get("api_key_encrypted")
    if enc:
        try:
            return _get_vault().decrypt(enc) or ""
        except Exception as e:
            logger.warning(f"ai_providers decrypt failed: {e}")
            return ""
    return row.get("api_key") or ""


async def backfill_ai_providers_encryption() -> int:
    """
    One-shot backfill: encrypt every legacy plaintext api_key into the
    api_key_encrypted column. Idempotent (skips rows that already have
    encrypted set). Called from app.py lifespan after migration 069.
    Returns the number of rows updated.
    """
    pool = await get_db_pool()
    if not pool:
        return 0
    updated = 0
    try:
        async with pool.tenant_acquire() as conn:
            try:
                await conn.execute("SET app.is_platform_admin = 'true'")
            except Exception:
                pass
            rows = await conn.fetch(
                "SELECT id, api_key FROM ai_providers "
                "WHERE api_key IS NOT NULL AND api_key != '' "
                "AND api_key_encrypted IS NULL"
            )
            vault = _get_vault()
            for r in rows:
                enc = vault.encrypt(r["api_key"])
                await conn.execute(
                    "UPDATE ai_providers SET api_key_encrypted = $1 WHERE id = $2",
                    enc, r["id"],
                )
                updated += 1
        if updated:
            logger.info(f"Backfilled api_key_encrypted on {updated} ai_providers row(s)")
    except Exception as e:
        logger.warning(f"ai_providers encryption backfill skipped: {e}")
    return updated


class ModelInfo(BaseModel):
    id: str
    name: str


class CreateProviderRequest(BaseModel):
    name: str
    provider_type: str  # openai_compatible, anthropic, openai
    base_url: str
    api_key: Optional[str] = None
    models: List[ModelInfo] = []
    selected_model: Optional[str] = None  # Default model
    tier1_model: Optional[str] = None     # Fast model for T1 triage
    tier2_model: Optional[str] = None     # Reasoning model for T2 analysis
    tier3_model: Optional[str] = None     # Complex model for T3 investigation
    chat_model: Optional[str] = None      # Model for investigation chat
    is_default: bool = False
    enabled: bool = True


class UpdateProviderRequest(BaseModel):
    name: Optional[str] = None
    base_url: Optional[str] = None
    api_key: Optional[str] = None
    models: Optional[List[ModelInfo]] = None
    selected_model: Optional[str] = None
    tier1_model: Optional[str] = None
    tier2_model: Optional[str] = None
    tier3_model: Optional[str] = None
    chat_model: Optional[str] = None
    is_default: Optional[bool] = None
    enabled: Optional[bool] = None


async def get_db_pool():
    """Get the postgres DB instance for tenant-aware connections"""
    from services.postgres_db import postgres_db
    if postgres_db.pool:
        return postgres_db
    return None


async def _sync_tier_models_to_agents(conn, provider_id: uuid.UUID):
    """
    Sync tier model assignments from ai_providers to agent_definitions.

    When a user sets tier1_model, tier2_model, or tier3_model on a provider,
    this function updates the corresponding agent_definitions.model_config
    to use that model.
    """
    try:
        # Get the provider with tier model assignments
        provider = await conn.fetchrow(
            """SELECT name, provider_type, base_url, tier1_model, tier2_model, tier3_model
               FROM ai_providers WHERE id = $1""",
            provider_id
        )
        if not provider:
            return

        # Map provider_type to the format expected by agent executor
        provider_type_map = {
            'openai_compatible': 'lm_studio',
            'anthropic': 'anthropic',
            'openai': 'openai'
        }
        mapped_provider = provider_type_map.get(provider['provider_type'], provider['provider_type'])

        # Build tier-to-model mapping
        tier_models = {
            1: provider['tier1_model'],
            2: provider['tier2_model'],
            3: provider['tier3_model']
        }

        # Update each tier's agent definitions
        for tier, model in tier_models.items():
            if model:  # Only update if a model is assigned for this tier
                new_config = json.dumps({
                    'provider': mapped_provider,
                    'model': model,
                    'base_url': provider['base_url']
                })

                result = await conn.execute(
                    """UPDATE agent_definitions
                       SET model_config = $1::jsonb, updated_at = NOW()
                       WHERE tier = $2 AND enabled = true""",
                    new_config,
                    tier
                )
                logger.info(f"Synced tier {tier} agents to model '{model}' (provider: {mapped_provider})")

    except Exception as e:
        logger.error(f"Failed to sync tier models to agents: {e}")


@router.get("")
async def list_providers():
    """List all AI providers"""
    pool = await get_db_pool()
    if not pool:
        return {"providers": []}

    try:
        async with pool.tenant_acquire() as conn:
            rows = await conn.fetch(
                "SELECT * FROM ai_providers ORDER BY is_default DESC, name ASC"
            )
            providers = []
            for row in rows:
                p = dict(row)
                if isinstance(p.get("models"), str):
                    p["models"] = json.loads(p["models"])
                if p.get("api_key"):
                    p["api_key"] = "***hidden***"
                p["id"] = str(p["id"])
                providers.append(p)
            return {"providers": providers}
    except Exception as e:
        logger.error(f"Failed to list providers: {e}")
        return {"providers": []}


@router.post("")
async def create_provider(request: CreateProviderRequest):
    """Create a new AI provider"""
    pool = await get_db_pool()
    if not pool:
        raise HTTPException(status_code=500, detail="Database not available")

    try:
        async with pool.tenant_acquire() as conn:
            if request.is_default:
                await conn.execute(
                    "UPDATE ai_providers SET is_default = false WHERE is_default = true"
                )

            encrypted_key = ""
            if request.api_key:
                encrypted_key = _get_vault().encrypt(request.api_key)

            row = await conn.fetchrow(
                """INSERT INTO ai_providers
                   (name, provider_type, base_url, api_key, api_key_encrypted, models, selected_model, tier1_model, tier2_model, tier3_model, chat_model, is_default, enabled, created_at)
                   VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
                   RETURNING id""",
                request.name,
                request.provider_type,
                request.base_url,
                "",  # legacy plaintext column kept empty for new writes
                encrypted_key,
                json.dumps([m.dict() for m in request.models]),
                request.selected_model or "",
                request.tier1_model or "",
                request.tier2_model or "",
                request.tier3_model or "",
                request.chat_model or "",
                request.is_default,
                request.enabled,
                datetime.utcnow()
            )

            return {"id": str(row["id"]), "status": "created"}
    except Exception as e:
        logger.error(f"Failed to create provider: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/{provider_id}")
async def delete_provider(provider_id: str):
    """Delete a provider"""
    pool = await get_db_pool()
    if not pool:
        raise HTTPException(status_code=500, detail="Database not available")

    try:
        async with pool.tenant_acquire() as conn:
            await conn.execute(
                "DELETE FROM ai_providers WHERE id = $1",
                uuid.UUID(provider_id)
            )
            return {"status": "deleted"}
    except Exception as e:
        logger.error(f"Failed to delete provider: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.patch("/{provider_id}")
async def update_provider(provider_id: str, request: UpdateProviderRequest):
    """Update a provider"""
    pool = await get_db_pool()
    if not pool:
        raise HTTPException(status_code=500, detail="Database not available")

    try:
        updates = request.dict(exclude_unset=True)
        if not updates:
            raise HTTPException(status_code=400, detail="No updates provided")

        async with pool.tenant_acquire() as conn:
            if updates.get("is_default"):
                await conn.execute(
                    "UPDATE ai_providers SET is_default = false WHERE is_default = true"
                )

            # Whitelist allowed column names to prevent SQL injection.
            # Note: `api_key` in the update payload now means "new plaintext
            # key" — it gets encrypted before write and stored in the
            # api_key_encrypted column, not the legacy plaintext column.
            ALLOWED_COLUMNS = {
                "name", "provider_type", "api_key", "api_base_url", "is_default",
                "models", "tier1_model", "tier2_model", "tier3_model",
                "max_tokens", "temperature", "enabled",
            }

            set_clauses = []
            values = []
            for i, (key, value) in enumerate(updates.items(), start=1):
                if key not in ALLOWED_COLUMNS:
                    raise HTTPException(status_code=400, detail=f"Invalid field: {key}")
                if key == "models":
                    value = json.dumps([m if isinstance(m, dict) else m.dict() for m in value])
                if key == "api_key":
                    # Encrypt and write to the new column; leave the legacy
                    # plaintext column alone (it'll be dropped in a follow-up
                    # migration once we're confident in the rollout).
                    if value:
                        value = _get_vault().encrypt(value)
                    else:
                        value = ""
                    key = "api_key_encrypted"
                set_clauses.append(f"{key} = ${i}")
                values.append(value)

            values.append(uuid.UUID(provider_id))
            query = f"UPDATE ai_providers SET {', '.join(set_clauses)} WHERE id = ${len(values)}"

            await conn.execute(query, *values)

            # =====================================================
            # SYNC: Update agent_definitions when tier models change
            # =====================================================
            tier_models_changed = any(k in updates for k in ['tier1_model', 'tier2_model', 'tier3_model'])
            if tier_models_changed:
                await _sync_tier_models_to_agents(conn, uuid.UUID(provider_id))

            return {"status": "updated"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update provider: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/{provider_id}/set-default")
async def set_default_provider(provider_id: str):
    """Set a provider as the default"""
    pool = await get_db_pool()
    if not pool:
        raise HTTPException(status_code=500, detail="Database not available")

    try:
        async with pool.tenant_acquire() as conn:
            await conn.execute(
                "UPDATE ai_providers SET is_default = false WHERE is_default = true"
            )
            await conn.execute(
                "UPDATE ai_providers SET is_default = true WHERE id = $1",
                uuid.UUID(provider_id)
            )
            return {"status": "default_set"}
    except Exception as e:
        logger.error(f"Failed to set default: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/{provider_id}/test")
async def test_provider(provider_id: str):
    """Test connection to an AI provider and fetch available models"""
    pool = await get_db_pool()
    if not pool:
        raise HTTPException(status_code=500, detail="Database not available")

    try:
        async with pool.tenant_acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM ai_providers WHERE id = $1",
                uuid.UUID(provider_id)
            )
            if not row:
                raise HTTPException(status_code=404, detail="Provider not found")

            provider = dict(row)
            if isinstance(provider.get("models"), str):
                provider["models"] = json.loads(provider["models"])

        async with httpx.AsyncClient(timeout=10.0) as client:
            headers = {}
            plain_key = _provider_plaintext_key(provider)
            if plain_key:
                if provider["provider_type"] == "anthropic":
                    headers["x-api-key"] = plain_key
                    headers["anthropic-version"] = "2023-06-01"
                else:
                    headers["Authorization"] = f"Bearer {plain_key}"

            if provider["provider_type"] == "anthropic":
                return {
                    "success": True,
                    "message": "Anthropic API key configured",
                    "models": [m.get("name", m.get("id")) for m in (provider.get("models") or [])]
                }
            else:
                url = f"{provider['base_url'].rstrip('/')}/models"
                response = await client.get(url, headers=headers)

                if response.status_code == 200:
                    data = response.json()
                    models = [m.get("id", m.get("name", "unknown")) for m in data.get("data", [])]
                    return {
                        "success": True,
                        "models": models[:20]
                    }
                else:
                    return {
                        "success": False,
                        "error": f"HTTP {response.status_code}"
                    }

    except httpx.TimeoutException:
        return {"success": False, "error": "Connection timeout - is the server running?"}
    except httpx.ConnectError as e:
        return {"success": False, "error": f"Connection failed: {str(e)}"}
    except Exception as e:
        logger.error(f"Failed to test provider: {e}")
        return {"success": False, "error": str(e)}


@router.post("/{provider_id}/fetch-models")
async def fetch_models(provider_id: str):
    """Fetch available models from the provider and update the provider config"""
    pool = await get_db_pool()
    if not pool:
        raise HTTPException(status_code=500, detail="Database not available")

    try:
        async with pool.tenant_acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM ai_providers WHERE id = $1",
                uuid.UUID(provider_id)
            )
            if not row:
                raise HTTPException(status_code=404, detail="Provider not found")

            provider = dict(row)

        async with httpx.AsyncClient(timeout=10.0) as client:
            headers = {}
            plain_key = _provider_plaintext_key(provider)
            if plain_key:
                if provider["provider_type"] == "anthropic":
                    # Anthropic doesn't have a models list endpoint
                    return {
                        "success": True,
                        "models": [
                            {"id": "claude-sonnet-4-20250514", "name": "Claude Sonnet 4"},
                            {"id": "claude-3-5-sonnet-20241022", "name": "Claude 3.5 Sonnet"},
                            {"id": "claude-3-opus-20240229", "name": "Claude 3 Opus"},
                            {"id": "claude-3-haiku-20240307", "name": "Claude 3 Haiku"}
                        ],
                        "message": "Showing common Anthropic models"
                    }
                else:
                    headers["Authorization"] = f"Bearer {plain_key}"

            # OpenAI-compatible providers
            url = f"{provider['base_url'].rstrip('/')}/models"
            response = await client.get(url, headers=headers)

            if response.status_code == 200:
                data = response.json()
                fetched_models = []
                for m in data.get("data", []):
                    model_id = m.get("id", m.get("name", "unknown"))
                    fetched_models.append({
                        "id": model_id,
                        "name": model_id
                    })

                # Update the provider with fetched models
                async with pool.tenant_acquire() as conn:
                    await conn.execute(
                        "UPDATE ai_providers SET models = $1 WHERE id = $2",
                        json.dumps(fetched_models),
                        uuid.UUID(provider_id)
                    )

                return {
                    "success": True,
                    "models": fetched_models,
                    "count": len(fetched_models)
                }
            else:
                return {
                    "success": False,
                    "error": f"HTTP {response.status_code}"
                }

    except httpx.TimeoutException:
        return {"success": False, "error": "Connection timeout - is the server running?"}
    except httpx.ConnectError as e:
        return {"success": False, "error": f"Connection failed: {str(e)}"}
    except Exception as e:
        logger.error(f"Failed to fetch models: {e}")
        return {"success": False, "error": str(e)}


@router.post("/{provider_id}/warm")
async def warm_model(provider_id: str):
    """
    Warm up the AI model to ensure it's loaded in memory.

    For local AI providers (Ollama, LM Studio), this sends a minimal request
    with keep_alive to ensure the model stays loaded and ready for queries.
    This reduces latency for subsequent requests.
    """
    try:
        from services.agent_executor import AgentExecutor
        executor = AgentExecutor()
        result = await executor.warm_model(provider_id)
        return result
    except Exception as e:
        logger.error(f"Failed to warm model: {e}")
        return {"success": False, "error": str(e)}


