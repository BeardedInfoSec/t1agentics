# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Playbook Catalog Service — Marketplace backend

Powers the Playbook Marketplace:
- Load builtin playbook templates from disk (playbook-store-output/)
- Browse/search/filter marketplace catalog
- Check integration dependencies against tenant's connect_instances
- Install templates into tenant's playbooks table
"""

import os
import json
import uuid
import logging
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List

from services.postgres_db import postgres_db

logger = logging.getLogger(__name__)

# Path to the builtin playbook catalog shipped with the backend image
_CATALOG_ROOT = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "playbook-store-output",
    "playbooks",
)


class PlaybookCatalogService:
    """
    Service for the Playbook Marketplace.

    All database access goes through ``postgres_db.pool`` (asyncpg).
    Follows the same pattern as ConnectService.load_builtin_catalog().
    """

    # ------------------------------------------------------------------
    # Catalog Loading (from disk → DB)
    # ------------------------------------------------------------------

    async def load_builtin_catalog(self) -> int:
        """
        Walk playbook-store-output/playbooks/ and upsert every
        playbook JSON into playbook_templates with source='builtin'.
        Returns the number of templates loaded.
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
        """Inner implementation of load_builtin_catalog (runs with admin mode)."""
        if not os.path.isdir(_CATALOG_ROOT):
            logger.warning(f"[PlaybookCatalog] Catalog root not found: {_CATALOG_ROOT}")
            return 0

        loaded = 0
        skipped = 0
        failed = 0
        loaded_slugs: set = set()

        for dirpath, _dirnames, filenames in os.walk(_CATALOG_ROOT):
            for fname in filenames:
                if not fname.endswith(".json"):
                    continue

                filepath = os.path.join(dirpath, fname)
                try:
                    with open(filepath, "r", encoding="utf-8") as f:
                        data = json.load(f)
                except Exception as e:
                    logger.error(f"[PlaybookCatalog] Failed to read {filepath}: {e}")
                    skipped += 1
                    continue

                slug = data.get("slug") or fname.replace(".json", "")
                name = data.get("name")
                if not name:
                    logger.warning(f"[PlaybookCatalog] Skipping {filepath}: no name")
                    skipped += 1
                    continue

                # Guard: skip entries with empty slug (would fail the
                # partial unique index or conflict clause).
                if not slug or not slug.strip():
                    logger.warning(f"[PlaybookCatalog] Skipping {filepath}: empty slug")
                    skipped += 1
                    continue

                loaded_slugs.add(slug)

                canvas_data = data.get("canvas_data", {"nodes": [], "edges": []})
                tags = data.get("tags", [])
                alert_types = data.get("alert_types", [])
                severity_filter = data.get("severity_filter", [])
                required_integrations = data.get("required_integrations", [])

                # Sanitise list fields: ensure they are actually lists,
                # not empty strings or None (asyncpg rejects '' for TEXT[]).
                if not isinstance(tags, list):
                    tags = []
                if not isinstance(alert_types, list):
                    alert_types = []
                if not isinstance(severity_filter, list):
                    severity_filter = []

                try:
                    async with postgres_db.tenant_acquire() as conn:
                        await conn.execute(
                            """
                            INSERT INTO playbook_templates (
                                name, slug, description, category, subcategory,
                                canvas_data, trigger_conditions, tags, alert_types,
                                severity_filter, required_integrations,
                                difficulty, estimated_time, author, version,
                                source, tenant_id,
                                created_at, updated_at
                            ) VALUES (
                                $1, $2, $3, $4, $5,
                                $6::jsonb, $7::jsonb, $8, $9,
                                $10, $11::jsonb,
                                $12, $13, $14, $15,
                                'builtin', NULL,
                                NOW(), NOW()
                            )
                            ON CONFLICT (slug) WHERE tenant_id IS NULL
                            DO UPDATE SET
                                name                 = EXCLUDED.name,
                                description          = EXCLUDED.description,
                                category             = EXCLUDED.category,
                                subcategory          = EXCLUDED.subcategory,
                                canvas_data          = EXCLUDED.canvas_data,
                                trigger_conditions   = EXCLUDED.trigger_conditions,
                                tags                 = EXCLUDED.tags,
                                alert_types          = EXCLUDED.alert_types,
                                severity_filter      = EXCLUDED.severity_filter,
                                required_integrations = EXCLUDED.required_integrations,
                                difficulty           = EXCLUDED.difficulty,
                                estimated_time       = EXCLUDED.estimated_time,
                                author               = EXCLUDED.author,
                                version              = EXCLUDED.version,
                                updated_at           = NOW()
                            """,
                            name,
                            slug,
                            data.get("description", ""),
                            data.get("category", "general"),
                            data.get("subcategory"),
                            json.dumps(canvas_data),
                            json.dumps(data.get("trigger_conditions", {})),
                            tags,
                            alert_types,
                            severity_filter,
                            json.dumps(required_integrations),
                            data.get("difficulty", "intermediate"),
                            data.get("estimated_time"),
                            data.get("author", "T1 Agentics"),
                            data.get("version", "1.0.0"),
                        )
                    loaded += 1
                except Exception as e:
                    failed += 1
                    logger.error(f"[PlaybookCatalog] Failed to upsert {slug}: {e}")

        if failed:
            logger.warning(
                f"[PlaybookCatalog] Loaded {loaded} builtin templates, "
                f"{failed} failed, {skipped} skipped"
            )
        else:
            logger.info(f"[PlaybookCatalog] Loaded {loaded} builtin playbook templates")

        # Clean up orphaned builtin templates that no longer exist on disk
        if loaded_slugs:
            try:
                async with postgres_db.tenant_acquire() as conn:
                    result = await conn.execute(
                        """
                        DELETE FROM playbook_templates
                        WHERE source = 'builtin' AND tenant_id IS NULL
                          AND slug IS NOT NULL
                          AND slug != ALL($1::text[])
                        """,
                        list(loaded_slugs),
                    )
                    deleted = int(result.split()[-1]) if result else 0
                    if deleted:
                        logger.info(f"[PlaybookCatalog] Purged {deleted} orphaned templates")
            except Exception as e:
                logger.warning(f"[PlaybookCatalog] Orphan cleanup failed: {e}")

        return loaded

    # ------------------------------------------------------------------
    # Marketplace Browse / Search
    # ------------------------------------------------------------------

    async def get_marketplace(
        self,
        category: Optional[str] = None,
        subcategory: Optional[str] = None,
        difficulty: Optional[str] = None,
        search: Optional[str] = None,
        integration: Optional[str] = None,
        tag: Optional[str] = None,
        page: int = 1,
        per_page: int = 24,
    ) -> Dict[str, Any]:
        """
        Query playbook_templates with filters.
        Returns paginated results with metadata.
        """
        conditions = ["source = 'builtin'", "tenant_id IS NULL"]
        params: list = []
        idx = 1

        if category:
            conditions.append(f"category = ${idx}")
            params.append(category)
            idx += 1

        if subcategory:
            conditions.append(f"subcategory = ${idx}")
            params.append(subcategory)
            idx += 1

        if difficulty:
            conditions.append(f"difficulty = ${idx}")
            params.append(difficulty)
            idx += 1

        if search:
            conditions.append(
                f"(name ILIKE ${idx} OR description ILIKE ${idx} OR category ILIKE ${idx})"
            )
            params.append(f"%{search}%")
            idx += 1

        if integration:
            conditions.append(
                f"required_integrations @> ${idx}::jsonb"
            )
            params.append(json.dumps([{"connector_id": integration}]))
            idx += 1

        if tag:
            conditions.append(f"${idx} = ANY(tags)")
            params.append(tag)
            idx += 1

        where = " AND ".join(conditions)
        offset = (page - 1) * per_page

        async with postgres_db.tenant_acquire() as conn:
            # Count total
            count_row = await conn.fetchrow(
                f"SELECT COUNT(*) AS total FROM playbook_templates WHERE {where}",
                *params,
            )
            total = count_row["total"] if count_row else 0

            # Fetch page
            rows = await conn.fetch(
                f"""
                SELECT id, name, slug, description, category, subcategory,
                       tags, alert_types, severity_filter,
                       required_integrations, difficulty, estimated_time,
                       author, version, install_count, source, rating,
                       created_at, updated_at
                FROM playbook_templates
                WHERE {where}
                ORDER BY install_count DESC, name ASC
                LIMIT ${idx} OFFSET ${idx + 1}
                """,
                *params, per_page, offset,
            )

        templates = []
        for row in rows:
            t = dict(row)
            # Serialize UUIDs and datetimes
            for k, v in list(t.items()):
                if isinstance(v, uuid.UUID):
                    t[k] = str(v)
                elif isinstance(v, datetime):
                    t[k] = v.isoformat()
            # Ensure JSONB fields are proper objects, not strings
            for jsonb_field in ('required_integrations', 'canvas_data', 'trigger_conditions'):
                val = t.get(jsonb_field)
                if isinstance(val, str):
                    try:
                        t[jsonb_field] = json.loads(val)
                    except (json.JSONDecodeError, TypeError):
                        t[jsonb_field] = [] if jsonb_field == 'required_integrations' else {}
            templates.append(t)

        return {
            "templates": templates,
            "total": total,
            "page": page,
            "per_page": per_page,
            "total_pages": max(1, (total + per_page - 1) // per_page),
        }

    # ------------------------------------------------------------------
    # Marketplace Categories / Stats
    # ------------------------------------------------------------------

    async def get_categories(self) -> List[Dict[str, Any]]:
        """Get all categories with counts."""
        async with postgres_db.tenant_acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT category, COUNT(*) AS count
                FROM playbook_templates
                WHERE source = 'builtin' AND tenant_id IS NULL
                GROUP BY category
                ORDER BY count DESC
                """
            )
        return [{"category": r["category"], "count": r["count"]} for r in rows]

    async def get_stats(self) -> Dict[str, Any]:
        """Get marketplace summary stats."""
        async with postgres_db.tenant_acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT
                    COUNT(*) AS total_templates,
                    COUNT(DISTINCT category) AS categories,
                    COALESCE(SUM(install_count), 0) AS total_installs
                FROM playbook_templates
                WHERE source = 'builtin' AND tenant_id IS NULL
                """
            )
        return {
            "total_templates": row["total_templates"],
            "categories": row["categories"],
            "total_installs": row["total_installs"],
        }

    # ------------------------------------------------------------------
    # Template Detail
    # ------------------------------------------------------------------

    async def get_template_detail(self, template_id: str) -> Optional[Dict[str, Any]]:
        """Get full template detail including canvas_data."""
        try:
            tid = uuid.UUID(template_id)
        except ValueError:
            return None

        async with postgres_db.tenant_acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM playbook_templates WHERE id = $1",
                tid,
            )

        if not row:
            return None

        t = dict(row)
        for k, v in list(t.items()):
            if isinstance(v, uuid.UUID):
                t[k] = str(v)
            elif isinstance(v, datetime):
                t[k] = v.isoformat()
        # Ensure JSONB fields are proper objects, not strings
        for jsonb_field in ('required_integrations', 'canvas_data', 'trigger_conditions'):
            val = t.get(jsonb_field)
            if isinstance(val, str):
                try:
                    t[jsonb_field] = json.loads(val)
                except (json.JSONDecodeError, TypeError):
                    t[jsonb_field] = [] if jsonb_field == 'required_integrations' else {}
        return t

    # ------------------------------------------------------------------
    # Integration Dependency Check
    # ------------------------------------------------------------------

    async def check_integration_deps(
        self, template_id: str, tenant_id: str
    ) -> Dict[str, Any]:
        """
        Compare a template's required_integrations against the tenant's
        installed connect_instances.  Returns satisfied/missing lists plus
        a mapping_proposal that maps each required connector_id to a tenant
        instance UUID (exact match or category-based alternative).
        """
        template = await self.get_template_detail(template_id)
        if not template:
            return {"error": "Template not found"}

        required = template.get("required_integrations", [])
        if not required:
            return {
                "all_satisfied": True,
                "satisfied": [],
                "missing": [],
                "mapping_proposal": {},
            }

        try:
            t_id = uuid.UUID(tenant_id)
        except ValueError:
            return {"error": "Invalid tenant_id"}

        async with postgres_db.tenant_acquire() as conn:
            # Get tenant's installed+enabled integrations with instance id
            rows = await conn.fetch(
                """
                SELECT ci.id, ci.connector_id, ci.display_name,
                       ci.health_status, ci.enabled,
                       cd.category
                FROM connect_instances ci
                LEFT JOIN connector_definitions cd
                       ON ci.connector_id = cd.connector_id
                WHERE ci.tenant_id = $1 AND ci.enabled = true
                """,
                t_id,
            )

        # Index by connector_id and by category
        installed = {}          # connector_id -> row dict
        by_category = {}        # category -> [row dict, ...]
        for r in rows:
            d = dict(r)
            installed[d["connector_id"]] = d
            cat = (d.get("category") or "").lower()
            if cat:
                by_category.setdefault(cat, []).append(d)

        satisfied = []
        missing = []
        mapping_proposal = {}   # connector_id -> instance UUID string

        for req in required:
            connector_id = req.get("connector_id", "")
            if connector_id in installed:
                inst = installed[connector_id]
                satisfied.append({
                    "connector_id": connector_id,
                    "name": inst.get("display_name", connector_id),
                    "instance_id": str(inst["id"]),
                    "health_status": inst.get("health_status", "unknown"),
                    "reason": req.get("reason", ""),
                })
                mapping_proposal[connector_id] = str(inst["id"])
            else:
                # Category-based fallback: find alternatives
                cat = (req.get("category") or "").lower()
                alternatives = []
                if cat and cat in by_category:
                    for alt in by_category[cat]:
                        alternatives.append({
                            "connector_id": alt["connector_id"],
                            "name": alt.get("display_name", alt["connector_id"]),
                            "instance_id": str(alt["id"]),
                        })

                entry = {
                    "connector_id": connector_id,
                    "category": req.get("category", ""),
                    "name": req.get("name", connector_id),
                    "reason": req.get("reason", ""),
                    "marketplace_url": f"/workbench/connect?install={connector_id}",
                    "alternatives": alternatives,
                }
                missing.append(entry)

                # Auto-propose if exactly one alternative
                if len(alternatives) == 1:
                    mapping_proposal[connector_id] = alternatives[0]["instance_id"]

        return {
            "all_satisfied": len(missing) == 0,
            "satisfied": satisfied,
            "missing": missing,
            "mapping_proposal": mapping_proposal,
        }

    # ------------------------------------------------------------------
    # Install Template
    # ------------------------------------------------------------------

    def _rewrite_canvas_integrations(
        self,
        canvas_data: Dict[str, Any],
        integration_map: Dict[str, str],
        instance_lookup: Dict[str, Dict[str, str]],
    ) -> Dict[str, Any]:
        """
        Rewrite integration references in canvas_data nodes.

        integration_map:  source_connector_id -> target_instance_id (UUID str)
        instance_lookup:  instance_id -> {"connector_id": ..., "display_name": ...}

        Handles 4 patterns:
          1. config.integration_instance_id  (slug -> UUID)
          2. config.integration_action.connector_id  (slug -> new slug + UUID)
          3. config.system  (create_ticket slug)
          4. config.channel (notify slug)
        """
        for node in canvas_data.get("nodes", []):
            data = node.get("data", {})
            kind = data.get("kind", "")
            if kind not in ("respond", "action"):
                continue

            config = data.get("config", {})
            if not config:
                continue

            response_type = config.get("response_type", "integration_action")

            # Determine the source connector slug for this node
            source_slug = None
            if response_type == "create_ticket":
                source_slug = config.get("system")
            elif response_type == "notify":
                source_slug = config.get("channel")
            elif config.get("integration_instance_id"):
                source_slug = config["integration_instance_id"]
            elif config.get("integration_action", {}).get("connector_id"):
                source_slug = config["integration_action"]["connector_id"]

            if not source_slug or source_slug not in integration_map:
                continue

            target_instance_id = integration_map[source_slug]
            target_info = instance_lookup.get(target_instance_id, {})
            target_slug = target_info.get("connector_id", source_slug)

            # Always set the instance UUID
            config["integration_instance_id"] = target_instance_id

            # Rewrite slug fields per pattern
            if response_type == "create_ticket":
                config["system"] = target_slug
            elif response_type == "notify":
                config["channel"] = target_slug

            if "integration_action" in config and isinstance(
                config["integration_action"], dict
            ):
                config["integration_action"]["connector_id"] = target_slug

        return canvas_data

    async def install_template(
        self,
        template_id: str,
        tenant_id: str,
        user_id: str,
        integration_map: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """
        Copy a marketplace template into the tenant's playbooks table.
        Increments install_count.  Optionally rewrites integration references
        using integration_map (source_connector_id -> target_instance_id).
        """
        template = await self.get_template_detail(template_id)
        if not template:
            return {"error": "Template not found"}

        try:
            t_id = uuid.UUID(tenant_id)
            u_id = uuid.UUID(user_id)
            tmpl_id = uuid.UUID(template_id)
        except ValueError:
            return {"error": "Invalid ID format"}

        playbook_id = uuid.uuid4()
        canvas_data = template.get("canvas_data", {"nodes": [], "edges": []})
        if isinstance(canvas_data, str):
            canvas_data = json.loads(canvas_data)

        # Rewrite integration references if a mapping was provided
        if integration_map:
            # Build instance lookup: instance_id -> {connector_id, display_name}
            instance_ids = list(integration_map.values())
            instance_lookup = {}
            if instance_ids:
                async with postgres_db.tenant_acquire() as conn:
                    rows = await conn.fetch(
                        """
                        SELECT id, connector_id, display_name
                        FROM connect_instances
                        WHERE tenant_id = $1 AND id = ANY($2::uuid[])
                        """,
                        t_id,
                        [uuid.UUID(iid) for iid in instance_ids],
                    )
                for r in rows:
                    instance_lookup[str(r["id"])] = {
                        "connector_id": r["connector_id"],
                        "display_name": r["display_name"],
                    }

            canvas_data = self._rewrite_canvas_integrations(
                canvas_data, integration_map, instance_lookup
            )

        async with postgres_db.tenant_acquire() as conn:
            # Insert into playbooks
            await conn.execute(
                """
                INSERT INTO playbooks (
                    id, name, description, canvas_data,
                    trigger_conditions, tags, alert_types, severity_filter,
                    priority, created_by, tenant_id
                ) VALUES (
                    $1, $2, $3, $4::jsonb,
                    $5::jsonb, $6, $7, $8,
                    50, $9, $10
                )
                """,
                playbook_id,
                template.get("name", "Imported Playbook"),
                template.get("description", ""),
                json.dumps(canvas_data),
                json.dumps(template.get("trigger_conditions", {})),
                template.get("tags", []),
                template.get("alert_types", []),
                template.get("severity_filter", []),
                u_id,
                t_id,
            )

            # Increment install count on the template
            await conn.execute(
                """
                UPDATE playbook_templates
                SET install_count = COALESCE(install_count, 0) + 1
                WHERE id = $1
                """,
                tmpl_id,
            )

        return {
            "playbook_id": str(playbook_id),
            "name": template.get("name"),
            "message": f"Playbook '{template.get('name')}' installed successfully",
        }


# Singleton
playbook_catalog = PlaybookCatalogService()
