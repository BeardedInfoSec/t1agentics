# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Recommended Actions Service

Generates and manages actionable recommendations from Riggs AI analysis.
Maps IOCs to available connector actions so analysts can approve with one click.
"""

import asyncio
import json
import uuid
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

from services.postgres_db import postgres_db

logger = logging.getLogger(__name__)


# IOC type to connector action mapping
# Maps what kind of IOC we have to what connector actions can handle it
IOC_ACTION_MAP = {
    "ip": {
        "enrich": ["enrich_ip", "get_ip_report", "ip_lookup", "ip_reputation"],
        "block": ["block_ip", "add_to_blocklist", "block_address", "quarantine_ip"],
    },
    "domain": {
        "enrich": ["enrich_domain", "get_domain_report", "domain_lookup", "domain_reputation"],
        "block": ["block_domain", "add_to_blocklist", "block_url"],
    },
    "hash": {
        "enrich": ["enrich_file_hash", "get_file_report", "hash_lookup", "file_reputation", "scan_hash"],
        "block": ["block_hash", "add_to_blocklist", "quarantine_file", "block_file"],
    },
    "url": {
        "enrich": ["enrich_url", "get_url_report", "url_lookup", "scan_url", "url_reputation"],
        "block": ["block_url", "add_to_blocklist"],
    },
    "email": {
        "enrich": ["enrich_email", "get_email_report", "email_lookup", "check_breach"],
        "block": ["block_sender", "quarantine_email"],
    },
    "hostname": {
        "isolate": ["isolate_host", "contain_host", "quarantine_endpoint"],
        "enrich": ["get_host_info", "host_lookup", "get_device"],
    },
    "username": {
        "disable": ["disable_user", "suspend_user", "revoke_sessions", "force_password_reset"],
        "enrich": ["get_user_info", "user_lookup", "get_user_risk"],
    },
}

# Human-readable action type labels
ACTION_TYPE_LABELS = {
    "enrich": "Enrich",
    "block": "Block",
    "isolate": "Isolate",
    "disable": "Disable",
}

# Total recommendation cap per investigation. Above this we lose the
# analyst — the demo's 3-action pattern is the target, 5 is the ceiling.
MAX_RECOMMENDATIONS_PER_INVESTIGATION = 5

# Infrastructure / SaaS domains that almost never represent the actual
# threat — they're DKIM auth domains, CDN hosts, image hosts, etc.
# Generating "Block ssl.com" or "Block gmail.com" is wrong and noisy.
# Matched against the registrable parent domain (lowercased).
INFRASTRUCTURE_NOISE_DOMAINS = frozenset({
    # Generic email / auth infrastructure
    "gmail.com", "outlook.com", "office.com", "office365.com", "live.com",
    "yahoo.com", "icloud.com", "hotmail.com", "aol.com",
    "amazonses.com", "sendgrid.net", "mailgun.org", "mailchimp.com",
    "mailfrom.com", "sparkpostmail.com", "mandrillapp.com",
    # CDN / static asset hosts
    "gstatic.com", "googleusercontent.com", "googleapis.com",
    "cloudfront.net", "akamai.net", "akamaihd.net", "akamaized.net",
    "fastly.net", "cloudflare.com", "cloudflare.net",
    "azureedge.net", "cdn.shopify.com",
    # Certificate / SSL infrastructure
    "ssl.com", "letsencrypt.org", "digicert.com", "globalsign.com",
    # Tracking / analytics — frequent in marketing emails
    "google-analytics.com", "doubleclick.net", "googletagmanager.com",
    "braze.com", "braze-images.com", "sendgrid.com",
    "mixpanel.com", "segment.com", "hubspot.com",
    # Marketplaces' own pixel/redirect hosts (recurring in shipping emails)
    "ebaystatic.com", "ebayadservices.com", "amazon-mail.com",
    "linkedin.com", "twitter.com", "facebook.com",
})


def _parent_domain(host: str) -> str:
    """Best-effort registrable parent domain for grouping.

    Not a full PSL implementation -- we only need to collapse subdomains
    of the same parent (url3538.tiereduptech.com + url3539.tiereduptech.com
    -> tiereduptech.com). Returns lowercased; if input has <2 labels it
    returns the input unchanged.
    """
    if not host:
        return ""
    h = host.strip().lower().rstrip(".")
    parts = h.split(".")
    if len(parts) <= 2:
        return h
    # Handle common 2-label TLDs (co.uk, com.au) by keeping 3 labels.
    last_two = ".".join(parts[-2:])
    second_level_tlds = {"co.uk", "co.jp", "com.au", "com.br", "co.nz", "ac.uk", "gov.uk"}
    if last_two in second_level_tlds and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _filter_and_group_iocs(iocs: Dict[str, List[str]], tenant_email_domain: str = "") -> Dict[str, List[str]]:
    """Drop infrastructure noise and collapse subdomains of the same parent.

    Goal: turn 27 IOCs into the 3-5 that actually represent the threat.
      - infrastructure noise -> dropped
      - the tenant's own domain -> dropped (don't recommend blocking ourselves)
      - 12 subdomains of attacker.com -> 1 entry for attacker.com
      - URLs are reduced to their registrable host, then deduped against domains
    """
    cleaned: Dict[str, List[str]] = {}
    tenant_parent = _parent_domain(tenant_email_domain) if tenant_email_domain else ""

    def should_drop(host: str) -> bool:
        parent = _parent_domain(host)
        if not parent:
            return True
        if parent in INFRASTRUCTURE_NOISE_DOMAINS:
            return True
        if tenant_parent and parent == tenant_parent:
            return True
        return False

    seen_domains = set()  # parent domains we already covered

    # Domains: collapse to parents
    for raw_domain in iocs.get("domain", []) or []:
        if should_drop(raw_domain):
            continue
        parent = _parent_domain(raw_domain)
        if parent in seen_domains:
            continue
        seen_domains.add(parent)
        cleaned.setdefault("domain", []).append(parent)

    # URLs: reduce to host, then to parent domain — but only add as a
    # standalone "url" rec if the parent isn't already represented as a
    # domain (otherwise it's the same block action twice).
    for raw_url in iocs.get("url", []) or []:
        host = ""
        try:
            from urllib.parse import urlparse
            host = urlparse(raw_url if "://" in raw_url else f"http://{raw_url}").hostname or ""
        except Exception:
            host = raw_url
        if should_drop(host):
            continue
        parent = _parent_domain(host)
        if parent in seen_domains:
            continue
        seen_domains.add(parent)
        # Promote to a domain-level rec — blocking the parent is what we
        # actually want to do, not blocking individual URLs.
        cleaned.setdefault("domain", []).append(parent)

    # IPs, hashes, emails, hostnames, usernames: keep as-is but cap.
    for ioc_type in ("ip", "hash", "email", "hostname", "username"):
        values = iocs.get(ioc_type, []) or []
        if not values:
            continue
        # Drop tenant's own email domain on email-type IOCs
        if ioc_type == "email" and tenant_parent:
            values = [v for v in values if not v.lower().endswith("@" + tenant_parent)]
        # Dedup but preserve order, cap at 5 per type (defensive)
        seen = set()
        out = []
        for v in values:
            if v in seen:
                continue
            seen.add(v)
            out.append(v)
            if len(out) >= 5:
                break
        if out:
            cleaned[ioc_type] = out

    return cleaned


def _verdict_intent_templates(
    verdict: str,
    riggs_analysis: Dict[str, Any],
    grouped_iocs: Dict[str, List[str]],
) -> List[Dict[str, Any]]:
    """Generate intent-aware, demo-quality recommendations from verdict.

    These do NOT require a connector — they're analyst-workflow actions
    (close, whitelist, tune detection rule, escalate). The IOC-mechanical
    block/isolate path runs separately and is layered on top for
    MALICIOUS verdicts.

    Returns recs in priority order; caller caps the total list.
    """
    v = (verdict or "").upper()
    recs: List[Dict[str, Any]] = []
    # Primary domain / sender for templating into the title (if we have one)
    primary_domain = (grouped_iocs.get("domain") or [""])[0]
    primary_email = (grouped_iocs.get("email") or [""])[0]
    sender_label = primary_domain or primary_email or "this sender"

    def add(action_type: str, title: str, description: str, priority: str = "high",
            destructive: bool = False, owner: str = "T1 Agentics"):
        recs.append({
            "action_type": action_type,
            "title": title,
            "description": description,
            "priority": priority,
            "is_destructive": destructive,
            "ioc_type": None,
            "ioc_value": None,
            "connector_id": None,
            "instance_id": None,
            "connector_action_id": None,
            "connector_name": owner,
            "category": "workflow",
            "metadata": {"source": "verdict_template", "verdict": v},
        })

    if v in ("BENIGN", "FALSE_POSITIVE", "BENIGN_POSITIVE"):
        add(
            "close_as_false_positive",
            "Auto-close as false positive",
            "Verdict is benign with high confidence. Close the investigation and mark the originating alert as FP.",
            priority="high", destructive=False, owner="T1 Agentics",
        )
        if primary_domain or primary_email:
            add(
                "whitelist_sender",
                f"Whitelist sender {sender_label}",
                "Sender domain repeatedly flagged but consistently benign. Whitelisting suppresses future alerts from this source.",
                priority="medium", destructive=False, owner="Email Gateway",
            )
        add(
            "tune_detection_rule",
            "Tune detection rule that misfired",
            "The rule that produced this alert has a low precision against this traffic pattern. Adjust the rule to require additional conditions before firing.",
            priority="medium", destructive=False, owner="Detection Engineering",
        )

    elif v in ("MALICIOUS",):
        # IOC-mechanical block/isolate recs come from match_ioc_to_actions
        # below — here we add the human-workflow wrappers.
        add(
            "create_incident_ticket",
            "Open incident ticket and notify on-call",
            "Verdict is malicious — escalate to incident response so the responder can drive containment beyond the automated block actions.",
            priority="high", destructive=False, owner="Incident Response",
        )

    elif v in ("SUSPICIOUS", "NEEDS_INVESTIGATION", "NEEDS_REVIEW"):
        add(
            "escalate_to_senior",
            "Escalate to senior analyst",
            "Verdict is inconclusive — assign to a senior analyst for manual review before any containment action.",
            priority="high", destructive=False, owner="SOC Tier 2",
        )
        # Note: enrichment runs automatically; recommending it again would
        # be the same noise the existing match_ioc_to_actions already
        # filters out.

    return recs


async def get_tenant_connectors(tenant_id: str) -> List[Dict[str, Any]]:
    """Get all enabled connector instances for a tenant with their available actions.

    Uses platform-admin RLS bypass because this function is called from
    job workers (handle_riggs_analysis) that don't have the request
    context's tenant_id set. The query already filters by tenant_id
    explicitly so the bypass cannot leak cross-tenant data.
    """
    try:
        if not postgres_db.pool:
            return []
        async with postgres_db.pool.acquire() as conn:
            async with conn.transaction():
                await conn.execute("SET LOCAL app.is_platform_admin = 'true'")
                rows = await conn.fetch(
                    """
                    SELECT i.id AS instance_id, i.connector_id, i.enabled,
                           c.name AS connector_name, c.vendor, c.category,
                           c.actions AS connector_actions
                    FROM connect_instances i
                    JOIN connector_definitions c
                      ON c.id = i.connector_id
                      AND (c.tenant_id IS NULL OR c.tenant_id = i.tenant_id)
                    WHERE i.tenant_id = $1::uuid AND i.enabled = true
                    """,
                    uuid.UUID(tenant_id),
                )

        connectors = []
        for row in rows:
            actions = row["connector_actions"]
            if isinstance(actions, str):
                actions = json.loads(actions)
            connectors.append({
                "instance_id": str(row["instance_id"]),
                "connector_id": str(row["connector_id"]),
                "connector_name": row["connector_name"],
                "vendor": row["vendor"],
                "category": row["category"],
                "actions": actions or [],
            })
        return connectors
    except Exception as e:
        logger.error(f"Failed to get tenant connectors: {e}")
        return []


def match_ioc_to_actions(
    ioc_type: str,
    ioc_value: str,
    connectors: List[Dict[str, Any]],
    verdict: str = "SUSPICIOUS",
) -> List[Dict[str, Any]]:
    """
    Match an IOC to available connector actions.

    Returns a list of recommended actions with connector details.

    Enrichment actions are NEVER recommended: auto_enrichment runs
    automatically on every alert and surfaces results inline. Recommending
    enrich-via-VirusTotal/AlienVault/URLScan duplicates work the system
    has already done and floods the Recommended Actions list with N IOCs
    x M connectors of noise. Only actions that require analyst decision
    (block / isolate / disable) are recommended.
    """
    recommendations = []
    action_map = IOC_ACTION_MAP.get(ioc_type, {})
    if not action_map:
        return recommendations

    # Determine which action categories to recommend based on verdict.
    # Enrichment is excluded everywhere — it is automatic.
    decision_categories = [c for c in action_map.keys() if c != "enrich"]
    if verdict.upper() == "MALICIOUS":
        action_categories = decision_categories  # block/isolate/disable
    elif verdict.upper() in ("SUSPICIOUS", "NEEDS_INVESTIGATION"):
        action_categories = decision_categories  # analyst can pre-emptively block
    else:
        # Benign or unknown verdicts: no recommendations (auto-close path
        # handles these for free tier; paid tier sees no actionable noise).
        action_categories = []

    for category in action_categories:
        action_ids = action_map.get(category, [])
        if not action_ids:
            continue

        for connector in connectors:
            for action in connector.get("actions", []):
                action_id = action.get("id", "")
                if action_id in action_ids:
                    label = ACTION_TYPE_LABELS.get(category, category.title())
                    recommendations.append({
                        "action_type": f"{category}_{ioc_type}",
                        "title": f"{label} {ioc_type.upper()} {ioc_value} via {connector['connector_name']}",
                        "ioc_type": ioc_type,
                        "ioc_value": ioc_value,
                        "connector_id": connector["connector_id"],
                        "instance_id": connector["instance_id"],
                        "connector_action_id": action_id,
                        "connector_name": connector["connector_name"],
                        "category": connector["category"],
                        "is_destructive": category != "enrich",
                    })
                    break  # One match per connector per category is enough

    return recommendations


async def generate_recommendations(
    tenant_id: str,
    investigation_id: str,
    riggs_analysis: Dict[str, Any],
    iocs: Dict[str, List[str]],
) -> List[Dict[str, Any]]:
    """
    Generate recommended actions from Riggs analysis results.

    Combines Riggs IOC findings with available tenant connectors
    to produce actionable recommendations.
    """
    verdict = riggs_analysis.get("verdict", "SUSPICIOUS")
    connectors = await get_tenant_connectors(tenant_id)

    # Workflow recommendations (close-as-FP, escalate, whitelist, tune
    # detection rule) don't need connectors — they're analyst actions
    # T1 Agentics owns. So we proceed even with no connectors and just
    # skip the IOC-mechanical block/isolate layer below.
    if not connectors:
        logger.info(f"No enabled connectors for tenant {tenant_id}; will only emit workflow recommendations")

    all_recommendations = []

    # Normalize iocs to dict format if it's a list
    if isinstance(iocs, list):
        normalized_iocs = {}
        for item in iocs:
            if isinstance(item, dict):
                ioc_type = item.get("type", "").lower()
                ioc_value = item.get("value", "")
                if ioc_type and ioc_value:
                    if ioc_type not in normalized_iocs:
                        normalized_iocs[ioc_type] = []
                    if ioc_value not in normalized_iocs[ioc_type]:
                        normalized_iocs[ioc_type].append(ioc_value)
        iocs = normalized_iocs

    # Map IOC types from Riggs format to our internal format
    ioc_type_map = {
        "ips": "ip",
        "domains": "domain",
        "hashes": "hash",
        "urls": "url",
        "emails": "email",
    }

    # Also pull IOCs from Riggs analysis output
    riggs_iocs = riggs_analysis.get("iocs", [])
    for riggs_ioc in riggs_iocs:
        ioc_t = riggs_ioc.get("type", "")
        ioc_v = riggs_ioc.get("value", "")
        if ioc_t and ioc_v:
            # Normalize type
            if ioc_t in ("hash", "md5", "sha1", "sha256"):
                ioc_t = "hash"
            mapped = ioc_type_map.get(ioc_t, ioc_t)
            if mapped not in iocs:
                iocs[mapped] = []
            if ioc_v not in iocs[mapped]:
                iocs[mapped].append(ioc_v)

    # Normalize verbose Riggs keys (ips/domains/hashes/urls/emails) into
    # our internal singular keys before any filtering or grouping.
    canonical_iocs: Dict[str, List[str]] = {}
    for raw_type, values in iocs.items():
        normalized_type = ioc_type_map.get(raw_type, raw_type)
        if not values:
            continue
        canonical_iocs.setdefault(normalized_type, []).extend(values)

    # Drop infrastructure noise (CDN/auth/SaaS domains, tenant's own
    # domain) and collapse subdomains of the same parent. This is the
    # single highest-leverage change: an investigation with 27 IOCs (most
    # of them CDN/braze/gstatic noise) typically reduces to 1-3 actual
    # threat IOCs after grouping.
    tenant_email_domain = (
        riggs_analysis.get("tenant_email_domain")
        or riggs_analysis.get("recipient_domain")
        or ""
    )
    grouped_iocs = _filter_and_group_iocs(canonical_iocs, tenant_email_domain)

    # Layer 1: verdict-intent templates (workflow actions — close, whitelist,
    # tune, escalate). These mirror the demo's intent-aware shape and don't
    # need a connector to be useful.
    template_recs = _verdict_intent_templates(verdict, riggs_analysis, grouped_iocs)
    all_recommendations.extend(template_recs)

    # Layer 2: IOC-mechanical connector actions (block/isolate/disable).
    # Only runs when we actually have connectors AND the verdict warrants
    # destructive action. match_ioc_to_actions already returns [] for
    # benign verdicts.
    if connectors:
        for normalized_type, values in grouped_iocs.items():
            for value in values:
                matches = match_ioc_to_actions(normalized_type, value, connectors, verdict)
                all_recommendations.extend(matches)

        # Host/user containment from affected_entities (already-filtered
        # entities Riggs identified).
        affected = riggs_analysis.get("affected_entities", [])
        for entity in affected:
            entity_type = entity.get("type", "")
            entity_value = entity.get("value", "")
            if entity_type == "host" and verdict == "MALICIOUS":
                matches = match_ioc_to_actions("hostname", entity_value, connectors, verdict)
                all_recommendations.extend(matches)
            elif entity_type == "user" and verdict == "MALICIOUS":
                matches = match_ioc_to_actions("username", entity_value, connectors, verdict)
                all_recommendations.extend(matches)

    # Assign priorities for IOC-mechanical recs that didn't get one yet.
    for rec in all_recommendations:
        if rec.get("priority"):
            continue
        rec["priority"] = "high" if rec.get("is_destructive") else "medium"
        if "description" not in rec:
            rec["description"] = ""

    # Deduplicate. Template recs (no connector_action_id) dedupe by
    # action_type alone; IOC recs dedupe by (ioc_value, connector_action_id,
    # instance_id) as before.
    seen = set()
    unique = []
    for rec in all_recommendations:
        if rec.get("connector_action_id"):
            key = ("ioc", rec.get("ioc_value"), rec["connector_action_id"], rec.get("instance_id"))
        else:
            key = ("tpl", rec.get("action_type"))
        if key not in seen:
            seen.add(key)
            unique.append(rec)

    # Sort: workflow templates first (highest signal-to-noise for the
    # analyst), then high-priority destructive actions, then the rest.
    def _sort_key(r):
        is_template = r.get("metadata", {}).get("source") == "verdict_template"
        pri_order = {"high": 0, "medium": 1, "low": 2}.get(r.get("priority", "medium"), 1)
        return (0 if is_template else 1, pri_order)
    unique.sort(key=_sort_key)

    # Cap to the demo's signal-density target. Beyond ~5 actions the
    # analyst skims past them; the marginal value of action #6+ is
    # essentially zero and they add visual debt.
    if len(unique) > MAX_RECOMMENDATIONS_PER_INVESTIGATION:
        dropped = len(unique) - MAX_RECOMMENDATIONS_PER_INVESTIGATION
        logger.info(
            f"Investigation {investigation_id}: capped recommendations "
            f"({len(unique)} -> {MAX_RECOMMENDATIONS_PER_INVESTIGATION}, "
            f"{dropped} dropped)"
        )
        unique = unique[:MAX_RECOMMENDATIONS_PER_INVESTIGATION]

    # Ask Riggs to generate a 1-2 sentence rationale for each IOC-mechanical
    # action (template recs already carry their own description).
    needs_rationale = [r for r in unique if not r.get("description")]
    if needs_rationale:
        await _attach_action_rationales(needs_rationale, riggs_analysis, tenant_id, investigation_id)

    return unique


async def _attach_action_rationales(
    recommendations: List[Dict[str, Any]],
    riggs_analysis: Dict[str, Any],
    tenant_id: str,
    investigation_id: str,
) -> None:
    """Mutate recommendations in place, attaching a per-action rationale.

    One Claude call per investigation regardless of action count -- we
    pass the full action list and ask for a JSON map keyed by action
    index so the LLM can reuse context across all of them.
    """
    verdict = riggs_analysis.get("verdict", "UNKNOWN")
    fallback = f"Recommended by Riggs based on {verdict} verdict."

    try:
        from services.claude_service import get_claude_service
        import uuid as _uuid
        import json as _json

        claude = await get_claude_service()
        if not getattr(claude, "is_configured", False):
            for r in recommendations:
                r["description"] = fallback
            return

        # Pull the most useful context fields without blowing the prompt.
        summary = (riggs_analysis.get("summary")
                   or riggs_analysis.get("executive_summary")
                   or "")[:1200]
        narrative = (riggs_analysis.get("threat_narrative")
                     or riggs_analysis.get("attack_narrative")
                     or "")[:1500]
        confidence = riggs_analysis.get("confidence")

        # Compact action list -- only what the LLM needs to write a reason
        action_list = []
        for idx, r in enumerate(recommendations):
            action_list.append({
                "i": idx,
                "title": r.get("title", ""),
                "type": r.get("action_type", ""),
                "ioc_type": r.get("ioc_type"),
                "ioc_value": r.get("ioc_value"),
                "connector": r.get("connector_name"),
                "destructive": bool(r.get("is_destructive")),
            })

        system = (
            "You are Riggs, a senior SOC analyst. For each proposed response "
            "action, write ONE plain-English sentence (max 30 words) explaining "
            "WHY this specific action is justified given the investigation "
            "context. Reference the actual evidence (e.g. 'flagged as "
            "Cobalt Strike infrastructure by 4 feeds', 'user clicked the "
            "phishing link and entered credentials'). Do NOT say 'because the "
            "IOC was found' or restate the action title. If an action is "
            "destructive, briefly note the safety reasoning (e.g. 'verdict "
            "is MALICIOUS at 95% so containment is appropriate'). Reply with "
            "ONLY a JSON object mapping the action index (as a string) to "
            "the rationale string. No markdown, no commentary."
        )
        prompt = (
            f"Investigation verdict: {verdict}"
            + (f" (confidence {confidence})" if confidence is not None else "")
            + f"\n\nSummary:\n{summary}\n\nThreat narrative:\n{narrative}\n\n"
            f"Proposed actions:\n{_json.dumps(action_list, indent=2)}\n\n"
            f"Return: {{\"0\": \"...\", \"1\": \"...\", ...}}"
        )

        try:
            tid_uuid = _uuid.UUID(str(tenant_id)) if tenant_id else None
            inv_uuid = None
            try:
                inv_uuid = _uuid.UUID(str(investigation_id))
            except (ValueError, TypeError):
                inv_uuid = None
        except (ValueError, TypeError):
            tid_uuid = None

        result = await claude.complete(
            tenant_id=tid_uuid,
            system=system,
            prompt=prompt,
            max_tokens=900,
            temperature=0.2,
            request_type="recommended_action_rationale",
            investigation_id=inv_uuid,
        )

        text = (getattr(result, "text", "") or "").strip()
        # Strip markdown code fences if the model wrapped them despite instructions
        if text.startswith("```"):
            text = text.strip("`")
            if text.lower().startswith("json"):
                text = text[4:]
            text = text.strip()
        rationales = _json.loads(text)

        for idx, r in enumerate(recommendations):
            reason = rationales.get(str(idx)) or rationales.get(idx)
            r["description"] = (reason or fallback).strip()
    except Exception as e:
        logger.warning(f"Failed to generate action rationales: {e}")
        for r in recommendations:
            if not r.get("description"):
                r["description"] = fallback


async def save_recommendations(
    tenant_id: str,
    investigation_id: str,
    recommendations: List[Dict[str, Any]],
    riggs_analysis_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Save generated recommendations to the database."""
    saved = []
    async with postgres_db.tenant_acquire() as conn:
        for rec in recommendations:
            try:
                # Validate and convert UUID fields safely — connector_id may be a slug string
                connector_id = None
                raw_connector_id = rec.get("connector_id")
                if raw_connector_id:
                    try:
                        connector_id = uuid.UUID(str(raw_connector_id))
                    except (ValueError, TypeError):
                        # Look up UUID from connector slug/codename
                        try:
                            cid_row = await conn.fetchrow(
                                "SELECT id FROM connect_instances WHERE connector_id = $1 OR connector_codename = $1 LIMIT 1",
                                str(raw_connector_id),
                            )
                            if cid_row:
                                connector_id = cid_row["id"]
                        except Exception:
                            pass
                        # Still no UUID? Store without connector_id — don't skip
                        if not connector_id:
                            logger.debug(f"connector_id '{raw_connector_id}' is not a UUID and not found in connect_instances, saving without")

                instance_id = None
                raw_instance_id = rec.get("instance_id")
                if raw_instance_id:
                    try:
                        instance_id = uuid.UUID(str(raw_instance_id))
                    except (ValueError, TypeError):
                        try:
                            iid_row = await conn.fetchrow(
                                "SELECT id FROM connect_instances WHERE connector_codename = $1 LIMIT 1",
                                str(raw_instance_id),
                            )
                            if iid_row:
                                instance_id = iid_row["id"]
                        except Exception:
                            pass

                row = await conn.fetchrow(
                    """
                    INSERT INTO recommended_actions (
                        tenant_id, investigation_id, action_type, title, description,
                        priority, ioc_type, ioc_value, connector_id, instance_id,
                        connector_action_id, connector_name, status, riggs_analysis_id, metadata
                    ) VALUES (
                        $1::uuid, $2::uuid, $3, $4, $5,
                        $6, $7, $8, $9::uuid, $10::uuid,
                        $11, $12, 'pending', $13, $14::jsonb
                    )
                    RETURNING *
                    """,
                    uuid.UUID(tenant_id),
                    uuid.UUID(investigation_id),
                    rec["action_type"],
                    rec["title"],
                    rec.get("description", ""),
                    rec.get("priority", "medium"),
                    rec.get("ioc_type"),
                    rec.get("ioc_value"),
                    connector_id,
                    instance_id,
                    rec.get("connector_action_id"),
                    rec.get("connector_name"),
                    riggs_analysis_id,
                    json.dumps(rec.get("metadata", {})),
                )
                saved.append(dict(row))
            except Exception as e:
                logger.error(f"Failed to save recommendation: {e}")
    return saved


async def check_auto_response_and_execute(
    tenant_id: str,
    saved_recommendations: List[Dict[str, Any]],
) -> None:
    """
    For each saved recommendation, check if auto-response is enabled.

    Priority:
      1. If a per-action setting exists in auto_response_settings for this
         (instance_id, action_type), use that.
      2. Otherwise fall back to the global auto_response_enabled on the instance.
    """
    for rec in saved_recommendations:
        instance_id = rec.get("instance_id")
        action_id = rec.get("id")
        action_type = rec.get("action_type")
        if not instance_id or not action_id:
            continue

        try:
            async with postgres_db.tenant_acquire() as conn:
                # Get global setting
                instance_row = await conn.fetchrow(
                    """
                    SELECT auto_response_enabled FROM connect_instances
                    WHERE id = $1::uuid AND tenant_id = $2::uuid
                    """,
                    uuid.UUID(str(instance_id)),
                    uuid.UUID(str(tenant_id)),
                )

                # Check for per-action override
                per_action_row = None
                if action_type:
                    per_action_row = await conn.fetchrow(
                        """
                        SELECT enabled FROM auto_response_settings
                        WHERE instance_id = $1::uuid AND action_type = $2
                        """,
                        uuid.UUID(str(instance_id)),
                        action_type,
                    )

            if not instance_row:
                continue

            # Per-action setting takes priority over global
            if per_action_row is not None:
                auto_enabled = per_action_row["enabled"]
            else:
                auto_enabled = instance_row["auto_response_enabled"]

            if not auto_enabled:
                continue

            # Auto-approve: set status to approved, store riggs_auto in metadata
            async with postgres_db.tenant_acquire() as conn:
                await conn.execute(
                    """
                    UPDATE recommended_actions
                    SET status = 'approved',
                        approved_at = NOW(),
                        updated_at = NOW(),
                        metadata = COALESCE(metadata, '{}'::jsonb) || '{"approved_by": "riggs_auto"}'::jsonb
                    WHERE id = $1::uuid AND tenant_id = $2::uuid AND status = 'pending'
                    """,
                    uuid.UUID(str(action_id)),
                    uuid.UUID(str(tenant_id)),
                )

            logger.info(f"Auto-approved action {action_id} via riggs_auto for instance {instance_id}")

            # Execute in background (fire-and-forget)
            asyncio.ensure_future(_safe_execute(tenant_id, str(action_id)))

        except Exception as e:
            logger.error(f"Auto-response check failed for action {action_id}: {e}")


async def _safe_execute(tenant_id: str, action_id: str) -> None:
    """Wrapper to safely execute an action without propagating exceptions."""
    try:
        await execute_action(tenant_id, action_id)
    except Exception as e:
        logger.error(f"Auto-execute failed for action {action_id}: {e}")


async def get_available_actions_for_ioc(
    tenant_id: str,
    ioc_type: str,
    ioc_value: str,
    investigation_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Return available connector actions for an IOC without saving to the database.
    Used by the one-touch IOC action UI to show what actions are possible.
    """
    connectors = await get_tenant_connectors(tenant_id)
    if not connectors:
        return []

    # Use MALICIOUS verdict to show all possible actions (enrich + block/contain)
    matches = match_ioc_to_actions(ioc_type, ioc_value, connectors, "MALICIOUS")

    # Enrich with auto_response status for each instance
    instance_ids = list({m["instance_id"] for m in matches})
    auto_response_map = {}
    if instance_ids:
        try:
            async with postgres_db.tenant_acquire() as conn:
                rows = await conn.fetch(
                    """
                    SELECT id, auto_response_enabled FROM connect_instances
                    WHERE tenant_id = $1::uuid AND id = ANY($2::uuid[])
                    """,
                    uuid.UUID(tenant_id),
                    [uuid.UUID(iid) for iid in instance_ids],
                )
            for row in rows:
                auto_response_map[str(row["id"])] = row["auto_response_enabled"]
        except Exception as e:
            logger.error(f"Failed to fetch auto_response status: {e}")

    for m in matches:
        m["auto_response_enabled"] = auto_response_map.get(m["instance_id"], False)

    return matches


async def execute_instant_action(
    tenant_id: str,
    investigation_id: str,
    ioc_type: str,
    ioc_value: str,
    action_type: str,
    instance_id: str,
    user_id: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """
    One-touch action: create, approve, and execute a recommended action in one step.
    Returns the completed/failed action record.
    """
    # Find the matching connector action
    connectors = await get_tenant_connectors(tenant_id)
    target_connector = None
    for c in connectors:
        if c["instance_id"] == instance_id:
            target_connector = c
            break

    if not target_connector:
        logger.error(f"Instance {instance_id} not found for tenant {tenant_id}")
        return None

    # Find the specific action on this connector
    connector_action_id = None
    action_map = IOC_ACTION_MAP.get(ioc_type, {})
    for category, action_ids in action_map.items():
        cat_action_type = f"{category}_{ioc_type}"
        if cat_action_type == action_type:
            for action in target_connector.get("actions", []):
                if action.get("id", "") in action_ids:
                    connector_action_id = action["id"]
                    break
            break

    if not connector_action_id:
        logger.error(f"No matching action found for type {action_type} on instance {instance_id}")
        return None

    label = ACTION_TYPE_LABELS.get(action_type.split("_")[0], action_type.split("_")[0].title())
    title = f"{label} {ioc_type.upper()} {ioc_value} via {target_connector['connector_name']}"

    # Save as approved directly
    async with postgres_db.tenant_acquire() as conn:
        row = await conn.fetchrow(
            """
            INSERT INTO recommended_actions (
                tenant_id, investigation_id, action_type, title, description,
                priority, ioc_type, ioc_value, connector_id, instance_id,
                connector_action_id, connector_name, status, approved_by, approved_at,
                metadata
            ) VALUES (
                $1::uuid, $2::uuid, $3, $4, $5,
                $6, $7, $8, $9::uuid, $10::uuid,
                $11, $12, 'approved', $13, NOW(),
                $14::jsonb
            )
            RETURNING *
            """,
            uuid.UUID(tenant_id),
            uuid.UUID(investigation_id),
            action_type,
            title,
            "One-touch action executed by analyst",
            "high",
            ioc_type,
            ioc_value,
            uuid.UUID(target_connector["connector_id"]),
            uuid.UUID(instance_id),
            connector_action_id,
            target_connector["connector_name"],
            uuid.UUID(user_id) if user_id else None,
            json.dumps({"instant_action": True}),
        )

    if not row:
        return None

    action_id = str(row["id"])

    # Execute immediately
    result = await execute_action(tenant_id, action_id)
    return result


async def get_recommendations(
    tenant_id: str,
    investigation_id: str,
    status: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Get all recommended actions for an investigation."""
    async with postgres_db.tenant_acquire() as conn:
        # Resolve VARCHAR investigation_id (e.g., INV-F429EA9E) to UUID if needed
        try:
            inv_uuid = uuid.UUID(investigation_id)
        except ValueError:
            # Not a UUID — look up the investigation's UUID primary key
            row = await conn.fetchrow(
                "SELECT id FROM investigations WHERE investigation_id = $1",
                investigation_id,
            )
            if not row:
                return []
            inv_uuid = row['id']

        if status:
            rows = await conn.fetch(
                """
                SELECT * FROM recommended_actions
                WHERE tenant_id = $1::uuid AND investigation_id = $2::uuid AND status = $3
                ORDER BY
                    CASE priority WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 END,
                    created_at DESC
                """,
                uuid.UUID(tenant_id),
                inv_uuid,
                status,
            )
        else:
            rows = await conn.fetch(
                """
                SELECT * FROM recommended_actions
                WHERE tenant_id = $1::uuid AND investigation_id = $2::uuid
                ORDER BY
                    CASE status WHEN 'pending' THEN 1 WHEN 'executing' THEN 2 WHEN 'approved' THEN 3
                         WHEN 'completed' THEN 4 WHEN 'failed' THEN 5 WHEN 'dismissed' THEN 6 END,
                    CASE priority WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 END,
                    created_at DESC
                """,
                uuid.UUID(tenant_id),
                inv_uuid,
            )

    results = []
    for row in rows:
        d = dict(row)
        # Convert UUIDs and datetimes to strings for JSON serialization
        for key, val in d.items():
            if isinstance(val, uuid.UUID):
                d[key] = str(val)
            elif isinstance(val, datetime):
                d[key] = val.isoformat()
        results.append(d)
    return results


async def approve_action(
    tenant_id: str,
    action_id: str,
    user_id: str,
) -> Optional[Dict[str, Any]]:
    """Approve a recommended action for execution."""
    async with postgres_db.tenant_acquire() as conn:
        row = await conn.fetchrow(
            """
            UPDATE recommended_actions
            SET status = 'approved', approved_by = $3::uuid, approved_at = NOW(), updated_at = NOW()
            WHERE id = $1::uuid AND tenant_id = $2::uuid AND status = 'pending'
            RETURNING *
            """,
            uuid.UUID(action_id),
            uuid.UUID(tenant_id),
            uuid.UUID(user_id),
        )
    if row:
        d = dict(row)
        for key, val in d.items():
            if isinstance(val, uuid.UUID):
                d[key] = str(val)
            elif isinstance(val, datetime):
                d[key] = val.isoformat()
        return d
    return None


async def execute_action(
    tenant_id: str,
    action_id: str,
) -> Optional[Dict[str, Any]]:
    """
    Execute an approved recommended action via the connector.
    Uses the action_engine to run the connector action.
    """
    async with postgres_db.tenant_acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT * FROM recommended_actions
            WHERE id = $1::uuid AND tenant_id = $2::uuid AND status = 'approved'
            """,
            uuid.UUID(action_id),
            uuid.UUID(tenant_id),
        )

    if not row:
        return None

    action = dict(row)

    # Mark as executing
    async with postgres_db.tenant_acquire() as conn:
        await conn.execute(
            """
            UPDATE recommended_actions
            SET status = 'executing', updated_at = NOW()
            WHERE id = $1::uuid
            """,
            uuid.UUID(action_id),
        )

    try:
        # Import here to avoid circular imports
        from services.connect_service import ConnectService
        connect = ConnectService()

        instance_id = str(action["instance_id"])
        connector_action_id = action["connector_action_id"]
        ioc_value = action["ioc_value"]

        # Execute the connector action
        result = await connect.execute_action(
            tenant_id=tenant_id,
            instance_id=instance_id,
            action_id=connector_action_id,
            params={"value": ioc_value, "indicator": ioc_value},
        )

        # Mark completed
        async with postgres_db.tenant_acquire() as conn:
            updated = await conn.fetchrow(
                """
                UPDATE recommended_actions
                SET status = 'completed', executed_at = NOW(), execution_result = $2::jsonb, updated_at = NOW()
                WHERE id = $1::uuid
                RETURNING *
                """,
                uuid.UUID(action_id),
                json.dumps(result or {}),
            )

        if updated:
            d = dict(updated)
            for key, val in d.items():
                if isinstance(val, uuid.UUID):
                    d[key] = str(val)
                elif isinstance(val, datetime):
                    d[key] = val.isoformat()
            return d

    except Exception as e:
        logger.error(f"Failed to execute action {action_id}: {e}")
        async with postgres_db.tenant_acquire() as conn:
            await conn.execute(
                """
                UPDATE recommended_actions
                SET status = 'failed', execution_result = $2::jsonb, updated_at = NOW()
                WHERE id = $1::uuid
                """,
                uuid.UUID(action_id),
                json.dumps({"error": str(e)}),
            )
        return None


async def dismiss_action(
    tenant_id: str,
    action_id: str,
    user_id: str,
    reason: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """Dismiss a recommended action."""
    async with postgres_db.tenant_acquire() as conn:
        row = await conn.fetchrow(
            """
            UPDATE recommended_actions
            SET status = 'dismissed', dismissed_by = $3::uuid, dismissed_at = NOW(),
                dismiss_reason = $4, updated_at = NOW()
            WHERE id = $1::uuid AND tenant_id = $2::uuid AND status = 'pending'
            RETURNING *
            """,
            uuid.UUID(action_id),
            uuid.UUID(tenant_id),
            uuid.UUID(user_id),
            reason,
        )
    if row:
        d = dict(row)
        for key, val in d.items():
            if isinstance(val, uuid.UUID):
                d[key] = str(val)
            elif isinstance(val, datetime):
                d[key] = val.isoformat()
        return d
    return None
