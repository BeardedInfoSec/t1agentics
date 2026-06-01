# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Riggs - Senior SOC Analyst Agent

ARCHITECTURE:
- Flag-based prompt selection: Uses alert flags from T1 triage (PHISHING, MALWARE, C2, etc.)
- Each flag type gets a specialized investigation prompt with relevant focus areas
- Single LLM call per investigation (no FAST→DEEP escalation)

RULES:
- Confidence is always 0-100 integer
- riggs_analysis is NEVER in input (prevents feedback loops)
- Prompt metadata stored for auditability
"""

import json
import logging
import os
from typing import Dict, Any, Optional, Tuple, List
from dataclasses import dataclass, asdict
from datetime import datetime

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════════
# RIGGS INPUT SCHEMA - Minimal, deduplicated
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class RiggsInput:
    """Minimal input for Riggs analysis. Never includes prior riggs_analysis."""

    # Identity
    investigation_id: str
    alert_id: str

    # T1 Context (compact)
    t1_verdict: str
    t1_confidence: int  # 0-100 integer
    t1_summary: str

    # Alert Metadata
    title: str
    severity: str
    source: str
    timestamp: str

    # Evidence (single source of truth)
    raw_event: Dict[str, Any]

    # Pre-extracted (deduplicated)
    iocs: Dict[str, List[str]]
    entities: Dict[str, List[str]]

    # Optional enrichments
    decoded_content: Optional[List[Dict]] = None
    enrichment_summary: Optional[Dict[str, int]] = None

    # Email authentication (for phishing verdicts)
    email_auth_status: Optional[Dict[str, bool]] = None
    sender_legitimacy_verified: bool = False

    # Mode
    analysis_mode: str = "DEEP"

    # Knowledge Base recommendations (optional)
    kb_recommendations: Optional[List[Dict]] = None

    # Pre-triage playbook results (what already ran before T1)
    playbook_results_summary: Optional[str] = None

    # Per-tenant LLM context overrides (from tenant_llm_context table).
    # See services/tenant_llm_context_service.py for the schema. Allows a
    # tenant to inject org-specific prose and to flip individual raw_event
    # keys in/out of the default redaction set.
    tenant_llm_context: Optional[Dict[str, Any]] = None

    # ─── Round B platform-awareness fields ──────────────────────────────
    # Each of these is optional context the audit identified as missing
    # from Riggs's prompt. The orchestrator (build_riggs_input below)
    # populates them with cheap reads against the tenant's data so Riggs
    # can reason against platform state, not just the raw alert.

    # If this investigation came in via an intake form, the structured
    # context: which form, what category, the submitter's notes. Lets
    # Riggs treat user-submitted reports as already-classified instead
    # of triaging the rendered title as if it were vendor telemetry.
    intake_context: Optional[Dict[str, Any]] = None

    # Snapshot of the entity-risk score for the primary entity in this
    # alert (user/host/ioc), plus whether it's hit the tenant's
    # configured threshold. Surfaced so Riggs can recommend escalation
    # for "this user is above threshold across N alerts."
    entity_risk_summary: Optional[Dict[str, Any]] = None

    # SLA target + elapsed time for this investigation. Riggs prompt
    # references it so verdict urgency is informed by time pressure.
    sla_context: Optional[Dict[str, Any]] = None

    # Connector actions actually available for this tenant (e.g. "Block
    # IP via CrowdStrike" — only listed if the connector is installed
    # and enabled). Lets Riggs recommend actions that the tenant can
    # actually execute, not generic suggestions.
    available_actions: Optional[List[Dict[str, Any]]] = None

    # Tenant-defined dedup rules / phishing-test sender list / PII
    # patterns / sender trust list. Riggs respects these for
    # suppression decisions instead of independently analyzing already-
    # classified senders.
    tenant_custom_rules: Optional[Dict[str, Any]] = None

    def to_prompt_context(self) -> str:
        """Convert to minimal prompt context string."""
        parts = [
            f"Investigation: {self.investigation_id}",
            f"Alert: {self.alert_id}",
            f"",
            f"T1 VERDICT: {self.t1_verdict} ({self.t1_confidence}% confidence)",
            f"T1 Summary: {self.t1_summary}",
        ]

        # Add email authentication status for BENIGN phishing verdicts
        if self.t1_verdict.upper() == 'BENIGN' and (self.sender_legitimacy_verified or self.email_auth_status):
            parts.append("")
            parts.append("═══════════════════════════════════════════════════════════════")
            parts.append("SENDER VERIFICATION STATUS (from T1):")
            if self.sender_legitimacy_verified:
                parts.append("  ✓ SENDER IS CRYPTOGRAPHICALLY VERIFIED")
            if self.email_auth_status:
                auth = self.email_auth_status
                if auth.get('all_passed'):
                    parts.append("  ✓ SPF: PASS | DKIM: PASS | DMARC: PASS")
                else:
                    auth_parts = []
                    if auth.get('spf_pass'): auth_parts.append("SPF: PASS")
                    if auth.get('dkim_pass'): auth_parts.append("DKIM: PASS")
                    if auth.get('dmarc_pass'): auth_parts.append("DMARC: PASS")
                    if auth_parts:
                        parts.append(f"  Email Auth: {' | '.join(auth_parts)}")
            parts.append("═══════════════════════════════════════════════════════════════")

        # Sanitize raw_event: strip sensitive fields before sending to LLM.
        # Substring match (not set membership) so camelCase / kebab-case /
        # composite names like OAuthAccessToken, X-Api-Key, refreshTokenV2
        # are caught — they all contain one of these tokens but aren't
        # literally equal to one.
        _SENSITIVE_KEYS = frozenset({
            'password', 'passwd', 'secret', 'token', 'api_key', 'apikey',
            'access_key', 'private_key', 'auth_token', 'bearer', 'credential',
            'client_secret', 'refresh_token', 'session_token', 'cookie',
        })

        # Per-tenant key overrides — see tenant_llm_context migration 065.
        # include_set: keys the tenant explicitly wants preserved even when
        # the sensitive-key heuristic would otherwise redact them.
        # exclude_set: extra keys the tenant wants dropped on top of the
        # platform defaults (drop wins over include if both are set).
        tlc = self.tenant_llm_context or {}
        _normalize = lambda k: (k or '').lower().replace('-', '_')
        include_set = {_normalize(k) for k in (tlc.get('include_field_keys') or [])}
        exclude_set = {_normalize(k) for k in (tlc.get('exclude_field_keys') or [])}

        def _is_sensitive(key: str) -> bool:
            k = _normalize(key)
            if k in include_set:
                return False
            return any(s in k for s in _SENSITIVE_KEYS)
        def _sanitize(obj, depth=0):
            if depth > 10:
                return "[truncated]"
            if isinstance(obj, dict):
                out = {}
                for k, v in obj.items():
                    if _normalize(k) in exclude_set:
                        continue
                    out[k] = "[REDACTED]" if _is_sensitive(k) else _sanitize(v, depth + 1)
                return out
            if isinstance(obj, list):
                return [_sanitize(item, depth + 1) for item in obj[:50]]
            return obj

        sanitized_event = _sanitize(self.raw_event)

        parts.extend([
            f"",
            f"ALERT: {self.title}",
            f"Severity: {self.severity} | Source: {self.source}",
            f"Time: {self.timestamp}",
            f"",
            f"RAW EVENT:",
            json.dumps(sanitized_event, indent=2, default=str),
        ])

        if self.iocs and any(self.iocs.values()):
            parts.append("")
            parts.append("EXTRACTED IOCs:")
            for ioc_type, values in self.iocs.items():
                if values:
                    parts.append(f"  {ioc_type}: {', '.join(str(v) for v in values[:10])}")

        if self.entities and any(self.entities.values()):
            parts.append("")
            parts.append("ENTITIES:")
            for entity_type, values in self.entities.items():
                if values:
                    parts.append(f"  {entity_type}: {', '.join(str(v) for v in values[:10])}")

        if self.decoded_content:
            parts.append("")
            parts.append("DECODED CONTENT (CRITICAL):")
            for i, dc in enumerate(self.decoded_content[:3]):
                parts.append(f"  [{i+1}] {dc.get('context', 'base64')}: {str(dc.get('decoded', ''))[:500]}")

        if self.enrichment_summary:
            parts.append("")
            parts.append(f"ENRICHMENT: {self.enrichment_summary}")

        # Include pre-triage playbook results (automated actions already taken)
        if self.playbook_results_summary and self.playbook_results_summary != "No automated playbooks have run for this alert.":
            parts.append("")
            parts.append("═══════════════════════════════════════════════════════════════")
            parts.append("AUTOMATED RESPONSE ACTIONS (ALREADY EXECUTED BEFORE T1):")
            parts.append("═══════════════════════════════════════════════════════════════")
            parts.append(self.playbook_results_summary)
            parts.append("")
            parts.append("NOTE: Factor these results into your investigation. If containment")
            parts.append("actions succeeded, the threat may be partially mitigated. If actions")
            parts.append("failed, recommend manual follow-up or alternative playbooks.")
            parts.append("═══════════════════════════════════════════════════════════════")

        # Include KB recommendations (company SOPs and playbooks)
        if self.kb_recommendations:
            parts.append("")
            parts.append("═══════════════════════════════════════════════════════════════")
            parts.append("COMPANY SOPs AND PLAYBOOKS (from Knowledge Base):")
            parts.append("═══════════════════════════════════════════════════════════════")
            parts.append("The following SOPs are recommended based on this alert type:")
            parts.append("")
            for i, kb_entry in enumerate(self.kb_recommendations[:5], 1):
                parts.append(f"[SOP {i}] {kb_entry.get('title', 'Untitled')}")
                parts.append(f"  Type: {kb_entry.get('content_type', 'sop')} | Category: {kb_entry.get('category', 'general')}")
                parts.append(f"  Relevance: {kb_entry.get('similarity', 0.0):.0%}")
                # Include first 300 chars of content
                content = kb_entry.get('content', '')
                if content:
                    content_preview = content[:300] + ('...' if len(content) > 300 else '')
                    parts.append(f"  Content: {content_preview}")
                if kb_entry.get('mitre_techniques'):
                    parts.append(f"  MITRE: {', '.join(kb_entry.get('mitre_techniques', []))}")
                parts.append("")
            parts.append("Use these SOPs as guidance in your investigation and recommendations.")
            parts.append("═══════════════════════════════════════════════════════════════")

        # Per-tenant free-form context. Sized (4 KB cap, enforced at write
        # time) so this stays cheap to send on every alert.
        extra_ctx = (tlc.get('extra_context') if tlc else None)
        if extra_ctx:
            parts.append("")
            parts.append("═══════════════════════════════════════════════════════════════")
            parts.append("ORGANIZATIONAL CONTEXT (configured by tenant admin):")
            parts.append("═══════════════════════════════════════════════════════════════")
            parts.append(extra_ctx.strip())
            parts.append("═══════════════════════════════════════════════════════════════")

        # ─── Round B platform-awareness context ────────────────────────────

        if self.intake_context:
            ic = self.intake_context
            parts.append("")
            parts.append("═══════════════════════════════════════════════════════════════")
            parts.append("INTAKE FORM CONTEXT (user-submitted report, NOT vendor telemetry):")
            parts.append("═══════════════════════════════════════════════════════════════")
            if ic.get('form_name'):
                parts.append(f"Form: {ic['form_name']}")
            if ic.get('category'):
                parts.append(f"Category (user-classified): {ic['category']}")
            if ic.get('submitter'):
                parts.append(f"Submitter: {ic['submitter']}")
            if ic.get('summary'):
                parts.append(f"Summary: {ic['summary'][:500]}")
            parts.append("")
            parts.append("Note: The user already classified this by choosing this form.")
            parts.append("Don't re-litigate the category. Focus on extracting IOCs and")
            parts.append("recommending containment / next steps.")
            parts.append("═══════════════════════════════════════════════════════════════")

        if self.entity_risk_summary:
            ers = self.entity_risk_summary
            parts.append("")
            parts.append("═══════════════════════════════════════════════════════════════")
            parts.append("ENTITY RISK CONTEXT:")
            parts.append("═══════════════════════════════════════════════════════════════")
            for entry in ers.get('entities', [])[:5]:
                entity = entry.get('entity_value', 'unknown')
                etype = entry.get('entity_type', 'entity')
                score = entry.get('score', 0)
                threshold = entry.get('threshold', 100)
                breached = entry.get('threshold_breached', False)
                related = entry.get('related_alert_count', 0)
                marker = '⚠ BREACHED' if breached else 'below threshold'
                parts.append(f"  {etype}={entity}: risk={score:.1f}/{threshold:.1f} ({marker}), {related} related alerts")
            if any(e.get('threshold_breached') for e in ers.get('entities', [])):
                parts.append("")
                parts.append("RECOMMENDATION: At least one entity is above the tenant's risk")
                parts.append("threshold. Consider whether this alert is part of a campaign and")
                parts.append("recommend correlation review.")
            parts.append("═══════════════════════════════════════════════════════════════")

        if self.sla_context:
            sla = self.sla_context
            target_min = sla.get('target_minutes')
            elapsed_min = sla.get('elapsed_minutes')
            breached = sla.get('breached', False)
            parts.append("")
            parts.append("SLA CONTEXT:")
            if target_min is not None and elapsed_min is not None:
                parts.append(f"  Resolution target: {target_min}m | elapsed: {int(elapsed_min)}m"
                             + (' (BREACHED)' if breached else ''))
            if breached:
                parts.append("  Time pressure: PAST SLA. Prefer a verdict over deferral if")
                parts.append("  you have enough evidence; flag escalation in recommendations.")
            elif target_min and elapsed_min and elapsed_min > target_min * 0.66:
                parts.append("  Time pressure: approaching SLA. Lean toward decisive verdict.")

        if self.available_actions:
            parts.append("")
            parts.append("═══════════════════════════════════════════════════════════════")
            parts.append("AVAILABLE CONNECTOR ACTIONS (this tenant has these wired):")
            parts.append("═══════════════════════════════════════════════════════════════")
            for act in self.available_actions[:12]:
                action = act.get('action', 'unknown')
                connector = act.get('connector', 'unknown')
                ioc_type = act.get('ioc_type', '')
                ioc_str = f" ({ioc_type})" if ioc_type else ""
                parts.append(f"  - {action} via {connector}{ioc_str}")
            parts.append("")
            parts.append("Ground your recommended actions in this list. Don't recommend an")
            parts.append("action the tenant has no connector for.")
            parts.append("═══════════════════════════════════════════════════════════════")

        if self.tenant_custom_rules:
            tcr = self.tenant_custom_rules
            has_any = (tcr.get('phishing_test_senders') or tcr.get('trusted_senders')
                       or tcr.get('dedup_rules') or tcr.get('pii_patterns'))
            if has_any:
                parts.append("")
                parts.append("TENANT-SPECIFIC SUPPRESSION RULES (apply these BEFORE verdict):")
                if tcr.get('phishing_test_senders'):
                    senders = ', '.join(tcr['phishing_test_senders'][:8])
                    parts.append(f"  Phishing-test senders: {senders}")
                    parts.append("    → Mark BENIGN if a sender from this list appears.")
                if tcr.get('trusted_senders'):
                    senders = ', '.join(tcr['trusted_senders'][:8])
                    parts.append(f"  Trusted senders (tenant-allowlisted): {senders}")
                if tcr.get('dedup_rules'):
                    parts.append(f"  Custom dedup rules: {len(tcr['dedup_rules'])} configured")
                    parts.append("    → If this alert matches one, recommend dismissal.")
                if tcr.get('pii_patterns'):
                    parts.append(f"  Custom PII patterns active: {len(tcr['pii_patterns'])}")

        return "\n".join(parts)


# ═══════════════════════════════════════════════════════════════════════════════
# FIELDS TO EXCLUDE - Prevent feedback loops and bloat
# ═══════════════════════════════════════════════════════════════════════════════

RIGGS_EXCLUDED_FIELDS = frozenset([
    # NEVER include prior Riggs output (prevents feedback loops)
    'riggs_analysis',
    'tier2_analysis',
    'riggs_extracted_iocs',
    'riggs_extracted_entities',
    'riggs_analyzed_at',
    'deep_analysis',

    # NEVER include investigation_data (contains riggs_analysis)
    'investigation_data',

    # NEVER include UI artifacts
    'widgets',
    'display_config',
    'ui_state',

    # NEVER include duplicate structures
    'merged_iocs',
    'all_indicators',
    'enrichment_data',  # Use enrichment_summary instead

    # NEVER include raw binary content
    'attachment_content',
    'binary_data',
    'raw_bytes',
    'email_body_html',

    # NEVER include full headers
    'email_headers',  # Use essential headers only

    # NEVER include execution metadata
    'execution_id',
    'job_id',
    'queue_metadata',
    'processing_timestamps',

    # NEVER include deprecated fields
    'tier1_findings',
    'tier1_analysis',
    'ai_triage_data',
])


def validate_no_riggs_recursion(data: Dict[str, Any]) -> None:
    """Raise error if riggs_analysis is in input. Non-negotiable guard."""
    data_str = json.dumps(data, default=str)
    forbidden = ['riggs_analysis', 'tier2_analysis', 'riggs_extracted']
    for term in forbidden:
        if term in data_str:
            raise ValueError(f"RIGGS INPUT CONTAMINATED: Found '{term}' in input data. This creates feedback loops.")


# ═══════════════════════════════════════════════════════════════════════════════
# FLAG-BASED PROMPT SELECTION
# ═══════════════════════════════════════════════════════════════════════════════

def select_riggs_prompt_flagged(
    alert_flags: List[str],
    t1_verdict: str,
    t1_confidence: int,
    t1_summary: str,
    alert_context: str
) -> Tuple[str, Dict[str, Any]]:
    """
    Select and format the appropriate Riggs prompt based on alert flags.

    Uses the alert flags computed during T1 triage to select a specialized
    investigation prompt (PHISHING, MALWARE, C2, CREDENTIAL_ACCESS, etc.).

    Args:
        alert_flags: List of flag strings from T1 classification
        t1_verdict: T1 triage verdict
        t1_confidence: T1 confidence (0-100)
        t1_summary: T1 summary text
        alert_context: Alert context string (IOCs, entities, raw event)

    Returns:
        Tuple of (formatted_prompt, prompt_metadata)
    """
    from services.alert_classifier import AlertClassifier, AlertFlag
    from agents.riggs_prompts import format_riggs_prompt

    # Convert string flags to AlertFlag set
    flags = AlertClassifier.list_to_flags(alert_flags)

    # Get primary flag for prompt selection
    primary_flag = AlertClassifier.get_primary_flag(flags)

    logger.info(f"[RIGGS_FLAG_PROMPT] Selected flag: {primary_flag.value}, all_flags: {[f.value for f in flags]}")

    # Format the specialized prompt (includes secondary flags in context)
    return format_riggs_prompt(
        flag=primary_flag,
        all_flags=flags,
        t1_verdict=t1_verdict,
        t1_confidence=t1_confidence,
        t1_summary=t1_summary,
        alert_context=alert_context
    )


def get_riggs_max_tokens() -> int:
    """Get max output tokens for Riggs analysis."""
    # GPT-5.x models need more tokens due to different tokenization
    ai_provider = os.getenv('AI_PROVIDER', '').lower()
    if ai_provider == 'openai':
        return 2000  # OpenAI models may need more output space
    return 600  # Local models: actual output is 250-500 tokens


# Alias for backward compatibility
get_riggs_max_tokens_flagged = get_riggs_max_tokens


# ═══════════════════════════════════════════════════════════════════════════════
# INPUT BUILDER - Constructs minimal Riggs input
# ═══════════════════════════════════════════════════════════════════════════════

def build_riggs_input(
    investigation: Dict[str, Any],
    alert: Dict[str, Any],
    t1_analysis: Dict[str, Any],
    mode: str,
    decoded_content: Optional[List[Dict]] = None,
    enrichment_summary: Optional[Dict[str, int]] = None,
    kb_recommendations: Optional[List[Dict]] = None,
    playbook_results_summary: Optional[str] = None,
    tenant_llm_context: Optional[Dict[str, Any]] = None,
    # Round B platform-awareness inputs. All optional — orchestrator
    # populates whichever it has cheap reads for; missing ones are fine.
    intake_context: Optional[Dict[str, Any]] = None,
    entity_risk_summary: Optional[Dict[str, Any]] = None,
    sla_context: Optional[Dict[str, Any]] = None,
    available_actions: Optional[List[Dict[str, Any]]] = None,
    tenant_custom_rules: Optional[Dict[str, Any]] = None,
) -> RiggsInput:
    """
    Build minimal, deduplicated input for Riggs.

    FAST mode: Minimal payload (~500-800 tokens)
    DEEP mode: Full payload (~1000-1500 tokens)
    """

    # Extract raw_event
    raw_event = alert.get('raw_event', {})
    if isinstance(raw_event, str):
        try:
            raw_event = json.loads(raw_event)
        except:
            raw_event = {}

    # Truncate raw_event based on mode. Pass the tenant exclude_field_keys
    # so per-tenant drops are honored alongside the platform defaults.
    extra_exclude = set()
    if tenant_llm_context:
        for k in (tenant_llm_context.get('exclude_field_keys') or []):
            extra_exclude.add((k or '').lower().replace('-', '_'))
    max_chars = 2000 if mode == "FAST" else 4000
    raw_event = _truncate_dict(raw_event, max_chars, extra_exclude=extra_exclude)

    # Normalize T1 confidence to 0-100 integer
    t1_conf = t1_analysis.get('confidence', 0)
    if isinstance(t1_conf, float) and t1_conf <= 1.0:
        t1_conf = int(t1_conf * 100)
    t1_conf = int(t1_conf)
    assert 0 <= t1_conf <= 100, f"Confidence must be 0-100, got {t1_conf}"

    # Build IOCs (deduplicated)
    iocs = _extract_iocs(alert, raw_event)

    # Build entities
    entities = _extract_entities(alert, raw_event)

    # For FAST mode, include only first decoded block (~200 tokens) to avoid
    # unnecessary FAST→DEEP escalations when payload validation is needed.
    # Previously excluded entirely, causing ~30% of FAST cases to escalate needlessly.
    if mode == "FAST" and decoded_content:
        # Keep just the first block, truncated to 300 chars
        first_block = decoded_content[0] if decoded_content else None
        if first_block and first_block.get('decoded'):
            decoded_content = [{
                'context': first_block.get('context', 'base64'),
                'decoded': str(first_block.get('decoded', ''))[:300]
            }]
        else:
            decoded_content = None
    elif mode == "FAST":
        decoded_content = None

    # Extract email authentication status from T1 analysis
    email_auth_status = t1_analysis.get('email_auth_status', {})
    sender_verified = t1_analysis.get('sender_legitimacy_verified', False)

    return RiggsInput(
        investigation_id=investigation.get('investigation_id', 'unknown'),
        alert_id=alert.get('alert_id', 'unknown'),
        t1_verdict=t1_analysis.get('verdict', 'unknown'),
        t1_confidence=t1_conf,
        t1_summary=str(t1_analysis.get('summary', ''))[:200],
        title=alert.get('title', 'Security Alert'),
        severity=alert.get('severity', 'medium'),
        source=alert.get('source', 'unknown'),
        timestamp=raw_event.get('timestamp', datetime.utcnow().isoformat()),
        raw_event=raw_event,
        iocs=iocs,
        entities=entities,
        decoded_content=decoded_content[:3] if decoded_content else None,
        enrichment_summary=enrichment_summary,
        email_auth_status=email_auth_status if email_auth_status else None,
        sender_legitimacy_verified=sender_verified,
        kb_recommendations=kb_recommendations,
        playbook_results_summary=playbook_results_summary,
        analysis_mode=mode,
        tenant_llm_context=tenant_llm_context,
        intake_context=intake_context,
        entity_risk_summary=entity_risk_summary,
        sla_context=sla_context,
        available_actions=available_actions,
        tenant_custom_rules=tenant_custom_rules,
    )


def _truncate_dict(d: Dict, max_chars: int, extra_exclude: Optional[set] = None) -> Dict:
    """Truncate dictionary to max characters when serialized."""
    result = {}
    current_size = 0
    extra_exclude = extra_exclude or set()

    for key, value in d.items():
        # Skip excluded fields (platform defaults + per-tenant exclude list)
        if key.lower() in RIGGS_EXCLUDED_FIELDS:
            continue
        if key.lower().replace('-', '_') in extra_exclude:
            continue

        # Skip binary-like fields
        if key.lower() in ('attachment_content', 'binary_data', 'raw_bytes'):
            continue

        value_str = json.dumps({key: value}, default=str)
        if current_size + len(value_str) > max_chars:
            # Truncate string values
            if isinstance(value, str) and len(value) > 200:
                value = value[:200] + '...[truncated]'
                value_str = json.dumps({key: value})
            if current_size + len(value_str) > max_chars:
                continue

        result[key] = value
        current_size += len(value_str)

    return result


def _extract_iocs(alert: Dict, raw_event: Dict) -> Dict[str, List[str]]:
    """Extract and deduplicate IOCs from alert data."""
    iocs = {
        'ips': [],
        'domains': [],
        'hashes': [],
        'urls': [],
        'emails': []
    }

    # From alert's extracted data
    alert_iocs = alert.get('iocs_extracted', {}) or alert.get('_extracted', {}).get('iocs', {})
    if alert_iocs:
        for ioc_type in iocs.keys():
            if ioc_type in alert_iocs:
                iocs[ioc_type].extend(alert_iocs[ioc_type])

    # From raw_event common fields
    for ip_field in ['source_ip', 'dest_ip', 'src_ip', 'dst_ip']:
        if ip_field in raw_event and raw_event[ip_field]:
            ip = raw_event[ip_field]
            if not ip.startswith(('10.', '192.168.', '172.')):  # Skip private IPs for IOC list
                iocs['ips'].append(ip)

    if 'file_hash' in raw_event:
        iocs['hashes'].append(raw_event['file_hash'])

    # Deduplicate
    for key in iocs:
        iocs[key] = list(set(iocs[key]))[:10]  # Max 10 per type

    return iocs


def _extract_entities(alert: Dict, raw_event: Dict) -> Dict[str, List[str]]:
    """Extract entities from alert data."""
    entities = {
        'users': [],
        'hosts': [],
        'processes': []
    }

    # Users
    for field in ['user', 'username', 'account_name']:
        if field in raw_event and raw_event[field]:
            entities['users'].append(str(raw_event[field]).lower())

    # Hosts
    for field in ['hostname', 'host', 'computer_name']:
        if field in raw_event and raw_event[field]:
            entities['hosts'].append(str(raw_event[field]).lower())

    # Processes
    for field in ['process', 'process_name', 'parent_process', 'image']:
        if field in raw_event and raw_event[field]:
            entities['processes'].append(str(raw_event[field]).lower())

    # Deduplicate
    for key in entities:
        entities[key] = list(set(entities[key]))[:10]

    return entities


# ═══════════════════════════════════════════════════════════════════════════════
# SINGLE-FLIGHT GUARD - Prevent duplicate Riggs runs
# ═══════════════════════════════════════════════════════════════════════════════

class RiggsFlightGuard:
    """
    Prevents duplicate Riggs analysis on the same investigation.

    Usage:
        guard = RiggsFlightGuard(postgres_db)
        async with guard.acquire(investigation_id) as acquired:
            if not acquired:
                return  # Already running or complete
            # Run Riggs analysis
    """

    def __init__(self, db):
        self.db = db

    async def is_running_or_complete(self, investigation_id: str) -> bool:
        """Check if Riggs is already running or complete for this investigation."""
        async with self.db.tenant_acquire() as conn:
            result = await conn.fetchrow("""
                SELECT
                    (investigation_data->>'riggs_analysis') IS NOT NULL as has_riggs,
                    EXISTS(
                        SELECT 1 FROM job_queue
                        WHERE payload->>'investigation_id' = $1
                        AND job_type = 'riggs_analysis'
                        AND status IN ('pending', 'processing')
                    ) as has_pending_job
                FROM investigations
                WHERE investigation_id = $1
            """, investigation_id)

            if result:
                return result['has_riggs'] or result['has_pending_job']
            return False

    async def mark_started(self, investigation_id: str) -> bool:
        """
        Atomically mark Riggs as started. Returns False if already running.
        Uses SELECT FOR UPDATE to prevent race conditions.
        """
        async with self.db.tenant_acquire() as conn:
            async with conn.transaction():
                # Lock the row
                inv = await conn.fetchrow("""
                    SELECT investigation_id, investigation_data
                    FROM investigations
                    WHERE investigation_id = $1
                    FOR UPDATE
                """, investigation_id)

                if not inv:
                    return False

                inv_data = inv['investigation_data'] or {}
                if isinstance(inv_data, str):
                    inv_data = json.loads(inv_data)

                # Check if already has Riggs analysis
                if inv_data.get('riggs_analysis'):
                    logger.info(f"[RIGGS_GUARD] {investigation_id} already has riggs_analysis, skipping")
                    return False

                # Check if Riggs is in progress (with 30-minute timeout for stuck jobs)
                if inv_data.get('riggs_status') == 'RUNNING':
                    started_at = inv_data.get('riggs_started_at')
                    if started_at:
                        try:
                            started_time = datetime.fromisoformat(started_at)
                            elapsed = (datetime.utcnow() - started_time).total_seconds()
                            if elapsed > 1800:  # 30 minutes
                                logger.warning(f"[RIGGS_GUARD] {investigation_id} stuck RUNNING for {elapsed/60:.0f}m, resetting for retry")
                                inv_data['riggs_status'] = 'TIMEOUT'
                                inv_data['riggs_timeout_at'] = datetime.utcnow().isoformat()
                                # Fall through to allow re-run
                            else:
                                logger.info(f"[RIGGS_GUARD] {investigation_id} riggs_status=RUNNING ({elapsed/60:.0f}m), skipping")
                                return False
                        except (ValueError, TypeError):
                            logger.info(f"[RIGGS_GUARD] {investigation_id} riggs_status=RUNNING, skipping")
                            return False
                    else:
                        logger.info(f"[RIGGS_GUARD] {investigation_id} riggs_status=RUNNING (no timestamp), skipping")
                        return False

                # Mark as running
                inv_data['riggs_status'] = 'RUNNING'
                inv_data['riggs_started_at'] = datetime.utcnow().isoformat()

                await conn.execute("""
                    UPDATE investigations
                    SET investigation_data = $2
                    WHERE investigation_id = $1
                """, investigation_id, json.dumps(inv_data))

                return True

    async def mark_complete(self, investigation_id: str, success: bool = True):
        """Mark Riggs as complete."""
        async with self.db.tenant_acquire() as conn:
            inv = await conn.fetchrow("""
                SELECT investigation_data FROM investigations WHERE investigation_id = $1
            """, investigation_id)

            if inv:
                inv_data = inv['investigation_data'] or {}
                if isinstance(inv_data, str):
                    inv_data = json.loads(inv_data)

                inv_data['riggs_status'] = 'COMPLETE' if success else 'FAILED'
                inv_data['riggs_completed_at'] = datetime.utcnow().isoformat()

                await conn.execute("""
                    UPDATE investigations
                    SET investigation_data = $2
                    WHERE investigation_id = $1
                """, investigation_id, json.dumps(inv_data))


# ═══════════════════════════════════════════════════════════════════════════════
# ML FEEDBACK HOOK - Learning from investigations
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class RiggsFeedback:
    """Feedback data for ML learning from Riggs investigations."""
    investigation_id: str
    alert_id: str
    t1_verdict: str
    t1_confidence: int
    riggs_verdict: str
    riggs_confidence: int
    riggs_mode: str  # FAST or DEEP
    human_verdict: Optional[str]  # Final human decision if available
    was_escalated: bool
    escalation_reason: Optional[str]
    processing_time_ms: int
    token_count: int
    timestamp: str

    # Feature vector for ML
    ioc_count: int
    entity_count: int
    has_encoded_content: bool
    severity: str
    source: str
    threat_type: str
    mitre_techniques: List[str]


async def record_riggs_feedback(
    db,
    investigation: Dict[str, Any],
    riggs_result: Dict[str, Any],
    mode: str,
    processing_time_ms: int,
    token_count: int
):
    """
    Record Riggs analysis outcome for ML feedback loop.

    This data is used to:
    1. Improve T1 accuracy (did T1 match Riggs?)
    2. Tune FAST/DEEP mode selection
    3. Train classification models
    4. Detect drift in alert patterns
    """
    try:
        feedback = RiggsFeedback(
            investigation_id=str(investigation.get('investigation_id', '')),
            alert_id=str(investigation.get('alert_id', '')),
            t1_verdict=str(investigation.get('t1_verdict', '')),
            t1_confidence=int(investigation.get('t1_confidence', 0)),
            riggs_verdict=str(riggs_result.get('verdict', '')),
            riggs_confidence=int(riggs_result.get('confidence', 0)),
            riggs_mode=str(mode),
            human_verdict=None,  # Filled in later when human reviews
            was_escalated=bool(riggs_result.get('escalate_to_deep', False)),
            escalation_reason=str(riggs_result.get('escalation_reason', '')) if riggs_result.get('escalation_reason') else None,
            processing_time_ms=int(processing_time_ms),
            token_count=int(token_count),
            timestamp=datetime.utcnow().isoformat(),
            ioc_count=sum(len(v) if isinstance(v, (list, dict)) else 1 for v in riggs_result.get('iocs', [])),
            entity_count=len(riggs_result.get('affected_entities', [])),
            has_encoded_content=len(riggs_result.get('decoded_artifacts', [])) > 0,
            severity=str(investigation.get('severity', 'medium')),
            source=str(investigation.get('source', 'unknown')),
            threat_type=str(riggs_result.get('threat_type', 'unknown')),
            mitre_techniques=[t.get('id', t) if isinstance(t, dict) else t for t in riggs_result.get('mitre', [])]
        )

        async with db.tenant_acquire() as conn:
            await conn.execute("""
                INSERT INTO riggs_feedback (
                    investigation_id, alert_id, t1_verdict, t1_confidence,
                    riggs_verdict, riggs_confidence, riggs_mode,
                    was_escalated, escalation_reason,
                    processing_time_ms, token_count,
                    ioc_count, entity_count, has_encoded_content,
                    severity, source, threat_type, mitre_techniques,
                    created_at, tenant_id
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, NOW(), $19)
                ON CONFLICT (investigation_id) DO UPDATE SET
                    riggs_verdict = EXCLUDED.riggs_verdict,
                    riggs_confidence = EXCLUDED.riggs_confidence,
                    processing_time_ms = EXCLUDED.processing_time_ms,
                    token_count = EXCLUDED.token_count,
                    updated_at = NOW()
            """,
                feedback.investigation_id,
                feedback.alert_id,
                feedback.t1_verdict,
                feedback.t1_confidence,
                feedback.riggs_verdict,
                feedback.riggs_confidence,
                feedback.riggs_mode,
                feedback.was_escalated,
                feedback.escalation_reason,
                feedback.processing_time_ms,
                feedback.token_count,
                feedback.ioc_count,
                feedback.entity_count,
                feedback.has_encoded_content,
                feedback.severity,
                feedback.source,
                feedback.threat_type,
                feedback.mitre_techniques,
                investigation.get('tenant_id')
            )

        logger.info(f"[RIGGS_FEEDBACK] Recorded: {feedback.investigation_id} "
                   f"mode={mode} verdict={feedback.riggs_verdict} "
                   f"t1_match={feedback.t1_verdict.lower() == feedback.riggs_verdict.lower()}")

    except Exception as e:
        # Non-fatal - don't break Riggs flow for feedback recording
        logger.warning(f"[RIGGS_FEEDBACK] Failed to record: {e}")


async def get_riggs_accuracy_stats(db, days: int = 7) -> Dict[str, Any]:
    """
    Get Riggs accuracy statistics for dashboard and tuning.

    Returns metrics like:
    - T1 vs Riggs agreement rate
    - FAST vs DEEP mode distribution
    - Average processing times by mode
    - Escalation rate from FAST to DEEP
    """
    async with db.tenant_acquire() as conn:
        stats = await conn.fetchrow("""
            SELECT
                COUNT(*) as total,
                COUNT(*) FILTER (WHERE riggs_mode = 'FAST') as fast_count,
                COUNT(*) FILTER (WHERE riggs_mode = 'DEEP') as deep_count,
                COUNT(*) FILTER (WHERE t1_verdict = riggs_verdict) as t1_match_count,
                COUNT(*) FILTER (WHERE was_escalated) as escalated_count,
                AVG(processing_time_ms) FILTER (WHERE riggs_mode = 'FAST') as avg_fast_ms,
                AVG(processing_time_ms) FILTER (WHERE riggs_mode = 'DEEP') as avg_deep_ms,
                AVG(token_count) FILTER (WHERE riggs_mode = 'FAST') as avg_fast_tokens,
                AVG(token_count) FILTER (WHERE riggs_mode = 'DEEP') as avg_deep_tokens
            FROM riggs_feedback
            WHERE created_at > NOW() - INTERVAL '%s days'
        """ % days)

        if stats and stats['total'] > 0:
            return {
                'total_analyses': stats['total'],
                'fast_mode_pct': round(100 * stats['fast_count'] / stats['total'], 1),
                'deep_mode_pct': round(100 * stats['deep_count'] / stats['total'], 1),
                't1_agreement_pct': round(100 * stats['t1_match_count'] / stats['total'], 1),
                'escalation_rate_pct': round(100 * stats['escalated_count'] / stats['total'], 1),
                'avg_fast_time_ms': round(stats['avg_fast_ms'] or 0),
                'avg_deep_time_ms': round(stats['avg_deep_ms'] or 0),
                'avg_fast_tokens': round(stats['avg_fast_tokens'] or 0),
                'avg_deep_tokens': round(stats['avg_deep_tokens'] or 0),
            }

        return {'total_analyses': 0, 'message': 'No data available'}
