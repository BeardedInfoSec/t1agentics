# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Riggs Playbook Builder Service

AI-powered playbook generation using Riggs's intelligence.
Allows Riggs to create, optimize, and modify playbooks based on:
- Alert patterns
- Investigation findings
- Security best practices
- Natural language requirements
"""

import json
import logging
import uuid
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


# ============================================================================
# Models
# ============================================================================


def _normalize_explicit_canvas(
    raw_nodes: List[Dict[str, Any]],
    raw_edges: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Take the LLM's nodes+edges as-is and shape them into the canvas
    schema React Flow + the engine expect. Preserves graph topology
    exactly (no auto-layout, no reconvergence).

    For each node:
      - id is required (kept from the LLM)
      - type is the legacy block type (riggs_analyze / enrich / condition /
        approval_gate / notify / action / utility / end / etc.)
      - position is kept if provided; otherwise auto-laid-out top-to-bottom
      - data.label / data.config / data.description normalized
      - data.kind mirrors data.type so the editor's lookup works either way

    For each edge:
      - id, source, target required (kept from the LLM)
      - sourceHandle preserved (yes/no for condition branches, etc.)
      - label preserved (so the canvas shows "Malicious" / "Benign" rather
        than the hardcoded fallback "Yes" / "No")
    """
    cleaned_nodes: List[Dict[str, Any]] = []
    auto_y = 80
    for n in raw_nodes:
        nid = n.get("id")
        ntype = n.get("type") or (n.get("data") or {}).get("type") or "action"
        if not nid:
            # Skip nodes without an id — they would break edge resolution.
            continue
        # Position fallback if the LLM didn't lay it out.
        pos = n.get("position") or {}
        if not isinstance(pos, dict) or "x" not in pos or "y" not in pos:
            pos = {"x": 520, "y": auto_y}
            auto_y += 180
        # Merge top-level + data-level config / label / description.
        node_data = n.get("data") or {}
        label = n.get("label") or node_data.get("label") or ntype
        description = n.get("description") or node_data.get("description") or ""
        config = n.get("config") or node_data.get("config") or {}
        cleaned_nodes.append({
            "id": nid,
            "type": ntype,
            "position": {"x": float(pos.get("x", 520)), "y": float(pos.get("y", auto_y))},
            "data": {
                "label": label,
                "description": description,
                "kind": ntype,
                "config": config,
            },
        })

    valid_ids = {n["id"] for n in cleaned_nodes}
    cleaned_edges: List[Dict[str, Any]] = []
    for e in raw_edges:
        if not isinstance(e, dict):
            continue
        src = e.get("source")
        tgt = e.get("target")
        if src not in valid_ids or tgt not in valid_ids:
            continue
        eid = e.get("id") or f"e_{src}_{tgt}_{uuid.uuid4().hex[:4]}"
        edge = {"id": eid, "source": src, "target": tgt}
        if e.get("sourceHandle"):
            edge["sourceHandle"] = e["sourceHandle"]
        if e.get("targetHandle"):
            edge["targetHandle"] = e["targetHandle"]
        if e.get("label"):
            edge["label"] = e["label"]
        cleaned_edges.append(edge)

    return {
        "nodes": cleaned_nodes,
        "edges": cleaned_edges,
        "viewport": {"x": 0, "y": 0, "zoom": 0.85},
    }


class PlaybookBuildRequest(BaseModel):
    """Request for Riggs to build a playbook."""
    name: Optional[str] = None
    description: Optional[str] = None
    requirements: str  # Natural language description of what playbook should do
    alert_type: Optional[str] = None
    severity: Optional[str] = None
    threat_type: Optional[str] = None
    sample_alert: Optional[Dict[str, Any]] = None
    include_enrichment: bool = True
    include_approval_gates: bool = True
    auto_execute_safe_actions: bool = False
    # Tenant context: which connectors are configured + which IOC types
    # the platform already auto-enriches. Lets Riggs build a playbook that
    # uses real available actions and skips redundant enrichment nodes.
    available_connectors: Optional[List[Dict[str, Any]]] = None
    auto_enriched_ioc_types: Optional[List[str]] = None
    # Relevant SOPs from the knowledge base — Riggs reads these and builds
    # a playbook that mirrors the team's documented response procedure.
    relevant_sops: Optional[List[Dict[str, Any]]] = None


class NodeTemplate(BaseModel):
    """Template for a playbook node."""
    type: str
    label: str
    config: Dict[str, Any] = Field(default_factory=dict)
    description: str = ""


class PlaybookBlueprint(BaseModel):
    """Blueprint for a playbook before finalization."""
    name: str
    description: str
    nodes: List[NodeTemplate] = Field(default_factory=list)
    flow_description: str
    estimated_complexity: str  # simple, moderate, complex
    suggested_tags: List[str] = Field(default_factory=list)
    suggested_alert_types: List[str] = Field(default_factory=list)
    # When the LLM returns explicit nodes-with-ids AND edges, we honor them
    # directly instead of letting _blueprint_to_canvas rebuild the graph
    # from node order (which loses topology — cross-branches, no labels, etc.)
    explicit_nodes: Optional[List[Dict[str, Any]]] = None
    explicit_edges: Optional[List[Dict[str, Any]]] = None


# ============================================================================
# Riggs Playbook Builder
# ============================================================================

class RiggsPlaybookBuilder:
    """
    AI-powered playbook builder using Riggs's intelligence.

    Capabilities:
    - Generate playbooks from natural language requirements
    - Analyze alert patterns and suggest playbooks
    - Optimize existing playbooks
    - Add best-practice nodes (error handling, approvals, etc.)
    """

    def __init__(self):
        from agents.riggs_playbook import get_riggs_playbook_agent
        self.playbook_agent = get_riggs_playbook_agent()

    # ========================================================================
    # AI-Powered Playbook Generation
    # ========================================================================

    async def generate_playbook_from_requirements(
        self,
        request: PlaybookBuildRequest,
        tenant_id=None
    ) -> Dict[str, Any]:
        """
        Generate a complete playbook from natural language requirements.

        Uses LLM to understand requirements and create appropriate workflow.

        Args:
            request: Playbook build request with requirements.
            tenant_id: Tenant UUID for Claude quota enforcement and billing.
        """
        try:
            # Step 1: Analyze requirements with LLM
            blueprint, generation_source, generation_reason = await self._analyze_requirements_with_llm(request, tenant_id=tenant_id)

            # Step 2: Build node graph.
            #
            # Fast path: when the LLM returned explicit nodes-with-ids AND
            # edges, honor them as-is. The legacy auto-layout converts a flat
            # node list into a graph by guessing — for condition nodes it
            # forces left/right branches AND reconverges them at the next
            # non-condition node, which breaks topology (the "end_malicious
            # -> notify_benign" cross-edge bug). When Riggs writes the edges
            # himself, ship them.
            if blueprint.explicit_nodes and blueprint.explicit_edges:
                canvas_data = _normalize_explicit_canvas(
                    blueprint.explicit_nodes,
                    blueprint.explicit_edges,
                )
            else:
                canvas_data = await self._blueprint_to_canvas(blueprint, request)

                # Best-practice enhancers only run on the legacy auto-layout
                # path; with explicit edges, the LLM is authoritative.
                if request.include_enrichment:
                    canvas_data = self._add_enrichment_nodes(canvas_data, request)

                if request.include_approval_gates:
                    canvas_data = self._add_approval_gates(canvas_data)

            # Step 4: Validate and optimize
            canvas_data = self._optimize_flow(canvas_data)

            # Step 5: Generate metadata
            playbook_data = {
                "name": blueprint.name or request.name or "AI-Generated Playbook",
                "description": blueprint.description,
                "canvas_data": canvas_data,
                "tags": blueprint.suggested_tags,
                "alert_types": blueprint.suggested_alert_types,
                "riggs_generated": True,
                "riggs_confidence": 0.85,  # High confidence in AI generation
                "generation_requirements": request.requirements,
                "estimated_complexity": blueprint.estimated_complexity,
                "generation_source": generation_source,
                "generation_reason": generation_reason
            }

            return playbook_data

        except Exception as e:
            logger.error(f"Failed to generate playbook: {e}")
            raise

    async def _analyze_requirements_with_llm(
        self,
        request: PlaybookBuildRequest,
        tenant_id=None
    ) -> Tuple[PlaybookBlueprint, str, Optional[str]]:
        """
        Use LLM to analyze requirements and create playbook blueprint.
        Falls back to template-based generation if LLM is unavailable.
        """
        import os

        # Try to use AI triage service for LLM calls
        try:
            from services.ai_triage_service import AITriageService
            triage_service = AITriageService()

            # Build prompt for LLM
            prompt = self._build_generation_prompt(request)

            system_prompt = """You are Riggs, the SOC playbook designer inside T1 Agentics. You produce playbooks that run on the T1 visual playbook engine.

# IMPORTANT: when this playbook runs, the alert has ALREADY been processed
By the time a post-triage playbook fires, the platform has already done two things automatically:
  1. Run Riggs AI triage on the alert
  2. Auto-enriched any IOCs the alert carried

The results are sitting on the alert itself. Reference them directly — do NOT regenerate them by adding `riggs_analyze` or `enrich` nodes.

Available alert fields (use these directly in `condition.expression` AND in template strings):
  - alert.ai_verdict          → "MALICIOUS" | "SUSPICIOUS" | "BENIGN"
  - alert.ai_confidence       → 0-100
  - alert.ai_summary          → Riggs's written analysis
  - alert.disposition         → "true_positive" | "false_positive" | "benign" | null
  - alert.severity            → "critical" | "high" | "medium" | "low"
  - alert.category, alert.subcategory
  - alert.enrichment_summary  → aggregated IOC enrichment results (JSON)
  - alert.iocs, alert.extracted_entities
  - alert.title, alert.description, alert.raw_event.<field>

# Path syntax depends on WHERE you use it
Two dialects exist:

1. In a `condition.expression` (the engine parses this as code):
       $.trigger.alert.ai_verdict == "MALICIOUS"
   Use the `$.trigger.alert.<field>` prefix and JSON literals (double-quoted strings, bare numbers).

2. In any free-text message (notify.message, case_update.resolution, etc.) the engine does template substitution with `{$.trigger.alert.<field>}` braces:
       "Malicious phishing confirmed: {$.trigger.alert.ai_summary}"
   IMPORTANT: notification template syntax is `{$.path}` -- single curly braces with a JSONPath inside -- NOT Jinja `{{...}}`.

# Block types — use these EXACT type values (matched to engine handlers + UI forms)
trigger, condition, approval_gate, notify, action, create_ticket, utility, python_code, transform, delay, end

For closing/updating the T1 investigation, use `utility` with `operation: "case_update"` — NOT a bare `case_update` type, which gets corrupted by the canvas editor round-trip.

(`riggs_analyze` and `enrich` are valid block types but you should rarely emit them — only in `pre_triage` playbooks where you genuinely need to re-analyze or pull extra enrichment that the platform didn't already run.)

Each block has a SPECIFIC config schema (below); use the field names exactly as listed or the form will silently fall back to defaults.

# Block schemas — match these field names EXACTLY

- `trigger` : entry point. Exactly one.
    config: { "trigger_type": "alert" }

- `condition` : two-branch decision.
    config: { "expression": "{{analyze_main.verdict}} == 'MALICIOUS'",
              "default_branch": "no",
              "branches": [{"id":"yes","label":"Malicious"},
                           {"id":"no","label":"Benign/Suspicious"}] }

- `approval_gate` : human approval gate. ALWAYS gate destructive actions.
    config: { "message": "Approve blocking <X>?",
              "timeout_minutes": 30 }

- `notify` : Slack/Teams/email/webhook notification. DEDICATED block — do NOT use `action` for notifications.
    config: { "channel": "slack" | "teams" | "email" | "webhook",
              "slack_channel": "#soc-alerts",   // for channel=slack
              "email_recipients": "soc@...",    // for channel=email
              "webhook_url": "https://...",     // for channel=webhook
              "message": "...{{alert.title}}...",
              "priority": "low" | "medium" | "high" }

- `action` : execute a connector action (block, isolate, contain, screenshot, lookup). REQUIRES a configured connector.
    config: { "integration_instance_id": "<exact connector name from AVAILABLE CONNECTORS>",
              "endpoint_id": "<action id from that connector's listed actions>",
              "params": { ... action-specific params ... },
              "requires_approval": false }
    If NO connector matches the needed capability, emit a `notify` with manual-step instructions instead — do not invent a fake action.

- `create_ticket` : external ticketing (Jira, ServiceNow).
    config: { "system": "jira" | "servicenow",
              "summary": "...", "severity": "..." }
    PREFER `case_update` over `create_ticket` when no ticketing connector exists.

- `utility` (with operation="case_update") : update / close the T1 investigation. NO external system needed.
    config: { "operation": "case_update",
              "status": "resolved" | "closed" | "in_progress",
              "severity": "low" | "medium" | "high" | "critical",
              "resolution": "<one-line summary>",
              "disposition": "true_positive" | "false_positive" | "benign" | null }
    The engine's case_update handler updates the investigation row directly.
    Always include `disposition` and a one-line `resolution`.

- `python_code` : custom Python when nothing else fits. Use sparingly.
    config: { "function_name": "main",
              "code": "<python>",
              "inputs": { "var": "{{path}}" } }

- `transform` : reshape data between steps.
    config: { "input_path": "{{...}}",
              "transform_type": "extract" | "format",
              "transform_config": {} }

- `delay` : pause.
    config: { "duration_seconds": 60 }

- `end` : terminal. EVERY branch terminates in exactly one `end`.
    config: { "disposition": "true_positive" | "false_positive" | "benign" | null }

# Data path syntax
Reference upstream data with Jinja braces `{{...}}`:
- `{{alert.<field>}}`              — triggering alert (e.g. `{{alert.title}}`, `{{alert.iocs.urls}}`, `{{alert.raw_event.sender}}`)
- `{{case.<field>}}`               — parent investigation (`{{case.id}}`, `{{case.title}}`)
- `{{<node_id_or_label>.<field>}}` — previous node output (e.g. `{{analyze_main.verdict}}`, `{{enrich_urls.malicious_count}}`)

# Hard rules
1. Do NOT add `riggs_analyze` or `enrich` nodes. Riggs's verdict is at {{alert.ai_verdict}} / {{alert.ai_confidence}} / {{alert.ai_summary}} and enrichment is at {{alert.enrichment_summary}}. Reference these directly in `condition` expressions and `notify` messages.
2. The FIRST decision node should branch on the existing verdict, e.g. `condition.expression = "{{alert.ai_verdict}} == 'MALICIOUS'"`.
3. For `action`: use `integration_instance_id` (exact connector name like "Cisco Meraki") and `endpoint_id` (exact action id from the connector). If no connector matches the needed capability, emit a `notify` block with manual-step instructions — do NOT generate an `action` with empty integration fields.
4. Use `notify` for notifications. Do NOT use `action` with response_type=notify.
5. Wrap every destructive `action` (block, isolate, disable, delete, contain, quarantine) in an `approval_gate` first. Read-only actions do NOT need approval.
6. For closing the investigation, use `utility` with `operation: "case_update"` — NOT a bare `case_update` type.

# TOPOLOGY RULES — graph correctness (the #1 thing analysts catch when reviewing your output)
7. Every branch out of a `condition` is INDEPENDENT. The "yes" branch and the "no" branch never share nodes and never converge. Each branch has its own approval/notify/utility/end chain.
8. Each branch terminates in its OWN dedicated `end` node. An `end` node has NO outgoing edges. NEVER emit an edge whose `source` is an `end` node.
9. Wire the edges out of a `condition` with `sourceHandle` set to the matching branch id ("yes" or "no"). Set `label` on each such edge to the human-readable branch label (e.g. "Malicious", "Benign"). The condition's `config.branches` array's `label` field MUST match the corresponding edge `label`.

# Edge structure for a binary condition node
For a `condition` node with branches=[{"id":"yes","label":"Malicious"},{"id":"no","label":"Benign"}], the edges leaving it look like:
    {"id":"e_cond_<yes_target>","source":"<condition_id>","target":"<yes_branch_first_node>","sourceHandle":"yes","label":"Malicious"}
    {"id":"e_cond_<no_target>", "source":"<condition_id>","target":"<no_branch_first_node>", "sourceHandle":"no", "label":"Benign"}

# Layout
10. Trunk at x=520. Yes-branch at x=260 (or x=520 if no other branch). No-branch at x=780. y increments of 180.
11. Yes-branch and no-branch run as PARALLEL vertical chains. They visually diverge from the condition and never reconverge.

# Misc
12. NEVER reference an LLM vendor (Claude, Anthropic, OpenAI, GPT, etc.) anywhere in node labels, configs, or messages. The AI is "Riggs".
13. Keep configs minimal — only fields the block actually needs.

Quality bar: a senior SOC analyst should immediately see what this playbook DOES given that the verdict and enrichment are already done. Aim for 5-8 nodes total. If you find yourself writing more than 8, you're probably regenerating work the platform already did."""

            # Use the triage service's LLM calling mechanism
            combined_prompt = f"{system_prompt}\n\n{prompt}"
            llm_output = await triage_service._call_llm_for_triage(
                combined_prompt,
                purpose="riggs_playbook_builder",
                max_tokens=4096,
                tenant_id=tenant_id
            )

            if llm_output:
                blueprint = self._parse_llm_blueprint(llm_output)
                return blueprint, "llm", None
            return self._fallback_blueprint(request), "template", "llm_no_response"

        except ImportError:
            logger.warning("AITriageService not available, using template-based generation")
            return self._fallback_blueprint(request), "template", "aitriage_import_missing"
        except Exception as e:
            logger.error(f"LLM generation failed: {e}")
            return self._fallback_blueprint(request), "template", f"llm_error: {str(e)}"

        # Fallback to template-based generation
        return self._fallback_blueprint(request), "template", "llm_unavailable"

    def _build_generation_prompt(self, request: PlaybookBuildRequest) -> str:
        """Build prompt for LLM playbook generation.

        Structure:
          1. The user's requirements brief
          2. The actual alert payload (so the LLM can reason about real data)
          3. Available connectors with REAL action IDs and observable types
          4. Auto-enrichment context (which IOC types are pre-enriched)
          5. Output schema (compact)
        """
        parts: List[str] = []

        # 1. Requirements
        parts.append(f"# Task\n{request.requirements}")
        meta_bits = []
        if request.alert_type:
            meta_bits.append(f"alert_type={request.alert_type}")
        if request.threat_type:
            meta_bits.append(f"threat_type={request.threat_type}")
        if request.severity:
            meta_bits.append(f"severity={request.severity}")
        if meta_bits:
            parts.append("Context: " + ", ".join(meta_bits))

        # 2. Alert payload (the actual triggering event)
        if request.sample_alert:
            try:
                payload_json = json.dumps(request.sample_alert, indent=2, default=str)
                # Truncate hard — large alerts blow the prompt budget.
                if len(payload_json) > 2500:
                    payload_json = payload_json[:2500] + "\n  ...[truncated]"
                parts.append(
                    "# Triggering alert (use this to pick targeted actions and "
                    "data paths like {{alert.<field>}})\n```json\n" + payload_json + "\n```"
                )
            except Exception:
                pass

        # 3. Available connectors with real action IDs
        connectors = request.available_connectors or []
        if connectors:
            lines = ["# Available connectors in this tenant"]
            lines.append(
                "Use these EXACT names in `vendor` fields and these action `id` "
                "values in `action_id` fields. Do not invent vendors or actions."
            )
            for c in connectors[:30]:
                name = c.get("connector_name") or c.get("vendor") or "unknown"
                category = c.get("category") or "uncategorized"
                actions = c.get("actions") or c.get("supported_actions") or []
                if not isinstance(actions, list):
                    actions = []
                action_descs = []
                for a in actions[:10]:
                    if isinstance(a, dict):
                        aid = a.get("id") or a.get("action_id") or a.get("name")
                        if not aid:
                            continue
                        otype = a.get("observable_type") or ""
                        atype = a.get("action_type") or ""
                        tag = f" [{otype}]" if otype else (f" [{atype}]" if atype else "")
                        action_descs.append(f"{aid}{tag}")
                    elif isinstance(a, str):
                        action_descs.append(a)
                actions_str = ", ".join(action_descs) if action_descs else "(no actions listed)"
                lines.append(f"- **{name}** ({category}): {actions_str}")
            if len(connectors) > 30:
                lines.append(f"  ... and {len(connectors) - 30} more")
            parts.append("\n".join(lines))
        else:
            parts.append(
                "# Available connectors\nNone configured. Use `notify` + `case_update` "
                "blocks for analyst signaling; leave connector-specific `action` blocks "
                "out entirely."
            )

        # 4. Auto-enrichment hint
        auto_types = request.auto_enriched_ioc_types
        if auto_types:
            parts.append(
                "# Pre-enriched IOC types\n"
                f"The platform already enriched: {', '.join(auto_types)}. "
                "Do NOT add `enrich` nodes for these — enrichment results are "
                "already on the alert. Only add `enrich` for IOC types NOT in "
                "this list."
            )

        # 4b. Relevant SOPs — the team's documented response procedure.
        # Mirror these steps in the playbook so analysts get the response
        # they already know how to do, codified into automation.
        sops = request.relevant_sops or []
        if sops:
            lines = [
                "# Relevant SOPs (Standard Operating Procedures)",
                "These are the team's documented procedures for this kind of alert. "
                "Mirror their decision points and response steps in the playbook so "
                "the automation matches institutional knowledge. If an SOP step has "
                "no matching connector action, emit a `notify` block describing the "
                "manual step instead.",
            ]
            for i, sop in enumerate(sops[:3], start=1):
                title = sop.get("title", "Untitled SOP")
                category = sop.get("category") or ""
                score = sop.get("relevance_score", 0)
                summary = (sop.get("summary") or "")[:600]
                key_steps = sop.get("key_steps") or []
                lines.append(f"\n## SOP {i}: {title}  (category={category}, relevance={score:.2f})")
                if summary:
                    lines.append(f"Summary: {summary}")
                if key_steps:
                    lines.append("Key steps:")
                    for step in key_steps[:8]:
                        step_text = step if isinstance(step, str) else str(step)
                        # Trim per-step to keep the prompt bounded
                        lines.append(f"  - {step_text[:280]}")
            parts.append("\n".join(lines))

        # 5. Output schema (compact). Both `nodes` and `edges` are required.
        #    The two branches out of the condition NEVER share nodes and
        #    NEVER reconverge — each ends in its own `end` node.
        parts.append("""# Output
Respond with ONE valid JSON object, no markdown fences, no commentary:
{
  "name": "<60 chars>",
  "description": "one-sentence summary",
  "flow_description": "trigger -> condition -> {malicious branch} | {benign branch}",
  "estimated_complexity": "simple|moderate|complex",
  "suggested_tags": ["..."],
  "suggested_alert_types": ["..."],
  "nodes": [
    {"id":"trigger_001","type":"trigger","position":{"x":520,"y":80},"data":{"label":"Alert Received","config":{"trigger_type":"alert"}}},
    {"id":"cond_001","type":"condition","position":{"x":520,"y":260},"data":{"label":"Riggs Verdict?","config":{"expression":"$.trigger.alert.ai_verdict == \"MALICIOUS\"","default_branch":"no","branches":[{"id":"yes","label":"Malicious"},{"id":"no","label":"Benign"}]}}},

    {"id":"approval_001","type":"approval_gate","position":{"x":260,"y":440},"data":{"label":"Approve Block Sender","config":{"message":"Riggs flagged {$.trigger.alert.title} as MALICIOUS ({$.trigger.alert.ai_confidence}%). Approve blocking sender?","timeout_minutes":30}}},
    {"id":"notify_mal","type":"notify","position":{"x":260,"y":620},"data":{"label":"Notify SOC - Malicious","config":{"channel":"slack","slack_channel":"#soc-alerts","message":"MALICIOUS phishing confirmed. {$.trigger.alert.ai_summary}","priority":"high"}}},
    {"id":"util_close_tp","type":"utility","position":{"x":260,"y":800},"data":{"label":"Close as TP","config":{"operation":"case_update","status":"resolved","disposition":"true_positive","resolution":"Contained per playbook."}}},
    {"id":"end_mal","type":"end","position":{"x":260,"y":980},"data":{"label":"Done - Malicious","config":{"disposition":"true_positive"}}},

    {"id":"notify_ben","type":"notify","position":{"x":780,"y":440},"data":{"label":"Notify SOC - Benign","config":{"channel":"slack","slack_channel":"#soc-alerts","message":"Riggs verdict: BENIGN. No action needed.","priority":"low"}}},
    {"id":"util_close_fp","type":"utility","position":{"x":780,"y":620},"data":{"label":"Close as FP","config":{"operation":"case_update","status":"closed","disposition":"false_positive","resolution":"Riggs verdict: {$.trigger.alert.ai_verdict} ({$.trigger.alert.ai_confidence}%)."}}},
    {"id":"end_ben","type":"end","position":{"x":780,"y":800},"data":{"label":"Done - Benign","config":{"disposition":"false_positive"}}}
  ],
  "edges": [
    {"id":"e_trig_cond","source":"trigger_001","target":"cond_001"},
    {"id":"e_cond_mal","source":"cond_001","target":"approval_001","sourceHandle":"yes","label":"Malicious"},
    {"id":"e_appr_notmal","source":"approval_001","target":"notify_mal"},
    {"id":"e_notmal_util","source":"notify_mal","target":"util_close_tp"},
    {"id":"e_util_end_mal","source":"util_close_tp","target":"end_mal"},
    {"id":"e_cond_ben","source":"cond_001","target":"notify_ben","sourceHandle":"no","label":"Benign"},
    {"id":"e_notben_util","source":"notify_ben","target":"util_close_fp"},
    {"id":"e_util_end_ben","source":"util_close_fp","target":"end_ben"}
  ]
}

Notice: zero edges touch any `end` node as a source. The malicious chain (approval → notify → utility → end_mal) and the benign chain (notify → utility → end_ben) are completely separate after the condition.""")

        return "\n\n".join(parts)

    def _repair_truncated_json(self, json_str: str) -> str:
        """Attempt to repair truncated JSON by closing open brackets/braces."""
        # Track nesting
        stack = []
        in_string = False
        escape_next = False

        for ch in json_str:
            if escape_next:
                escape_next = False
                continue
            if ch == '\\' and in_string:
                escape_next = True
                continue
            if ch == '"' and not escape_next:
                in_string = not in_string
                continue
            if in_string:
                continue
            if ch in ('{', '['):
                stack.append(ch)
            elif ch == '}' and stack and stack[-1] == '{':
                stack.pop()
            elif ch == ']' and stack and stack[-1] == '[':
                stack.pop()

        # If still unclosed, try to close them
        if not stack:
            return json_str

        # Truncate any trailing incomplete string/value
        # Find last complete key-value pair by stripping back to last } or ]
        repaired = json_str.rstrip()
        # Remove trailing partial values (incomplete strings, trailing commas)
        while repaired and repaired[-1] not in ('}', ']', '"', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'e', 'l', 'n'):
            repaired = repaired[:-1]
        # Remove trailing comma if present
        repaired = repaired.rstrip(',')

        # Close any open brackets
        for opener in reversed(stack):
            if opener == '{':
                repaired += '}'
            elif opener == '[':
                repaired += ']'

        return repaired

    def _parse_llm_blueprint(self, llm_output: str) -> PlaybookBlueprint:
        """Parse LLM output into PlaybookBlueprint."""
        try:
            # Extract JSON from markdown if present
            if "```json" in llm_output:
                json_start = llm_output.find("```json") + 7
                json_end = llm_output.find("```", json_start)
                if json_end == -1:
                    json_str = llm_output[json_start:].strip()
                else:
                    json_str = llm_output[json_start:json_end].strip()
            elif "```" in llm_output:
                json_start = llm_output.find("```") + 3
                json_end = llm_output.find("```", json_start)
                if json_end == -1:
                    json_str = llm_output[json_start:].strip()
                else:
                    json_str = llm_output[json_start:json_end].strip()
            else:
                json_str = llm_output.strip()

            # Try parsing directly first
            try:
                data = json.loads(json_str)
            except json.JSONDecodeError:
                # Attempt to repair truncated JSON
                logger.info("Attempting JSON repair on truncated LLM output")
                repaired = self._repair_truncated_json(json_str)
                data = json.loads(repaired)

            raw_nodes = data.get('nodes', []) or []
            raw_edges = data.get('edges', []) or []

            # Convert to NodeTemplate list (for legacy fallback path that
            # still wants the simple list, e.g. _add_enrichment_nodes hooks).
            nodes = [
                NodeTemplate(
                    type=n.get('type', 'unknown'),
                    label=n.get('label') or (n.get('data') or {}).get('label', ''),
                    config=n.get('config') or (n.get('data') or {}).get('config', {}),
                    description=n.get('description') or (n.get('data') or {}).get('description', ''),
                )
                for n in raw_nodes
            ]

            # If the LLM provided node ids AND any edges, capture the
            # explicit graph so build_from_alert / generate_playbook can
            # bypass the legacy auto-layout and ship the topology as-is.
            explicit_nodes = None
            explicit_edges = None
            if raw_edges and any(n.get('id') for n in raw_nodes):
                explicit_nodes = raw_nodes
                explicit_edges = raw_edges

            return PlaybookBlueprint(
                name=data.get('name', 'Generated Playbook'),
                description=data.get('description', ''),
                nodes=nodes,
                flow_description=data.get('flow_description', ''),
                estimated_complexity=data.get('estimated_complexity', 'moderate'),
                suggested_tags=data.get('suggested_tags', []),
                suggested_alert_types=data.get('suggested_alert_types', []),
                explicit_nodes=explicit_nodes,
                explicit_edges=explicit_edges,
            )

        except Exception as e:
            logger.error(f"Failed to parse LLM blueprint: {e}")
            raise ValueError(f"Could not parse LLM output: {e}")

    def _fallback_blueprint(self, request: PlaybookBuildRequest) -> PlaybookBlueprint:
        """Fallback template-based blueprint if LLM fails. Uses requirements to infer playbook shape."""

        alert_type = request.alert_type or "generic"
        req_lower = request.requirements.lower()

        # Infer a name from the requirements
        name = request.name
        if not name:
            # Extract meaningful name from the first sentence
            first_line = request.requirements.split('.')[0].split('\n')[0][:60]
            if first_line.lower().startswith(("create ", "build ", "design ", "make ")):
                name = first_line.split(' ', 1)[1].strip().title()
            else:
                name = first_line.strip().title()
            if not name:
                name = f"{alert_type.title()} Response"

        # Infer threat type from requirements
        threat_keywords = {
            "phishing": ["phishing", "phish", "email", "sender", "spoof"],
            "malware": ["malware", "virus", "trojan", "hash", "sandbox"],
            "network": ["network", "lateral", "c2", "beacon", "dns"],
            "credential": ["credential", "password", "brute", "login"],
            "ransomware": ["ransomware", "ransom", "encrypt"],
        }
        inferred_type = alert_type
        inferred_tags = ["automated"]
        for ttype, keywords in threat_keywords.items():
            if any(kw in req_lower for kw in keywords):
                inferred_type = ttype
                inferred_tags.insert(0, ttype)
                break

        # Build nodes based on requirements keywords
        nodes = [
            NodeTemplate(
                type="trigger",
                label="Alert Trigger",
                config={"trigger_type": "alert", "alert_types": [inferred_type]},
                description=f"Triggered by {inferred_type} alerts"
            ),
            NodeTemplate(
                type="riggs_analyze",
                label="Riggs AI Analysis",
                config={},
                description="AI-powered investigation and threat assessment"
            ),
        ]

        # Add enrichment node if user mentions enrichment-related terms
        if any(kw in req_lower for kw in ["enrich", "virustotal", "ioc", "indicator", "lookup", "url", "domain", "hash", "ip"]):
            nodes.append(NodeTemplate(
                type="enrich",
                label="Enrich IOCs",
                config={"integrations": ["virustotal"], "observable_types": ["ip", "domain", "hash", "url"]},
                description="Enrich indicators with threat intelligence"
            ))

        # Add condition node
        nodes.append(NodeTemplate(
            type="condition",
            label="Check Verdict",
            config={"field": "$.nodes.riggs_analyze.verdict", "operator": "equals", "value": "MALICIOUS"},
            description="Branch based on threat assessment"
        ))

        # Add action nodes based on requirements
        if any(kw in req_lower for kw in ["block", "isolate", "contain", "quarantine", "disable"]):
            action_word = next(kw for kw in ["block", "isolate", "contain", "quarantine", "disable"] if kw in req_lower)
            nodes.append(NodeTemplate(
                type="action",
                label=f"{action_word.title()} Threat",
                config={"action_type": action_word},
                description=f"Execute {action_word} action on threat"
            ))

        # Add ticket creation if mentioned
        if any(kw in req_lower for kw in ["ticket", "jira", "servicenow", "case"]):
            nodes.append(NodeTemplate(
                type="create_ticket",
                label="Create Ticket",
                config={"system": "jira"},
                description="Create investigation ticket"
            ))

        # Add notification
        nodes.append(NodeTemplate(
            type="notify",
            label="Notify SOC Team",
            config={"channel": "slack", "message": "Security alert requires attention"},
            description="Alert SOC team about findings"
        ))

        nodes.append(NodeTemplate(
            type="end",
            label="Complete",
            config={"disposition": "investigated"},
            description="Playbook complete"
        ))

        return PlaybookBlueprint(
            name=name,
            description=f"Automated playbook: {request.requirements[:120]}",
            nodes=nodes,
            flow_description=" → ".join(n.label for n in nodes),
            estimated_complexity="moderate" if len(nodes) > 5 else "simple",
            suggested_tags=inferred_tags,
            suggested_alert_types=[inferred_type]
        )

    # ========================================================================
    # Canvas Generation
    # ========================================================================

    async def _blueprint_to_canvas(
        self,
        blueprint: PlaybookBlueprint,
        request: PlaybookBuildRequest
    ) -> Dict[str, Any]:
        """Convert blueprint to React Flow canvas data with smart layout.

        Layout strategy:
        - Center column at x=520 (matches editor baseX)
        - Vertical gap of 180px between rows
        - Condition nodes branch into left/right columns
        - Converge back to center after branches
        """

        nodes = []
        edges = []
        center_x = 520
        branch_offset = 260  # horizontal distance from center for branches
        y_gap = 180
        y_position = 80  # start with some top padding

        prev_node_id = None
        in_branch = False
        branch_left_id = None
        branch_right_id = None
        skip_indices = set()  # indices already placed as branch children

        for i, node_template in enumerate(blueprint.nodes):
            if i in skip_indices:
                continue

            node_id = f"{node_template.type}_{uuid.uuid4().hex[:6]}"

            # Condition node: branch the next two nodes left/right
            if node_template.type == "condition" and i + 2 < len(blueprint.nodes):
                # Pull business-meaningful branch labels from config if the
                # LLM provided them (per prompt instructions). Stable ids
                # are always "yes"/"no" so edge sourceHandles line up with
                # the editor's Branches panel.
                cfg_branches = (node_template.config or {}).get("branches") or []
                yes_label = "Yes"
                no_label = "No"
                for br in cfg_branches:
                    if not isinstance(br, dict):
                        continue
                    bid = (br.get("id") or "").lower()
                    if bid == "yes" and br.get("label"):
                        yes_label = br["label"]
                    elif bid == "no" and br.get("label"):
                        no_label = br["label"]

                # Ensure the saved config has a normalized branches array
                # so the editor opens with the labels populated even on
                # first load.
                normalized_config = dict(node_template.config or {})
                normalized_config["branches"] = [
                    {"id": "yes", "label": yes_label},
                    {"id": "no",  "label": no_label},
                ]

                # Place condition at center
                nodes.append({
                    "id": node_id,
                    "type": node_template.type,
                    "position": {"x": center_x, "y": y_position},
                    "data": {
                        "label": node_template.label,
                        "config": normalized_config,
                        "description": node_template.description
                    }
                })

                if prev_node_id:
                    edges.append({
                        "id": f"e_{prev_node_id}_{node_id}",
                        "source": prev_node_id,
                        "target": node_id,
                    })

                y_position += y_gap

                # Left branch (Yes path) -- uses LLM-provided label
                left_template = blueprint.nodes[i + 1]
                left_id = f"{left_template.type}_{uuid.uuid4().hex[:6]}"
                nodes.append({
                    "id": left_id,
                    "type": left_template.type,
                    "position": {"x": center_x - branch_offset, "y": y_position},
                    "data": {
                        "label": left_template.label,
                        "config": left_template.config,
                        "description": left_template.description
                    }
                })
                edges.append({
                    "id": f"e_{node_id}_{left_id}",
                    "source": node_id,
                    "target": left_id,
                    "sourceHandle": "yes",
                    "label": yes_label,
                })

                # Right branch (No path) -- uses LLM-provided label
                right_template = blueprint.nodes[i + 2]
                right_id = f"{right_template.type}_{uuid.uuid4().hex[:6]}"
                nodes.append({
                    "id": right_id,
                    "type": right_template.type,
                    "position": {"x": center_x + branch_offset, "y": y_position},
                    "data": {
                        "label": right_template.label,
                        "config": right_template.config,
                        "description": right_template.description
                    }
                })
                edges.append({
                    "id": f"e_{node_id}_{right_id}",
                    "source": node_id,
                    "target": right_id,
                    "sourceHandle": "no",
                    "label": no_label,
                })

                skip_indices.add(i + 1)
                skip_indices.add(i + 2)
                in_branch = True
                branch_left_id = left_id
                branch_right_id = right_id
                prev_node_id = node_id
                y_position += y_gap
                continue

            # Regular node — place at center
            nodes.append({
                "id": node_id,
                "type": node_template.type,
                "position": {"x": center_x, "y": y_position},
                "data": {
                    "label": node_template.label,
                    "config": node_template.config,
                    "description": node_template.description
                }
            })

            # Connect edges
            if in_branch and branch_left_id and branch_right_id:
                # Converge both branches into this node
                edges.append({
                    "id": f"e_{branch_left_id}_{node_id}",
                    "source": branch_left_id,
                    "target": node_id,
                })
                edges.append({
                    "id": f"e_{branch_right_id}_{node_id}",
                    "source": branch_right_id,
                    "target": node_id,
                })
                in_branch = False
                branch_left_id = None
                branch_right_id = None
            elif prev_node_id:
                edges.append({
                    "id": f"e_{prev_node_id}_{node_id}",
                    "source": prev_node_id,
                    "target": node_id,
                })

            prev_node_id = node_id
            y_position += y_gap

        return {
            "nodes": nodes,
            "edges": edges,
            "viewport": {"x": 0, "y": 0, "zoom": 0.85}
        }

    def _add_enrichment_nodes(
        self,
        canvas_data: Dict[str, Any],
        request: PlaybookBuildRequest
    ) -> Dict[str, Any]:
        """Add enrichment nodes based on threat type."""

        threat_type = request.threat_type or request.alert_type or ""

        # Determine enrichment integrations
        enrichment_map = {
            "phishing": ["virustotal", "urlscan"],
            "malware": ["virustotal", "hybrid_analysis"],
            "network": ["shodan", "abuseipdb"],
            "credential": ["hibp", "okta"],
        }

        integrations = []
        for key, values in enrichment_map.items():
            if key in threat_type.lower():
                integrations.extend(values)
                break

        if not integrations:
            integrations = ["virustotal"]  # Default

        # Find riggs_analyze node
        nodes = canvas_data.get("nodes", [])
        riggs_node = next((n for n in nodes if n.get("type") == "riggs_analyze"), None)

        if riggs_node:
            # Insert enrichment node after riggs_analyze
            enrich_id = f"enrich_{uuid.uuid4().hex[:6]}"
            enrich_node = {
                "id": enrich_id,
                "type": "enrich",
                "position": {
                    "x": riggs_node["position"]["x"],
                    "y": riggs_node["position"]["y"] + 180
                },
                "data": {
                    "label": "Enrich IOCs",
                    "config": {
                        "integrations": integrations,
                        "observable_types": ["ip", "domain", "hash", "url"]
                    },
                    "description": f"Enrich with {', '.join(integrations)}"
                }
            }

            # Insert node
            riggs_index = nodes.index(riggs_node)
            nodes.insert(riggs_index + 1, enrich_node)

            # Update edges
            edges = canvas_data.get("edges", [])

            # Reconnect edges
            old_edges = [e for e in edges if e["source"] == riggs_node["id"]]
            for old_edge in old_edges:
                old_edge["source"] = enrich_id  # Redirect to new node

            # Add edge from riggs to enrich
            edges.append({
                "id": f"e_{riggs_node['id']}_{enrich_id}",
                "source": riggs_node["id"],
                "target": enrich_id
            })

            # Shift subsequent nodes down
            for node in nodes[riggs_index + 2:]:
                node["position"]["y"] += 180

        return canvas_data

    def _add_approval_gates(self, canvas_data: Dict[str, Any]) -> Dict[str, Any]:
        """Add approval gates before destructive actions."""

        nodes = canvas_data.get("nodes", [])
        edges = canvas_data.get("edges", [])

        destructive_types = ["action", "webhook_call"]

        for node in nodes[:]:  # Copy list to modify during iteration
            if node.get("type") in destructive_types:
                config = node.get("data", {}).get("config", {})
                action_type = config.get("action_type", "")

                # Check if destructive
                if any(keyword in action_type.lower() for keyword in ["block", "isolate", "delete", "disable", "contain"]):
                    # Check if already has approval gate upstream
                    incoming_edges = [e for e in edges if e["target"] == node["id"]]
                    if incoming_edges:
                        source_id = incoming_edges[0]["source"]
                        source_node = next((n for n in nodes if n["id"] == source_id), None)

                        if source_node and source_node.get("type") != "approval_gate":
                            # Insert approval gate between source and action
                            # Place gate at midpoint, then push action + subsequent nodes down
                            approval_id = f"approval_{uuid.uuid4().hex[:6]}"
                            gate_y = source_node["position"]["y"] + 180
                            approval_node = {
                                "id": approval_id,
                                "type": "approval_gate",
                                "position": {
                                    "x": node["position"]["x"],
                                    "y": gate_y
                                },
                                "data": {
                                    "label": "Approval Required",
                                    "config": {
                                        "message": f"Approve {action_type}?",
                                        "timeout_minutes": 30
                                    },
                                    "description": "Human approval required for safety"
                                }
                            }

                            action_index = nodes.index(node)
                            nodes.insert(action_index, approval_node)

                            # Shift action node and all subsequent nodes down
                            for n in nodes[action_index + 1:]:
                                n["position"]["y"] += 180

                            # Update edges
                            for edge in incoming_edges:
                                edge["target"] = approval_id

                            edges.append({
                                "id": f"e_{approval_id}_{node['id']}",
                                "source": approval_id,
                                "target": node["id"]
                            })

        return canvas_data

    def _optimize_flow(self, canvas_data: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize playbook flow for better UX."""

        nodes = canvas_data.get("nodes", [])

        # Add IDs if missing
        for node in nodes:
            if "id" not in node:
                node["id"] = f"{node.get('type', 'node')}_{uuid.uuid4().hex[:6]}"

        # Ensure positions are set
        y_pos = 80
        for node in nodes:
            if "position" not in node or not node["position"]:
                node["position"] = {"x": 520, "y": y_pos}
                y_pos += 180

        # Recalculate max y for end node placement
        if nodes:
            y_pos = max(n["position"]["y"] for n in nodes) + 180

        # Ensure end node exists
        has_end = any(n.get("type") == "end" for n in nodes)
        if not has_end:
            end_node = {
                "id": f"end_{uuid.uuid4().hex[:6]}",
                "type": "end",
                "position": {"x": 520, "y": y_pos},
                "data": {
                    "label": "Complete",
                    "config": {"disposition": "completed"},
                    "description": "Playbook execution complete"
                }
            }
            nodes.append(end_node)

            # Connect last node to end
            edges = canvas_data.get("edges", [])
            if edges:
                last_edge = edges[-1]
                edges.append({
                    "id": f"e_{last_edge['target']}_{end_node['id']}",
                    "source": last_edge["target"],
                    "target": end_node["id"]
                })

        return canvas_data

    # ========================================================================
    # SOAR Playbook Conversion (Riggs-Powered)
    # ========================================================================

    async def convert_soar_playbook(
        self,
        parsed_playbook,  # ParsedPlaybook from converter
        source_platform: str,
        raw_content: str = "",
        name_override: str = None,
        tenant_id=None,
    ) -> Dict[str, Any]:
        """
        Convert a parsed SOAR playbook into a native T1 playbook using Riggs AI.

        Instead of mechanical node-by-node mapping, Riggs reads the source
        playbook structure and generates an optimal native T1 playbook that
        captures the original intent.

        Args:
            parsed_playbook: Intermediate representation from platform-specific parser
            source_platform: Source SOAR platform name
            raw_content: Original raw content (for extra context)
            name_override: Optional name override
            tenant_id: Tenant UUID for Claude quota/billing
        """
        try:
            # Step 1: Build a rich description of the source playbook for Riggs
            source_description = self._describe_parsed_playbook(parsed_playbook, source_platform)

            # Step 2: Call LLM with conversion-specific prompt
            blueprint = await self._convert_with_llm(
                source_description=source_description,
                playbook_name=name_override or parsed_playbook.name,
                playbook_description=parsed_playbook.description,
                source_platform=source_platform,
                tenant_id=tenant_id,
            )

            # Step 3: Build canvas from blueprint
            request = PlaybookBuildRequest(
                name=name_override or parsed_playbook.name,
                requirements=source_description,
                include_enrichment=False,   # Riggs handles this in the blueprint
                include_approval_gates=False,
            )
            canvas_data = await self._blueprint_to_canvas(blueprint, request)

            # Step 4: Validate and optimize flow
            canvas_data = self._optimize_flow(canvas_data)

            # Step 5: Build result
            playbook_data = {
                "name": blueprint.name or name_override or parsed_playbook.name,
                "description": blueprint.description or parsed_playbook.description,
                "canvas_data": canvas_data,
                "tags": blueprint.suggested_tags or self._extract_tags_from_parsed(parsed_playbook),
                "alert_types": blueprint.suggested_alert_types,
                "riggs_generated": True,
                "riggs_confidence": 0.90,
                "generation_source": "soar_conversion",
                "imported_from": source_platform,
                "import_metadata": {
                    "source_platform": source_platform,
                    "original_name": parsed_playbook.name,
                    "original_step_count": len(parsed_playbook.steps),
                    "conversion_method": "riggs_ai",
                },
            }

            return playbook_data

        except Exception as e:
            logger.error(f"Riggs SOAR conversion failed: {e}")
            raise

    def _describe_parsed_playbook(self, parsed_playbook, source_platform: str) -> str:
        """Build a rich natural language description of a parsed SOAR playbook for Riggs."""
        lines = [
            f"Convert this {source_platform.replace('_', ' ').title()} playbook to a T1 Agentics native playbook.",
            f"Playbook name: {parsed_playbook.name}",
        ]

        if parsed_playbook.description:
            lines.append(f"Description: {parsed_playbook.description}")

        if parsed_playbook.triggers:
            lines.append(f"Triggers: {json.dumps(parsed_playbook.triggers, default=str)[:300]}")

        lines.append(f"\nSource playbook has {len(parsed_playbook.steps)} steps:")
        for i, step in enumerate(parsed_playbook.steps):
            step_desc = f"  {i+1}. [{step.step_type}] {step.name}"
            if step.config:
                # Include key config details
                config_summary = {k: v for k, v in step.config.items() if k in (
                    'action', 'integration', 'app', 'command', 'script_name',
                    'message', 'channel', 'severity', 'operator', 'field',
                )}
                if config_summary:
                    step_desc += f" — config: {json.dumps(config_summary, default=str)[:150]}"
            if step.inputs:
                inputs_summary = list(step.inputs.keys())[:5]
                step_desc += f" — inputs: {inputs_summary}"
            if step.next_steps:
                step_desc += f" → next: {step.next_steps}"
            if step.condition:
                step_desc += f" (condition: {step.condition})"
            lines.append(step_desc)

        if parsed_playbook.variables:
            lines.append(f"\nVariables: {list(parsed_playbook.variables.keys())[:10]}")

        lines.append("\nCreate an equivalent T1 Agentics playbook that captures the same intent and logic flow.")

        return "\n".join(lines)

    async def _convert_with_llm(
        self,
        source_description: str,
        playbook_name: str,
        playbook_description: str,
        source_platform: str,
        tenant_id=None,
    ) -> PlaybookBlueprint:
        """Use LLM to convert a source playbook description into a T1 native blueprint."""
        try:
            from services.ai_triage_service import AITriageService
            triage_service = AITriageService()

            system_prompt = """You are Riggs, a senior SOC automation expert converting SOAR playbooks into T1 Agentics native format.

You understand workflows from Splunk SOAR, XSOAR, Tines, Swimlane, Chronicle SOAR, and QRadar SOAR.
Your job is to understand the INTENT of the source playbook and create an optimal native T1 playbook.

Do NOT do a literal 1:1 node mapping. Instead:
- Understand what the playbook is trying to accomplish
- Use T1's native node types to achieve the same goal efficiently
- Combine redundant steps where appropriate
- Add best practices (error handling, approvals for destructive actions)

Available T1 node types:
- trigger: Start playbook (alert, webhook, schedule, manual)
- riggs_analyze: AI-powered threat analysis (use for investigation/classification steps)
- enrich: Enrich IOCs via threat intel integrations (VirusTotal, AbuseIPDB, etc.)
- decision: If/then branching with conditions
- action: Execute integration actions (block IP, isolate host, disable user, etc.)
- approval: Human approval gate (use before destructive actions)
- notify: Send notification (Slack, Teams, email)
- create_ticket: Create ticket (Jira, ServiceNow)
- code: Custom Python logic
- delay: Wait/pause
- end: Finalize with disposition"""

            prompt = f"""{source_description}

Respond with ONLY this JSON (no markdown, no explanation):
{{"name":"{playbook_name}","description":"...","flow_description":"...","estimated_complexity":"simple|moderate|complex","suggested_tags":["..."],"suggested_alert_types":["..."],"nodes":[{{"type":"trigger","label":"...","description":"...","config":{{}}}},{{"type":"...","label":"...","description":"...","config":{{}}}}]}}"""

            combined = f"{system_prompt}\n\n{prompt}"
            llm_output = await triage_service._call_llm_for_triage(
                combined,
                purpose="riggs_soar_conversion",
                max_tokens=4096,
                tenant_id=tenant_id,
            )

            if llm_output:
                return self._parse_llm_blueprint(llm_output)

            logger.warning("LLM returned empty output for SOAR conversion, using fallback")
            return self._fallback_conversion_blueprint(playbook_name, playbook_description, source_description)

        except Exception as e:
            logger.error(f"LLM SOAR conversion failed: {e}, using fallback")
            return self._fallback_conversion_blueprint(playbook_name, playbook_description, source_description)

    def _fallback_conversion_blueprint(
        self, name: str, description: str, source_description: str
    ) -> PlaybookBlueprint:
        """Fallback blueprint when LLM is unavailable for SOAR conversion."""
        return PlaybookBlueprint(
            name=name or "Imported Playbook",
            description=description or "Converted from external SOAR platform",
            nodes=[
                NodeTemplate(type="trigger", label="Alert Trigger",
                             config={"trigger_type": "alert"}, description="Start on alert"),
                NodeTemplate(type="riggs_analyze", label="AI Analysis",
                             config={}, description="Analyze with Riggs AI"),
                NodeTemplate(type="condition", label="Check Verdict",
                             config={"field": "$.nodes.riggs_analyze.verdict",
                                     "operator": "equals", "value": "MALICIOUS"},
                             description="Branch on threat verdict"),
                NodeTemplate(type="action", label="Respond",
                             config={}, description="Execute response action"),
                NodeTemplate(type="notify", label="Notify Team",
                             config={"channel": "slack"}, description="Alert the SOC team"),
                NodeTemplate(type="end", label="Complete",
                             config={"disposition": "investigated"}, description="Done"),
            ],
            flow_description="Trigger → AI Analysis → Decision → Respond/Notify → End",
            estimated_complexity="moderate",
            suggested_tags=["imported", "automated"],
            suggested_alert_types=[],
        )

    def _extract_tags_from_parsed(self, parsed_playbook) -> List[str]:
        """Extract tags from a parsed playbook."""
        tags = ["imported"]
        name_lower = parsed_playbook.name.lower()
        for tag in ["phishing", "malware", "ransomware", "incident", "alert", "response", "network", "email"]:
            if tag in name_lower:
                tags.append(tag)
        return tags

    # ========================================================================
    # Playbook Analysis from Alerts
    # ========================================================================

    async def suggest_playbook_from_alert_pattern(
        self,
        alert_type: str,
        sample_alerts: List[Dict[str, Any]],
        min_alert_count: int = 5
    ) -> Optional[PlaybookBuildRequest]:
        """
        Analyze alert patterns and suggest a playbook.

        Useful for creating playbooks from recurring alert types.
        """
        if len(sample_alerts) < min_alert_count:
            return None

        # Analyze common fields
        common_fields = self._analyze_alert_commonality(sample_alerts)

        # Determine threat type
        threat_type = self._infer_threat_type(alert_type, sample_alerts)

        # Generate requirements
        requirements = self._generate_requirements_from_pattern(
            alert_type=alert_type,
            threat_type=threat_type,
            common_fields=common_fields,
            sample_count=len(sample_alerts)
        )

        return PlaybookBuildRequest(
            name=f"Auto: {alert_type.replace('_', ' ').title()} Response",
            requirements=requirements,
            alert_type=alert_type,
            threat_type=threat_type,
            sample_alert=sample_alerts[0],
            include_enrichment=True,
            include_approval_gates=True
        )

    def _analyze_alert_commonality(
        self,
        alerts: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Find common fields across alerts."""
        common = {}

        if not alerts:
            return common

        # Get all keys from first alert
        first_alert = alerts[0]
        for key in first_alert.keys():
            values = [a.get(key) for a in alerts if key in a]
            if len(values) == len(alerts):  # Present in all alerts
                unique_values = set(str(v) for v in values)
                if len(unique_values) == 1:  # Same value in all
                    common[key] = first_alert[key]
                elif len(unique_values) <= 3:  # Few variations
                    common[f"{key}_variants"] = list(unique_values)

        return common

    def _infer_threat_type(
        self,
        alert_type: str,
        alerts: List[Dict[str, Any]]
    ) -> str:
        """Infer threat type from alert type and content."""

        threat_keywords = {
            "phishing": ["phish", "email", "sender", "spoof"],
            "malware": ["malware", "virus", "trojan", "hash"],
            "ransomware": ["ransom", "encrypt", "crypto"],
            "c2": ["c2", "command", "control", "beacon"],
            "lateral_movement": ["lateral", "psexec", "wmi", "rdp"],
            "credential": ["credential", "password", "kerberos", "lsass"],
        }

        alert_text = f"{alert_type} {json.dumps(alerts[0])}".lower()

        for threat_type, keywords in threat_keywords.items():
            if any(kw in alert_text for kw in keywords):
                return threat_type

        return "unknown"

    def _generate_requirements_from_pattern(
        self,
        alert_type: str,
        threat_type: str,
        common_fields: Dict[str, Any],
        sample_count: int
    ) -> str:
        """Generate playbook requirements from alert pattern."""

        parts = [
            f"Create a playbook to automatically respond to {alert_type} alerts.",
            f"\nObserved pattern: {sample_count} similar alerts detected.",
            f"\nThreat type: {threat_type}",
        ]

        if common_fields:
            parts.append("\nCommon characteristics:")
            for key, value in list(common_fields.items())[:5]:
                parts.append(f"  - {key}: {value}")

        parts.extend([
            "\n\nPlaybook should:",
            "1. Analyze the alert with Riggs",
            "2. Enrich relevant IOCs",
            "3. Make containment decision",
            "4. Notify SOC team",
            "5. Create ticket for investigation"
        ])

        return "\n".join(parts)


    # ========================================================================
    # Integration-Aware Playbook Suggestions
    # ========================================================================

    async def suggest_from_integrations(
        self,
        tenant_id,
        max_suggestions: int = 15,
        include_gap_analysis: bool = True,
    ) -> Dict[str, Any]:
        """
        Analyze a tenant's installed integrations and suggest playbooks
        they could build right now, plus what they'd unlock by adding more.

        Returns:
            {
                "suggestions": [...],     # Playbooks they can build now
                "gap_analysis": [...],    # What they'd unlock with more integrations
                "installed_summary": {},  # Summary of what they have
            }
        """
        from services.connect_service import get_connect_service
        from services.postgres_db import postgres_db

        connect = get_connect_service()

        # --- Get installed integrations ---
        instances = await connect.get_instances(tenant_id=str(tenant_id))
        installed = [
            {
                "name": inst.get("connector_name") or inst.get("display_name", "Unknown"),
                "connector_id": inst.get("connector_id", ""),
                "category": inst.get("category", "unknown"),
                "vendor": inst.get("vendor", ""),
                "enabled": inst.get("enabled", False),
                "actions": [
                    {"id": a.get("id", ""), "name": a.get("name", ""), "type": a.get("observable_type", "")}
                    for a in (inst.get("connector_actions") or [])
                ][:10],  # Limit actions per integration to save tokens
            }
            for inst in instances
            if inst.get("enabled", False)
        ]

        if not installed:
            return {
                "suggestions": [],
                "gap_analysis": [{
                    "missing_category": "any",
                    "recommendation": "Install your first integration to unlock Riggs playbook suggestions.",
                    "example_integrations": ["VirusTotal", "Slack", "Jira"],
                    "unlocked_playbooks": [],
                }],
                "installed_summary": {"count": 0, "categories": []},
            }

        # --- Get available catalog for gap analysis ---
        available_categories = set()
        if include_gap_analysis:
            try:
                marketplace = await connect.get_marketplace(
                    tenant_id=str(tenant_id), page=1, per_page=100
                )
                for item in marketplace:
                    cat = item.get("category", "")
                    if cat:
                        available_categories.add(cat)
            except Exception:
                pass

        # --- Build context for LLM ---
        installed_categories = set(i["category"] for i in installed)
        installed_summary = {
            "count": len(installed),
            "categories": sorted(installed_categories),
            "integrations": [f"{i['name']} ({i['category']})" for i in installed],
        }

        # --- Call LLM for suggestions ---
        suggestions_data = await self._suggest_with_llm(
            installed=installed,
            installed_summary=installed_summary,
            available_categories=available_categories - installed_categories,
            max_suggestions=max_suggestions,
            include_gap_analysis=include_gap_analysis,
            tenant_id=tenant_id,
        )

        suggestions_data["installed_summary"] = installed_summary
        return suggestions_data

    async def _suggest_with_llm(
        self,
        installed: List[Dict],
        installed_summary: Dict,
        available_categories: set,
        max_suggestions: int,
        include_gap_analysis: bool,
        tenant_id=None,
    ) -> Dict[str, Any]:
        """Use LLM to generate integration-aware playbook suggestions."""
        try:
            from services.ai_triage_service import AITriageService
            triage_service = AITriageService()

            system_prompt = """You are Riggs, a senior SOC automation expert.
Analyze this tenant's installed integrations and suggest practical security playbooks they can build RIGHT NOW.

Rules:
- Only suggest playbooks that use integrations they ALREADY have installed
- Each suggestion: name, description, which installed integrations it uses, complexity (simple/moderate/complex)
- Be specific and practical — real SOC workflows, not generic"""

            # Build integration context
            integration_list = "\n".join(
                f"- {i['name']} ({i['category']}): actions={[a['name'] for a in i['actions'][:5]]}"
                for i in installed
            )

            gap_section = ""
            if include_gap_analysis and available_categories:
                gap_section = f"""

Also provide gap_analysis: what categories they're MISSING and what 3-5 playbooks they'd unlock by adding integrations in those categories.
Missing categories available in our marketplace: {sorted(available_categories)}"""

            prompt = f"""Tenant's installed integrations:
{integration_list}

Suggest up to {max_suggestions} playbooks they can build with these integrations.{gap_section}

Respond with ONLY this JSON:
{{"suggestions":[{{"name":"...","description":"...","integrations_used":["connector_id1","connector_id2"],"complexity":"simple|moderate|complex","category":"threat_response|enrichment|notification|compliance|hunting"}}],"gap_analysis":[{{"missing_category":"edr|siem|ticketing|...","recommendation":"...","example_integrations":["CrowdStrike","SentinelOne"],"unlocked_playbooks":["Playbook name 1","Playbook name 2"]}}]}}"""

            combined = f"{system_prompt}\n\n{prompt}"
            llm_output = await triage_service._call_llm_for_triage(
                combined,
                purpose="riggs_integration_suggestions",
                max_tokens=4096,
                tenant_id=tenant_id,
            )

            if llm_output:
                return self._parse_suggestions_output(llm_output)

            return self._fallback_suggestions(installed)

        except Exception as e:
            logger.error(f"LLM integration suggestion failed: {e}")
            return self._fallback_suggestions(installed)

    def _parse_suggestions_output(self, llm_output: str) -> Dict[str, Any]:
        """Parse LLM output for integration suggestions."""
        try:
            # Extract JSON
            if "```json" in llm_output:
                start = llm_output.find("```json") + 7
                end = llm_output.find("```", start)
                json_str = llm_output[start:end].strip() if end != -1 else llm_output[start:].strip()
            elif "```" in llm_output:
                start = llm_output.find("```") + 3
                end = llm_output.find("```", start)
                json_str = llm_output[start:end].strip() if end != -1 else llm_output[start:].strip()
            else:
                json_str = llm_output.strip()

            try:
                data = json.loads(json_str)
            except json.JSONDecodeError:
                repaired = self._repair_truncated_json(json_str)
                data = json.loads(repaired)

            return {
                "suggestions": data.get("suggestions", []),
                "gap_analysis": data.get("gap_analysis", []),
            }
        except Exception as e:
            logger.error(f"Failed to parse suggestions output: {e}")
            return {"suggestions": [], "gap_analysis": []}

    def _fallback_suggestions(self, installed: List[Dict]) -> Dict[str, Any]:
        """Fallback suggestions when LLM is unavailable."""
        categories = set(i["category"] for i in installed)
        suggestions = []

        if "threat_intel" in categories:
            suggestions.append({
                "name": "IOC Enrichment Pipeline",
                "description": "Automatically enrich IPs, domains, and hashes from alerts using your threat intel integrations.",
                "integrations_used": [i["connector_id"] for i in installed if i["category"] == "threat_intel"],
                "complexity": "simple",
                "category": "enrichment",
            })

        if "communication" in categories or any(i["connector_id"] == "slack" for i in installed):
            suggestions.append({
                "name": "SOC Alert Notifications",
                "description": "Notify your team of critical alerts and investigation results.",
                "integrations_used": [i["connector_id"] for i in installed if i["category"] == "communication"],
                "complexity": "simple",
                "category": "notification",
            })

        if "threat_intel" in categories and ("communication" in categories or "ticketing" in categories):
            suggestions.append({
                "name": "Phishing Response Playbook",
                "description": "Analyze phishing emails, enrich IOCs, block sender, and notify SOC.",
                "integrations_used": [i["connector_id"] for i in installed],
                "complexity": "moderate",
                "category": "threat_response",
            })

        return {"suggestions": suggestions, "gap_analysis": []}

    # ========================================================================
    # Build From Ingested Alert (Phase A entry point)
    # ========================================================================

    async def build_from_alert(
        self,
        alert_id: str,
        tenant_id,
        persist: bool = True,
    ) -> Dict[str, Any]:
        """Build a draft playbook from a specific ingested alert.

        Fetches the alert, builds a PlaybookBuildRequest with the tenant's
        installed connectors, calls the LLM-driven generator, and (if persist)
        writes the result to the `playbooks` table as a draft (is_enabled=false,
        name prefixed "Riggs Draft: "). Returns playbook_id, name, source,
        canvas_data, and the VPE editor URL.

        Raises ValueError if the alert is not found.
        """
        from services.postgres_db import postgres_db

        if not postgres_db.connected:
            raise RuntimeError("Database not connected")

        # ---- Fetch the alert (handle UUID-or-string alert id) ----
        async with postgres_db.tenant_acquire() as conn:
            alert = None
            try:
                alert_uuid = uuid.UUID(str(alert_id))
                row = await conn.fetchrow("SELECT * FROM alerts WHERE id = $1", alert_uuid)
                if row:
                    alert = dict(row)
            except (ValueError, TypeError):
                pass
            if alert is None:
                row = await conn.fetchrow("SELECT * FROM alerts WHERE alert_id = $1", str(alert_id))
                if row:
                    alert = dict(row)

        if alert is None:
            raise ValueError(f"alert not found: {alert_id}")

        # Normalize JSONB fields that asyncpg may hand back as strings.
        for k in ("raw_event", "iocs", "entities", "enrichment"):
            v = alert.get(k)
            if isinstance(v, str):
                try:
                    alert[k] = json.loads(v)
                except Exception:
                    alert[k] = {}

        raw_event = alert.get("raw_event") or {}
        alert_type = (alert.get("alert_type") or raw_event.get("alert_type") or "generic").lower()
        severity = alert.get("severity") or raw_event.get("severity") or "medium"
        title = alert.get("title") or raw_event.get("title") or f"{alert_type} alert"
        description = (alert.get("description") or raw_event.get("description") or "")[:600]

        # ---- Tenant context: connectors + auto-enriched IOC types ----
        connectors: List[Dict[str, Any]] = []
        try:
            from services.connect_service import get_connect_service
            connect = get_connect_service()
            instances = await connect.get_instances(tenant_id=str(tenant_id))
            for inst in instances:
                if not inst.get("enabled", False):
                    continue
                connectors.append({
                    "vendor": inst.get("vendor") or inst.get("connector_name", "unknown"),
                    "connector_name": inst.get("connector_name", ""),
                    "category": inst.get("category", "uncategorized"),
                    "actions": [
                        {
                            "id": a.get("id", ""),
                            "name": a.get("name", ""),
                            "observable_type": a.get("observable_type", ""),
                        }
                        for a in (inst.get("connector_actions") or [])[:8]
                    ],
                })
        except Exception as exc:
            logger.debug(f"[BUILD_FROM_ALERT] connector lookup failed: {exc}")

        # Detect IOC types already on the alert so the LLM doesn't add
        # redundant enrichment nodes for them.
        auto_enriched: List[str] = []
        iocs = alert.get("iocs") or []
        if isinstance(iocs, list):
            for ioc in iocs:
                if isinstance(ioc, dict):
                    t = ioc.get("type")
                    if t and t not in auto_enriched:
                        auto_enriched.append(t)

        # ---- Retrieve the tenant's OWN SOPs so the playbook mirrors how
        # this team actually responds. Strictly tenant-scoped — platform
        # curriculum content stays out (different purpose).
        relevant_sops: List[Dict[str, Any]] = []
        try:
            from services.sop_recommendation_service import get_sop_recommendation_service
            sop_service = get_sop_recommendation_service()
            sop_result = await sop_service.recommend_for_alert(
                alert_data=alert,
                limit=3,
                min_score=0.2,
            )
            for rec in sop_result.recommendations:
                relevant_sops.append({
                    "title": rec.title,
                    "category": rec.category,
                    "summary": rec.summary or "",
                    "key_steps": rec.key_steps or [],
                    "relevance_score": rec.relevance_score,
                    "match_reasons": rec.match_reasons or [],
                })
        except Exception as exc:
            logger.debug(f"[BUILD_FROM_ALERT] SOP retrieval failed: {exc}")

        # ---- Build the natural-language requirements brief ----
        ioc_summary = ""
        if iocs:
            preview = []
            for ioc in iocs[:5]:
                if isinstance(ioc, dict):
                    preview.append(f"{ioc.get('type', '?')}={ioc.get('value', '?')}")
            if preview:
                ioc_summary = f" Observed indicators: {', '.join(preview)}."

        requirements = (
            f"Build a POST-TRIAGE response playbook for '{title}' "
            f"({alert_type}, severity={severity}) alerts."
            f" {description}"
            f"{ioc_summary}"
            " The platform has already run Riggs AI triage and auto-enrichment"
            " on the alert before this playbook fires, so the verdict and"
            " enrichment data are already on the alert object. Branch on"
            " {{alert.ai_verdict}}, gate any destructive actions behind"
            " approval, notify the SOC team with Riggs's existing summary, and"
            " close the case. Do NOT add riggs_analyze or enrich nodes — they"
            " would duplicate work already done."
        )

        # When we have the tenant's real connectors, trust the LLM to compose
        # enrichment + approval gates using those connectors. The post-processor
        # versions inject a generic "virustotal" enrich + a default approval
        # gate that duplicates what the LLM already does better. Only let the
        # post-processors run when we have no connector signal at all.
        has_connectors = bool(connectors)

        # Pass a real alert payload to the LLM, not just metadata. Includes
        # raw_event (trimmed), iocs, entities — enough to pick targeted
        # enrichment + actions and to write good {{alert.<field>}} paths.
        raw_event = alert.get("raw_event") or {}
        entities = alert.get("entities") or raw_event.get("entities") or []
        sample_alert_payload = {
            "alert_id": alert.get("alert_id") or str(alert.get("id", "")),
            "title": title,
            "alert_type": alert_type,
            "severity": severity,
            "description": description,
            "data_source": alert.get("data_source") or raw_event.get("data_source"),
            "category": alert.get("category"),
            "iocs": iocs[:20] if isinstance(iocs, list) else [],
            "entities": entities[:10] if isinstance(entities, list) else [],
            "raw_event": raw_event,
        }

        request = PlaybookBuildRequest(
            requirements=requirements,
            alert_type=alert_type,
            severity=severity,
            sample_alert=sample_alert_payload,
            include_enrichment=not has_connectors,
            include_approval_gates=not has_connectors,
            auto_execute_safe_actions=False,
            available_connectors=connectors,
            auto_enriched_ioc_types=auto_enriched,
            relevant_sops=relevant_sops or None,
        )

        playbook_data = await self.generate_playbook_from_requirements(
            request, tenant_id=tenant_id
        )

        # Tag and name as a Riggs draft so it shows up clearly in lists.
        original_name = (playbook_data.get("name") or "").strip() or f"Response: {alert_type}"
        if not original_name.lower().startswith("riggs draft:"):
            playbook_data["name"] = f"Riggs Draft: {original_name}"[:255]

        tags = list(playbook_data.get("tags") or [])
        if "riggs-draft" not in tags:
            tags.insert(0, "riggs-draft")
        if "from-alert" not in tags:
            tags.append("from-alert")
        playbook_data["tags"] = tags

        if not persist:
            return {
                "playbook_id": None,
                "name": playbook_data["name"],
                "source": playbook_data.get("generation_source", "unknown"),
                "canvas_data": playbook_data.get("canvas_data", {}),
                "editor_url": None,
                "draft": playbook_data,
            }

        canvas_data = playbook_data.get("canvas_data", {"nodes": [], "edges": []})
        async with postgres_db.tenant_acquire() as conn:
            row = await conn.fetchrow(
                """
                INSERT INTO playbooks (
                    tenant_id, name, description, trigger_conditions, canvas_data,
                    tags, alert_types, severity_filter, data_sources, priority,
                    riggs_allowed, trigger_timing, is_enabled
                ) VALUES (
                    current_setting('app.current_tenant_id')::uuid,
                    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, false
                )
                RETURNING id, name, created_at
                """,
                playbook_data["name"],
                playbook_data.get("description") or f"Generated by Riggs from alert {alert_id}",
                json.dumps({"alert_types": [alert_type]}),
                json.dumps(canvas_data),
                tags,
                [alert_type],
                [severity] if severity else [],
                [alert.get("data_source")] if alert.get("data_source") else [],
                50,        # default priority
                False,     # riggs_allowed: drafts are not auto-runnable
                "post_triage",  # alert already has verdict + enrichment by then
            )

        playbook_id = str(row["id"])
        return {
            "playbook_id": playbook_id,
            "name": row["name"],
            "source": playbook_data.get("generation_source", "unknown"),
            "generation_reason": playbook_data.get("generation_reason"),
            "canvas_data": canvas_data,
            "editor_url": f"/playbooks/{playbook_id}",
            "node_count": len(canvas_data.get("nodes", [])),
            "edge_count": len(canvas_data.get("edges", [])),
        }


# ============================================================================
# Singleton
# ============================================================================

_builder: Optional[RiggsPlaybookBuilder] = None


def get_riggs_playbook_builder() -> RiggsPlaybookBuilder:
    """Get singleton Riggs playbook builder instance."""
    global _builder
    if _builder is None:
        _builder = RiggsPlaybookBuilder()
    return _builder
