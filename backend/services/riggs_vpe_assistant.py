# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Riggs VPE Assistant — interactive playbook-editing chat inside the Visual
Playbook Editor.

Takes the current canvas (nodes + edges) and a user message and asks Claude
to return both a natural-language reply and a structured `mutations` list
the frontend can apply directly to React Flow state.

Mutation operations:
    add_node       { op, node }
    remove_node    { op, node_id }
    update_node    { op, node_id, data }     # merges into node.data
    add_edge       { op, edge }
    remove_edge    { op, edge_id }

The model is allowed to return zero mutations (pure Q&A) or many (multi-step
edits). All mutations are validated against the canonical block-type
allowlist + the existing canvas's node ids before being returned, so a bad
LLM payload can never corrupt the frontend canvas.
"""

import json
import logging
import re
import uuid
from typing import Any, Dict, List, Optional, Tuple
from uuid import UUID

logger = logging.getLogger(__name__)


# Canonical block kinds (12) — these are what the Workflow Studio UI uses.
# Legacy aliases are accepted for backwards-compat but Riggs is told to
# prefer canonical kinds (see riggs_playbook_builder.py system prompt).
CANONICAL_BLOCK_TYPES = frozenset({
    # Canonical (12)
    "trigger", "analyze", "ai_agent", "decision", "respond", "code",
    "loop", "delay", "approval", "subflow", "utility", "end",
    # Legacy aliases the studio still accepts (auto-mapped under the hood).
    # Keep them in the allowlist so we don't reject pre-existing playbooks.
    "riggs_analyze", "enrich", "action", "condition", "approval_gate",
    "notify", "create_ticket", "case_update", "webhook_call",
    "python_code", "function_call", "transform",
    "list_lookup", "list_update", "edl_add", "edl_remove",
    "variable_set", "variable_get", "user_input", "webform",
    "file_upload", "note", "switch", "parallel", "merge", "schedule",
})


SYSTEM_PROMPT = """You are Riggs, the SOC playbook designer embedded in the T1 Agentics Visual Playbook Editor.

The user is editing a SOAR playbook on a React Flow canvas. You can answer questions about the canvas and propose structured edits.

# Canonical block kinds (12) — use these in any `add_node`:
trigger, analyze, ai_agent, decision, respond, code, loop, delay, approval, subflow, utility, end

Mode/sub-type fields:
- `analyze`  : default = Riggs AI verdict; `config.mode="enrich"` = IOC threat-intel lookup
- `respond`  : `config.response_type` is one of `"notify"`, `"create_ticket"`, `"action"`
- `code`     : `config.mode` is one of `"script"` (python), `"assign"` (var), `"note"`, `"transform"`
- `approval` : human approval gate (replaces legacy `approval_gate`)
- `decision` : if/then branching (replaces legacy `condition`); config has `expression` + `branches: [{id:'yes',...},{id:'no',...}]`
- `utility`  : `config.operation` = `"case_update" | "list_update" | "edl_add" | "edl_remove"`

Legacy types (riggs_analyze, enrich, action, condition, approval_gate, notify, create_ticket, case_update, webhook_call, python_code, variable_set, etc.) are ACCEPTED for backwards-compat but trigger "Legacy block ..." warnings. Prefer canonical kinds.

Output ONLY valid JSON with this shape (no markdown, no commentary):

{
  "reply": "1-3 sentence natural-language reply",
  "mutations": [
    {"op": "add_node",    "node": {"id": "<kind>_<hex6>", "type": "<canonical_kind>", "position": {"x":N,"y":N}, "data": {"label":"...", "config": {...}}}},
    {"op": "remove_node", "node_id": "<existing_node_id>"},
    {"op": "update_node", "node_id": "<existing_node_id>", "data": {"label":"...", "config": {...}}},
    {"op": "add_edge",    "edge": {"id":"e_<src>_<dst>", "source":"<src_id>", "target":"<dst_id>"}},
    {"op": "remove_edge", "edge_id": "<existing_edge_id>"}
  ]
}

# Data path syntax
Reference upstream data with Jinja `{{...}}`:
- `{{alert.<field>}}` — triggering alert payload
- `{{case.<field>}}` — parent investigation
- `{{<node_id_or_label>.<field>}}` — output of an earlier node

Hard rules:
1. Every `add_node` MUST use a type from this allowlist: {ALLOWED_TYPES}
2. Every `add_edge` MUST reference node ids that exist in the current canvas OR are being created in the same mutation batch.
3. Every `remove_node` / `update_node` / `remove_edge` MUST reference an id that exists in the current canvas.
4. Do NOT remove the only trigger node. Do NOT leave the graph without an `end` node if it had one.
5. Keep node positions sensible: main trunk at x=520, true-branch at x=260, false-branch at x=780, y increments of 180.
6. Generate node ids as `<kind>_<6 hex chars>` (e.g. `analyze_3a9f1c`). Generate edge ids as `e_<src>_<dst>`.
7. When the user asks a question (no edit requested), return `mutations: []` and answer in `reply`.
8. NEVER reference vendor LLM names (Claude, Anthropic, OpenAI, etc.) — say "Riggs AI".
9. If you need information you don't have, ask in `reply` and return no mutations.

Be concise. Don't lecture. A senior SOC analyst is asking; meet them at that level."""


def _strip_code_fences(text: str) -> str:
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```[a-zA-Z]*\n", "", text)
        text = re.sub(r"\n```\s*$", "", text)
    return text.strip()


def _summarize_canvas(canvas: Dict[str, Any]) -> str:
    """Compact representation of the canvas for the prompt. Avoids dumping
    the full JSON for every request — keeps token cost low."""
    nodes = canvas.get("nodes") or []
    edges = canvas.get("edges") or []
    node_lines = []
    for n in nodes[:60]:
        nid = n.get("id", "?")
        ntype = n.get("type", "?")
        label = (n.get("data") or {}).get("label", "")
        cfg = (n.get("data") or {}).get("config") or {}
        # Keep only short config keys; long blobs eat the prompt budget.
        cfg_keys = [k for k in cfg.keys() if isinstance(k, str)][:6]
        node_lines.append(
            f"- {nid} ({ntype}) \"{label}\""
            + (f"  config_keys={cfg_keys}" if cfg_keys else "")
        )
    if len(nodes) > 60:
        node_lines.append(f"... and {len(nodes) - 60} more nodes")

    edge_lines = []
    for e in edges[:80]:
        sh = e.get("sourceHandle")
        suffix = f"  via {sh}" if sh else ""
        edge_lines.append(f"- {e.get('source','?')} -> {e.get('target','?')}{suffix}")
    if len(edges) > 80:
        edge_lines.append(f"... and {len(edges) - 80} more edges")

    return (
        f"Current canvas: {len(nodes)} nodes, {len(edges)} edges.\n\n"
        "Nodes:\n" + ("\n".join(node_lines) if node_lines else "(empty)") + "\n\n"
        "Edges:\n" + ("\n".join(edge_lines) if edge_lines else "(empty)")
    )


def _validate_mutations(
    mutations: List[Dict[str, Any]],
    existing_node_ids: set,
    existing_edge_ids: set,
) -> Tuple[List[Dict[str, Any]], List[str]]:
    """Filter the LLM's mutations to only those that are safe and well-formed.
    Returns (kept_mutations, rejection_messages). Each rejected op is logged
    but does not abort the others — we'd rather apply 3 valid edits than 0."""
    kept: List[Dict[str, Any]] = []
    rejected: List[str] = []

    # Track ids being created in this batch so add_edge can reference them.
    pending_node_ids = set()
    pending_edge_ids = set()

    for i, m in enumerate(mutations):
        if not isinstance(m, dict):
            rejected.append(f"#{i}: not an object")
            continue
        op = m.get("op")

        if op == "add_node":
            node = m.get("node") or {}
            nid = node.get("id")
            ntype = node.get("type")
            pos = node.get("position") or {}
            data = node.get("data") or {}
            if not isinstance(nid, str) or not nid:
                rejected.append(f"#{i} add_node: missing id"); continue
            if ntype not in CANONICAL_BLOCK_TYPES:
                rejected.append(f"#{i} add_node: bad type '{ntype}'"); continue
            if nid in existing_node_ids or nid in pending_node_ids:
                rejected.append(f"#{i} add_node: id collision '{nid}'"); continue
            if not isinstance(pos, dict) or "x" not in pos or "y" not in pos:
                # auto-position if missing; better than rejecting
                node["position"] = {"x": 520, "y": 80 + 180 * len(existing_node_ids)}
            if not isinstance(data, dict):
                node["data"] = {"label": ntype, "config": {}}
            elif "config" not in data:
                data["config"] = {}
            pending_node_ids.add(nid)
            kept.append({"op": "add_node", "node": node})

        elif op == "remove_node":
            nid = m.get("node_id")
            if not isinstance(nid, str) or nid not in existing_node_ids:
                rejected.append(f"#{i} remove_node: unknown id '{nid}'"); continue
            kept.append({"op": "remove_node", "node_id": nid})

        elif op == "update_node":
            nid = m.get("node_id")
            data = m.get("data") or {}
            if not isinstance(nid, str) or nid not in existing_node_ids:
                rejected.append(f"#{i} update_node: unknown id '{nid}'"); continue
            if not isinstance(data, dict):
                rejected.append(f"#{i} update_node: bad data"); continue
            kept.append({"op": "update_node", "node_id": nid, "data": data})

        elif op == "add_edge":
            edge = m.get("edge") or {}
            eid = edge.get("id")
            src = edge.get("source")
            tgt = edge.get("target")
            if not isinstance(eid, str) or not eid:
                eid = f"e_{src}_{tgt}_{uuid.uuid4().hex[:4]}"
                edge["id"] = eid
            valid_src = (src in existing_node_ids) or (src in pending_node_ids)
            valid_tgt = (tgt in existing_node_ids) or (tgt in pending_node_ids)
            if not valid_src or not valid_tgt:
                rejected.append(f"#{i} add_edge: endpoint(s) not in canvas"); continue
            if eid in existing_edge_ids or eid in pending_edge_ids:
                # disambiguate
                edge["id"] = f"{eid}_{uuid.uuid4().hex[:4]}"
            pending_edge_ids.add(edge["id"])
            kept.append({"op": "add_edge", "edge": edge})

        elif op == "remove_edge":
            eid = m.get("edge_id")
            if not isinstance(eid, str) or eid not in existing_edge_ids:
                rejected.append(f"#{i} remove_edge: unknown id '{eid}'"); continue
            kept.append({"op": "remove_edge", "edge_id": eid})

        else:
            rejected.append(f"#{i}: unknown op '{op}'")

    return kept, rejected


async def vpe_assist(
    message: str,
    canvas: Dict[str, Any],
    tenant_id: UUID,
    playbook_id: Optional[str] = None,
    user_id: Optional[UUID] = None,
) -> Dict[str, Any]:
    """Single-turn VPE assistant call.

    Returns:
        {
            "reply": str,
            "mutations": [...],         # validated, safe to apply
            "rejected": [...],          # human-readable reasons (for debug)
            "source": "llm" | "error",
        }
    """
    nodes = canvas.get("nodes") or []
    edges = canvas.get("edges") or []
    existing_node_ids = {n.get("id") for n in nodes if isinstance(n, dict) and n.get("id")}
    existing_edge_ids = {e.get("id") for e in edges if isinstance(e, dict) and e.get("id")}

    system = SYSTEM_PROMPT.replace(
        "{ALLOWED_TYPES}", ", ".join(sorted(CANONICAL_BLOCK_TYPES))
    )
    user_prompt = (
        _summarize_canvas(canvas)
        + "\n\n---\n\nUser message:\n"
        + (message or "").strip()
    )

    try:
        from services.claude_service import get_claude_service, QuotaExceededError
        claude = await get_claude_service()
        if not getattr(claude, "is_configured", False):
            return {
                "reply": "I'm offline — the AI backend isn't configured. Edit nodes manually for now.",
                "mutations": [],
                "rejected": [],
                "source": "error",
            }
        result = await claude.complete(
            tenant_id=tenant_id,
            prompt=user_prompt,
            system=system,
            max_tokens=2000,
            temperature=0.2,
            request_type="riggs_vpe_assist",
            user_id=user_id,
        )
    except QuotaExceededError:
        return {
            "reply": "Your AI token quota is exhausted for this period — try again next cycle.",
            "mutations": [],
            "rejected": [],
            "source": "error",
        }
    except Exception as exc:
        logger.exception(f"VPE assist LLM call failed: {exc}")
        return {
            "reply": "I hit a backend error. Try again in a moment.",
            "mutations": [],
            "rejected": [],
            "source": "error",
        }

    text = _strip_code_fences(result.text or "")
    try:
        payload = json.loads(text)
    except Exception:
        logger.warning(f"VPE assist returned non-JSON: {text[:200]}")
        return {
            "reply": text[:500] if text else "I couldn't structure a response.",
            "mutations": [],
            "rejected": ["non-JSON response"],
            "source": "error",
        }

    reply = (payload.get("reply") or "").strip() or "Done."
    raw_mutations = payload.get("mutations") or []
    if not isinstance(raw_mutations, list):
        raw_mutations = []

    kept, rejected = _validate_mutations(
        raw_mutations, existing_node_ids, existing_edge_ids
    )

    if rejected:
        logger.info(
            f"VPE assist: applied {len(kept)} of {len(raw_mutations)} mutations; "
            f"rejected: {rejected}"
        )

    return {
        "reply": reply,
        "mutations": kept,
        "rejected": rejected,
        "source": "llm",
    }
