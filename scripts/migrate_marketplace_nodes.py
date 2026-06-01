#!/usr/bin/env python3
"""
Migrate all 120 marketplace template JSON files from old node types to new
consolidated node system.

Old types → New types:
  - riggs_analyze → analyze (mode: ai_analysis)
  - enrich        → analyze (mode: enrich)
  - action        → respond (response_type: integration_action)
  - notify        → respond (response_type: notify)
  - create_ticket → respond (response_type: create_ticket)
  - condition     → decision (unchanged kind, just rename type field)

Also converts from old format (type on node root, label in data)
to new format (type=signal, kind+title+config in data).
"""
import json
import os
import sys
import uuid
from pathlib import Path

STORE_DIR = Path(__file__).parent.parent / "playbook-store-output" / "playbooks"

# Map old node type → new kind + how to build config
TYPE_MAP = {
    "trigger": "trigger",
    "condition": "decision",
    "decision": "decision",
    "end": "end",
    "approval": "approval",
    "approval_gate": "approval",
    "loop": "loop",
    "delay": "delay",
    "subflow": "subflow",
    "code": "code",
    "utility": "utility",
    # Consolidated types
    "riggs_analyze": "analyze",
    "enrich": "analyze",
    "action": "respond",
    "integration": "respond",
    "notify": "respond",
    "create_ticket": "respond",
    "webhook_call": "respond",
}


def migrate_node(node):
    """Convert a single node to the new format."""
    old_type = node.get("type", "action")
    old_data = node.get("data", {})
    old_config = old_data.get("config", {})
    old_label = old_data.get("label", old_type.replace("_", " ").title())

    new_kind = TYPE_MAP.get(old_type, "respond")
    new_config = dict(old_config)

    # Inject discriminator fields based on old type
    if old_type == "riggs_analyze":
        new_config["mode"] = "ai_analysis"
        new_config.setdefault("prompt", "")
        new_config.setdefault("alert_path", "$.trigger.alert")
        new_config.setdefault("focus", "threat_assessment")
        new_config.setdefault("include_context", True)
    elif old_type == "enrich":
        new_config["mode"] = "enrich"
        new_config.setdefault("observable_type", "ip")
        new_config.setdefault("observable_path", "$.trigger.alert.src_ip")
        new_config.setdefault("sources", ["virustotal"])
        new_config.setdefault("aggregate_results", True)
    elif old_type == "notify":
        new_config["response_type"] = "notify"
        new_config.setdefault("channel", "slack")
        new_config.setdefault("slack_channel", "")
        new_config.setdefault("message", "")
    elif old_type == "create_ticket":
        new_config["response_type"] = "create_ticket"
        new_config.setdefault("system", "jira")
        new_config.setdefault("project_key", "")
        new_config.setdefault("title", "")
        new_config.setdefault("description", "")
        new_config.setdefault("priority", "medium")
    elif old_type in ("action", "integration", "webhook_call"):
        new_config["response_type"] = "integration_action"
        new_config.setdefault("integration_instance_id", "")
        new_config.setdefault("endpoint_id", old_config.get("action_type", ""))
        new_config.setdefault("params", {})
        new_config.setdefault("requires_approval", True)
        new_config.setdefault("priority", "medium")
    elif old_type in ("condition", "decision"):
        new_config.setdefault("expression", old_config.get("expression", ""))
        new_config.setdefault("branches", [
            {"id": "yes", "label": "Yes"},
            {"id": "no", "label": "No"},
        ])
    elif old_type == "trigger":
        new_config.setdefault("trigger_type", "alert")
    elif old_type == "end":
        new_config.setdefault("disposition", "completed")

    # Build new node in standard format
    return {
        "id": node.get("id", str(uuid.uuid4())),
        "type": "signal",
        "position": node.get("position", {"x": 0, "y": 0}),
        "data": {
            "kind": new_kind,
            "title": old_label,
            "summary": old_data.get("description", ""),
            "config": new_config,
        },
    }


def migrate_edge(edge):
    """Normalize edge format."""
    new_edge = {
        "id": edge.get("id", str(uuid.uuid4())),
        "source": edge["source"],
        "target": edge["target"],
        "animated": True,
        "type": "smoothstep",
    }
    # Convert old condition handles (true/false → yes/no)
    sh = edge.get("sourceHandle")
    if sh == "true":
        sh = "yes"
    elif sh == "false":
        sh = "no"
    if sh:
        new_edge["sourceHandle"] = sh
        label_map = {"yes": "Yes", "no": "No", "true": "Yes", "false": "No"}
        new_edge["data"] = {"label": label_map.get(sh, sh)}
    return new_edge


def migrate_file(filepath):
    """Migrate a single template JSON file."""
    with open(filepath, "r", encoding="utf-8") as f:
        template = json.load(f)

    canvas = template.get("canvas_data", {})
    old_nodes = canvas.get("nodes", [])
    old_edges = canvas.get("edges", [])

    new_nodes = [migrate_node(n) for n in old_nodes]
    new_edges = [migrate_edge(e) for e in old_edges]

    template["canvas_data"] = {"nodes": new_nodes, "edges": new_edges}

    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(template, f, indent=2, ensure_ascii=False)
        f.write("\n")

    return len(new_nodes)


def main():
    if not STORE_DIR.exists():
        print(f"ERROR: Store directory not found: {STORE_DIR}")
        sys.exit(1)

    files = sorted(STORE_DIR.rglob("*.json"))
    print(f"Migrating {len(files)} marketplace templates...")

    total_nodes = 0
    for i, fp in enumerate(files, 1):
        try:
            count = migrate_file(fp)
            total_nodes += count
            print(f"  [{i:3d}/{len(files)}] {fp.relative_to(STORE_DIR)} ({count} nodes)")
        except Exception as e:
            print(f"  [{i:3d}/{len(files)}] FAILED {fp.name}: {e}")

    print(f"\nDone! Migrated {len(files)} templates ({total_nodes} total nodes)")


if __name__ == "__main__":
    main()
