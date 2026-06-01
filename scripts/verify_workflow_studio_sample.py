# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

import json
from pathlib import Path


def main() -> None:
    sample_path = Path(__file__).resolve().parents[1] / "playbook_examples" / "t1agentics" / "workflow_studio_sample.json"
    data = json.loads(sample_path.read_text(encoding="utf-8"))
    canvas = data.get("canvas_data", {})
    nodes = canvas.get("nodes", [])
    edges = canvas.get("edges", [])

    node_ids = {node.get("id") for node in nodes}
    missing_nodes = [edge for edge in edges if edge.get("source") not in node_ids or edge.get("target") not in node_ids]
    if missing_nodes:
        raise SystemExit(f"Edges reference missing nodes: {missing_nodes}")

    python_nodes = [node for node in nodes if node.get("data", {}).get("kind") == "python_code"]
    for node in python_nodes:
        inputs = node.get("data", {}).get("config", {}).get("inputs", [])
        if not isinstance(inputs, list):
            raise SystemExit(f"Python node {node.get('id')} inputs is not a list")
        for entry in inputs:
            if not entry.get("key") or not entry.get("path"):
                raise SystemExit(f"Python node {node.get('id')} has invalid input entry: {entry}")

    print("Workflow Studio sample verification passed.")
    print(f"Nodes: {len(nodes)} | Edges: {len(edges)} | Python nodes: {len(python_nodes)}")


if __name__ == "__main__":
    main()
