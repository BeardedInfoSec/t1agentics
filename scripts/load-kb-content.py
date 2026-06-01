#!/usr/bin/env python3
# Copyright (c) 2025-2026 T1 Agentics LLC. SPDX-License-Identifier: Apache-2.0
"""
Load KB articles from kb-content-output/ into the database via API.

Usage:
    python scripts/load-kb-content.py [--base-url http://localhost:8000] [--token TOKEN]

Or run inside the backend container:
    python /app/scripts/load-kb-content.py --base-url http://localhost:8000 --token <admin-jwt>
"""

import os
import sys
import json
import glob
import argparse
import requests

def main():
    parser = argparse.ArgumentParser(description="Load KB articles into T1 Agentics")
    parser.add_argument("--base-url", default="http://localhost:8000",
                        help="Backend API base URL")
    parser.add_argument("--token", required=True,
                        help="Admin JWT token for authentication")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print what would be loaded without actually loading")
    parser.add_argument("--dir", default=None,
                        help="Override KB content directory")
    args = parser.parse_args()

    # Find content directory
    if args.dir:
        content_dir = args.dir
    else:
        # Try relative to script location
        script_dir = os.path.dirname(os.path.abspath(__file__))
        project_root = os.path.dirname(script_dir)
        content_dir = os.path.join(project_root, "kb-content-output", "articles")

    if not os.path.isdir(content_dir):
        print(f"Error: Content directory not found: {content_dir}")
        sys.exit(1)

    # Scan for JSON files
    pattern = os.path.join(content_dir, "**", "*.json")
    files = sorted(glob.glob(pattern, recursive=True))

    if not files:
        print(f"No JSON files found in {content_dir}")
        sys.exit(1)

    print(f"Found {len(files)} KB articles to load")
    print(f"Target: {args.base_url}")
    print()

    headers = {
        "Authorization": f"Bearer {args.token}",
        "Content-Type": "application/json",
    }

    success = 0
    skipped = 0
    failed = 0

    for filepath in files:
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                article = json.load(f)
        except Exception as e:
            print(f"  SKIP (bad JSON): {filepath}: {e}")
            failed += 1
            continue

        title = article.get("title", "Untitled")
        category = article.get("category", "general")
        rel_path = os.path.relpath(filepath, content_dir)

        if args.dry_run:
            print(f"  DRY: {rel_path} -> {title}")
            success += 1
            continue

        # Check if article already exists (by title)
        try:
            check_url = f"{args.base_url}/api/v1/knowledge-base/?search={requests.utils.quote(title)}&limit=1"
            check_resp = requests.get(check_url, headers=headers, timeout=10)
            if check_resp.ok:
                data = check_resp.json()
                items = data.get("items") or data.get("articles") or []
                if any(item.get("title") == title for item in items):
                    print(f"  SKIP (exists): {title}")
                    skipped += 1
                    continue
        except Exception:
            pass  # If check fails, try to insert anyway

        # POST the article
        payload = {
            "title": title,
            "content": article.get("content", ""),
            "content_type": article.get("content_type", "sop"),
            "category": category,
            "subcategory": article.get("subcategory"),
            "tags": article.get("tags", []),
            "severity_filter": article.get("severity_filter", []),
            "incident_types": article.get("incident_types", []),
            "ioc_types": article.get("ioc_types", []),
            "mitre_techniques": article.get("mitre_techniques", []),
            "compliance_frameworks": article.get("compliance_frameworks", []),
            "priority": article.get("priority", 50),
            "status": "approved",  # Auto-approve seed content
        }

        try:
            resp = requests.post(
                f"{args.base_url}/api/v1/knowledge-base/",
                headers=headers,
                json=payload,
                timeout=30,
            )
            if resp.ok:
                print(f"  OK: [{category}] {title}")
                success += 1
            else:
                detail = resp.json().get("detail", resp.text[:100]) if resp.text else "Unknown error"
                print(f"  FAIL ({resp.status_code}): {title} — {detail}")
                failed += 1
        except Exception as e:
            print(f"  ERROR: {title} — {e}")
            failed += 1

    print()
    print(f"Done! Loaded: {success}, Skipped: {skipped}, Failed: {failed}")


if __name__ == "__main__":
    main()
