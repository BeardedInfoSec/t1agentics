"""Walk every file in /tmp/playbook_examples through the matching converter.

Run inside the t1agentics-backend container after staging the examples.
Reports success / failure / step counts per file so we can see which
conversions land cleanly and which need work.
"""

import os
import sys
import json
import traceback

sys.path.insert(0, "/app")

from services.playbook_converters import (
    SplunkSOARConverter, XSOARConverter, TinesConverter, SwimlaneConverter,
    BlinkOpsConverter,
)

# Map test files → (converter, friendly label)
TESTS = [
    # XSOAR — the bug Aaron hit
    ("/tmp/playbook_examples/xsoar/IP_Enrichment_-_Generic_v2.yml",       XSOARConverter,        "XSOAR · IP Enrichment Generic v2"),
    ("/tmp/playbook_examples/xsoar/Entity_Enrichment_-_Phishing_v2.yml",  XSOARConverter,        "XSOAR · Entity Enrichment Phishing v2"),
    ("/tmp/playbook_examples/xsoar/Phishing_-_Core_v2.yml",               XSOARConverter,        "XSOAR · Phishing Core v2"),
    ("/tmp/playbook_examples/xsoar/Block_Indicators_-_Generic_v3.yml",    XSOARConverter,        "XSOAR · Block Indicators Generic v3"),
    # Tines
    ("/tmp/playbook_examples/tines/Tag AWS resources based on Cyera data classification findings.json", TinesConverter, "Tines · Cyera AWS tagging"),
    # Splunk SOAR (paired JSON+PY — JSON test only)
    ("/tmp/playbook_examples/splunk_soar/automation/Cisco External Dynamic ACL Updates.json", SplunkSOARConverter, "Splunk SOAR · Cisco EDL"),
    ("/tmp/playbook_examples/splunk_soar/automation/testin_snow_to_ES.json",                  SplunkSOARConverter, "Splunk SOAR · SNOW to ES"),
    ("/tmp/playbook_examples/splunk_soar/automation/custome_code_playbook.json",              SplunkSOARConverter, "Splunk SOAR · Custom Code"),
    ("/tmp/playbook_examples/splunk_soar/input/AD_LDAP_Account_Locking.json",                 SplunkSOARConverter, "Splunk SOAR · AD Account Lock"),
    # Swimlane
    ("/tmp/playbook_examples/swimlane/greynoise_integration/greynoise_ip_lookup.json",       SwimlaneConverter,    "Swimlane · GreyNoise IP Lookup"),
    ("/tmp/playbook_examples/swimlane/greynoise_integration/greynoise_context_lookup.json",  SwimlaneConverter,    "Swimlane · GreyNoise Context"),
    # BlinkOps
    ("/tmp/playbook_examples/blinkops/blink_api_swagger.yaml",                                BlinkOpsConverter,    "BlinkOps · Swagger sample"),
]


def short(s, n=100):
    s = str(s)
    return s if len(s) <= n else s[: n - 3] + "..."


def run_one(path, ConverterCls, label):
    if not os.path.exists(path):
        return {"label": label, "ok": False, "error": "file not found", "path": path}

    size = os.path.getsize(path)
    if size == 0:
        return {"label": label, "ok": False, "error": "file is empty (0 bytes)", "path": path, "size": 0}

    try:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
    except Exception as e:
        return {"label": label, "ok": False, "error": f"read failed: {e}", "path": path}

    try:
        converter = ConverterCls()
        native, report = converter.convert(content)
    except Exception as e:
        return {
            "label": label,
            "ok": False,
            "size": size,
            "error": f"{type(e).__name__}: {e}",
            "trace": traceback.format_exc().splitlines()[-5:],
        }

    return {
        "label": label,
        "ok": bool(report.success),
        "size": size,
        "name": getattr(native, "name", "?"),
        "total_steps": report.total_steps,
        "converted_steps": report.converted_steps,
        "skipped": len(report.skipped_steps),
        "warnings": len(report.warnings),
        "unmapped": len(report.unmapped_actions),
        "time_ms": round(report.conversion_time_ms, 1),
        "first_skip": short(report.skipped_steps[0].reason) if report.skipped_steps else None,
        "first_warn": short(report.warnings[0]) if report.warnings else None,
    }


def main():
    print()
    print("Playbook conversion smoke test")
    print("=" * 78)
    results = []
    for path, ConverterCls, label in TESTS:
        r = run_one(path, ConverterCls, label)
        results.append(r)
        status = "PASS" if r["ok"] else "FAIL"
        print(f"\n[{status}] {r['label']}")
        if not r["ok"]:
            print(f"  ERROR: {r.get('error')}")
            if "trace" in r:
                for line in r["trace"]:
                    print(f"  {line}")
            continue
        print(f"  name:       {r['name']}")
        print(f"  size:       {r['size']:>7,} bytes")
        print(f"  total:      {r['total_steps']:>5} steps in source")
        print(f"  converted:  {r['converted_steps']:>5} steps mapped to T1")
        print(f"  skipped:    {r['skipped']:>5}  warnings: {r['warnings']}  unmapped: {r['unmapped']}")
        print(f"  time:       {r['time_ms']} ms")
        if r["first_skip"]:
            print(f"  first skip: {r['first_skip']}")
        if r["first_warn"]:
            print(f"  first warn: {r['first_warn']}")

    print()
    print("=" * 78)
    n_pass = sum(1 for r in results if r["ok"])
    n_fail = len(results) - n_pass
    print(f"Summary: {n_pass} passed, {n_fail} failed")


if __name__ == "__main__":
    main()
