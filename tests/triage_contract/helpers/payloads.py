"""Canned alert payloads for triage contract tests.

Every payload embeds:
  metadata.test_marker = TEST_MARKER  (for cleanup)
  metadata.test_id     = unique per-test id (for retrieval)

Add new payload shapes here as we expand the test matrix.
"""
from __future__ import annotations

import uuid
from typing import Any

from .droplet import TEST_MARKER


def _new_test_id(label: str) -> str:
    return f"{label}-{uuid.uuid4().hex[:12]}"


def _envelope(label: str, **fields: Any) -> tuple[str, dict[str, Any]]:
    """Build a webhook payload with required test markers. Returns (test_id, payload)."""
    test_id = _new_test_id(label)
    payload = {
        **fields,
        "metadata": {
            "test_marker": TEST_MARKER,
            "test_id": test_id,
            **fields.get("metadata", {}),
        },
    }
    return test_id, payload


def benign_low_severity() -> tuple[str, dict[str, Any]]:
    """The kind of alert fast_triage should auto-close.

    No IOCs, low severity, informational language. Should land in `closed`
    with disposition='benign' (or similar) per the contract.
    """
    return _envelope(
        "benign",
        title="Routine login from known device",
        description="User authenticated from a previously seen workstation. No anomalies detected.",
        severity="low",
        source="windows_event_log",
        category="authentication",
        raw_log='EventID=4624 LogonType=2 User="alice" Workstation="ALICE-PC" Status=Success',
    )


def malicious_with_iocs() -> tuple[str, dict[str, Any]]:
    """The kind of alert that should escalate to an investigation + Riggs.

    High severity, multiple IOCs, malware language.
    """
    return _envelope(
        "malicious",
        title="Beaconing detected to known C2 infrastructure",
        description=(
            "Endpoint EDR observed repeated outbound connections from PID 4488 (powershell.exe) "
            "to 185.220.101.42 over port 443 every 60 seconds. Domain resolves to known Cobalt "
            "Strike infrastructure. SHA256 of binary: "
            "deadbeef1234deadbeef1234deadbeef1234deadbeef1234deadbeef1234dead"
        ),
        severity="critical",
        source="crowdstrike_falcon",
        category="command_and_control",
        raw_log=(
            "process=powershell.exe pid=4488 user=SYSTEM "
            "remote_ip=185.220.101.42 remote_port=443 "
            "domain=evil-c2-domain.tk "
            "sha256=deadbeef1234deadbeef1234deadbeef1234deadbeef1234deadbeef1234dead"
        ),
    )


def edr_behavioral_no_iocs() -> tuple[str, dict[str, Any]]:
    """Behavioral EDR alert with no IOCs in title/description.

    Tests that fast_triage's heuristic fallback does NOT auto-close
    just because IOC count is low. (Gap 4 in our analysis.)
    """
    return _envelope(
        "behavioral",
        title="Process injection technique observed",
        description=(
            "EDR detected CreateRemoteThread targeting lsass.exe from an unsigned binary "
            "in user temp directory. Behavior matches T1055.001."
        ),
        severity="high",
        source="sentinelone",
        category="defense_evasion",
        raw_log="parent_process=temp_loader.exe target_process=lsass.exe technique=process_injection",
    )


def informational_noise() -> tuple[str, dict[str, Any]]:
    """The kind of alert that should be auto-closed as informational."""
    return _envelope(
        "info",
        title="Daily backup completed successfully",
        description="Scheduled backup job finished without errors.",
        severity="low",
        source="backup_service",
        category="informational",
        raw_log="job=daily_backup status=success duration=42m",
    )


def mixed_batch_of_ten() -> list[tuple[str, dict[str, Any]]]:
    """Ten alerts spanning the contract surface, for the invariant test."""
    return [
        benign_low_severity(),
        benign_low_severity(),
        informational_noise(),
        informational_noise(),
        malicious_with_iocs(),
        malicious_with_iocs(),
        edr_behavioral_no_iocs(),
        edr_behavioral_no_iocs(),
        benign_low_severity(),
        malicious_with_iocs(),
    ]
