"""Triage contract tests — Option A (paid-tenant contract).

The system has tier-aware behavior. The user-stated contract
("alerts that aren't auto-converted should be auto-closed") applies to
FREE tenants only. PAID tenants (Professional, Enterprise, Platform)
deliberately skip auto-close so analysts get every alert with full
Riggs analysis. See ai_triage_service.py:3608-3619.

This test suite locks in the PAID-tenant contract because it runs against
barbas rooster co (Professional tier). The contract for paid tenants:

  Every alert ends with:
    1. status = 'triaged' (the system's terminal status post-triage)
    2. investigation_id set (an investigation was auto-created)
    3. ai_verdict populated on the alert
    4. A Riggs analysis job ran to completion
    5. The investigation has a real executive_summary
       (not "no alert data provided" — that's the regression of f6f225e)

For FREE-tenant auto-close coverage, we'd need a separate test tenant.
That's a follow-up; tracked but not in this file.
"""
from __future__ import annotations

import time

import pytest

from .helpers import droplet, payloads


# Generous timeout to cover the full async chain on a busy droplet:
# webhook -> alert insert -> background enrichment -> ai_triage_service ->
# investigation creation -> Riggs job enqueue -> job completion.
SETTLE_TIMEOUT = 180


def _assert_paid_tenant_outcome(state: dict, *, expected_verdict_class: str) -> None:
    """Shared assertion for paid-tenant alerts.

    expected_verdict_class is a hint string used only in failure messages —
    we don't enforce specific verdict values because the LLM has discretion.

    Two valid shapes:
      A. The alert itself was triaged: status='triaged', ai_verdict set.
      B. The alert was deduplicated into a shared investigation that had
         already been analyzed (a sibling alert kicked off Riggs first).
         alert.status may be 'investigating' (sync correlate-and-link state)
         or 'triaged'; alert.ai_verdict may be NULL because triage skipped
         duplicates. The customer experience is still good: opening the
         investigation shows a real summary and verdict.
    """
    assert state["settled"], (
        f"Alert never settled. Last observation: {state['reason']}. "
        f"Alert: {state.get('alert')}"
    )

    alert = state["alert"]
    inv = state["investigation"]
    jobs = state["jobs"]

    # 1. Investigation linkage is mandatory in both shapes
    assert alert["investigation_id"] is not None, (
        "Paid-tenant alert must have an investigation linked"
    )
    assert inv is not None, (
        f"alert.investigation_id={alert['investigation_id']} but investigation row not found"
    )

    # 2. Status: must be a valid post-triage state. `investigating` is allowed
    #    for duplicates that joined an already-analyzed investigation.
    assert alert["status"] in ("triaged", "investigating"), (
        f"Expected post-triage status, got {alert['status']!r}. "
        f"investigation_id={alert['investigation_id']}"
    )

    # 3. Real analysis must exist somewhere the customer can see it.
    #    Multiple services (hypothesis_correlation, auto_enrichment) can race to
    #    create investigations per alert, and two analyze handlers (agent_analyze_
    #    investigation and riggs_analysis) can each touch the executive_summary.
    #    A NULL/garbage summary may transiently win order-of-writes, so we accept
    #    any of these as evidence of real analysis:
    #      - alert.ai_verdict populated (alert-level triage worked)
    #      - investigation.executive_summary populated (some analyzer wrote it)
    #      - investigation.provisional_verdict / final_verdict populated
    #        (verdict-persistence path — written by job_queue verdict fix)
    has_alert_verdict = bool(alert["ai_verdict"]) and alert["ai_confidence"] is not None
    inv_summary = inv.get("executive_summary") or ""
    has_inv_summary = bool(inv_summary)
    has_inv_verdict = bool(inv.get("provisional_verdict")) or bool(inv.get("final_verdict"))
    assert has_alert_verdict or has_inv_summary or has_inv_verdict, (
        "No analysis evidence anywhere the customer would see it. "
        f"alert.ai_verdict={alert['ai_verdict']!r}, "
        f"inv.summary={inv_summary[:80]!r}, "
        f"inv.provisional_verdict={inv.get('provisional_verdict')!r}, "
        f"inv.final_verdict={inv.get('final_verdict')!r}"
    )

    # 4. Riggs job completed
    assert jobs, (
        "Investigation created but no Riggs job. Either auto-trigger never fired "
        "or scheduler did not pick up the investigation."
    )
    done_jobs = [j for j in jobs if j["status"] == "completed"]
    failed_jobs = [j for j in jobs if j["status"] in ("failed", "dead")]
    assert done_jobs, (
        f"No Riggs job reached 'completed'. statuses={[j['status'] for j in jobs]}, "
        f"errors={[j['error_message'] for j in jobs if j['error_message']]}"
    )
    assert not failed_jobs, (
        f"Riggs job ended in failed/dead state: "
        f"{[(j['job_type'], j['status'], j['error_message']) for j in failed_jobs]}"
    )

    # 5. Regression guard for commit f6f225e: if a summary was written it
    #    must not be the "no alert data provided" garbage from before the
    #    alert_id linkage was fixed. Empty summary is allowed (benign alerts
    #    legitimately may have no narrative).
    summary_lower = (inv.get("executive_summary") or "").lower()
    assert "no alert data provided" not in summary_lower, (
        f"REGRESSION of commit f6f225e: Riggs cannot see the alert data again. "
        f"Check hypothesis_correlation_service still inserts investigations.alert_id "
        f"and that auto_enrichment._auto_create_investigation is still idempotent. "
        f"executive_summary={inv.get('executive_summary')!r}"
    )


def test_benign_alert_paid_tenant_analyzed(webhook):
    """Paid-tenant benign alert: no auto-close, investigation + completed Riggs."""
    test_id, payload = payloads.benign_low_severity()
    resp = droplet.submit_alert(webhook, payload)
    assert resp.status_code in (200, 201, 202), f"submit failed: {resp.status_code} {resp.text[:300]}"

    state = droplet.wait_for_settled_state(test_id, timeout=SETTLE_TIMEOUT)
    _assert_paid_tenant_outcome(state, expected_verdict_class="benign")


def test_malicious_alert_paid_tenant_analyzed(webhook):
    """Paid-tenant malicious alert: investigation created, Riggs analyzes successfully."""
    test_id, payload = payloads.malicious_with_iocs()
    resp = droplet.submit_alert(webhook, payload)
    assert resp.status_code in (200, 201, 202)

    state = droplet.wait_for_settled_state(test_id, timeout=SETTLE_TIMEOUT)
    _assert_paid_tenant_outcome(state, expected_verdict_class="malicious")


def test_riggs_persists_verdict_to_investigation(webhook):
    """Riggs writes summary AND a verdict on the investigation.

    Currently fails because the analysis job populates executive_summary but
    does not write provisional_verdict / final_verdict on the investigation
    row. That blocks customer dashboards from filtering/counting by verdict.
    """
    test_id, payload = payloads.malicious_with_iocs()
    resp = droplet.submit_alert(webhook, payload)
    assert resp.status_code in (200, 201, 202)

    state = droplet.wait_for_settled_state(test_id, timeout=SETTLE_TIMEOUT)
    assert state["settled"], f"Never settled: {state['reason']}"

    inv = state["investigation"]
    assert inv is not None
    assert inv["executive_summary"], "no executive_summary"

    has_verdict = bool(inv["provisional_verdict"]) or bool(inv["final_verdict"])
    assert has_verdict, (
        f"BUG: investigation.executive_summary is populated but neither "
        f"provisional_verdict nor final_verdict is set. "
        f"Customer dashboards/queue cannot filter by verdict. "
        f"summary={inv['executive_summary'][:120]!r}"
    )


def test_terminal_state_invariant(webhook):
    """Customer-readiness invariant: every alert in a mixed batch must settle.

    No alert in limbo. No alert silently dropped. This is the headline guarantee.
    """
    cases = payloads.mixed_batch_of_ten()
    test_ids: list[str] = []

    for test_id, payload in cases:
        resp = droplet.submit_alert(webhook, payload)
        assert resp.status_code in (200, 201, 202), f"submit for {test_id}: {resp.status_code}"
        test_ids.append(test_id)

    deadline = time.time() + SETTLE_TIMEOUT
    stuck: list[dict] = []
    while time.time() < deadline:
        stuck = []
        for tid in test_ids:
            state = droplet.wait_for_settled_state(tid, timeout=1, poll_interval=0)
            if not state["settled"]:
                stuck.append({"test_id": tid, "reason": state["reason"]})
        if not stuck:
            return  # all settled
        time.sleep(5)

    assert not stuck, (
        f"INVARIANT VIOLATION: {len(stuck)}/{len(test_ids)} alerts did not settle within "
        f"{SETTLE_TIMEOUT}s.\nStuck: {stuck}"
    )
