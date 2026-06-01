/**
/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

const SEVERITY_CONFIG = {
  critical: { color: '#ef4444' },
  high: { color: '#f59e0b' },
  medium: { color: '#38bdf8' },
  low: { color: '#22c55e' }
};

function generateAutomationData() {
  return [
    { day: 'Mon', automated: 0, manual: 0 },
    { day: 'Tue', automated: 0, manual: 0 },
    { day: 'Wed', automated: 0, manual: 0 },
    { day: 'Thu', automated: 0, manual: 0 },
    { day: 'Fri', automated: 0, manual: 0 },
    { day: 'Sat', automated: 0, manual: 0 },
    { day: 'Sun', automated: 0, manual: 0 }
  ];
}

function getRecentAlerts(stats) {
  const alerts = stats?.recent_alerts || [];

  return alerts.slice(0, 8).map((alert) => {
    const severity = (alert.severity || 'medium').toLowerCase();
    const config = SEVERITY_CONFIG[severity] || SEVERITY_CONFIG.medium;

    let timeAgo = 'Unknown';
    if (alert.created_at) {
      const created = new Date(alert.created_at);
      const now = new Date();
      const diffMs = now - created;
      const diffMins = Math.floor(diffMs / 60000);
      const diffHours = Math.floor(diffMins / 60);
      const diffDays = Math.floor(diffHours / 24);

      if (diffMins < 1) timeAgo = 'Just now';
      else if (diffMins < 60) timeAgo = `${diffMins}m ago`;
      else if (diffHours < 24) timeAgo = `${diffHours}h ago`;
      else timeAgo = `${diffDays}d ago`;
    }

    // Server now computes effective_state (closes/resolutions on either the
    // alert or investigation roll up to CLOSED). Fall back to the older
    // resolution chain only for backward compatibility with cached payloads.
    const stateLabel =
      alert.effective_state || alert.investigation_state || alert.status || null;
    const dispositionLabel = alert.investigation_disposition || null;

    // ai_confidence may come back as a 0–1 decimal (some paths) or 0–100
    // percentage (the alert column is CHECK 0..100). Normalize to whole-
    // number percent for display.
    let aiConfidence = null;
    if (alert.ai_confidence != null) {
      const n = Number(alert.ai_confidence);
      if (!Number.isNaN(n)) {
        aiConfidence = n <= 1 ? Math.round(n * 100) : Math.round(n);
      }
    }

    return {
      id: alert.alert_id || alert.id || null,
      alert_id: alert.alert_id || null,
      investigation_id: alert.investigation_id || null,
      title: alert.title || alert.name || 'Untitled Alert',
      severity: severity.charAt(0).toUpperCase() + severity.slice(1),
      severityColor: config.color,
      source: alert.source || null,
      status: alert.status || null,
      state: stateLabel,
      assignee: alert.investigation_owner || null,
      disposition: dispositionLabel,
      ai_confidence: aiConfidence,
      time: timeAgo,
      created_at: alert.created_at || null,
    };
  });
}

export { generateAutomationData, getRecentAlerts };
