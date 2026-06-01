/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

/**
 * SecurityQueue Data Transformations
 *
 * Pure, centralized transformation logic.
 * All alerts and investigations are normalized to SecurityQueueItem here.
 * This is called ONCE in useSecurityQueue - UI code never touches raw backend objects.
 */

/**
 * SLA thresholds in minutes by severity
 */
const SLA_BY_SEVERITY = {
  critical: 60,    // 1 hour
  high:     240,   // 4 hours
  medium:   480,   // 8 hours
  low:      1440,  // 24 hours
};

/**
 * Calculate SLA for any queue item (alert or investigation).
 * @param {Object} item - Raw alert or investigation from API
 * @returns {Object} { status, remaining, threshold }
 */
function calculateSLA(item) {
  const created = new Date(item.created_at);
  const severity = (item.severity || 'medium').toLowerCase();
  const threshold = SLA_BY_SEVERITY[severity] || SLA_BY_SEVERITY.medium;

  const isClosed = ['closed', 'resolved', 'false_positive', 'confirmed', 'CLOSED', 'RESOLVED'].includes(
    item.state || item.status
  );

  // For closed items, measure how long it actually took to close (frozen at close time).
  // Prefer the dedicated close timestamps over updated_at, which can drift forward
  // when downstream services touch the row (enrichment, status sync, etc.) and
  // would otherwise falsely flag fast-closed items as breached.
  // For open items, measure age against now.
  const endpoint = isClosed
    ? new Date(item.closed_at || item.completed_at || item.resolved_at || item.updated_at || item.created_at)
    : new Date();
  const minutesElapsed = Math.max(0, Math.floor((endpoint - created) / (1000 * 60)));
  const remaining = Math.max(threshold - minutesElapsed, 0);

  let status;
  if (isClosed) {
    status = minutesElapsed <= threshold ? 'met' : 'exceeded';
  } else if (remaining <= 0) {
    status = 'exceeded';
  } else if (remaining <= 60) {
    status = 'at_risk';
  } else {
    status = 'ok';
  }

  return { status, remaining, threshold };
}

/**
 * Normalize an alert to SecurityQueueItem
 * @param {Object} alert - Raw alert object from API
 * @returns {import('./types').SecurityQueueItem}
 */
export function normalizeAlert(alert) {
  const sla = calculateSLA(alert);

  return {
    queue_id: `alert-${alert.alert_id || alert.id}`,
    item_type: 'alert',

    alert_id: alert.alert_id || alert.id,
    investigation_id: null,

    title: alert.title || 'Untitled Alert',
    severity: (alert.severity || 'medium').toLowerCase(),
    status: alert.status || 'open',
    created_at: alert.created_at,
    updated_at: alert.updated_at,
    closed_at: alert.closed_at || null,
    source: alert.source || 'unknown',

    // Alert-specific fields
    enrichment_status: alert.enrichment_status,
    ai_confidence: alert.ai_confidence,
    ai_verdict: alert.ai_verdict,

    // Sensitivity
    sensitivity: alert.sensitivity || 'internal',

    // Investigation fields (use ai_verdict as disposition for alerts)
    disposition: alert.ai_verdict || null,
    priority: null,
    owner: null,
    sla,
    executive_summary: null,

    // Correlation metadata
    correlation_count: alert.correlation_count || 0,
    correlation_group: alert.correlation_group || null,
    correlation_score: alert.correlation_score || null,

    // Context for expanded view
    alert_context: alert,
    investigation_context: null,
  };
}

/**
 * Normalize an investigation to SecurityQueueItem
 * @param {Object} inv - Raw investigation object from API
 * @param {Object} [sourceAlert] - Optional source alert object
 * @returns {import('./types').SecurityQueueItem}
 */
export function normalizeInvestigation(inv, sourceAlert = null, childAlerts = []) {
  // For SLA we prefer completed_at from the investigation; if missing, fall back
  // to the underlying alert's closed_at so legacy auto-resolved items don't
  // appear breached just because no one stamped completed_at on the inv row.
  const slaInput = {
    ...inv,
    closed_at: inv.completed_at || sourceAlert?.closed_at || inv.closed_at || null,
  };
  const sla = calculateSLA(slaInput);

  return {
    queue_id: `inv-${inv.investigation_id || inv.id}`,
    item_type: 'investigation',

    alert_id: sourceAlert?.alert_id || inv.alert_id,
    investigation_id: inv.investigation_id || inv.id,

    title: inv.alert_title || sourceAlert?.title || 'Untitled Investigation',
    severity: (inv.severity || sourceAlert?.severity || 'medium').toLowerCase(),
    status: inv.state || 'NEW',  // Use investigation state as status
    created_at: inv.created_at,
    updated_at: inv.updated_at,
    closed_at: inv.completed_at || sourceAlert?.closed_at || null,
    source: inv.source || inv.alert_source || sourceAlert?.source || sourceAlert?.alert_source || 'unknown',

    // Sensitivity
    sensitivity: inv.sensitivity || sourceAlert?.sensitivity || 'internal',

    // Investigation-specific fields
    disposition: inv.disposition,
    priority: inv.priority || 'P3',
    owner: inv.owner,
    sla,
    executive_summary: inv.executive_summary,

    // Alert fields (inherit from source alert if available)
    enrichment_status: sourceAlert?.enrichment_status,
    ai_confidence: sourceAlert?.ai_confidence || inv.ai_confidence,
    ai_verdict: sourceAlert?.ai_verdict,

    // Correlation metadata
    // correlation_count = how many alert children this investigation has.
    // Prefer the actual count from the joined alerts list; fall back to any
    // server-provided count or per-alert hint.
    correlation_count: childAlerts.length || inv.correlated_alert_count || (sourceAlert?.correlation_count) || 0,
    correlation_group: inv.correlation_group || null,
    correlation_score: inv.correlation_score || null,

    // True if ANY child alert has a non-benign verdict AND is still active —
    // drives the red M-badge in the queue. Resolved / closed alerts are
    // excluded even if the AI's last verdict was "NEEDS_INVESTIGATION"
    // (low confidence): the analyst has already disposed of them, so they
    // shouldn't keep pinging as "needs review".
    has_non_benign_child: childAlerts.some(a => {
      const status = (a.status || '').toLowerCase();
      const isTerminal = ['closed', 'resolved', 'false_positive', 'confirmed'].includes(status);
      if (isTerminal) return false;
      const v = (a.ai_verdict || a.disposition || '').toUpperCase();
      return v && !['BENIGN', 'FALSE_POSITIVE', 'BENIGN_POSITIVE'].includes(v)
        && ['MALICIOUS', 'SUSPICIOUS', 'TRUE_POSITIVE', 'NEEDS_INVESTIGATION', 'NEEDS_REVIEW'].includes(v);
    }),

    // Full child list for the drawer's correlated-alerts panel
    correlated_alerts: childAlerts,

    // Context for expanded view
    alert_context: sourceAlert,
    investigation_context: inv,
  };
}

/**
 * Build the unified security queue from alerts and investigations
 *
 * Logic:
 * - If an alert has investigation_id OR an investigation has alert_id matching the alert,
 *   the alert is "promoted" to an investigation and shown as investigation row only.
 * - Alerts without any linked investigation → normalizeAlert()
 * - Investigations without matching alert → normalizeInvestigation() (standalone)
 *
 * @param {Array} alerts - Raw alerts from API
 * @param {Array} investigations - Raw investigations from API
 * @returns {import('./types').SecurityQueueItem[]}
 */
export function buildSecurityQueue(alerts, investigations) {
  // Investigation lookup by their alphanumeric id ("INV-XXXX") and UUID id.
  // Alerts join via either depending on the path that linked them.
  const invByInvId = new Map(
    investigations.map(inv => [inv.investigation_id || inv.id, inv])
  );
  const invByUuid = new Map(
    investigations.filter(inv => inv.id).map(inv => [inv.id, inv])
  );
  const invByAlertId = new Map(
    investigations.filter(inv => inv.alert_id).map(inv => [inv.alert_id, inv])
  );

  // Group alert children per investigation. Each investigation gets ONE queue
  // row (M ×N badge) regardless of how many child alerts it has.
  const alertsByInvKey = new Map();   // key = investigation_id ("INV-...") or uuid
  const standaloneAlerts = [];

  for (const alert of alerts) {
    const alertId = alert.alert_id || alert.id;

    // Resolve the parent investigation by either of the two link shapes the
    // backend uses (uuid in alerts.investigation_id, or investigation pointing
    // at alert_id).
    let parentInv = null;
    if (alert.investigation_id) {
      parentInv = invByInvId.get(alert.investigation_id) || invByUuid.get(alert.investigation_id) || null;
    }
    if (!parentInv && invByAlertId.has(alertId)) {
      parentInv = invByAlertId.get(alertId);
    }

    if (parentInv) {
      const key = parentInv.investigation_id || parentInv.id;
      const bucket = alertsByInvKey.get(key) || [];
      bucket.push(alert);
      alertsByInvKey.set(key, bucket);
    } else {
      standaloneAlerts.push(alert);
    }
  }

  const items = [];

  // One investigation row per investigation, with all child alerts attached.
  for (const inv of investigations) {
    const key = inv.investigation_id || inv.id;
    const children = alertsByInvKey.get(key) || [];
    // Pick the newest child as the source alert for inherited display fields.
    const sourceAlert = children.length > 0
      ? children.slice().sort((a, b) => new Date(b.created_at) - new Date(a.created_at))[0]
      : null;
    items.push(normalizeInvestigation(inv, sourceAlert, children));
  }

  // Standalone alerts (no investigation linkage) keep their A row.
  for (const alert of standaloneAlerts) {
    items.push(normalizeAlert(alert));
  }

  items.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
  return items;
}

/**
 * Compute metrics from queue items
 * @param {import('./types').SecurityQueueItem[]} items
 * @returns {import('./types').QueueMetrics}
 */
export function computeMetrics(items) {
  const today = new Date();
  today.setHours(0, 0, 0, 0);

  return {
    total: items.length,
    alerts: items.filter(i => i.item_type === 'alert').length,
    investigations: items.filter(i => i.item_type === 'investigation').length,
    critical: items.filter(i => i.severity === 'critical').length,
    needsReview: items.filter(i =>
      i.item_type === 'investigation' &&
      (i.status === 'NEEDS_REVIEW' || i.status === 'AWAITING_HUMAN' || i.status === 'RIGGS_REVIEW')
    ).length,
    breached: items.filter(i => i.sla?.status === 'exceeded').length,
    atRisk: items.filter(i => i.sla?.status === 'at_risk').length,
    resolvedToday: items.filter(i => {
      if (i.status !== 'CLOSED' && i.status !== 'RESOLVED' && i.status !== 'resolved') return false;
      const updatedDate = new Date(i.updated_at);
      return updatedDate >= today;
    }).length,
  };
}

/**
 * Filter queue items based on filter state
 * @param {import('./types').SecurityQueueItem[]} items
 * @param {import('./types').QueueFilters} filters
 * @returns {import('./types').SecurityQueueItem[]}
 */
export function filterQueueItems(items, filters) {
  const {
    viewMode,
    statusFilter,
    severityFilter,
    dispositionFilter,
    priorityFilter,
    slaFilter,
    sourceFilter,
    sensitivityFilter,
    timeRange,
    searchQuery,
  } = filters;

  // Time range cutoff
  const getTimeCutoff = () => {
    const timeRangeMinutes = {
      '1h': 60,
      '6h': 360,
      '24h': 1440,
      '7d': 10080,
      '30d': 43200,
      'all': null,
    };
    const minutes = timeRangeMinutes[timeRange];
    if (!minutes) return null;
    return new Date(Date.now() - minutes * 60 * 1000);
  };

  const cutoff = getTimeCutoff();

  return items.filter(item => {
    // View mode filter
    if (viewMode === 'alerts' && item.item_type !== 'alert') return false;
    if (viewMode === 'investigations' && item.item_type !== 'investigation') return false;

    // Time range filter — use the most recent of created_at / updated_at
    if (cutoff) {
      const created = new Date(item.created_at);
      const updated = item.updated_at ? new Date(item.updated_at) : created;
      const mostRecent = updated > created ? updated : created;
      if (mostRecent < cutoff) return false;
    }

    // Status filter. 'active' is a pseudo-value that matches anything that
    // isn't a terminal state — i.e. work still in flight. Used by the Riggs
    // SLA-breach tip so "View breached" lands on currently-open breaches,
    // not historical closed/resolved items that ever happened to breach.
    if (statusFilter !== 'all') {
      const itemStatus = item.status?.toLowerCase();
      if (statusFilter === 'active') {
        if (itemStatus === 'closed' || itemStatus === 'resolved') return false;
      } else if (itemStatus !== statusFilter.toLowerCase()) {
        return false;
      }
    }

    // Severity filter
    if (severityFilter !== 'all') {
      if (item.severity !== severityFilter) return false;
    }

    // SLA filter (applies to all item types)
    if (slaFilter !== 'all' && item.sla?.status !== slaFilter) {
      return false;
    }

    // Investigation-only filters
    if (item.item_type === 'investigation') {
      if (dispositionFilter !== 'all' && item.disposition?.toLowerCase() !== dispositionFilter) {
        return false;
      }
      if (priorityFilter !== 'all' && item.priority !== priorityFilter) {
        return false;
      }
    }

    // Alert-only filters
    if (item.item_type === 'alert') {
      if (sourceFilter !== 'all' && item.source?.toLowerCase() !== sourceFilter.toLowerCase()) {
        return false;
      }
    }

    // Sensitivity filter
    if (sensitivityFilter && sensitivityFilter !== 'all') {
      const itemSensitivity = (item.sensitivity || 'internal').toLowerCase();
      if (itemSensitivity !== sensitivityFilter.toLowerCase()) return false;
    }

    // Search query
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      const matchesId = item.queue_id?.toLowerCase().includes(q) ||
                        item.alert_id?.toLowerCase().includes(q) ||
                        item.investigation_id?.toLowerCase().includes(q);
      const matchesTitle = item.title?.toLowerCase().includes(q);
      const matchesOwner = item.owner?.toLowerCase().includes(q);
      const matchesSummary = item.executive_summary?.toLowerCase().includes(q);
      if (!matchesId && !matchesTitle && !matchesOwner && !matchesSummary) return false;
    }

    return true;
  });
}

export default {
  normalizeAlert,
  normalizeInvestigation,
  buildSecurityQueue,
  computeMetrics,
  filterQueueItems,
};
