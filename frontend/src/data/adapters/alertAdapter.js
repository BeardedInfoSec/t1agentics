/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

/**
 * Alert Data Adapter
 *
 * Transforms raw API alert responses to normalized AlertVM format.
 * Ensures UI components receive consistent, predictable data shapes.
 */

/**
 * @typedef {import('../types/alert.types').AlertVM} AlertVM
 * @typedef {import('../types/alert.types').AlertMetrics} AlertMetrics
 * @typedef {import('../types/common.types').Severity} Severity
 * @typedef {import('../types/common.types').AlertStatus} AlertStatus
 * @typedef {import('../types/common.types').SLAInfo} SLAInfo
 * @typedef {import('../types/common.types').Attribution} Attribution
 * @typedef {import('../types/common.types').IOC} IOC
 */

/**
 * Normalize severity to standard format
 * @param {string|undefined} severity
 * @returns {Severity}
 */
function normalizeSeverity(severity) {
  const normalized = (severity || '').toLowerCase();
  const validSeverities = ['critical', 'high', 'medium', 'low'];

  if (validSeverities.includes(normalized)) {
    return normalized;
  }

  // Map legacy values
  const severityMap = {
    crit: 'critical',
    error: 'high',
    warning: 'medium',
    warn: 'medium',
    info: 'low',
    informational: 'low'
  };

  return severityMap[normalized] || 'medium';
}

/**
 * Normalize status to standard format
 * @param {string|undefined} status
 * @returns {AlertStatus}
 */
function normalizeStatus(status) {
  const normalized = (status || '').toLowerCase().replace(/[_-]/g, '_');
  const validStatuses = ['new', 'in_progress', 'resolved', 'closed', 'escalated'];

  if (validStatuses.includes(normalized)) {
    return normalized;
  }

  // Map legacy values
  const statusMap = {
    open: 'new',
    active: 'in_progress',
    investigating: 'in_progress',
    pending: 'new',
    done: 'closed',
    complete: 'closed',
    completed: 'closed'
  };

  return statusMap[normalized] || 'new';
}

/**
 * Parse SLA information
 * @param {Object|undefined} sla - Raw SLA data
 * @returns {SLAInfo|null}
 */
function parseSLA(sla) {
  if (!sla) return null;

  const status = sla.status || 'healthy';
  const dueAt = sla.due_at ? new Date(sla.due_at) : null;
  const now = new Date();

  let remainingMs = 0;
  if (dueAt) {
    remainingMs = dueAt.getTime() - now.getTime();
  }

  // Calculate human-readable label
  let label = '';
  if (remainingMs < 0) {
    const overMs = Math.abs(remainingMs);
    const overMins = Math.floor(overMs / 60000);
    const overHours = Math.floor(overMins / 60);
    if (overHours > 0) {
      label = `${overHours}h ${overMins % 60}m overdue`;
    } else {
      label = `${overMins}m overdue`;
    }
  } else {
    const mins = Math.floor(remainingMs / 60000);
    const hours = Math.floor(mins / 60);
    if (hours > 0) {
      label = `${hours}h ${mins % 60}m remaining`;
    } else {
      label = `${mins}m remaining`;
    }
  }

  return {
    status: remainingMs < 0 ? 'breached' : (remainingMs < 3600000 ? 'at_risk' : 'healthy'),
    remainingMs,
    dueAt,
    label
  };
}

/**
 * Extract IOCs from alert data
 * @param {Object} raw - Raw alert data
 * @returns {IOC[]}
 */
function extractIOCs(raw) {
  const iocs = [];

  // Extract from structured ioc field
  if (raw.iocs && Array.isArray(raw.iocs)) {
    raw.iocs.forEach(ioc => {
      iocs.push({
        value: ioc.value || ioc,
        type: ioc.type || 'unknown',
        context: ioc.context,
        severity: normalizeSeverity(ioc.severity)
      });
    });
  }

  // Extract from metadata if present
  if (raw.metadata?.indicators) {
    Object.entries(raw.metadata.indicators).forEach(([type, values]) => {
      if (Array.isArray(values)) {
        values.forEach(value => {
          iocs.push({ value, type, context: null });
        });
      }
    });
  }

  return iocs;
}

/**
 * Parse attribution information
 * @param {Object|undefined} action - Last action data
 * @returns {Attribution|null}
 */
function parseAttribution(action) {
  if (!action) return null;

  return {
    source: action.source || (action.user_id ? 'human' : 'system'),
    userId: action.user_id,
    username: action.username,
    playbookId: action.playbook_id,
    playbookName: action.playbook_name,
    confidence: action.confidence,
    rationale: action.rationale,
    timestamp: action.timestamp ? new Date(action.timestamp) : new Date()
  };
}

/**
 * Transform raw API alert to AlertVM
 * @param {Object} raw - Raw API response
 * @returns {AlertVM}
 */
export function toAlertVM(raw) {
  return {
    id: raw.alert_id || raw.id || '',
    title: raw.title || 'Untitled Alert',
    description: raw.description || null,
    severity: normalizeSeverity(raw.severity),
    status: normalizeStatus(raw.status),
    source: raw.source || 'Unknown',
    createdAt: raw.created_at ? new Date(raw.created_at) : new Date(),
    updatedAt: raw.updated_at ? new Date(raw.updated_at) : new Date(),
    sla: parseSLA(raw.sla),
    iocs: extractIOCs(raw),
    investigationId: raw.investigation_id || null,
    assignee: raw.assignee || raw.owner || null,
    metadata: raw.metadata || {},
    rawLog: raw.raw_log || raw.raw_data || {},
    lastAction: parseAttribution(raw.last_action)
  };
}

/**
 * Transform list of alerts
 * @param {Object[]} rawList - Raw API response array
 * @returns {AlertVM[]}
 */
export function toAlertVMList(rawList) {
  if (!Array.isArray(rawList)) return [];
  return rawList.map(toAlertVM);
}

/**
 * Transform alert metrics from API
 * @param {Object} raw - Raw metrics data
 * @returns {AlertMetrics}
 */
export function toAlertMetrics(raw) {
  return {
    total: raw.total || 0,
    critical: raw.critical || raw.severity_counts?.critical || 0,
    high: raw.high || raw.severity_counts?.high || 0,
    medium: raw.medium || raw.severity_counts?.medium || 0,
    low: raw.low || raw.severity_counts?.low || 0,
    new: raw.new || raw.status_counts?.new || 0,
    inProgress: raw.in_progress || raw.status_counts?.in_progress || 0,
    resolved: raw.resolved || raw.status_counts?.resolved || 0,
    breached: raw.breached || raw.sla_counts?.breached || 0,
    atRisk: raw.at_risk || raw.sla_counts?.at_risk || 0
  };
}

/**
 * Convert AlertVM back to API format for updates
 * @param {Partial<AlertVM>} vm - ViewModel data
 * @returns {Object}
 */
export function fromAlertVM(vm) {
  const result = {};

  if (vm.status !== undefined) result.status = vm.status;
  if (vm.severity !== undefined) result.severity = vm.severity;
  if (vm.assignee !== undefined) result.assignee = vm.assignee;
  if (vm.title !== undefined) result.title = vm.title;
  if (vm.description !== undefined) result.description = vm.description;

  return result;
}

export default {
  toAlertVM,
  toAlertVMList,
  toAlertMetrics,
  fromAlertVM
};
