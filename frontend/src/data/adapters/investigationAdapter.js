/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

/**
 * Investigation Data Adapter
 *
 * Transforms raw API investigation responses to normalized InvestigationVM format.
 */

/**
 * @typedef {import('../types/investigation.types').InvestigationVM} InvestigationVM
 * @typedef {import('../types/investigation.types').TechnicalFinding} TechnicalFinding
 * @typedef {import('../types/investigation.types').TimelineEvent} TimelineEvent
 * @typedef {import('../types/investigation.types').RecommendedAction} RecommendedAction
 * @typedef {import('../types/investigation.types').InvestigationNote} InvestigationNote
 * @typedef {import('../types/investigation.types').InvestigationMetrics} InvestigationMetrics
 * @typedef {import('../types/common.types').InvestigationStatus} InvestigationStatus
 * @typedef {import('../types/common.types').SLAInfo} SLAInfo
 */

/**
 * Normalize investigation status
 * @param {string|undefined} status
 * @returns {InvestigationStatus}
 */
function normalizeStatus(status) {
  const normalized = (status || '').toUpperCase().replace(/[_-]/g, '_');
  const validStatuses = [
    'NEW', 'ANALYZING', 'NEEDS_REVIEW', 'IN_PROGRESS',
    'AWAITING_HUMAN', 'RIGGS_REVIEW', 'CLOSED', 'RESOLVED'
  ];

  if (validStatuses.includes(normalized)) {
    return normalized;
  }

  // Map legacy values
  const statusMap = {
    OPEN: 'NEW',
    ACTIVE: 'IN_PROGRESS',
    PENDING: 'NEW',
    REVIEW: 'NEEDS_REVIEW',
    COMPLETE: 'CLOSED',
    COMPLETED: 'CLOSED',
    DONE: 'CLOSED'
  };

  return statusMap[normalized] || 'NEW';
}

/**
 * Normalize priority level
 * @param {string|number|undefined} priority
 * @returns {import('../types/common.types').PriorityLevel}
 */
function normalizePriority(priority) {
  if (typeof priority === 'number') {
    if (priority <= 1) return 'P1';
    if (priority <= 2) return 'P2';
    if (priority <= 3) return 'P3';
    return 'P4';
  }

  const normalized = (priority || '').toUpperCase();
  const validPriorities = ['P1', 'P2', 'P3', 'P4'];

  if (validPriorities.includes(normalized)) {
    return normalized;
  }

  const priorityMap = {
    CRITICAL: 'P1',
    HIGH: 'P2',
    MEDIUM: 'P3',
    LOW: 'P4',
    URGENT: 'P1'
  };

  return priorityMap[normalized] || 'P3';
}

/**
 * Normalize severity
 * @param {string|undefined} severity
 * @returns {import('../types/common.types').Severity}
 */
function normalizeSeverity(severity) {
  const normalized = (severity || '').toLowerCase();
  const validSeverities = ['critical', 'high', 'medium', 'low'];

  return validSeverities.includes(normalized) ? normalized : 'medium';
}

/**
 * Parse SLA information
 * @param {Object|undefined} sla
 * @returns {SLAInfo|null}
 */
function parseSLA(sla) {
  if (!sla) return null;

  const dueAt = sla.due_at ? new Date(sla.due_at) : null;
  const now = new Date();
  let remainingMs = dueAt ? dueAt.getTime() - now.getTime() : 0;

  let status = 'healthy';
  if (remainingMs < 0) {
    status = 'breached';
  } else if (remainingMs < 3600000) {
    status = 'at_risk';
  }

  // Label
  let label = '';
  if (remainingMs < 0) {
    const overMins = Math.floor(Math.abs(remainingMs) / 60000);
    const overHours = Math.floor(overMins / 60);
    label = overHours > 0 ? `${overHours}h ${overMins % 60}m overdue` : `${overMins}m overdue`;
  } else {
    const mins = Math.floor(remainingMs / 60000);
    const hours = Math.floor(mins / 60);
    label = hours > 0 ? `${hours}h ${mins % 60}m remaining` : `${mins}m remaining`;
  }

  return { status, remainingMs, dueAt, label };
}

/**
 * Parse technical findings
 * @param {Object[]|undefined} findings
 * @returns {TechnicalFinding[]}
 */
function parseFindings(findings) {
  if (!Array.isArray(findings)) return [];

  return findings.map(f => ({
    id: f.id || f.finding_id || Math.random().toString(36).substr(2, 9),
    title: f.title || 'Untitled Finding',
    description: f.description || '',
    severity: normalizeSeverity(f.severity),
    mitreTactics: f.mitre_tactics || f.tactics || [],
    mitreTechniques: f.mitre_techniques || f.techniques || [],
    evidence: f.evidence || {},
    confidence: f.confidence || 'medium',
    attribution: f.attribution || { source: 'system', timestamp: new Date() }
  }));
}

/**
 * Parse timeline events
 * @param {Object[]|undefined} timeline
 * @returns {TimelineEvent[]}
 */
function parseTimeline(timeline) {
  if (!Array.isArray(timeline)) return [];

  return timeline.map(e => ({
    id: e.id || e.event_id || Math.random().toString(36).substr(2, 9),
    timestamp: e.timestamp ? new Date(e.timestamp) : new Date(),
    title: e.title || e.event_type || 'Event',
    description: e.description,
    type: e.type || e.event_type || 'note',
    severity: e.severity ? normalizeSeverity(e.severity) : undefined,
    data: e.data || e.metadata,
    attribution: e.attribution || { source: 'system', timestamp: new Date(e.timestamp) }
  })).sort((a, b) => b.timestamp - a.timestamp);
}

/**
 * Parse recommended actions
 * @param {Object[]|undefined} actions
 * @returns {RecommendedAction[]}
 */
function parseRecommendations(actions) {
  if (!Array.isArray(actions)) return [];

  return actions.map(a => ({
    id: a.id || a.action_id || Math.random().toString(36).substr(2, 9),
    title: a.title || a.action || 'Recommended Action',
    description: a.description || '',
    priority: normalizePriority(a.priority),
    rationale: a.rationale || a.reason || '',
    status: a.status || 'pending',
    confidence: a.confidence || 'medium',
    playbookId: a.playbook_id,
    parameters: a.parameters || a.params
  }));
}

/**
 * Parse investigation notes
 * @param {Object[]|undefined} notes
 * @returns {InvestigationNote[]}
 */
function parseNotes(notes) {
  if (!Array.isArray(notes)) return [];

  return notes.map(n => ({
    id: n.id || n.note_id || Math.random().toString(36).substr(2, 9),
    content: n.content || n.text || '',
    type: n.type || n.note_type || 'analyst',
    createdAt: n.created_at ? new Date(n.created_at) : new Date(),
    updatedAt: n.updated_at ? new Date(n.updated_at) : undefined,
    attribution: n.attribution || {
      source: n.type === 'ai' ? 'riggs' : 'human',
      username: n.author || n.created_by,
      timestamp: new Date(n.created_at)
    },
    parentId: n.parent_id || null,
    attachments: n.attachments || []
  })).sort((a, b) => b.createdAt - a.createdAt);
}

/**
 * Extract IOCs from investigation
 * @param {Object} raw
 * @returns {import('../types/common.types').IOC[]}
 */
function extractIOCs(raw) {
  const iocs = [];

  // From iocs field
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

  // From ioc_summary
  if (raw.ioc_summary) {
    Object.entries(raw.ioc_summary).forEach(([type, values]) => {
      if (Array.isArray(values)) {
        values.forEach(v => iocs.push({ value: v, type, context: null }));
      }
    });
  }

  return iocs;
}

/**
 * Transform raw API investigation to InvestigationVM
 * @param {Object} raw - Raw API response
 * @returns {InvestigationVM}
 */
export function toInvestigationVM(raw) {
  return {
    id: raw.investigation_id || raw.id || '',
    title: raw.title || 'Untitled Investigation',
    description: raw.description || null,
    status: normalizeStatus(raw.status),
    priority: normalizePriority(raw.priority),
    severity: normalizeSeverity(raw.severity),
    disposition: raw.disposition || null,
    createdAt: raw.created_at ? new Date(raw.created_at) : new Date(),
    updatedAt: raw.updated_at ? new Date(raw.updated_at) : new Date(),
    sla: parseSLA(raw.sla),
    owner: raw.owner || raw.assigned_to || null,
    alertIds: raw.alert_ids || raw.alerts?.map(a => a.alert_id || a.id) || [],
    alertCount: raw.alert_count || raw.alert_ids?.length || raw.alerts?.length || 0,
    findings: parseFindings(raw.findings || raw.technical_findings),
    timeline: parseTimeline(raw.timeline || raw.events),
    recommendations: parseRecommendations(raw.recommendations || raw.recommended_actions),
    iocs: extractIOCs(raw),
    notes: parseNotes(raw.notes),
    metadata: raw.metadata || {},
    lastAction: raw.last_action ? {
      source: raw.last_action.source || 'system',
      userId: raw.last_action.user_id,
      username: raw.last_action.username,
      timestamp: new Date(raw.last_action.timestamp)
    } : null
  };
}

/**
 * Transform list of investigations
 * @param {Object[]} rawList
 * @returns {InvestigationVM[]}
 */
export function toInvestigationVMList(rawList) {
  if (!Array.isArray(rawList)) return [];
  return rawList.map(toInvestigationVM);
}

/**
 * Transform investigation metrics from API
 * @param {Object} raw
 * @returns {InvestigationMetrics}
 */
export function toInvestigationMetrics(raw) {
  return {
    total: raw.total || 0,
    open: raw.open || raw.status_counts?.open || 0,
    needsReview: raw.needs_review || raw.status_counts?.needs_review || 0,
    inProgress: raw.in_progress || raw.status_counts?.in_progress || 0,
    closed: raw.closed || raw.status_counts?.closed || 0,
    breached: raw.breached || raw.sla_counts?.breached || 0,
    atRisk: raw.at_risk || raw.sla_counts?.at_risk || 0,
    avgResolutionMs: raw.avg_resolution_ms || raw.mttr_ms || 0
  };
}

/**
 * Convert InvestigationVM back to API format for updates
 * @param {Partial<InvestigationVM>} vm
 * @returns {Object}
 */
export function fromInvestigationVM(vm) {
  const result = {};

  if (vm.status !== undefined) result.status = vm.status;
  if (vm.priority !== undefined) result.priority = vm.priority;
  if (vm.severity !== undefined) result.severity = vm.severity;
  if (vm.disposition !== undefined) result.disposition = vm.disposition;
  if (vm.owner !== undefined) result.owner = vm.owner;
  if (vm.title !== undefined) result.title = vm.title;
  if (vm.description !== undefined) result.description = vm.description;

  return result;
}

export default {
  toInvestigationVM,
  toInvestigationVMList,
  toInvestigationMetrics,
  fromInvestigationVM
};
