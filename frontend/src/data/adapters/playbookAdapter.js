/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

/**
 * Playbook Data Adapter
 *
 * Transforms raw API playbook responses to normalized PlaybookVM format.
 */

/**
 * @typedef {import('../types/playbook.types').PlaybookVM} PlaybookVM
 * @typedef {import('../types/playbook.types').PlaybookExecution} PlaybookExecution
 * @typedef {import('../types/playbook.types').PlaybookValidity} PlaybookValidity
 * @typedef {import('../types/playbook.types').PlaybookStats} PlaybookStats
 * @typedef {import('../types/playbook.types').PlaybookNode} PlaybookNode
 * @typedef {import('../types/playbook.types').PlaybookEdge} PlaybookEdge
 * @typedef {import('../types/playbook.types').NodeExecutionResult} NodeExecutionResult
 */

/**
 * Normalize playbook status
 * @param {string|undefined} status
 * @returns {'draft'|'active'|'disabled'|'archived'}
 */
function normalizeStatus(status) {
  const normalized = (status || '').toLowerCase();
  const validStatuses = ['draft', 'active', 'disabled', 'archived'];

  if (validStatuses.includes(normalized)) {
    return normalized;
  }

  const statusMap = {
    enabled: 'active',
    published: 'active',
    inactive: 'disabled',
    deleted: 'archived'
  };

  return statusMap[normalized] || 'draft';
}

/**
 * Parse trigger configuration
 * @param {Object|undefined} trigger
 * @returns {import('../types/playbook.types').PlaybookTrigger}
 */
function parseTrigger(trigger) {
  if (!trigger) {
    return { type: 'manual' };
  }

  return {
    type: trigger.type || trigger.trigger_type || 'manual',
    conditions: trigger.conditions,
    schedule: trigger.schedule || trigger.cron,
    webhookId: trigger.webhook_id
  };
}

/**
 * Parse workflow nodes
 * @param {Object[]|undefined} nodes
 * @returns {PlaybookNode[]}
 */
function parseNodes(nodes) {
  if (!Array.isArray(nodes)) return [];

  return nodes.map(n => ({
    id: n.id || n.node_id,
    type: n.type || n.node_type,
    label: n.label || n.data?.label || n.type,
    position: n.position || { x: 0, y: 0 },
    config: n.config || n.data?.config || n.data || {},
    isConfigured: n.is_configured !== false,
    errors: n.errors || []
  }));
}

/**
 * Parse workflow edges
 * @param {Object[]|undefined} edges
 * @returns {PlaybookEdge[]}
 */
function parseEdges(edges) {
  if (!Array.isArray(edges)) return [];

  return edges.map(e => ({
    id: e.id || e.edge_id || `${e.source}-${e.target}`,
    source: e.source || e.source_id,
    target: e.target || e.target_id,
    sourceHandle: e.sourceHandle || e.source_handle,
    label: e.label
  }));
}

/**
 * Parse execution statistics
 * @param {Object|undefined} stats
 * @returns {PlaybookStats}
 */
function parseStats(stats) {
  if (!stats) {
    return {
      totalExecutions: 0,
      successfulExecutions: 0,
      failedExecutions: 0,
      avgDurationMs: 0,
      lastExecutedAt: null,
      activeExecutions: 0
    };
  }

  return {
    totalExecutions: stats.total_executions || stats.total || 0,
    successfulExecutions: stats.successful_executions || stats.success || 0,
    failedExecutions: stats.failed_executions || stats.failed || 0,
    avgDurationMs: stats.avg_duration_ms || stats.avg_duration || 0,
    lastExecutedAt: stats.last_executed_at ? new Date(stats.last_executed_at) : null,
    activeExecutions: stats.active_executions || stats.running || 0
  };
}

/**
 * Calculate playbook validity
 * @param {Object} raw - Raw playbook data
 * @returns {PlaybookValidity}
 */
function calculateValidity(raw) {
  const errors = [];
  const warnings = [];
  const missingInputs = [];

  // Check nodes
  const nodes = raw.nodes || raw.canvas_data?.nodes || [];

  // Check for trigger
  const hasTrigger = nodes.some(n => n.type === 'trigger' || n.node_type === 'trigger');
  if (!hasTrigger) {
    errors.push('Playbook must have a trigger node');
  }

  // Check for unconfigured nodes
  nodes.forEach(n => {
    if (n.errors && n.errors.length > 0) {
      errors.push(...n.errors.map(e => `Node "${n.label || n.id}": ${e}`));
    }
    if (n.missing_inputs && n.missing_inputs.length > 0) {
      missingInputs.push(...n.missing_inputs);
    }
  });

  // Check for disconnected nodes
  const edges = raw.edges || raw.canvas_data?.edges || [];
  const connectedNodes = new Set();
  edges.forEach(e => {
    connectedNodes.add(e.source || e.source_id);
    connectedNodes.add(e.target || e.target_id);
  });

  nodes.forEach(n => {
    const nodeId = n.id || n.node_id;
    if (!connectedNodes.has(nodeId) && n.type !== 'trigger' && nodes.length > 1) {
      warnings.push(`Node "${n.label || nodeId}" is not connected`);
    }
  });

  // Determine overall status
  let status = 'valid';
  if (errors.length > 0) {
    status = 'has_errors';
  } else if (missingInputs.length > 0) {
    status = 'needs_inputs';
  } else if (raw.requires_approval) {
    status = 'requires_approval';
  }

  return {
    status,
    errors,
    warnings,
    missingInputs,
    canDeploy: errors.length === 0 && missingInputs.length === 0
  };
}

/**
 * Transform raw API playbook to PlaybookVM
 * @param {Object} raw - Raw API response
 * @returns {PlaybookVM}
 */
export function toPlaybookVM(raw) {
  const canvasData = raw.canvas_data || {};

  return {
    id: raw.playbook_id || raw.id || '',
    name: raw.name || raw.title || 'Untitled Playbook',
    description: raw.description || null,
    status: normalizeStatus(raw.status),
    version: raw.version || '1.0.0',
    createdAt: raw.created_at ? new Date(raw.created_at) : new Date(),
    updatedAt: raw.updated_at ? new Date(raw.updated_at) : new Date(),
    createdBy: raw.created_by || raw.author || 'Unknown',
    updatedBy: raw.updated_by,
    trigger: parseTrigger(raw.trigger || canvasData.trigger),
    nodes: parseNodes(raw.nodes || canvasData.nodes),
    edges: parseEdges(raw.edges || canvasData.edges),
    stats: parseStats(raw.stats || raw.execution_stats),
    validity: calculateValidity(raw),
    tags: raw.tags || [],
    metadata: raw.metadata || {}
  };
}

/**
 * Transform list of playbooks
 * @param {Object[]} rawList
 * @returns {PlaybookVM[]}
 */
export function toPlaybookVMList(rawList) {
  if (!Array.isArray(rawList)) return [];
  return rawList.map(toPlaybookVM);
}

/**
 * Normalize execution status
 * @param {string|undefined} status
 * @returns {PlaybookExecution['status']}
 */
function normalizeExecutionStatus(status) {
  const normalized = (status || '').toLowerCase().replace(/[_-]/g, '_');
  const validStatuses = [
    'queued', 'running', 'completed', 'failed',
    'cancelled', 'waiting_approval', 'waiting_delay'
  ];

  if (validStatuses.includes(normalized)) {
    return normalized;
  }

  const statusMap = {
    pending: 'queued',
    in_progress: 'running',
    success: 'completed',
    done: 'completed',
    error: 'failed',
    stopped: 'cancelled',
    paused: 'waiting_approval'
  };

  return statusMap[normalized] || 'queued';
}

/**
 * Parse node execution results
 * @param {Object[]|undefined} results
 * @returns {NodeExecutionResult[]}
 */
function parseNodeResults(results) {
  if (!Array.isArray(results)) return [];

  return results.map(r => ({
    nodeId: r.node_id || r.id,
    nodeType: r.node_type || r.type,
    status: r.status || 'pending',
    startedAt: r.started_at ? new Date(r.started_at) : null,
    completedAt: r.completed_at || r.ended_at ? new Date(r.completed_at || r.ended_at) : null,
    durationMs: r.duration_ms || r.duration,
    inputs: r.inputs || {},
    outputs: r.outputs || {},
    error: r.error || r.error_message || null,
    meta: r.meta || {}
  }));
}

/**
 * Transform raw execution to PlaybookExecution
 * @param {Object} raw
 * @returns {PlaybookExecution}
 */
export function toPlaybookExecution(raw) {
  return {
    id: raw.execution_id || raw.id || '',
    playbookId: raw.playbook_id,
    playbookName: raw.playbook_name || raw.playbook?.name || 'Unknown',
    status: normalizeExecutionStatus(raw.status),
    startedAt: raw.started_at ? new Date(raw.started_at) : new Date(),
    completedAt: raw.completed_at || raw.ended_at
      ? new Date(raw.completed_at || raw.ended_at)
      : null,
    durationMs: raw.duration_ms || raw.duration || null,
    triggeredBy: raw.triggered_by || raw.trigger_source || 'manual',
    triggerContext: raw.trigger_context || raw.context || {},
    nodeResults: parseNodeResults(raw.node_results || raw.results),
    outputs: raw.outputs || {},
    error: raw.error || raw.error_message || null
  };
}

/**
 * Transform list of executions
 * @param {Object[]} rawList
 * @returns {PlaybookExecution[]}
 */
export function toPlaybookExecutionList(rawList) {
  if (!Array.isArray(rawList)) return [];
  return rawList.map(toPlaybookExecution);
}

/**
 * Convert PlaybookVM to API format for saving
 * @param {Partial<PlaybookVM>} vm
 * @returns {Object}
 */
export function fromPlaybookVM(vm) {
  const result = {};

  if (vm.name !== undefined) result.name = vm.name;
  if (vm.description !== undefined) result.description = vm.description;
  if (vm.status !== undefined) result.status = vm.status;
  if (vm.tags !== undefined) result.tags = vm.tags;
  if (vm.nodes !== undefined || vm.edges !== undefined) {
    result.canvas_data = {
      nodes: vm.nodes?.map(n => ({
        id: n.id,
        type: n.type,
        position: n.position,
        data: { label: n.label, config: n.config }
      })) || [],
      edges: vm.edges?.map(e => ({
        id: e.id,
        source: e.source,
        target: e.target,
        sourceHandle: e.sourceHandle,
        label: e.label
      })) || []
    };
  }

  return result;
}

export default {
  toPlaybookVM,
  toPlaybookVMList,
  toPlaybookExecution,
  toPlaybookExecutionList,
  fromPlaybookVM
};
