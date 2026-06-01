/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

import React, { useMemo, useState, useCallback, useEffect, useRef } from 'react';
import { createPortal } from 'react-dom';
import { useNavigate, useParams } from 'react-router-dom';
import ReactFlow, {
  Controls,
  MiniMap,
  addEdge,
  useNodesState,
  useEdgesState,
  Handle,
  Position,
  BaseEdge,
  EdgeLabelRenderer,
  getSmoothStepPath,
} from 'reactflow';
import Editor from '@monaco-editor/react';
import 'reactflow/dist/style.css';
import './WorkflowStudio.css';
import { authFetch, API_BASE_URL } from '../../utils/api';
import { telemetry } from '../../utils/telemetry';
import { useToast } from '../ui/Toast';
import DataPathPicker from '../PlaybookEditor/DataPathPicker';
import ExecutionView from '../PlaybookEditor/ExecutionView';
import { normalizeInputsEntries, entriesToInputObject } from './inputsMapUtils';
import { registerPythonCompletions, generateCodeFromInputs, updateCodeWithInputs, isDynamicValue } from '../PlaybookEditor/pythonCompletions';
import * as Icons from 'lucide-react';
import {
  Bell,
  Zap,
  GitBranch,
  Shuffle,
  Repeat,
  Clock,
  ShieldCheck,
  Layers,
  StopCircle,
  Wrench,
} from 'lucide-react';

const CANONICAL_BLOCKS = {
  trigger: {
    kind: 'trigger',
    label: 'Trigger',
    hint: 'Alert, webhook, schedule, or manual',
    icon: Bell,
  },
  analyze: {
    kind: 'analyze',
    label: 'Analyze',
    hint: 'AI triage or IOC enrichment',
    icon: Icons.Brain,
  },
  ai_agent: {
    kind: 'ai_agent',
    label: 'AI Agent',
    hint: 'Run a custom Claude prompt at any point in the workflow',
    icon: Icons.Bot || Icons.Sparkles,
  },
  decision: {
    kind: 'decision',
    label: 'Decision',
    hint: 'If / then branching with conditions',
    icon: GitBranch,
  },
  respond: {
    kind: 'respond',
    label: 'Respond',
    hint: 'Actions, notifications & tickets',
    icon: Zap,
  },
  code: {
    kind: 'code',
    label: 'Code',
    hint: 'Run custom Python or structured transforms',
    icon: Icons.Code,
  },
  loop: {
    kind: 'loop',
    label: 'Loop',
    hint: 'Iterate over a list',
    icon: Repeat,
  },
  delay: {
    kind: 'delay',
    label: 'Delay',
    hint: 'Pause workflow execution',
    icon: Clock,
  },
  approval: {
    kind: 'approval',
    label: 'Approval',
    hint: 'Human approval with policy',
    icon: ShieldCheck,
  },
  subflow: {
    kind: 'subflow',
    label: 'Subflow',
    hint: 'Run another playbook',
    icon: Layers,
  },
  utility: {
    kind: 'utility',
    label: 'Utility',
    hint: 'Update status, severity, SLA, EDL',
    icon: Wrench,
  },
  end: {
    kind: 'end',
    label: 'End',
    hint: 'Finalize disposition',
    icon: StopCircle,
  },
};

const PALETTE_GROUPS = [
  { id: 'core', label: 'Core', items: ['analyze', 'decision', 'respond', 'approval'] },
  { id: 'advanced', label: 'Advanced', items: ['code', 'loop', 'delay', 'subflow', 'utility', 'end'] },
];

const createUuid = () => {
  if (typeof crypto !== 'undefined' && crypto.randomUUID) {
    return crypto.randomUUID();
  }
  const part = () => Math.floor((1 + Math.random()) * 0x10000).toString(16).slice(1);
  return `${part()}${part()}-${part()}-${part()}-${part()}-${part()}${part()}${part()}`;
};

const DECISION_OPERATORS = [
  { value: 'equals', label: 'Equals', symbol: '==' },
  { value: 'not_equals', label: 'Not equals', symbol: '!=' },
  { value: 'greater', label: 'Greater than', symbol: '>' },
  { value: 'less', label: 'Less than', symbol: '<' },
  { value: 'greater_or_equal', label: 'Greater or equal', symbol: '>=' },
  { value: 'less_or_equal', label: 'Less or equal', symbol: '<=' },
  { value: 'in', label: 'In list', symbol: 'in' },
  { value: 'not_in', label: 'Not in list', symbol: 'not_in' },
  { value: 'contains', label: 'Contains', symbol: 'contains' },
  { value: 'not_contains', label: 'Not contains', symbol: 'not_contains' },
  { value: 'exists', label: 'Exists', symbol: 'exists' },
  { value: 'missing', label: 'Missing', symbol: 'missing' },
];

const DECISION_OPERATOR_TO_EXPR = {
  equals: '==',
  not_equals: '!=',
  greater: '>',
  less: '<',
  greater_or_equal: '>=',
  less_or_equal: '<=',
  in: 'in',
  not_in: 'not_in',
  contains: 'contains',
  not_contains: 'not_contains',
  exists: '!=',
  missing: '==',
};

const EXPRESSION_TO_DECISION = {
  '==': 'equals',
  '!=': 'not_equals',
  '>': 'greater',
  '<': 'less',
  '>=': 'greater_or_equal',
  '<=': 'less_or_equal',
  in: 'in',
  not_in: 'not_in',
  contains: 'contains',
  not_contains: 'not_contains',
};

// Helper to parse expression to decision config (moved before templates to avoid TDZ)
function parseDecisionSingleEarly(expr) {
  const match = String(expr || '').trim().match(/^\s*(\$\.[^\s]+)\s*(==|!=|>=|<=|>|<|contains|not_contains|in|not_in)\s*(.+?)\s*$/);
  if (!match) return null;
  const leftPath = match[1];
  const op = match[2];
  let rawValue = match[3].trim();
  if ((rawValue.startsWith('"') && rawValue.endsWith('"')) || (rawValue.startsWith("'") && rawValue.endsWith("'"))) {
    rawValue = rawValue.slice(1, -1);
  }
  let operator = EXPRESSION_TO_DECISION[op] || 'equals';
  let right = { type: 'value', value: rawValue };
  if (rawValue.startsWith('$.')) {
    right = { type: 'path', value: rawValue };
  }
  if ((rawValue === 'null' || rawValue === 'None') && (op === '==' || op === '!=')) {
    operator = op === '==' ? 'missing' : 'exists';
    right = { type: 'value', value: '' };
  }
  return {
    id: createUuid(),
    left: { type: 'path', value: leftPath },
    operator,
    right,
  };
}

function decisionConfigFromExpressionEarly(expression) {
  const trimmed = String(expression || '').trim();
  if (!trimmed) {
    return {
      conditions: { id: createUuid(), operator: 'AND', conditions: [], groups: [] },
      expression: '',
      default_branch: 'no',
    };
  }
  const hasAnd = /\s+AND\s+/i.test(trimmed);
  const hasOr = /\s+OR\s+/i.test(trimmed);
  let operator = 'AND';
  let parts = [trimmed];
  if (hasAnd && !hasOr) {
    operator = 'AND';
    parts = trimmed.split(/\s+AND\s+/i);
  } else if (hasOr && !hasAnd) {
    operator = 'OR';
    parts = trimmed.split(/\s+OR\s+/i);
  }
  const conditions = parts.map((part) => parseDecisionSingleEarly(part)).filter(Boolean);
  return {
    conditions: { id: createUuid(), operator, conditions, groups: [] },
    expression: expression || '',
    default_branch: 'no',
  };
}

const templates = [
  {
    id: 'tpl-phishing',
    name: 'Phishing Response',
    summary: 'Triage, enrich, and contain malicious senders.',
    nodes: [
      { id: 't1', type: 'signal', position: { x: 520, y: 60 }, data: baseNode('trigger', 'Inbound Alert', 'Phishing detection', { trigger_type: 'alert' }) },
      { id: 't2', type: 'signal', position: { x: 520, y: 220 }, data: baseNode('decision', 'High Severity?', 'Branch on severity', decisionConfigFromExpressionEarly('$.trigger.alert.severity == "high"')) },
      { id: 't3', type: 'signal', position: { x: 360, y: 380 }, data: baseNode('action', 'Contain Sender', 'Block malicious domain', { action_type: 'block_domain', target_path: '$.trigger.alert.sender_domain', requires_approval: false }) },
      { id: 't4', type: 'signal', position: { x: 680, y: 380 }, data: baseNode('action', 'Notify Analyst', 'Send SOC notification', { action_type: 'notify', requires_approval: false }) },
      { id: 't5', type: 'signal', position: { x: 520, y: 540 }, data: baseNode('subflow', 'Case Closure', 'Notify + ticket', { playbook_name: 'case_closure' }) },
    ],
    edges: [
      { id: 'e1', source: 't1', target: 't2', animated: true, type: 'smoothstep' },
      { id: 'e2', source: 't2', target: 't3', sourceHandle: 'yes', label: 'Yes', animated: true, type: 'smoothstep' },
      { id: 'e3', source: 't2', target: 't4', sourceHandle: 'no', label: 'No', animated: true, type: 'smoothstep' },
      { id: 'e4', source: 't3', target: 't5', animated: true, type: 'smoothstep' },
      { id: 'e5', source: 't4', target: 't5', animated: true, type: 'smoothstep' },
    ],
  },
  {
    id: 'tpl-ato',
    name: 'Account Takeover',
    summary: 'Validate risk, step-up auth, and notify.',
    nodes: [
      { id: 'a1', type: 'signal', position: { x: 520, y: 60 }, data: baseNode('trigger', 'Auth Alert', 'Impossible travel', { trigger_type: 'alert' }) },
      { id: 'a2', type: 'signal', position: { x: 520, y: 220 }, data: baseNode('code', 'Extract Risk Score', 'Pull risk score from alert', { mode: 'extract', input_path: '$.trigger.alert', transform_type: 'extract', transform_config: { output_path: '$.risk.score' } }) },
      { id: 'a3', type: 'signal', position: { x: 520, y: 380 }, data: baseNode('decision', 'Risk Score', 'If risk > 80', decisionConfigFromExpressionEarly('$.nodes.a2.result > 80')) },
      { id: 'a4', type: 'signal', position: { x: 360, y: 540 }, data: baseNode('action', 'Force MFA', 'Step-up auth', { action_type: 'force_mfa', target_path: '$.trigger.alert.user_id' }) },
      { id: 'a5', type: 'signal', position: { x: 680, y: 540 }, data: baseNode('action', 'Close Alert', 'No action', { action_type: 'close_alert', requires_approval: false }) },
    ],
    edges: [
      { id: 'ea1', source: 'a1', target: 'a2', animated: true, type: 'smoothstep' },
      { id: 'ea2', source: 'a2', target: 'a3', animated: true, type: 'smoothstep' },
      { id: 'ea3', source: 'a3', target: 'a4', sourceHandle: 'yes', label: 'High', animated: true, type: 'smoothstep' },
      { id: 'ea4', source: 'a3', target: 'a5', sourceHandle: 'no', label: 'Low', animated: true, type: 'smoothstep' },
    ],
  },
];

const starterNodes = [
  {
    id: 'trigger-1',
    type: 'signal',
    position: { x: 520, y: 220 },
    data: baseNode('trigger', 'Inbound Alert', 'Alert, webhook, or schedule', { trigger_type: 'alert' }),
  },
];

const starterEdges = [];

const nodeTypes = {
  signal: SignalNode,
};

const edgeTypes = {
  deletable: DeletableEdge,
};

const LEFT_PANEL_MIN_WIDTH = 220;
const LEFT_PANEL_MAX_WIDTH = 520;
const RIGHT_PANEL_MIN_WIDTH = 260;
const RIGHT_PANEL_MAX_WIDTH = 560;

const PYTHON_EDITOR_OPTIONS = {
  minimap: { enabled: false },
  fontSize: 13,
  lineHeight: 20,
  scrollBeyondLastLine: false,
  wordWrap: 'on',
  tabSize: 4,
  insertSpaces: true,
  automaticLayout: true,
  renderLineHighlight: 'line',
  quickSuggestions: true,
  suggestOnTriggerCharacters: true,
  scrollbar: {
    verticalScrollbarSize: 8,
    horizontalScrollbarSize: 8,
  },
};



const LEGACY_KIND_MAP = {
  condition: 'decision',
  approval_gate: 'approval',
  // Old separate types → consolidated analyze
  riggs_analyze: 'analyze',
  enrich: 'analyze',
  // Old separate types → consolidated respond
  action: 'respond',
  integration: 'respond',
  notify: 'respond',
  create_ticket: 'respond',
  webhook_call: 'respond',
  http_request: 'respond',
  list_lookup: 'respond',
  list_update: 'respond',
  edl_add: 'respond',
  edl_remove: 'respond',
  case_update: 'respond',
  // Other mappings
  python_code: 'code',
  function_call: 'code',
  variable_set: 'code',
  variable_get: 'code',
  webform: 'code',
  file_upload: 'code',
  user_input: 'code',
  input: 'code',
  note: 'code',
  parallel: 'loop',
  merge: 'loop',
  decision: 'decision',
  loop: 'loop',
  delay: 'delay',
  subflow: 'subflow',
  trigger: 'trigger',
  end: 'end',
};

const CANONICAL_KINDS = new Set([
  'trigger',
  'analyze',
  'ai_agent',
  'decision',
  'respond',
  'code',
  'loop',
  'delay',
  'approval',
  'subflow',
  'utility',
  'end',
]);

const createDecisionCondition = () => ({
  id: createUuid(),
  left: { type: 'path', value: '' },
  operator: 'equals',
  right: { type: 'value', value: '' },
});

const createDecisionGroup = () => ({
  id: createUuid(),
  operator: 'AND',
  conditions: [createDecisionCondition()],
  groups: [],
});

function decisionConfigFromExpression(expression) {
  const group = parseDecisionExpression(expression);
  return {
    conditions: group,
    expression: expression || '',
    default_branch: 'no',
  };
}

function parseDecisionExpression(expression) {
  const trimmed = String(expression || '').trim();
  if (!trimmed) return createDecisionGroup();
  const hasAnd = /\s+AND\s+/i.test(trimmed);
  const hasOr = /\s+OR\s+/i.test(trimmed);
  let operator = 'AND';
  let parts = [trimmed];
  if (hasAnd && !hasOr) {
    operator = 'AND';
    parts = trimmed.split(/\s+AND\s+/i);
  } else if (hasOr && !hasAnd) {
    operator = 'OR';
    parts = trimmed.split(/\s+OR\s+/i);
  }
  const conditions = parts
    .map((part) => parseDecisionSingle(part))
    .filter(Boolean);
  if (conditions.length === 0) return createDecisionGroup();
  return {
    id: createUuid(),
    operator,
    conditions,
    groups: [],
  };
}

function parseDecisionSingle(expr) {
  const match = String(expr || '').trim().match(/^\s*(\$\.[^\s]+)\s*(==|!=|>=|<=|>|<|contains|not_contains|in|not_in)\s*(.+?)\s*$/);
  if (!match) return null;
  const leftPath = match[1];
  const op = match[2];
  let rawValue = match[3].trim();
  if ((rawValue.startsWith('"') && rawValue.endsWith('"')) || (rawValue.startsWith("'") && rawValue.endsWith("'"))) {
    rawValue = rawValue.slice(1, -1);
  }
  let operator = EXPRESSION_TO_DECISION[op] || 'equals';
  let right = { type: 'value', value: rawValue };
  if (rawValue.startsWith('$.')) {
    right = { type: 'path', value: rawValue };
  }
  if ((rawValue === 'null' || rawValue === 'None') && (op === '==' || op === '!=')) {
    operator = op === '==' ? 'missing' : 'exists';
    right = { type: 'value', value: '' };
  }
  return {
    id: createUuid(),
    left: { type: 'path', value: leftPath },
    operator,
    right,
  };
}

function decisionValueToLiteral(value) {
  if (value === null || value === undefined) return 'null';
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  const raw = String(value);
  if (raw === 'true' || raw === 'false' || raw === 'null') return raw;
  if (/^-?\d+(\.\d+)?$/.test(raw)) return raw;
  if (raw.startsWith('[') && raw.endsWith(']')) return raw;
  return `"${raw.replace(/"/g, '\\"')}"`;
}

function compileDecisionCondition(condition) {
  if (!condition?.left?.value) return '';
  const op = DECISION_OPERATOR_TO_EXPR[condition.operator] || '==';
  if (condition.operator === 'exists') {
    return `${condition.left.value} != null`;
  }
  if (condition.operator === 'missing') {
    return `${condition.left.value} == null`;
  }
  const right = condition.right || { type: 'value', value: '' };
  if (right.type === 'path' && right.value) {
    return `${condition.left.value} ${op} ${right.value}`;
  }
  if ((condition.operator === 'in' || condition.operator === 'not_in') && typeof right.value === 'string') {
    const list = right.value
      .split(',')
      .map((item) => item.trim())
      .filter(Boolean);
    if (list.length > 1) {
      return `${condition.left.value} ${op} ${JSON.stringify(list)}`;
    }
  }
  return `${condition.left.value} ${op} ${decisionValueToLiteral(right.value)}`;
}

function compileDecisionGroup(group) {
  if (!group) return '';
  const parts = [];
  (group.conditions || []).forEach((condition) => {
    const expr = compileDecisionCondition(condition);
    if (expr) parts.push(expr);
  });
  (group.groups || []).forEach((child) => {
    const expr = compileDecisionGroup(child);
    if (expr) parts.push(`(${expr})`);
  });
  if (parts.length === 0) return '';
  const joiner = group.operator === 'OR' ? ' OR ' : ' AND ';
  return parts.join(joiner);
}

function normalizeDecisionConfig(config) {
  let conditions;
  if (config?.conditions && config.conditions.id) {
    conditions = config.conditions;
  } else if (config?.expression) {
    conditions = parseDecisionExpression(config.expression);
  } else {
    conditions = createDecisionGroup();
  }
  // Ensure root group always has at least one editable condition
  if (!conditions.conditions || conditions.conditions.length === 0) {
    conditions = { ...conditions, conditions: [createDecisionCondition()] };
  }

  // Ensure branches array always has at least Yes + No so the editor
  // exposes both paths and lets the user rename them. SOAR imports
  // sometimes produce decisions with a single 'no' branch (or none),
  // which made the editor show only one un-renameable path.
  let branches = Array.isArray(config?.branches) ? config.branches.slice() : [];
  const seen = new Set(branches.map((b) => (b?.id || '').toLowerCase()));
  if (!seen.has('yes')) {
    branches.unshift({ id: 'yes', label: 'Yes' });
    seen.add('yes');
  }
  if (!seen.has('no')) {
    branches.push({ id: 'no', label: 'No' });
    seen.add('no');
  }

  return {
    ...config,
    conditions,
    branches,
    default_branch: config?.default_branch || 'no',
  };
}

function updateDecisionGroup(group, groupId, updater) {
  if (group.id === groupId) {
    return updater(group);
  }
  return {
    ...group,
    groups: (group.groups || []).map((child) => updateDecisionGroup(child, groupId, updater)),
  };
}

function updateDecisionCondition(group, conditionId, updater) {
  let updated = false;
  const conditions = (group.conditions || []).map((condition) => {
    if (condition.id === conditionId) {
      updated = true;
      return updater(condition);
    }
    return condition;
  });
  const groups = (group.groups || []).map((child) => {
    const next = updateDecisionCondition(child, conditionId, updater);
    if (next !== child) updated = true;
    return next;
  });
  return updated ? { ...group, conditions, groups } : group;
}

function removeDecisionCondition(group, conditionId) {
  const conditions = (group.conditions || []).filter((condition) => condition.id !== conditionId);
  const groups = (group.groups || []).map((child) => removeDecisionCondition(child, conditionId));
  if (conditions.length === 0 && groups.length === 0) {
    return { ...group, conditions: [createDecisionCondition()], groups };
  }
  return { ...group, conditions, groups };
}

function removeDecisionGroup(group, groupId) {
  if (group.id === groupId) {
    return createDecisionGroup();
  }
  return {
    ...group,
    groups: (group.groups || []).filter((child) => child.id !== groupId).map((child) => removeDecisionGroup(child, groupId)),
  };
}

function updateDecisionConditionPath(group, conditionId, path, side = 'left') {
  return updateDecisionCondition(group, conditionId, (condition) => {
    if (side === 'right') {
      return { ...condition, right: { ...condition.right, value: path, type: 'path' } };
    }
    return { ...condition, left: { ...condition.left, value: path, type: 'path' } };
  });
}

const SAMPLE_WORKFLOW = {
  name: 'Sample: Enrich and Contain',
  description: 'Alert enrichment with python decisioning and response actions.',
  canvas_data: {
    nodes: [
        {
          id: 'trigger-1',
          type: 'trigger',
          position: { x: 520, y: 120 },
          data: {
            label: 'Inbound Alert',
            description: 'Alert, webhook, or schedule',
            kind: 'trigger',
            config: { trigger_type: 'alert', alert_filter: '' },
          },
        },
        {
          id: 'action-1',
          type: 'action',
          position: { x: 520, y: 300 },
          data: {
            label: 'Enrich IOC',
            description: 'Call enrichment integration',
            kind: 'action',
            config: {
              integration_instance_id: '',
              endpoint_id: '',
              action_type: 'enrich',
              params: {},
              target_path: '$.trigger.alert.iocs[0]',
              requires_approval: false,
              priority: 'medium',
            },
          },
        },
        {
          id: 'python-1',
          type: 'code',
          position: { x: 520, y: 500 },
          data: {
            label: 'Score Alert',
            description: 'Compute risk from enrichment + alert fields',
            kind: 'code',
            config: {
              mode: 'script',
              script: {
                function_name: 'main',
                inputs: [
                  { key: 'alert', path: '$.trigger.alert' },
                  { key: 'enrichment', path: '$.nodes.action-1.result' },
                ],
                code: "def main(inputs):\n    alert = inputs.get('alert', {})\n    enrichment = inputs.get('enrichment', {})\n    score = enrichment.get('risk_score', 0)\n    return {\n        'score': score,\n        'contains_malicious': score >= 75,\n        'alert_id': alert.get('id')\n    }\n",
              },
            },
          },
        },
        {
          id: 'condition-1',
          type: 'decision',
          position: { x: 520, y: 700 },
          data: {
            label: 'High Risk?',
            description: 'Branch on python score',
            kind: 'decision',
            config: decisionConfigFromExpression('$.nodes.python-1.result.contains_malicious == true'),
          },
        },
        {
          id: 'action-2',
          type: 'action',
          position: { x: 360, y: 880 },
          data: {
            label: 'Contain Sender',
            description: 'Block malicious sender',
            kind: 'action',
            config: {
              integration_instance_id: '',
              endpoint_id: '',
              action_type: 'block_sender',
              params: {},
              target_path: '$.trigger.alert.sender',
              requires_approval: false,
              priority: 'high',
            },
          },
        },
        {
          id: 'action-3',
          type: 'action',
          position: { x: 680, y: 880 },
          data: {
            label: 'Notify Analyst',
            description: 'Send analyst notification',
            kind: 'action',
            config: {
              integration_instance_id: '',
              endpoint_id: '',
              action_type: 'notify',
              params: {},
              target_path: '$.trigger.alert.id',
              requires_approval: false,
              priority: 'low',
            },
          },
        },
    ],
    edges: [
      { id: 'e1', source: 'trigger-1', target: 'action-1', animated: true, type: 'smoothstep' },
      { id: 'e2', source: 'action-1', target: 'python-1', animated: true, type: 'smoothstep' },
      { id: 'e3', source: 'python-1', target: 'condition-1', animated: true, type: 'smoothstep' },
      { id: 'e4', source: 'condition-1', target: 'action-2', sourceHandle: 'yes', label: 'Yes', animated: true, type: 'smoothstep' },
      { id: 'e5', source: 'condition-1', target: 'action-3', sourceHandle: 'no', label: 'No', animated: true, type: 'smoothstep' },
    ],
  },
};

// Layout dimensions tuned to actual rendered node-card size.
// A typical signal node renders ~250px wide and ~260px tall once title,
// description, 2-3 config rows, and footer chips are included; the
// previous values (120/110) were the *minimum* card size and led to
// overlapping cards when imported playbooks were auto-laid-out.
const NODE_MIN_WIDTH = 260;
const NODE_MIN_HEIGHT = 280;
const NODE_PADDING = 32;

const autoLayoutNodes = (nodes, edges) => {
  const nodeById = new Map(nodes.map((node) => [node.id, node]));
  const incoming = new Map();
  const outgoing = new Map();
  nodes.forEach((node) => {
    incoming.set(node.id, new Set());
    outgoing.set(node.id, new Set());
  });
  (edges || []).forEach((edge) => {
    if (!incoming.has(edge.target) || !outgoing.has(edge.source)) return;
    incoming.get(edge.target).add(edge.source);
    outgoing.get(edge.source).add(edge.target);
  });

  const levels = new Map();
  const kindRank = (node) => {
    const kind = (node?.data?.kind || '').toLowerCase();
    const order = {
      trigger: 0,
      decision: 1,
      transform: 2,
      action: 3,
      approval: 4,
      loop: 5,
      delay: 6,
      subflow: 7,
      end: 8,
    };
    return order[kind] ?? 50;
  };

  const roots = nodes.filter((node) => incoming.get(node.id)?.size === 0);
  roots.sort((a, b) => kindRank(a) - kindRank(b));

  const queue = roots.map((node) => node.id);
  roots.forEach((node) => {
    levels.set(node.id, 0);
  });

  while (queue.length) {
    const current = queue.shift();
    const currentLevel = levels.get(current) ?? 0;
    (outgoing.get(current) || []).forEach((next) => {
      const nextLevel = Math.max(levels.get(next) ?? 0, currentLevel + 1);
      levels.set(next, nextLevel);
      queue.push(next);
    });
  }

  const grouped = new Map();
  nodes.forEach((node) => {
    const level = levels.get(node.id) ?? 0;
    if (!grouped.has(level)) grouped.set(level, []);
    grouped.get(level).push(node.id);
  });

  const initialX = new Map(nodes.map((node) => [node.id, node.position?.x ?? 0]));
  // rowGap must exceed the actual rendered node height so successive
  // levels don't visually overlap. colGap mirrors width + breathing room.
  const rowGap = 320;
  const colGap = 320;
  const baseX = 520;
  const baseY = 80;
  // React Flow's `position.x` is the LEFT edge of the node, but we want
  // to align nodes by their CENTER on the baseX axis. Subtracting half
  // the node width when placing each node makes a single-child column
  // visually center under its parent and makes a row of N siblings
  // spread symmetrically around baseX.
  const halfNodeWidth = NODE_MIN_WIDTH / 2;

  grouped.forEach((ids, level) => {
    ids.sort((a, b) => (initialX.get(a) ?? 0) - (initialX.get(b) ?? 0));
    ids.forEach((id, idx) => {
      const node = nodeById.get(id);
      if (!node) return;
      const centerX = baseX + (idx - (ids.length - 1) / 2) * colGap;
      node.position = {
        x: Math.round(centerX - halfNodeWidth),
        y: Math.round(baseY + level * rowGap),
      };
    });
  });

  const nodeWidth = NODE_MIN_WIDTH;
  const nodeHeight = NODE_MIN_HEIGHT;
  const padding = NODE_PADDING;
  const placed = [];
  const ordered = nodes
    .slice()
    .sort((a, b) => (a.position?.y ?? 0) - (b.position?.y ?? 0) || (a.position?.x ?? 0) - (b.position?.x ?? 0));

  const overlaps = (node, other) => {
    const ax = node.position?.x ?? 0;
    const ay = node.position?.y ?? 0;
    const bx = other.position?.x ?? 0;
    const by = other.position?.y ?? 0;
    return Math.abs(ax - bx) < nodeWidth + padding && Math.abs(ay - by) < nodeHeight + padding;
  };

  ordered.forEach((node) => {
    let iterations = 0;
    while (placed.some((other) => overlaps(node, other)) && iterations < 80) {
      node.position = {
        x: node.position.x,
        y: node.position.y + nodeHeight + padding,
      };
      iterations += 1;
    }
    placed.push(node);
  });

  return nodes;
};

const ensureReadableLayout = (nodes, edges) => {
  if (!nodes || nodes.length === 0) return nodes;
  const missingPosition = nodes.some((node) =>
    !node.position || !Number.isFinite(node.position.x) || !Number.isFinite(node.position.y)
  );
  if (missingPosition) {
    const cloned = nodes.map((node) => ({ ...node, position: { x: node.position?.x ?? 0, y: node.position?.y ?? 0 } }));
    return autoLayoutNodes(cloned, edges);
  }
  const overlaps = (a, b) => {
    const ax = a.position?.x ?? 0;
    const ay = a.position?.y ?? 0;
    const bx = b.position?.x ?? 0;
    const by = b.position?.y ?? 0;
    return Math.abs(ax - bx) < NODE_MIN_WIDTH + NODE_PADDING &&
      Math.abs(ay - by) < NODE_MIN_HEIGHT + NODE_PADDING;
  };
  for (let i = 0; i < nodes.length; i += 1) {
    for (let j = i + 1; j < nodes.length; j += 1) {
      if (overlaps(nodes[i], nodes[j])) {
        const cloned = nodes.map((node) => ({ ...node, position: { ...node.position } }));
        return autoLayoutNodes(cloned, edges);
      }
    }
  }
  return nodes;
};

function WorkflowStudio() {
  const { id: playbookId } = useParams();
  const navigate = useNavigate();
  const toast = useToast();
  const [nodes, setNodes, onNodesChange] = useNodesState(starterNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(starterEdges);
  const [selectedNodeId, setSelectedNodeId] = useState(null);
  const [flowName, setFlowName] = useState('');
  const [flowDescription, setFlowDescription] = useState('');
  const [flowStatus, setFlowStatus] = useState('Draft');
  const [playbookMeta, setPlaybookMeta] = useState({
    id: playbookId || null,
    is_enabled: false,
    riggs_allowed: false,
    trigger_timing: 'post_triage',
    trigger_conditions: defaultTriggerConditions(),
    tags: [],
    alert_types: [],
    severity_filter: [],
    data_sources: [],
    priority: 50,
  });
  const [loading, setLoading] = useState(false);
  const [loadError, setLoadError] = useState(null);
  const [isSaving, setIsSaving] = useState(false);
  const [saveError, setSaveError] = useState(null);
  const [executionView, setExecutionView] = useState(null);
  const [lastExecution, setLastExecution] = useState(null);
  const [showDataPathPicker, setShowDataPathPicker] = useState(false);
  const [dataPathContext, setDataPathContext] = useState(null);
  const [availableLists, setAvailableLists] = useState([]);
  const [availableFunctions, setAvailableFunctions] = useState([]);
  const [availableIntegrations, setAvailableIntegrations] = useState([]);
  const [playbookIntegrations, setPlaybookIntegrations] = useState([]);
  const [inspectorTab, setInspectorTab] = useState('preview');
  const [buildFromPreviewState, setBuildFromPreviewState] = useState({ loading: false, error: null });
  const [submitCommunityState, setSubmitCommunityState] = useState({ loading: false, status: null, error: null });
  const [showNodeAdvanced, setShowNodeAdvanced] = useState(false);
  const [riggsTab, setRiggsTab] = useState('build');
  const [riggsPrompt, setRiggsPrompt] = useState('');
  const [riggsAlertType, setRiggsAlertType] = useState('');
  // riggsInvestigationId removed — now auto-populated from Data Preview
  const [riggsBuildLoading, setRiggsBuildLoading] = useState(false);
  const [riggsSuggestLoading, setRiggsSuggestLoading] = useState(false);
  const [riggsRecommendLoading, setRiggsRecommendLoading] = useState(false);
  const [riggsResult, setRiggsResult] = useState(null);
  const [riggsSuggestion, setRiggsSuggestion] = useState(null);
  const [riggsRecommendations, setRiggsRecommendations] = useState([]);
  const [riggsError, setRiggsError] = useState(null);
  const riggsStatus = riggsError ? 'error' : (riggsBuildLoading || riggsSuggestLoading || riggsRecommendLoading) ? 'thinking' : 'ready';
  const [alertTypeDraft, setAlertTypeDraft] = useState('');
  const [dataSourceDraft, setDataSourceDraft] = useState('');
  const [alertTagDraft, setAlertTagDraft] = useState('');
  const [investigationTagDraft, setInvestigationTagDraft] = useState('');
  const [assetError, setAssetError] = useState(null);
  const [assetMessage, setAssetMessage] = useState(null);
  const [listDraft, setListDraft] = useState({
    name: '',
    description: '',
    list_type: 'allowlist',
    items: ''
  });
  const [functionDraft, setFunctionDraft] = useState({
    name: '',
    description: '',
    code: '',
    input_schema: '',
    output_schema: ''
  });
  const [metrics, setMetrics] = useState(null);
  const [metricsLoading, setMetricsLoading] = useState(false);
  const [versions, setVersions] = useState([]);
  const [versionsLoading, setVersionsLoading] = useState(false);
  const [executionHistory, setExecutionHistory] = useState([]);
  const [executionHistoryLoading, setExecutionHistoryLoading] = useState(false);
  const [executionHistoryFilter, setExecutionHistoryFilter] = useState('');
  const [leftPanelWidth, setLeftPanelWidth] = useState(280);
  const [rightPanelWidth, setRightPanelWidth] = useState(320);
  const [paletteQuery, setPaletteQuery] = useState('');
  const [showExecutionOverlay, setShowExecutionOverlay] = useState(true);
  const [showFlowOverlay, setShowFlowOverlay] = useState(true);
  // Per-node test
  const [nodeTestResult, setNodeTestResult] = useState(null); // { ok, status, outputs, error, duration_ms }
  const [nodeTestLoading, setNodeTestLoading] = useState(false);
  const [nodeTestNodeId, setNodeTestNodeId] = useState(null); // which node was last tested
  // "Copied" flash feedback — stores the path that was just copied
  const [copiedPath, setCopiedPath] = useState(null);
  const copiedPathTimerRef = useRef(null);
  // Template picker (shown on new playbook)
  const [showTemplatePicker, setShowTemplatePicker] = useState(false);
  const [mktTemplates, setMktTemplates] = useState([]);
  const [mktTemplatesLoading, setMktTemplatesLoading] = useState(false);
  const [mktTemplateCategory, setMktTemplateCategory] = useState('all');
  const [mktTemplateSearch, setMktTemplateSearch] = useState('');
  const [mktTemplateLoadingId, setMktTemplateLoadingId] = useState(null);
  const [snapEnabled, setSnapEnabled] = useState(true);
  const [autoLayoutEnabled, setAutoLayoutEnabled] = useState(false);
  const [showCodePanel, setShowCodePanel] = useState(true);
  const [codePanelHeight, setCodePanelHeight] = useState(340);
  const [dataPreviewMode, setDataPreviewMode] = useState('execution');
  const [dataPreviewNodeId, setDataPreviewNodeId] = useState(null);
  const [dataPreviewView, setDataPreviewView] = useState('simple');
  const [dataPreviewSearch, setDataPreviewSearch] = useState('');
  const [blockSearchQuery, setBlockSearchQuery] = useState('');
  const [dataPreviewLocked, setDataPreviewLocked] = useState(false);
  const [previewEntityId, setPreviewEntityId] = useState('');
  const [previewSearchDisplay, setPreviewSearchDisplay] = useState(''); // Display name in search input
  const justSelectedSearchRef = useRef(false); // Prevent search trigger after selection
  const [previewEntityType, setPreviewEntityType] = useState(null);
  const [previewAlert, setPreviewAlert] = useState(null);
  const [previewInvestigation, setPreviewInvestigation] = useState(null);
  const [previewTrigger, setPreviewTrigger] = useState(null);
  const [previewLoading, setPreviewLoading] = useState(false);
  const [previewError, setPreviewError] = useState(null);
  const [previewSuggestions, setPreviewSuggestions] = useState([]);
  const [previewSuggestionsLoading, setPreviewSuggestionsLoading] = useState(false);
  const [rfViewport, setRfViewport] = useState({ x: 0, y: 0, zoom: 1 });
  const reactFlowRef = useRef(null);
  const reactFlowWrapperRef = useRef(null);
  const resizeStateRef = useRef(null);
  const rightResizeStateRef = useRef(null);
  const codePanelResizeRef = useRef(null);
  const pythonCompletionRef = useRef(false);
  const nodesRef = useRef(nodes);
  const [activityLog, setActivityLog] = useState([
    { id: 'log-1', time: '2m ago', text: 'Draft saved' },
    { id: 'log-2', time: '9m ago', text: 'Node "Contain Sender" updated' },
    { id: 'log-3', time: '22m ago', text: 'Run simulated' },
  ]);
  const [connectMenu, setConnectMenu] = useState(null); // { x, y, sourceId, sourceHandle }
  const suppressPaneClickRef = useRef(false);
  const [searchFocused, setSearchFocused] = useState(false);

  // === Autosave, Undo/Redo, Copy/Paste, Node Search State ===
  const [hasDraft, setHasDraft] = useState(false);
  const [draftRestorePrompt, setDraftRestorePrompt] = useState(false);
  const [undoStack, setUndoStack] = useState([]);
  const [redoStack, setRedoStack] = useState([]);
  const [clipboard, setClipboard] = useState(null); // { nodes: [], edges: [] }
  const [nodeSearchOpen, setNodeSearchOpen] = useState(false);
  const [nodeSearchQuery, setNodeSearchQuery] = useState('');
  const [nodeSearchMatches, setNodeSearchMatches] = useState([]);
  const [nodeSearchIndex, setNodeSearchIndex] = useState(0);
  const lastSavedStateRef = useRef(null);
  const isUndoRedoRef = useRef(false);
  // Stable ref for handleTestNode — allows renderNodes (declared before handleTestNode) to pass
  // a stable callback into node data without causing all nodes to re-render on selection change.
  const handleTestNodeRef = useRef(null);

  // Track canvas changes for undo/redo (snapshot on significant changes)
  const pushUndoState = useCallback(() => {
    if (isUndoRedoRef.current) return; // Don't push during undo/redo
    const snapshot = { nodes: JSON.parse(JSON.stringify(nodes)), edges: JSON.parse(JSON.stringify(edges)) };
    setUndoStack((prev) => [...prev.slice(-49), snapshot]); // Keep max 50 states
    setRedoStack([]); // Clear redo on new change
  }, [nodes, edges]);

  // Undo handler
  const handleUndo = useCallback(() => {
    if (undoStack.length === 0) return;
    isUndoRedoRef.current = true;
    const currentState = { nodes: JSON.parse(JSON.stringify(nodes)), edges: JSON.parse(JSON.stringify(edges)) };
    const prevState = undoStack[undoStack.length - 1];
    setRedoStack((prev) => [...prev, currentState]);
    setUndoStack((prev) => prev.slice(0, -1));
    setNodes(prevState.nodes);
    setEdges(prevState.edges);
    setTimeout(() => { isUndoRedoRef.current = false; }, 50);
  }, [undoStack, nodes, edges, setNodes, setEdges]);

  // Redo handler
  const handleRedo = useCallback(() => {
    if (redoStack.length === 0) return;
    isUndoRedoRef.current = true;
    const currentState = { nodes: JSON.parse(JSON.stringify(nodes)), edges: JSON.parse(JSON.stringify(edges)) };
    const nextState = redoStack[redoStack.length - 1];
    setUndoStack((prev) => [...prev, currentState]);
    setRedoStack((prev) => prev.slice(0, -1));
    setNodes(nextState.nodes);
    setEdges(nextState.edges);
    setTimeout(() => { isUndoRedoRef.current = false; }, 50);
  }, [redoStack, nodes, edges, setNodes, setEdges]);

  // Copy selected nodes
  const handleCopy = useCallback(() => {
    const selectedNodes = nodes.filter((n) => n.selected);
    if (selectedNodes.length === 0) return;
    const selectedIds = new Set(selectedNodes.map((n) => n.id));
    const selectedEdges = edges.filter((e) => selectedIds.has(e.source) && selectedIds.has(e.target));
    setClipboard({ nodes: JSON.parse(JSON.stringify(selectedNodes)), edges: JSON.parse(JSON.stringify(selectedEdges)) });
  }, [nodes, edges]);

  // Paste copied nodes
  const handlePaste = useCallback(() => {
    if (!clipboard || clipboard.nodes.length === 0) return;
    pushUndoState();
    const idMap = {};
    const newNodes = clipboard.nodes.map((n) => {
      const newId = `${n.id}-copy-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
      idMap[n.id] = newId;
      return { ...n, id: newId, position: { x: n.position.x + 40, y: n.position.y + 40 }, selected: true };
    });
    const newEdges = clipboard.edges.map((e) => ({
      ...e,
      id: `${e.id}-copy-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
      source: idMap[e.source] || e.source,
      target: idMap[e.target] || e.target,
    }));
    setNodes((prev) => [...prev.map((n) => ({ ...n, selected: false })), ...newNodes]);
    setEdges((prev) => [...prev, ...newEdges]);
  }, [clipboard, pushUndoState, setNodes, setEdges]);

  // Node search - find and highlight matching nodes
  const performNodeSearch = useCallback((query) => {
    if (!query || query.length < 1) {
      setNodeSearchMatches([]);
      setNodeSearchIndex(0);
      // Clear search highlighting
      setNodes((prev) => prev.map((n) => ({ ...n, data: { ...n.data, searchMatch: false, searchMatchActive: false } })));
      return;
    }
    const lowerQuery = query.toLowerCase();
    const matches = nodes.filter((n) => {
      const title = (n.data?.title || n.data?.label || '').toLowerCase();
      const kind = (n.data?.kind || '').toLowerCase();
      const summary = (n.data?.summary || '').toLowerCase();
      return title.includes(lowerQuery) || kind.includes(lowerQuery) || summary.includes(lowerQuery);
    }).map((n) => n.id);
    setNodeSearchMatches(matches);
    setNodeSearchIndex(0);
    // Update node data with search match highlighting
    const matchSet = new Set(matches);
    setNodes((prev) => prev.map((n) => ({
      ...n,
      data: {
        ...n.data,
        searchMatch: matchSet.has(n.id),
        searchMatchActive: matches.length > 0 && matches[0] === n.id,
      },
    })));
    // Fit view to first match
    if (matches.length > 0 && reactFlowRef.current) {
      const matchNode = nodes.find((n) => n.id === matches[0]);
      if (matchNode) {
        reactFlowRef.current.setCenter(matchNode.position.x + 100, matchNode.position.y + 50, { zoom: 1.2, duration: 300 });
      }
    }
  }, [nodes, setNodes]);

  // Navigate to next search match
  const nextSearchMatch = useCallback(() => {
    if (nodeSearchMatches.length === 0) return;
    const nextIndex = (nodeSearchIndex + 1) % nodeSearchMatches.length;
    setNodeSearchIndex(nextIndex);
    const activeId = nodeSearchMatches[nextIndex];
    // Update active highlighting
    setNodes((prev) => prev.map((n) => ({
      ...n,
      data: { ...n.data, searchMatchActive: n.id === activeId },
    })));
    const matchNode = nodes.find((n) => n.id === activeId);
    if (matchNode && reactFlowRef.current) {
      reactFlowRef.current.setCenter(matchNode.position.x + 100, matchNode.position.y + 50, { zoom: 1.2, duration: 300 });
    }
  }, [nodeSearchMatches, nodeSearchIndex, nodes, setNodes]);

  // Autosave to localStorage every 30 seconds
  useEffect(() => {
    if (!playbookMeta.id) return; // Only autosave for existing playbooks
    const draftKey = `ws_draft_${playbookMeta.id}`;
    const interval = setInterval(() => {
      const draftData = {
        nodes: JSON.parse(JSON.stringify(nodes)),
        edges: JSON.parse(JSON.stringify(edges)),
        flowName,
        flowDescription,
        savedAt: Date.now(),
      };
      localStorage.setItem(draftKey, JSON.stringify(draftData));
    }, 30000);
    return () => clearInterval(interval);
  }, [nodes, edges, flowName, flowDescription, playbookMeta.id]);

  // Check for draft on load
  useEffect(() => {
    if (!playbookMeta.id) return;
    const draftKey = `ws_draft_${playbookMeta.id}`;
    const draft = localStorage.getItem(draftKey);
    if (draft) {
      try {
        const parsed = JSON.parse(draft);
        // Check if draft is newer than 5 minutes
        if (parsed.savedAt && Date.now() - parsed.savedAt < 5 * 60 * 1000) {
          setHasDraft(true);
          setDraftRestorePrompt(true);
        } else {
          localStorage.removeItem(draftKey); // Remove old drafts
        }
      } catch (e) {
      }
    }
  }, [playbookMeta.id]);

  // Restore draft handler
  const restoreDraft = useCallback(() => {
    const draftKey = `ws_draft_${playbookMeta.id}`;
    const draft = localStorage.getItem(draftKey);
    if (draft) {
      try {
        const parsed = JSON.parse(draft);
        if (parsed.nodes) setNodes(parsed.nodes);
        if (parsed.edges) setEdges(parsed.edges);
        if (parsed.flowName) setFlowName(parsed.flowName);
        if (parsed.flowDescription) setFlowDescription(parsed.flowDescription);
        setActivityLog((prev) => [{ id: `log-${Date.now()}`, time: 'just now', text: 'Draft restored' }, ...prev]);
      } catch (e) {
      }
    }
    setDraftRestorePrompt(false);
    setHasDraft(false);
  }, [playbookMeta.id, setNodes, setEdges]);

  // Dismiss draft
  const dismissDraft = useCallback(() => {
    const draftKey = `ws_draft_${playbookMeta.id}`;
    localStorage.removeItem(draftKey);
    setDraftRestorePrompt(false);
    setHasDraft(false);
  }, [playbookMeta.id]);

  // Clear draft on successful save
  const clearDraft = useCallback(() => {
    if (playbookMeta.id) {
      const draftKey = `ws_draft_${playbookMeta.id}`;
      localStorage.removeItem(draftKey);
      setHasDraft(false);
    }
  }, [playbookMeta.id]);

  // Global keyboard shortcuts
  useEffect(() => {
    const handleKeyDown = (e) => {
      // Don't capture shortcuts when typing in input/textarea
      if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA' || e.target.isContentEditable) {
        // Allow Escape to close search even in inputs
        if (e.key === 'Escape' && nodeSearchOpen) {
          setNodeSearchOpen(false);
          setNodeSearchQuery('');
          setNodeSearchMatches([]);
        }
        return;
      }

      const isMac = navigator.platform.toUpperCase().indexOf('MAC') >= 0;
      const modKey = isMac ? e.metaKey : e.ctrlKey;

      // Ctrl/Cmd + Z = Undo
      if (modKey && e.key === 'z' && !e.shiftKey) {
        e.preventDefault();
        handleUndo();
        return;
      }

      // Ctrl/Cmd + Shift + Z or Ctrl/Cmd + Y = Redo
      if ((modKey && e.key === 'z' && e.shiftKey) || (modKey && e.key === 'y')) {
        e.preventDefault();
        handleRedo();
        return;
      }

      // Ctrl/Cmd + C = Copy
      if (modKey && e.key === 'c') {
        e.preventDefault();
        handleCopy();
        return;
      }

      // Ctrl/Cmd + V = Paste
      if (modKey && e.key === 'v') {
        e.preventDefault();
        handlePaste();
        return;
      }

      // Ctrl/Cmd + F = Find nodes
      if (modKey && e.key === 'f') {
        e.preventDefault();
        setNodeSearchOpen(true);
        return;
      }

      // Ctrl/Cmd + A = Select all nodes
      if (modKey && e.key === 'a') {
        e.preventDefault();
        setNodes((prev) => prev.map((n) => ({ ...n, selected: true })));
        return;
      }

      // Escape = Deselect all / Close search
      if (e.key === 'Escape') {
        if (nodeSearchOpen) {
          setNodeSearchOpen(false);
          setNodeSearchQuery('');
          setNodeSearchMatches([]);
        } else {
          setNodes((prev) => prev.map((n) => ({ ...n, selected: false })));
          setSelectedNodeId(null);
        }
        return;
      }

      // Enter in search = next match
      if (e.key === 'Enter' && nodeSearchOpen) {
        e.preventDefault();
        nextSearchMatch();
        return;
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [handleUndo, handleRedo, handleCopy, handlePaste, nodeSearchOpen, nextSearchMatch, setNodes]);

  // Track changes for undo stack (debounced)
  useEffect(() => {
    const stateStr = JSON.stringify({ nodes, edges });
    if (lastSavedStateRef.current === stateStr) return;
    const timer = setTimeout(() => {
      if (!isUndoRedoRef.current && lastSavedStateRef.current !== null) {
        pushUndoState();
      }
      lastSavedStateRef.current = stateStr;
    }, 500); // Debounce 500ms
    return () => clearTimeout(timer);
  }, [nodes, edges, pushUndoState]);

  // Auto-search alerts and investigations as user types, or show recent on focus
  useEffect(() => {
    // Only show suggestions when search is focused
    if (!searchFocused) {
      setPreviewSuggestions([]);
      return;
    }

    // Skip search if we just selected an item (prevents dropdown from reappearing)
    if (justSelectedSearchRef.current) {
      // Don't clear the ref here - it will be cleared when user types
      return;
    }

    const hasQuery = previewSearchDisplay && previewSearchDisplay.length >= 2;
    const showRecent = !previewSearchDisplay || previewSearchDisplay.length < 2;

    if (!hasQuery && !showRecent) {
      setPreviewSuggestions([]);
      return;
    }

    const searchTerm = hasQuery ? previewSearchDisplay.toLowerCase().trim() : '';
    setPreviewSuggestionsLoading(true);

    // Debounce the search
    const timeoutId = setTimeout(async () => {
      try {
        // Fetch both alerts and investigations in parallel
        const [alertsRes, investigationsRes] = await Promise.all([
          authFetch(`${API_BASE_URL}/api/v1/alerts?limit=100`).then(r => r.ok ? r.json() : []),
          authFetch(`${API_BASE_URL}/api/v1/investigations?limit=100`).then(r => r.ok ? r.json() : []),
        ]);

        const alerts = Array.isArray(alertsRes) ? alertsRes : (alertsRes?.items || alertsRes?.alerts || []);
        const investigations = Array.isArray(investigationsRes) ? investigationsRes : (investigationsRes?.items || investigationsRes?.investigations || []);

        let matchingAlerts, matchingInvestigations;

        if (showRecent) {
          // Show most recent (sorted by created_at desc, take first 3 of each)
          matchingAlerts = alerts
            .sort((a, b) => new Date(b.created_at || 0) - new Date(a.created_at || 0))
            .slice(0, 3)
            .map(alert => ({
              id: alert.alert_id || alert.id,
              type: 'alert',
              title: alert.title || alert.name || alert.alert_type,
            }));

          matchingInvestigations = investigations
            .sort((a, b) => new Date(b.created_at || 0) - new Date(a.created_at || 0))
            .slice(0, 3)
            .map(inv => ({
              id: inv.investigation_id || inv.id,
              type: 'investigation',
              title: inv.alert_title || inv.title || inv.executive_summary || inv.name,
            }));
        } else {
          // Filter alerts matching the search term
          matchingAlerts = alerts
            .filter(alert => {
              const id = (alert.alert_id || alert.id || '').toLowerCase();
              const title = (alert.title || alert.name || '').toLowerCase();
              const type = (alert.alert_type || alert.type || '').toLowerCase();
              return id.includes(searchTerm) || title.includes(searchTerm) || type.includes(searchTerm);
            })
            .slice(0, 5)
            .map(alert => ({
              id: alert.alert_id || alert.id,
              type: 'alert',
              title: alert.title || alert.name || alert.alert_type,
            }));

          // Filter investigations matching the search term
          matchingInvestigations = investigations
            .filter(inv => {
              const id = (inv.investigation_id || inv.id || '').toLowerCase();
              const title = (inv.alert_title || inv.title || inv.executive_summary || inv.name || '').toLowerCase();
              return id.includes(searchTerm) || title.includes(searchTerm);
            })
            .slice(0, 5)
            .map(inv => ({
              id: inv.investigation_id || inv.id,
              type: 'investigation',
              title: inv.alert_title || inv.title || inv.executive_summary || inv.name,
            }));
        }

        // Combine results
        let combined = [...matchingAlerts, ...matchingInvestigations];

        if (!showRecent) {
          // Sort by exact match when searching
          combined = combined.sort((a, b) => {
            const aExact = a.id.toLowerCase() === searchTerm;
            const bExact = b.id.toLowerCase() === searchTerm;
            if (aExact && !bExact) return -1;
            if (!aExact && bExact) return 1;
            return 0;
          });
        }

        setPreviewSuggestions(combined.slice(0, 8));
      } catch (err) {
        setPreviewSuggestions([]);
      } finally {
        setPreviewSuggestionsLoading(false);
      }
    }, showRecent ? 0 : 300); // No debounce for recent, 300ms for search

    return () => clearTimeout(timeoutId);
  }, [previewSearchDisplay, searchFocused]);

  const handleDeleteEdge = useCallback((edgeId) => {
    setEdges((eds) => eds.filter((edge) => edge.id !== edgeId));
    setActivityLog((prev) => [
      { id: `log-${Date.now()}`, time: 'just now', text: 'Deleted a path' },
      ...prev,
    ]);
  }, [setEdges]);

  const handleDeleteNode = useCallback((nodeId) => {
    setNodes((prev) => prev.filter((node) => node.id !== nodeId));
    setEdges((eds) => eds.filter((edge) => edge.source !== nodeId && edge.target !== nodeId));
    if (selectedNodeId === nodeId) {
      setSelectedNodeId(null);
    }
    setActivityLog((prev) => [
      { id: `log-${Date.now()}`, time: 'just now', text: 'Deleted a node' },
      ...prev,
    ]);
  }, [selectedNodeId, setNodes, setEdges]);

  const selectedNode = useMemo(
    () => nodes.find((node) => node.id === selectedNodeId) || null,
    [nodes, selectedNodeId]
  );

  const paletteGroups = useMemo(
    () => PALETTE_GROUPS.map((group) => ({
      ...group,
      items: group.items.map((kind) => CANONICAL_BLOCKS[kind]).filter(Boolean),
    })),
    []
  );

  const filteredPaletteGroups = useMemo(() => {
    const query = String(paletteQuery ?? '').trim().toLowerCase();
    if (!query) return paletteGroups;
    return paletteGroups
      .map((group) => ({
        ...group,
        items: group.items.filter((item) => {
          const label = item.label?.toLowerCase() || '';
          const hint = item.hint?.toLowerCase() || '';
          const kind = item.kind?.toLowerCase() || '';
          return label.includes(query) || hint.includes(query) || kind.includes(query);
        }),
      }))
      .filter((group) => group.items.length > 0);
  }, [paletteGroups, paletteQuery]);

  const executionContext = lastExecution?.execution_context || null;
  const triggerContext = executionContext?.trigger || null;
  const triggerPaths = useMemo(() => {
    if (!triggerContext) return [];
    const paths = [];
    if (triggerContext.alert) {
      paths.push({ label: 'Alert', path: '$.trigger.alert' });
    }
    if (triggerContext.investigation) {
      paths.push({ label: 'Investigation', path: '$.trigger.investigation' });
    }
    paths.push({ label: 'Trigger', path: '$.trigger' });
    return paths;
  }, [triggerContext]);

  const selectedNodeExecution = useMemo(() => {
    if (!selectedNodeId) return null;
    return lastExecution?.node_results?.[selectedNodeId] || null;
  }, [lastExecution?.node_results, selectedNodeId]);

  const selectedNodeOutput = selectedNodeExecution?.outputs ?? selectedNodeExecution?.output ?? null;

  const executionNodeOptions = useMemo(
    () => nodes.map((node) => ({
      id: node.id,
      label: node.data?.title || node.data?.label || node.id,
    })),
    [nodes]
  );

  const executionPreviewPath = dataPreviewNodeId === 'trigger'
    ? '$.trigger'
    : dataPreviewNodeId
      ? `$.nodes.${dataPreviewNodeId}`
      : '';

  const executionPreviewData = useMemo(() => {
    if (!executionContext) return null;
    if (dataPreviewNodeId === 'trigger') {
      return executionContext.trigger || null;
    }
    if (dataPreviewNodeId) {
      return executionContext.nodes?.[dataPreviewNodeId]
        || lastExecution?.node_results?.[dataPreviewNodeId]?.outputs
        || lastExecution?.node_results?.[dataPreviewNodeId]?.output
        || null;
    }
    return null;
  }, [executionContext, dataPreviewNodeId, lastExecution?.node_results]);

  const selectedNodeLabel = useMemo(
    () => executionNodeOptions.find((node) => node.id === dataPreviewNodeId)?.label || dataPreviewNodeId,
    [executionNodeOptions, dataPreviewNodeId]
  );

  const lookupNodeOutput = useMemo(() => {
    if (!dataPreviewNodeId || dataPreviewNodeId === 'trigger') return null;
    return executionContext?.nodes?.[dataPreviewNodeId]
      || lastExecution?.node_results?.[dataPreviewNodeId]?.output
      || null;
  }, [dataPreviewNodeId, executionContext, lastExecution?.node_results]);

  const lookupBaseData = useMemo(() => (
    previewEntityType === 'investigation' ? previewInvestigation : previewAlert
  ), [previewEntityType, previewInvestigation, previewAlert]);

  const lookupPreviewData = lookupNodeOutput || lookupBaseData;
  const lookupPreviewPath = lookupNodeOutput
    ? `$.nodes.${dataPreviewNodeId}`
    : previewEntityType === 'investigation'
      ? '$.trigger.investigation'
      : '$.trigger.alert';
  const lookupPreviewLabel = lookupNodeOutput
    ? selectedNodeLabel
    : previewEntityType === 'investigation'
      ? 'Investigation'
      : 'Alert';

  const getSuggestionLookupId = (item) => {
    if (item.type === 'alert') return item.alert_id || item.id;
    if (item.type === 'investigation') return item.investigation_id || item.id;
    return item.id;
  };

  const formatSuggestionTitle = (item) => {
    if (!item) return '';
    if (item.type === 'alert') return item.title || item.alert_id || item.id;
    if (item.type === 'investigation') return item.title || item.investigation_id || item.id;
    return item.id || 'Result';
  };

  const formatSuggestionMeta = (item) => {
    if (!item) return '';
    const idPart = item.type === 'alert'
      ? item.alert_id || item.id
      : item.investigation_id || item.id;
    const statusPart = item.type === 'alert'
      ? item.severity
      : item.state || item.severity;
    const timePart = item.created_at
      ? new Date(item.created_at).toLocaleString()
      : '';
    const segments = [item.type?.toUpperCase(), idPart, statusPart, timePart].filter(Boolean);
    return segments.join(' · ');
  };

  const dataPreviewQuery = String(dataPreviewSearch ?? '').trim().toLowerCase();
  const matchCacheRef = useRef(new Map());

  useEffect(() => {
    matchCacheRef.current = new Map();
  }, [dataPreviewQuery, executionPreviewData, previewAlert, previewInvestigation]);

  // Keep nodesRef in sync for use in callbacks
  useEffect(() => {
    nodesRef.current = nodes;
  }, [nodes]);

  const hasJsonMatch = useCallback((value, path) => {
    if (!dataPreviewQuery) return true;
    const cacheKey = path;
    if (matchCacheRef.current.has(cacheKey)) {
      return matchCacheRef.current.get(cacheKey);
    }
    let matches = false;
    if (value === null || value === undefined) {
      matches = path.toLowerCase().includes(dataPreviewQuery);
    } else if (typeof value !== 'object') {
      matches = path.toLowerCase().includes(dataPreviewQuery)
        || String(value).toLowerCase().includes(dataPreviewQuery);
    } else if (Array.isArray(value)) {
      matches = value.some((item, idx) => hasJsonMatch(item, `${path}[${idx}]`));
    } else {
      matches = Object.entries(value).some(([key, child]) => {
        const childPath = path ? `${path}.${key}` : key;
        return key.toLowerCase().includes(dataPreviewQuery) || hasJsonMatch(child, childPath);
      });
    }
    matchCacheRef.current.set(cacheKey, matches);
    return matches;
  }, [dataPreviewQuery]);

  const formatPrimitive = (value) => {
    if (value === null) return <span className="json-null">null</span>;
    if (value === undefined) return <span className="json-undefined">undefined</span>;
    if (typeof value === 'boolean') return <span className="json-boolean">{String(value)}</span>;
    if (typeof value === 'number') return <span className="json-number" title={String(value)}>{String(value)}</span>;
    if (typeof value === 'string') return <span className="json-string" title={value}>{value}</span>;
    return String(value);
  };

  const renderJsonNode = (value, path, label, depth) => {
    // Skip null and undefined values — they clutter the tree without useful info
    if (value === null || value === undefined) return null;
    if (!hasJsonMatch(value, path)) return null;
    const isArray = Array.isArray(value);
    const isObject = value && typeof value === 'object' && !isArray;
    const nodeType = isArray ? 'Array' : isObject ? 'Object' : typeof value;

    if (!isArray && !isObject) {
      const isCopied = copiedPath === path;
      return (
        <div className="json-row" key={path}>
          <span className="json-key">{label}</span>
          <span className="json-value">{formatPrimitive(value)}</span>
          <button
            type="button"
            className={`json-copy${isCopied ? ' copied' : ''}`}
            title={isCopied ? 'Copied!' : 'Copy path'}
            onClick={(event) => {
              event.stopPropagation();
              copyToClipboard(path);
            }}
          >
            {isCopied ? 'Copied' : <Icons.Copy size={12} />}
          </button>
        </div>
      );
    }

    const entries = isArray ? value.map((item, idx) => [idx, item]) : Object.entries(value);
    const openByDefault = dataPreviewQuery ? true : depth < 2;
    const isCopiedGroup = copiedPath === path;

    return (
      <details className="json-group" open={openByDefault} key={path}>
        <summary>
          <span className="json-key">{label}</span>
          <span className="json-type">{nodeType}</span>
          <span className="json-count">{entries.length}</span>
          <button
            type="button"
            className={`json-copy${isCopiedGroup ? ' copied' : ''}`}
            title={isCopiedGroup ? 'Copied!' : 'Copy path'}
            onClick={(event) => {
              event.stopPropagation();
              copyToClipboard(path);
            }}
          >
            {isCopiedGroup ? 'Copied' : <Icons.Copy size={12} />}
          </button>
        </summary>
        <div className="json-children">
          {entries.map(([key, child]) => {
            const childPath = isArray ? `${path}[${key}]` : `${path}.${key}`;
            return renderJsonNode(child, childPath, key, depth + 1);
          })}
        </div>
      </details>
    );
  };

  const getValuePreview = (value) => {
    if (value === null) return <span className="json-null">null</span>;
    if (value === undefined) return <span className="json-undefined">undefined</span>;
    if (Array.isArray(value)) return <span className="json-type-preview">Array({value.length})</span>;
    if (typeof value === 'object') return <span className="json-type-preview">Object({Object.keys(value).length})</span>;
    if (typeof value === 'boolean') return <span className="json-boolean">{String(value)}</span>;
    if (typeof value === 'number') return <span className="json-number" title={String(value)}>{String(value)}</span>;
    if (typeof value === 'string') {
      // Truncate long strings, show full value on hover
      const truncated = value.length > 50 ? value.substring(0, 50) + '...' : value;
      return <span className="json-string" title={value}>{truncated}</span>;
    }
    return String(value);
  };

  const renderJsonPreview = (value, rootPath, rootLabel = 'Data') => {
    if (value === null || value === undefined) {
      return (
        <div className="data-preview-empty">
          No structured data to display.
        </div>
      );
    }
    if (typeof value !== 'object') {
      return (
        <div className="data-preview-view">
          <div className="data-preview-toolbar">
            <div className="data-preview-view-toggle">
              <button
                type="button"
                className={`data-preview-toggle ${dataPreviewView === 'simple' ? 'active' : ''}`}
                onClick={() => setDataPreviewView('simple')}
              >
                Simple
              </button>
              <button
                type="button"
                className={`data-preview-toggle ${dataPreviewView === 'tree' ? 'active' : ''}`}
                onClick={() => setDataPreviewView('tree')}
              >
                Tree
              </button>
              <button
                type="button"
                className={`data-preview-toggle ${dataPreviewView === 'raw' ? 'active' : ''}`}
                onClick={() => setDataPreviewView('raw')}
              >
                Raw
              </button>
            </div>
            <input
              className="data-preview-search"
              value={dataPreviewSearch}
              onChange={(e) => setDataPreviewSearch(e.target.value)}
              placeholder="Search keys or values..."
            />
          </div>
          {dataPreviewView === 'raw' && (
            <pre className="data-preview-output">{JSON.stringify(value, null, 2)}</pre>
          )}
          {dataPreviewView === 'tree' && (
            <div className="data-preview-tree">
              {renderJsonNode(value, rootPath, rootLabel, 0)}
            </div>
          )}
          {dataPreviewView === 'simple' && (
            <div className="data-preview-simple">
              <div className="data-preview-simple-header">
                <span>{rootLabel}</span>
                <span>{Array.isArray(value) ? `Array(${value.length})` : `Object(${Object.keys(value).length})`}</span>
              </div>
              <div className="data-preview-simple-body">
                {Object.entries(value).filter(([key, child]) => {
                  const path = `${rootPath}.${key}`;
                  return hasJsonMatch(child, path);
                }).map(([key, child]) => {
                  const path = `${rootPath}.${key}`;
                  return (
                    <div className="data-preview-simple-row" key={path}>
                      <div className="data-preview-simple-key">{key}</div>
                      <div className="data-preview-simple-value">{getValuePreview(child)}</div>
                      <button
                        type="button"
                        className="data-preview-simple-copy"
                        title="Copy path"
                        onClick={() => copyToClipboard(path)}
                      >
                        <Icons.Copy size={12} />
                      </button>
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </div>
      );
    }
    if (Array.isArray(value) && value.length === 0) {
      return (
        <div className="data-preview-empty">
          No structured data to display.
        </div>
      );
    }
    return (
      <div className="data-preview-view">
        <div className="data-preview-toolbar">
          <div className="data-preview-view-toggle">
            <button
              type="button"
              className={`data-preview-toggle ${dataPreviewView === 'tree' ? 'active' : ''}`}
              onClick={() => setDataPreviewView('tree')}
            >
              Tree
            </button>
            <button
              type="button"
              className={`data-preview-toggle ${dataPreviewView === 'raw' ? 'active' : ''}`}
              onClick={() => setDataPreviewView('raw')}
            >
              Raw
            </button>
          </div>
          <input
            className="data-preview-search"
            value={dataPreviewSearch}
            onChange={(e) => setDataPreviewSearch(e.target.value)}
            placeholder="Search keys or values..."
          />
        </div>
        {dataPreviewView === 'raw' ? (
          <pre className="data-preview-output">{JSON.stringify(value, null, 2)}</pre>
        ) : (
          <div className="data-preview-tree">
            {renderJsonNode(value, rootPath, rootLabel, 0)}
          </div>
        )}
      </div>
    );
  };

  const copyToClipboard = useCallback((text) => {
    if (!text) return;
    const flashCopied = () => {
      setCopiedPath(text);
      if (copiedPathTimerRef.current) clearTimeout(copiedPathTimerRef.current);
      copiedPathTimerRef.current = setTimeout(() => setCopiedPath(null), 1500);
      setActivityLog((prev) => [
        { id: `log-${Date.now()}`, time: 'just now', text: 'Copied data path' },
        ...prev,
      ]);
    };
    if (navigator?.clipboard?.writeText) {
      navigator.clipboard.writeText(text).then(flashCopied).catch(() => {});
      return;
    }
    const textarea = document.createElement('textarea');
    textarea.value = text;
    textarea.style.position = 'fixed';
    textarea.style.opacity = '0';
    document.body.appendChild(textarea);
    textarea.focus();
    textarea.select();
    try {
      document.execCommand('copy');
      flashCopied();
    } catch (err) {
      // ignore
    } finally {
      document.body.removeChild(textarea);
    }
  }, [setActivityLog]);

  useEffect(() => {
    if (dataPreviewLocked) return;
    if (selectedNodeId && dataPreviewMode === 'execution') {
      setDataPreviewNodeId(selectedNodeId);
    }
    if (selectedNodeId && dataPreviewMode === 'lookup') {
      setDataPreviewNodeId(selectedNodeId);
    }
  }, [selectedNodeId, dataPreviewMode, dataPreviewLocked]);

  useEffect(() => {
    setPreviewError(null);
    if (dataPreviewMode !== 'lookup') {
      setPreviewSuggestions([]);
      setPreviewSuggestionsLoading(false);
    }
  }, [dataPreviewMode]);

  useEffect(() => {
    if (!previewEntityId) {
      setPreviewEntityType(null);
      setPreviewAlert(null);
      setPreviewInvestigation(null);
      setPreviewTrigger((prev) => {
        if (!prev) return null;
        const { alert, investigation, ...rest } = prev;
        return Object.keys(rest).length ? rest : null;
      });
      setPreviewSuggestions([]);
      return;
    }
    setPreviewEntityType(null);
    setPreviewAlert(null);
    setPreviewInvestigation(null);
  }, [previewEntityId]);

  useEffect(() => {
    // Skip if the entity ID was just set by clicking a suggestion — the main search
    // effect (watching previewSearchDisplay) already handles the dropdown.
    if (justSelectedSearchRef.current) return;
    const query = String(previewEntityId ?? '').trim();
    if (query.length < 2) {
      setPreviewSuggestions([]);
      return;
    }
    const controller = new AbortController();
    const timeoutId = window.setTimeout(() => {
      setPreviewSuggestionsLoading(true);
      fetch(`/api/v1/playbooks/context/search?query=${encodeURIComponent(query)}&limit=8`, {
        credentials: 'include',
        signal: controller.signal,
      })
        .then((r) => (r.ok ? r.json() : Promise.reject(new Error(`Search failed (${r.status})`))))
        .then((data) => {
          setPreviewSuggestions(data.results || []);
        })
        .catch((err) => {
          if (err.name !== 'AbortError') {
            setPreviewSuggestions([]);
          }
        })
        .finally(() => setPreviewSuggestionsLoading(false));
    }, 300);

    return () => {
      controller.abort();
      window.clearTimeout(timeoutId);
    };
  }, [previewEntityId]);

  // Auto-load when the user pastes/types something that looks like a complete
  // alert or investigation id. Saves the analyst from having to hit Enter.
  useEffect(() => {
    if (justSelectedSearchRef.current) return;
    const value = String(previewSearchDisplay || '').trim();
    if (!value) return;
    const looksLikeUuid = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(value);
    const looksLikeAlertId = /^(PHI|MAL|BRU|INC|INV)-[A-Z0-9]+-[A-Z0-9]+$/i.test(value);
    if (!looksLikeUuid && !looksLikeAlertId) return;
    const timer = setTimeout(() => {
      justSelectedSearchRef.current = true;
      loadPreviewData(value);
      setPreviewEntityId(value);
      setPreviewSuggestions([]);
      setSearchFocused(false);
    }, 400);
    return () => clearTimeout(timer);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [previewSearchDisplay]);

  const handleBuildPlaybookFromPreview = useCallback(async () => {
    // Resolve the alert id from whichever entity is loaded in the preview.
    // Investigations carry an alert_id; an alert loaded directly is its own id.
    const alertId =
      previewAlert?.alert_id ||
      previewAlert?.id ||
      previewInvestigation?.alert_id ||
      null;
    if (!alertId) {
      setBuildFromPreviewState({
        loading: false,
        error: 'Load an alert (or an investigation with an alert) into the preview first.',
      });
      return;
    }
    setBuildFromPreviewState({ loading: true, error: null });
    try {
      const response = await authFetch(`${API_BASE_URL}/api/v1/riggs/playbooks/build-from-alert`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ alert_id: String(alertId), persist: true, use_llm: true }),
      });
      if (!response.ok) {
        const detail = await response.text();
        throw new Error(`Build failed: ${response.status} ${detail.slice(0, 200)}`);
      }
      const data = await response.json();
      const editorUrl = data.editor_url || (data.playbook_id ? `/playbooks/${data.playbook_id}` : null);
      if (editorUrl) {
        // Open in a new tab so the analyst doesn't lose their current canvas.
        window.open(editorUrl, '_blank', 'noopener');
        setBuildFromPreviewState({ loading: false, error: null });
      } else {
        setBuildFromPreviewState({ loading: false, error: 'No editor URL returned.' });
      }
    } catch (err) {
      console.error('Build playbook from preview failed:', err);
      setBuildFromPreviewState({ loading: false, error: err.message || 'Failed to build playbook' });
    }
  }, [previewAlert, previewInvestigation]);

  const loadPreviewData = useCallback(async (entityOverride) => {
    const id = String(entityOverride ?? previewEntityId ?? '').trim();
    if (!id) return;
    setPreviewLoading(true);
    setPreviewError(null);
    setPreviewSuggestions([]);
    try {
      const response = await fetch(`/api/v1/playbooks/context/${id}`, {
        credentials: 'include',
      });
      if (!response.ok) {
        throw new Error(`Failed to load (${response.status})`);
      }
      const data = await response.json();
      if (data.type === 'alert') {
        setPreviewEntityType('alert');
        setPreviewAlert(data.data);
        setPreviewInvestigation(null);
        setPreviewTrigger((prev) => ({
          ...(prev || {}),
          alert: data.data,
          alert_id: data.data.alert_id || data.data.id,
        }));
      } else if (data.type === 'investigation') {
        setPreviewEntityType('investigation');
        setPreviewInvestigation(data.data);
        setPreviewAlert(null);
        setPreviewTrigger((prev) => ({
          ...(prev || {}),
          investigation: data.data,
          investigation_id: data.data.investigation_id || data.data.id,
        }));
      } else {
        throw new Error('Unknown entity type');
      }
    } catch (err) {
      setPreviewError(err.message || 'Failed to load data');
    } finally {
      setPreviewLoading(false);
    }
  }, [previewEntityId]);

  useEffect(() => {
    if (selectedNodeId) {
      setShowNodeAdvanced(false);
    }
  }, [selectedNodeId]);

  const isExecutionActive = (status) => ['running', 'waiting', 'waiting_approval'].includes(status);

  useEffect(() => {
    if (!lastExecution?.execution_id || !isExecutionActive(lastExecution?.status)) return;
    const interval = setInterval(() => {
      fetch(`/api/v1/playbooks/executions/${lastExecution.execution_id}`)
        .then((r) => r.json())
        .then((data) => {
          setLastExecution(data);
          if (executionView?.execution_id === data.execution_id) {
            setExecutionView(data);
          }
        })
        .catch(e => console.error('Execution poll error:', e));
    }, 3000);
    return () => clearInterval(interval);
  }, [lastExecution?.execution_id, lastExecution?.status, executionView?.execution_id]);

  useEffect(() => {
    if (!lastExecution?.status) return;
    if (isExecutionActive(lastExecution.status)) {
      setFlowStatus('Running');
      return;
    }
    setFlowStatus(playbookMeta.is_enabled ? 'Live' : 'Draft');
  }, [lastExecution?.status, playbookMeta.is_enabled]);

  const nudgeViewportDown = useCallback((offset = 80) => {
    const instance = reactFlowRef.current;
    if (!instance?.getViewport || !instance?.setViewport) return;
    const viewport = instance.getViewport();
    instance.setViewport(
      { x: viewport.x, y: viewport.y + offset, zoom: viewport.zoom },
      { duration: 300 }
    );
  }, []);

  const loadSampleWorkflow = useCallback(() => {
    const shouldReplace = nodes.length === 0 || window.confirm('Replace the current workflow with the sample?');
    if (!shouldReplace) return;
    const sampleNodes = SAMPLE_WORKFLOW.canvas_data.nodes.map((node) => toStudioNode(node));
    const sampleEdges = toStudioEdges(SAMPLE_WORKFLOW.canvas_data.edges, sampleNodes);
    const spacedNodes = ensureReadableLayout(sampleNodes, sampleEdges);
    const spacedEdges = toStudioEdges(SAMPLE_WORKFLOW.canvas_data.edges, spacedNodes);
    setNodes(spacedNodes);
    setEdges(spacedEdges);
    setFlowName(SAMPLE_WORKFLOW.name);
    setFlowDescription(SAMPLE_WORKFLOW.description);
    setPlaybookMeta((prev) => ({
      ...prev,
      id: null,
      is_enabled: false,
      trigger_conditions: defaultTriggerConditions(),
    }));
    setFlowStatus('Draft');
    setSelectedNodeId(null);
    setActivityLog((prev) => [
      { id: `log-${Date.now()}`, time: 'just now', text: 'Loaded sample workflow' },
      ...prev,
    ]);
    setTimeout(() => {
      if (reactFlowRef.current) {
        reactFlowRef.current.fitView({ padding: 0.3, maxZoom: 1.2 });
        nudgeViewportDown(70);
      }
    }, 80);
  }, [nodes.length, setNodes, setEdges, nudgeViewportDown]);

  const executionNodeResults = useMemo(() => {
    if (!showExecutionOverlay) return {};
    return lastExecution?.node_results || {};
  }, [lastExecution?.node_results, showExecutionOverlay]);

  const runAutoLayout = useCallback(() => {
    setNodes((prev) => {
      const cloned = prev.map((node) => ({ ...node, position: { ...node.position } }));
      return autoLayoutNodes(cloned, edges);
    });
    requestAnimationFrame(() => {
      if (reactFlowRef.current) {
        reactFlowRef.current.fitView({ padding: 0.3, maxZoom: 1.2 });
        nudgeViewportDown(60);
      }
    });
  }, [edges, nudgeViewportDown, setNodes]);

  const flowOverlay = useMemo(() => {
    const result = { nodes: new Set(), edges: new Map() };
    if (!showFlowOverlay || !selectedNodeId) return result;

    const edgesBySource = new Map();
    const edgesByTarget = new Map();
    edges.forEach((edge) => {
      if (!edgesBySource.has(edge.source)) edgesBySource.set(edge.source, []);
      if (!edgesByTarget.has(edge.target)) edgesByTarget.set(edge.target, []);
      edgesBySource.get(edge.source).push(edge);
      edgesByTarget.get(edge.target).push(edge);
    });

    const visit = (startId, direction) => {
      const stack = [startId];
      const visited = new Set();
      while (stack.length) {
        const nodeId = stack.pop();
        if (visited.has(nodeId)) continue;
        visited.add(nodeId);
        result.nodes.add(nodeId);
        const nextEdges = direction === 'down'
          ? edgesBySource.get(nodeId) || []
          : edgesByTarget.get(nodeId) || [];
        nextEdges.forEach((edge) => {
          result.edges.set(edge.id, direction);
          const nextNode = direction === 'down' ? edge.target : edge.source;
          if (!visited.has(nextNode)) {
            stack.push(nextNode);
          }
        });
      }
    };

    visit(selectedNodeId, 'down');
    visit(selectedNodeId, 'up');
    return result;
  }, [edges, selectedNodeId, showFlowOverlay]);

  const startLeftResize = useCallback((event) => {
    event.preventDefault();
    resizeStateRef.current = {
      startX: event.clientX,
      startWidth: leftPanelWidth,
    };
    document.body.style.cursor = 'col-resize';
    document.body.style.userSelect = 'none';

    const handleMouseMove = (moveEvent) => {
      if (!resizeStateRef.current) return;
      const { startX, startWidth } = resizeStateRef.current;
      const delta = moveEvent.clientX - startX;
      const nextWidth = Math.min(
        LEFT_PANEL_MAX_WIDTH,
        Math.max(LEFT_PANEL_MIN_WIDTH, startWidth + delta)
      );
      setLeftPanelWidth(nextWidth);
    };

    const handleMouseUp = () => {
      resizeStateRef.current = null;
      document.body.style.cursor = '';
      document.body.style.userSelect = '';
      window.removeEventListener('mousemove', handleMouseMove);
      window.removeEventListener('mouseup', handleMouseUp);
    };

    window.addEventListener('mousemove', handleMouseMove);
    window.addEventListener('mouseup', handleMouseUp);
  }, [leftPanelWidth]);

  const startRightResize = useCallback((event) => {
    event.preventDefault();
    rightResizeStateRef.current = {
      startX: event.clientX,
      startWidth: rightPanelWidth,
    };
    document.body.style.cursor = 'col-resize';
    document.body.style.userSelect = 'none';

    const handleMouseMove = (moveEvent) => {
      if (!rightResizeStateRef.current) return;
      const { startX, startWidth } = rightResizeStateRef.current;
      const delta = startX - moveEvent.clientX;
      const nextWidth = Math.min(
        RIGHT_PANEL_MAX_WIDTH,
        Math.max(RIGHT_PANEL_MIN_WIDTH, startWidth + delta)
      );
      setRightPanelWidth(nextWidth);
    };

    const handleMouseUp = () => {
      rightResizeStateRef.current = null;
      document.body.style.cursor = '';
      document.body.style.userSelect = '';
      window.removeEventListener('mousemove', handleMouseMove);
      window.removeEventListener('mouseup', handleMouseUp);
    };

    window.addEventListener('mousemove', handleMouseMove);
    window.addEventListener('mouseup', handleMouseUp);
  }, [rightPanelWidth]);

  const startCodePanelResize = useCallback((event) => {
    event.preventDefault();
    event.stopPropagation();
    const canvasEl = reactFlowWrapperRef.current;
    if (!canvasEl) return;
    const canvasRect = canvasEl.getBoundingClientRect();
    codePanelResizeRef.current = { startY: event.clientY, startHeight: codePanelHeight, canvasBottom: canvasRect.bottom, canvasHeight: canvasRect.height };
    document.body.style.cursor = 'row-resize';
    document.body.style.userSelect = 'none';

    const onMove = (e) => {
      if (!codePanelResizeRef.current) return;
      const { startY, startHeight, canvasHeight } = codePanelResizeRef.current;
      const delta = startY - e.clientY;
      const next = Math.min(canvasHeight - 60, Math.max(120, startHeight + delta));
      setCodePanelHeight(next);
    };
    const onUp = () => {
      codePanelResizeRef.current = null;
      document.body.style.cursor = '';
      document.body.style.userSelect = '';
      window.removeEventListener('mousemove', onMove);
      window.removeEventListener('mouseup', onUp);
    };
    window.addEventListener('mousemove', onMove);
    window.addEventListener('mouseup', onUp);
  }, [codePanelHeight]);

  const handlePythonEditorMount = useCallback((editor, monaco) => {
    if (pythonCompletionRef.current) return;
    pythonCompletionRef.current = true;
    registerPythonCompletions(monaco);
  }, []);

  const stableTestNode = useCallback(() => handleTestNodeRef.current?.(), []);

  const renderNodes = useMemo(
    () => nodes.map((node) => {
      const execResult = executionNodeResults[node.id];
      const flowState = flowOverlay.nodes.has(node.id)
        ? node.id === selectedNodeId
          ? 'focused'
          : 'connected'
        : null;
      return {
        ...node,
        data: {
          ...node.data,
          onDelete: handleDeleteNode,
          onTest: stableTestNode,
          testLoading: nodeTestLoading && nodeTestNodeId === node.id,
          executionStatus: execResult?.status,
          executionTimeMs: execResult?.duration_ms ?? execResult?.execution_time_ms,
          executionIsCurrent: showExecutionOverlay && lastExecution?.current_node_id === node.id,
          flowState,
        },
      };
    }),
    [nodes, handleDeleteNode, stableTestNode, nodeTestLoading, nodeTestNodeId, executionNodeResults, flowOverlay.nodes, selectedNodeId, showExecutionOverlay, lastExecution?.current_node_id]
  );

  const renderEdges = useMemo(
    () => edges.map((edge) => ({
      ...edge,
      type: edge.type || 'deletable',
      data: {
        ...(edge.data || {}),
        onDelete: handleDeleteEdge,
        flowDirection: flowOverlay.edges.get(edge.id) || null,
      },
    })),
    [edges, handleDeleteEdge, flowOverlay.edges]
  );

  // Track if a connection was successfully made (for drop menu logic)
  const connectionMadeRef = useRef(false);

  const onConnect = useCallback(
    (params) => {
      // Mark that a valid connection was made
      connectionMadeRef.current = true;

      // Look up branch label from source node's config using ref for latest state
      const currentNodes = nodesRef.current;
      const sourceNode = currentNodes.find((n) => n.id === params.source);
      let edgeLabel;
      if (sourceNode?.data?.kind === 'decision') {
        const branches = sourceNode.data?.config?.branches || [
          { id: 'yes', label: 'Yes' },
          { id: 'no', label: 'No' },
        ];
        const branch = branches.find((b) => b.id === params.sourceHandle);
        edgeLabel = branch?.label;
      }
      setEdges((eds) =>
        addEdge(
          {
            ...params,
            animated: true,
            type: 'deletable',
            data: { label: edgeLabel, onDelete: handleDeleteEdge },
          },
          eds
        )
      );
    },
    [setEdges, handleDeleteEdge]
  );

  // Track pending connection for drop menu
  const pendingConnection = useRef(null);

  const onConnectStart = useCallback((event, { nodeId, handleId, handleType }) => {
    pendingConnection.current = { nodeId, handleId, handleType };
    setConnectMenu(null);
  }, []);

  const onConnectEnd = useCallback((event) => {
    if (!pendingConnection.current) return;

    const { nodeId, handleId, handleType } = pendingConnection.current;

    // Check if a connection was actually made (onConnect would have fired)
    // If not, we dropped in empty space
    if (!connectionMadeRef.current && handleType === 'source') {
      // Use screen coordinates directly (menu uses fixed positioning)
      // Offset slightly so menu appears below/right of cursor
      const x = event.clientX + 8;
      const y = event.clientY + 8;
      setConnectMenu({ x, y, sourceId: nodeId, sourceHandle: handleId });
      suppressPaneClickRef.current = true;
      window.setTimeout(() => {
        suppressPaneClickRef.current = false;
      }, 150);
    }

    connectionMadeRef.current = false;
    pendingConnection.current = null;
  }, []);

  const handleConnectMenuSelect = useCallback((kind) => {
    if (!connectMenu) return;

    const instance = reactFlowRef.current;
    if (!instance) return;

    // Convert screen position to flow position
    const position = instance.screenToFlowPosition({ x: connectMenu.x, y: connectMenu.y });

    // Create new node
    const newNodeId = `node-${Date.now()}`;
    const blockDef = CANONICAL_BLOCKS[kind];
    const newNode = {
      id: newNodeId,
      type: 'signal',
      position: { x: position.x - 100, y: position.y },
      data: {
        kind,
        title: blockDef?.label || kind,
        summary: blockDef?.hint || 'Describe your intent',
        config: defaultConfig(kind),
        onDelete: handleDeleteNode,
      },
    };

    // Get edge label for decision nodes
    const currentNodes = nodesRef.current;
    const sourceNode = currentNodes.find((n) => n.id === connectMenu.sourceId);
    let edgeLabel;
    if (sourceNode?.data?.kind === 'decision') {
      const branches = sourceNode.data?.config?.branches || [
        { id: 'yes', label: 'Yes' },
        { id: 'no', label: 'No' },
      ];
      const branch = branches.find((b) => b.id === connectMenu.sourceHandle);
      edgeLabel = branch?.label;
    }

    // Create edge connecting to new node
    const newEdge = {
      id: `edge-${Date.now()}`,
      source: connectMenu.sourceId,
      sourceHandle: connectMenu.sourceHandle,
      target: newNodeId,
      animated: true,
      type: 'deletable',
      data: { label: edgeLabel, onDelete: handleDeleteEdge },
    };

    setNodes((nds) => [...nds, newNode]);
    setEdges((eds) => [...eds, newEdge]);
    setConnectMenu(null);
    setSelectedNodeId(newNodeId);

    setActivityLog((prev) => [
      { id: `log-${Date.now()}`, time: 'just now', text: `Added ${blockDef?.label || kind} block` },
      ...prev,
    ]);
  }, [connectMenu, handleDeleteNode, handleDeleteEdge, setNodes, setEdges]);

  // Handle node deletion (remove connected edges too)
  const onNodesDelete = useCallback(
    (deleted) => {
      const deletedIds = deleted.map((node) => node.id);
      if (selectedNodeId && deletedIds.includes(selectedNodeId)) {
        setSelectedNodeId(null);
      }
      setEdges((eds) => eds.filter((edge) => !deletedIds.includes(edge.source) && !deletedIds.includes(edge.target)));
      setActivityLog((prev) => [
        { id: `log-${Date.now()}`, time: 'just now', text: `Deleted ${deletedIds.length} node(s)` },
        ...prev,
      ]);
    },
    [selectedNodeId, setEdges]
  );

  // Handle edge deletion
  const onEdgesDelete = useCallback(
    (deleted) => {
      const deletedIds = deleted.map((edge) => edge.id);
      setActivityLog((prev) => [
        { id: `log-${Date.now()}`, time: 'just now', text: `Deleted ${deletedIds.length} path(s)` },
        ...prev,
      ]);
    },
    []
  );

  // Removed: fitView on every nodes/edges change was interfering with imported positions
  // useEffect(() => {
  //   if (!reactFlowRef.current) return;
  //   reactFlowRef.current.fitView({ padding: 0.25, maxZoom: 1 });
  // }, [nodes.length, edges.length]);

  // Load from sessionStorage (Riggs Studio)
  useEffect(() => {
    if (playbookId && playbookId !== 'new') return;
    const stored = sessionStorage.getItem('riggs_generated_playbook');
    if (!stored) return;
    try {
      const payload = JSON.parse(stored);
      const canvas = payload?.canvas_data || payload;
      if (canvas?.nodes && canvas?.edges) {
        const mappedNodes = canvas.nodes.map((node) => toStudioNode(node, false));
        const mappedEdges = toStudioEdges(canvas.edges, mappedNodes);
        const spacedNodes = ensureReadableLayout(mappedNodes, mappedEdges);
        const spacedEdges = toStudioEdges(canvas.edges, spacedNodes);
        setNodes(spacedNodes);
        setEdges(spacedEdges);
        if (payload?.name) setFlowName(payload.name);
        if (payload?.description) setFlowDescription(payload.description);
        setPlaybookMeta((prev) => ({
          ...prev,
          tags: payload?.tags || prev.tags,
          alert_types: payload?.alert_types || prev.alert_types,
        }));
        setSelectedNodeId(null);
        setFlowStatus('Draft');
        if (reactFlowRef.current) {
          reactFlowRef.current.fitView({ padding: 0.25, maxZoom: 1 });
        }
      }
    } finally {
      sessionStorage.removeItem('riggs_generated_playbook');
    }
  }, [playbookId, setNodes, setEdges]);

  // Load from sessionStorage (Codex converter)
  useEffect(() => {
    const stored = sessionStorage.getItem('codex_converted_playbook');
    if (!stored) return;
    try {
      const payload = JSON.parse(stored);
      if (payload?.nodes && payload?.edges) {
        const mappedNodes = payload.nodes.map((node) => toStudioNode(node, false));
        const mappedEdges = toStudioEdges(payload.edges, mappedNodes);
        const spacedNodes = ensureReadableLayout(mappedNodes, mappedEdges);
        const spacedEdges = toStudioEdges(payload.edges, spacedNodes);
        setNodes(spacedNodes);
        setEdges(spacedEdges);
        if (payload.name) setFlowName(payload.name);
        setSelectedNodeId(null);
        setFlowStatus('Draft');
        if (reactFlowRef.current) {
          reactFlowRef.current.fitView({ padding: 0.25, maxZoom: 1 });
        }
      }
    } finally {
      sessionStorage.removeItem('codex_converted_playbook');
    }
  }, [setNodes, setEdges]);

  // Template picker: show on new playbook, fetch marketplace templates
  const fetchMktTemplates = useCallback(async () => {
    setMktTemplatesLoading(true);
    try {
      const res = await authFetch('/api/v1/playbooks/marketplace/browse?per_page=60');
      if (res.ok) {
        const data = await res.json();
        setMktTemplates(data.templates || []);
      }
    } catch { /* network error — fall through to built-in templates */ }
    finally { setMktTemplatesLoading(false); }
  }, []);

  useEffect(() => {
    if (playbookId && playbookId !== 'new') return;
    const hasRiggs = !!sessionStorage.getItem('riggs_generated_playbook');
    const hasCodex = !!sessionStorage.getItem('codex_converted_playbook');
    if (hasRiggs || hasCodex) return;
    setShowTemplatePicker(true);
    fetchMktTemplates();
  }, [playbookId, fetchMktTemplates]);

  const handlePickMarketplaceTemplate = useCallback(async (template) => {
    setMktTemplateLoadingId(template.id);
    try {
      const res = await authFetch(`/api/v1/playbooks/marketplace/${template.id}`);
      if (res.ok) {
        const data = await res.json();
        const raw = data.canvas_data || data;
        const canvas = typeof raw === 'string' ? JSON.parse(raw) : raw;
        if (canvas?.nodes && canvas?.edges) {
          const mappedNodes = canvas.nodes.map((n) => toStudioNode(n, false));
          const mappedEdges = toStudioEdges(canvas.edges, mappedNodes);
          const spacedNodes = ensureReadableLayout(mappedNodes, mappedEdges);
          const spacedEdges = toStudioEdges(canvas.edges, spacedNodes);
          setNodes(spacedNodes);
          setEdges(spacedEdges);
          setFlowName(data.name || template.name || 'New Playbook');
          if (data.description) setFlowDescription(data.description);
          setActivityLog((prev) => [
            { id: `log-${Date.now()}`, time: 'just now', text: `Loaded template: ${data.name || template.name}` },
            ...prev,
          ]);
        }
      }
    } catch { /* load failed — stay on blank canvas */ }
    finally {
      setMktTemplateLoadingId(null);
      setShowTemplatePicker(false);
    }
  }, [setNodes, setEdges]);

  const loadCatalogs = useCallback(async () => {
    try {
      const [listsRes, funcsRes] = await Promise.all([
        authFetch('/api/v1/playbooks/lists'),
        authFetch('/api/v1/playbooks/functions'),
      ]);
      if (listsRes.ok) {
        const listsData = await listsRes.json();
        setAvailableLists(listsData.lists || []);
      }
      if (funcsRes.ok) {
        const funcsData = await funcsRes.json();
        setAvailableFunctions(funcsData.functions || []);
      }
    } catch (err) {
    }
  }, []);

  // Load custom lists and functions for config dropdowns
  useEffect(() => {
    loadCatalogs();
  }, [loadCatalogs]);

  useEffect(() => {
    const loadIntegrations = async () => {
      try {
        // Load legacy integrations for backward compatibility
        const response = await authFetch('/api/v1/connect/instances');
        if (response.ok) {
          const data = await response.json();
          setAvailableIntegrations(data.instances || data.integrations || data || []);
        }
      } catch (err) {
      }

      // Load playbook integrations with endpoints
      try {
        const pbResponse = await authFetch('/api/v1/playbooks/config/integrations');
        if (pbResponse.ok) {
          const pbData = await pbResponse.json();
          setPlaybookIntegrations(pbData.integrations || []);
        }
      } catch (err) {
      }
    };

    loadIntegrations();
  }, []);

  // Load playbook from API when playbookId is present
  useEffect(() => {
    if (!playbookId || playbookId === 'new') return;

    const fetchPlaybook = async () => {
      setLoading(true);
      setLoadError(null);

      try {
        const response = await fetch(`/api/v1/playbooks/${playbookId}`, {
          credentials: 'include'
        });

        if (!response.ok) {
          throw new Error(`Failed to load playbook: ${response.status}`);
        }

        const data = await response.json();

        // Load canvas data (nodes and edges)
          if (data.canvas_data) {
            const rawNodes = Array.isArray(data.canvas_data.nodes) ? data.canvas_data.nodes : [];
            const rawEdges = Array.isArray(data.canvas_data.edges) ? data.canvas_data.edges : [];
          const transformedNodes = rawNodes.map((node) => toStudioNode(node, data.is_enabled));
          const transformedEdges = toStudioEdges(rawEdges, transformedNodes);
          const spacedNodes = ensureReadableLayout(transformedNodes, transformedEdges);
          const spacedEdges = toStudioEdges(rawEdges, spacedNodes);
          setNodes(spacedNodes);
          setEdges(spacedEdges);
        }

        // Set playbook metadata
        if (data.name) {
          setFlowName(data.name);
        }
        if (data.description) {
          setFlowDescription(data.description);
        }
        setPlaybookMeta((prev) => ({
          ...prev,
          id: data.id || prev.id,
          is_enabled: !!data.is_enabled,
          riggs_allowed: !!data.riggs_allowed,
          trigger_timing: data.trigger_timing || 'post_triage',
          trigger_conditions: data.trigger_conditions || defaultTriggerConditions(),
          tags: data.tags || [],
          alert_types: data.alert_types || [],
          severity_filter: data.severity_filter || [],
          data_sources: data.data_sources || [],
          priority: data.priority || 50,
        }));
        setFlowStatus(data.is_enabled ? 'Live' : 'Draft');
        telemetry.track('workflow', 'workflow.open', { playbook_id: playbookId });

        // Reset selection
        setSelectedNodeId(null);

        // Fit view ONCE after loading imported playbook (helps position viewport correctly)
        // This doesn't change node positions, just adjusts viewport to see all nodes
        setTimeout(() => {
          if (reactFlowRef.current) {
            reactFlowRef.current.fitView({ padding: 0.3, maxZoom: 1.4 });
            nudgeViewportDown(70);
          }
        }, 100);

      } catch (err) {
        setLoadError(err.message);
      } finally {
        setLoading(false);
      }
    };

    fetchPlaybook();
  }, [playbookId, setNodes, setEdges, nudgeViewportDown]);

  useEffect(() => {
    if (executionView?.status === 'running') {
      setFlowStatus('Running');
    } else {
      setFlowStatus(playbookMeta.is_enabled ? 'Live' : 'Draft');
    }
  }, [executionView?.status, playbookMeta.is_enabled]);

  const createNode = (kind, position) => {
    const id = `${kind}-${Date.now()}`;
    return {
      id,
      type: 'signal',
      position,
      data: baseNode(kind, `${capitalize(kind)} Node`, 'Describe your intent', defaultConfig(kind)),
    };
  };

  const hasTriggerNode = useCallback(
    (nodeList = nodes) => nodeList.some((node) => node.data?.kind === 'trigger'),
    [nodes]
  );

  const addNode = (kind) => {
    if (kind === 'trigger' && hasTriggerNode()) {
      setActivityLog((prev) => [
        { id: `log-${Date.now()}`, time: 'just now', text: 'Only one trigger is allowed per playbook.' },
        ...prev,
      ]);
      return;
    }
    const baseX = 520;
    const offsetX = kind === 'decision' ? -140 : kind === 'action' ? 140 : 0;
    const position = {
      x: baseX + offsetX,
      y: 220 + nodes.length * 170,
    };
    const next = createNode(kind, position);
    setNodes((prev) => {
      const updated = [...prev, next];
      if (autoLayoutEnabled) {
        return autoLayoutNodes(updated.map((node) => ({ ...node, position: { ...node.position } })), edges);
      }
      return updated;
    });
    setSelectedNodeId(next.id);
    setActivityLog((prev) => [
      { id: `log-${Date.now()}`, time: 'just now', text: `Added ${kind} node` },
      ...prev,
    ]);
  };

  const onDragStart = (event, kind) => {
    event.dataTransfer.setData('application/t1flow', kind);
    event.dataTransfer.effectAllowed = 'move';
  };

  const onDragOver = useCallback((event) => {
    event.preventDefault();
    event.dataTransfer.dropEffect = 'move';
  }, []);

  const onDrop = useCallback((event) => {
    event.preventDefault();
    const kind = event.dataTransfer.getData('application/t1flow');
    if (!kind) return;
    if (kind === 'trigger' && hasTriggerNode()) {
      setActivityLog((prev) => [
        { id: `log-${Date.now()}`, time: 'just now', text: 'Only one trigger is allowed per playbook.' },
        ...prev,
      ]);
      return;
    }

    const position = reactFlowRef.current?.screenToFlowPosition
      ? reactFlowRef.current.screenToFlowPosition({
          x: event.clientX,
          y: event.clientY,
        })
      : { x: event.clientX, y: event.clientY };

    const next = createNode(kind, position);
    setNodes((prev) => {
      const updated = [...prev, next];
      if (autoLayoutEnabled) {
        return autoLayoutNodes(updated.map((node) => ({ ...node, position: { ...node.position } })), edges);
      }
      return updated;
    });
    setSelectedNodeId(next.id);
    setActivityLog((prev) => [
      { id: `log-${Date.now()}`, time: 'just now', text: `Dropped ${kind} node` },
      ...prev,
    ]);
  }, [createNode, hasTriggerNode, autoLayoutEnabled, edges]);

  const applyTemplate = (template) => {
    const triggerCount = template.nodes?.filter((node) => node.data?.kind === 'trigger').length || 0;
    if (triggerCount > 1) {
      setSaveError('Playbooks can only have one trigger. This template has multiple triggers.');
      return;
    }
    setNodes(template.nodes);
    setEdges(template.edges);
    setSelectedNodeId(null);
    setFlowName(template.name);
    setActivityLog((prev) => [
      { id: `log-${Date.now()}`, time: 'just now', text: `Loaded template: ${template.name}` },
      ...prev,
    ]);
  };

  const handleTestNode = useCallback(async () => {
    if (!selectedNode || !playbookMeta?.id) return;
    const kind = selectedNode.data?.kind;
    const config = selectedNode.data?.config || {};
    setNodeTestLoading(true);
    setNodeTestResult(null);
    setNodeTestNodeId(selectedNode.id);
    try {
      const res = await authFetch(`/api/v1/playbooks/${playbookMeta.id}/test-node`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          node_id: selectedNode.id,
          node_kind: kind,
          node_config: config,
          sample_context: previewTrigger
            ? { alert: previewTrigger, manual: false }
            : null,
        }),
      });
      const data = await res.json();
      setNodeTestResult(data);
    } catch (err) {
      setNodeTestResult({ ok: false, error: err.message || 'Request failed', outputs: {} });
    } finally {
      setNodeTestLoading(false);
    }
  }, [selectedNode, playbookMeta, previewTrigger]);
  handleTestNodeRef.current = handleTestNode;

  const updateNode = (updates) => {
    if (!selectedNode) return;
    setNodes((prev) =>
      prev.map((node) =>
        node.id === selectedNode.id
          ? { ...node, data: { ...node.data, ...updates } }
          : node
      )
    );
  };

  const updateNodeConfig = (updates) => {
    if (!selectedNode) return;
    setNodes((prev) =>
      prev.map((node) =>
        node.id === selectedNode.id
          ? { ...node, data: { ...node.data, config: { ...node.data.config, ...updates } } }
          : node
      )
    );
  };

  const openDataPathPicker = (nodeId, fieldName, meta = {}) => {
    setDataPathContext({ nodeId, fieldName, ...meta });
    setShowDataPathPicker(true);
  };

  const selectDataPath = (path) => {
    if (!dataPathContext || !path) return;
    if (selectedNode && selectedNode.id === dataPathContext.nodeId) {
      if (dataPathContext.mode === 'inputs') {
        const currentInputs = selectedNode.data?.config?.script?.inputs || selectedNode.data?.config?.inputs;
        const currentEntries = Array.isArray(currentInputs)
          ? currentInputs
          : normalizeInputsEntries(currentInputs);
        const nextEntries = currentEntries.map((entry, index) =>
          index === dataPathContext.inputIndex ? { ...entry, value: path } : entry
        );
        if (selectedNode.data?.kind === 'code' && selectedNode.data?.config?.mode === 'script') {
          updateNodeConfig({
            script: {
              ...(selectedNode.data?.config?.script || {}),
              inputs: nextEntries,
            },
          });
        } else {
          updateNodeConfig({ inputs: nextEntries });
        }
      } else if (dataPathContext.mode === 'decision') {
        const current = normalizeDecisionConfig(selectedNode.data?.config || {});
        const next = updateDecisionConditionPath(current.conditions, dataPathContext.conditionId, path, dataPathContext.side);
        const expression = compileDecisionGroup(next);
        updateNodeConfig({ conditions: next, expression });
      } else {
        const fieldName = dataPathContext.fieldName;
        if (fieldName && fieldName.includes('.')) {
          const [root, child] = fieldName.split('.');
          const currentRoot = selectedNode.data?.config?.[root] || {};
          updateNodeConfig({ [root]: { ...currentRoot, [child]: path } });
        } else {
          updateNodeConfig({ [dataPathContext.fieldName]: path });
        }
      }
    }
    setShowDataPathPicker(false);
    setDataPathContext(null);
  };

  const updateTriggerCondition = (key, value) => {
    setPlaybookMeta((prev) => ({
      ...prev,
      trigger_conditions: {
        ...prev.trigger_conditions,
        [key]: value,
      },
    }));
  };

  const updateTriggerNested = (section, key, value) => {
    setPlaybookMeta((prev) => ({
      ...prev,
      trigger_conditions: {
        ...prev.trigger_conditions,
        [section]: {
          ...(prev.trigger_conditions?.[section] || {}),
          [key]: value,
        },
      },
    }));
  };

  const normalizeListInput = (raw) => raw
    .split(',')
    .map((entry) => entry.trim())
    .filter(Boolean);

  const updateMetaList = (field, updater) => {
    setPlaybookMeta((prev) => ({
      ...prev,
      [field]: updater(prev[field] || []),
    }));
  };

  const updateTriggerList = (field, updater) => {
    setPlaybookMeta((prev) => ({
      ...prev,
      trigger_conditions: {
        ...prev.trigger_conditions,
        [field]: updater(prev.trigger_conditions?.[field] || []),
      },
    }));
  };

  const addToList = (field, raw, scope = 'meta') => {
    const items = normalizeListInput(raw);
    if (items.length === 0) return;
    const update = (prevList) => {
      const set = new Set(prevList);
      items.forEach((item) => set.add(item));
      return Array.from(set);
    };
    if (scope === 'trigger') {
      updateTriggerList(field, update);
    } else {
      updateMetaList(field, update);
    }
  };

  const removeFromList = (field, value, scope = 'meta') => {
    const update = (prevList) => prevList.filter((item) => item !== value);
    if (scope === 'trigger') {
      updateTriggerList(field, update);
    } else {
      updateMetaList(field, update);
    }
  };

  const toggleRiggsAllowed = async (nextValue) => {
    setPlaybookMeta((prev) => ({ ...prev, riggs_allowed: nextValue }));
    if (!playbookMeta.id) return;
    try {
      const endpoint = nextValue ? 'allow-riggs' : 'disallow-riggs';
      await fetch(`/api/v1/playbooks/${playbookMeta.id}/${endpoint}`, {
        method: 'POST',
        credentials: 'include',
      });
    } catch (err) {
    }
  };

  // Validation helper - checks for incomplete node configurations
  const validatePlaybook = (nodesToValidate, edgesToValidate) => {
    const warnings = [];
    const errors = [];
    const allIntegrations = playbookIntegrations.length > 0 ? playbookIntegrations : availableIntegrations;
    const getIntegrationEndpoint = (config = {}) => {
      const selectedIntegration = allIntegrations.find(
        (i) => i.instance_id === config.integration_instance_id || i.id === config.integration_instance_id || i.id === config.integration
      );
      if (!selectedIntegration) return { integration: null, endpoint: null };
      const endpoints = selectedIntegration.endpoints || selectedIntegration.actions || [];
      const endpoint = endpoints.find((e) => e.id === config.endpoint_id || e.name === config.endpoint_id);
      return { integration: selectedIntegration, endpoint };
    };

    // Check trigger count
    const triggerCount = nodesToValidate.filter((n) => n.data?.kind === 'trigger').length;
    if (triggerCount === 0) {
      errors.push('Playbook must include exactly one trigger node.');
    } else if (triggerCount > 1) {
      errors.push('Playbook can only have one trigger node.');
    }

    // Check for nodes requiring configuration
    const integrationNodes = ['action'];
    nodesToValidate.forEach((node) => {
      const kind = node.data?.kind;
      const config = node.data?.config || {};
      const label = node.data?.title || node.data?.label || kind;

      if (integrationNodes.includes(kind)) {
        if (!config.integration_instance_id || !config.endpoint_id) {
          warnings.push(`"${label}" (${kind}): Integration or endpoint not configured.`);
        }

        const { endpoint } = getIntegrationEndpoint(config);
        if (endpoint) {
          const requiredFields = Array.isArray(endpoint?.parameters)
            ? endpoint.parameters.filter((param) => param?.required).map((param) => param.name)
            : Array.isArray(endpoint?.params)
              ? endpoint.params.filter((param) => param?.required).map((param) => param.name)
              : Array.isArray(endpoint?.request?.schema?.required)
                ? endpoint.request.schema.required
                : [];
          if (requiredFields.length > 0) {
            const params = config.params || {};
            requiredFields.forEach((field) => {
              const value = params?.[field];
              if (value === undefined || value === null || String(value).trim() === '') {
                warnings.push(`"${label}" (${kind}): Missing required field "${field}".`);
              }
            });
          }
        }
      }

      if (kind === 'loop' && !config.items_path) {
        warnings.push(`"${label}" (loop): No items path configured.`);
      }

      if (kind === 'decision') {
        const expression = compileDecisionGroup((config.conditions || createDecisionGroup()));
        if (!expression) {
          warnings.push(`"${label}" (decision): No conditions configured.`);
        }
      }

      if (kind === 'code') {
        const mode = config.mode || config.transform_type || 'extract';
        if (mode === 'assign' && !config.assign?.name) {
          warnings.push(`"${label}" (code): No variable name set for assignment.`);
        }
        if (['extract', 'map', 'filter'].includes(mode) && !config.input_path) {
          warnings.push(`"${label}" (code): No input path configured.`);
        }
      }
    });

    // Check for orphan nodes (not connected to flow)
    const connectedNodeIds = new Set();
    edgesToValidate.forEach((edge) => {
      connectedNodeIds.add(edge.source);
      connectedNodeIds.add(edge.target);
    });
    nodesToValidate.forEach((node) => {
      if (node.data?.kind !== 'trigger' && !connectedNodeIds.has(node.id)) {
        const label = node.data?.title || node.data?.label || node.data?.kind;
        warnings.push(`"${label}" is not connected to the workflow.`);
      }
    });

    return { warnings, errors };
  };

  const savePlaybook = async ({ navigateOnCreate = true } = {}) => {
    // Run validation
    const { warnings, errors } = validatePlaybook(nodes, edges);

    // Block save on errors
    if (errors.length > 0) {
      setSaveError(errors.join(' '));
      return null;
    }

    // Show warnings but allow save
    if (warnings.length > 0) {
      const proceed = window.confirm(
        `Playbook has configuration warnings:\n\n• ${warnings.join('\n• ')}\n\nSave anyway?`
      );
      if (!proceed) return null;
    }

    setIsSaving(true);
    setSaveError(null);

    try {
      const canvasData = toEngineCanvas(nodes, edges);
      const payload = {
        name: flowName || 'Untitled Workflow',
        description: flowDescription || '',
        trigger_conditions: playbookMeta.trigger_conditions || defaultTriggerConditions(),
        canvas_data: canvasData,
        tags: playbookMeta.tags || [],
        alert_types: playbookMeta.alert_types || [],
        severity_filter: playbookMeta.severity_filter || [],
        data_sources: playbookMeta.data_sources || [],
        priority: playbookMeta.priority || 50,
        trigger_timing: playbookMeta.trigger_timing || 'post_triage',
        riggs_allowed: !!playbookMeta.riggs_allowed,
      };

      let response;
      if (playbookMeta.id) {
        response = await authFetch(`${API_BASE_URL}/api/v1/playbooks/${playbookMeta.id}`, {
          method: 'PUT',
          body: JSON.stringify(payload),
        });
      } else {
        response = await authFetch(`${API_BASE_URL}/api/v1/playbooks`, {
          method: 'POST',
          body: JSON.stringify(payload),
        });
      }

      if (!response.ok) {
        throw new Error(`Failed to save playbook (${response.status})`);
      }

      const data = await response.json();
      const saved = data.playbook || data;
      setPlaybookMeta((prev) => ({
        ...prev,
        id: saved.id || prev.id,
        is_enabled: !!saved.is_enabled,
        riggs_allowed: !!saved.riggs_allowed,
        trigger_timing: saved.trigger_timing || prev.trigger_timing || 'post_triage',
      }));

      if (saved.name) {
        setFlowName(saved.name);
      }
      if (navigateOnCreate && saved.id && saved.id !== playbookMeta.id) {
        navigate(`/playbooks/${saved.id}`);
      }

      setActivityLog((prev) => [
        { id: `log-${Date.now()}`, time: 'just now', text: 'Draft saved' },
        ...prev,
      ]);
      clearDraft(); // Clear localStorage draft on successful save
      return saved;
    } catch (err) {
      setSaveError(err.message || 'Failed to save playbook');
      return null;
    } finally {
      setIsSaving(false);
    }
  };

  const handlePublish = async () => {
    const saved = await savePlaybook();
    if (!saved?.id) return;

    try {
      const response = await fetch(`/api/v1/playbooks/${saved.id}/enable`, {
        method: 'POST',
        credentials: 'include',
      });
      if (!response.ok) {
        throw new Error(`Failed to publish (${response.status})`);
      }
      setPlaybookMeta((prev) => ({ ...prev, is_enabled: true }));
      setFlowStatus('Live');
      setActivityLog((prev) => [
        { id: `log-${Date.now()}`, time: 'just now', text: 'Published playbook' },
        ...prev,
      ]);
    } catch (err) {
      setSaveError(err.message || 'Failed to publish');
    }
  };

  const handleSubmitToCommunity = async () => {
    // Save first so we know the playbook has an id, then prompt for a note.
    const saved = await savePlaybook({ navigateOnCreate: false });
    if (!saved?.id) {
      setSubmitCommunityState({ loading: false, status: null, error: 'Save the playbook first.' });
      return;
    }
    const notes = window.prompt(
      "Submit this playbook to the community marketplace?\n\n" +
      "Aaron will review and approve. Add a short note for context (optional):",
      ""
    );
    if (notes === null) return; // user hit cancel

    setSubmitCommunityState({ loading: true, status: null, error: null });
    try {
      const response = await fetch('/api/v1/playbooks/community-submissions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({
          playbook_id: saved.id,
          submission_notes: notes || null,
        }),
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) {
        throw new Error(data.detail || `Submit failed (${response.status})`);
      }
      setSubmitCommunityState({ loading: false, status: data.status || 'pending', error: null });
      setActivityLog((prev) => [
        { id: `log-${Date.now()}`, time: 'just now', text: 'Submitted to community for review' },
        ...prev,
      ]);
    } catch (err) {
      setSubmitCommunityState({ loading: false, status: null, error: err.message || 'Submit failed' });
    }
  };

  const handleRun = async () => {
    const saved = await savePlaybook({ navigateOnCreate: false });
    if (!saved?.id) return;

    try {
      const response = await fetch(`/api/v1/playbooks/${saved.id}/execute`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({
          trigger_context: {
            manual: true,
            triggered_at: new Date().toISOString(),
          },
        }),
      });
      if (!response.ok) {
        throw new Error(`Failed to run playbook (${response.status})`);
      }
      const result = await response.json();
      setExecutionView(result);
      setLastExecution(result);
      setFlowStatus('Running');
      setActivityLog((prev) => [
        { id: `log-${Date.now()}`, time: 'just now', text: 'Run queued' },
        ...prev,
      ]);
    } catch (err) {
      setSaveError(err.message || 'Failed to run playbook');
    }
  };

  const handleRunSample = async () => {
    const saved = await savePlaybook({ navigateOnCreate: false });
    if (!saved?.id) return;

    // If the analyst loaded a real alert (or an investigation with an alert)
    // into the Preview tab, run THAT through the playbook. Otherwise fall
    // back to a synthetic sample.
    let sampleAlert = null;
    let sampleAlertId = null;
    if (previewAlert) {
      sampleAlert = previewAlert;
      sampleAlertId = previewAlert.alert_id || previewAlert.id || createUuid();
    } else if (previewInvestigation) {
      sampleAlert = previewInvestigation.alert || null;
      sampleAlertId = previewInvestigation.alert_id || (sampleAlert?.alert_id) || (sampleAlert?.id) || createUuid();
    }
    if (!sampleAlert) {
      sampleAlertId = createUuid();
      sampleAlert = {
        id: sampleAlertId,
        title: flowName ? `Sample: ${flowName}` : 'Sample Alert',
        severity: 'medium',
        source: 'workflow-studio',
        created_at: new Date().toISOString(),
        sender: 'phishing@example.com',
        sender_domain: 'example.com',
        iocs: ['8.8.8.8', 'bad.example.com', 'd41d8cd98f00b204e9800998ecf8427e'],
        entities: [
          { type: 'ip', value: '8.8.8.8' },
          { type: 'domain', value: 'bad.example.com' },
          { type: 'hash', value: 'd41d8cd98f00b204e9800998ecf8427e' },
        ],
        tags: ['sample', 'workflow-studio'],
        metadata: {
          channel: 'manual',
          note: 'Generated by Workflow Studio sample runner.',
        },
      };
    }

    try {
      const response = await fetch(`/api/v1/playbooks/${saved.id}/execute`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({
          trigger_context: {
            manual: true,
            triggered_at: new Date().toISOString(),
            alert_id: sampleAlertId,
            alert: sampleAlert,
          },
        }),
      });
      if (!response.ok) {
        throw new Error(`Failed to run playbook (${response.status})`);
      }
      const result = await response.json();
      setExecutionView(result);
      setLastExecution(result);
      setFlowStatus('Running');
      setActivityLog((prev) => [
        { id: `log-${Date.now()}`, time: 'just now', text: 'Run sample queued' },
        ...prev,
      ]);
    } catch (err) {
      setSaveError(err.message || 'Failed to run sample');
    }
  };

  // ============================================================================
  // Import/Export Handlers
  // ============================================================================

  const handleExport = () => {
    const canvasData = toEngineCanvas(nodes, edges);
    const exportData = {
      version: '1.0',
      exported_at: new Date().toISOString(),
      playbook: {
        name: flowName || 'Untitled Workflow',
        description: flowDescription || '',
        canvas_data: canvasData,
        trigger_conditions: playbookMeta.trigger_conditions || {},
        tags: playbookMeta.tags || [],
        alert_types: playbookMeta.alert_types || [],
        severity_filter: playbookMeta.severity_filter || [],
        data_sources: playbookMeta.data_sources || [],
        priority: playbookMeta.priority || 50,
      },
    };

    const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${(flowName || 'playbook').replace(/[^a-z0-9]/gi, '_').toLowerCase()}_export.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    setActivityLog((prev) => [
      { id: `log-${Date.now()}`, time: 'just now', text: 'Playbook exported' },
      ...prev,
    ]);
  };

  const handleImport = () => {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = '.json,application/json';
    input.onchange = async (e) => {
      const file = e.target.files?.[0];
      if (!file) return;

      try {
        const text = await file.text();
        const data = JSON.parse(text);

        // Validate structure
        if (!data.playbook || !data.playbook.canvas_data) {
          throw new Error('Invalid playbook format: missing canvas_data');
        }

        const { playbook } = data;

        // Confirm import
        if (!window.confirm(
          `Import "${playbook.name || 'Untitled'}"?\n\n` +
          `This will replace your current canvas with ${playbook.canvas_data?.nodes?.length || 0} nodes.`
        )) {
          return;
        }

        // Save current state for undo
        pushUndoState();

        // Load canvas
        const cd = playbook.canvas_data;
        const fromEngine = fromEngineCanvas(cd.nodes || [], cd.edges || []);
        setNodes(fromEngine.nodes);
        setEdges(fromEngine.edges);

        // Load metadata
        if (playbook.name) setFlowName(playbook.name);
        if (playbook.description) setFlowDescription(playbook.description);
        setPlaybookMeta((prev) => ({
          ...prev,
          trigger_conditions: playbook.trigger_conditions || prev.trigger_conditions,
          tags: playbook.tags || prev.tags,
          alert_types: playbook.alert_types || prev.alert_types,
          severity_filter: playbook.severity_filter || prev.severity_filter,
          data_sources: playbook.data_sources || prev.data_sources,
          priority: playbook.priority || prev.priority,
        }));

        setActivityLog((prev) => [
          { id: `log-${Date.now()}`, time: 'just now', text: `Imported "${playbook.name || 'playbook'}"` },
          ...prev,
        ]);

      } catch (err) {
        toast.error(`Import failed: ${err.message}`);
      }
    };
    input.click();
  };

  const parseItemsInput = (value) => {
    if (!value) return [];
    if (typeof value !== 'string') return value;
    const trimmed = String(value ?? '').trim();
    if (!trimmed) return [];
    try {
      return JSON.parse(trimmed);
    } catch (err) {
      return trimmed.split(',').map((item) => item.trim()).filter(Boolean);
    }
  };

  const handleCreateList = async () => {
    setAssetError(null);
    setAssetMessage(null);
    if (!String(listDraft.name ?? '').trim()) {
      setAssetError('List name is required.');
      return;
    }
    try {
      const payload = {
        name: String(listDraft.name ?? '').trim(),
        description: listDraft.description || '',
        list_type: listDraft.list_type,
        items: parseItemsInput(listDraft.items),
      };
      const response = await authFetch(`${API_BASE_URL}/api/v1/playbooks/lists`, {
        method: 'POST',
        body: JSON.stringify(payload),
      });
      if (!response.ok) {
        throw new Error(`Failed to create list (${response.status})`);
      }
      setAssetMessage('List created');
      setListDraft({ name: '', description: '', list_type: 'allowlist', items: '' });
      await loadCatalogs();
    } catch (err) {
      setAssetError(err.message || 'Failed to create list');
    }
  };

  const handleCreateFunction = async () => {
    setAssetError(null);
    setAssetMessage(null);
    if (!String(functionDraft.name ?? '').trim() || !String(functionDraft.code ?? '').trim()) {
      setAssetError('Function name and code are required.');
      return;
    }
    try {
      const payload = {
        name: String(functionDraft.name ?? '').trim(),
        description: functionDraft.description || '',
        code: functionDraft.code,
        input_schema: parseJsonMaybe(functionDraft.input_schema, {}),
        output_schema: parseJsonMaybe(functionDraft.output_schema, {}),
      };
      const response = await authFetch(`${API_BASE_URL}/api/v1/playbooks/functions`, {
        method: 'POST',
        body: JSON.stringify(payload),
      });
      if (!response.ok) {
        throw new Error(`Failed to create function (${response.status})`);
      }
      setAssetMessage('Function created (pending approval)');
      setFunctionDraft({ name: '', description: '', code: '', input_schema: '', output_schema: '' });
      await loadCatalogs();
    } catch (err) {
      setAssetError(err.message || 'Failed to create function');
    }
  };

  const handleApproveFunction = async (functionId) => {
    try {
      await authFetch(`/api/v1/playbooks/functions/${functionId}/approve`, {
        method: 'POST',
      });
      await loadCatalogs();
    } catch (err) {
    }
  };

  const readResponsePayload = async (response) => {
    let rawText = '';
    try {
      rawText = await response.text();
    } catch (err) {
      rawText = '';
    }
    let data = null;
    if (rawText) {
      try {
        data = JSON.parse(rawText);
      } catch (err) {
        data = null;
      }
    }
    return { data, rawText };
  };

  const handleRiggsBuild = async () => {
    setRiggsError(null);
    setRiggsResult(null);
    if (!String(riggsPrompt ?? '').trim()) {
      setRiggsError('Add requirements for Riggs to build.');
      return;
    }
    setRiggsBuildLoading(true);
    try {
      const response = await authFetch(`${API_BASE_URL}/api/v1/riggs/builder/generate`, {
        method: 'POST',
        body: JSON.stringify({
          requirements: riggsPrompt,
          alert_type: riggsAlertType || null,
          auto_save: false,
        }),
      });
      const { data, rawText } = await readResponsePayload(response);
      if (!response.ok) {
        const detail =
          data?.detail ||
          data?.message ||
          (response.status === 404
            ? 'Riggs builder endpoint not available (404). Check backend riggs_builder routes.'
            : null) ||
          rawText ||
          `Riggs build failed (${response.status})`;
        throw new Error(detail);
      }
      const playbook = data.playbook;
      setRiggsResult(playbook);
      if (playbook?.canvas_data?.nodes) {
        const mappedNodes = playbook.canvas_data.nodes.map((node) => toStudioNode(node, false));
        const mappedEdges = toStudioEdges(playbook.canvas_data.edges || [], mappedNodes);
        const spacedNodes = ensureReadableLayout(mappedNodes, mappedEdges);
        const spacedEdges = toStudioEdges(playbook.canvas_data.edges || [], spacedNodes);
        setNodes(spacedNodes);
        setEdges(spacedEdges);
      }
      if (playbook?.name) setFlowName(playbook.name);
      if (playbook?.description) setFlowDescription(playbook.description);
      if (playbook?.tags || playbook?.alert_types) {
        setPlaybookMeta((prev) => ({
          ...prev,
          tags: playbook.tags || prev.tags,
          alert_types: playbook.alert_types || prev.alert_types,
        }));
      }
    } catch (err) {
      setRiggsError(err.message || 'Riggs build failed');
    } finally {
      setRiggsBuildLoading(false);
    }
  };

  const handleRiggsSuggest = async () => {
    setRiggsError(null);
    setRiggsSuggestion(null);
    if (!String(riggsAlertType ?? '').trim()) {
      setRiggsError('Provide an alert type for suggestions.');
      return;
    }
    setRiggsSuggestLoading(true);
    try {
      const response = await authFetch(`${API_BASE_URL}/api/v1/riggs/builder/suggest-from-alerts`, {
        method: 'POST',
        body: JSON.stringify({
          alert_type: String(riggsAlertType ?? '').trim(),
          limit: 10,
        }),
      });
      const { data, rawText } = await readResponsePayload(response);
      if (!response.ok) {
        const detail =
          data?.detail ||
          data?.message ||
          (response.status === 404
            ? 'Riggs suggest endpoint not available (404). Check backend riggs_builder routes.'
            : null) ||
          rawText ||
          `Riggs suggestion failed (${response.status})`;
        throw new Error(detail);
      }
      if (data?.suggestion) {
        setRiggsSuggestion(data.suggestion);
      } else {
        setRiggsError(data.message || 'No suggestion returned');
      }
    } catch (err) {
      setRiggsError(err.message || 'Riggs suggestion failed');
    } finally {
      setRiggsSuggestLoading(false);
    }
  };

  const handleRiggsRecommend = async () => {
    setRiggsError(null);
    setRiggsRecommendations([]);
    if (previewEntityType !== 'investigation' || !previewInvestigation) {
      setRiggsError('Load an investigation in Data Preview first.');
      return;
    }
    setRiggsRecommendLoading(true);
    try {
      const invId = previewInvestigation?.investigation_id || previewEntityId;
      const response = await authFetch(`${API_BASE_URL}/api/v1/riggs/playbooks/recommend`, {
        method: 'POST',
        body: JSON.stringify({
          investigation_id: String(invId ?? '').trim(),
          max_recommendations: 3,
        }),
      });
      const { data, rawText } = await readResponsePayload(response);
      if (!response.ok) {
        const detail =
          data?.detail ||
          data?.message ||
          (response.status === 404
            ? 'Riggs recommendation endpoint not available (404). Check backend riggs_playbooks router.'
            : null) ||
          rawText ||
          `Riggs recommendations failed (${response.status})`;
        throw new Error(detail);
      }
      setRiggsRecommendations(data?.recommendations || []);
    } catch (err) {
      setRiggsError(err.message || 'Riggs recommendations failed');
    } finally {
      setRiggsRecommendLoading(false);
    }
  };

  const loadMetrics = useCallback(async (id) => {
    if (!id) return;
    setMetricsLoading(true);
    try {
      const response = await fetch(`/api/v1/playbooks/${id}/metrics`, {
        credentials: 'include',
      });
      if (response.ok) {
        const data = await response.json();
        setMetrics(data);
      } else {
        setMetrics(null);
      }
    } catch (err) {
      setMetrics(null);
    } finally {
      setMetricsLoading(false);
    }
  }, []);

  useEffect(() => {
    if (!playbookMeta.id) return;
    loadMetrics(playbookMeta.id);
  }, [playbookMeta.id, lastExecution?.execution_id, loadMetrics]);

  const loadVersions = useCallback(async (id) => {
    if (!id) return;
    setVersionsLoading(true);
    try {
      const response = await fetch(`/api/v1/playbooks/${id}/versions`, {
        credentials: 'include',
      });
      if (response.ok) {
        const data = await response.json();
        setVersions(data.versions || []);
      } else {
        setVersions([]);
      }
    } catch (err) {
      setVersions([]);
    } finally {
      setVersionsLoading(false);
    }
  }, []);

  const loadExecutionHistory = useCallback(async (id, statusFilter = '') => {
    if (!id) return;
    setExecutionHistoryLoading(true);
    try {
      let url = `/api/v1/playbooks/${id}/executions?limit=50`;
      if (statusFilter) url += `&status=${statusFilter}`;
      const response = await fetch(url, {
        credentials: 'include',
      });
      if (response.ok) {
        const data = await response.json();
        setExecutionHistory(data.executions || []);
      } else {
        setExecutionHistory([]);
      }
    } catch (err) {
      setExecutionHistory([]);
    } finally {
      setExecutionHistoryLoading(false);
    }
  }, []);

  const restoreVersion = async (versionId) => {
    if (!playbookMeta.id) return;
    if (!window.confirm('Restore this version? Your current canvas will be saved as a snapshot first.')) return;
    try {
      const response = await fetch(`/api/v1/playbooks/${playbookMeta.id}/versions/${versionId}/restore`, {
        method: 'POST',
        credentials: 'include',
      });
      if (response.ok) {
        const data = await response.json();
        const restored = data.playbook;
        // Reload canvas from restored playbook
        if (restored.canvas_data) {
          const cd = typeof restored.canvas_data === 'string'
            ? JSON.parse(restored.canvas_data)
            : restored.canvas_data;
          const fromEngine = fromEngineCanvas(cd.nodes || [], cd.edges || []);
          setNodes(fromEngine.nodes);
          setEdges(fromEngine.edges);
        }
        if (restored.name) setFlowName(restored.name);
        loadVersions(playbookMeta.id);
        setActivityLog((prev) => [
          { id: `log-${Date.now()}`, time: 'just now', text: 'Restored from revision' },
          ...prev,
        ]);
      }
    } catch (err) {
    }
  };

  // Show loading state
  if (loading) {
    return (
      <div className="workflow-studio" style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100vh' }}>
        <div style={{ textAlign: 'center', color: 'var(--text-secondary)' }}>
          <div className="spinner" style={{ margin: '0 auto 16px' }}></div>
          <p>Loading playbook...</p>
        </div>
      </div>
    );
  }

  // Show error state
  if (loadError) {
    return (
      <div className="workflow-studio" style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100vh' }}>
        <div style={{ textAlign: 'center', maxWidth: '500px', padding: '24px' }}>
          <div style={{ fontSize: '48px', marginBottom: '16px', color: 'var(--status-warning)' }}>!</div>
          <h2 style={{ color: 'var(--text-primary)', marginBottom: '8px' }}>Failed to Load Playbook</h2>
          <p style={{ color: 'var(--text-secondary)', marginBottom: '24px' }}>{loadError}</p>
          <button
            className="btn btn-primary"
            onClick={() => window.location.href = '/playbooks'}
          >
            Back to Playbooks
          </button>
        </div>
      </div>
    );
  }

  const nodeInspector = selectedNode ? (
    <div className="inspector left-node-panel">
      <label>
        Title
        <input
          value={selectedNode.data?.title || ''}
          onChange={(e) => {
            const newTitle = e.target.value;
            updateNode({ title: newTitle });
            if (selectedNode.data?.kind === 'code' && selectedNode.data?.config?.mode === 'script') {
              const cfg = selectedNode.data?.config || {};
              const script = cfg.script || {};
              const code = script.code || '';
              const inputs = Array.isArray(script.inputs) ? script.inputs : [];
              if (code) {
                updateNodeConfig({
                  script: {
                    ...script,
                    code: updateCodeWithInputs(code, inputs, newTitle),
                    function_name: newTitle,
                  },
                });
              }
            }
          }}
        />
      </label>
      <label>
        Summary
        <textarea
          rows={3}
          value={selectedNode.data?.summary || ''}
          onChange={(e) => updateNode({ summary: e.target.value })}
        />
      </label>
      {selectedNode.data?.config?._migration && (
        <div className="config-note warning">
          {selectedNode.data.config._migration.note || 'Legacy block mapped to a canonical block. Review settings.'}
        </div>
      )}
      <div className="inspector-section">
        <div className="section-title">{formatKindLabel(selectedNode.data?.kind)} Settings</div>
        {renderConfigFields(
          selectedNode.data?.kind,
          selectedNode.data?.config || {},
          updateNodeConfig,
          {
            nodeId: selectedNode.id,
            onOpenDataPath: openDataPathPicker,
            onPythonMount: handlePythonEditorMount,
            onSetEdges: setEdges,
            lists: availableLists,
            functions: availableFunctions,
            integrations: availableIntegrations,
            playbookIntegrations: playbookIntegrations,
          }
        )}
      </div>
      {/* Last Run — shows actual execution result for this node */}
      {selectedNodeExecution && (
        <div className="inspector-section">
          <div className="section-title">
            Last Run
            <span className={`node-exec node-exec--${selectedNodeExecution.status}`} style={{ marginLeft: 8 }}>
              {(selectedNodeExecution.status || '').replace(/_/g, ' ')}
              {selectedNodeExecution.duration_ms != null ? ` · ${Math.round(selectedNodeExecution.duration_ms)}ms` : ''}
            </span>
          </div>
          {selectedNodeExecution.error && (
            <div className="node-test-error">{selectedNodeExecution.error}</div>
          )}
          {selectedNodeOutput && Object.keys(selectedNodeOutput).length > 0 && (
            <details className="node-test-outputs" open>
              <summary>Output</summary>
              {renderJsonPreview(selectedNodeOutput, `$.${selectedNode.id}`, 'Output')}
            </details>
          )}
          {(!selectedNodeOutput || Object.keys(selectedNodeOutput).length === 0) && !selectedNodeExecution.error && (
            <div className="config-note">No output data for this node.</div>
          )}
        </div>
      )}

      {/* Test Node button — only for saved playbooks */}
      {playbookMeta?.id && selectedNode.data?.kind !== 'trigger' && selectedNode.data?.kind !== 'end' && (
        <div className="inspector-section">
          <div className="section-title" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            Test Node
            <button
              className={`btn-test-node${nodeTestLoading && nodeTestNodeId === selectedNode.id ? ' loading' : ''}`}
              onClick={handleTestNode}
              disabled={nodeTestLoading}
            >
              {nodeTestLoading && nodeTestNodeId === selectedNode.id ? 'Running...' : 'Run Test'}
            </button>
          </div>
          {nodeTestResult && nodeTestNodeId === selectedNode.id && (
            <div className={`node-test-result${nodeTestResult.ok ? ' ok' : ' fail'}`}>
              <div className="node-test-meta">
                <span className={`node-test-badge${nodeTestResult.ok ? '' : ' fail'}`}>
                  {nodeTestResult.status || (nodeTestResult.ok ? 'success' : 'failed')}
                </span>
                {nodeTestResult.duration_ms != null && (
                  <span className="node-test-duration">{nodeTestResult.duration_ms}ms</span>
                )}
              </div>
              {nodeTestResult.error && (
                <div className="node-test-error">{nodeTestResult.error}</div>
              )}
              {nodeTestResult.outputs && Object.keys(nodeTestResult.outputs).length > 0 && (
                <details className="node-test-outputs" open>
                  <summary>Output</summary>
                  {renderJsonPreview(nodeTestResult.outputs, `$.${selectedNode.id}`, 'Output')}
                </details>
              )}
            </div>
          )}
          {!playbookMeta?.id && (
            <div className="config-note">Save the playbook first to enable node testing.</div>
          )}
        </div>
      )}

      {selectedNode.data?.kind !== 'trigger' && (
        <details className="inspector-section inspector-advanced">
          <summary className="section-title">Advanced</summary>
          <div className="config-group" style={{ marginTop: 8 }}>
            <label>
              Max Retries
              <input
                type="number"
                min="0"
                max="10"
                value={selectedNode.data?.config?.max_retries || 0}
                onChange={(e) => updateNodeConfig({ max_retries: parseInt(e.target.value) || 0 })}
                placeholder="0"
              />
            </label>
            {(selectedNode.data?.config?.max_retries || 0) > 0 && (
              <label>
                Retry Delay (seconds)
                <input
                  type="number"
                  min="1"
                  max="300"
                  value={selectedNode.data?.config?.retry_delay_seconds || 5}
                  onChange={(e) => updateNodeConfig({ retry_delay_seconds: parseInt(e.target.value) || 5 })}
                  placeholder="5"
                />
              </label>
            )}
            <label>
              On Error
              <select
                value={selectedNode.data?.config?.error_policy || 'stop'}
                onChange={(e) => updateNodeConfig({ error_policy: e.target.value })}
              >
                <option value="stop">Stop Playbook</option>
                <option value="continue">Continue to Next Node</option>
                <option value="route_to_error">Route to Error Handler</option>
              </select>
            </label>
            {selectedNode.data?.config?.error_policy === 'route_to_error' && (
              <div className="config-note">
                Connect an edge from the red "error" handle to define the error path.
              </div>
            )}
          </div>
        </details>
      )}
    </div>
  ) : (
    <div className="inspector-empty left-node-panel">
      <div className="orb" />
      <p>Select a node to tune its behavior.</p>
    </div>
  );

  return (
    <div className="workflow-studio">
      {/* Draft Restore Prompt */}
      {draftRestorePrompt && (
        <div className="draft-restore-overlay">
          <div className="draft-restore-modal">
            <h3>Restore Draft?</h3>
            <p>You have an unsaved draft from a recent session. Would you like to restore it?</p>
            <div className="draft-restore-actions">
              <button className="btn btn-secondary" onClick={dismissDraft}>Discard</button>
              <button className="btn btn-primary" onClick={restoreDraft}>Restore Draft</button>
            </div>
          </div>
        </div>
      )}

      {/* Template Picker (shown when creating a new playbook) */}
      {showTemplatePicker && (() => {
        const MKT_CATEGORIES = ['all', 'phishing', 'malware', 'identity', 'network', 'cloud', 'ransomware', 'vulnerability', 'threat intel'];
        const allTemplates = [
          ...templates.map((t) => ({ ...t, _builtin: true })),
          ...mktTemplates.filter((t) => !templates.some((b) => b.id === t.id)),
        ];
        const filtered = allTemplates.filter((t) => {
          const cat = mktTemplateCategory;
          const q = mktTemplateSearch.toLowerCase();
          const matchCat = cat === 'all' || (t.category || '').toLowerCase() === cat ||
            (Array.isArray(t.tags) && t.tags.some((tag) => tag.toLowerCase() === cat));
          const matchQ = !q || (t.name || '').toLowerCase().includes(q) ||
            (t.description || t.summary || '').toLowerCase().includes(q);
          return matchCat && matchQ;
        });
        return (
          <div className="tpl-picker-overlay" onClick={(e) => { if (e.target === e.currentTarget) setShowTemplatePicker(false); }}>
            <div className="tpl-picker-modal">
              <div className="tpl-picker-header">
                <div>
                  <h2 className="tpl-picker-title">Start from a template</h2>
                  <p className="tpl-picker-subtitle">Choose a template or start with a blank canvas.</p>
                </div>
                <button className="tpl-picker-scratch" onClick={() => setShowTemplatePicker(false)}>
                  Start from Scratch
                </button>
              </div>
              <div className="tpl-picker-search-row">
                <input
                  className="tpl-picker-search"
                  type="text"
                  placeholder="Search templates..."
                  value={mktTemplateSearch}
                  onChange={(e) => setMktTemplateSearch(e.target.value)}
                  autoFocus
                />
              </div>
              <div className="tpl-picker-cats">
                {MKT_CATEGORIES.map((cat) => (
                  <button
                    key={cat}
                    className={`tpl-picker-cat${mktTemplateCategory === cat ? ' active' : ''}`}
                    onClick={() => setMktTemplateCategory(cat)}
                  >
                    {cat.charAt(0).toUpperCase() + cat.slice(1)}
                  </button>
                ))}
              </div>
              <div className="tpl-picker-grid">
                {mktTemplatesLoading ? (
                  <div className="tpl-picker-loading">Loading templates...</div>
                ) : filtered.length === 0 ? (
                  <div className="tpl-picker-empty">No templates match your search.</div>
                ) : filtered.map((tpl) => {
                  const isLoading = mktTemplateLoadingId === tpl.id;
                  const tags = Array.isArray(tpl.tags) ? tpl.tags.slice(0, 3) : [];
                  return (
                    <button
                      key={tpl.id}
                      className="tpl-picker-card"
                      onClick={() => {
                        if (tpl._builtin) {
                          applyTemplate(tpl);
                          setShowTemplatePicker(false);
                        } else {
                          handlePickMarketplaceTemplate(tpl);
                        }
                      }}
                      disabled={isLoading}
                    >
                      <div className="tpl-picker-card-name">{tpl.name}</div>
                      <div className="tpl-picker-card-desc">{tpl.description || tpl.summary || ''}</div>
                      {tags.length > 0 && (
                        <div className="tpl-picker-card-tags">
                          {tags.map((tag) => <span key={tag} className="tpl-picker-tag">{tag}</span>)}
                        </div>
                      )}
                      {isLoading && <div className="tpl-picker-card-loading">Loading...</div>}
                    </button>
                  );
                })}
              </div>
            </div>
          </div>
        );
      })()}

      {/* Node Search Overlay (Ctrl+F) */}
      {nodeSearchOpen && (
        <div className="node-search-overlay">
          <div className="node-search-box">
            <Icons.Search size={16} />
            <input
              type="text"
              placeholder="Search nodes by title, type, or description..."
              value={nodeSearchQuery}
              onChange={(e) => {
                setNodeSearchQuery(e.target.value);
                performNodeSearch(e.target.value);
              }}
              autoFocus
            />
            {nodeSearchMatches.length > 0 && (
              <span className="node-search-count">
                {nodeSearchIndex + 1} / {nodeSearchMatches.length}
              </span>
            )}
            <button className="node-search-close" onClick={() => {
              setNodeSearchOpen(false);
              setNodeSearchQuery('');
              setNodeSearchMatches([]);
            }}>
              <Icons.X size={16} />
            </button>
          </div>
          {nodeSearchMatches.length > 0 && (
            <div className="node-search-hint">
              Press Enter to cycle through matches, Escape to close
            </div>
          )}
        </div>
      )}

      <div className="studio-shell">
        <header className="studio-topbar">
          <div className="studio-left">
            <button
              className="studio-home"
              onClick={() => navigate('/playbooks')}
              aria-label="Back to playbooks"
              title="Back to playbooks"
            >
              <img src="/T1_Agentics_Logo-removebg-preview.png" alt="T1 Agentics" className="t1-logo-dark" />
              <img src="/T1_Agentics_Light_Logo.png" alt="T1 Agentics" className="t1-logo-light" />
            </button>
            <div className="studio-title">
              <div className="studio-badge">Workflow Studio</div>
              <div className="studio-name-wrap">
                <input
                  className="studio-name"
                  value={flowName}
                  onChange={(e) => setFlowName(e.target.value)}
                  placeholder="Workflow name"
                />
                <span className={`studio-status status-${flowStatus.toLowerCase()}`}>
                  {flowStatus}
                </span>
              </div>
            </div>
          </div>
          <div className="studio-actions">
            <button className="btn btn-ghost" onClick={handleImport} title="Import playbook from JSON">
              <Icons.Upload size={14} /> Import
            </button>
            <button className="btn btn-ghost" onClick={handleExport} title="Export playbook as JSON">
              <Icons.Download size={14} /> Export
            </button>
            <button className="btn btn-ghost" onClick={() => savePlaybook()} disabled={isSaving}>
              {isSaving ? 'Saving...' : 'Save'}
            </button>
            <button className="btn btn-muted" onClick={handleRunSample}>Run Sample</button>
            <button className="btn btn-secondary" onClick={handleRun}>Run</button>
            <button
              className="btn btn-ghost"
              onClick={handleSubmitToCommunity}
              disabled={submitCommunityState.loading || submitCommunityState.status === 'pending'}
              title={
                submitCommunityState.status === 'pending'
                  ? 'Already submitted — awaiting review'
                  : submitCommunityState.error || 'Submit this playbook to the community marketplace'
              }
            >
              {submitCommunityState.loading
                ? 'Submitting…'
                : submitCommunityState.status === 'pending'
                  ? 'Submitted ✓'
                  : 'Submit to Community'}
            </button>
            <button className="btn btn-primary" onClick={handlePublish}>Publish</button>
          </div>
        </header>
        {saveError && (
          <div className="studio-error">
            <strong>Save failed:</strong> {saveError}
          </div>
        )}

        <div
          className="studio-body"
          style={{
            '--left-panel-width': `${leftPanelWidth}px`,
            '--right-panel-width': `${rightPanelWidth}px`,
          }}
        >
          <aside className="studio-panel left-panel">
            <div className="panel-header">
              <h3>{selectedNode ? 'Node Settings' : 'Blocks'}</h3>
              <p>
                {selectedNode
                  ? `Editing ${formatKindLabel(selectedNode.data?.kind)} node.`
                  : 'Drag a block or tap to insert.'}
              </p>
            </div>
            {selectedNode ? (
              nodeInspector
            ) : (
              <>
                <div className="palette-search">
                  <input
                    type="text"
                    value={paletteQuery}
                    onChange={(e) => setPaletteQuery(e.target.value)}
                    placeholder="Search blocks"
                    aria-label="Search blocks"
                  />
                  {paletteQuery && (
                    <button
                      type="button"
                      className="palette-search-clear"
                      onClick={() => setPaletteQuery('')}
                      aria-label="Clear search"
                    >
                      x
                    </button>
                  )}
                </div>
                {filteredPaletteGroups.map((group) => (
                  <div key={group.id} className="palette-group">
                    <div className="palette-group-title">{group.label}</div>
                    <div className="palette-grid">
                      {group.items.map((item) => (
                        <button
                          key={item.kind}
                          className={`palette-card palette-${item.kind}`}
                          draggable
                          onDragStart={(event) => onDragStart(event, item.kind)}
                          onClick={() => addNode(item.kind)}
                          style={{ '--palette-accent': nodeColor(item.kind) }}
                          title={item.hint}
                        >
                          <div className="palette-icon">
                            {item.icon && <item.icon size={16} />}
                          </div>
                          <div className="palette-title">{item.label}</div>
                        </button>
                      ))}
                    </div>
                  </div>
                ))}
                {filteredPaletteGroups.length === 0 && (
                  <div className="palette-empty">No blocks match that search.</div>
                )}
                <div className="section-title" style={{ marginTop: 16 }}>Templates</div>
                <div className="templates-grid">
                  {templates.map((tpl) => (
                    <div
                      key={tpl.id}
                      className="template-card"
                      onClick={() => {
                        if (window.confirm(`Load template "${tpl.name}"? This will replace the current canvas.`)) {
                          setNodes(tpl.nodes);
                          setEdges(tpl.edges);
                          setFlowName(tpl.name);
                        }
                      }}
                    >
                      <div className="template-name">{tpl.name}</div>
                      <div className="template-summary">{tpl.summary}</div>
                    </div>
                  ))}
                </div>
              </>
            )}
          </aside>

          <div
            className="panel-resizer"
            onMouseDown={startLeftResize}
            role="separator"
            aria-orientation="vertical"
            aria-label="Resize left panel"
          />

          <section className="studio-canvas" ref={reactFlowWrapperRef}>
            <div className="canvas-toolbar">
              <button
                className={`toolbar-pill toolbar-toggle ${autoLayoutEnabled ? 'active' : ''}`}
                onClick={() => {
                  if (!autoLayoutEnabled) {
                    runAutoLayout();
                  }
                  setAutoLayoutEnabled((prev) => !prev);
                }}
                type="button"
              >
                Auto layout: {autoLayoutEnabled ? 'On' : 'Off'}
              </button>
              <button
                className={`toolbar-pill toolbar-toggle ${snapEnabled ? 'active' : ''}`}
                onClick={() => setSnapEnabled((prev) => !prev)}
                type="button"
              >
                Snapping: {snapEnabled ? 'On' : 'Off'}
              </button>
              <button
                className={`toolbar-pill toolbar-toggle ${showExecutionOverlay ? 'active' : ''}`}
                onClick={() => setShowExecutionOverlay((prev) => !prev)}
                type="button"
              >
                Execution: {showExecutionOverlay ? 'On' : 'Off'}
              </button>
              <button
                className={`toolbar-pill toolbar-toggle ${showFlowOverlay ? 'active' : ''}`}
                onClick={() => setShowFlowOverlay((prev) => !prev)}
                type="button"
              >
                Data Flow: {showFlowOverlay ? 'On' : 'Off'}
              </button>
              <button
                className="toolbar-pill toolbar-action"
                onClick={loadSampleWorkflow}
                type="button"
              >
                Load Sample
              </button>
            </div>
            <ReactFlow
              nodes={renderNodes}
              edges={renderEdges}
              onNodesChange={onNodesChange}
              onEdgesChange={onEdgesChange}
              onConnect={onConnect}
              onConnectStart={onConnectStart}
              onConnectEnd={onConnectEnd}
              onNodesDelete={onNodesDelete}
              onEdgesDelete={onEdgesDelete}
              onDrop={onDrop}
              onDragOver={onDragOver}
              nodeTypes={nodeTypes}
              edgeTypes={edgeTypes}
              onNodeClick={(event, node) => setSelectedNodeId(node.id)}
              onPaneClick={() => {
                if (suppressPaneClickRef.current) {
                  suppressPaneClickRef.current = false;
                  return;
                }
                setSelectedNodeId(null);
                setConnectMenu(null);
              }}
              onMove={(_event, vp) => setRfViewport(vp)}
              onInit={(instance) => {
                reactFlowRef.current = instance;
                instance.fitView({ padding: 0.3, maxZoom: 1.1 });
                requestAnimationFrame(() => {
                  if (reactFlowRef.current) {
                    nudgeViewportDown(60);
                    setRfViewport(instance.getViewport());
                  }
                });
              }}
              minZoom={0.4}
              maxZoom={1.6}
              snapToGrid={snapEnabled}
              snapGrid={[20, 20]}
              elementsSelectable={true}
              nodesConnectable={true}
              nodesDraggable={true}
              deleteKeyCode={['Delete', 'Backspace']}
              selectNodesOnDrag={false}
              proOptions={{ hideAttribution: true }}
            >
              <Controls showInteractive={false} />
              <MiniMap
                nodeColor={(node) => nodeColor(node.data?.kind)}
                maskColor="rgba(9, 16, 26, 0.7)"
                pannable
                zoomable
              />
            </ReactFlow>

            {/* Inline node output popover — shows to the right of selected node.
                Displays full-run execution results OR single-node test results.
                Click any value in the output to copy its data path. */}
            {selectedNode && (() => {
              const kind = selectedNode.data?.kind;
              if (kind === 'trigger' || kind === 'end') return null;

              const hasTestResult = nodeTestResult && nodeTestNodeId === selectedNode.id;
              const isRunning = nodeTestLoading && nodeTestNodeId === selectedNode.id;
              if (!hasTestResult && !selectedNodeExecution && !isRunning) return null;

              const pos = selectedNode.positionAbsolute || selectedNode.position || { x: 0, y: 0 };
              const { x: vx, y: vy, zoom: vz } = rfViewport;
              const NODE_W = 240;
              const popLeft = pos.x * vz + vx + NODE_W * vz + 12;
              const popTop = pos.y * vz + vy;

              // Prefer test result over full-run execution when both exist
              const activeStatus = hasTestResult
                ? (nodeTestResult.status || (nodeTestResult.ok ? 'success' : 'failed'))
                : selectedNodeExecution?.status;
              const activeDuration = hasTestResult
                ? nodeTestResult.duration_ms
                : selectedNodeExecution?.duration_ms;
              const activeError = hasTestResult
                ? nodeTestResult.error
                : selectedNodeExecution?.error;
              const activeOutput = hasTestResult ? nodeTestResult.outputs : selectedNodeOutput;
              const rootPath = `$.${selectedNode.id}`;

              return (
                <div
                  className="node-exec-popover"
                  style={{ left: popLeft, top: popTop }}
                  onClick={(e) => e.stopPropagation()}
                >
                  <div className="node-exec-popover-header">
                    {activeStatus && (
                      <span className={`node-exec node-exec--${activeStatus}`}>
                        {activeStatus.replace(/_/g, ' ')}
                      </span>
                    )}
                    {activeDuration != null && (
                      <span className="node-exec-dur">{Math.round(activeDuration)}ms</span>
                    )}
                    <button
                      type="button"
                      className="node-exec-popover-close"
                      onClick={() => setSelectedNodeId(null)}
                    >
                      ×
                    </button>
                  </div>
                  {activeError && (
                    <div className="node-exec-popover-error">{activeError}</div>
                  )}
                  {activeOutput && Object.keys(activeOutput).length > 0 && (
                    <div className="node-exec-popover-output">
                      <div className="node-exec-popover-output-label">OUTPUT</div>
                      {renderJsonPreview(activeOutput, rootPath, 'Output')}
                    </div>
                  )}
                  {isRunning && !activeOutput && !activeError && (
                    <div className="node-exec-popover-loading">Running...</div>
                  )}
                  {!activeOutput && !activeError && !isRunning && (
                    <div className="node-exec-popover-empty">No output data.</div>
                  )}
                </div>
              );
            })()}

            <div className="canvas-glow" />

            {/* Bottom Code Panel - visible when Code Script is selected */}
            {selectedNode && selectedNode.data?.kind === 'code' && selectedNode.data?.config?.mode === 'script' && (() => {
              const pyConfig = selectedNode.data?.config?.script || {};
              const inputEntries = Array.isArray(pyConfig.inputs) ? pyConfig.inputs : [];
              const nodeFnName = selectedNode.data?.title || pyConfig.function_name || 'main';
              const currentCode = pyConfig.code || '';
              const autoCode = generateCodeFromInputs(inputEntries, nodeFnName);
              const emptyAuto = generateCodeFromInputs([], nodeFnName);
              const isAutoGenerated = !currentCode || currentCode === autoCode || currentCode === emptyAuto;

                const pyOnChange = (patch) => updateNodeConfig({ script: { ...pyConfig, ...patch } });

              const codeForInputs = (updated) => {
                if (isAutoGenerated) {
                  return generateCodeFromInputs(updated, nodeFnName);
                }
                return updateCodeWithInputs(currentCode, updated, nodeFnName);
              };

              const updateEntry = (idx, patch) => {
                const updated = inputEntries.map((e, i) => i === idx ? { ...e, ...patch } : e);
                  pyOnChange({ inputs: updated, code: codeForInputs(updated) });
              };

              const addEntry = () => {
                const updated = [...inputEntries, { key: '', value: '' }];
                  pyOnChange({ inputs: updated, code: codeForInputs(updated) });
              };

              const removeEntry = (idx) => {
                const updated = inputEntries.filter((_, i) => i !== idx);
                  pyOnChange({ inputs: updated, code: codeForInputs(updated) });
              };

              return (
                <div
                  className={`code-bottom-panel ${showCodePanel ? 'expanded' : 'collapsed'}`}
                  style={showCodePanel ? { height: codePanelHeight } : undefined}
                  onKeyDown={(e) => e.stopPropagation()}
                  onKeyUp={(e) => e.stopPropagation()}
                  onKeyPress={(e) => e.stopPropagation()}
                >
                  {/* Drag handle for resizing */}
                  {showCodePanel && (
                    <div
                      className="code-panel-resize-handle"
                      onMouseDown={startCodePanelResize}
                    />
                  )}
                  <div className="code-panel-header" onClick={() => setShowCodePanel(p => !p)}>
                    <div className="code-panel-title">
                      <span className={`chevron ${showCodePanel ? 'up' : ''}`}>&#9660;</span>
                      Code Editor
                      <span style={{ fontSize: 11, color: 'rgba(148,163,184,0.6)', fontWeight: 400 }}>
                        {inputEntries.filter(e => e.key).length} input{inputEntries.filter(e => e.key).length !== 1 ? 's' : ''}
                      </span>
                    </div>
                    <span style={{ fontSize: 11, color: 'rgba(148,163,184,0.5)' }}>
                      {showCodePanel ? 'Collapse' : 'Expand'}
                    </span>
                  </div>
                  {showCodePanel && (
                    <div className="code-panel-body">
                      <div className="code-panel-inputs">
                        <div className="code-panel-inputs-header">
                          <span>Inputs</span>
                          <button type="button" className="btn btn-ghost btn-sm" onClick={addEntry}>+ Add</button>
                        </div>
                        <div className="code-panel-inputs-list">
                          {inputEntries.length === 0 && (
                            <div className="code-inputs-empty">No inputs. Click + Add to map data into your code.</div>
                          )}
                          {inputEntries.map((entry, idx) => (
                            <div key={idx} className="code-input-row">
                              <div className="code-input-row-top">
                                <input
                                  value={entry.key || ''}
                                  onChange={(e) => updateEntry(idx, { key: e.target.value })}
                                  placeholder="variable name"
                                />
                                <button className="code-input-remove" onClick={() => removeEntry(idx)}>&times;</button>
                              </div>
                              <div className="code-input-value-row">
                                <input
                                  value={entry.value || ''}
                                  onChange={(e) => updateEntry(idx, { value: e.target.value })}
                                  placeholder="$.trigger.alert.* or literal value"
                                />
                                <button
                                  type="button"
                                  className="code-input-pick-btn"
                                  onClick={() => openDataPathPicker(selectedNode.id, 'inputs', { mode: 'inputs', inputIndex: idx })}
                                  title="Pick data path"
                                >
                                  &#8943;
                                </button>
                              </div>
                              {entry.value && (
                                <div className="code-input-type-hint">
                                  {isDynamicValue(entry.value) ? 'data path' : 'static value'}
                                </div>
                              )}
                            </div>
                          ))}
                        </div>
                      </div>
                      <div className="code-panel-editor">
                        <div className="code-panel-editor-header">
                          <span>Python &middot; {nodeFnName}(inputs)</span>
                          {isAutoGenerated && inputEntries.length > 0 && (
                            <span style={{ color: '#3CB371' }}>Auto-generating from inputs</span>
                          )}
                        </div>
                        <div className="code-panel-editor-wrap">
                          <Editor
                            height="100%"
                            language="python"
                            theme="vs-dark"
                            value={currentCode || generateCodeFromInputs(inputEntries, nodeFnName)}
                            onChange={(value) => pyOnChange({ code: value || '' })}
                            onMount={handlePythonEditorMount}
                            options={PYTHON_EDITOR_OPTIONS}
                          />
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              );
            })()}
          </section>

          <div
            className="panel-resizer panel-resizer--right"
            onMouseDown={startRightResize}
            role="separator"
            aria-orientation="vertical"
            aria-label="Resize right panel"
          />

          <aside className="studio-panel right-panel">
            <div className="data-panel-header">
              <h3>Data preview</h3>
              <div className="data-panel-actions">
                <button type="button" className="icon-btn" title="Expand">
                  <Icons.Maximize2 size={16} />
                </button>
                <button type="button" className="icon-btn" title="Pop out">
                  <Icons.ArrowRight size={16} />
                </button>
              </div>
            </div>
            <div className="data-panel-search-wrapper">
              <div className="data-panel-search">
                <Icons.Search size={16} className="search-icon" />
                <input
                  type="text"
                  placeholder="Search alerts / investigations"
                  value={previewSearchDisplay}
                  onChange={(e) => {
                    justSelectedSearchRef.current = false; // Clear selection flag when user types
                    setPreviewSearchDisplay(e.target.value);
                  }}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') {
                      e.preventDefault();
                      if (previewSuggestions.length > 0) {
                        const item = previewSuggestions[0];
                        justSelectedSearchRef.current = true; // Prevent search from re-triggering
                        loadPreviewData(item.id);
                        setPreviewEntityId(item.id);
                        setPreviewSearchDisplay(item.title || item.id);
                        setPreviewSuggestions([]);
                        setSearchFocused(false);
                      } else if (previewSearchDisplay) {
                        loadPreviewData(previewSearchDisplay);
                      }
                    }
                    if (e.key === 'Escape') {
                      setPreviewSuggestions([]);
                      setSearchFocused(false);
                    }
                  }}
                  onFocus={() => {
                    // Always allow suggestions on re-focus (user is deliberately clicking in)
                    justSelectedSearchRef.current = false;
                    setSearchFocused(true);
                  }}
                  onBlur={(e) => {
                    // Delay blur to allow click on suggestions
                    setTimeout(() => setSearchFocused(false), 200);
                  }}
                />
                {previewSuggestionsLoading && (
                  <Icons.Loader2 size={16} className="search-spinner" />
                )}
              </div>
              {previewSuggestions.length > 0 && (
                <div className="search-suggestions">
                  {previewSuggestions.map((item) => (
                    <button
                      key={item.id}
                      type="button"
                      className="search-suggestion-item"
                      title={`${item.title || item.id}\n${item.type === 'alert' ? 'Alert' : 'Investigation'}: ${item.id}`}
                      onClick={() => {
                        justSelectedSearchRef.current = true; // Prevent search from re-triggering
                        loadPreviewData(item.id);
                        setPreviewEntityId(item.id);
                        setPreviewSearchDisplay(item.title || item.id);
                        setPreviewSuggestions([]);
                        setSearchFocused(false);
                      }}
                    >
                      <span className={`suggestion-type ${item.type}`}>
                        {item.type === 'alert' ? <Icons.AlertTriangle size={14} /> : <Icons.Folder size={14} />}
                      </span>
                      <div className="suggestion-content">
                        <span className="suggestion-name">{item.title || item.id}</span>
                        {item.title && <span className="suggestion-id-small">{item.id}</span>}
                      </div>
                    </button>
                  ))}
                </div>
              )}
            </div>

            <div className="inspector-tabs">
              <button
                className={`inspector-tab ${inspectorTab === 'playbook' || inspectorTab === 'revisions' ? 'active' : ''}`}
                onClick={() => setInspectorTab('playbook')}
              >
                Settings
              </button>
              <button
                className={`inspector-tab ${inspectorTab === 'preview' ? 'active' : ''}`}
                onClick={() => setInspectorTab('preview')}
              >
                Preview
              </button>
              <button
                className={`inspector-tab ${inspectorTab === 'executions' ? 'active' : ''}`}
                onClick={() => {
                  setInspectorTab('executions');
                  loadExecutionHistory(playbookMeta.id, executionHistoryFilter);
                }}
              >
                Runs
              </button>
            </div>

            {inspectorTab === 'playbook' && (
              <div className="inspector-section playbook-settings-v2">
                <>
                {/* Description */}
                <div className="settings-section">
                  <textarea
                    rows={2}
                    value={flowDescription}
                    onChange={(e) => setFlowDescription(e.target.value)}
                    placeholder="What does this playbook do?"
                    className="desc-input"
                  />
                </div>

                {/* ═══════════════════════════════════════════════════════════
                    TRIGGERS SECTION - When should this playbook run?
                ═══════════════════════════════════════════════════════════ */}
                <div className="settings-section">
                  <div className="section-header">
                    <Icons.Zap size={14} />
                    <span>Triggers</span>
                    <span className="section-hint">When to run</span>
                  </div>

                  <div className="trigger-grid">
                    {[
                      { key: 'on_alert_created', label: 'Alert Created', icon: Icons.AlertCircle, color: '#f59e0b' },
                      { key: 'on_alert_closed', label: 'Alert Closed', icon: Icons.CheckCircle2, color: '#22c55e' },
                      { key: 'on_investigation_created', label: 'Case Created', icon: Icons.FolderOpen, color: '#8b5cf6' },
                      { key: 'on_investigation_closed', label: 'Case Closed', icon: Icons.Archive, color: '#6366f1' },
                      { key: 'on_webhook', label: 'Webhook', icon: Icons.Webhook, color: '#ec4899' },
                      { key: 'on_schedule', label: 'Schedule', icon: Icons.CalendarClock, color: '#14b8a6' },
                    ].map((trigger) => {
                      const enabled = !!playbookMeta.trigger_conditions?.[trigger.key];
                      const IconComponent = trigger.icon;
                      return (
                        <button
                          key={trigger.key}
                          type="button"
                          className={`trigger-tile ${enabled ? 'active' : ''}`}
                          onClick={() => updateTriggerCondition(trigger.key, !enabled)}
                          style={{ '--tile-color': trigger.color }}
                        >
                          <IconComponent size={16} />
                          <span>{trigger.label}</span>
                        </button>
                      );
                    })}
                  </div>

                  {/* Webhook config - inline when enabled */}
                  {playbookMeta.trigger_conditions?.on_webhook && (
                    <div className="trigger-config">
                      <Icons.Link size={12} />
                      <input
                        value={playbookMeta.trigger_conditions?.webhook?.path || ''}
                        onChange={(e) => updateTriggerNested('webhook', 'path', e.target.value)}
                        placeholder="/webhooks/my-playbook"
                      />
                    </div>
                  )}

                  {/* Schedule config - inline when enabled */}
                  {playbookMeta.trigger_conditions?.on_schedule && (
                    <div className="trigger-config">
                      <Icons.Clock size={12} />
                      <input
                        value={playbookMeta.trigger_conditions?.schedule?.cron || ''}
                        onChange={(e) => updateTriggerNested('schedule', 'cron', e.target.value)}
                        placeholder="0 * * * * (cron)"
                      />
                    </div>
                  )}

                  {/* Riggs toggle */}
                  <label className="riggs-toggle">
                    <input
                      type="checkbox"
                      checked={!!playbookMeta.riggs_allowed}
                      onChange={(e) => toggleRiggsAllowed(e.target.checked)}
                    />
                    <Icons.Bot size={14} />
                    <span>Allow Riggs to run automatically</span>
                  </label>

                  {/* Run timing relative to Riggs */}
                  <label className="riggs-timing">
                    <span>Run timing</span>
                    <select
                      value={playbookMeta.trigger_timing || 'post_triage'}
                      onChange={(e) =>
                        setPlaybookMeta((prev) => ({ ...prev, trigger_timing: e.target.value }))
                      }
                    >
                      <option value="pre_triage">Before Riggs (pre-triage)</option>
                      <option value="post_triage">After Riggs (post-triage)</option>
                      <option value="parallel">Parallel with Riggs</option>
                      <option value="on_demand">On demand only</option>
                    </select>
                  </label>
                </div>

                {/* ═══════════════════════════════════════════════════════════
                    FILTERS SECTION - What events should match?
                ═══════════════════════════════════════════════════════════ */}
                <div className="settings-section">
                  <div className="section-header">
                    <Icons.Filter size={14} />
                    <span>Filters</span>
                    <span className="section-hint">What to match</span>
                  </div>

                  {/* Severity - Always visible, compact */}
                  <div className="filter-row">
                    <span className="filter-label">Severity</span>
                    <div className="sev-pills">
                      {[
                        { key: 'low', letter: 'L', color: '#22c55e' },
                        { key: 'medium', letter: 'M', color: '#f59e0b' },
                        { key: 'high', letter: 'H', color: '#f97316' },
                        { key: 'critical', letter: 'C', color: '#ef4444' },
                      ].map((sev) => {
                        const active = (playbookMeta.severity_filter || []).includes(sev.key);
                        return (
                          <button
                            key={sev.key}
                            type="button"
                            className={`sev-btn ${active ? 'active' : ''}`}
                            style={{ '--sev-color': sev.color }}
                            onClick={() => {
                              if (active) {
                                updateMetaList('severity_filter', (prev) => prev.filter((item) => item !== sev.key));
                              } else {
                                updateMetaList('severity_filter', (prev) => [...prev, sev.key]);
                              }
                            }}
                            title={sev.key}
                          >
                            {sev.letter}
                          </button>
                        );
                      })}
                      {(!playbookMeta.severity_filter?.length) && <span className="any-badge">Any</span>}
                    </div>
                  </div>

                  <details className="filter-advanced">
                    <summary className="filter-advanced-summary">Advanced Filters</summary>

                    {/* Alert Types */}
                    <div className="filter-row">
                      <span className="filter-label">Types</span>
                      <div className="filter-tags">
                        {(playbookMeta.alert_types || []).map((item) => (
                          <span key={item} className="tag" onClick={() => removeFromList('alert_types', item, 'meta')}>{item} ×</span>
                        ))}
                        {!(playbookMeta.alert_types?.length) && ['phishing', 'malware', 'brute_force', 'data_exfil'].map((s) => (
                          <span key={s} className="suggestion" onClick={() => addToList('alert_types', s, 'meta')}>{s}</span>
                        ))}
                        <input
                          className="tag-input"
                          value={alertTypeDraft}
                          onChange={(e) => setAlertTypeDraft(e.target.value)}
                          placeholder="+ custom"
                          onKeyDown={(e) => {
                            if (e.key === 'Enter' && alertTypeDraft.trim()) {
                              e.preventDefault();
                              addToList('alert_types', alertTypeDraft, 'meta');
                              setAlertTypeDraft('');
                            }
                          }}
                          onBlur={() => {
                            if (alertTypeDraft.trim()) {
                              addToList('alert_types', alertTypeDraft, 'meta');
                              setAlertTypeDraft('');
                            }
                          }}
                        />
                      </div>
                    </div>

                    {/* Data Sources */}
                    <div className="filter-row">
                      <span className="filter-label">Sources</span>
                      <div className="filter-tags">
                        {(playbookMeta.data_sources || []).map((item) => (
                          <span key={item} className="tag" onClick={() => removeFromList('data_sources', item, 'meta')}>{item} ×</span>
                        ))}
                        {!(playbookMeta.data_sources?.length) && ['edr', 'email', 'siem', 'firewall', 'identity'].map((s) => (
                          <span key={s} className="suggestion" onClick={() => addToList('data_sources', s, 'meta')}>{s}</span>
                        ))}
                        <input
                          className="tag-input"
                          value={dataSourceDraft}
                          onChange={(e) => setDataSourceDraft(e.target.value)}
                          placeholder="+ custom"
                          onKeyDown={(e) => {
                            if (e.key === 'Enter' && dataSourceDraft.trim()) {
                              e.preventDefault();
                              addToList('data_sources', dataSourceDraft, 'meta');
                              setDataSourceDraft('');
                            }
                          }}
                          onBlur={() => {
                            if (dataSourceDraft.trim()) {
                              addToList('data_sources', dataSourceDraft, 'meta');
                              setDataSourceDraft('');
                            }
                          }}
                        />
                      </div>
                    </div>

                    {/* Alert Tags */}
                    <div className="filter-row">
                      <span className="filter-label">Alert Tags</span>
                      <div className="filter-tags">
                        {(playbookMeta.trigger_conditions?.alert_tags || []).map((item) => (
                          <span key={item} className="tag" onClick={() => removeFromList('alert_tags', item, 'trigger')}>{item} ×</span>
                        ))}
                        {!(playbookMeta.trigger_conditions?.alert_tags?.length) && ['vip', 'production', 'critical_asset'].map((s) => (
                          <span key={s} className="suggestion" onClick={() => addToList('alert_tags', s, 'trigger')}>{s}</span>
                        ))}
                        <input
                          className="tag-input"
                          value={alertTagDraft}
                          onChange={(e) => setAlertTagDraft(e.target.value)}
                          placeholder="+ custom"
                          onKeyDown={(e) => {
                            if (e.key === 'Enter' && alertTagDraft.trim()) {
                              e.preventDefault();
                              addToList('alert_tags', alertTagDraft, 'trigger');
                              setAlertTagDraft('');
                            }
                          }}
                          onBlur={() => {
                            if (alertTagDraft.trim()) {
                              addToList('alert_tags', alertTagDraft, 'trigger');
                              setAlertTagDraft('');
                            }
                          }}
                        />
                      </div>
                    </div>

                    {/* Case Tags */}
                    <div className="filter-row">
                      <span className="filter-label">Case Tags</span>
                      <div className="filter-tags">
                        {(playbookMeta.trigger_conditions?.investigation_tags || []).map((item) => (
                          <span key={item} className="tag" onClick={() => removeFromList('investigation_tags', item, 'trigger')}>{item} ×</span>
                        ))}
                        {!(playbookMeta.trigger_conditions?.investigation_tags?.length) && ['fraud', 'insider', 'apt'].map((s) => (
                          <span key={s} className="suggestion" onClick={() => addToList('investigation_tags', s, 'trigger')}>{s}</span>
                        ))}
                        <input
                          className="tag-input"
                          value={investigationTagDraft}
                          onChange={(e) => setInvestigationTagDraft(e.target.value)}
                          placeholder="+ custom"
                          onKeyDown={(e) => {
                            if (e.key === 'Enter' && investigationTagDraft.trim()) {
                              e.preventDefault();
                              addToList('investigation_tags', investigationTagDraft, 'trigger');
                              setInvestigationTagDraft('');
                            }
                          }}
                          onBlur={() => {
                            if (investigationTagDraft.trim()) {
                              addToList('investigation_tags', investigationTagDraft, 'trigger');
                              setInvestigationTagDraft('');
                            }
                          }}
                        />
                      </div>
                    </div>
                  </details>
                </div>

                {/* Version history link */}
                {playbookMeta.id && (
                  <div className="settings-section" style={{ paddingTop: 8 }}>
                    <button
                      type="button"
                      className="btn btn-ghost btn-sm"
                      style={{ fontSize: 11, opacity: 0.6 }}
                      onClick={() => {
                        setInspectorTab('revisions');
                        loadVersions(playbookMeta.id);
                      }}
                    >
                      Version history
                    </button>
                  </div>
                )}
                  </>
              </div>
            )}

            {inspectorTab === 'preview' && (
              <div className="inspector-section preview-tab">
                {/* Header card: action + status. Always visible. */}
                <div
                  style={{
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '0.5rem',
                    padding: '0.75rem',
                    marginBottom: '0.75rem',
                    background: 'rgba(60,179,113,0.06)',
                    border: '1px solid rgba(60,179,113,0.25)',
                    borderRadius: 8,
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '0.5rem' }}>
                    <div style={{ fontSize: 12, color: 'var(--text-muted, #94a3b8)', lineHeight: 1.4 }}>
                      Have Riggs draft a SOAR playbook tailored to this alert.
                      Opens the new draft in a new tab.
                    </div>
                    <button
                      type="button"
                      onClick={handleBuildPlaybookFromPreview}
                      disabled={
                        buildFromPreviewState.loading ||
                        !(previewAlert || previewInvestigation)
                      }
                      style={{
                        padding: '0.5rem 0.85rem',
                        background: buildFromPreviewState.loading
                          ? 'rgba(60,179,113,0.4)'
                          : 'var(--primary, #3CB371)',
                        color: '#fff',
                        border: 'none',
                        borderRadius: 6,
                        cursor:
                          buildFromPreviewState.loading ||
                          !(previewAlert || previewInvestigation)
                            ? 'not-allowed'
                            : 'pointer',
                        fontWeight: 500,
                        fontSize: 12,
                        whiteSpace: 'nowrap',
                      }}
                    >
                      {buildFromPreviewState.loading
                        ? 'Drafting…'
                        : 'Build Playbook from this Alert'}
                    </button>
                  </div>
                  {buildFromPreviewState.error && (
                    <div style={{ fontSize: 11, color: 'var(--danger, #ef4444)' }}>
                      {buildFromPreviewState.error}
                    </div>
                  )}
                </div>

                {/* Payload */}
                {(previewAlert || previewInvestigation) && !previewLoading ? (
                  <div className="payload-fullview">
                    <div className="payload-fullview-header">
                      <span className="trigger-payload-label">
                        {previewEntityType === 'investigation' ? 'Case' : 'Alert'} Payload
                      </span>
                      <span className="trigger-payload-path">
                        {previewEntityType === 'investigation' ? '$.trigger.investigation' : '$.trigger.alert'}
                      </span>
                    </div>
                    {renderJsonPreview(
                      previewEntityType === 'investigation' ? previewInvestigation : previewAlert,
                      previewEntityType === 'investigation' ? '$.trigger.investigation' : '$.trigger.alert',
                      previewEntityType === 'investigation' ? 'Investigation' : 'Alert'
                    )}
                  </div>
                ) : previewLoading ? (
                  <div style={{ padding: '1rem', fontSize: 12, color: 'var(--text-muted, #94a3b8)' }}>
                    Loading payload…
                  </div>
                ) : (
                  <div style={{ padding: '1rem', fontSize: 12, color: 'var(--text-muted, #94a3b8)', lineHeight: 1.5 }}>
                    Search for an alert or investigation in the search bar above
                    to load it here. You can use it as a sample run target and
                    seed Riggs's draft.
                  </div>
                )}
              </div>
            )}

            {inspectorTab === 'data' && (
              <div className="block-results-section">
                {!dataPreviewNodeId && (
                  <>
                    <div className="block-search">
                      <Icons.Search size={14} className="search-icon" />
                      <input
                        type="text"
                        placeholder="Search blocks"
                        value={blockSearchQuery || ''}
                        onChange={(e) => setBlockSearchQuery(e.target.value)}
                      />
                    </div>
                    <div className="block-list">
                  {nodes
                    .filter(n => !blockSearchQuery ||
                      (n.data?.label || n.data?.kind || '').toLowerCase().includes(blockSearchQuery.toLowerCase())
                    )
                    .map((node) => {
                      const kind = node.data?.kind || 'unknown';
                      const label = node.data?.label || node.data?.title || kind;
                      const isSelected = dataPreviewNodeId === node.id;
                      const iconProps = { size: 16 };
                      let IconComponent = Icons.Box;
                      let iconColor = '#6b7c93';

                      switch(kind) {
                        case 'trigger': IconComponent = Icons.Flag; iconColor = '#22c55e'; break;
                        case 'action': IconComponent = Icons.Zap; iconColor = '#f59e0b'; break;
                        case 'decision': IconComponent = Icons.GitBranch; iconColor = '#8b5cf6'; break;
                        case 'code': IconComponent = Icons.Code; iconColor = '#8b5cf6'; break;
                        case 'loop': IconComponent = Icons.Repeat; iconColor = '#ec4899'; break;
                        case 'approval': IconComponent = Icons.UserCheck; iconColor = '#f97316'; break;
                        case 'delay': IconComponent = Icons.Clock; iconColor = '#6366f1'; break;
                        case 'utility': IconComponent = Icons.Wrench; iconColor = '#06b6d4'; break;
                        case 'end': IconComponent = Icons.Square; iconColor = '#22c55e'; break;
                        case 'notify': IconComponent = Icons.Bell; iconColor = '#38bdf8'; break;
                        case 'enrich': IconComponent = Icons.Database; iconColor = '#14b8a6'; break;
                        case 'riggs_analyze': IconComponent = Icons.Brain; iconColor = '#a855f7'; break;
                        case 'create_ticket': IconComponent = Icons.Ticket; iconColor = '#f472b6'; break;
                        default: IconComponent = Icons.Box; iconColor = '#6b7c93';
                      }

                      return (
                        <button
                          key={node.id}
                          type="button"
                          className={`block-item ${isSelected ? 'selected' : ''}`}
                          onClick={() => {
                            setDataPreviewNodeId(node.id);
                            setNodes((nds) => nds.map((n) => ({
                              ...n,
                              selected: n.id === node.id
                            })));
                          }}
                        >
                          <span className="block-icon" style={{ color: iconColor }}>
                            <IconComponent {...iconProps} />
                          </span>
                          <span className="block-name">{label}</span>
                        </button>
                      );
                    })
                  }
                    </div>
                  </>
                )}

                {dataPreviewNodeId && (
                  <div className="block-detail">
                    <div className="block-detail-header">
                      <button type="button" className="icon-btn" onClick={() => setDataPreviewNodeId(null)}>
                        <Icons.ArrowLeft size={16} />
                      </button>
                      <span className="block-detail-name">
                        {nodes.find(n => n.id === dataPreviewNodeId)?.data?.label || 'Block'}
                      </span>
                      <div className="block-detail-actions">
                        <button type="button" className="icon-btn" title="Pin"><Icons.Pin size={14} /></button>
                        <button type="button" className="icon-btn" title="Previous"><Icons.ChevronLeft size={14} /></button>
                        <button type="button" className="icon-btn" title="Next"><Icons.ChevronRight size={14} /></button>
                      </div>
                    </div>
                    <div className="block-detail-tabs">
                      <button className={`block-detail-tab ${dataPreviewMode === 'execution' ? 'active' : ''}`} onClick={() => setDataPreviewMode('execution')}>Data</button>
                      <button className={`block-detail-tab ${dataPreviewMode === 'lookup' ? 'active' : ''}`} onClick={() => setDataPreviewMode('lookup')}>Logs</button>
                    </div>
                    <div className="block-detail-content">
                      {!lastExecution && !previewAlert && !previewInvestigation && (
                        <div className="data-preview-empty">
                          Run the playbook or load data to see block output.
                        </div>
                      )}
                      {(lastExecution || previewAlert || previewInvestigation) && (
                        <>
                          <div className="data-preview-path">
                            <span>Path</span>
                            <button type="button" onClick={() => copyToClipboard(executionPreviewPath || lookupPreviewPath)}>
                              {executionPreviewPath || lookupPreviewPath || '—'}
                            </button>
                          </div>
                          {renderJsonPreview(
                            executionPreviewData || lookupPreviewData || {},
                            executionPreviewPath || lookupPreviewPath,
                            nodes.find(n => n.id === dataPreviewNodeId)?.data?.label || 'Block'
                          )}
                        </>
                      )}
                    </div>
                  </div>
                )}

              </div>
            )}

            {inspectorTab === 'riggs' && (
              <div className="inspector-section riggs-section">

                {/* Header */}
                <div className="riggs-header">
                  <div className={`riggs-avatar ${riggsStatus}`}>
                    {riggsStatus === 'error'
                      ? <Icons.AlertTriangle size={16} />
                      : riggsStatus === 'thinking'
                      ? <Icons.Brain size={16} />
                      : <Icons.Bot size={16} />
                    }
                  </div>
                  <div className="riggs-header-meta">
                    <div className="riggs-title">Riggs AI Assistant</div>
                    <div className={`riggs-status-badge ${riggsStatus}`}>
                      <span className="status-dot" />
                      {riggsStatus === 'thinking' ? 'Thinking' : riggsStatus === 'error' ? 'Error' : 'Ready'}
                    </div>
                  </div>
                </div>

                {/* Tabs */}
                <div className="riggs-tabs">
                  <button
                    className={`riggs-tab ${riggsTab === 'build' ? 'active' : ''}`}
                    onClick={() => setRiggsTab('build')}
                  >
                    Build
                  </button>
                  <button
                    className={`riggs-tab ${riggsTab === 'recommend' ? 'active' : ''}`}
                    onClick={() => setRiggsTab('recommend')}
                  >
                    Recommend
                  </button>
                </div>

                {!playbookMeta.riggs_allowed && (
                  <div className="inline-info">
                    Riggs can still build and recommend playbooks. Auto-run is currently disabled for this playbook.
                  </div>
                )}
                {riggsError && <div className="inline-error">{riggsError}</div>}

                {/* BUILD TAB */}
                {riggsTab === 'build' ? (
                  <div className="riggs-pane">
                    <label className="riggs-field-label">
                      Requirements
                      <textarea
                        className="riggs-textarea"
                        rows={4}
                        value={riggsPrompt}
                        onChange={(e) => setRiggsPrompt(e.target.value)}
                        placeholder="Describe the response flow you need..."
                      />
                    </label>

                    <label className="riggs-field-label">
                      Alert Type <span style={{ textTransform: 'none', fontWeight: 400, opacity: 0.6 }}>(optional)</span>
                      <input
                        className="riggs-input"
                        value={riggsAlertType}
                        onChange={(e) => setRiggsAlertType(e.target.value)}
                        placeholder="phishing, malware, brute-force..."
                      />
                    </label>

                    <button
                      className="riggs-generate-btn"
                      onClick={handleRiggsBuild}
                      disabled={riggsBuildLoading || !String(riggsPrompt ?? '').trim()}
                    >
                      {riggsBuildLoading ? (
                        <>
                          <span className="riggs-spinner" />
                          <span>Building</span>
                          <span className="riggs-dots"><span /><span /><span /></span>
                        </>
                      ) : (
                        <>
                          <Icons.Sparkles size={14} />
                          Generate Playbook
                        </>
                      )}
                    </button>

                    {riggsResult && (
                      <div className="riggs-result-card">
                        <div className="riggs-result-name">{riggsResult.name}</div>
                        {riggsResult.description && (
                          <div className="riggs-result-desc">{riggsResult.description}</div>
                        )}
                        <div className="riggs-result-footer">
                          <div className="riggs-result-meta-row">
                            {riggsResult.generation_source && (
                              <span className={`riggs-badge ${riggsResult.generation_source === 'llm' ? 'ai' : 'template'}`}>
                                {riggsResult.generation_source === 'llm'
                                  ? <><Icons.Sparkles size={9} /> AI</>
                                  : <><Icons.Layers size={9} /> Template</>
                                }
                              </span>
                            )}
                            {riggsResult.canvas_data?.nodes?.length > 0 && (
                              <span className="riggs-badge nodes">
                                {riggsResult.canvas_data.nodes.length} nodes
                              </span>
                            )}
                          </div>
                          {riggsResult.canvas_data?.nodes?.length > 0 && (
                            <button
                              className="riggs-load-canvas-btn"
                              onClick={() => setRiggsResult(null)}
                            >
                              <Icons.Check size={11} />
                              Loaded
                            </button>
                          )}
                        </div>
                        {riggsResult.generation_reason && (
                          <div className="riggs-result-desc" style={{ fontSize: 11, opacity: 0.7 }}>
                            {riggsResult.generation_reason}
                          </div>
                        )}
                      </div>
                    )}
                  </div>

                ) : (
                  /* RECOMMEND TAB */
                  <div className="riggs-pane">

                    {/* Card 1: From Investigation */}
                    <div className="riggs-card">
                      <div className="riggs-card-header">
                        <div className="riggs-card-icon investigate">
                          <Icons.Brain size={13} />
                        </div>
                        <div className="riggs-card-title">From Investigation</div>
                      </div>

                      <div className={`riggs-hint ${previewEntityType === 'investigation' && previewInvestigation ? 'active' : 'inactive'}`}>
                        {previewEntityType === 'investigation' && previewInvestigation ? (
                          <>Using: <strong>{previewInvestigation.investigation_id || previewEntityId}</strong></>
                        ) : previewEntityType === 'alert' ? (
                          'An alert is loaded. Switch to an investigation for recommendations.'
                        ) : (
                          'Search for an investigation in Data Preview above.'
                        )}
                      </div>

                      <button
                        className="riggs-action-btn"
                        onClick={handleRiggsRecommend}
                        disabled={riggsRecommendLoading || previewEntityType !== 'investigation' || !previewInvestigation}
                      >
                        {riggsRecommendLoading ? (
                          <>
                            <span className="riggs-spinner" />
                            Analyzing
                            <span className="riggs-dots"><span /><span /><span /></span>
                          </>
                        ) : (
                          <>
                            <Icons.Search size={12} />
                            Recommend Playbooks
                          </>
                        )}
                      </button>

                      {riggsRecommendations.length > 0 && (
                        <div className="riggs-list">
                          {riggsRecommendations.map((rec) => {
                            const score = typeof rec.match_score === 'number' ? rec.match_score : parseFloat(rec.match_score) || 0;
                            const pct = Math.min(100, Math.round(score * 10));
                            return (
                              <div key={rec.playbook_id} className="riggs-item">
                                <div className="riggs-item-name">{rec.playbook_name}</div>
                                <div className="riggs-item-score-row">
                                  <div className="riggs-score-bar-track">
                                    <div className="riggs-score-bar-fill" style={{ width: `${pct}%` }} />
                                  </div>
                                  <span className="riggs-score-label">{score.toFixed(1)}</span>
                                </div>
                              </div>
                            );
                          })}
                        </div>
                      )}
                    </div>

                    {/* Card 2: From Alert Patterns */}
                    <div className="riggs-card">
                      <div className="riggs-card-header">
                        <div className="riggs-card-icon patterns">
                          <Icons.Zap size={13} />
                        </div>
                        <div className="riggs-card-title">From Alert Patterns</div>
                      </div>

                      <label className="riggs-field-label">
                        Alert Type
                        <input
                          className="riggs-input"
                          value={riggsAlertType}
                          onChange={(e) => setRiggsAlertType(e.target.value)}
                          placeholder="phishing, malware, brute-force..."
                        />
                      </label>

                      <button
                        className="riggs-action-btn"
                        onClick={handleRiggsSuggest}
                        disabled={riggsSuggestLoading || !String(riggsAlertType ?? '').trim()}
                      >
                        {riggsSuggestLoading ? (
                          <>
                            <span className="riggs-spinner" />
                            Analyzing
                            <span className="riggs-dots"><span /><span /><span /></span>
                          </>
                        ) : (
                          <>
                            <Icons.Zap size={12} />
                            Suggest from Alerts
                          </>
                        )}
                      </button>

                      {riggsSuggestion && (
                        <div className="riggs-suggest-result">
                          <div className="riggs-suggest-name">{riggsSuggestion.name}</div>
                          {riggsSuggestion.requirements && (
                            <div className="riggs-suggest-requirements">{riggsSuggestion.requirements}</div>
                          )}
                        </div>
                      )}
                    </div>

                  </div>
                )}
              </div>
            )}

            {inspectorTab === 'assets' && (
              <div className="inspector-section asset-section">
                <div className="section-title">Assets</div>
                {assetError && <div className="inline-error">{assetError}</div>}
                {assetMessage && <div className="inline-success">{assetMessage}</div>}
                <div className="asset-block">
                  <div className="asset-title">Custom Lists</div>
                  <div className="asset-list">
                    {availableLists.length === 0 && (
                      <div className="asset-empty">No lists yet.</div>
                    )}
                    {availableLists.map((lst) => (
                      <div key={lst.id || lst.name} className="asset-row">
                        <strong>{lst.name}</strong>
                        <span>{lst.list_type}</span>
                        <span>{lst.item_count || 0} items</span>
                      </div>
                    ))}
                  </div>
                  <div className="asset-form">
                    <label>
                      List Name
                      <input
                        value={listDraft.name}
                        onChange={(e) => setListDraft((prev) => ({ ...prev, name: e.target.value }))}
                        placeholder="suspicious_domains"
                      />
                    </label>
                    <label>
                      Type
                      <select
                        value={listDraft.list_type}
                        onChange={(e) => setListDraft((prev) => ({ ...prev, list_type: e.target.value }))}
                      >
                        <option value="allowlist">Allowlist</option>
                        <option value="blocklist">Blocklist</option>
                        <option value="lookup">Lookup</option>
                        <option value="enum">Enum</option>
                      </select>
                    </label>
                    <label>
                      Items (JSON or comma-separated)
                      <textarea
                        rows={2}
                        value={listDraft.items}
                        onChange={(e) => setListDraft((prev) => ({ ...prev, items: e.target.value }))}
                        placeholder='["one","two"] or one,two'
                      />
                    </label>
                    <button className="btn btn-ghost btn-sm" onClick={handleCreateList}>
                      Create List
                    </button>
                  </div>
                </div>

                <div className="asset-block">
                  <div className="asset-title">Custom Functions</div>
                  <div className="asset-list">
                    {availableFunctions.length === 0 && (
                      <div className="asset-empty">No functions yet.</div>
                    )}
                    {availableFunctions.map((fn) => (
                      <div key={fn.id} className="asset-row">
                        <strong>{fn.name}</strong>
                        <span>{fn.is_approved ? 'Approved' : 'Pending'}</span>
                        {!fn.is_approved && (
                          <button
                            className="btn btn-ghost btn-sm"
                            onClick={() => handleApproveFunction(fn.id)}
                          >
                            Approve
                          </button>
                        )}
                      </div>
                    ))}
                  </div>
                  <div className="asset-form">
                    <label>
                      Function Name
                      <input
                        value={functionDraft.name}
                        onChange={(e) => setFunctionDraft((prev) => ({ ...prev, name: e.target.value }))}
                        placeholder="normalize_alert"
                      />
                    </label>
                    <label>
                      Code
                      <textarea
                        rows={4}
                        value={functionDraft.code}
                        onChange={(e) => setFunctionDraft((prev) => ({ ...prev, code: e.target.value }))}
                        placeholder="def main(alert):\n    return {'ok': True}"
                      />
                    </label>
                    <label>
                      Input Schema (JSON)
                      <textarea
                        rows={2}
                        value={functionDraft.input_schema}
                        onChange={(e) => setFunctionDraft((prev) => ({ ...prev, input_schema: e.target.value }))}
                        placeholder='{"type":"object"}'
                      />
                    </label>
                    <label>
                      Output Schema (JSON)
                      <textarea
                        rows={2}
                        value={functionDraft.output_schema}
                        onChange={(e) => setFunctionDraft((prev) => ({ ...prev, output_schema: e.target.value }))}
                        placeholder='{"type":"object"}'
                      />
                    </label>
                    <button className="btn btn-secondary btn-sm" onClick={handleCreateFunction}>
                      Create Function
                    </button>
                  </div>
                </div>
              </div>
            )}

            {inspectorTab === 'metrics' && (
              <div className="inspector-section metrics-section">
                <div className="section-title">Metrics</div>
                {metricsLoading && <div className="metrics-empty">Loading metrics...</div>}
                {!metricsLoading && !metrics && (
                  <div className="metrics-empty">Run this playbook to see metrics.</div>
                )}
                {!metricsLoading && metrics && (
                  <>
                    <div className="metrics-grid">
                      <div className="metric-card">
                        <span>Executions</span>
                        <strong>{metrics.total_executions}</strong>
                      </div>
                      <div className="metric-card">
                        <span>Success Rate</span>
                        <strong>{metrics.success_rate}%</strong>
                      </div>
                      <div className="metric-card">
                        <span>Avg Duration</span>
                        <strong>{metrics.avg_duration_seconds ? `${metrics.avg_duration_seconds}s` : '—'}</strong>
                      </div>
                    </div>
                    {metrics.node_metrics?.length > 0 && (
                      <div className="metrics-list">
                        {metrics.node_metrics.slice(0, 5).map((node) => (
                          <div key={node.node_id} className="metric-row">
                            <strong>{node.node_id}</strong>
                            <span>{node.kind || node.node_type}</span>
                            <span>{node.failures} fails</span>
                          </div>
                        ))}
                      </div>
                    )}
                  </>
                )}
              </div>
            )}

            {inspectorTab === 'revisions' && (
              <div className="inspector-section revisions-section">
                <div className="section-title">Revision History</div>
                {versionsLoading && <div className="metrics-empty">Loading revisions...</div>}
                {!versionsLoading && versions.length === 0 && (
                  <div className="metrics-empty">No revisions yet. Save the playbook to create a version.</div>
                )}
                {!versionsLoading && versions.length > 0 && (
                  <div className="revisions-list">
                    {versions.map((v) => (
                      <div key={v.id} className="revision-row">
                        <div className="revision-info">
                          <strong>v{v.version_number}</strong>
                          <span className="revision-date">
                            {new Date(v.created_at).toLocaleString()}
                          </span>
                        </div>
                        {v.change_summary && (
                          <div className="revision-summary">{v.change_summary}</div>
                        )}
                        <button
                          className="btn btn-secondary btn-sm"
                          onClick={() => restoreVersion(v.id)}
                        >
                          Restore
                        </button>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}

            {inspectorTab === 'executions' && (
              <div className="inspector-section executions-section">
                <div className="section-title">Execution History</div>
                <div className="execution-filter">
                  <select
                    value={executionHistoryFilter}
                    onChange={(e) => {
                      setExecutionHistoryFilter(e.target.value);
                      loadExecutionHistory(playbookMeta.id, e.target.value);
                    }}
                  >
                    <option value="">All statuses</option>
                    <option value="completed">Completed</option>
                    <option value="running">Running</option>
                    <option value="failed">Failed</option>
                    <option value="waiting_approval">Waiting Approval</option>
                  </select>
                </div>
                {executionHistoryLoading && <div className="metrics-empty">Loading executions...</div>}
                {!executionHistoryLoading && executionHistory.length === 0 && (
                  <div className="metrics-empty">No executions yet. Run the playbook to see history.</div>
                )}
                {!executionHistoryLoading && executionHistory.length > 0 && (
                  <div className="executions-list">
                    {executionHistory.map((ex) => (
                      <div key={ex.execution_id} className="execution-row">
                        <div className="execution-row-header">
                          <span className={`status-badge status-${ex.status}`}>
                            {ex.status}
                          </span>
                          <span className="execution-id">{ex.execution_id}</span>
                        </div>
                        <div className="execution-row-meta">
                          <span className="execution-time">
                            {new Date(ex.started_at).toLocaleString()}
                          </span>
                          {ex.duration_ms && (
                            <span className="execution-duration">
                              {ex.duration_ms < 1000
                                ? `${Math.round(ex.duration_ms)}ms`
                                : `${(ex.duration_ms / 1000).toFixed(1)}s`}
                            </span>
                          )}
                        </div>
                        <div className="execution-row-actions">
                          <button
                            className="btn btn-secondary btn-sm"
                            onClick={async () => {
                              try {
                                const resp = await fetch(`/api/v1/playbooks/executions/${ex.execution_id}`, {
                                  credentials: 'include',
                                });
                                if (resp.ok) {
                                  const data = await resp.json();
                                  setExecutionView(data);
                                }
                              } catch (err) {
                              }
                            }}
                          >
                            View
                          </button>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}

            <div className="panel-footer">
              {lastExecution && (
                <div className="execution-card">
                  <div className="activity-title">Execution</div>
                  <div className="execution-meta">
                    <div>
                      <span>ID</span>
                      <strong>{lastExecution.execution_id}</strong>
                    </div>
                    <div>
                      <span>Status</span>
                      <strong>{lastExecution.status}</strong>
                    </div>
                  </div>
                  <button
                    className="btn btn-secondary btn-sm"
                    onClick={() => setExecutionView(lastExecution)}
                  >
                    Open Debugger
                  </button>
                </div>
              )}
            </div>
          </aside>
        </div>
      </div>
      {showDataPathPicker && (
        <DataPathPicker
          executionId={lastExecution?.execution_id}
          nodeId={dataPathContext?.nodeId}
          nodes={nodes}
          edges={edges}
          previewTrigger={previewTrigger}
          onSelect={selectDataPath}
          onClose={() => {
            setShowDataPathPicker(false);
            setDataPathContext(null);
          }}
        />
      )}
      {executionView && (
        <ExecutionView
          execution={executionView}
          onClose={() => setExecutionView(null)}
          onRefresh={() => {
            fetch(`/api/v1/playbooks/executions/${executionView.execution_id}`)
              .then((r) => r.json())
              .then((data) => {
                setExecutionView(data);
                setLastExecution(data);
              })
              .catch(e => console.error('Execution refresh error:', e));
          }}
        />
      )}

      {/* Connection drop menu - positioned fixed at screen coordinates */}
      {connectMenu && (
        <div
          className="connect-menu"
          style={{
            position: 'fixed',
            left: connectMenu.x,
            top: connectMenu.y,
            zIndex: 999999,
            background: 'rgba(12, 17, 25, 0.98)',
            border: '1px solid rgba(148, 163, 184, 0.2)',
            borderRadius: '8px',
            boxShadow: '0 12px 40px rgba(0, 0, 0, 0.5)',
            padding: '6px',
            width: '240px',
          }}
        >
          <div style={{ padding: '4px 8px 6px', fontSize: '10px', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.06em', color: 'rgba(148, 163, 184, 0.6)', borderBottom: '1px solid rgba(148, 163, 184, 0.1)', marginBottom: '6px' }}>
            Add Block
          </div>
          {PALETTE_GROUPS.map((group) => (
            <div key={group.id}>
              {group.id === 'advanced' && (
                <div
                  style={{ padding: '4px 8px', fontSize: '10px', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.06em', color: 'rgba(148, 163, 184, 0.4)', borderTop: '1px solid rgba(148, 163, 184, 0.1)', marginTop: '4px', paddingTop: '6px', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '4px' }}
                  onClick={(e) => {
                    const target = e.currentTarget.nextElementSibling;
                    if (target) target.style.display = target.style.display === 'none' ? 'grid' : 'none';
                    e.currentTarget.querySelector('span').textContent = target && target.style.display === 'none' ? '\u25B6' : '\u25BC';
                  }}
                >
                  <span style={{ fontSize: '8px' }}>{'\u25B6'}</span> More
                </div>
              )}
              <div style={{ display: group.id === 'advanced' ? 'none' : 'grid', gridTemplateColumns: '1fr 1fr', gap: '2px' }}>
                {group.items.map((itemKey) => {
                  const block = CANONICAL_BLOCKS[itemKey];
                  if (!block) return null;
                  const IconComp = block.icon;
                  return (
                    <button
                      key={itemKey}
                      type="button"
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: '6px',
                        padding: '6px 8px',
                        border: 'none',
                        borderRadius: '4px',
                        background: 'transparent',
                        color: '#e2e8f0',
                        fontSize: '12px',
                        textAlign: 'left',
                        cursor: 'pointer',
                      }}
                      onMouseOver={(e) => e.currentTarget.style.background = 'rgba(99, 102, 241, 0.15)'}
                      onMouseOut={(e) => e.currentTarget.style.background = 'transparent'}
                      onClick={() => handleConnectMenuSelect(itemKey)}
                    >
                      {IconComp && <IconComp size={14} style={{ color: 'rgba(148, 163, 184, 0.7)' }} />}
                      <span>{block.label}</span>
                    </button>
                  );
                })}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Keyboard Shortcuts Hint */}
      <div className="keyboard-hint">
        <span><kbd>Ctrl</kbd>+<kbd>Z</kbd> Undo</span>
        <span><kbd>Ctrl</kbd>+<kbd>Y</kbd> Redo</span>
        <span><kbd>Ctrl</kbd>+<kbd>C</kbd> Copy</span>
        <span><kbd>Ctrl</kbd>+<kbd>V</kbd> Paste</span>
        <span><kbd>Ctrl</kbd>+<kbd>F</kbd> Find</span>
        <span><kbd>Ctrl</kbd>+<kbd>A</kbd> Select All</span>
        <span><kbd>Del</kbd> Delete</span>
      </div>
    </div>
  );
}

function SignalNode({ id, data, selected }) {
  const isDecision = data?.kind === 'decision';
  const isTrigger = data?.kind === 'trigger';
  const isEnd = data?.kind === 'end';
  const hasErrorRoute = data?.config?.error_policy === 'route_to_error';
  const summary = configSummary(data?.kind, data?.config);
  const kindLabel = formatKindLabel(data?.kind);
  const executionStatus = data?.executionStatus;
  const executionTime = data?.executionTimeMs;
  const flowState = data?.flowState;
  const executionLabel = executionStatus ? executionStatus.replace(/_/g, ' ') : '';
  const migration = data?.config?._migration;
  // Hint when the node still has its default auto-generated title
  const hasDefaultTitle = !data?.title || data.title === kindLabel;

  // Get decision branches - default to yes/no if none defined
  const decisionBranches = isDecision ? (data?.config?.branches || [
    { id: 'yes', label: 'Yes' },
    { id: 'no', label: 'No' },
  ]) : [];

  return (
    <div className={`signal-node node-${data?.kind} ${selected ? 'selected' : ''} ${flowState ? `flow-${flowState}` : ''} ${executionStatus ? `exec-${executionStatus}` : ''} ${data?.executionIsCurrent ? 'exec-current' : ''} ${hasErrorRoute ? 'has-error-route' : ''} ${data?.searchMatch ? 'search-match' : ''} ${data?.searchMatchActive ? 'search-match-active' : ''} ${hasDefaultTitle && !selected ? 'node-default-title' : ''}`}>
      {!isTrigger && <Handle type="target" position={Position.Top} className="signal-handle" />}
      <button
        className="node-delete"
        onClick={(event) => {
          event.stopPropagation();
          data?.onDelete?.(id);
        }}
        aria-label="Delete node"
        title="Delete node"
      >
        ×
      </button>
      {!isTrigger && !isEnd && data?.onTest && (
        <button
          className={`node-run-btn${data?.testLoading ? ' running' : ''}`}
          onClick={(event) => {
            event.stopPropagation();
            data?.onTest?.();
          }}
          aria-label="Run this node"
          title="Run this node in isolation"
        >
          {data?.testLoading ? '...' : '▶'}
        </button>
      )}
        <div className="signal-node-body">
          <div className="node-header">
            <span className="node-pill">{kindLabel || 'node'}</span>
            {executionStatus && (
              <span className={`node-exec node-exec--${executionStatus}`}>
                {executionLabel}
                {executionTime ? ` · ${Math.round(executionTime)}ms` : ''}
              </span>
            )}
          </div>
          {migration && (
            <div className="node-migration">
              Migrated from {formatKindLabel(migration.from || migration.kind || 'legacy')} block
            </div>
          )}
          <div className="node-title">{data?.title || 'Untitled'}</div>
        <div className="node-summary">{data?.summary || 'Describe the purpose'}</div>
        {summary.length > 0 && (
          <div className="node-config">
            {summary.map((line) => (
              <div key={line} className="node-config-line">{line}</div>
            ))}
          </div>
        )}
      </div>
      <div className="node-ports">
        <span className="port" />
        <span className="port" />
        <span className="port" />
      </div>
      {isDecision ? (
        <div className="decision-ports">
          {decisionBranches.map((branch) => (
            <div key={branch.id} className="decision-port">
              <Handle type="source" position={Position.Bottom} id={branch.id} className="signal-handle" />
              <span>{branch.label}</span>
            </div>
          ))}
        </div>
      ) : hasErrorRoute ? (
        <div className="error-route-ports">
          <div className="error-route-port success-port">
            <Handle type="source" position={Position.Bottom} id="default" className="signal-handle" />
            <span>Success</span>
          </div>
          <div className="error-route-port error-port">
            <Handle type="source" position={Position.Bottom} id="error" className="signal-handle signal-handle--error" />
            <span>Error</span>
          </div>
        </div>
      ) : (
        <Handle type="source" position={Position.Bottom} className="signal-handle" />
      )}
    </div>
  );
}

function DeletableEdge({
  id,
  sourceX,
  sourceY,
  targetX,
  targetY,
  sourcePosition,
  targetPosition,
  markerEnd,
  data,
  selected,
}) {
  const [edgePath, labelX, labelY] = getSmoothStepPath({
    sourceX,
    sourceY,
    sourcePosition,
    targetX,
    targetY,
    targetPosition,
  });
  const flowDirection = data?.flowDirection;
  const isHighlighted = flowDirection === 'up' || flowDirection === 'down';
  const strokeColor = flowDirection === 'up' ? '#38bdf8' : flowDirection === 'down' ? '#22c55e' : undefined;
  const edgeLabel = data?.label;

  return (
    <>
      <BaseEdge
        path={edgePath}
        markerEnd={markerEnd}
        className={isHighlighted ? 'edge-highlight' : ''}
        style={isHighlighted ? { stroke: strokeColor, strokeWidth: 2.5 } : undefined}
      />
      <EdgeLabelRenderer>
        {edgeLabel && (
          <div
            className="edge-label"
            style={{
              transform: `translate(-50%, -50%) translate(${labelX}px, ${labelY - 12}px)`,
            }}
          >
            {edgeLabel}
          </div>
        )}
        <button
          className={`edge-delete ${selected ? 'edge-delete--visible' : ''}`}
          style={{
            transform: `translate(-50%, -50%) translate(${labelX}px, ${labelY}px)`,
          }}
          onClick={(event) => {
            event.stopPropagation();
            data?.onDelete?.(id);
          }}
          aria-label="Delete path"
          title="Delete path"
        >
          ×
        </button>
      </EdgeLabelRenderer>
    </>
  );
}

  function renderConfigFields(kind, config, onChange, helpers = {}) {
    const {
      nodeId,
      onOpenDataPath,
      onPythonMount,
      onSetEdges,
      lists = [],
      functions = [],
      integrations = [],
      playbookIntegrations = [],
    } = helpers;
    const approvedFunctions = functions.filter((fn) => fn.is_approved !== false);
    const withPathPicker = (field) => onOpenDataPath && nodeId && field;

    // Maps observable_type to the most common alert data path for that type
    const OBSERVABLE_PATHS = {
      domain:    '$.trigger.alert.entity',
      url:       '$.trigger.alert.entity',
      ip:        '$.trigger.alert.src_ip',
      ip_dst:    '$.trigger.alert.dst_ip',
      file_hash: '$.trigger.alert.file_hash',
      hash:      '$.trigger.alert.file_hash',
      md5:       '$.trigger.alert.file_hash',
      sha256:    '$.trigger.alert.file_hash',
      email:     '$.trigger.alert.entity',
      hostname:  '$.trigger.alert.hostname',
      user:      '$.trigger.alert.username',
      process:   '$.trigger.alert.process_name',
    };

    const allIntegrations = playbookIntegrations.length > 0 ? playbookIntegrations : integrations;
    const selectedIntegration = allIntegrations.find(
      (i) => i.instance_id === config.integration_instance_id || i.id === config.integration_instance_id || i.id === config.integration
    );
    const integrationEndpoints = selectedIntegration?.endpoints || selectedIntegration?.actions || [];
    const selectedEndpoint = integrationEndpoints.find((e) => e.id === config.endpoint_id || e.name === config.endpoint_id);
    const endpointParameters = (() => {
      if (Array.isArray(selectedEndpoint?.parameters)) return selectedEndpoint.parameters;
      if (Array.isArray(selectedEndpoint?.params)) return selectedEndpoint.params;
      const schemaProps = selectedEndpoint?.request?.schema?.properties || selectedEndpoint?.schema?.properties;
      if (schemaProps && typeof schemaProps === 'object') {
        return Object.entries(schemaProps).map(([name, schema]) => ({
          name,
          required: Array.isArray(selectedEndpoint?.request?.schema?.required) ? selectedEndpoint.request.schema.required.includes(name) : false,
          type: schema?.type || 'string',
          description: schema?.description || '',
        }));
      }
      return [];
    })();

    const getConfigValue = (field) => {
      if (!field || !field.includes('.')) return config[field];
      const [root, child] = field.split('.');
      return config?.[root]?.[child];
    };

    const setConfigValue = (field, value) => {
      if (!field || !field.includes('.')) {
        onChange({ [field]: value });
        return;
      }
      const [root, child] = field.split('.');
      const currentRoot = config?.[root] || {};
      onChange({ [root]: { ...currentRoot, [child]: value } });
    };

    const renderPathInput = (label, field, placeholder) => (
      <label>
        {label}
        <div className="field-row">
          <input
            value={getConfigValue(field) || ''}
            onChange={(e) => setConfigValue(field, e.target.value)}
            placeholder={placeholder}
          />
          {withPathPicker(field) && (
            <button
              type="button"
              className="btn btn-ghost btn-sm"
              onClick={() => onOpenDataPath(nodeId, field)}
            >
              Pick
            </button>
          )}
        </div>
      </label>
    );

  switch (kind) {
      case 'trigger':
        return (
          <>
            <label>
              Trigger Type
              <select
                value={config.trigger_type || 'alert'}
                onChange={(e) => onChange({ trigger_type: e.target.value })}
              >
                <option value="alert">Alert</option>
                <option value="webhook">Webhook</option>
                <option value="schedule">Schedule</option>
                <option value="manual">Manual</option>
              </select>
            </label>
            {config.trigger_type === 'alert' && (
              <label>
                Alert Filter
                <input
                  value={config.alert_filter || ''}
                  onChange={(e) => onChange({ alert_filter: e.target.value })}
                  placeholder="severity:high"
                />
                <span className="field-hint">Filter alerts by criteria (e.g., severity:high, type:phishing)</span>
              </label>
            )}
            {config.trigger_type === 'webhook' && (
              <label>
                Webhook Secret
                <input
                  value={config.webhook_secret || ''}
                  onChange={(e) => onChange({ webhook_secret: e.target.value })}
                  placeholder="optional secret"
                />
                <span className="field-hint">Optional HMAC secret for webhook validation</span>
              </label>
            )}
            {config.trigger_type === 'schedule' && (
              <label>
                Schedule (Cron)
                <input
                  value={config.schedule_cron || ''}
                  onChange={(e) => onChange({ schedule_cron: e.target.value })}
                  placeholder="0 * * * *"
                />
                <span className="field-hint">Cron expression (e.g., "0 9 * * *" for daily at 9 AM)</span>
              </label>
            )}
            {config.trigger_type === 'manual' && (
              <label>
                Button Label
                <input
                  value={config.manual_label || ''}
                  onChange={(e) => onChange({ manual_label: e.target.value })}
                  placeholder="Run manual investigation"
                />
              </label>
            )}
          </>
        );
      case 'respond': {
        return (
          <>
            {true && (
              <>
                <div className="config-group">
                  <div className="config-group-title">Integration</div>
                  <label>
                    Integration Instance
                    <select
                      value={config.integration_instance_id || ''}
                      onChange={(e) => {
                        const val = e.target.value;
                        onChange({ integration_instance_id: val, endpoint_id: '', action_type: '', params: {} });
                        // Auto-title: set node title to integration name
                        const intg = allIntegrations.find((i) => (i.instance_id || i.id) === val);
                        if (intg) updateNode({ title: intg.name || intg.display_name || intg.id });
                      }}
                    >
                      <option value="">Select integration</option>
                      {allIntegrations.map((integration) => (
                        <option key={integration.instance_id || integration.id} value={integration.instance_id || integration.id}>
                          {integration.name || integration.display_name || integration.id}
                        </option>
                      ))}
                    </select>
                  </label>
                  <label>
                    Action
                    <select
                      value={config.endpoint_id || ''}
                      onChange={(e) => {
                        const val = e.target.value;
                        onChange({ endpoint_id: val, action_type: val });
                        // Auto-title: "IntegrationName - Action Name"
                        const intg = allIntegrations.find((i) => (i.instance_id || i.id) === config.integration_instance_id);
                        const ep = integrationEndpoints.find((ep) => (ep.id || ep.name) === val);
                        if (intg && ep) {
                          const intgName = intg.name || intg.display_name || intg.id;
                          const epName = ep.name || ep.id;
                          updateNode({ title: `${intgName} - ${epName}` });
                        }
                      }}
                      disabled={!config.integration_instance_id}
                    >
                      <option value="">Select action</option>
                      {integrationEndpoints.length > 0 ? (
                        integrationEndpoints.map((endpoint) => (
                          <option key={endpoint.id || endpoint.name} value={endpoint.id || endpoint.name}>
                            {endpoint.name || endpoint.id}
                          </option>
                        ))
                      ) : (
                        <option value="" disabled>No actions available</option>
                      )}
                    </select>
                  </label>
                  {!config.integration_instance_id && (
                    <div className="config-note info">
                      Select an integration to see available actions.
                    </div>
                  )}
                  {selectedEndpoint && (
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginTop: '4px', flexWrap: 'wrap' }}>
                      {selectedEndpoint.observable_type && (
                        <span style={{ display: 'flex', alignItems: 'center', gap: '5px', fontSize: '0.72rem', color: 'var(--text-muted)' }}>
                          Expects:
                          <span style={{ background: 'rgba(60,179,113,0.12)', color: 'var(--primary)', padding: '1px 7px', borderRadius: '4px', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                            {selectedEndpoint.observable_type}
                          </span>
                        </span>
                      )}
                      {selectedEndpoint.read_only === false && (
                        <span style={{ background: 'rgba(239,68,68,0.1)', color: 'var(--danger)', padding: '1px 7px', borderRadius: '4px', fontSize: '0.72rem', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                          write
                        </span>
                      )}
                      {(selectedEndpoint.observable_type || endpointParameters.length > 0) && (
                        <button
                          type="button"
                          className="btn btn-ghost btn-sm"
                          style={{ fontSize: '0.72rem', padding: '2px 10px', marginLeft: 'auto', color: 'var(--primary)', border: '1px solid rgba(60,179,113,0.3)' }}
                          onClick={() => {
                            const suggestedPath = OBSERVABLE_PATHS[selectedEndpoint.observable_type] || '$.trigger.alert.entity';
                            const newParams = { ...(config.params || {}) };
                            const requiredParams = endpointParameters.filter((p) => p.required);
                            if (requiredParams.length > 0) {
                              requiredParams.forEach((p) => {
                                if (!newParams[p.name]) {
                                  const containsPath = p.contains && p.contains.length > 0 ? (OBSERVABLE_PATHS[p.contains[0]] || suggestedPath) : suggestedPath;
                                  newParams[p.name] = containsPath;
                                }
                              });
                            } else if (selectedEndpoint.observable_type) {
                              const key = selectedEndpoint.observable_type === 'file_hash' ? 'hash' : selectedEndpoint.observable_type;
                              if (!newParams[key]) newParams[key] = suggestedPath;
                            } else if (endpointParameters.length === 0) {
                              if (!newParams['value']) newParams['value'] = '$.trigger.alert.entity';
                            }
                            onChange({ params: newParams });
                          }}
                          title="Suggest data path mappings for this action"
                        >
                          Auto-fill
                        </button>
                      )}
                    </div>
                  )}
                </div>

                {config.integration_instance_id && config.endpoint_id && (
                  <div className="config-group">
                    <div className="config-group-title" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <span>Input Mapping</span>
                      <button
                        type="button"
                        className="btn btn-ghost btn-sm"
                        style={{ fontSize: '0.7rem', padding: '2px 8px', marginLeft: 'auto' }}
                        onClick={() => {
                          const currentParams = config.params || {};
                          const newKey = `field_${Object.keys(currentParams).length + 1}`;
                          onChange({ params: { ...currentParams, [newKey]: '' } });
                        }}
                      >
                        + Add Field
                      </button>
                    </div>

                    {/* Connector-defined parameters */}
                    {endpointParameters.map((param) => (
                      <label key={param.name}>
                        <span style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                          {param.name}
                          {param.required && (
                            <span style={{ color: 'var(--danger)', fontSize: '0.65rem', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.04em' }}>required</span>
                          )}
                        </span>
                        <div className="field-row">
                          <input
                            value={config.params?.[param.name] || ''}
                            onChange={(e) => onChange({
                              params: { ...(config.params || {}), [param.name]: e.target.value },
                            })}
                            placeholder="value or $.data.path"
                          />
                          <button
                            type="button"
                            className="btn btn-ghost btn-sm path-picker-btn"
                            onClick={() => onOpenDataPath(nodeId, `params.${param.name}`)}
                            title="Pick from alert/investigation data"
                          >
                            $.
                          </button>
                        </div>
                        {(param.description || (param.contains && param.contains.length > 0)) && (
                          <span className="field-hint">
                            {param.description && <span>{param.description}</span>}
                            {param.contains && param.contains.length > 0 && (
                              <span style={{ marginLeft: param.description ? '6px' : 0, color: 'var(--text-muted)', fontStyle: 'italic' }}>
                                accepts: {param.contains.join(', ')}
                              </span>
                            )}
                          </span>
                        )}
                      </label>
                    ))}

                    {/* Custom / additional params not in the connector definition */}
                    {Object.entries(config.params || {})
                      .filter(([key]) => !endpointParameters.find((p) => p.name === key))
                      .map(([key, val]) => (
                        <div key={key} style={{ display: 'flex', gap: '4px', alignItems: 'center', marginBottom: '6px' }}>
                          <input
                            value={key}
                            onChange={(e) => {
                              const newParams = { ...(config.params || {}) };
                              const newKey = e.target.value;
                              const oldVal = newParams[key];
                              delete newParams[key];
                              if (newKey) newParams[newKey] = oldVal;
                              onChange({ params: newParams });
                            }}
                            placeholder="field name"
                            style={{ flex: '0 0 36%', minWidth: 0 }}
                          />
                          <input
                            value={val || ''}
                            onChange={(e) => onChange({
                              params: { ...(config.params || {}), [key]: e.target.value },
                            })}
                            placeholder="value or $.data.path"
                            style={{ flex: 1, minWidth: 0 }}
                          />
                          <button
                            type="button"
                            className="btn btn-ghost btn-sm path-picker-btn"
                            onClick={() => onOpenDataPath(nodeId, `params.${key}`)}
                            title="Pick from alert/investigation data"
                            style={{ flexShrink: 0 }}
                          >
                            $.
                          </button>
                          <button
                            type="button"
                            className="btn btn-ghost btn-sm"
                            style={{ color: 'var(--danger)', padding: '0 8px', flexShrink: 0, fontSize: '1rem', lineHeight: 1 }}
                            onClick={() => {
                              const newParams = { ...(config.params || {}) };
                              delete newParams[key];
                              onChange({ params: newParams });
                            }}
                            title="Remove field"
                          >
                            &times;
                          </button>
                        </div>
                      ))
                    }

                    {endpointParameters.length === 0 && Object.keys(config.params || {}).length === 0 && (
                      <div className="config-note info" style={{ fontSize: '0.75rem' }}>
                        {selectedEndpoint?.observable_type ? (
                          <>
                            This action expects a <strong>{selectedEndpoint.observable_type}</strong>. Click <strong>Auto-fill</strong> above, or use "+ Add Field" to map manually —
                            e.g., field <strong>{selectedEndpoint.observable_type === 'file_hash' ? 'hash' : selectedEndpoint.observable_type}</strong> &rarr; <strong>{OBSERVABLE_PATHS[selectedEndpoint.observable_type] || '$.trigger.alert.entity'}</strong>
                          </>
                        ) : (
                          <>
                            No parameters defined for this action. Use "+ Add Field" to map alert data — e.g., field <strong>value</strong> &rarr; <strong>$.trigger.alert.entity</strong>
                          </>
                        )}
                      </div>
                    )}
                  </div>
                )}

                <div className="config-group">
                  <div className="config-group-title">Behavior</div>
                  {renderPathInput('Primary Entity', 'target_path', '$.trigger.alert.entity')}
                  <span className="field-hint">The main entity this action targets — used for logging and result tracking</span>

                  <div className="field-row-inline">
                    <label>
                      <span className="label-text">Priority</span>
                      <select
                        value={config.priority || 'medium'}
                        onChange={(e) => onChange({ priority: e.target.value })}
                        className="inline-select"
                      >
                        <option value="low">Low</option>
                        <option value="medium">Medium</option>
                        <option value="high">High</option>
                      </select>
                    </label>
                  </div>
                </div>
              </>
            )}

          </>
        );
      }
      case 'decision': {
        const decision = normalizeDecisionConfig(config);
        const rootGroup = decision.conditions;
        const updateDecision = (nextGroup) => {
          const expression = compileDecisionGroup(nextGroup);
          onChange({ conditions: nextGroup, expression });
        };

        const renderGroup = (group, depth = 0) => (
          <div className={`decision-group ${depth > 0 ? 'nested' : ''}`} key={group.id}>
            <div className="decision-group-header">
              <span className="decision-group-label">{depth === 0 ? 'If' : 'Group'}</span>
              <div className="decision-group-controls">
                <button
                  type="button"
                  className={`btn btn-ghost btn-sm ${group.operator === 'AND' ? 'active' : ''}`}
                  onClick={() => updateDecision(updateDecisionGroup(rootGroup, group.id, (g) => ({ ...g, operator: 'AND' })))}
                >
                  AND
                </button>
                <button
                  type="button"
                  className={`btn btn-ghost btn-sm ${group.operator === 'OR' ? 'active' : ''}`}
                  onClick={() => updateDecision(updateDecisionGroup(rootGroup, group.id, (g) => ({ ...g, operator: 'OR' })))}
                >
                  OR
                </button>
                {depth > 0 && (
                  <button
                    type="button"
                    className="btn btn-ghost btn-sm"
                    onClick={() => updateDecision(removeDecisionGroup(rootGroup, group.id))}
                  >
                    Remove Group
                  </button>
                )}
              </div>
            </div>
            <div className="decision-rows">
              {(group.conditions || []).map((condition) => (
                <div key={condition.id} className="decision-row">
                  <div className="decision-operand">
                    <select
                      value={condition.left?.type || 'path'}
                      onChange={(e) => updateDecision(updateDecisionCondition(rootGroup, condition.id, (c) => ({
                        ...c,
                        left: { ...c.left, type: e.target.value },
                      })))}
                    >
                      <option value="path">Data Path</option>
                      <option value="value">Value</option>
                    </select>
                    <div className="field-row">
                      <input
                        className="config-input"
                        value={condition.left?.value || ''}
                        onChange={(e) => updateDecision(updateDecisionCondition(rootGroup, condition.id, (c) => ({
                          ...c,
                          left: { ...c.left, value: e.target.value },
                        })))}
                        placeholder={condition.left?.type === 'value' ? 'literal value' : '$.trigger.alert.severity'}
                      />
                      {(condition.left?.type === 'path' || !condition.left?.type) && onOpenDataPath && (
                        <button
                          type="button"
                          className="btn btn-ghost btn-sm"
                          onClick={() => onOpenDataPath(nodeId, 'decision', { mode: 'decision', conditionId: condition.id, side: 'left' })}
                        >
                          Pick
                        </button>
                      )}
                    </div>
                  </div>
                  <select
                    value={condition.operator || 'equals'}
                    onChange={(e) => updateDecision(updateDecisionCondition(rootGroup, condition.id, (c) => ({
                      ...c,
                      operator: e.target.value,
                    })))}
                  >
                    {DECISION_OPERATORS.map((op) => (
                      <option key={op.value} value={op.value}>{op.label}</option>
                    ))}
                  </select>
                  {!['exists', 'missing'].includes(condition.operator) && (
                    <div className="decision-operand">
                      <select
                        value={condition.right?.type || 'value'}
                        onChange={(e) => updateDecision(updateDecisionCondition(rootGroup, condition.id, (c) => ({
                          ...c,
                          right: { ...c.right, type: e.target.value },
                        })))}
                      >
                        <option value="value">Value</option>
                        <option value="path">Data Path</option>
                      </select>
                      {condition.right?.type === 'path' ? (
                        <div className="field-row">
                          <input
                            value={condition.right?.value || ''}
                            onChange={(e) => updateDecision(updateDecisionCondition(rootGroup, condition.id, (c) => ({
                              ...c,
                              right: { ...c.right, value: e.target.value, type: 'path' },
                            })))}
                            placeholder="$.trigger.alert.score"
                          />
                          {withPathPicker(`decision.${condition.id}.right`) && (
                            <button
                              type="button"
                              className="btn btn-ghost btn-sm"
                              onClick={() => onOpenDataPath(nodeId, 'decision', { mode: 'decision', conditionId: condition.id, side: 'right' })}
                            >
                              Pick
                            </button>
                          )}
                        </div>
                      ) : (
                        <input
                          value={condition.right?.value || ''}
                          onChange={(e) => updateDecision(updateDecisionCondition(rootGroup, condition.id, (c) => ({
                            ...c,
                            right: { ...c.right, value: e.target.value, type: 'value' },
                          })))}
                          placeholder="value or comma list"
                        />
                      )}
                    </div>
                  )}
                  <button
                    type="button"
                    className="btn btn-ghost btn-sm"
                    onClick={() => updateDecision(removeDecisionCondition(rootGroup, condition.id))}
                  >
                    Remove
                  </button>
                </div>
              ))}
            </div>
            <div className="decision-group-actions">
              <button
                type="button"
                className="btn btn-ghost btn-sm"
                onClick={() => updateDecision(updateDecisionGroup(rootGroup, group.id, (g) => ({
                  ...g,
                  conditions: [...(g.conditions || []), createDecisionCondition()],
                })))}
              >
                + Condition
              </button>
              <button
                type="button"
                className="btn btn-ghost btn-sm"
                onClick={() => updateDecision(updateDecisionGroup(rootGroup, group.id, (g) => ({
                  ...g,
                  groups: [...(g.groups || []), createDecisionGroup()],
                })))}
              >
                + Group
              </button>
            </div>
            {(group.groups || []).map((child) => renderGroup(child, depth + 1))}
          </div>
        );

        // Branches management
        const branches = config.branches || [
          { id: 'yes', label: 'Yes' },
          { id: 'no', label: 'No' },
        ];

        const updateBranches = (newBranches) => {
          onChange({ branches: newBranches });
          // Sync edges:
          //  - Orphaned sourceHandle (branch removed) → reroute to the last branch
          //  - Live branch label changed → propagate the new label onto the edge
          if (onSetEdges && nodeId) {
            const validHandleIds = new Set(newBranches.map(b => b.id));
            const labelByHandle = new Map(newBranches.map(b => [b.id, b.label]));
            onSetEdges(prev => prev.map(edge => {
              if (edge.source !== nodeId || !edge.sourceHandle) return edge;
              if (!validHandleIds.has(edge.sourceHandle)) {
                // Branch removed — reroute to the last (else) branch
                const lastBranch = newBranches[newBranches.length - 1];
                return {
                  ...edge,
                  sourceHandle: lastBranch.id,
                  label: lastBranch.label,
                  data: { ...edge.data, label: lastBranch.label },
                };
              }
              // Branch still exists; propagate any label change to the edge
              const liveLabel = labelByHandle.get(edge.sourceHandle);
              if (liveLabel && edge.label !== liveLabel) {
                return {
                  ...edge,
                  label: liveLabel,
                  data: { ...edge.data, label: liveLabel },
                };
              }
              return edge;
            }));
          }
        };

        const addBranch = () => {
          const newId = `branch-${Date.now()}`;
          updateBranches([
            ...branches.slice(0, -1), // Insert before the last branch (else)
            { id: newId, label: `Branch ${branches.length}` },
            branches[branches.length - 1], // Keep last branch at end
          ]);
        };

        const removeBranch = (branchId) => {
          if (branches.length <= 2) return; // Keep at least 2 branches
          updateBranches(branches.filter((b) => b.id !== branchId));
        };

        const updateBranchLabel = (branchId, label) => {
          updateBranches(branches.map((b) => b.id === branchId ? { ...b, label } : b));
        };

        return (
          <>
            <div className="config-group">
              <div className="config-group-title">Branches</div>
              <div className="decision-branches">
                {branches.map((branch, index) => (
                  <div key={branch.id} className="decision-branch-row">
                    <input
                      value={branch.label}
                      onChange={(e) => updateBranchLabel(branch.id, e.target.value)}
                      placeholder="Branch label"
                      className="branch-label-input"
                    />
                    {branches.length > 2 && (
                      <button
                        type="button"
                        className="btn btn-ghost btn-sm"
                        onClick={() => removeBranch(branch.id)}
                      >
                        ×
                      </button>
                    )}
                  </div>
                ))}
              </div>
              <button
                type="button"
                className="btn btn-ghost btn-sm"
                onClick={addBranch}
              >
                + Add Branch
              </button>
            </div>
            <div className="config-group">
              <div className="config-group-title">Condition</div>
              {renderGroup(rootGroup)}
              <div className="config-note">
                First matching branch is taken. Last branch acts as "else".
              </div>
            </div>
          </>
        );
      }
      case 'code': {
        const modeValue = config.mode || config.transform_type || 'extract';
        const setMode = (value) => {
          if (['extract', 'map', 'filter', 'identity'].includes(value)) {
            onChange({ mode: value, transform_type: value });
          } else {
            onChange({ mode: value });
          }
        };

        return (
          <>
            <label>
              Code Mode
              <select value={modeValue} onChange={(e) => setMode(e.target.value)}>
                <option value="extract">Extract</option>
                <option value="map">Map</option>
                <option value="filter">Filter</option>
                <option value="assign">Assign Variable</option>
                <option value="script">Script (Python)</option>
              </select>
            </label>
            {['extract', 'map', 'filter'].includes(modeValue) && (
              <>
                {renderPathInput('Input Path', 'input_path', '$.trigger.alert')}
                {modeValue === 'extract' && renderPathInput('Output Path', 'transform_config.output_path', '$.field')}
                {modeValue === 'map' && renderPathInput('Map Path', 'transform_config.map_path', '$.items[*].id')}
                {modeValue === 'filter' && (
                  <>
                    {renderPathInput('Filter Path', 'transform_config.filter_path', '$.severity')}
                    <label>
                      Filter Value
                      <input
                        value={getConfigValue('transform_config.filter_value') || ''}
                        onChange={(e) => setConfigValue('transform_config.filter_value', e.target.value)}
                        placeholder="high"
                      />
                    </label>
                  </>
                )}
              </>
            )}
            {modeValue === 'assign' && (
              <>
                <label>
                  Variable Name
                  <input
                    value={config.assign?.name || ''}
                    onChange={(e) => onChange({ assign: { ...(config.assign || {}), name: e.target.value } })}
                    placeholder="risk_score"
                  />
                </label>
                {renderPathInput('Value Path', 'assign.value_path', '$.trigger.alert.score')}
                <label>
                  Static Value (optional)
                  <input
                    value={config.assign?.static_value || ''}
                    onChange={(e) => onChange({ assign: { ...(config.assign || {}), static_value: e.target.value } })}
                    placeholder="optional"
                  />
                </label>
              </>
            )}
            {modeValue === 'script' && (
              <div className="config-note">
                Use the code panel below to configure script inputs and logic.
              </div>
            )}
          </>
        );
      }
      case 'loop':
        return (
          <>
            <div className="config-group">
              <div className="config-group-title">Loop Source</div>
              {renderPathInput('Items Path', 'items_path', '$.trigger.alert.iocs')}
              <label>
                Loop Variable Name
                <input
                  value={config.loop_variable || 'item'}
                  onChange={(e) => onChange({ loop_variable: e.target.value })}
                  placeholder="item"
                />
              </label>
            </div>
            <div className="config-group">
              <div className="config-group-title">Limits</div>
              <label>
                Max Iterations
                <input
                  type="number"
                  min="1"
                  max="1000"
                  value={config.max_iterations || 100}
                  onChange={(e) => onChange({ max_iterations: parseInt(e.target.value, 10) || 100 })}
                  placeholder="100"
                />
              </label>
            </div>
            <div className="config-note">
              Access current item via <code>$.variables.{config.loop_variable || 'item'}</code>
              and index via <code>$.variables.{config.loop_variable || 'item'}_index</code>
            </div>
          </>
        );
      case 'delay':
        return (
          <>
            <div className="config-group">
              <div className="config-group-title">Timing</div>
              <label>
                Delay Type
                <select
                  value={config.delay_type || 'short'}
                  onChange={(e) => onChange({ delay_type: e.target.value })}
                >
                  <option value="short">Short Delay</option>
                  <option value="long">Long Delay (Resumable)</option>
                </select>
              </label>
              <label>
                Duration (seconds)
                <input
                  value={config.duration_seconds || ''}
                  onChange={(e) => onChange({ duration_seconds: e.target.value })}
                  placeholder="60"
                />
              </label>
              {config.delay_type === 'long' && (
                <label>
                  Resume At (ISO timestamp)
                  <input
                    value={config.resume_at || ''}
                    onChange={(e) => onChange({ resume_at: e.target.value })}
                    placeholder="2026-02-05T12:00:00Z"
                  />
                </label>
              )}
            </div>
          </>
        );
      case 'approval':
        return (
          <>
            <div className="config-group">
              <div className="config-group-title">Request</div>
              <label>
                Message
                <input value={config.message || ''} onChange={(e) => onChange({ message: e.target.value })} placeholder="Approval required for containment action" />
              </label>
              <label>
                Assign To
                <input value={config.assign_to || ''} onChange={(e) => onChange({ assign_to: e.target.value })} placeholder="secops, soc-lead" />
              </label>
            </div>
            <div className="config-group">
              <div className="config-group-title">Timeout Behavior</div>
              <label>
                Timeout (minutes)
                <input
                  type="number"
                  min="1"
                  max="1440"
                  value={config.timeout_minutes || ''}
                  onChange={(e) => onChange({ timeout_minutes: e.target.value })}
                  placeholder="60"
                />
              </label>
              <label>
                On Timeout
                <select value={config.auto_decision || 'none'} onChange={(e) => onChange({ auto_decision: e.target.value })}>
                  <option value="none">Wait indefinitely</option>
                  <option value="approve">Auto-approve</option>
                  <option value="deny">Auto-deny</option>
                </select>
              </label>
            </div>
            <div className="config-group">
              <div className="config-group-title">Escalation</div>
              <label>
                Escalation Target
                <input value={config.escalation || ''} onChange={(e) => onChange({ escalation: e.target.value })} placeholder="on-call, manager" />
              </label>
            </div>
          </>
        );
      case 'subflow':
        return (
          <>
            <label>
              Playbook Name
              <input value={config.playbook_name || ''} onChange={(e) => onChange({ playbook_name: e.target.value })} placeholder="case_closure" />
            </label>
          </>
        );
      case 'utility':
        return (
          <>
            <label>
              Operation
              <select
                value={config.operation || ''}
                onChange={(e) => onChange({ operation: e.target.value })}
              >
                <option value="">Select operation...</option>
                <option value="case_update">Close / Update Case</option>
                <option value="update_status">Update Status</option>
                <option value="update_severity">Update Severity</option>
                <option value="set_sla">Set SLA</option>
                <option value="add_note">Add Note</option>
                <option value="update_owner">Update Owner</option>
                <option value="add_tag">Add Tag</option>
                <option value="remove_tag">Remove Tag</option>
                <option value="edl_add">EDL Add Entry</option>
                <option value="edl_remove">EDL Remove Entry</option>
              </select>
            </label>
            {config.operation === 'case_update' && (
              <>
                <label>
                  Status
                  <select
                    value={config.status || ''}
                    onChange={(e) => onChange({ status: e.target.value })}
                  >
                    <option value="">Leave unchanged</option>
                    <option value="in_progress">In Progress</option>
                    <option value="resolved">Resolved</option>
                    <option value="closed">Closed</option>
                  </select>
                </label>
                <label>
                  Disposition
                  <select
                    value={config.disposition || ''}
                    onChange={(e) => onChange({ disposition: e.target.value })}
                  >
                    <option value="">Leave unchanged</option>
                    <option value="true_positive">True Positive</option>
                    <option value="false_positive">False Positive</option>
                    <option value="benign">Benign</option>
                    <option value="inconclusive">Inconclusive</option>
                  </select>
                </label>
                <label>
                  Severity
                  <select
                    value={config.severity || ''}
                    onChange={(e) => onChange({ severity: e.target.value })}
                  >
                    <option value="">Leave unchanged</option>
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                  </select>
                </label>
                <label>
                  Resolution
                  <input
                    type="text"
                    value={config.resolution || ''}
                    onChange={(e) => onChange({ resolution: e.target.value })}
                    placeholder="One-line summary of how the case was resolved"
                  />
                </label>
              </>
            )}
            {config.operation === 'update_status' && (
              <label>
                Status
                <select
                  value={config.status || ''}
                  onChange={(e) => onChange({ status: e.target.value })}
                >
                  <option value="">Select status...</option>
                  <option value="new">New</option>
                  <option value="in_progress">In Progress</option>
                  <option value="resolved">Resolved</option>
                  <option value="closed">Closed</option>
                  <option value="escalated">Escalated</option>
                </select>
              </label>
            )}
            {config.operation === 'update_severity' && (
              <label>
                Severity
                <select
                  value={config.severity || ''}
                  onChange={(e) => onChange({ severity: e.target.value })}
                >
                  <option value="">Select severity...</option>
                  <option value="critical">Critical</option>
                  <option value="high">High</option>
                  <option value="medium">Medium</option>
                  <option value="low">Low</option>
                  <option value="info">Informational</option>
                </select>
              </label>
            )}
            {config.operation === 'set_sla' && (
              <>
                <label>
                  SLA Minutes
                  <input
                    type="number"
                    value={config.sla_minutes || ''}
                    onChange={(e) => onChange({ sla_minutes: parseInt(e.target.value) || '' })}
                    placeholder="60"
                  />
                </label>
              </>
            )}
            {config.operation === 'add_note' && (
              <label>
                Note
                <textarea
                  value={config.note || ''}
                  onChange={(e) => onChange({ note: e.target.value })}
                  placeholder="Enter note text..."
                  rows={3}
                />
              </label>
            )}
            {config.operation === 'update_owner' && (
              <label>
                Owner
                <input
                  value={config.owner || ''}
                  onChange={(e) => onChange({ owner: e.target.value })}
                  placeholder="user@example.com"
                />
              </label>
            )}
            {(config.operation === 'add_tag' || config.operation === 'remove_tag') && (
              <label>
                Tag
                <input
                  value={config.tag || ''}
                  onChange={(e) => onChange({ tag: e.target.value })}
                  placeholder="malware"
                />
              </label>
            )}
            {(config.operation === 'edl_add' || config.operation === 'edl_remove') && (
              <>
                <label>
                  EDL Name
                  <input
                    value={config.edl_name || ''}
                    onChange={(e) => onChange({ edl_name: e.target.value })}
                    placeholder="blocked_ips"
                  />
                </label>
                {renderPathInput('Value', 'edl_value', '$.trigger.alert.src_ip')}
              </>
            )}
          </>
        );
      case 'analyze': {
        const analyzeMode = config.mode || 'ai_analysis';
        return (
          <>
            <label>
              Analysis Mode
              <select
                value={analyzeMode}
                onChange={(e) => {
                  const m = e.target.value;
                  if (m === 'enrich') {
                    onChange({ ...defaultConfig('analyze'), mode: 'enrich' });
                  } else {
                    onChange({ ...defaultConfig('analyze'), mode: 'ai_analysis' });
                  }
                }}
              >
                <option value="ai_analysis">AI Analysis</option>
                <option value="enrich">IOC Enrichment</option>
              </select>
            </label>

            {analyzeMode === 'ai_analysis' && (
              <>
                <label>
                  Analysis Template
                  <select
                    value={config.template_id || 'phishing_triage'}
                    onChange={(e) => onChange({ template_id: e.target.value })}
                  >
                    {[
                      { cat: 'Email', items: [{ id: 'phishing_triage', name: 'Phishing Email Triage' }] },
                      { cat: 'Endpoint', items: [
                        { id: 'malware_assessment', name: 'Malware Alert Assessment' },
                        { id: 'priv_escalation', name: 'Privilege Escalation Assessment' },
                        { id: 'ransomware_check', name: 'Ransomware Indicator Check' },
                      ]},
                      { cat: 'Identity', items: [
                        { id: 'brute_force', name: 'Brute Force Analysis' },
                        { id: 'credential_access', name: 'Credential Access Analysis' },
                        { id: 'insider_threat', name: 'Insider Threat Evaluation' },
                        { id: 'suspicious_login', name: 'Suspicious Login Investigation' },
                      ]},
                      { cat: 'Network', items: [
                        { id: 'lateral_movement', name: 'Lateral Movement Detection' },
                        { id: 'c2_detection', name: 'C2 Communication Check' },
                      ]},
                      { cat: 'Data', items: [{ id: 'data_exfil', name: 'Data Exfiltration Review' }] },
                      { cat: 'Cloud', items: [{ id: 'cloud_security', name: 'Cloud Security Posture' }] },
                      { cat: 'Vuln Mgmt', items: [{ id: 'vuln_risk', name: 'Vulnerability Risk Assessment' }] },
                      { cat: 'Threat Intel', items: [{ id: 'ioc_correlation', name: 'IOC Threat Correlation' }] },
                      { cat: 'Reporting', items: [{ id: 'executive_summary', name: 'Executive Summary' }] },
                    ].map((group) => (
                      <optgroup key={group.cat} label={group.cat}>
                        {group.items.map((t) => (
                          <option key={t.id} value={t.id}>{t.name}</option>
                        ))}
                      </optgroup>
                    ))}
                  </select>
                  <span className="field-hint">
                    {{
                      phishing_triage: 'Analyze email headers, sender reputation, URLs, and attachment indicators',
                      malware_assessment: 'Evaluate file hashes, process behavior, and execution chains',
                      brute_force: 'Assess credential brute force or password spray attempts',
                      lateral_movement: 'Detect east-west movement via PsExec, WMI, RDP, SMB',
                      c2_detection: 'Identify C2 traffic patterns, beaconing, DNS tunneling',
                      data_exfil: 'Detect unauthorized data transfers and exfiltration',
                      priv_escalation: 'Assess privilege escalation via UAC bypass, token manipulation',
                      credential_access: 'Analyze LSASS dumps, Kerberoasting, credential theft',
                      ransomware_check: 'Assess encryption behavior, shadow copy deletion, ransom artifacts',
                      insider_threat: 'Evaluate abnormal access patterns and policy violations',
                      cloud_security: 'Assess cloud misconfigurations, exposed resources, IAM anomalies',
                      vuln_risk: 'Evaluate vulnerability exploitability and remediation priority',
                      ioc_correlation: 'Correlate IOCs against threat intel feeds and campaigns',
                      suspicious_login: 'Investigate impossible travel, new device, unusual location',
                      executive_summary: 'Generate management-level incident summary',
                    }[config.template_id || 'phishing_triage']}
                  </span>
                </label>
                <label>
                  Additional Instructions
                  <textarea
                    value={config.custom_instructions || ''}
                    onChange={(e) => {
                      const val = e.target.value.slice(0, 500);
                      onChange({ custom_instructions: val });
                    }}
                    placeholder="Optional: add context specific to your environment..."
                    rows={3}
                    maxLength={500}
                  />
                  <span className="field-hint">
                    Supplement the template with environment-specific details ({(config.custom_instructions || '').length}/500)
                  </span>
                </label>
                {renderPathInput('Alert Data Path', 'alert_path', '$.trigger.alert')}
                <span className="field-hint">Path to the alert data to analyze</span>
                <label className="toggle-label">
                  <input
                    type="checkbox"
                    checked={config.include_context !== false}
                    onChange={(e) => onChange({ include_context: e.target.checked })}
                  />
                  <span>Include full alert context</span>
                </label>
              </>
            )}

            {analyzeMode === 'enrich' && (
              <>
                <label>
                  Observable Type
                  <select
                    value={config.observable_type || 'ip'}
                    onChange={(e) => onChange({ observable_type: e.target.value })}
                  >
                    <option value="ip">IP Address</option>
                    <option value="domain">Domain</option>
                    <option value="hash">File Hash</option>
                    <option value="url">URL</option>
                    <option value="email">Email Address</option>
                  </select>
                </label>
                {renderPathInput('Observable Value', 'observable_path', '$.trigger.alert.src_ip')}
                <span className="field-hint">Data path to the value to enrich</span>
                <div className="config-group">
                  <div className="config-group-title">Enrichment Sources</div>
                  <div className="checkbox-grid">
                    {[
                      { id: 'virustotal', label: 'VirusTotal' },
                      { id: 'abuseipdb', label: 'AbuseIPDB' },
                      { id: 'shodan', label: 'Shodan' },
                      { id: 'greynoise', label: 'GreyNoise' },
                      { id: 'crowdstrike', label: 'CrowdStrike' },
                    ].map((source) => (
                      <label key={source.id} className="checkbox-label">
                        <input
                          type="checkbox"
                          checked={(config.sources || ['virustotal']).includes(source.id)}
                          onChange={(e) => {
                            const current = config.sources || ['virustotal'];
                            const next = e.target.checked
                              ? [...current, source.id]
                              : current.filter((s) => s !== source.id);
                            onChange({ sources: next });
                          }}
                        />
                        <span>{source.label}</span>
                      </label>
                    ))}
                  </div>
                </div>
                <label className="toggle-label">
                  <input
                    type="checkbox"
                    checked={config.aggregate_results !== false}
                    onChange={(e) => onChange({ aggregate_results: e.target.checked })}
                  />
                  <span>Aggregate results with verdict</span>
                </label>
              </>
            )}
          </>
        );
      }
      case 'ai_agent': {
        const responseFormat = config.response_format || 'text';
        return (
          <>
            <label>
              System Prompt
              <textarea
                value={config.system_prompt || ''}
                onChange={(e) => onChange({ system_prompt: e.target.value })}
                placeholder="You are a security analyst assistant. Analyze the provided data and return a structured assessment."
                rows={4}
              />
              <span className="field-hint">
                Instructions that define the AI's role and behavior for this step.
              </span>
            </label>
            <label>
              User Prompt
              <textarea
                value={config.user_prompt || ''}
                onChange={(e) => onChange({ user_prompt: e.target.value })}
                placeholder="Analyze this alert: {{$.trigger.alert.title}}&#10;&#10;Details: {{$.trigger.alert.description}}"
                rows={5}
              />
              <span className="field-hint">
                Use <code>{'{{$.path.to.value}}'}</code> to reference context data (e.g., <code>{'{{$.trigger.alert.title}}'}</code>).
              </span>
            </label>
            <label>
              Model
              <select
                value={config.model || 'claude-sonnet-4-5-20250929'}
                onChange={(e) => onChange({ model: e.target.value })}
              >
                <option value="claude-haiku-4-5-20251001">Claude Haiku — Fast, lightweight tasks</option>
                <option value="claude-sonnet-4-5-20250929">Claude Sonnet — Balanced (recommended)</option>
                <option value="claude-opus-4-6">Claude Opus — Deep reasoning, complex analysis</option>
              </select>
            </label>
            <label>
              Max Tokens
              <input
                type="number"
                min={100}
                max={8000}
                value={config.max_tokens || 1000}
                onChange={(e) => onChange({ max_tokens: parseInt(e.target.value, 10) || 1000 })}
              />
              <span className="field-hint">Maximum tokens in the response (100–8000).</span>
            </label>
            <label>
              Output Key
              <input
                value={config.output_key || ''}
                onChange={(e) => onChange({ output_key: e.target.value })}
                placeholder={nodeId || 'ai_agent_result'}
              />
              <span className="field-hint">
                Context key to store the result under. Reference it downstream as <code>{'{{$.'}{config.output_key || nodeId || 'ai_agent_result'}{'}}'}}</code>.
              </span>
            </label>
            <label>
              Response Format
              <select
                value={responseFormat}
                onChange={(e) => onChange({ response_format: e.target.value })}
              >
                <option value="text">Plain text</option>
                <option value="json">JSON (auto-parsed)</option>
              </select>
              <span className="field-hint">
                {responseFormat === 'json'
                  ? 'The model will be instructed to return valid JSON. Outputs will be parsed automatically.'
                  : 'Raw text response stored as-is.'}
              </span>
            </label>
            {responseFormat === 'json' && (
              <label>
                JSON Schema (optional)
                <textarea
                  value={config.json_schema || ''}
                  onChange={(e) => onChange({ json_schema: e.target.value })}
                  placeholder={'{\n  "verdict": "string",\n  "confidence": "number",\n  "summary": "string"\n}'}
                  rows={4}
                />
                <span className="field-hint">
                  Optional JSON schema describing the expected output shape. Included in the system prompt.
                </span>
              </label>
            )}
          </>
        );
      }
      case 'end':
        return (
          <>
            <label>
              Disposition
              <input value={config.disposition || ''} onChange={(e) => onChange({ disposition: e.target.value })} placeholder="completed" />
            </label>
          </>
        );
      default:
        return (
          <div className="config-note warning">
            Legacy block mapped to a canonical block. Please review configuration to ensure it behaves as expected.
          </div>
        );
    }
}

function configSummary(kind, config) {
  if (!config) return [];
  switch (kind) {
    case 'trigger':
      return [
        `Type: ${config.trigger_type || 'alert'}`,
        config.alert_filter ? `Filter: ${config.alert_filter}` : null,
        config.schedule_cron ? `Cron: ${config.schedule_cron}` : null,
      ].filter(Boolean);
    case 'decision': {
      const group = config.conditions || parseDecisionExpression(config.expression || '');
      const count = (group?.conditions || []).length + (group?.groups || []).length;
      return [count ? `Rules: ${count}` : 'Rules: (unset)'];
    }
    case 'loop':
      return [
        config.items_path ? `Items: ${config.items_path}` : 'Items: (unset)',
        `Var: ${config.loop_variable || 'item'}`
      ].filter(Boolean);
    case 'approval':
      return [
        config.message ? `Prompt: ${config.message}` : 'Prompt: (unset)',
        config.timeout_minutes ? `Timeout: ${config.timeout_minutes}m` : null,
      ].filter(Boolean);
    case 'analyze': {
      const mode = config.mode || 'ai_analysis';
      if (mode === 'enrich') {
        return [
          `Mode: Enrich`,
          `Type: ${config.observable_type || 'ip'}`,
          `Sources: ${(config.sources || ['virustotal']).join(', ')}`,
        ];
      }
      const templateNames = {
        phishing_triage: 'Phishing Triage', malware_assessment: 'Malware Assessment',
        brute_force: 'Brute Force', lateral_movement: 'Lateral Movement',
        c2_detection: 'C2 Detection', data_exfil: 'Data Exfil',
        priv_escalation: 'Priv Escalation', credential_access: 'Credential Access',
        ransomware_check: 'Ransomware Check', insider_threat: 'Insider Threat',
        cloud_security: 'Cloud Security', vuln_risk: 'Vuln Risk',
        ioc_correlation: 'IOC Correlation', suspicious_login: 'Suspicious Login',
        executive_summary: 'Executive Summary',
      };
      const tid = config.template_id || config.focus || 'phishing_triage';
      return [
        `Mode: AI Analysis`,
        `Template: ${templateNames[tid] || tid}`,
        config.custom_instructions ? `Notes: ${config.custom_instructions.slice(0, 25)}...` : null,
      ].filter(Boolean);
    }
    case 'ai_agent':
      return [
        config.model ? `Model: ${config.model.replace('claude-', '').replace(/-20\d{6}$/, '')}` : 'Model: sonnet',
        config.output_key ? `Output: ${config.output_key}` : null,
        config.response_format === 'json' ? 'Format: JSON' : null,
      ].filter(Boolean);
    case 'respond': {
      const rt = config.response_type || 'integration_action';
      if (rt === 'notify') {
        return [
          `Type: Notify`,
          `Channel: ${config.channel || 'slack'}`,
          config.slack_channel ? `To: ${config.slack_channel}` : null,
          config.email_recipients ? `To: ${config.email_recipients}` : null,
        ].filter(Boolean);
      }
      if (rt === 'create_ticket') {
        return [
          `Type: Create Ticket`,
          `System: ${config.system || 'jira'}`,
          config.project_key ? `Project: ${config.project_key}` : null,
          config.title ? `Title: ${config.title.slice(0, 30)}...` : null,
        ].filter(Boolean);
      }
      const integrationLabel = config.integration_instance_id
        ? `Integration: ${config.integration_instance_id}`
        : 'Integration: (unset)';
      return [
        `Type: Action`,
        integrationLabel,
        config.endpoint_id || config.action_type ? `Action: ${config.endpoint_id || config.action_type}` : 'Action: (unset)',
        config.target_path ? `Target: ${config.target_path}` : null,
      ].filter(Boolean);
    }
    case 'code': {
      const mode = config.mode || config.transform_type || 'extract';
      if (mode === 'script') {
        const script = config.script || {};
        const count = normalizeInputsEntries(script.inputs || []).filter((entry) => entry.key).length;
        return [
          `Mode: Script`,
          `Function: ${script.function_name || 'main'}`,
          count ? `Inputs: ${count}` : 'Inputs: none',
        ];
      }
      if (mode === 'assign') {
        return [
          `Mode: Assign`,
          config.assign?.name ? `Var: ${config.assign.name}` : 'Var: (unset)',
        ];
      }
      return [
        `Mode: ${mode}`,
        config.input_path ? `Input: ${config.input_path}` : 'Input: (unset)',
      ];
    }
    case 'subflow':
      return [`Playbook: ${config.playbook_name || 'unnamed'}`];
    case 'utility': {
      const opLabels = {
        case_update: 'Close / Update Case',
        update_status: 'Update Status',
        update_severity: 'Update Severity',
        set_sla: 'Set SLA',
        add_note: 'Add Note',
        update_owner: 'Update Owner',
        add_tag: 'Add Tag',
        remove_tag: 'Remove Tag',
        edl_add: 'EDL Add',
        edl_remove: 'EDL Remove',
      };
      const op = opLabels[config.operation] || config.operation || '(unset)';
      const details = [];
      if (config.status) details.push(`Status: ${config.status}`);
      if (config.disposition) details.push(`Disposition: ${config.disposition}`);
      if (config.severity) details.push(`Severity: ${config.severity}`);
      if (config.sla_minutes) details.push(`SLA: ${config.sla_minutes}m`);
      if (config.owner) details.push(`Owner: ${config.owner}`);
      if (config.tag) details.push(`Tag: ${config.tag}`);
      if (config.edl_name) details.push(`EDL: ${config.edl_name}`);
      return [`Op: ${op}`, ...details];
    }
    case 'delay':
      return [`Delay: ${config.duration_seconds || 60}s`];
    case 'end':
      return [`Disposition: ${config.disposition || 'completed'}`];
    default:
      return [];
  }
}

function baseNode(kind, title, summary, config) {
  return {
    kind,
    title,
    summary,
    config: config || defaultConfig(kind),
  };
}

function defaultConfig(kind) {
  switch (kind) {
    case 'trigger':
      return {
        trigger_type: 'alert',
        alert_filter: '',
        webhook_secret: '',
        schedule_cron: '',
        manual_label: '',
      };
    case 'decision':
      return decisionConfigFromExpression('');
    case 'loop':
      return { items_path: '', loop_variable: 'item', max_iterations: 100 };
    case 'delay':
      return { delay_type: 'short', duration_seconds: '60', resume_at: '' };
    case 'approval':
      return {
        message: 'Approval required',
        assign_to: 'team',
        timeout_minutes: '60',
        auto_decision: 'none',
        escalation: '',
      };
    case 'analyze':
      return {
        mode: 'ai_analysis',
        template_id: 'phishing_triage',
        custom_instructions: '',
        alert_path: '$.trigger.alert',
        include_context: true,
        observable_type: 'ip',
        observable_path: '$.trigger.alert.src_ip',
        sources: ['virustotal'],
        aggregate_results: true,
      };
    case 'ai_agent':
      return {
        system_prompt: '',
        user_prompt: '',
        model: 'claude-sonnet-4-5-20250929',
        max_tokens: 1000,
        output_key: '',
        response_format: 'text',
        json_schema: '',
      };
    case 'respond':
      return {
        response_type: 'integration_action',
        integration_instance_id: '',
        endpoint_id: '',
        action_type: '',
        params: {},
        target_path: '',
        requires_approval: false,
        priority: 'medium',
        channel: 'slack',
        slack_channel: '',
        teams_webhook: '',
        email_recipients: '',
        email_subject: '',
        webhook_url: '',
        message: '',
        system: 'jira',
        project_key: '',
        issue_type: 'Task',
        table: 'incident',
        title: '',
        description: '',
      };
    case 'subflow':
      return { playbook_name: '', playbook_id: '' };
    case 'utility':
      return {
        operation: '',
        status: '',
        severity: '',
        sla_minutes: '',
        note: '',
        owner: '',
        tag: '',
        edl_name: '',
        edl_value: '',
      };
    case 'code':
      return {
        mode: 'extract',
        input_path: '',
        transform_type: 'extract',
        transform_config: {
          output_path: '',
          filter_path: '',
          filter_value: '',
          map_path: '',
        },
        assign: { name: '', value_path: '', static_value: '' },
        script: { function_name: 'main', inputs: [], code: '' },
        note: '',
      };
    case 'end':
      return { disposition: 'completed', summary: '' };
    default:
      return {};
  }
}

function defaultTriggerConditions() {
  return {
    on_alert_created: true,
    on_investigation_created: false,
    on_alert_closed: false,
    on_investigation_closed: false,
    on_webhook: false,
    on_schedule: false,
    webhook: { path: '', secret: '' },
    schedule: { cron: '0 * * * *', timezone: 'UTC' },
    alert_tags: [],
    investigation_tags: [],
  };
}

function toEngineCanvas(nodes, edges) {
  const nodeById = new Map(nodes.map((node) => [node.id, node]));
  const serializedNodes = nodes.map((node) => toEngineNode(node));
  const serializedEdges = edges.map((edge) => toEngineEdge(edge, nodeById));
  return { nodes: serializedNodes, edges: serializedEdges };
}

function toEngineNode(node) {
  const rawKind = node?.data?.kind || node?.data?.type || node?.type || 'action';
  const kind = normalizeKindForEngine(rawKind, node?.data?.config || {});
  const config = normalizeConfigForSave(kind, node?.data?.config || {});
  return {
    id: node.id,
    type: kind,
    position: node.position,
    data: {
      label: node.data?.title || node.data?.label || 'Untitled',
      description: node.data?.summary || '',
      kind: kind,
      config,
    },
  };
}

function toEngineEdge(edge, nodeById) {
  // The execution engine's condition handler outputs branch="yes"|"no"
  // and matches it against edge.sourceHandle directly. Older versions
  // of this function rewrote yes->true / no->false on save and inverted
  // it on load -- that drift meant condition nodes evaluated, picked a
  // branch, then no outgoing edge matched and execution silently halted
  // at the condition. We now persist whatever sourceHandle was used.
  const { data, ...edgeRest } = edge;
  // Preserve label at top-level so React Flow renders it on the line.
  const label = edge.label || edge.data?.label;
  return {
    ...edgeRest,
    sourceHandle: edge.sourceHandle,
    animated: true,
    type: 'smoothstep',
    ...(label ? { label } : {}),
  };
}

  function toStudioNode(node, isEnabled) {
    const rawKind = node?.data?.kind || node?.data?.type || node?.type || 'action';
    const kind = normalizeKindForStudio(rawKind, node?.data?.config || {});
    const config = normalizeConfigFromEngine(rawKind, kind, node?.data?.config || {});
    return {
      ...node,
      type: 'signal',
    data: {
      kind,
      title: node.data?.label || node.data?.title || 'Untitled',
      summary: node.data?.summary || node.data?.description || '',
      config,
    },
  };
}

function toStudioEdges(edges, nodes) {
  const nodeById = new Map(nodes.map((node) => [node.id, node]));
  return edges.map((edge) => {
    // Back-compat: older playbooks saved with the legacy true/false
    // handle convention; new playbooks use yes/no consistently. Translate
    // on load so existing rows keep working.
    let sourceHandle = edge.sourceHandle;
    if (sourceHandle === 'true') sourceHandle = 'yes';
    if (sourceHandle === 'false') sourceHandle = 'no';

    // Look up the condition node's branch labels so we display the analyst's
    // chosen label (Malicious / Benign / etc.) on the canvas edge, not the
    // generic Yes/No.
    const sourceNode = nodeById.get(edge.source);
    const branches = sourceNode?.data?.config?.branches || [];
    const matchedBranch = branches.find((b) => b.id === sourceHandle);
    const label =
      edge.label
      || edge.data?.label
      || matchedBranch?.label
      || (sourceHandle === 'yes' ? 'Yes' : sourceHandle === 'no' ? 'No' : '');

    return {
      ...edge,
      sourceHandle,
      animated: true,
      type: 'deletable',
      label,
      // React Flow's edge component reads label from the top level, but
      // some custom edge renderers look at data.label. Mirror it.
      data: { ...(edge.data || {}), label },
    };
  });
}

function normalizeKindForEngine(kind, config) {
  const canonicalKind = CANONICAL_KINDS.has(kind) ? kind : (LEGACY_KIND_MAP[kind] || kind);
  if (canonicalKind === 'decision') return 'condition';
  if (canonicalKind === 'approval') return 'approval_gate';
  if (canonicalKind === 'analyze') {
    return config?.mode === 'enrich' ? 'enrich' : 'riggs_analyze';
  }
  if (canonicalKind === 'respond') {
    const rt = config?.response_type;
    if (rt === 'notify') return 'notify';
    if (rt === 'create_ticket') return 'create_ticket';
    return 'action';
  }
  if (canonicalKind === 'code') {
    const mode = config?.mode || config?.transform_type || 'extract';
    if (mode === 'assign') return 'variable_set';
    if (mode === 'script') return 'python_code';
    if (mode === 'note') return 'note';
    return 'code';
  }
  return canonicalKind;
}

function normalizeKindForStudio(kind, config) {
  if (CANONICAL_KINDS.has(kind)) return kind;
  const mapped = LEGACY_KIND_MAP[kind];
  return mapped || 'respond';
}

function normalizeConfigForSave(kind, config) {
  let normalized = { ...config };
  delete normalized._migration;

  if (kind === 'condition') {
    const decisionConfig = normalizeDecisionConfig(config);
    const expression = compileDecisionGroup(decisionConfig.conditions);
    normalized.expression = expression || decisionConfig.expression || '';
    normalized.default_branch = decisionConfig.default_branch || 'no';
  }

  if (kind === 'action') {
    normalized.integration_instance_id = config.integration_instance_id || config.integration || '';
    normalized.endpoint_id = config.endpoint_id || config.action_type || '';
    normalized.action_type = config.action_type || normalized.endpoint_id || '';
    normalized.params = config.params || {};
  }

  if (kind === 'variable_set') {
    const assign = config.assign || {};
    normalized = {
      name: assign.name || config.name || '',
      value_path: assign.value_path || config.value_path || '',
      static_value: assign.static_value || config.static_value || '',
    };
  }

  if (kind === 'python_code') {
    const script = config.script || config;
    normalized = {
      function_name: script.function_name || config.function_name || 'main',
      inputs: entriesToInputObject(normalizeInputsEntries(script.inputs || config.inputs)),
      code: script.code || config.code || '',
    };
  }

  if (kind === 'code') {
    normalized.input_path = config.input_path || '';
    normalized.transform_type = config.transform_type || config.mode || 'extract';
    normalized.transform_config = config.transform_config || {};
  }

  if (kind === 'delay') {
    normalized.duration_seconds = config.duration_seconds || config.duration || '60';
  }

  if (kind === 'webhook_call') {
    normalized.headers = parseJsonMaybe(config.headers, {});
  }
  if (kind === 'webform') {
    normalized.fields = parseJsonMaybe(config.fields, []);
  }
  if (kind === 'user_input') {
    normalized.options = parseListMaybe(config.options);
  }
  if (kind === 'file_upload') {
    normalized.allowed_types = parseListMaybe(config.allowed_types, ['*/*']);
    normalized.max_size_mb = config.max_size_mb ? Number(config.max_size_mb) : 10;
  }
  if (kind === 'enrich') {
    normalized.integrations = parseListMaybe(config.integrations, ['virustotal']);
  }
  if (kind === 'list_lookup' || kind === 'list_update') {
    normalized.list_name = config.list_name || '';
  }
  return normalized;
}

// These kind aliases are simple renames with compatible config — normalize silently, no migration warning.
// Legacy block kinds where the rename is purely cosmetic -- the config
// shape is unchanged or the conversion is well-defined and lossless.
// These get mapped silently with no "review configuration" warning.
// Kinds where the conversion can lose configuration (riggs_analyze,
// enrich, python_code, webform, parallel, merge, etc.) intentionally
// remain warning-eligible.
const SILENT_KIND_RENAMES = new Set([
  // Pure name changes
  'condition',         // -> decision
  'approval_gate',     // -> approval
  // Variable-assignment blocks from imported playbooks (XSOAR / Splunk SOAR
  // emit `set_variable`, which the converter normalizes to `variable_set`).
  // Maps 1:1 to code/assign — name + value_path + static_value carry over
  // exactly, so there is nothing for the analyst to "review".
  'variable_set',
  // Respond-family aliases. All of these were separate node types in
  // older releases but are now subtypes of `respond`; the conversion
  // sets response_type and preserves the original config fields, so
  // there is nothing for the user to review.
  'action',
  'integration',
  'notify',
  'create_ticket',
  'http_request',
  'webhook_call',
  'list_lookup',
  'list_update',
  'edl_add',
  'edl_remove',
  'case_update',
]);

function normalizeConfigFromEngine(rawKind, canonicalKind, config) {
  let normalized = { ...config };
  const legacy = rawKind && rawKind !== canonicalKind && !SILENT_KIND_RENAMES.has(rawKind)
    ? { from: rawKind, kind: rawKind }
    : null;

  if (canonicalKind === 'decision') {
    normalized = normalizeDecisionConfig({ ...normalized, expression: config.expression || normalized.expression || '' });
  }

  if (canonicalKind === 'analyze') {
    if (rawKind === 'enrich') {
      normalized = {
        ...defaultConfig('analyze'),
        ...normalized,
        mode: 'enrich',
        observable_type: config.observable_type || 'ip',
        observable_path: config.observable_path || '$.trigger.alert.src_ip',
        sources: config.sources || ['virustotal'],
        aggregate_results: config.aggregate_results !== false,
      };
    } else {
      // riggs_analyze or new analyze node
      const focusToTemplate = {
        threat_assessment: 'phishing_triage',
        ioc_extraction: 'ioc_correlation',
        attack_chain: 'malware_assessment',
        recommendations: 'executive_summary',
        summary: 'executive_summary',
      };
      const templateId = config.template_id || focusToTemplate[config.focus] || 'phishing_triage';
      const customInstr = config.custom_instructions || '';
      normalized = {
        ...defaultConfig('analyze'),
        ...normalized,
        mode: config.mode || 'ai_analysis',
        template_id: templateId,
        custom_instructions: customInstr,
      };
    }
  }

  if (canonicalKind === 'respond') {
    if (rawKind === 'notify') {
      normalized = {
        ...defaultConfig('respond'),
        ...normalized,
        response_type: 'notify',
        channel: config.channel || 'slack',
        slack_channel: config.slack_channel || '',
        teams_webhook: config.teams_webhook || '',
        email_recipients: config.email_recipients || '',
        email_subject: config.email_subject || '',
        webhook_url: config.webhook_url || '',
        message: config.message || '',
      };
    } else if (rawKind === 'create_ticket') {
      normalized = {
        ...defaultConfig('respond'),
        ...normalized,
        response_type: 'create_ticket',
        system: config.system || 'jira',
        project_key: config.project_key || '',
        issue_type: config.issue_type || 'Task',
        table: config.table || 'incident',
        title: config.title || '',
        description: config.description || '',
        priority: config.priority || 'medium',
      };
    } else {
      // action, integration, webhook_call, legacy action types
      const base = defaultConfig('respond');
      const params = { ...(config.params || {}) };

      if (rawKind === 'webhook_call') {
        params.method = config.method || 'POST';
        params.url = config.url || '';
        params.headers = config.headers || '';
        params.body = config.body || '';
      }
      if (['edl_add', 'edl_remove', 'list_update', 'list_lookup', 'case_update'].includes(rawKind)) {
        params.legacy = { ...config };
      }

      normalized = {
        ...base,
        ...normalized,
        response_type: 'integration_action',
        integration_instance_id: config.integration_instance_id || config.integration || '',
        endpoint_id: config.endpoint_id || config.action_type || '',
        action_type: config.action_type || config.endpoint_id || rawKind,
        target_path: config.target_path || config.value_path || '',
        requires_approval: config.requires_approval ?? base.requires_approval,
        priority: config.priority || base.priority,
        params,
      };
    }
  }

  if (canonicalKind === 'code') {
    if (rawKind === 'code') {
      normalized = {
        ...defaultConfig('code'),
        ...normalized,
        mode: config.transform_type || config.mode || 'extract',
        transform_type: config.transform_type || 'extract',
        transform_config: config.transform_config || {},
      };
    } else if (rawKind === 'variable_set') {
      normalized = {
        ...defaultConfig('code'),
        mode: 'assign',
        assign: {
          name: config.name || config.var_name || '',
          value_path: config.value_path || '',
          static_value: config.static_value || '',
        },
      };
    } else if (rawKind === 'python_code' || rawKind === 'function_call') {
      normalized = {
        ...defaultConfig('code'),
        mode: 'script',
        script: {
          function_name: config.function_name || 'main',
          inputs: normalizeInputsEntries(config.inputs),
          code: config.code || '',
        },
      };
    } else if (rawKind === 'note') {
      normalized = {
        ...defaultConfig('code'),
        mode: 'note',
        note: config.note || '',
      };
    } else {
      normalized = {
        ...defaultConfig('code'),
        mode: 'assign',
        assign: { name: '', value_path: '', static_value: '' },
      };
    }
  }

  if (canonicalKind === 'approval') {
    normalized = {
      ...defaultConfig('approval'),
      ...normalized,
    };
  }

  if (canonicalKind === 'delay') {
    normalized = {
      ...defaultConfig('delay'),
      duration_seconds: config.duration_seconds?.toString?.() || config.duration || '60',
      delay_type: config.delay_type || 'short',
      resume_at: config.resume_at || '',
    };
  }

  if (canonicalKind === 'trigger') {
    normalized = {
      ...defaultConfig('trigger'),
      ...normalized,
    };
  }

  // Always start clean: drop any _migration stored from older saves so
  // we don't perpetually show "review configuration" on a kind that has
  // since been moved into SILENT_KIND_RENAMES.
  delete normalized._migration;
  if (legacy) {
    normalized._migration = {
      ...legacy,
      note: `Legacy ${rawKind} block mapped to ${canonicalKind}. Review configuration.`,
    };
  }

  return normalized;
}

function parseJsonMaybe(value, fallback) {
  if (value == null) return fallback;
  if (typeof value === 'object') return value;
  if (typeof value !== 'string' || value.trim() === '') return fallback;
  try {
    return JSON.parse(value);
  } catch (err) {
    return fallback;
  }
}

function parseListMaybe(value, fallback = []) {
  if (Array.isArray(value)) return value;
  if (typeof value === 'string') {
    const items = value.split(',').map((item) => item.trim()).filter(Boolean);
    return items.length ? items : fallback;
  }
  return fallback;
}

function listToString(value) {
  if (Array.isArray(value)) return value.join(', ');
  if (typeof value === 'string') return value;
  return '';
}

function stringifyJson(value) {
  if (value == null) return '';
  if (typeof value === 'string') return value;
  try {
    return JSON.stringify(value, null, 2);
  } catch (err) {
    return '';
  }
}

function nodeColor(kind = 'respond') {
  const canonical = CANONICAL_KINDS.has(kind) ? kind : (LEGACY_KIND_MAP[kind] || kind);
  const colors = {
    trigger: '#22c55e',
    analyze: '#a855f7',
    decision: '#0ea5e9',
    respond: '#3b82f6',
    code: '#8b5cf6',
    transform: '#22d3ee',
    loop: '#8b5cf6',
    delay: '#f59e0b',
    approval: '#f43f5e',
    subflow: '#a855f7',
    end: '#94a3b8',
    utility: '#06b6d4',
  };
  return colors[canonical] || '#94a3b8';
}

function capitalize(value) {
  if (!value) return '';
  return value.charAt(0).toUpperCase() + value.slice(1).replace(/_/g, ' ');
}

function formatKindLabel(kind) {
  const canonical = CANONICAL_KINDS.has(kind) ? kind : (LEGACY_KIND_MAP[kind] || kind);
  const labels = {
    trigger: 'Trigger',
    analyze: 'Analyze',
    decision: 'Decision',
    respond: 'Respond',
    code: 'Code',
    transform: 'Transform',
    loop: 'Loop',
    delay: 'Delay',
    approval: 'Approval',
    subflow: 'Subflow',
    end: 'End',
    utility: 'Utility',
  };
  return labels[canonical] || capitalize(kind);
}

export default WorkflowStudio;
