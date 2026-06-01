/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

/**
 * Generic Node Component
 *
 * Used for node types that don't have a specific visual component.
 */

import React from 'react';
import { Handle, Position } from 'reactflow';
import {
  Clock, Bell, Ticket, Globe, Database, Variable,
  List, Upload, Repeat, GitMerge, Layers, Timer, Calendar
} from 'lucide-react';

// Map node types to icons and colors
const nodeConfig = {
  switch: { icon: Layers, color: '#3CB371', shape: 'hex' },
  loop: { icon: Repeat, color: '#3CB371', shape: 'hex' },
  parallel: { icon: GitMerge, color: '#3CB371', shape: 'angled' },
  merge: { icon: GitMerge, color: '#3CB371', shape: 'angled' },
  function_call: { icon: Variable, color: '#06b6d4', shape: 'cut' },
  transform: { icon: Database, color: '#06b6d4', shape: 'cut' },
  file_upload: { icon: Upload, color: '#ec4899', shape: 'document' },
  user_input: { icon: Variable, color: '#ec4899', shape: 'document' },
  list_lookup: { icon: List, color: '#14b8a6', shape: 'soft' },
  list_update: { icon: List, color: '#14b8a6', shape: 'soft' },
  edl_add: { icon: List, color: '#3b82f6', shape: 'tab' },
  edl_remove: { icon: List, color: '#ef4444', shape: 'tab' },
  variable_set: { icon: Variable, color: '#14b8a6', shape: 'slant' },
  variable_get: { icon: Variable, color: '#14b8a6', shape: 'slant' },
  notify: { icon: Bell, color: '#f97316', shape: 'tab' },
  create_ticket: { icon: Ticket, color: '#f97316', shape: 'tab' },
  webhook_call: { icon: Globe, color: '#f97316', shape: 'tab' },
  delay: { icon: Timer, color: '#64748b', shape: 'pill' },
  schedule: { icon: Calendar, color: '#64748b', shape: 'pill' },
};

const shapeStyles = {
  soft: { borderRadius: '12px' },
  pill: { borderRadius: '999px' },
  tab: { borderRadius: '18px 18px 6px 6px' },
  slant: { borderRadius: '6px 18px 6px 18px' },
  angled: { borderRadius: '16px 6px 16px 6px' },
  document: { borderRadius: '6px 6px 18px 18px' },
  hex: { borderRadius: '0', clipPath: 'polygon(8% 0, 92% 0, 100% 50%, 92% 100%, 8% 100%, 0 50%)' },
  cut: { borderRadius: '0', clipPath: 'polygon(4% 0, 96% 0, 100% 10%, 100% 90%, 96% 100%, 4% 100%, 0 90%, 0 10%)' },
};

function GenericNode({ data, selected }) {
  const nodeType = data?.type || 'unknown';
  const config = nodeConfig[nodeType] || { icon: Clock, color: '#64748b', shape: 'soft' };
  const IconComponent = config.icon;
  const shapeStyle = shapeStyles[config.shape] || shapeStyles.soft;

  return (
    <div
      style={{
        ...styles.node,
        ...shapeStyle,
        borderColor: config.color,
        ...(selected ? { boxShadow: `0 0 0 2px ${config.color}40` } : {}),
      }}
    >
      {/* Input handle for connections from previous nodes */}
      <Handle
        type="target"
        position={Position.Top}
        id="input"
        style={{ ...styles.handle, background: config.color }}
      />

      <div style={{ ...styles.header, background: `${config.color}15`, borderColor: `${config.color}30` }}>
        <IconComponent size={14} style={{ color: config.color }} />
        <span style={{ ...styles.label, color: config.color }}>
          {data?.label || nodeType.replace(/_/g, ' ')}
        </span>
      </div>
      <div style={styles.content}>
        <span style={styles.type}>{nodeType.replace(/_/g, ' ')}</span>
      </div>

      {/* Output handle for connecting to next nodes */}
      <Handle
        type="source"
        position={Position.Bottom}
        id="output"
        style={{ ...styles.handle, background: config.color }}
      />
    </div>
  );
}

const styles = {
  node: {
    minWidth: '160px',
    background: 'var(--bg-secondary, #1e293b)',
    border: '2px solid',
    borderRadius: '8px',
    overflow: 'hidden',
    position: 'relative',
  },
  header: {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
    padding: '10px 12px',
    borderBottom: '1px solid',
  },
  label: {
    fontSize: '13px',
    fontWeight: '600',
    textTransform: 'capitalize',
  },
  content: {
    padding: '10px 12px',
  },
  type: {
    fontSize: '11px',
    color: 'var(--text-secondary, #94a3b8)',
    textTransform: 'capitalize',
  },
  handle: {
    width: '10px',
    height: '10px',
    border: '2px solid var(--bg-secondary, #1e293b)',
  },
};

export default GenericNode;
