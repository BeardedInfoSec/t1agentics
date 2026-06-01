/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

/**
 * Action Node Component
 */

import { Handle, Position } from 'reactflow';
import React from 'react';
import { Shield, Lock } from 'lucide-react';

function ActionNode({ data, selected }) {
  const requiresApproval = data?.config?.requires_approval !== false;
  const actionType = data?.config?.action_type || '';
  const isApprovalGate = data?.type === 'approval_gate';
  const shapeStyle = isApprovalGate ? styles.approvalShape : styles.actionShape;

  return (
    <div style={{ ...styles.node, ...shapeStyle, ...(selected ? styles.selected : {}) }}>
      <Handle type="target" position={Position.Top} id="input" style={styles.handle} />
      <div style={styles.header}>
        <Shield size={14} style={{ color: '#ef4444' }} />
        <span style={styles.label}>{data?.label || 'Action'}</span>
        {requiresApproval && <Lock size={12} style={{ color: '#f59e0b', marginLeft: 'auto' }} />}
      </div>
      <div style={styles.content}>
        {actionType ? (
          <span style={styles.actionType}>{actionType.replace(/_/g, ' ')}</span>
        ) : (
          <span style={styles.placeholder}>Configure action</span>
        )}
        {requiresApproval && (
          <div style={styles.approvalBadge}>
            <Lock size={10} />
            <span>Requires Approval</span>
          </div>
        )}
      </div>
      <Handle type="source" position={Position.Bottom} id="output" style={styles.handle} />
    </div>
  );
}

const styles = {
  node: {
    minWidth: '180px',
    background: 'var(--bg-secondary, #1e293b)',
    border: '2px solid #ef4444',
    borderRadius: '8px',
    overflow: 'hidden',
    position: 'relative',
  },
  actionShape: {
    borderRadius: '6px 18px 6px 18px',
  },
  approvalShape: {
    borderRadius: '18px 18px 6px 6px',
    borderStyle: 'dashed',
  },
  selected: {
    boxShadow: '0 0 0 2px rgba(239, 68, 68, 0.4)',
  },
  header: {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
    padding: '10px 12px',
    background: 'rgba(239, 68, 68, 0.1)',
    borderBottom: '1px solid rgba(239, 68, 68, 0.2)',
  },
  label: {
    fontSize: '13px',
    fontWeight: '600',
    color: '#ef4444',
  },
  content: {
    padding: '10px 12px',
  },
  actionType: {
    fontSize: '12px',
    color: 'var(--text-primary, #f0f6fc)',
    textTransform: 'capitalize',
  },
  placeholder: {
    fontSize: '11px',
    color: 'var(--text-secondary, #94a3b8)',
  },
  approvalBadge: {
    display: 'flex',
    alignItems: 'center',
    gap: '4px',
    marginTop: '8px',
    padding: '4px 8px',
    borderRadius: '4px',
    background: 'rgba(245, 158, 11, 0.15)',
    color: '#f59e0b',
    fontSize: '10px',
  },
  handle: { width: '10px', height: '10px', border: '2px solid var(--bg-secondary, #1e293b)' },
};

export default ActionNode;
