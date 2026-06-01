/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

/**
 * Condition Node Component
 */

import { Handle, Position } from 'reactflow';
import React from 'react';
import { GitBranch } from 'lucide-react';

function ConditionNode({ data, selected }) {
  const field = data?.config?.field || '';
  const operator = data?.config?.operator || 'equals';
  const value = data?.config?.value || '';

  return (
    <div style={{ ...styles.node, ...(selected ? styles.selected : {}) }}>
      <Handle type="target" position={Position.Top} id="input" style={styles.handle} />
      <div style={styles.header}>
        <GitBranch size={14} style={{ color: '#3CB371' }} />
        <span style={styles.label}>{data?.label || 'Condition'}</span>
      </div>
      <div style={styles.content}>
        {field ? (
          <div style={styles.condition}>
            <code style={styles.conditionText}>
              {field.replace('$.', '')} {operator} {value}
            </code>
          </div>
        ) : (
          <span style={styles.placeholder}>Configure condition</span>
        )}
      </div>
      <div style={styles.branches}>
        <div style={styles.branch}>
      <Handle type="source" position={Position.Bottom} id="true" style={styles.handle} />
          <span style={styles.branchLabel}>True</span>
        </div>
        <div style={styles.branch}>
      <Handle type="source" position={Position.Bottom} id="false" style={styles.handle} />
          <span style={styles.branchLabel}>False</span>
        </div>
      </div>
    </div>
  );
}

const styles = {
  node: {
    minWidth: '200px',
    background: 'var(--bg-secondary, #1e293b)',
    border: '2px solid #3CB371',
    borderRadius: '0',
    clipPath: 'polygon(8% 0, 92% 0, 100% 50%, 92% 100%, 8% 100%, 0 50%)',
    overflow: 'hidden',
    position: 'relative',
  },
  selected: {
    boxShadow: '0 0 0 2px rgba(60, 179, 113, 0.4)',
  },
  header: {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
    padding: '10px 12px',
    background: 'rgba(60, 179, 113, 0.1)',
    borderBottom: '1px solid rgba(60, 179, 113, 0.2)',
  },
  label: {
    fontSize: '13px',
    fontWeight: '600',
    color: '#3CB371',
  },
  content: {
    padding: '10px 12px',
  },
  condition: {
    padding: '6px 10px',
    borderRadius: '4px',
    background: 'rgba(0,0,0,0.2)',
  },
  conditionText: {
    fontSize: '11px',
    color: 'var(--text-primary, #f0f6fc)',
    wordBreak: 'break-all',
  },
  placeholder: {
    fontSize: '11px',
    color: 'var(--text-secondary, #94a3b8)',
  },
  branches: {
    display: 'flex',
    justifyContent: 'space-between',
    padding: '8px 16px 16px',
  },
  branch: {
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
    gap: '4px',
  },
  branchLabel: {
    fontSize: '10px',
    color: 'var(--text-secondary, #94a3b8)',
  },
  handle: { width: '10px', height: '10px', border: '2px solid var(--bg-secondary, #1e293b)' },
  handleOutLeft: {
    width: '12px',
    height: '12px',
    borderRadius: '50%',
    border: '2px solid var(--bg-secondary, #1e293b)',
  },
  handleOutRight: {
    width: '12px',
    height: '12px',
    borderRadius: '50%',
    border: '2px solid var(--bg-secondary, #1e293b)',
  },
};

export default ConditionNode;
