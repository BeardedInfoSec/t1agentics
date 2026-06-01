/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

/**
 * End Node Component
 */

import React from 'react';
import { Handle, Position } from 'reactflow';
import { Square } from 'lucide-react';

function EndNode({ data, selected }) {
  const disposition = data?.config?.disposition || 'completed';

  return (
    <div style={{ ...styles.node, ...(selected ? styles.selected : {}) }}>
      {/* Input handle only - end nodes don't have outputs */}
      <Handle
        type="target"
        position={Position.Top}
        id="input"
        style={styles.handle}
      />

      <div style={styles.header}>
        <Square size={14} style={{ color: '#64748b' }} />
        <span style={styles.label}>{data?.label || 'End'}</span>
      </div>
      <div style={styles.content}>
        <span style={styles.disposition}>{disposition}</span>
      </div>
    </div>
  );
}

const styles = {
  node: {
    minWidth: '140px',
    background: 'var(--bg-secondary, #1e293b)',
    border: '2px solid #64748b',
    borderRadius: '999px',
    overflow: 'hidden',
    position: 'relative',
  },
  selected: {
    boxShadow: '0 0 0 2px rgba(100, 116, 139, 0.4)',
  },
  header: {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
    padding: '10px 12px',
    background: 'rgba(100, 116, 139, 0.1)',
    borderBottom: '1px solid rgba(100, 116, 139, 0.2)',
  },
  label: {
    fontSize: '13px',
    fontWeight: '600',
    color: '#64748b',
  },
  content: {
    padding: '10px 12px',
    textAlign: 'center',
  },
  disposition: {
    fontSize: '11px',
    padding: '4px 8px',
    borderRadius: '4px',
    background: 'rgba(100, 116, 139, 0.2)',
    color: '#94a3b8',
    textTransform: 'capitalize',
  },
  handle: {
    width: '10px',
    height: '10px',
    background: '#64748b',
    border: '2px solid var(--bg-secondary, #1e293b)',
  },
  handleIn: {
    position: 'absolute',
    top: '-6px',
    left: '50%',
    transform: 'translateX(-50%)',
    width: '12px',
    height: '12px',
    borderRadius: '50%',
    background: '#64748b',
    border: '2px solid var(--bg-secondary, #1e293b)',
  },
};

export default EndNode;
