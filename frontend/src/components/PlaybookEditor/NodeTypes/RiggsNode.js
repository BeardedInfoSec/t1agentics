/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

/**
 * Riggs Analysis Node Component
 */

import { Handle, Position } from 'reactflow';
import React from 'react';
import { Bot } from 'lucide-react';

function RiggsNode({ data, selected }) {
  return (
    <div style={{ ...styles.node, ...(selected ? styles.selected : {}) }}>
      <Handle type="target" position={Position.Top} id="input" style={styles.handle} />
      <div style={styles.header}>
        <Bot size={14} style={{ color: '#8b5cf6' }} />
        <span style={styles.label}>{data?.label || 'Riggs Analysis'}</span>
      </div>
      <div style={styles.content}>
        <span style={styles.description}>AI-powered alert analysis</span>
      </div>
      <Handle type="source" position={Position.Bottom} id="output" style={styles.handle} />
    </div>
  );
}

const styles = {
  node: {
    minWidth: '180px',
    background: 'var(--bg-secondary, #1e293b)',
    border: '2px solid #8b5cf6',
    borderRadius: '18px 6px 18px 6px',
    overflow: 'hidden',
    position: 'relative',
  },
  selected: {
    boxShadow: '0 0 0 2px rgba(139, 92, 246, 0.4)',
  },
  header: {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
    padding: '10px 12px',
    background: 'rgba(139, 92, 246, 0.1)',
    borderBottom: '1px solid rgba(139, 92, 246, 0.2)',
  },
  label: {
    fontSize: '13px',
    fontWeight: '600',
    color: '#8b5cf6',
  },
  content: {
    padding: '10px 12px',
  },
  description: {
    fontSize: '11px',
    color: 'var(--text-secondary, #94a3b8)',
  },
  handle: { width: '10px', height: '10px', border: '2px solid var(--bg-secondary, #1e293b)' },
};

export default RiggsNode;
