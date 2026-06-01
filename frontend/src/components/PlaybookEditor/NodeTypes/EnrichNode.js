/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

/**
 * Enrich Node Component
 */

import { Handle, Position } from 'reactflow';
import React from 'react';
import { Search } from 'lucide-react';

function EnrichNode({ data, selected }) {
  const integrations = data?.config?.integrations || [];

  return (
    <div style={{ ...styles.node, ...(selected ? styles.selected : {}) }}>
      <Handle type="target" position={Position.Top} id="input" style={styles.handle} />
      <div style={styles.header}>
        <Search size={14} style={{ color: '#3b82f6' }} />
        <span style={styles.label}>{data?.label || 'Enrich IOCs'}</span>
      </div>
      <div style={styles.content}>
        {integrations.length > 0 ? (
          <div style={styles.tags}>
            {integrations.map((int, idx) => (
              <span key={idx} style={styles.tag}>{int}</span>
            ))}
          </div>
        ) : (
          <span style={styles.placeholder}>Configure integrations</span>
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
    border: '2px solid #3b82f6',
    borderRadius: '12px 12px 20px 20px',
    overflow: 'hidden',
    position: 'relative',
  },
  selected: {
    boxShadow: '0 0 0 2px rgba(59, 130, 246, 0.4)',
  },
  header: {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
    padding: '10px 12px',
    background: 'rgba(59, 130, 246, 0.1)',
    borderBottom: '1px solid rgba(59, 130, 246, 0.2)',
  },
  label: {
    fontSize: '13px',
    fontWeight: '600',
    color: '#3b82f6',
  },
  content: {
    padding: '10px 12px',
  },
  tags: {
    display: 'flex',
    flexWrap: 'wrap',
    gap: '4px',
  },
  tag: {
    fontSize: '10px',
    padding: '2px 6px',
    borderRadius: '4px',
    background: 'rgba(59, 130, 246, 0.2)',
    color: '#3b82f6',
  },
  placeholder: {
    fontSize: '11px',
    color: 'var(--text-secondary, #94a3b8)',
  },
  handle: { width: '10px', height: '10px', border: '2px solid var(--bg-secondary, #1e293b)' },
};

export default EnrichNode;
