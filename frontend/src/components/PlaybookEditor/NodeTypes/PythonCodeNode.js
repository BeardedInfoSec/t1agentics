/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

/**
 * Python Code Node Component
 */

import { Handle, Position } from 'reactflow';
import React from 'react';
import { Code } from 'lucide-react';

function PythonCodeNode({ data, selected }) {
  const hasCode = !!data?.config?.code;

  return (
    <div style={{ ...styles.node, ...(selected ? styles.selected : {}) }}>
      <Handle type="target" position={Position.Top} id="input" style={styles.handle} />
      <div style={styles.header}>
        <Code size={14} style={{ color: '#06b6d4' }} />
        <span style={styles.label}>{data?.label || 'Python Code'}</span>
      </div>
      <div style={styles.content}>
        {hasCode ? (
          <div style={styles.codePreview}>
            <code style={styles.codeText}>
              {data.config.code.split('\n').slice(0, 3).join('\n')}
              {data.config.code.split('\n').length > 3 && '...'}
            </code>
          </div>
        ) : (
          <span style={styles.placeholder}>Write Python code</span>
        )}
      </div>
      <Handle type="source" position={Position.Bottom} id="output" style={styles.handle} />
    </div>
  );
}

const styles = {
  node: {
    minWidth: '200px',
    background: 'var(--bg-secondary, #1e293b)',
    border: '2px solid #06b6d4',
    borderRadius: '0',
    clipPath: 'polygon(4% 0, 96% 0, 100% 8%, 100% 92%, 96% 100%, 4% 100%, 0 92%, 0 8%)',
    overflow: 'hidden',
    position: 'relative',
  },
  selected: {
    boxShadow: '0 0 0 2px rgba(6, 182, 212, 0.4)',
  },
  header: {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
    padding: '10px 12px',
    background: 'rgba(6, 182, 212, 0.1)',
    borderBottom: '1px solid rgba(6, 182, 212, 0.2)',
  },
  label: {
    fontSize: '13px',
    fontWeight: '600',
    color: '#06b6d4',
  },
  content: {
    padding: '10px 12px',
  },
  codePreview: {
    padding: '8px',
    borderRadius: '4px',
    background: 'rgba(0,0,0,0.3)',
    overflow: 'hidden',
  },
  codeText: {
    fontSize: '10px',
    fontFamily: 'monospace',
    color: 'var(--text-primary, #f0f6fc)',
    whiteSpace: 'pre-wrap',
    wordBreak: 'break-all',
  },
  placeholder: {
    fontSize: '11px',
    color: 'var(--text-secondary, #94a3b8)',
  },
  handle: { width: '10px', height: '10px', border: '2px solid var(--bg-secondary, #1e293b)' },
};

export default PythonCodeNode;
