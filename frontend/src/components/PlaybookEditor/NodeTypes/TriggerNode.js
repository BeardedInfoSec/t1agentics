/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

/**
 * Trigger Node Component
 *
 * Visual representation of a trigger node in the playbook graph.
 * For use with React Flow.
 */

import React from 'react';
import { Handle, Position } from 'reactflow';
import { Zap } from 'lucide-react';

function TriggerNode({ data, selected }) {
  return (
    <div style={{ ...styles.node, ...(selected ? styles.selected : {}) }}>
      <div style={styles.header}>
        <Zap size={14} style={{ color: '#f59e0b' }} />
        <span style={styles.label}>{data?.label || 'Trigger'}</span>
      </div>
      <div style={styles.content}>
        {data?.config?.alert_types?.length > 0 ? (
          <div style={styles.tags}>
            {data.config.alert_types.map((type, idx) => (
              <span key={idx} style={styles.tag}>{type}</span>
            ))}
          </div>
        ) : (
          <span style={styles.placeholder}>All alerts</span>
        )}
      </div>

      {/* Output handle for connecting to next nodes */}
      <Handle
        type="source"
        position={Position.Bottom}
        id="output"
        style={styles.handle}
      />
    </div>
  );
}

const styles = {
  node: {
    minWidth: '180px',
    background: 'var(--bg-secondary, #1e293b)',
    border: '2px solid #f59e0b',
    borderRadius: '999px',
    overflow: 'hidden',
  },
  selected: {
    boxShadow: '0 0 0 2px rgba(245, 158, 11, 0.4)',
  },
  header: {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
    padding: '10px 12px',
    background: 'rgba(245, 158, 11, 0.1)',
    borderBottom: '1px solid rgba(245, 158, 11, 0.2)',
  },
  label: {
    fontSize: '13px',
    fontWeight: '600',
    color: '#f59e0b',
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
    background: 'rgba(245, 158, 11, 0.2)',
    color: '#f59e0b',
  },
  placeholder: {
    fontSize: '11px',
    color: 'var(--text-secondary, #94a3b8)',
  },
  handle: {
    width: '10px',
    height: '10px',
    background: '#f59e0b',
    border: '2px solid var(--bg-secondary, #1e293b)',
  },
};

export default TriggerNode;
