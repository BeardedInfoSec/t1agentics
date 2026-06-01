/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

/**
 * Webform Node Component
 */

import { Handle, Position } from 'reactflow';
import React from 'react';
import { FileText } from 'lucide-react';

function WebformNode({ data, selected }) {
  const fields = data?.config?.fields || [];

  return (
    <div style={{ ...styles.node, ...(selected ? styles.selected : {}) }}>
      <Handle type="target" position={Position.Top} id="input" style={styles.handle} />
      <div style={styles.header}>
        <FileText size={14} style={{ color: '#ec4899' }} />
        <span style={styles.label}>{data?.label || 'Webform'}</span>
      </div>
      <div style={styles.content}>
        {fields.length > 0 ? (
          <div style={styles.fieldList}>
            {fields.slice(0, 3).map((field, idx) => (
              <div key={idx} style={styles.fieldItem}>
                <span style={styles.fieldName}>{field.name || field.label}</span>
                <span style={styles.fieldType}>{field.type}</span>
              </div>
            ))}
            {fields.length > 3 && (
              <span style={styles.moreFields}>+{fields.length - 3} more fields</span>
            )}
          </div>
        ) : (
          <span style={styles.placeholder}>Configure form fields</span>
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
    border: '2px solid #ec4899',
    borderRadius: '6px 6px 18px 18px',
    overflow: 'hidden',
    position: 'relative',
  },
  selected: {
    boxShadow: '0 0 0 2px rgba(236, 72, 153, 0.4)',
  },
  header: {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
    padding: '10px 12px',
    background: 'rgba(236, 72, 153, 0.1)',
    borderBottom: '1px solid rgba(236, 72, 153, 0.2)',
  },
  label: {
    fontSize: '13px',
    fontWeight: '600',
    color: '#ec4899',
  },
  content: {
    padding: '10px 12px',
  },
  fieldList: {
    display: 'flex',
    flexDirection: 'column',
    gap: '4px',
  },
  fieldItem: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    padding: '4px 8px',
    borderRadius: '4px',
    background: 'rgba(0,0,0,0.2)',
  },
  fieldName: {
    fontSize: '11px',
    color: 'var(--text-primary, #f0f6fc)',
  },
  fieldType: {
    fontSize: '10px',
    color: 'var(--text-secondary, #94a3b8)',
  },
  moreFields: {
    fontSize: '10px',
    color: 'var(--text-secondary, #94a3b8)',
    fontStyle: 'italic',
    marginTop: '4px',
  },
  placeholder: {
    fontSize: '11px',
    color: 'var(--text-secondary, #94a3b8)',
  },
  handle: { width: '10px', height: '10px', border: '2px solid var(--bg-secondary, #1e293b)' },
};

export default WebformNode;
