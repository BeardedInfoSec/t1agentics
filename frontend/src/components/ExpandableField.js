/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

import React, { useState } from 'react';

/**
 * Expandable Field Component
 * Displays key-value pairs with expandable nested objects/arrays
 * Provides a clean, professional look for event field data
 */
function ExpandableField({ fieldKey, value }) {
  const [isExpanded, setIsExpanded] = useState(false);

  // Determine the type and render accordingly
  const renderValue = () => {
    // Null or undefined
    if (value === null || value === undefined) {
      return (
        <span style={{ 
          color: 'var(--text-muted)', 
          fontStyle: 'italic',
          fontFamily: 'monospace'
        }}>
          null
        </span>
      );
    }

    // Boolean
    if (typeof value === 'boolean') {
      return (
        <span style={{ 
          color: value ? '#22c55e' : '#ef4444',
          fontWeight: '600',
          fontFamily: 'monospace'
        }}>
          {value.toString()}
        </span>
      );
    }

    // Number
    if (typeof value === 'number') {
      return (
        <span style={{ 
          color: '#60a5fa',
          fontFamily: 'monospace'
        }}>
          {value}
        </span>
      );
    }

    // String
    if (typeof value === 'string') {
      // Highlight special patterns
      const isIP = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(value);
      const isURL = /^https?:\/\//.test(value);
      const isPath = /^\/[^\s]*$/.test(value);
      const isDate = /^\d{4}-\d{2}-\d{2}T/.test(value);

      let color = 'var(--text-secondary)';
      let icon = '';
      
      if (isIP) {
        color = '#3b82f6';
        icon = '🌐 ';
      } else if (isURL) {
        color = '#a855f7';
        icon = '🔗 ';
      } else if (isPath) {
        color = '#f59e0b';
        icon = '📁 ';
      } else if (isDate) {
        color = '#10b981';
        icon = '🕐 ';
      }

      return (
        <span style={{ 
          color: color,
          fontFamily: 'monospace',
          wordBreak: 'break-word'
        }}>
          {icon}{value}
        </span>
      );
    }

    // Array
    if (Array.isArray(value)) {
      if (value.length === 0) {
        return (
          <span style={{ 
            color: 'var(--text-muted)', 
            fontStyle: 'italic',
            fontFamily: 'monospace'
          }}>
            [ empty array ]
          </span>
        );
      }

      // If collapsed, show preview
      if (!isExpanded) {
        const preview = value.length <= 3 
          ? value.map(v => typeof v === 'string' ? v : JSON.stringify(v)).join(', ')
          : `${value.slice(0, 2).map(v => typeof v === 'string' ? v : JSON.stringify(v)).join(', ')}... +${value.length - 2} more`;
        
        return (
          <div style={{ display: 'inline-flex', alignItems: 'center', gap: '0.5rem' }}>
            <button
              onClick={() => setIsExpanded(true)}
              style={{
                background: 'rgba(59, 130, 246, 0.1)',
                border: '1px solid rgba(59, 130, 246, 0.3)',
                borderRadius: '4px',
                padding: '0.25rem 0.5rem',
                color: '#3b82f6',
                fontSize: '0.75rem',
                cursor: 'pointer',
                fontWeight: '600'
              }}
            >
              ▶ Array ({value.length} items)
            </button>
            <span style={{ 
              color: 'var(--text-muted)', 
              fontSize: '0.75rem',
              fontFamily: 'monospace'
            }}>
              {preview.length > 60 ? preview.substring(0, 60) + '...' : preview}
            </span>
          </div>
        );
      }

      // If expanded, show full array
      return (
        <div style={{ marginTop: '0.5rem' }}>
          <button
            onClick={() => setIsExpanded(false)}
            style={{
              background: 'rgba(59, 130, 246, 0.1)',
              border: '1px solid rgba(59, 130, 246, 0.3)',
              borderRadius: '4px',
              padding: '0.25rem 0.5rem',
              color: '#3b82f6',
              fontSize: '0.75rem',
              cursor: 'pointer',
              fontWeight: '600',
              marginBottom: '0.5rem'
            }}
          >
            ▼ Array ({value.length} items)
          </button>
          <div style={{
            marginLeft: '1rem',
            borderLeft: '2px solid rgba(100, 116, 139, 0.3)',
            paddingLeft: '1rem'
          }}>
            {value.map((item, idx) => (
              <div key={idx} style={{ 
                marginBottom: '0.5rem',
                padding: '0.5rem',
                background: 'rgba(100, 116, 139, 0.05)',
                borderRadius: '4px'
              }}>
                <span style={{ color: '#9cdcfe', marginRight: '0.5rem', fontFamily: 'monospace' }}>
                  [{idx}]
                </span>
                {typeof item === 'object' ? (
                  <div style={{ marginTop: '0.25rem' }}>
                    {renderNestedObject(item)}
                  </div>
                ) : (
                  <span style={{ fontFamily: 'monospace', color: 'var(--text-secondary)' }}>
                    {typeof item === 'string' ? item : JSON.stringify(item)}
                  </span>
                )}
              </div>
            ))}
          </div>
        </div>
      );
    }

    // Object
    if (typeof value === 'object') {
      const keys = Object.keys(value);
      
      if (keys.length === 0) {
        return (
          <span style={{ 
            color: 'var(--text-muted)', 
            fontStyle: 'italic',
            fontFamily: 'monospace'
          }}>
            { '{' } empty object { '}' }
          </span>
        );
      }

      // If collapsed, show preview
      if (!isExpanded) {
        const preview = keys.slice(0, 3).map(k => `${k}: ${value[k]}`).join(', ');
        return (
          <div style={{ display: 'inline-flex', alignItems: 'center', gap: '0.5rem' }}>
            <button
              onClick={() => setIsExpanded(true)}
              style={{
                background: 'rgba(168, 85, 247, 0.1)',
                border: '1px solid rgba(168, 85, 247, 0.3)',
                borderRadius: '4px',
                padding: '0.25rem 0.5rem',
                color: '#a855f7',
                fontSize: '0.75rem',
                cursor: 'pointer',
                fontWeight: '600'
              }}
            >
              ▶ Object ({keys.length} keys)
            </button>
            <span style={{ 
              color: 'var(--text-muted)', 
              fontSize: '0.75rem',
              fontFamily: 'monospace'
            }}>
              {preview.length > 60 ? preview.substring(0, 60) + '...' : preview}
            </span>
          </div>
        );
      }

      // If expanded, show full object
      return (
        <div style={{ marginTop: '0.5rem' }}>
          <button
            onClick={() => setIsExpanded(false)}
            style={{
              background: 'rgba(168, 85, 247, 0.1)',
              border: '1px solid rgba(168, 85, 247, 0.3)',
              borderRadius: '4px',
              padding: '0.25rem 0.5rem',
              color: '#a855f7',
              fontSize: '0.75rem',
              cursor: 'pointer',
              fontWeight: '600',
              marginBottom: '0.5rem'
            }}
          >
            ▼ Object ({keys.length} keys)
          </button>
          {renderNestedObject(value)}
        </div>
      );
    }

    return String(value);
  };

  const renderNestedObject = (obj) => {
    return (
      <div style={{
        marginLeft: '1rem',
        borderLeft: '2px solid rgba(100, 116, 139, 0.3)',
        paddingLeft: '1rem'
      }}>
        {Object.entries(obj).map(([key, val]) => (
          <div key={key} style={{ 
            marginBottom: '0.5rem',
            display: 'grid',
            gridTemplateColumns: '120px 1fr',
            gap: '0.75rem',
            padding: '0.5rem',
            background: 'rgba(100, 116, 139, 0.05)',
            borderRadius: '4px',
            alignItems: 'start'
          }}>
            <span style={{ 
              color: '#9cdcfe', 
              fontWeight: '600',
              fontFamily: 'monospace',
              wordBreak: 'break-word'
            }}>
              {key}
            </span>
            <div>
              <ExpandableField fieldKey={key} value={val} />
            </div>
          </div>
        ))}
      </div>
    );
  };

  return (
    <div 
      style={{ 
        display: 'flex', 
        alignItems: 'flex-start',
        width: '100%'
      }}
      onClick={(e) => {
        // Allow clicking anywhere in the row to copy
        if (e.target.tagName !== 'BUTTON') {
          const copyValue = typeof value === 'object' ? JSON.stringify(value) : String(value);
          navigator.clipboard.writeText(copyValue);
        }
      }}
      title="Click to copy value"
    >
      {renderValue()}
    </div>
  );
}

export default ExpandableField;
