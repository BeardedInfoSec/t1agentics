/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

import React, { useState } from 'react';

// JSON syntax highlighter with click-to-copy
function JsonViewer({ data }) {
  const [copiedPath, setCopiedPath] = useState(null);

  const handleCopyValue = (value, path) => {
    const textValue = typeof value === 'string' ? value : JSON.stringify(value);
    navigator.clipboard.writeText(textValue);
    setCopiedPath(path);
    setTimeout(() => setCopiedPath(null), 2000);
  };

  const renderValue = (value, key, path) => {
    const fullPath = path ? `${path}.${key}` : key;

    if (value === null) {
      return (
        <span
          style={{ color: '#808080', cursor: 'pointer' }}
          onClick={() => handleCopyValue(value, fullPath)}
          title="Click to copy"
        >
          null
        </span>
      );
    }

    if (typeof value === 'boolean') {
      return (
        <span
          style={{ color: '#569cd6', cursor: 'pointer' }}
          onClick={() => handleCopyValue(value, fullPath)}
          title="Click to copy"
        >
          {value.toString()}
        </span>
      );
    }

    if (typeof value === 'number') {
      return (
        <span
          style={{ color: '#b5cea8', cursor: 'pointer' }}
          onClick={() => handleCopyValue(value, fullPath)}
          title="Click to copy"
        >
          {value}
        </span>
      );
    }

    if (typeof value === 'string') {
      return (
        <span
          style={{ color: '#ce9178', cursor: 'pointer', position: 'relative' }}
          onClick={() => handleCopyValue(value, fullPath)}
          title="Click to copy"
        >
          "{value}"
          {copiedPath === fullPath && (
            <span
              style={{
                position: 'absolute',
                top: '-20px',
                left: '0',
                background: '#4caf50',
                color: 'white',
                padding: '2px 6px',
                borderRadius: '4px',
                fontSize: '0.7rem',
                whiteSpace: 'nowrap'
              }}
            >
              ✓ Copied!
            </span>
          )}
        </span>
      );
    }

    if (Array.isArray(value)) {
      if (value.length === 0) {
        return <span style={{ color: '#808080' }}>[]</span>;
      }
      return (
        <span>
          <span style={{ color: '#808080' }}>[</span>
          <div style={{ marginLeft: '20px' }}>
            {value.map((item, index) => (
              <div key={index}>
                {renderValue(item, index, fullPath)}
                {index < value.length - 1 && <span style={{ color: '#808080' }}>,</span>}
              </div>
            ))}
          </div>
          <span style={{ color: '#808080' }}>]</span>
        </span>
      );
    }

    if (typeof value === 'object') {
      const entries = Object.entries(value);
      if (entries.length === 0) {
        return <span style={{ color: '#808080' }}>{'{}'}</span>;
      }
      return (
        <span>
          <span style={{ color: '#808080' }}>{'{'}</span>
          <div style={{ marginLeft: '20px' }}>
            {entries.map(([k, v], index) => (
              <div key={k} style={{ marginBottom: '4px' }}>
                <span style={{ color: '#9cdcfe' }}>"{k}"</span>
                <span style={{ color: '#808080' }}>: </span>
                {renderValue(v, k, fullPath)}
                {index < entries.length - 1 && <span style={{ color: '#808080' }}>,</span>}
              </div>
            ))}
          </div>
          <span style={{ color: '#808080' }}>{'}'}</span>
        </span>
      );
    }

    return <span style={{ color: '#ce9178' }}>{String(value)}</span>;
  };

  return (
    <div
      style={{
        fontFamily: '"Fira Code", "Courier New", monospace',
        fontSize: '0.813rem',
        lineHeight: '1.6',
        color: '#d4d4d4',
        whiteSpace: 'pre-wrap',
        wordBreak: 'break-word'
      }}
    >
      {renderValue(data, '', '')}
    </div>
  );
}

export default JsonViewer;
