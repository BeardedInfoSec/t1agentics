/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

import React, { useState } from 'react';

function FieldExtractionPanel({ fields }) {
  const [searchTerm, setSearchTerm] = useState('');
  const [copiedField, setCopiedField] = useState(null);

  if (!fields || Object.keys(fields).length === 0) {
    return (
      <div className="card" style={{ marginTop: '1.5rem' }}>
        <h3 style={{ fontSize: '1.25rem', marginBottom: '1rem' }}>📊 Extracted Fields</h3>
        <p style={{ color: '#888', textAlign: 'center', padding: '2rem' }}>
          No fields extracted from alert data
        </p>
      </div>
    );
  }

  const fieldEntries = Object.entries(fields);
  const filteredFields = searchTerm
    ? fieldEntries.filter(([key, value]) => 
        key.toLowerCase().includes(searchTerm.toLowerCase()) ||
        String(value).toLowerCase().includes(searchTerm.toLowerCase())
      )
    : fieldEntries;

  const getFieldType = (value) => {
    if (value === null || value === undefined) return 'null';
    if (typeof value === 'number') return 'number';
    if (typeof value === 'boolean') return 'boolean';
    if (Array.isArray(value)) return 'array';
    if (typeof value === 'object') return 'object';
    
    // Check if it's an IP address
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(value)) return 'ip';
    
    // Check if it's a hash
    if (/^[a-f0-9]{32}$/i.test(value)) return 'md5';
    if (/^[a-f0-9]{40}$/i.test(value)) return 'sha1';
    if (/^[a-f0-9]{64}$/i.test(value)) return 'sha256';
    
    // Check if it's a URL
    if (/^https?:\/\//i.test(value)) return 'url';
    
    // Check if it's an email
    if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) return 'email';
    
    return 'string';
  };

  const getFieldTypeColor = (type) => {
    const colors = {
      'string': '#22c55e',
      'number': '#3b82f6',
      'boolean': '#a855f7',
      'ip': '#f59e0b',
      'md5': '#ec4899',
      'sha1': '#ec4899',
      'sha256': '#ec4899',
      'url': '#06b6d4',
      'email': '#3CB371',
      'array': '#14b8a6',
      'object': '#3CB371',
      'null': '#6b7280'
    };
    return colors[type] || '#9ca3af';
  };

  const copyToClipboard = async (field, value) => {
    try {
      await navigator.clipboard.writeText(String(value));
      setCopiedField(field);
      setTimeout(() => setCopiedField(null), 2000);
    } catch (err) {
    }
  };

  const formatValue = (value) => {
    if (value === null || value === undefined) return 'null';
    if (typeof value === 'object') return JSON.stringify(value, null, 2);
    return String(value);
  };

  return (
    <div className="card" style={{ marginTop: '1.5rem' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem' }}>
        <h3 style={{ fontSize: '1.25rem', margin: 0 }}>
          📊 Extracted Fields <span style={{ fontSize: '0.875rem', color: '#888' }}>({filteredFields.length})</span>
        </h3>
        <input
          type="text"
          placeholder="🔍 Search fields..."
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          style={{
            padding: '0.5rem 1rem',
            background: '#2d2d2d',
            border: '1px solid #3d3d3d',
            borderRadius: '6px',
            color: 'white',
            fontSize: '0.875rem',
            width: '300px'
          }}
        />
      </div>

      {/* Field Statistics */}
      <div style={{ 
        display: 'flex', 
        gap: '1rem', 
        marginBottom: '1.5rem', 
        padding: '1rem',
        background: '#2d2d2d',
        borderRadius: '6px',
        border: '1px solid #3d3d3d'
      }}>
        <div>
          <div style={{ fontSize: '0.75rem', color: '#888', marginBottom: '0.25rem' }}>Total Fields</div>
          <div style={{ fontSize: '1.5rem', fontWeight: '700', color: '#3CB371' }}>
            {fieldEntries.length}
          </div>
        </div>
        <div style={{ borderLeft: '1px solid #3d3d3d', paddingLeft: '1rem' }}>
          <div style={{ fontSize: '0.75rem', color: '#888', marginBottom: '0.25rem' }}>IPs Detected</div>
          <div style={{ fontSize: '1.5rem', fontWeight: '700', color: '#f59e0b' }}>
            {fieldEntries.filter(([_, v]) => getFieldType(v) === 'ip').length}
          </div>
        </div>
        <div style={{ borderLeft: '1px solid #3d3d3d', paddingLeft: '1rem' }}>
          <div style={{ fontSize: '0.75rem', color: '#888', marginBottom: '0.25rem' }}>Hashes Found</div>
          <div style={{ fontSize: '1.5rem', fontWeight: '700', color: '#ec4899' }}>
            {fieldEntries.filter(([_, v]) => ['md5', 'sha1', 'sha256'].includes(getFieldType(v))).length}
          </div>
        </div>
        <div style={{ borderLeft: '1px solid #3d3d3d', paddingLeft: '1rem' }}>
          <div style={{ fontSize: '0.75rem', color: '#888', marginBottom: '0.25rem' }}>URLs Found</div>
          <div style={{ fontSize: '1.5rem', fontWeight: '700', color: '#06b6d4' }}>
            {fieldEntries.filter(([_, v]) => getFieldType(v) === 'url').length}
          </div>
        </div>
      </div>

      {/* Fields Grid */}
      <div style={{ 
        display: 'grid', 
        gridTemplateColumns: 'repeat(auto-fill, minmax(350px, 1fr))',
        gap: '0.75rem',
        maxHeight: '600px',
        overflowY: 'auto',
        padding: '0.5rem'
      }}>
        {filteredFields.map(([key, value]) => {
          const fieldType = getFieldType(value);
          const typeColor = getFieldTypeColor(fieldType);
          const isCopied = copiedField === key;

          return (
            <div
              key={key}
              style={{
                padding: '1rem',
                background: '#2d2d2d',
                border: '1px solid #3d3d3d',
                borderRadius: '6px',
                transition: 'all 0.2s',
                cursor: 'pointer'
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.borderColor = '#3CB371';
                e.currentTarget.style.background = 'rgba(102, 126, 234, 0.05)';
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.borderColor = '#3d3d3d';
                e.currentTarget.style.background = '#2d2d2d';
              }}
              onClick={() => copyToClipboard(key, value)}
            >
              {/* Field Name & Type */}
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
                <code style={{ 
                  fontSize: '0.75rem', 
                  color: '#a0e9ff',
                  fontWeight: '600',
                  wordBreak: 'break-word'
                }}>
                  {key}
                </code>
                <span
                  style={{
                    padding: '0.25rem 0.5rem',
                    background: typeColor + '20',
                    color: typeColor,
                    borderRadius: '4px',
                    fontSize: '0.65rem',
                    fontWeight: '600',
                    textTransform: 'uppercase',
                    letterSpacing: '0.5px',
                    border: `1px solid ${typeColor}40`
                  }}
                >
                  {fieldType}
                </span>
              </div>

              {/* Field Value */}
              <div style={{ 
                fontSize: '0.875rem', 
                color: '#e0e0e0',
                wordBreak: 'break-word',
                maxHeight: '80px',
                overflowY: 'auto',
                padding: '0.5rem',
                background: '#1a1a1a',
                borderRadius: '4px',
                fontFamily: 'monospace'
              }}>
                {formatValue(value)}
              </div>

              {/* Copy Indicator */}
              <div style={{ 
                marginTop: '0.5rem', 
                fontSize: '0.75rem', 
                color: isCopied ? '#22c55e' : '#3CB371',
                textAlign: 'right'
              }}>
                {isCopied ? '✓ Copied!' : 'Click to copy'}
              </div>
            </div>
          );
        })}
      </div>

      {filteredFields.length === 0 && searchTerm && (
        <div style={{ textAlign: 'center', padding: '3rem', color: '#888' }}>
          <p>No fields match "{searchTerm}"</p>
        </div>
      )}
    </div>
  );
}

export default FieldExtractionPanel;
