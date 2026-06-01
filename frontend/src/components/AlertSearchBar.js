/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

import React, { useState, useEffect } from 'react';

/**
 * SIEM-Style Alert Search Bar
 * Supports field:value queries like Splunk/Sentinel
 */
function AlertSearchBar({ onSearch, alertCount }) {
  const [searchQuery, setSearchQuery] = useState('');
  const [quickFilters, setQuickFilters] = useState({
    status: 'all',
    severity: 'all'
  });
  const [showAdvanced, setShowAdvanced] = useState(false);

  // Debounce search
  useEffect(() => {
    const timer = setTimeout(() => {
      executeSearch();
    }, 300);
    return () => clearTimeout(timer);
  }, [searchQuery, quickFilters]);

  const executeSearch = () => {
    const filters = {
      query: searchQuery,
      ...quickFilters
    };
    onSearch(filters);
  };

  const parseQuery = () => {
    // Parse SIEM-style queries: field:value
    // Examples: 
    //   "severity:high"
    //   "source:edr status:open"
    //   "192.168.1.1"
    return searchQuery;
  };

  const quickFilterPresets = [
    { label: 'All', status: 'all', icon: '📋' },
    { label: 'Open', status: 'open', icon: '🔴' },
    { label: 'Investigating', status: 'investigating', icon: '🔍' },
    { label: 'Resolved', status: 'resolved', icon: '✅' },
    { label: 'Closed', status: 'closed', icon: '🔒' }
  ];

  const severityFilters = [
    { label: 'All', value: 'all' },
    { label: 'Critical', value: 'critical' },
    { label: 'High', value: 'high' },
    { label: 'Medium', value: 'medium' },
    { label: 'Low', value: 'low' }
  ];

  return (
    <div className="card" style={{ marginBottom: '1.5rem' }}>
      {/* Main Search Bar */}
      <div style={{ display: 'flex', gap: '1rem', alignItems: 'center', marginBottom: '1rem' }}>
        <div style={{ flex: 1, position: 'relative' }}>
          <input
            type="text"
            placeholder='Search alerts... (e.g., "severity:high source:edr" or "192.168.1.1")'
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            style={{
              width: '100%',
              padding: '0.75rem 1rem 0.75rem 2.5rem',
              background: 'var(--bg-secondary)',
              border: '2px solid rgba(102, 126, 234, 0.3)',
              borderRadius: '8px',
              color: 'var(--text-primary)',
              fontSize: '0.875rem',
              fontFamily: 'monospace',
              transition: 'all 0.2s'
            }}
            onFocus={(e) => {
              e.target.style.borderColor = 'var(--primary)';
              e.target.style.background = 'var(--bg-tertiary)';
            }}
            onBlur={(e) => {
              e.target.style.borderColor = 'rgba(102, 126, 234, 0.3)';
              e.target.style.background = 'var(--bg-secondary)';
            }}
          />
          <span style={{
            position: 'absolute',
            left: '1rem',
            top: '50%',
            transform: 'translateY(-50%)',
            fontSize: '1.25rem',
            opacity: 0.5
          }}>
            🔍
          </span>
        </div>

        {/* Results Count */}
        <div style={{
          padding: '0.75rem 1rem',
          background: 'rgba(102, 126, 234, 0.1)',
          borderRadius: '8px',
          fontSize: '0.875rem',
          fontWeight: '600',
          color: 'var(--primary)',
          whiteSpace: 'nowrap'
        }}>
          {alertCount} alert{alertCount !== 1 ? 's' : ''}
        </div>

        {/* Advanced Toggle */}
        <button
          onClick={() => setShowAdvanced(!showAdvanced)}
          className="button button-secondary"
          style={{ padding: '0.75rem 1rem', fontSize: '0.75rem', whiteSpace: 'nowrap' }}
        >
          {showAdvanced ? '▲ Simple' : '▼ Advanced'}
        </button>
      </div>

      {/* Quick Filters Row */}
      <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap', alignItems: 'center' }}>
        <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontWeight: '600', marginRight: '0.5rem' }}>
          STATUS:
        </span>
        {quickFilterPresets.map((preset) => (
          <button
            key={preset.status}
            onClick={() => setQuickFilters(prev => ({ ...prev, status: preset.status }))}
            style={{
              padding: '0.375rem 0.75rem',
              background: quickFilters.status === preset.status ? 'var(--primary)' : 'var(--bg-secondary)',
              border: quickFilters.status === preset.status ? '1px solid var(--primary)' : '1px solid rgba(255, 255, 255, 0.1)',
              borderRadius: '6px',
              color: quickFilters.status === preset.status ? 'white' : 'var(--text-secondary)',
              fontSize: '0.75rem',
              fontWeight: '600',
              cursor: 'pointer',
              transition: 'all 0.15s',
              display: 'flex',
              alignItems: 'center',
              gap: '0.375rem'
            }}
            onMouseEnter={(e) => {
              if (quickFilters.status !== preset.status) {
                e.target.style.background = 'rgba(102, 126, 234, 0.1)';
                e.target.style.borderColor = 'var(--primary)';
              }
            }}
            onMouseLeave={(e) => {
              if (quickFilters.status !== preset.status) {
                e.target.style.background = 'var(--bg-secondary)';
                e.target.style.borderColor = 'rgba(255, 255, 255, 0.1)';
              }
            }}
          >
            <span>{preset.icon}</span>
            <span>{preset.label}</span>
          </button>
        ))}

        <div style={{ width: '1px', height: '20px', background: 'rgba(255, 255, 255, 0.1)', margin: '0 0.5rem' }} />

        <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontWeight: '600', marginRight: '0.5rem' }}>
          SEVERITY:
        </span>
        {severityFilters.map((sev) => (
          <button
            key={sev.value}
            onClick={() => setQuickFilters(prev => ({ ...prev, severity: sev.value }))}
            style={{
              padding: '0.375rem 0.75rem',
              background: quickFilters.severity === sev.value ? 'var(--primary)' : 'var(--bg-secondary)',
              border: quickFilters.severity === sev.value ? '1px solid var(--primary)' : '1px solid rgba(255, 255, 255, 0.1)',
              borderRadius: '6px',
              color: quickFilters.severity === sev.value ? 'white' : 'var(--text-secondary)',
              fontSize: '0.75rem',
              fontWeight: '600',
              cursor: 'pointer',
              transition: 'all 0.15s'
            }}
            onMouseEnter={(e) => {
              if (quickFilters.severity !== sev.value) {
                e.target.style.background = 'rgba(102, 126, 234, 0.1)';
                e.target.style.borderColor = 'var(--primary)';
              }
            }}
            onMouseLeave={(e) => {
              if (quickFilters.severity !== sev.value) {
                e.target.style.background = 'var(--bg-secondary)';
                e.target.style.borderColor = 'rgba(255, 255, 255, 0.1)';
              }
            }}
          >
            {sev.label}
          </button>
        ))}
      </div>

      {/* Advanced Search (if shown) */}
      {showAdvanced && (
        <div style={{
          marginTop: '1rem',
          padding: '1rem',
          background: 'var(--bg-secondary)',
          borderRadius: '8px',
          border: '1px solid rgba(255, 255, 255, 0.05)'
        }}>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '0.75rem' }}>
            <strong>Search Tips:</strong>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '0.5rem', fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
            <div>• <code>severity:high</code> - Filter by severity</div>
            <div>• <code>source:edr</code> - Filter by source</div>
            <div>• <code>status:open</code> - Filter by status</div>
            <div>• <code>192.168.1.1</code> - Search for IP</div>
            <div>• <code>malware</code> - Full text search</div>
            <div>• Combine: <code>severity:high source:edr</code></div>
          </div>
        </div>
      )}
    </div>
  );
}

export default AlertSearchBar;
