/**
 * Copyright (c) 2025-2026 T1 Agentics LLC. SPDX-License-Identifier: Apache-2.0
 */

/**
 * ConnectMyConnections - Manage active connector instances.
 * Shows installed connectors with health status, stats, and management actions.
 */

import React, { useState, useCallback, useRef, useEffect } from 'react';
import { authFetch, API_BASE_URL } from '../../utils/api';
import AutoResponseToggle from './AutoResponseToggle';

// SVG icons
const SearchIcon = ({ size = 16 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <circle cx="11" cy="11" r="8" /><path d="M21 21l-4.35-4.35" />
  </svg>
);

const RefreshIcon = ({ size = 14 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M23 4v6h-6" /><path d="M1 20v-6h6" />
    <path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15" />
  </svg>
);

const TrashIcon = ({ size = 14 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M3 6h18" /><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6" />
    <path d="M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2" />
  </svg>
);

const SettingsIcon = ({ size = 14 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <circle cx="12" cy="12" r="3" />
    <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z" />
  </svg>
);

const PlayIcon = ({ size = 14 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <polygon points="5 3 19 12 5 21 5 3" />
  </svg>
);

const PlugIcon = ({ size = 24 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M12 22v-5" /><path d="M9 8V2" /><path d="M15 8V2" />
    <path d="M18 8v5a6 6 0 0 1-12 0V8h12z" />
  </svg>
);

const CheckIcon = ({ size = 14 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <polyline points="20 6 9 17 4 12" />
  </svg>
);

const XIcon = ({ size = 14 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M18 6L6 18" /><path d="M6 6l12 12" />
  </svg>
);

const FILTER_OPTIONS = [
  { id: 'all', label: 'All' },
  { id: 'healthy', label: 'Healthy' },
  { id: 'degraded', label: 'Degraded' },
  { id: 'down', label: 'Down' },
];

export default function ConnectMyConnections({ instances, onRefresh, user }) {
  const [filter, setFilter] = useState('all');
  const [search, setSearch] = useState('');
  const [testing, setTesting] = useState(new Map());
  const [testResults, setTestResults] = useState(new Map());
  const [confirmRemove, setConfirmRemove] = useState(null);
  const [removing, setRemoving] = useState(false);
  const [toggling, setToggling] = useState(new Map());
  const mountedRef = useRef(true);

  useEffect(() => {
    mountedRef.current = true;
    return () => { mountedRef.current = false; };
  }, []);

  // Filter instances
  const filtered = (instances || []).filter(inst => {
    // Search filter
    if (search) {
      const term = search.toLowerCase();
      const name = (inst.connector_name || inst.display_name || '').toLowerCase();
      const display = (inst.display_name || '').toLowerCase();
      if (!name.includes(term) && !display.includes(term)) return false;
    }
    // Status filter
    if (filter === 'all') return true;
    if (filter === 'healthy') return inst.health_status === 'healthy';
    if (filter === 'degraded') return inst.health_status === 'degraded';
    if (filter === 'down') return inst.health_status === 'down';
    return true;
  });

  // Test connection
  const handleTest = useCallback(async (instanceId) => {
    setTesting(prev => new Map(prev).set(instanceId, true));
    setTestResults(prev => {
      const next = new Map(prev);
      next.delete(instanceId);
      return next;
    });

    try {
      const res = await authFetch(`${API_BASE_URL}/api/v1/connect/instances/${instanceId}/test`, {
        method: 'POST',
      });
      const data = await res.json();
      if (mountedRef.current) {
        setTestResults(prev => new Map(prev).set(instanceId, {
          success: res.ok && data.success !== false,
          message: data.message || (res.ok ? 'Connection successful' : 'Connection failed'),
          status_code: data.status_code,
          duration_ms: data.duration_ms,
        }));
        // Refresh to update health status
        if (onRefresh) onRefresh();
      }
    } catch (err) {
      if (mountedRef.current) {
        setTestResults(prev => new Map(prev).set(instanceId, {
          success: false,
          message: err.message || 'Test failed',
        }));
      }
    } finally {
      if (mountedRef.current) {
        setTesting(prev => {
          const next = new Map(prev);
          next.delete(instanceId);
          return next;
        });
      }
    }
  }, [onRefresh]);

  // Toggle enabled/disabled
  const handleToggle = useCallback(async (instanceId, currentEnabled) => {
    setToggling(prev => new Map(prev).set(instanceId, true));
    try {
      const res = await authFetch(`${API_BASE_URL}/api/v1/connect/instances/${instanceId}/toggle`, {
        method: 'POST',
      });
      if (res.ok && onRefresh) {
        await onRefresh();
      }
    } catch {
      // Ignore toggle errors silently
    } finally {
      if (mountedRef.current) {
        setToggling(prev => {
          const next = new Map(prev);
          next.delete(instanceId);
          return next;
        });
      }
    }
  }, [onRefresh]);

  // Remove instance
  const handleRemove = useCallback(async (instanceId) => {
    setRemoving(true);
    try {
      const res = await authFetch(`${API_BASE_URL}/api/v1/connect/instances/${instanceId}`, {
        method: 'DELETE',
      });
      if (res.ok && onRefresh) {
        await onRefresh();
      }
    } catch {
      // Ignore
    } finally {
      if (mountedRef.current) {
        setRemoving(false);
        setConfirmRemove(null);
      }
    }
  }, [onRefresh]);

  const formatDate = (dateStr) => {
    if (!dateStr) return 'Never';
    const d = new Date(dateStr);
    const now = new Date();
    const diffMs = now - d;
    const diffMins = Math.floor(diffMs / 60000);
    if (diffMins < 1) return 'Just now';
    if (diffMins < 60) return `${diffMins}m ago`;
    const diffHours = Math.floor(diffMins / 60);
    if (diffHours < 24) return `${diffHours}h ago`;
    return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
  };

  const getCategoryBadgeClass = (cat) => {
    if (!cat) return 'badge badge-category';
    const slug = cat.toLowerCase().replace(/\s+/g, '_');
    return `badge badge-${slug}`;
  };

  // Empty state
  if (!instances || instances.length === 0) {
    return (
      <div className="connect-empty">
        <div className="connect-empty-icon">
          <PlugIcon size={24} />
        </div>
        <h3>No connections yet</h3>
        <p>Browse the Marketplace to add your first integration.</p>
      </div>
    );
  }

  return (
    <div className="connections-container">
      {/* Toolbar */}
      <div className="connections-toolbar">
        <div className="connections-search">
          <span className="connections-search-icon">
            <SearchIcon size={14} />
          </span>
          <input
            type="text"
            placeholder="Search connections..."
            value={search}
            onChange={e => setSearch(e.target.value)}
          />
        </div>

        <div className="connections-filter-pills">
          {FILTER_OPTIONS.map(opt => (
            <button
              key={opt.id}
              className={`connections-filter-pill ${filter === opt.id ? 'active' : ''}`}
              onClick={() => setFilter(opt.id)}
            >
              {opt.label}
            </button>
          ))}
        </div>

        <button
          className="connect-btn connect-btn-outline connect-btn-sm"
          onClick={onRefresh}
          style={{ marginLeft: 'auto' }}
        >
          <RefreshIcon size={12} />
          Refresh
        </button>
      </div>

      {/* Filtered empty state */}
      {filtered.length === 0 && (
        <div className="connect-empty">
          <h3>No matching connections</h3>
          <p>Try adjusting your search or filter criteria.</p>
        </div>
      )}

      {/* Connection list */}
      <div className="connections-list">
        {filtered.map(inst => {
          const isTest = testing.get(inst.id);
          const testResult = testResults.get(inst.id);
          const isToggling = toggling.get(inst.id);
          const status = inst.health_status || 'unknown';

          return (
            <div key={inst.id} className="connection-card">
              <div className="connection-card-left">
                <span className={`connection-status-dot ${status}`} title={status} />
                <div className="connection-card-info">
                  <h4 className="connection-card-name">
                    {inst.connector_name || inst.display_name || 'Unknown Connector'}
                  </h4>
                  <div className="connection-card-subname">
                    {inst.display_name && inst.display_name !== inst.connector_name
                      ? inst.display_name
                      : inst.vendor || ''}
                    {inst.category && (
                      <span className={getCategoryBadgeClass(inst.category)} style={{ marginLeft: '0.5rem' }}>
                        {inst.category}
                      </span>
                    )}
                  </div>
                </div>
              </div>

              <div className="connection-card-center">
                <div className="connection-card-stat">
                  <div className="connection-card-stat-value">{inst.total_requests || 0}</div>
                  <div className="connection-card-stat-label">Total</div>
                </div>
                <div className="connection-card-stat">
                  <div className="connection-card-stat-value success">{inst.success_requests || 0}</div>
                  <div className="connection-card-stat-label">Success</div>
                </div>
                <div className="connection-card-stat">
                  <div className="connection-card-stat-value failed">{inst.failed_requests || 0}</div>
                  <div className="connection-card-stat-label">Failed</div>
                </div>
                <div className="connection-card-last-check">
                  Last check: {formatDate(inst.health_checked)}
                </div>
              </div>

              <div className="connection-actions">
                {/* Toggle switch */}
                <label className="connect-toggle" title={inst.enabled ? 'Enabled' : 'Disabled'}>
                  <input
                    type="checkbox"
                    checked={inst.enabled !== false}
                    onChange={() => handleToggle(inst.id, inst.enabled)}
                    disabled={isToggling}
                  />
                  <span className="connect-toggle-slider" />
                </label>

                {/* Test button */}
                <button
                  className="connect-btn connect-btn-outline connect-btn-sm"
                  onClick={() => handleTest(inst.id)}
                  disabled={isTest}
                  title="Test connection"
                >
                  {isTest ? <span className="connect-spinner sm" /> : <PlayIcon size={12} />}
                  Test
                </button>

                {/* Configure button */}
                {(user?.role === 'admin' || user?.role === 'platform_owner') && (
                  <button
                    className="connect-btn-icon"
                    title="Configure"
                    onClick={() => {/* Future: open config modal */}}
                  >
                    <SettingsIcon size={14} />
                  </button>
                )}

                {/* Remove button */}
                {(user?.role === 'admin' || user?.role === 'platform_owner') && (
                  <button
                    className="connect-btn-icon danger"
                    title="Remove"
                    onClick={() => setConfirmRemove(inst)}
                  >
                    <TrashIcon size={14} />
                  </button>
                )}
              </div>

              {/* Inline test result */}
              {testResult && (
                <div
                  className={`test-result ${testResult.success ? 'success' : 'failure'}`}
                >
                  <div className="test-result-header">
                    <span className={`test-result-status ${testResult.success ? 'success' : 'failure'}`}>
                      {testResult.success ? <CheckIcon size={12} /> : <XIcon size={12} />}
                      {' '}{testResult.message}
                    </span>
                    {testResult.duration_ms && (
                      <span className="test-result-duration">{testResult.duration_ms}ms</span>
                    )}
                  </div>
                </div>
              )}

              {/* Auto-response toggle for admins */}
              <AutoResponseToggle
                instanceId={inst.id}
                initialEnabled={inst.auto_response_enabled || false}
                connectorName={inst.connector_name || inst.display_name || 'this integration'}
                onToggle={(newState) => {
                  inst.auto_response_enabled = newState;
                }}
                isAdmin={user?.role === 'admin' || user?.role === 'platform_owner'}
              />
            </div>
          );
        })}
      </div>

      {/* Remove confirmation dialog */}
      {confirmRemove && (
        <div className="connect-confirm-overlay" onClick={() => setConfirmRemove(null)}>
          <div className="connect-confirm-dialog" onClick={e => e.stopPropagation()}>
            <h3>Remove Connection</h3>
            <p>
              Are you sure you want to remove "{confirmRemove.connector_name || confirmRemove.display_name}"?
              This will disable all actions from this connector.
            </p>
            <div className="connect-confirm-actions">
              <button
                className="connect-btn connect-btn-outline"
                onClick={() => setConfirmRemove(null)}
                disabled={removing}
              >
                Cancel
              </button>
              <button
                className="connect-btn connect-btn-danger"
                onClick={() => handleRemove(confirmRemove.id)}
                disabled={removing}
              >
                {removing ? <span className="connect-spinner sm" /> : null}
                Remove
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
