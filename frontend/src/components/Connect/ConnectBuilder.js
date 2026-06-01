/**
 * Copyright (c) 2025-2026 T1 Agentics LLC. SPDX-License-Identifier: Apache-2.0
 */

/**
 * ConnectBuilder - Custom connector builder with live testing.
 * Provides a form-based interface for creating and editing custom connectors.
 * Sections: Basic Info, Authentication, Actions, Save.
 */

import React, { useState, useCallback, useRef, useEffect } from 'react';
import { authFetch, API_BASE_URL } from '../../utils/api';

// SVG icons
const ChevronDownIcon = ({ size = 16 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <polyline points="6 9 12 15 18 9" />
  </svg>
);

const PlusIcon = ({ size = 14 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M12 5v14" /><path d="M5 12h14" />
  </svg>
);

const PlayIcon = ({ size = 12 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <polygon points="5 3 19 12 5 21 5 3" />
  </svg>
);

const CopyIcon = ({ size = 12 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <rect x="9" y="9" width="13" height="13" rx="2" ry="2" />
    <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
  </svg>
);

const EditIcon = ({ size = 12 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7" />
    <path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z" />
  </svg>
);

const TrashIcon = ({ size = 12 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M3 6h18" /><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6" />
    <path d="M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2" />
  </svg>
);

const SaveIcon = ({ size = 14 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z" />
    <polyline points="17 21 17 13 7 13 7 21" />
    <polyline points="7 3 7 8 15 8" />
  </svg>
);

const DownloadIcon = ({ size = 14 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
    <polyline points="7 10 12 15 17 10" />
    <line x1="12" y1="15" x2="12" y2="3" />
  </svg>
);

const CheckIcon = ({ size = 12 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <polyline points="20 6 9 17 4 12" />
  </svg>
);

const XIcon = ({ size = 12 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M18 6L6 18" /><path d="M6 6l12 12" />
  </svg>
);

const LockIcon = ({ size = 10 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
    <path d="M7 11V7a5 5 0 0 1 10 0v4" />
  </svg>
);

const CATEGORIES = [
  'Threat Intel', 'SIEM', 'EDR', 'Ticketing', 'Communication',
  'Vulnerability', 'Identity', 'Network', 'Sandbox', 'Email Security',
  'Cloud', 'Enrichment', 'Other',
];

const AUTH_TYPES = [
  { value: 'api_key', label: 'API Key' },
  { value: 'bearer', label: 'Bearer Token' },
  { value: 'basic', label: 'Basic Auth' },
  { value: 'oauth2_client', label: 'OAuth2 Client Credentials' },
  { value: 'custom_header', label: 'Custom Headers' },
  { value: 'none', label: 'No Authentication' },
];

const HTTP_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'];

const OBSERVABLE_TYPES = [
  '', 'ip', 'domain', 'url', 'hash_md5', 'hash_sha1', 'hash_sha256',
  'email', 'filename', 'cve', 'hostname', 'mac_address', 'user', 'process',
];

const emptyAction = () => ({
  id: `action_${Date.now()}_${Math.random().toString(36).substr(2, 6)}`,
  name: '',
  method: 'GET',
  endpoint: '',
  observable_type: '',
  description: '',
  request_body: '',
  origin: 'custom',
});

// JSON validation helper — returns null if valid, error message string if invalid
const validateJson = (str) => {
  if (!str || !str.trim()) return null;
  try {
    JSON.parse(str);
    return null;
  } catch (e) {
    // Extract a useful position hint from the error message
    const match = e.message.match(/position\s+(\d+)/i);
    if (match) {
      const pos = parseInt(match[1], 10);
      const lineNum = str.substring(0, pos).split('\n').length;
      return `Invalid JSON near line ${lineNum}: ${e.message}`;
    }
    return `Invalid JSON: ${e.message}`;
  }
};

// Pretty-print JSON string; returns original if invalid
const formatJson = (str) => {
  if (!str || !str.trim()) return str;
  try {
    return JSON.stringify(JSON.parse(str), null, 2);
  } catch {
    return str;
  }
};

// Minify JSON string; returns original if invalid
const minifyJson = (str) => {
  if (!str || !str.trim()) return str;
  try {
    return JSON.stringify(JSON.parse(str));
  } catch {
    return str;
  }
};

export default function ConnectBuilder({ user, onConnectorCreated, connector: editConnector }) {
  // Section expand state
  const [expandedSections, setExpandedSections] = useState({
    info: true,
    auth: true,
    actions: true,
    save: true,
  });

  // Connector data
  const [connectorData, setConnectorData] = useState({
    name: editConnector?.name || '',
    vendor: editConnector?.vendor || '',
    category: editConnector?.category || '',
    description: editConnector?.description || '',
    base_url: editConnector?.base_url || '',
  });

  const [authType, setAuthType] = useState(editConnector?.auth_type || 'api_key');
  const [authConfig, setAuthConfig] = useState(editConnector?.auth_config || {});
  const [actions, setActions] = useState(editConnector?.actions || []);
  const [editingActionId, setEditingActionId] = useState(null);
  const [editingActionData, setEditingActionData] = useState(null);
  const [testingActionId, setTestingActionId] = useState(null);
  const [testParams, setTestParams] = useState({});
  const [testResults, setTestResults] = useState(new Map());
  const [testCredential, setTestCredential] = useState({});
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState(null);
  const [saveSuccess, setSaveSuccess] = useState(false);
  const [savedConnectorId, setSavedConnectorId] = useState(editConnector?.id || null);
  const [testingAuth, setTestingAuth] = useState(false);
  const [authTestResult, setAuthTestResult] = useState(null);
  const mountedRef = useRef(true);

  useEffect(() => {
    mountedRef.current = true;
    return () => { mountedRef.current = false; };
  }, []);

  const toggleSection = (section) => {
    setExpandedSections(prev => ({ ...prev, [section]: !prev[section] }));
  };

  const updateConnectorField = (field, value) => {
    setConnectorData(prev => ({ ...prev, [field]: value }));
  };

  const updateAuthConfig = (key, value) => {
    setAuthConfig(prev => ({ ...prev, [key]: value }));
  };

  // Extract path parameters from endpoint (e.g., /lookup/{ip} -> ['ip'])
  const extractPathParams = (endpoint) => {
    const matches = endpoint.match(/\{(\w+)\}/g) || [];
    return matches.map(m => m.replace(/[{}]/g, ''));
  };

  // Add new action
  const handleAddAction = () => {
    const newAction = emptyAction();
    setActions(prev => [...prev, newAction]);
    setEditingActionId(newAction.id);
    setEditingActionData({ ...newAction });
  };

  // Clone action
  const handleCloneAction = (action) => {
    const cloned = {
      ...action,
      id: `action_${Date.now()}_${Math.random().toString(36).substr(2, 6)}`,
      name: `${action.name} (copy)`,
      origin: 'cloned',
    };
    setActions(prev => [...prev, cloned]);
  };

  // Remove action
  const handleRemoveAction = (actionId) => {
    setActions(prev => prev.filter(a => a.id !== actionId));
    if (editingActionId === actionId) {
      setEditingActionId(null);
      setEditingActionData(null);
    }
    if (testingActionId === actionId) {
      setTestingActionId(null);
    }
  };

  // Start editing an action
  const handleEditAction = (action) => {
    if (editingActionId === action.id) {
      setEditingActionId(null);
      setEditingActionData(null);
    } else {
      setEditingActionId(action.id);
      setEditingActionData({ ...action });
    }
  };

  // Save action edits
  const handleSaveActionEdit = () => {
    if (!editingActionData) return;
    setActions(prev => prev.map(a =>
      a.id === editingActionId ? { ...editingActionData } : a
    ));
    setEditingActionId(null);
    setEditingActionData(null);
  };

  // Cancel action edits
  const handleCancelActionEdit = () => {
    // If it was a new empty action, remove it
    if (editingActionData && !editingActionData.name) {
      setActions(prev => prev.filter(a => a.id !== editingActionId));
    }
    setEditingActionId(null);
    setEditingActionData(null);
  };

  // Toggle test panel for an action
  const handleToggleTest = (actionId) => {
    if (testingActionId === actionId) {
      setTestingActionId(null);
    } else {
      setTestingActionId(actionId);
      setTestParams({});
    }
  };

  // Run test for an action
  const handleRunTest = useCallback(async (action) => {
    const resultKey = action.id;
    setTestResults(prev => {
      const next = new Map(prev);
      next.set(resultKey, { loading: true });
      return next;
    });

    try {
      const payload = {
        connector: {
          ...connectorData,
          auth_type: authType,
          auth_config: authConfig,
        },
        action: {
          name: action.name,
          method: action.method,
          endpoint: action.endpoint,
          observable_type: action.observable_type,
          request_body: action.request_body || '',
        },
        credentials: testCredential,
        params: testParams,
      };

      const startTime = Date.now();
      const res = await authFetch(`${API_BASE_URL}/api/v1/connect/test-action`, {
        method: 'POST',
        body: JSON.stringify(payload),
      });
      const duration = Date.now() - startTime;
      const data = await res.json();

      if (mountedRef.current) {
        setTestResults(prev => {
          const next = new Map(prev);
          next.set(resultKey, {
            loading: false,
            success: res.ok,
            status_code: res.status,
            duration_ms: duration,
            data: data,
          });
          return next;
        });
      }
    } catch (err) {
      if (mountedRef.current) {
        setTestResults(prev => {
          const next = new Map(prev);
          next.set(resultKey, {
            loading: false,
            success: false,
            error: err.message || 'Test failed',
          });
          return next;
        });
      }
    }
  }, [connectorData, authType, authConfig, testCredential, testParams]);

  // Test auth
  const handleTestAuth = useCallback(async () => {
    setTestingAuth(true);
    setAuthTestResult(null);
    try {
      const payload = {
        base_url: connectorData.base_url,
        auth_type: authType,
        auth_config: authConfig,
        credentials: testCredential,
      };
      const res = await authFetch(`${API_BASE_URL}/api/v1/connect/test-auth`, {
        method: 'POST',
        body: JSON.stringify(payload),
      });
      const data = await res.json();
      if (mountedRef.current) {
        setAuthTestResult({
          success: res.ok && data.success !== false,
          message: data.message || (res.ok ? 'Authentication successful' : 'Authentication failed'),
        });
      }
    } catch (err) {
      if (mountedRef.current) {
        setAuthTestResult({ success: false, message: err.message || 'Test failed' });
      }
    } finally {
      if (mountedRef.current) setTestingAuth(false);
    }
  }, [connectorData.base_url, authType, authConfig, testCredential]);

  // Save connector
  const handleSave = useCallback(async () => {
    setSaving(true);
    setSaveError(null);
    setSaveSuccess(false);
    try {
      const payload = {
        ...connectorData,
        auth_type: authType,
        auth_config: authConfig,
        actions: actions.map(a => ({
          name: a.name,
          method: a.method,
          endpoint: a.endpoint,
          observable_type: a.observable_type,
          description: a.description,
          request_body: a.request_body || '',
          origin: a.origin || 'custom',
        })),
        visibility: 'private',
      };

      // Builtin/community connectors need the admin endpoint
      const isBuiltin = editConnector?.source === 'builtin' || editConnector?.source === 'community';
      let url, method;
      if (savedConnectorId && isBuiltin) {
        url = `${API_BASE_URL}/api/v1/connect/admin/connectors/${savedConnectorId}`;
        method = 'PUT';
      } else if (savedConnectorId) {
        url = `${API_BASE_URL}/api/v1/connect/connectors/${savedConnectorId}`;
        method = 'PUT';
      } else {
        url = `${API_BASE_URL}/api/v1/connect/connectors`;
        method = 'POST';
      }

      const res = await authFetch(url, {
        method,
        body: JSON.stringify(payload),
      });

      if (res.ok) {
        const data = await res.json();
        if (mountedRef.current) {
          setSavedConnectorId(data.id || savedConnectorId);
          setSaveSuccess(true);
          setTimeout(() => {
            if (mountedRef.current) setSaveSuccess(false);
          }, 3000);
          if (onConnectorCreated) onConnectorCreated(data);
        }
      } else {
        const errData = await res.json().catch(() => ({}));
        if (mountedRef.current) {
          setSaveError(errData.detail || 'Failed to save connector');
        }
      }
    } catch (err) {
      if (mountedRef.current) {
        setSaveError(err.message || 'Failed to save connector');
      }
    } finally {
      if (mountedRef.current) setSaving(false);
    }
  }, [connectorData, authType, authConfig, actions, savedConnectorId, onConnectorCreated]);

  // Submit to marketplace
  const handleSubmitToMarketplace = useCallback(async () => {
    if (!savedConnectorId) return;
    try {
      const res = await authFetch(`${API_BASE_URL}/api/v1/connect/connectors/${savedConnectorId}/submit`, {
        method: 'POST',
      });
      if (res.ok) {
        setSaveSuccess(true);
        setTimeout(() => {
          if (mountedRef.current) setSaveSuccess(false);
        }, 3000);
      } else {
        const errData = await res.json().catch(() => ({}));
        setSaveError(errData.detail || 'Failed to submit to marketplace');
      }
    } catch (err) {
      setSaveError(err.message || 'Submission failed');
    }
  }, [savedConnectorId]);

  // Export as JSON
  const handleExport = useCallback(async () => {
    if (!savedConnectorId) {
      // Export unsaved connector data
      const payload = {
        ...connectorData,
        auth_type: authType,
        auth_config: authConfig,
        actions,
      };
      const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${connectorData.name || 'connector'}.json`;
      a.click();
      URL.revokeObjectURL(url);
      return;
    }

    try {
      const res = await authFetch(`${API_BASE_URL}/api/v1/connect/connectors/${savedConnectorId}/export`);
      if (res.ok) {
        const data = await res.json();
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${connectorData.name || 'connector'}.json`;
        a.click();
        URL.revokeObjectURL(url);
      }
    } catch {
      setSaveError('Failed to export connector');
    }
  }, [savedConnectorId, connectorData, authType, authConfig, actions]);

  // Render auth config fields based on type
  const renderAuthConfig = () => {
    switch (authType) {
      case 'api_key':
        return (
          <>
            <div className="connect-form-group">
              <label className="connect-form-label">Header Name</label>
              <input
                className="connect-input"
                type="text"
                value={authConfig.header_name || ''}
                onChange={e => updateAuthConfig('header_name', e.target.value)}
                placeholder="e.g., X-API-Key or Authorization"
              />
            </div>
            <div className="connect-form-group">
              <label className="connect-form-label">Key Prefix (optional)</label>
              <input
                className="connect-input"
                type="text"
                value={authConfig.key_prefix || ''}
                onChange={e => updateAuthConfig('key_prefix', e.target.value)}
                placeholder="e.g., Bearer or ApiKey"
              />
            </div>
          </>
        );
      case 'oauth2_client':
        return (
          <>
            <div className="connect-form-group">
              <label className="connect-form-label">Token URL</label>
              <input
                className="connect-input"
                type="text"
                value={authConfig.token_url || ''}
                onChange={e => updateAuthConfig('token_url', e.target.value)}
                placeholder="https://api.example.com/oauth/token"
              />
            </div>
            <div className="connect-form-group">
              <label className="connect-form-label">Default Scope (optional)</label>
              <input
                className="connect-input"
                type="text"
                value={authConfig.scope || ''}
                onChange={e => updateAuthConfig('scope', e.target.value)}
                placeholder="read write"
              />
            </div>
          </>
        );
      case 'bearer':
      case 'basic':
      case 'custom_header':
      case 'none':
      default:
        return null;
    }
  };

  // Render test credential inputs
  const renderTestCredFields = () => {
    switch (authType) {
      case 'api_key':
        return (
          <div className="connect-form-group">
            <label className="connect-form-label">Test API Key</label>
            <input
              className="connect-input mono"
              type="password"
              value={testCredential.api_key || ''}
              onChange={e => setTestCredential(prev => ({ ...prev, api_key: e.target.value }))}
              placeholder="Enter API key for testing"
            />
          </div>
        );
      case 'bearer':
        return (
          <div className="connect-form-group">
            <label className="connect-form-label">Test Token</label>
            <input
              className="connect-input mono"
              type="password"
              value={testCredential.token || ''}
              onChange={e => setTestCredential(prev => ({ ...prev, token: e.target.value }))}
              placeholder="Enter token for testing"
            />
          </div>
        );
      case 'basic':
        return (
          <>
            <div className="connect-form-group">
              <label className="connect-form-label">Test Username</label>
              <input
                className="connect-input"
                type="text"
                value={testCredential.username || ''}
                onChange={e => setTestCredential(prev => ({ ...prev, username: e.target.value }))}
              />
            </div>
            <div className="connect-form-group">
              <label className="connect-form-label">Test Password</label>
              <input
                className="connect-input mono"
                type="password"
                value={testCredential.password || ''}
                onChange={e => setTestCredential(prev => ({ ...prev, password: e.target.value }))}
              />
            </div>
          </>
        );
      case 'oauth2_client':
        return (
          <>
            <div className="connect-form-group">
              <label className="connect-form-label">Test Client ID</label>
              <input
                className="connect-input"
                type="text"
                value={testCredential.client_id || ''}
                onChange={e => setTestCredential(prev => ({ ...prev, client_id: e.target.value }))}
              />
            </div>
            <div className="connect-form-group">
              <label className="connect-form-label">Test Client Secret</label>
              <input
                className="connect-input mono"
                type="password"
                value={testCredential.client_secret || ''}
                onChange={e => setTestCredential(prev => ({ ...prev, client_secret: e.target.value }))}
              />
            </div>
          </>
        );
      case 'custom_header':
        return (
          <div className="connect-form-group">
            <label className="connect-form-label">Test Headers (JSON)</label>
            <textarea
              className="connect-textarea"
              value={testCredential.headers_json || ''}
              onChange={e => setTestCredential(prev => ({ ...prev, headers_json: e.target.value }))}
              placeholder='{"X-API-Key": "test-key"}'
              rows={3}
            />
          </div>
        );
      default:
        return null;
    }
  };

  return (
    <div className="builder-container">
      {/* Basic Info Section */}
      <div className="builder-section">
        <div className="builder-section-header" onClick={() => toggleSection('info')}>
          <div className="builder-section-header-left">
            <h3>Basic Information</h3>
          </div>
          <span className={`builder-section-header-icon ${expandedSections.info ? 'expanded' : ''}`}>
            <ChevronDownIcon size={16} />
          </span>
        </div>
        {expandedSections.info && (
          <div className="builder-section-content">
            <div className="builder-form-grid">
              <div className="connect-form-group">
                <label className="connect-form-label">Connector Name *</label>
                <input
                  className="connect-input"
                  type="text"
                  value={connectorData.name}
                  onChange={e => updateConnectorField('name', e.target.value)}
                  placeholder="e.g., VirusTotal"
                />
              </div>
              <div className="connect-form-group">
                <label className="connect-form-label">Vendor</label>
                <input
                  className="connect-input"
                  type="text"
                  value={connectorData.vendor}
                  onChange={e => updateConnectorField('vendor', e.target.value)}
                  placeholder="e.g., Google"
                />
              </div>
              <div className="connect-form-group">
                <label className="connect-form-label">Category</label>
                <select
                  className="connect-select"
                  value={connectorData.category}
                  onChange={e => updateConnectorField('category', e.target.value)}
                >
                  <option value="">Select category...</option>
                  {CATEGORIES.map(cat => (
                    <option key={cat} value={cat}>{cat}</option>
                  ))}
                </select>
              </div>
              <div className="connect-form-group">
                <label className="connect-form-label">Base URL *</label>
                <input
                  className="connect-input mono"
                  type="text"
                  value={connectorData.base_url}
                  onChange={e => updateConnectorField('base_url', e.target.value)}
                  placeholder="https://api.example.com/v3"
                />
              </div>
              <div className="connect-form-group full-width">
                <label className="connect-form-label">Description</label>
                <textarea
                  className="connect-textarea"
                  value={connectorData.description}
                  onChange={e => updateConnectorField('description', e.target.value)}
                  placeholder="Brief description of what this connector does..."
                  rows={3}
                />
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Authentication Section */}
      <div className="builder-section">
        <div className="builder-section-header" onClick={() => toggleSection('auth')}>
          <div className="builder-section-header-left">
            <h3>Authentication</h3>
          </div>
          <span className={`builder-section-header-icon ${expandedSections.auth ? 'expanded' : ''}`}>
            <ChevronDownIcon size={16} />
          </span>
        </div>
        {expandedSections.auth && (
          <div className="builder-section-content">
            <div className="builder-form-grid">
              <div className="connect-form-group">
                <label className="connect-form-label">Auth Type</label>
                <select
                  className="connect-select"
                  value={authType}
                  onChange={e => {
                    setAuthType(e.target.value);
                    setAuthConfig({});
                    setTestCredential({});
                    setAuthTestResult(null);
                  }}
                >
                  {AUTH_TYPES.map(t => (
                    <option key={t.value} value={t.value}>{t.label}</option>
                  ))}
                </select>
              </div>
              {renderAuthConfig()}
            </div>

            {/* Test credential section */}
            {authType !== 'none' && (
              <div style={{ marginTop: '1rem', paddingTop: '1rem', borderTop: '1px solid var(--border-subtle, rgba(148, 163, 184, 0.08))' }}>
                <h4 style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary, #8b949e)', marginBottom: '0.75rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                  Test Credentials
                </h4>
                <div className="builder-form-grid">
                  {renderTestCredFields()}
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginTop: '0.75rem' }}>
                  <button
                    className="connect-btn connect-btn-outline connect-btn-sm"
                    onClick={handleTestAuth}
                    disabled={testingAuth}
                  >
                    {testingAuth ? <span className="connect-spinner sm" /> : <PlayIcon size={12} />}
                    Test Auth
                  </button>
                  {authTestResult && (
                    <span style={{
                      fontSize: '0.8rem',
                      color: authTestResult.success ? 'var(--accent-green, #10b981)' : 'var(--accent-red, #ef4444)',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '0.25rem',
                    }}>
                      {authTestResult.success ? <CheckIcon size={12} /> : <XIcon size={12} />}
                      {authTestResult.message}
                    </span>
                  )}
                </div>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Actions Section */}
      <div className="builder-section">
        <div className="builder-section-header" onClick={() => toggleSection('actions')}>
          <div className="builder-section-header-left">
            <h3>Actions ({actions.length})</h3>
          </div>
          <span className={`builder-section-header-icon ${expandedSections.actions ? 'expanded' : ''}`}>
            <ChevronDownIcon size={16} />
          </span>
        </div>
        {expandedSections.actions && (
          <div className="builder-section-content">
            {actions.length === 0 && (
              <div className="connect-empty" style={{ padding: '1.5rem' }}>
                <p style={{ margin: 0 }}>No actions defined yet. Add an action to get started.</p>
              </div>
            )}

            <div className="builder-actions-list">
              {actions.map(action => {
                const isEditing = editingActionId === action.id;
                const isTesting = testingActionId === action.id;
                const testResult = testResults.get(action.id);
                const pathParams = extractPathParams(action.endpoint || '');
                const isBuiltin = action.origin === 'builtin';

                return (
                  <div key={action.id} className={`builder-action-card ${action.origin || 'custom'}`}>
                    <div className="builder-action-header">
                      <div className="builder-action-header-left">
                        <h4 className="builder-action-name">
                          {action.name || '(unnamed action)'}
                          {isBuiltin && (
                            <span style={{ marginLeft: '0.5rem', opacity: 0.6 }}>
                              <LockIcon size={10} />
                            </span>
                          )}
                        </h4>
                        {action.description && (
                          <p className="builder-action-desc">{action.description}</p>
                        )}
                      </div>
                      <div className="builder-action-buttons">
                        <button
                          className="connect-btn connect-btn-outline connect-btn-sm"
                          onClick={() => handleToggleTest(action.id)}
                          title="Test"
                        >
                          <PlayIcon size={10} />
                          Test
                        </button>
                        <button
                          className="connect-btn connect-btn-outline connect-btn-sm"
                          onClick={() => handleCloneAction(action)}
                          title="Clone"
                        >
                          <CopyIcon size={10} />
                          Clone
                        </button>
                        {!isBuiltin && (
                          <>
                            <button
                              className="connect-btn connect-btn-outline connect-btn-sm"
                              onClick={() => handleEditAction(action)}
                              title="Edit"
                            >
                              <EditIcon size={10} />
                              Edit
                            </button>
                            <button
                              className="connect-btn-icon danger"
                              onClick={() => handleRemoveAction(action.id)}
                              title="Remove"
                            >
                              <TrashIcon size={12} />
                            </button>
                          </>
                        )}
                      </div>
                    </div>

                    <div className="builder-action-meta">
                      <span className={`badge badge-method badge-method-${(action.method || 'get').toLowerCase()}`}>
                        {action.method || 'GET'}
                      </span>
                      <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary, #8b949e)', fontFamily: 'monospace' }}>
                        {action.endpoint || '/'}
                      </span>
                      {action.observable_type && (
                        <span className="badge badge-category">{action.observable_type}</span>
                      )}
                      {action.request_body && action.request_body.trim() && (
                        <span className="badge" style={{
                          background: 'var(--color-info-bg, #1f3044)',
                          color: 'var(--color-info, #58a6ff)',
                          fontSize: '0.65rem',
                          padding: '1px 5px',
                        }}>BODY</span>
                      )}
                      <span className={`badge badge-origin badge-origin-${action.origin || 'custom'}`}>
                        {action.origin || 'custom'}
                      </span>
                    </div>

                    {/* Edit form */}
                    {isEditing && (
                      <div className="builder-action-edit">
                        <div className="builder-action-edit-grid">
                          <div className="connect-form-group">
                            <label className="connect-form-label">Action Name *</label>
                            <input
                              className="connect-input"
                              type="text"
                              value={editingActionData?.name || ''}
                              onChange={e => setEditingActionData(prev => ({ ...prev, name: e.target.value }))}
                              placeholder="e.g., Lookup IP"
                            />
                          </div>
                          <div className="connect-form-group">
                            <label className="connect-form-label">Method</label>
                            <select
                              className="connect-select"
                              value={editingActionData?.method || 'GET'}
                              onChange={e => setEditingActionData(prev => ({ ...prev, method: e.target.value }))}
                            >
                              {HTTP_METHODS.map(m => (
                                <option key={m} value={m}>{m}</option>
                              ))}
                            </select>
                          </div>
                          <div className="connect-form-group">
                            <label className="connect-form-label">Endpoint *</label>
                            <input
                              className="connect-input mono"
                              type="text"
                              value={editingActionData?.endpoint || ''}
                              onChange={e => setEditingActionData(prev => ({ ...prev, endpoint: e.target.value }))}
                              placeholder="/ip-address/{ip}/report"
                            />
                          </div>
                          <div className="connect-form-group">
                            <label className="connect-form-label">Observable Type</label>
                            <select
                              className="connect-select"
                              value={editingActionData?.observable_type || ''}
                              onChange={e => setEditingActionData(prev => ({ ...prev, observable_type: e.target.value }))}
                            >
                              {OBSERVABLE_TYPES.map(t => (
                                <option key={t} value={t}>{t || '(none)'}</option>
                              ))}
                            </select>
                          </div>
                          <div className="connect-form-group full-width">
                            <label className="connect-form-label">Description</label>
                            <input
                              className="connect-input"
                              type="text"
                              value={editingActionData?.description || ''}
                              onChange={e => setEditingActionData(prev => ({ ...prev, description: e.target.value }))}
                              placeholder="What does this action do?"
                            />
                          </div>
                          {/* Request Body — JSON editor with validation */}
                          {editingActionData?.method && editingActionData.method !== 'GET' && editingActionData.method !== 'DELETE' && (
                            <div className="connect-form-group full-width">
                              <label className="connect-form-label">Request Body (JSON)</label>
                              <div style={{ position: 'relative' }}>
                                <textarea
                                  className="connect-input mono"
                                  rows={6}
                                  value={editingActionData?.request_body || ''}
                                  onChange={e => setEditingActionData(prev => ({ ...prev, request_body: e.target.value }))}
                                  placeholder={'{\n  "key": "value"\n}'}
                                  spellCheck={false}
                                  style={{
                                    fontFamily: 'monospace',
                                    fontSize: '0.8rem',
                                    lineHeight: '1.4',
                                    resize: 'vertical',
                                    minHeight: '80px',
                                    tabSize: 2,
                                    borderColor: editingActionData?.request_body && validateJson(editingActionData.request_body)
                                      ? 'var(--color-danger, #f85149)' : undefined,
                                  }}
                                />
                                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginTop: '0.25rem' }}>
                                  <button
                                    type="button"
                                    className="connect-btn connect-btn-outline connect-btn-sm"
                                    style={{ fontSize: '0.7rem', padding: '2px 6px' }}
                                    onClick={() => setEditingActionData(prev => ({
                                      ...prev,
                                      request_body: formatJson(prev?.request_body || ''),
                                    }))}
                                    title="Format JSON"
                                  >
                                    Format
                                  </button>
                                  <button
                                    type="button"
                                    className="connect-btn connect-btn-outline connect-btn-sm"
                                    style={{ fontSize: '0.7rem', padding: '2px 6px' }}
                                    onClick={() => setEditingActionData(prev => ({
                                      ...prev,
                                      request_body: minifyJson(prev?.request_body || ''),
                                    }))}
                                    title="Minify JSON"
                                  >
                                    Minify
                                  </button>
                                  {editingActionData?.request_body && (
                                    <span style={{
                                      fontSize: '0.7rem',
                                      marginLeft: 'auto',
                                      color: validateJson(editingActionData.request_body)
                                        ? 'var(--color-danger, #f85149)'
                                        : 'var(--color-success, #3fb950)',
                                    }}>
                                      {validateJson(editingActionData.request_body) || 'Valid JSON'}
                                    </span>
                                  )}
                                </div>
                              </div>
                            </div>
                          )}
                        </div>
                        <div style={{ display: 'flex', gap: '0.5rem', justifyContent: 'flex-end', marginTop: '0.75rem' }}>
                          <button
                            className="connect-btn connect-btn-outline connect-btn-sm"
                            onClick={handleCancelActionEdit}
                          >
                            Cancel
                          </button>
                          <button
                            className="connect-btn connect-btn-primary connect-btn-sm"
                            onClick={handleSaveActionEdit}
                            disabled={!editingActionData?.name || !editingActionData?.endpoint}
                          >
                            Save Action
                          </button>
                        </div>
                      </div>
                    )}

                    {/* Test panel */}
                    {isTesting && (
                      <div className="builder-action-test">
                        {pathParams.length > 0 && (
                          <div className="builder-test-params">
                            {pathParams.map(param => (
                              <div key={param} className="builder-test-param">
                                <span className="builder-test-param-label">{param}</span>
                                <input
                                  className="connect-input"
                                  type="text"
                                  value={testParams[param] || ''}
                                  onChange={e => setTestParams(prev => ({ ...prev, [param]: e.target.value }))}
                                  placeholder={`Enter ${param}...`}
                                  style={{ flex: 1 }}
                                />
                              </div>
                            ))}
                          </div>
                        )}

                        <div className="builder-test-actions">
                          <button
                            className="connect-btn connect-btn-primary connect-btn-sm"
                            onClick={() => handleRunTest(action)}
                            disabled={testResult?.loading}
                          >
                            {testResult?.loading ? <span className="connect-spinner sm" /> : <PlayIcon size={10} />}
                            Run Test
                          </button>
                        </div>

                        {/* Test result */}
                        {testResult && !testResult.loading && (
                          <div className={`test-result ${testResult.success ? 'success' : 'failure'}`}>
                            <div className="test-result-header">
                              <span className={`test-result-status ${testResult.success ? 'success' : 'failure'}`}>
                                {testResult.success ? <CheckIcon size={12} /> : <XIcon size={12} />}
                                {' '}
                                {testResult.success ? 'Success' : 'Failed'}
                                {testResult.status_code ? ` (${testResult.status_code})` : ''}
                              </span>
                              {testResult.duration_ms && (
                                <span className="test-result-duration">{testResult.duration_ms}ms</span>
                              )}
                            </div>
                            {testResult.data && (
                              <pre className="test-result-code">
                                {typeof testResult.data === 'string'
                                  ? testResult.data
                                  : JSON.stringify(testResult.data, null, 2)}
                              </pre>
                            )}
                            {testResult.error && (
                              <pre className="test-result-code">{testResult.error}</pre>
                            )}
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>

            <div style={{ marginTop: '0.75rem' }}>
              <button
                className="connect-btn connect-btn-outline"
                onClick={handleAddAction}
              >
                <PlusIcon size={14} />
                Add Action
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Save Section */}
      <div className="builder-section">
        <div className="builder-section-header" onClick={() => toggleSection('save')}>
          <div className="builder-section-header-left">
            <h3>Save &amp; Export</h3>
          </div>
          <span className={`builder-section-header-icon ${expandedSections.save ? 'expanded' : ''}`}>
            <ChevronDownIcon size={16} />
          </span>
        </div>
        {expandedSections.save && (
          <div className="builder-section-content">
            {saveError && (
              <div className="connect-error" style={{ marginBottom: '0.75rem' }}>
                <span>{saveError}</span>
                <button className="connect-btn-icon" onClick={() => setSaveError(null)} style={{ marginLeft: 'auto' }}>
                  &times;
                </button>
              </div>
            )}

            {saveSuccess && (
              <div style={{
                padding: '0.5rem 0.75rem',
                background: 'rgba(16, 185, 129, 0.08)',
                border: '1px solid rgba(16, 185, 129, 0.25)',
                borderRadius: '8px',
                color: 'var(--accent-green, #10b981)',
                fontSize: '0.85rem',
                marginBottom: '0.75rem',
                display: 'flex',
                alignItems: 'center',
                gap: '0.5rem',
              }}>
                <CheckIcon size={14} />
                Connector saved successfully!
              </div>
            )}

            <div className="builder-save-actions">
              <button
                className="connect-btn connect-btn-primary"
                onClick={handleSave}
                disabled={saving || !connectorData.name || !connectorData.base_url}
              >
                {saving ? <span className="connect-spinner sm" /> : <SaveIcon size={14} />}
                {savedConnectorId ? 'Update Connector' : 'Save as Private'}
              </button>

              {savedConnectorId && (
                <button
                  className="connect-btn connect-btn-success"
                  onClick={handleSubmitToMarketplace}
                >
                  Submit to Marketplace
                </button>
              )}

              <button
                className="connect-btn connect-btn-outline"
                onClick={handleExport}
              >
                <DownloadIcon size={14} />
                Export as JSON
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
