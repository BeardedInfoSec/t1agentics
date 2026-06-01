/**
 * Copyright (c) 2025-2026 T1 Agentics LLC. SPDX-License-Identifier: Apache-2.0
 */

/**
 * T1 Connect - Main Container
 * Tabbed interface for managing integrations, marketplace, credentials, and custom builders.
 */

import React, { useState, useEffect, useCallback, useRef } from 'react';
import { useSearchParams } from 'react-router-dom';
import ConnectMarketplace from './ConnectMarketplace';
import ConnectMyConnections from './ConnectMyConnections';
import ConnectSetupWizard from './ConnectSetupWizard';
import ConnectBuilder from './ConnectBuilder';
import WebhookManager from '../WebhookManager';
import { authFetch, API_BASE_URL } from '../../utils/api';
import './Connect.css';

// SVG icons
const PlugIcon = ({ size = 20 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M12 22v-5" /><path d="M9 8V2" /><path d="M15 8V2" />
    <path d="M18 8v5a6 6 0 0 1-12 0V8h12z" />
  </svg>
);

const PlusIcon = ({ size = 16 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M12 5v14" /><path d="M5 12h14" />
  </svg>
);

const GridIcon = ({ size = 16 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <rect x="3" y="3" width="7" height="7" /><rect x="14" y="3" width="7" height="7" />
    <rect x="3" y="14" width="7" height="7" /><rect x="14" y="14" width="7" height="7" />
  </svg>
);

const LinkIcon = ({ size = 16 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71" />
    <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71" />
  </svg>
);

const KeyIcon = ({ size = 16 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4" />
  </svg>
);

const WebhookIcon = ({ size = 16 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M18 16.98h-5.99c-1.1 0-1.95.94-2.48 1.9A4 4 0 0 1 2 17c.01-.7.2-1.4.57-2" />
    <path d="m6 17 3.13-5.78c.53-.97.1-2.18-.5-3.1a4 4 0 1 1 6.89-4.06" />
    <path d="m12 6 3.13 5.73C15.66 12.7 16.9 13 18 13a4 4 0 0 1 0 8H17" />
  </svg>
);

const WrenchIcon = ({ size = 16 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z" />
  </svg>
);

const TrashIcon = ({ size = 16 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M3 6h18" /><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6" />
    <path d="M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2" />
  </svg>
);

const TABS = [
  { id: 'connections', label: 'My Connections', icon: LinkIcon },
  { id: 'marketplace', label: 'Marketplace', icon: GridIcon },
  { id: 'webhooks', label: 'Webhooks', icon: WebhookIcon },
  { id: 'credentials', label: 'Credentials', icon: KeyIcon },
  { id: 'builder', label: 'Build', icon: WrenchIcon, adminOnly: true },
];

const VALID_TABS = new Set(TABS.map(t => t.id));

export default function Connect({ user }) {
  const [searchParams, setSearchParams] = useSearchParams();
  const initialTab = VALID_TABS.has(searchParams.get('tab')) ? searchParams.get('tab') : 'connections';
  const [activeTab, setActiveTabState] = useState(initialTab);

  const setActiveTab = useCallback((tab) => {
    setActiveTabState(tab);
    setSearchParams(tab === 'connections' ? {} : { tab }, { replace: true });
  }, [setSearchParams]);

  // Sync activeTab when URL search params change (e.g., nav link clicks)
  useEffect(() => {
    const tabParam = searchParams.get('tab');
    const newTab = VALID_TABS.has(tabParam) ? tabParam : 'connections';
    setActiveTabState(newTab);
  }, [searchParams]);

  const [setupWizard, setSetupWizard] = useState({ open: false, connector: null });
  const [credentials, setCredentials] = useState([]);
  const [instances, setInstances] = useState([]);
  const [healthSummary, setHealthSummary] = useState({ healthy: 0, degraded: 0, down: 0, unknown: 0 });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [credLoading, setCredLoading] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(null);
  const [showAddCred, setShowAddCred] = useState(false);
  const [addCredForm, setAddCredForm] = useState({
    name: '', auth_type: 'api_key', secret_data: {}, tags: ''
  });
  const [addCredError, setAddCredError] = useState(null);
  const [addCredSaving, setAddCredSaving] = useState(false);
  const mountedRef = useRef(true);

  useEffect(() => {
    mountedRef.current = true;
    return () => { mountedRef.current = false; };
  }, []);

  // Fetch instances
  const fetchInstances = useCallback(async () => {
    try {
      const res = await authFetch(`${API_BASE_URL}/api/v1/connect/instances`);
      if (!mountedRef.current) return;
      if (res.ok) {
        const data = await res.json();
        setInstances(data.instances || data || []);
      }
    } catch (err) {
      if (mountedRef.current) setError('Failed to load connections');
    }
  }, []);

  // Fetch credentials
  const fetchCredentials = useCallback(async () => {
    try {
      const res = await authFetch(`${API_BASE_URL}/api/v1/connect/credentials`);
      if (!mountedRef.current) return;
      if (res.ok) {
        const data = await res.json();
        setCredentials(data.credentials || data || []);
      }
    } catch (err) {
      if (mountedRef.current) setError('Failed to load credentials');
    }
  }, []);

  // Fetch health summary
  const fetchHealthSummary = useCallback(async () => {
    try {
      const res = await authFetch(`${API_BASE_URL}/api/v1/connect/health`);
      if (!mountedRef.current) return;
      if (res.ok) {
        const data = await res.json();
        setHealthSummary(data);
      }
    } catch {
      // Health summary is optional, don't error
    }
  }, []);

  // Load all data on mount
  useEffect(() => {
    const loadAll = async () => {
      setLoading(true);
      await Promise.all([fetchInstances(), fetchCredentials(), fetchHealthSummary()]);
      if (mountedRef.current) setLoading(false);
    };
    loadAll();
  }, [fetchInstances, fetchCredentials, fetchHealthSummary]);

  // Handle install from marketplace
  const handleInstall = useCallback((connector) => {
    setSetupWizard({ open: true, connector });
  }, []);

  // Handle wizard complete
  const handleWizardComplete = useCallback(async () => {
    setSetupWizard({ open: false, connector: null });
    setActiveTab('connections');
    await Promise.all([fetchInstances(), fetchCredentials(), fetchHealthSummary()]);
  }, [fetchInstances, fetchCredentials, fetchHealthSummary]);

  // Handle wizard close
  const handleWizardClose = useCallback(() => {
    setSetupWizard({ open: false, connector: null });
  }, []);

  // Handle credential created in wizard
  const handleCredentialCreated = useCallback((cred) => {
    setCredentials(prev => [...prev, cred]);
  }, []);

  // Handle add connection button
  const handleAddConnection = useCallback(() => {
    setActiveTab('marketplace');
  }, []);

  // Handle refresh instances
  const handleRefreshInstances = useCallback(async () => {
    await Promise.all([fetchInstances(), fetchHealthSummary()]);
  }, [fetchInstances, fetchHealthSummary]);

  // Handle builder connector created
  const handleConnectorCreated = useCallback(() => {
    // Switch to marketplace to see new connector
    setActiveTab('marketplace');
  }, []);

  // Delete credential
  const handleDeleteCredential = useCallback(async (credId) => {
    try {
      const res = await authFetch(`${API_BASE_URL}/api/v1/connect/credentials/${credId}`, {
        method: 'DELETE',
      });
      if (res.ok) {
        setCredentials(prev => prev.filter(c => c.id !== credId));
      } else {
        const data = await res.json().catch(() => ({}));
        setError(data.detail || 'Failed to delete credential');
      }
    } catch {
      setError('Failed to delete credential');
    }
    setConfirmDelete(null);
  }, []);

  // Auth type definitions for add credential form
  const AUTH_TYPES = [
    { id: 'api_key', label: 'API Key', fields: [
      { key: 'api_key', label: 'API Key', type: 'password', required: true },
      { key: 'api_key_header', label: 'Header Name', type: 'text', placeholder: 'X-API-Key' },
    ]},
    { id: 'bearer', label: 'Bearer Token', fields: [
      { key: 'bearer_token', label: 'Bearer Token', type: 'password', required: true },
    ]},
    { id: 'basic', label: 'Basic Auth', fields: [
      { key: 'username', label: 'Username', type: 'text', required: true },
      { key: 'password', label: 'Password', type: 'password', required: true },
    ]},
    { id: 'oauth2_client', label: 'OAuth2 Client Credentials', fields: [
      { key: 'client_id', label: 'Client ID', type: 'text', required: true },
      { key: 'client_secret', label: 'Client Secret', type: 'password', required: true },
      { key: 'token_url', label: 'Token URL', type: 'text', required: true },
      { key: 'scope', label: 'Scope', type: 'text' },
    ]},
    { id: 'custom_header', label: 'Custom Headers', fields: [
      { key: 'header_name', label: 'Header Name', type: 'text', required: true },
      { key: 'header_value', label: 'Header Value', type: 'password', required: true },
    ]},
  ];

  const getAuthTypeFields = (authType) => {
    return AUTH_TYPES.find(t => t.id === authType)?.fields || [];
  };

  // Open add credential modal
  const handleOpenAddCred = useCallback(() => {
    setAddCredForm({ name: '', auth_type: 'api_key', secret_data: {}, tags: '' });
    setAddCredError(null);
    setShowAddCred(true);
  }, []);

  // Handle form field changes
  const handleCredFormChange = useCallback((field, value) => {
    setAddCredForm(prev => ({ ...prev, [field]: value }));
  }, []);

  // Handle secret_data field changes
  const handleSecretFieldChange = useCallback((key, value) => {
    setAddCredForm(prev => ({
      ...prev,
      secret_data: { ...prev.secret_data, [key]: value }
    }));
  }, []);

  // Submit new credential
  const handleCreateCredential = useCallback(async () => {
    setAddCredError(null);
    if (!addCredForm.name.trim()) {
      setAddCredError('Name is required');
      return;
    }
    const fields = getAuthTypeFields(addCredForm.auth_type);
    const requiredFields = fields.filter(f => f.required);
    for (const f of requiredFields) {
      if (!addCredForm.secret_data[f.key]?.trim()) {
        setAddCredError(`${f.label} is required`);
        return;
      }
    }

    setAddCredSaving(true);
    try {
      const tags = addCredForm.tags
        ? addCredForm.tags.split(',').map(t => t.trim()).filter(Boolean)
        : [];
      const res = await authFetch(`${API_BASE_URL}/api/v1/connect/credentials`, {
        method: 'POST',
        body: JSON.stringify({
          name: addCredForm.name.trim(),
          auth_type: addCredForm.auth_type,
          secret_data: addCredForm.secret_data,
          tags: tags.length > 0 ? tags : undefined,
        }),
      });
      if (res.ok) {
        setShowAddCred(false);
        await fetchCredentials();
      } else {
        const data = await res.json().catch(() => ({}));
        setAddCredError(data.detail || 'Failed to create credential');
      }
    } catch {
      setAddCredError('Failed to create credential');
    } finally {
      if (mountedRef.current) setAddCredSaving(false);
    }
  }, [addCredForm, fetchCredentials]);

  // Compute health counts from instances if summary not available
  const health = {
    healthy: healthSummary.healthy || instances.filter(i => i.health_status === 'healthy').length,
    degraded: healthSummary.degraded || instances.filter(i => i.health_status === 'degraded').length,
    down: healthSummary.down || instances.filter(i => i.health_status === 'down').length,
    unknown: healthSummary.unknown || instances.filter(i => !i.health_status || i.health_status === 'unknown').length,
  };

  const visibleTabs = TABS.filter(t => !t.adminOnly || user?.role === 'admin' || user?.role === 'platform_owner');

  const formatAuthType = (type) => {
    const map = {
      api_key: 'API Key', bearer: 'Bearer', basic: 'Basic Auth',
      oauth2_client: 'OAuth2', custom_header: 'Custom', none: 'None',
    };
    return map[type] || type || 'Unknown';
  };

  const formatDate = (dateStr) => {
    if (!dateStr) return 'Never';
    const d = new Date(dateStr);
    return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
  };

  return (
    <div className="connect-container">
      {/* Header */}
      <div className="connect-header">
        <div className="connect-header-left">
          <div className="connect-header-icon">
            <PlugIcon size={20} />
          </div>
          <div>
            <h1 className="connect-title">T1 Connect</h1>
            <p className="connect-subtitle">Integration Management</p>
          </div>
        </div>
        <div className="connect-header-actions">
          <button className="connect-btn connect-btn-primary" onClick={handleAddConnection}>
            <PlusIcon size={14} />
            Add Connection
          </button>
        </div>
      </div>

      {/* Error banner */}
      {error && (
        <div className="connect-error">
          <span>{error}</span>
          <button
            className="connect-btn-icon"
            onClick={() => setError(null)}
            style={{ marginLeft: 'auto' }}
          >
            &times;
          </button>
        </div>
      )}

      {/* Tabs */}
      <nav className="connect-tabs">
        {visibleTabs.map(tab => (
          <button
            key={tab.id}
            className={`connect-tab ${activeTab === tab.id ? 'active' : ''}`}
            onClick={() => setActiveTab(tab.id)}
            data-tour={`connect-tab-${tab.id}`}
          >
            <tab.icon size={15} />
            <span>{tab.label}</span>
            {tab.id === 'connections' && instances.length > 0 && (
              <span className="connect-tab-badge">{instances.length}</span>
            )}
          </button>
        ))}
      </nav>

      {/* Tab content */}
      <div className="connect-tab-content">
      {loading && (
        <div className="connect-loading">
          <div className="connect-spinner lg" />
          <p>Loading connections...</p>
        </div>
      )}

      {!loading && (
        <>
          {/* Health bar for connections tab */}
          {activeTab === 'connections' && instances.length > 0 && (
            <div className="connect-health-bar">
              <div className="connect-health-item">
                <span className="health-dot healthy" />
                <span className="health-count">{health.healthy}</span>
                <span className="health-label">Healthy</span>
              </div>
              <div className="connect-health-item">
                <span className="health-dot degraded" />
                <span className="health-count">{health.degraded}</span>
                <span className="health-label">Degraded</span>
              </div>
              <div className="connect-health-item">
                <span className="health-dot down" />
                <span className="health-count">{health.down}</span>
                <span className="health-label">Down</span>
              </div>
              <div className="connect-health-item">
                <span className="health-dot unknown" />
                <span className="health-count">{health.unknown}</span>
                <span className="health-label">Not Tested</span>
              </div>
            </div>
          )}

          {activeTab === 'connections' && (
            <ConnectMyConnections
              instances={instances}
              onRefresh={handleRefreshInstances}
              user={user}
            />
          )}

          {activeTab === 'marketplace' && (
            <ConnectMarketplace
              onInstall={handleInstall}
              user={user}
            />
          )}

          {activeTab === 'webhooks' && (
              <WebhookManager />
          )}

          {activeTab === 'credentials' && (
            <div className="credentials-container">
              <div className="credentials-toolbar">
                <span style={{ fontSize: '0.85rem', color: 'var(--text-secondary, #8b949e)' }}>
                  {credentials.length} credential{credentials.length !== 1 ? 's' : ''} stored
                </span>
                <div style={{ display: 'flex', gap: '0.5rem' }}>
                  <button
                    className="connect-btn connect-btn-outline connect-btn-sm"
                    onClick={fetchCredentials}
                    disabled={credLoading}
                  >
                    {credLoading ? <span className="connect-spinner sm" /> : 'Refresh'}
                  </button>
                  <button
                    className="connect-btn connect-btn-primary connect-btn-sm"
                    onClick={handleOpenAddCred}
                  >
                    <PlusIcon size={14} />
                    Add Credential
                  </button>
                </div>
              </div>

              {credentials.length === 0 ? (
                <div className="connect-empty">
                  <div className="connect-empty-icon">
                    <KeyIcon size={24} />
                  </div>
                  <h3>No credentials stored</h3>
                  <p>Add credentials to authenticate your integrations, or create them when setting up connections through the Marketplace.</p>
                  <button
                    className="connect-btn connect-btn-primary"
                    onClick={handleOpenAddCred}
                    style={{ marginTop: '0.75rem' }}
                  >
                    <PlusIcon size={14} />
                    Add Credential
                  </button>
                </div>
              ) : (
                credentials.map(cred => (
                  <div key={cred.id} className="credential-card">
                    <div className="credential-card-info">
                      <div className="credential-card-name">{cred.name}</div>
                      <div className="credential-card-meta">
                        <span className="badge badge-auth">{formatAuthType(cred.auth_type)}</span>
                        <span>Created {formatDate(cred.created_at)}</span>
                        {cred.connector_name && <span>Used by: {cred.connector_name}</span>}
                      </div>
                    </div>
                    <div className="credential-card-actions">
                      {(user?.role === 'admin' || user?.role === 'platform_owner') && (
                        <button
                          className="connect-btn-icon danger"
                          title="Delete credential"
                          onClick={() => setConfirmDelete(cred)}
                        >
                          <TrashIcon size={14} />
                        </button>
                      )}
                    </div>
                  </div>
                ))
              )}
            </div>
          )}

          {activeTab === 'builder' && (user?.role === 'admin' || user?.role === 'platform_owner') && (
            <ConnectBuilder
              user={user}
              onConnectorCreated={handleConnectorCreated}
            />
          )}
        </>
      )}
      </div>

      {/* Setup Wizard Modal */}
      {setupWizard.open && setupWizard.connector && (
        <ConnectSetupWizard
          connector={setupWizard.connector}
          onComplete={handleWizardComplete}
          onClose={handleWizardClose}
          credentials={credentials}
          onCredentialCreated={handleCredentialCreated}
        />
      )}

      {/* Add Credential Modal */}
      {showAddCred && (
        <div className="connect-confirm-overlay" onClick={() => setShowAddCred(false)}>
          <div className="add-cred-dialog" onClick={e => e.stopPropagation()}>
            <h3>Add Credential</h3>
            <p style={{ marginBottom: '1rem', fontSize: '0.8rem', color: 'var(--text-secondary, #8b949e)' }}>
              Store authentication credentials for your integrations. Secrets are encrypted at rest.
            </p>

            {addCredError && (
              <div className="add-cred-error">{addCredError}</div>
            )}

            <div className="add-cred-field">
              <label className="add-cred-label">Name</label>
              <input
                className="add-cred-input"
                type="text"
                placeholder="e.g. CrowdStrike API Key"
                value={addCredForm.name}
                onChange={e => handleCredFormChange('name', e.target.value)}
                autoFocus
              />
            </div>

            <div className="add-cred-field">
              <label className="add-cred-label">Auth Type</label>
              <select
                className="add-cred-input"
                value={addCredForm.auth_type}
                onChange={e => {
                  handleCredFormChange('auth_type', e.target.value);
                  handleCredFormChange('secret_data', {});
                }}
              >
                {AUTH_TYPES.map(t => (
                  <option key={t.id} value={t.id}>{t.label}</option>
                ))}
              </select>
            </div>

            {getAuthTypeFields(addCredForm.auth_type).map(field => (
              <div className="add-cred-field" key={field.key}>
                <label className="add-cred-label">
                  {field.label}{field.required ? ' *' : ''}
                </label>
                <input
                  className="add-cred-input"
                  type={field.type}
                  placeholder={field.placeholder || ''}
                  value={addCredForm.secret_data[field.key] || ''}
                  onChange={e => handleSecretFieldChange(field.key, e.target.value)}
                />
              </div>
            ))}

            <div className="add-cred-field">
              <label className="add-cred-label">Tags (comma-separated, optional)</label>
              <input
                className="add-cred-input"
                type="text"
                placeholder="e.g. production, siem"
                value={addCredForm.tags}
                onChange={e => handleCredFormChange('tags', e.target.value)}
              />
            </div>

            <div className="connect-confirm-actions" style={{ marginTop: '1.25rem' }}>
              <button
                className="connect-btn connect-btn-outline"
                onClick={() => setShowAddCred(false)}
                disabled={addCredSaving}
              >
                Cancel
              </button>
              <button
                className="connect-btn connect-btn-primary"
                onClick={handleCreateCredential}
                disabled={addCredSaving}
              >
                {addCredSaving ? <span className="connect-spinner sm" /> : 'Create Credential'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Delete credential confirm dialog */}
      {confirmDelete && (
        <div className="connect-confirm-overlay" onClick={() => setConfirmDelete(null)}>
          <div className="connect-confirm-dialog" onClick={e => e.stopPropagation()}>
            <h3>Delete Credential</h3>
            <p>
              Are you sure you want to delete "{confirmDelete.name}"?
              This may break active connections using this credential.
            </p>
            <div className="connect-confirm-actions">
              <button className="connect-btn connect-btn-outline" onClick={() => setConfirmDelete(null)}>
                Cancel
              </button>
              <button className="connect-btn connect-btn-danger" onClick={() => handleDeleteCredential(confirmDelete.id)}>
                Delete
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
