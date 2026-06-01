/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

import React, { useState, useEffect } from 'react';
import { useToast } from '../ui/Toast';
import { API_BASE_URL, getAuthHeaders, getActionButtonStyle, getBadgeStyle, authFetch } from './settingsUtils';

const initialProviderState = {
  name: '',
  provider_type: 'openai_compatible',
  base_url: 'http://localhost:1234/v1',
  api_key: '',
  models: [],
  selected_model: '',
  tier1_model: '',
  tier2_model: '',
  tier3_model: '',
  chat_model: '',
  is_default: false,
  enabled: true
};

function AIProvidersSettings() {
  const toast = useToast();
  const [aiProviders, setAiProviders] = useState([]);
  const [loadingProviders, setLoadingProviders] = useState(true);
  const [testingProvider, setTestingProvider] = useState(null);
  const [showAddProvider, setShowAddProvider] = useState(false);
  const [editingProvider, setEditingProvider] = useState(null);
  const [newProvider, setNewProvider] = useState(initialProviderState);
  const [newModelName, setNewModelName] = useState('');

  useEffect(() => { fetchAiProviders(); }, []);

  const fetchAiProviders = async () => {
    try { setLoadingProviders(true); const r = await authFetch(`${API_BASE_URL}/api/v1/ai-providers`, { headers: getAuthHeaders() }); if (r.ok) setAiProviders((await r.json()).providers || []); } catch (e) { console.error('AI providers fetch error:', e); } finally { setLoadingProviders(false); }
  };

  const openEditProvider = (provider) => {
    setEditingProvider(provider.id);
    setNewProvider({
      name: provider.name, provider_type: provider.provider_type, base_url: provider.base_url,
      api_key: '', models: provider.models || [], selected_model: provider.selected_model || '',
      tier1_model: provider.tier1_model || '', tier2_model: provider.tier2_model || '',
      tier3_model: provider.tier3_model || '', chat_model: provider.chat_model || '',
      is_default: provider.is_default, enabled: provider.enabled
    });
    setShowAddProvider(true);
  };

  const closeProviderModal = () => { setShowAddProvider(false); setEditingProvider(null); setNewProvider(initialProviderState); setNewModelName(''); };

  const saveAiProvider = async (e) => {
    e.preventDefault();
    try {
      let response;
      if (editingProvider) {
        const updateData = { ...newProvider };
        if (!updateData.api_key) delete updateData.api_key;
        response = await authFetch(`${API_BASE_URL}/api/v1/ai-providers/${editingProvider}`, { method: 'PATCH', headers: getAuthHeaders(), body: JSON.stringify(updateData) });
      } else {
        response = await authFetch(`${API_BASE_URL}/api/v1/ai-providers`, { method: 'POST', headers: getAuthHeaders(), body: JSON.stringify(newProvider) });
      }
      if (response.ok) { await fetchAiProviders(); closeProviderModal(); }
      else { const err = await response.json(); toast.error(err.detail || 'Failed to save provider'); }
    } catch (error) { toast.error('Failed to save provider'); }
  };

  const deleteAiProvider = async (providerId) => {
    if (!window.confirm('Delete this AI provider?')) return;
    try { const r = await authFetch(`${API_BASE_URL}/api/v1/ai-providers/${providerId}`, { method: 'DELETE', headers: getAuthHeaders() }); if (r.ok) await fetchAiProviders(); } catch (e) { console.error('AI provider delete error:', e); }
  };

  const toggleProviderEnabled = async (providerId, currentEnabled) => {
    try { const r = await authFetch(`${API_BASE_URL}/api/v1/ai-providers/${providerId}`, { method: 'PATCH', headers: getAuthHeaders(), body: JSON.stringify({ enabled: !currentEnabled }) }); if (r.ok) await fetchAiProviders(); } catch (e) { console.error('AI provider toggle error:', e); }
  };

  const setDefaultProvider = async (providerId) => {
    try { const r = await authFetch(`${API_BASE_URL}/api/v1/ai-providers/${providerId}/set-default`, { method: 'POST', headers: getAuthHeaders() }); if (r.ok) await fetchAiProviders(); } catch (e) { console.error('AI provider set-default error:', e); }
  };

  const testAiProvider = async (providerId) => {
    setTestingProvider(providerId);
    try {
      const r = await authFetch(`${API_BASE_URL}/api/v1/ai-providers/${providerId}/test`, { method: 'POST', headers: getAuthHeaders() });
      const result = await r.json();
      if (result.success) toast.success(`Connection successful! Models available: ${result.models?.length || 0}`);
      else toast.error(`Connection failed: ${result.error || 'Unknown error'}`);
    } catch (error) { toast.error(`Connection failed: ${error.message}`); }
    finally { setTestingProvider(null); }
  };

  const fetchProviderModels = async (providerId) => {
    setTestingProvider(providerId);
    try {
      const r = await authFetch(`${API_BASE_URL}/api/v1/ai-providers/${providerId}/fetch-models`, { method: 'POST', headers: getAuthHeaders() });
      const result = await r.json();
      if (result.success) { await fetchAiProviders(); toast.success(`Fetched ${result.count || 0} models from provider`); }
      else toast.error(`Failed to fetch models: ${result.error || 'Unknown error'}`);
    } catch (error) { toast.error(`Failed to fetch models: ${error.message}`); }
    finally { setTestingProvider(null); }
  };

  const addModelToProvider = () => {
    if (newModelName.trim()) {
      setNewProvider({ ...newProvider, models: [...newProvider.models, { id: newModelName.trim(), name: newModelName.trim() }] });
      setNewModelName('');
    }
  };

  const removeModelFromProvider = (modelId) => {
    setNewProvider({ ...newProvider, models: newProvider.models.filter(m => m.id !== modelId) });
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
      {/* Provider List */}
      <div className="settings-card">
        <div className="settings-card-header">
          <div>
            <h3 className="settings-card-title">AI Provider Configuration</h3>
            <p className="settings-card-desc">Configure AI providers for your agents (LM Studio, Anthropic, OpenAI, etc.)</p>
          </div>
          <button onClick={() => setShowAddProvider(true)} className="button button-primary">+ Add Provider</button>
        </div>

        {loadingProviders ? (
          <div className="settings-loading"><div className="spinner"></div></div>
        ) : aiProviders.length === 0 ? (
          <div className="settings-empty">
            <div className="settings-empty-title">No AI providers configured</div>
            <p className="settings-empty-desc">Add a provider to enable AI agents. Supports LM Studio, Anthropic, OpenAI, and any OpenAI-compatible API.</p>
            <button onClick={() => setShowAddProvider(true)} className="button button-primary" style={{ marginTop: '1rem' }}>+ Add Your First Provider</button>
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
            {aiProviders.map((provider) => (
              <ProviderCard
                key={provider.id} provider={provider} testingProvider={testingProvider}
                onEdit={() => openEditProvider(provider)}
                onDelete={() => deleteAiProvider(provider.id)}
                onToggle={() => toggleProviderEnabled(provider.id, provider.enabled)}
                onSetDefault={() => setDefaultProvider(provider.id)}
                onTest={() => testAiProvider(provider.id)}
                onFetchModels={() => fetchProviderModels(provider.id)}
              />
            ))}
          </div>
        )}
      </div>

      {/* Add/Edit Provider Modal */}
      {showAddProvider && (
        <ProviderModal
          editingProvider={editingProvider} newProvider={newProvider} setNewProvider={setNewProvider}
          newModelName={newModelName} setNewModelName={setNewModelName}
          onSave={saveAiProvider} onClose={closeProviderModal}
          onAddModel={addModelToProvider} onRemoveModel={removeModelFromProvider}
        />
      )}

      {/* Quick Start Guide */}
      <div className="settings-card">
        <h3 className="settings-card-title" style={{ marginBottom: '1rem' }}>Quick Start Guide</h3>
        <div className="settings-guide-grid">
          <GuideCard title="LM Studio (Local)" steps={[
            'Download LM Studio from lmstudio.ai',
            'Load a model (e.g., Llama 3.2)',
            'Start the local server (default port 1234)',
            'Add provider with URL: http://localhost:1234/v1'
          ]} />
          <GuideCard title="Anthropic (Claude)" steps={[
            'Get API key from console.anthropic.com',
            'Select "Anthropic" provider type',
            'Enter your API key',
            'Add models: claude-sonnet-4-20250514, etc.'
          ]} />
          <GuideCard title="OpenAI" steps={[
            'Get API key from platform.openai.com',
            'Select "OpenAI" provider type',
            'Enter your API key',
            'Add models: gpt-4, gpt-4-turbo, etc.'
          ]} />
        </div>
      </div>
    </div>
  );
}

// ── Provider Card ──
function ProviderCard({ provider, testingProvider, onEdit, onDelete, onToggle, onSetDefault, onTest, onFetchModels }) {
  return (
    <div className={`settings-feature-card ${provider.is_default ? 'settings-feature-card--active' : ''} ${!provider.enabled ? 'settings-feature-card--disabled' : ''}`}>
      <div className="settings-feature-card-info">
        <div className="settings-feature-card-name">
          {provider.name}
          {provider.is_default && <span style={getBadgeStyle('primary')}>DEFAULT</span>}
          {!provider.enabled && <span style={getBadgeStyle('gray')}>DISABLED</span>}
        </div>
        <div className="settings-feature-card-meta">
          <span className="settings-type-chip" style={{ marginRight: '0.5rem' }}>{provider.provider_type}</span>
          {provider.base_url}
        </div>
        <ModelBadges provider={provider} />
      </div>
      <div className="settings-feature-card-actions">
        <button onClick={onEdit} style={getActionButtonStyle('purple')}>Configure</button>
        <button onClick={onFetchModels} disabled={testingProvider === provider.id} style={getActionButtonStyle('green')}>Fetch Models</button>
        <button onClick={onTest} disabled={testingProvider === provider.id} style={getActionButtonStyle('blue')}>
          {testingProvider === provider.id ? 'Testing...' : 'Test'}
        </button>
        {!provider.is_default && provider.enabled && (
          <button onClick={onSetDefault} style={getActionButtonStyle('primary')}>Set Default</button>
        )}
        <button onClick={onToggle} style={getActionButtonStyle(provider.enabled ? 'yellow' : 'green')}>
          {provider.enabled ? 'Disable' : 'Enable'}
        </button>
        <button onClick={onDelete} style={getActionButtonStyle('red')}>Delete</button>
      </div>
    </div>
  );
}

// ── Model Badges ──
function ModelBadges({ provider }) {
  const hasTierModels = provider.tier1_model || provider.tier2_model || provider.tier3_model || provider.chat_model || provider.selected_model;

  if (!hasTierModels) {
    if (provider.models?.length > 0) {
      return (
        <div style={{ ...getBadgeStyle('yellow'), padding: '0.4rem 0.65rem', fontSize: '0.75rem' }}>
          No models configured - click Configure to select models ({provider.models.length} available)
        </div>
      );
    }
    return (
      <div style={{ padding: '0.4rem 0.65rem', background: 'var(--bg-secondary)', border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-sm)', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
        No models - click Fetch Models to discover available models
      </div>
    );
  }

  return (
    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.35rem', alignItems: 'center', marginTop: '0.25rem' }}>
      {provider.tier1_model && <span style={getBadgeStyle('yellow')}><strong>T1:</strong> {provider.tier1_model}</span>}
      {provider.tier2_model && <span style={getBadgeStyle('green')}><strong>T2:</strong> {provider.tier2_model}</span>}
      {provider.tier3_model && <span style={getBadgeStyle('red')}><strong>T3:</strong> {provider.tier3_model}</span>}
      {provider.chat_model && <span style={getBadgeStyle('cyan')}><strong>Chat:</strong> {provider.chat_model}</span>}
      {provider.selected_model && !provider.tier1_model && !provider.tier2_model && !provider.tier3_model && (
        <span style={getBadgeStyle('green')}><strong>Default:</strong> {provider.selected_model}</span>
      )}
      {provider.models?.length > 0 && (
        <span style={{ fontSize: '0.65rem', color: 'var(--text-muted)' }}>({provider.models.length} available)</span>
      )}
    </div>
  );
}

// ── Provider Modal ──
function ProviderModal({ editingProvider, newProvider, setNewProvider, newModelName, setNewModelName, onSave, onClose, onAddModel, onRemoveModel }) {
  return (
    <div className="settings-modal-overlay">
      <div className="settings-modal">
        <h3 className="settings-modal-title">{editingProvider ? 'Configure AI Provider' : 'Add AI Provider'}</h3>
        <form onSubmit={onSave}>
          <div className="settings-form-group">
            <label className="settings-form-label">Provider Name</label>
            <input type="text" value={newProvider.name} onChange={(e) => setNewProvider({ ...newProvider, name: e.target.value })}
              placeholder="My LM Studio" required className="settings-form-input" />
          </div>

          <div className="settings-form-group">
            <label className="settings-form-label">Provider Type</label>
            <select value={newProvider.provider_type}
              onChange={(e) => {
                const type = e.target.value;
                let baseUrl = newProvider.base_url;
                if (type === 'anthropic') baseUrl = 'https://api.anthropic.com';
                else if (type === 'openai') baseUrl = 'https://api.openai.com/v1';
                else if (type === 'openai_compatible') baseUrl = 'http://localhost:1234/v1';
                setNewProvider({ ...newProvider, provider_type: type, base_url: baseUrl });
              }}
              className="settings-form-input">
              <option value="openai_compatible">OpenAI Compatible (LM Studio, Ollama, etc.)</option>
              <option value="anthropic">Anthropic (Claude)</option>
              <option value="openai">OpenAI</option>
            </select>
          </div>

          <div className="settings-form-group">
            <label className="settings-form-label">Base URL</label>
            <input type="text" value={newProvider.base_url} onChange={(e) => setNewProvider({ ...newProvider, base_url: e.target.value })}
              placeholder="http://localhost:1234/v1" required className="settings-form-input" />
            <p style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: '0.25rem' }}>
              {newProvider.provider_type === 'openai_compatible' && 'LM Studio default: http://localhost:1234/v1'}
              {newProvider.provider_type === 'anthropic' && 'Anthropic API: https://api.anthropic.com'}
              {newProvider.provider_type === 'openai' && 'OpenAI API: https://api.openai.com/v1'}
            </p>
          </div>

          <div className="settings-form-group">
            <label className="settings-form-label">
              API Key {newProvider.provider_type === 'openai_compatible' && '(optional for local)'}
              {editingProvider && <span style={{ color: 'var(--text-muted)', fontWeight: 'normal' }}> - leave blank to keep existing</span>}
            </label>
            <input type="password" value={newProvider.api_key} onChange={(e) => setNewProvider({ ...newProvider, api_key: e.target.value })}
              placeholder={editingProvider ? 'Enter new key to update, or leave blank' : (newProvider.provider_type === 'openai_compatible' ? 'Leave empty for local LM Studio' : 'sk-...')}
              autoComplete="new-password" className="settings-form-input" />
          </div>

          {/* Model Management */}
          <ModelManagement newProvider={newProvider} newModelName={newModelName} setNewModelName={setNewModelName}
            onAddModel={onAddModel} onRemoveModel={onRemoveModel} />

          {/* Tier Selection */}
          <TierModelSelection newProvider={newProvider} setNewProvider={setNewProvider} />

          {/* Default Model */}
          <div className="settings-form-group">
            <label className="settings-form-label">
              Default Model <span style={{ color: 'var(--text-muted)', fontWeight: 'normal' }}>(fallback if tier not specified)</span>
            </label>
            <select value={newProvider.selected_model} onChange={(e) => setNewProvider({ ...newProvider, selected_model: e.target.value })}
              className="settings-form-input">
              <option value="">-- Select a model --</option>
              {newProvider.models.map((model, idx) => <option key={idx} value={model.id}>{model.name}</option>)}
            </select>
            {newProvider.models.length === 0 && (
              <p style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: '0.35rem' }}>
                Add models above or click "Fetch Models" on the provider card first
              </p>
            )}
          </div>

          {/* Is Default Checkbox */}
          <div className="settings-form-group">
            <label className="settings-checkbox">
              <input type="checkbox" checked={newProvider.is_default}
                onChange={(e) => setNewProvider({ ...newProvider, is_default: e.target.checked })}
                style={{ width: '18px', height: '18px' }} />
              <span>Set as default provider for new agents</span>
            </label>
          </div>

          <div className="settings-modal-footer">
            <button type="button" onClick={onClose} className="settings-modal-cancel">Cancel</button>
            <button type="submit" className="button button-primary">{editingProvider ? 'Update Provider' : 'Save Provider'}</button>
          </div>
        </form>
      </div>
    </div>
  );
}

// ── Model Management ──
function ModelManagement({ newProvider, newModelName, setNewModelName, onAddModel, onRemoveModel }) {
  return (
    <div className="settings-form-group">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
        <label className="settings-form-label" style={{ margin: 0 }}>Available Models</label>
        <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>{newProvider.models.length} models</span>
      </div>

      <div style={{ display: 'flex', gap: '0.4rem', marginBottom: '0.5rem' }}>
        <input type="text" value={newModelName} onChange={(e) => setNewModelName(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && (e.preventDefault(), onAddModel())}
          placeholder="Add model name (e.g., llama-3.2-8b)"
          className="settings-form-input" style={{ flex: 1 }} />
        <button type="button" onClick={onAddModel} style={getActionButtonStyle('green')}>+ Add</button>
      </div>

      {newProvider.models.length > 0 && (
        <div style={{
          display: 'flex', gap: '0.3rem', flexWrap: 'wrap', padding: '0.65rem',
          background: 'var(--bg-secondary)', borderRadius: 'var(--radius-md)',
          border: '1px solid var(--border-subtle)', maxHeight: '100px', overflow: 'auto'
        }}>
          {newProvider.models.map((model, idx) => (
            <span key={idx} style={{ ...getBadgeStyle('green'), display: 'inline-flex', alignItems: 'center', gap: '0.3rem' }}>
              {model.name}
              <button type="button" onClick={() => onRemoveModel(model.id)}
                style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', padding: 0, fontSize: '0.85rem', lineHeight: 1 }}>x</button>
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

// ── Tier Model Selection ──
function TierModelSelection({ newProvider, setNewProvider }) {
  const tiers = [
    { key: 'tier1_model', label: 'Tier 1 - Fast Triage', badge: 'T1', badgeColor: 'yellow' },
    { key: 'tier2_model', label: 'Tier 2 - Analysis & Reasoning', badge: 'T2', badgeColor: 'green' },
    { key: 'tier3_model', label: 'Tier 3 - Deep Investigation', badge: 'T3', badgeColor: 'red' },
    { key: 'chat_model', label: 'Investigation Chat', badge: 'Chat', badgeColor: 'cyan' }
  ];

  return (
    <div className="settings-highlight-box" style={{ marginBottom: '1rem' }}>
      <div className="settings-highlight-box-title">Model Selection by Agent Tier</div>
      <p style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginBottom: '0.75rem' }}>
        Assign different models to different agent tiers. Use fast models for T1 triage, reasoning models for T2 analysis.
      </p>

      {tiers.map((tier, idx) => (
        <div key={tier.key} style={{ marginBottom: idx < tiers.length - 1 ? '0.6rem' : 0 }}>
          <label style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', marginBottom: '0.25rem', fontSize: '0.75rem' }}>
            <span style={getBadgeStyle(tier.badgeColor)}>{tier.badge}</span>
            {tier.label}
          </label>
          <select value={newProvider[tier.key]} onChange={(e) => setNewProvider({ ...newProvider, [tier.key]: e.target.value })}
            className="settings-form-input">
            <option value="">{tier.key === 'chat_model' ? 'Use tier model' : 'Use default model'}</option>
            {newProvider.models.map((model, idx) => <option key={idx} value={model.id}>{model.name}</option>)}
          </select>
        </div>
      ))}
    </div>
  );
}

// ── Guide Card ──
function GuideCard({ title, steps }) {
  return (
    <div className="settings-guide-card">
      <div className="settings-guide-title">{title}</div>
      <ol className="settings-guide-steps">
        {steps.map((step, idx) => <li key={idx}>{step}</li>)}
      </ol>
    </div>
  );
}

export default AIProvidersSettings;
