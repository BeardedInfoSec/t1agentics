/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

import React, { useState, useEffect, useCallback } from 'react';
import { API_BASE_URL } from '../utils/api';
import { useToast } from './ui/Toast';

// Helper to get auth headers
const getAuthHeaders = () => {return {
    'Content-Type': 'application/json',
  };
};

// Inline component for editing model config
function ModelConfigEditor({ aiProviders, currentConfig, onSave, onCancel, styles }) {
  const [selectedProviderId, setSelectedProviderId] = useState('');
  const [selectedModel, setSelectedModel] = useState('');

  // Try to match current config to a provider
  useEffect(() => {
    if (currentConfig?.provider_id) {
      setSelectedProviderId(currentConfig.provider_id);
      setSelectedModel(currentConfig.model || '');
    } else if (currentConfig?.model && aiProviders.length > 0) {
      // Try to find provider by model name
      for (const provider of aiProviders) {
        const matchingModel = provider.models?.find(m => m.id === currentConfig.model || m.name === currentConfig.model);
        if (matchingModel) {
          setSelectedProviderId(provider.id);
          setSelectedModel(matchingModel.id);
          break;
        }
      }
    }
  }, [currentConfig, aiProviders]);

  const selectedProvider = aiProviders.find(p => p.id === selectedProviderId);

  return (
    <div>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem', marginBottom: '1rem' }}>
        <div>
          <label style={{ display: 'block', fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '0.25rem' }}>
            Provider
          </label>
          <select
            value={selectedProviderId}
            onChange={(e) => {
              setSelectedProviderId(e.target.value);
              const provider = aiProviders.find(p => p.id === e.target.value);
              setSelectedModel(provider?.models?.[0]?.id || '');
            }}
            style={styles.input}
          >
            <option value="">Select Provider...</option>
            {aiProviders.map(provider => (
              <option key={provider.id} value={provider.id}>
                {provider.name} {provider.is_default ? '(Default)' : ''}
              </option>
            ))}
          </select>
        </div>

        <div>
          <label style={{ display: 'block', fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '0.25rem' }}>
            Model
          </label>
          <select
            value={selectedModel}
            onChange={(e) => setSelectedModel(e.target.value)}
            style={styles.input}
            disabled={!selectedProviderId}
          >
            <option value="">Select Model...</option>
            {selectedProvider?.models?.map(model => (
              <option key={model.id} value={model.id}>
                {model.name || model.id}
              </option>
            ))}
          </select>
        </div>
      </div>

      {selectedProvider && selectedModel && (
        <div style={{ padding: '0.5rem', background: 'rgba(34, 197, 94, 0.1)', borderRadius: '4px', fontSize: '0.75rem', color: '#22c55e', marginBottom: '1rem' }}>
          Will use: <strong>{selectedModel}</strong> via {selectedProvider.name} ({selectedProvider.base_url})
        </div>
      )}

      <div style={{ display: 'flex', gap: '0.5rem', justifyContent: 'flex-end' }}>
        <button onClick={onCancel} style={{ ...styles.btn, ...styles.btnSecondary }}>
          Cancel
        </button>
        <button
          onClick={() => onSave(selectedProviderId, selectedModel)}
          disabled={!selectedProviderId || !selectedModel}
          style={{ ...styles.btn, ...styles.btnPrimary, opacity: (!selectedProviderId || !selectedModel) ? 0.5 : 1 }}
        >
          Save Model
        </button>
      </div>
    </div>
  );
}

function AgentManager() {
  const toast = useToast();
  const [agents, setAgents] = useState([]);
  const [templates, setTemplates] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [showDetailModal, setShowDetailModal] = useState(false);
  const [selectedAgent, setSelectedAgent] = useState(null);
  const [selectedTemplate, setSelectedTemplate] = useState(null);
  const [filterTier, setFilterTier] = useState('all');
  const [pendingApprovals, setPendingApprovals] = useState([]);
  const [stats, setStats] = useState(null);
  const [aiProviders, setAiProviders] = useState([]);
  const [editingModelConfig, setEditingModelConfig] = useState(false);
  const [editingAutoClose, setEditingAutoClose] = useState(false);
  const [autoClosePolicy, setAutoClosePolicy] = useState({
    enabled: false,
    allowed_verdicts: ['benign', 'false_positive'],
    min_confidence: 0.8,
    close_alert: true,
    close_investigation: true,
    require_no_iocs: false
  });

  // Wizard state
  const [wizardStep, setWizardStep] = useState(1);
  const [wizardData, setWizardData] = useState({
    tier: 1,
    focus: 'Alert',
    role: 'Triage',
    codename: '',
    description: '',
    useTemplate: true,
    templateId: '',
    selectedProviderId: '',
    selectedModel: ''
  });

  const focusOptions = ['Alert', 'Identity', 'Endpoint', 'Network', 'Cloud', 'Email'];
  const roleOptions = {
    1: ['Triage'],
    2: ['Investigation'],
    3: ['Response']
  };

  const tierInfo = {
    1: { label: 'Tier 1', name: 'Triage & Enrichment', risk: 'LOW', color: '#22c55e', description: 'Read-only with enrichment capabilities. Best for high-volume alert triage.' },
    2: { label: 'Tier 2', name: 'Investigation', risk: 'MEDIUM', color: '#eab308', description: 'Can update tickets and alert status. Best for complex investigations.' },
    3: { label: 'Tier 3', name: 'Response', risk: 'HIGH', color: '#dc2626', description: 'Can execute containment actions. Requires approval by default.' }
  };

  const fetchAgents = useCallback(async () => {
    try {
      const params = new URLSearchParams();
      if (filterTier !== 'all') params.append('tier', filterTier);

      const response = await fetch(`${API_BASE_URL}/api/v1/agents?${params}`, {
        headers: getAuthHeaders()
      });
      const data = await response.json();
      setAgents(data.agents || []);
    } catch (error) {
      console.error('Agent list fetch error:', error);
    }
  }, [filterTier]);

  const fetchTemplates = async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/api/v1/agents/templates/list`, {
        headers: getAuthHeaders()
      });
      const data = await response.json();
      setTemplates(data.templates || []);
    } catch (error) {
      console.error('Agent templates fetch error:', error);
    }
  };

  const fetchPendingApprovals = async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/api/v1/approvals`, {
        headers: getAuthHeaders()
      });
      const data = await response.json();
      setPendingApprovals(data.approvals || []);
    } catch (error) {
      console.error('Approvals fetch error:', error);
    }
  };

  const fetchStats = async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/api/v1/agents/stats/overview`, {
        headers: getAuthHeaders()
      });
      const data = await response.json();
      setStats(data);
    } catch (error) {
      console.error('Agent stats fetch error:', error);
    }
  };

  const fetchAiProviders = async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/api/v1/ai-providers`, {
        headers: getAuthHeaders()
      });
      if (response.ok) {
        const data = await response.json();
        const enabledProviders = (data.providers || []).filter(p => p.enabled);
        setAiProviders(enabledProviders);
        // Auto-select default provider
        const defaultProvider = enabledProviders.find(p => p.is_default);
        if (defaultProvider) {
          setWizardData(prev => ({
            ...prev,
            selectedProviderId: defaultProvider.id,
            selectedModel: defaultProvider.models?.[0]?.id || ''
          }));
        }
      }
    } catch (error) {
      console.error('AI providers fetch error:', error);
    }
  };

  useEffect(() => {
    const loadData = async () => {
      setLoading(true);
      await Promise.all([
        fetchAgents(),
        fetchTemplates(),
        fetchPendingApprovals(),
        fetchStats(),
        fetchAiProviders()
      ]);
      setLoading(false);
    };
    loadData();
  }, [fetchAgents]);

  const handleCreateFromTemplate = async () => {
    try {
      // Get provider info for the selected model
      const selectedProvider = aiProviders.find(p => p.id === wizardData.selectedProviderId);

      const requestBody = {
        template_id: wizardData.templateId,
        codename: wizardData.codename || null,
        description: wizardData.description || null
      };

      // Add model config override if a model is selected
      if (selectedProvider && wizardData.selectedModel) {
        requestBody.model_config_override = {
          provider: selectedProvider.provider_type === 'openai_compatible' ? 'openai_compatible' : selectedProvider.provider_type,
          provider_id: selectedProvider.id,
          model: wizardData.selectedModel,
          base_url: selectedProvider.base_url
        };
      }

      const response = await fetch(`${API_BASE_URL}/api/v1/agents/from-template`, {
        method: 'POST',
        headers: getAuthHeaders(),
        body: JSON.stringify(requestBody)
      });

      if (response.ok) {
        setShowCreateModal(false);
        resetWizard();
        fetchAgents();
        fetchStats();
      } else {
        const error = await response.json();
        toast.error(`Error: ${error.detail}`);
      }
    } catch (error) {
      toast.error('Failed to create agent');
    }
  };

  const handleToggleAgent = async (agent) => {
    try {
      const endpoint = agent.enabled ? 'disable' : 'enable';
      const response = await fetch(`${API_BASE_URL}/api/v1/agents/${agent.id}/${endpoint}`, {
        method: 'POST',
        headers: getAuthHeaders()
      });

      if (response.ok) {
        fetchAgents();
        fetchStats();
      }
    } catch (error) {
      console.error('Agent update error:', error);
    }
  };

  const handleDeleteAgent = async (agent) => {
    if (!window.confirm(`Are you sure you want to delete "${agent.system_name}"${agent.codename ? ` (${agent.codename})` : ''}?`)) {
      return;
    }

    try {
      const response = await fetch(`${API_BASE_URL}/api/v1/agents/${agent.id}`, {
        method: 'DELETE',
        headers: getAuthHeaders()
      });

      if (response.ok) {
        fetchAgents();
        fetchStats();
      }
    } catch (error) {
      console.error('Agent model update error:', error);
    }
  };

  const handleApproval = async (requestId, approve) => {
    try {
      const endpoint = approve ? 'approve' : 'deny';
      const response = await fetch(`${API_BASE_URL}/api/v1/approvals/${requestId}/${endpoint}`, {
        method: 'POST',
        headers: getAuthHeaders(),
        body: JSON.stringify({ note: '' })
      });

      if (response.ok) {
        fetchPendingApprovals();
      }
    } catch (error) {
      console.error('Approval reject error:', error);
    }
  };

  const handleUpdateAgentModel = async (agentId, providerId, modelId) => {
    try {
      const provider = aiProviders.find(p => p.id === providerId);
      if (!provider) return;

      // Use the dedicated model-config endpoint
      const response = await fetch(`${API_BASE_URL}/api/v1/agents/${agentId}/model-config`, {
        method: 'PUT',
        headers: getAuthHeaders(),
        body: JSON.stringify({
          provider_id: providerId,
          model: modelId
        })
      });

      if (response.ok) {
        const result = await response.json();
        // Refresh the agent data
        const agentResponse = await fetch(`${API_BASE_URL}/api/v1/agents/${agentId}`, {
          headers: getAuthHeaders()
        });
        if (agentResponse.ok) {
          const updated = await agentResponse.json();
          setSelectedAgent(updated);
        }
        fetchAgents();
        setEditingModelConfig(false);
      } else {
        const error = await response.json();
        toast.error(`Failed to update: ${error.detail}`);
      }
    } catch (error) {
      toast.error('Failed to update agent model');
    }
  };

  const handleUpdateAutoClosePolicy = async (agentId, policy) => {
    try {
      const response = await fetch(`${API_BASE_URL}/api/v1/agents/${agentId}/auto-close-policy`, {
        method: 'PUT',
        headers: getAuthHeaders(),
        body: JSON.stringify(policy)
      });

      if (response.ok) {
        // Refresh the agent data
        const agentResponse = await fetch(`${API_BASE_URL}/api/v1/agents/${agentId}`, {
          headers: getAuthHeaders()
        });
        if (agentResponse.ok) {
          const updated = await agentResponse.json();
          setSelectedAgent(updated);
        }
        fetchAgents();
        setEditingAutoClose(false);
      } else {
        const error = await response.json();
        toast.error(`Failed to update: ${error.detail}`);
      }
    } catch (error) {
      toast.error('Failed to update auto-close policy');
    }
  };

  const resetWizard = () => {
    setWizardStep(1);
    const defaultProvider = aiProviders.find(p => p.is_default) || aiProviders[0];
    setWizardData({
      tier: 1,
      focus: 'Alert',
      role: 'Triage',
      codename: '',
      description: '',
      useTemplate: true,
      templateId: '',
      selectedProviderId: defaultProvider?.id || '',
      selectedModel: defaultProvider?.models?.[0]?.id || ''
    });
    setSelectedTemplate(null);
  };

  const styles = {
    container: { padding: 0 },
    header: {
      display: 'flex',
      justifyContent: 'space-between',
      alignItems: 'center',
      marginBottom: '1rem'
    },
    statsGrid: {
      display: 'grid',
      gridTemplateColumns: 'repeat(5, 1fr)',
      gap: '0.75rem',
      marginBottom: '1rem'
    },
    statCard: {
      background: 'var(--bg-tertiary)',
      borderRadius: '8px',
      padding: '1rem',
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
      gap: '0.25rem'
    },
    statValue: {
      fontSize: '1.75rem',
      fontWeight: '700',
      lineHeight: 1
    },
    statLabel: {
      fontSize: '0.7rem',
      color: 'var(--text-muted)',
      textTransform: 'uppercase'
    },
    filterBar: {
      display: 'flex',
      gap: '0.5rem',
      marginBottom: '1rem',
      alignItems: 'center'
    },
    select: {
      background: 'var(--bg-secondary)',
      border: '1px solid rgba(255,255,255,0.1)',
      borderRadius: '4px',
      padding: '0.4rem 0.6rem',
      color: 'var(--text-primary)',
      fontSize: '0.8rem'
    },
    agentGrid: {
      display: 'grid',
      gridTemplateColumns: 'repeat(auto-fill, minmax(350px, 1fr))',
      gap: '1rem'
    },
    agentCard: {
      background: 'var(--bg-tertiary)',
      borderRadius: '8px',
      padding: '1rem',
      border: '1px solid rgba(255,255,255,0.1)',
      transition: 'transform 0.15s, box-shadow 0.15s'
    },
    tierBadge: (tier) => ({
      display: 'inline-flex',
      alignItems: 'center',
      gap: '0.25rem',
      padding: '0.2rem 0.5rem',
      borderRadius: '4px',
      fontSize: '0.65rem',
      fontWeight: '600',
      background: `${tierInfo[tier]?.color}20`,
      color: tierInfo[tier]?.color,
      border: `1px solid ${tierInfo[tier]?.color}40`
    }),
    btn: {
      padding: '0.4rem 0.8rem',
      borderRadius: '4px',
      border: 'none',
      cursor: 'pointer',
      fontSize: '0.8rem',
      fontWeight: '500',
      transition: 'all 0.15s'
    },
    btnPrimary: {
      background: '#3b82f6',
      color: 'white'
    },
    btnSecondary: {
      background: 'rgba(255,255,255,0.1)',
      color: 'var(--text-secondary)',
      border: '1px solid rgba(255,255,255,0.1)'
    },
    btnDanger: {
      background: 'rgba(220, 38, 38, 0.2)',
      color: '#dc2626',
      border: '1px solid rgba(220, 38, 38, 0.3)'
    },
    modal: {
      position: 'fixed',
      top: 0,
      left: 0,
      right: 0,
      bottom: 0,
      background: 'rgba(0,0,0,0.7)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      zIndex: 1000
    },
    modalContent: {
      background: 'var(--bg-secondary)',
      borderRadius: '12px',
      padding: '1.5rem',
      width: '600px',
      maxHeight: '80vh',
      overflow: 'auto'
    },
    wizardCard: (selected) => ({
      background: selected ? 'rgba(59, 130, 246, 0.1)' : 'var(--bg-tertiary)',
      border: selected ? '2px solid #3b82f6' : '1px solid rgba(255,255,255,0.1)',
      borderRadius: '8px',
      padding: '1rem',
      cursor: 'pointer',
      transition: 'all 0.15s'
    }),
    input: {
      width: '100%',
      background: 'var(--bg-tertiary)',
      border: '1px solid rgba(255,255,255,0.1)',
      borderRadius: '4px',
      padding: '0.5rem 0.75rem',
      color: 'var(--text-primary)',
      fontSize: '0.85rem'
    },
    approvalCard: {
      background: 'rgba(234, 179, 8, 0.1)',
      border: '1px solid rgba(234, 179, 8, 0.3)',
      borderRadius: '8px',
      padding: '1rem',
      marginBottom: '0.75rem'
    }
  };

  const renderAgentCard = (agent) => (
    <div
      key={agent.id}
      style={styles.agentCard}
      onMouseEnter={(e) => { e.currentTarget.style.transform = 'translateY(-2px)'; e.currentTarget.style.boxShadow = '0 4px 12px rgba(0,0,0,0.3)'; }}
      onMouseLeave={(e) => { e.currentTarget.style.transform = 'translateY(0)'; e.currentTarget.style.boxShadow = 'none'; }}
    >
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '0.75rem' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.25rem' }}>
            <span style={styles.tierBadge(agent.tier)}>
              TIER {agent.tier} - {tierInfo[agent.tier]?.risk}
            </span>
            {!agent.enabled && (
              <span style={{ ...styles.tierBadge(1), background: 'rgba(100,116,139,0.2)', color: '#64748b', border: '1px solid rgba(100,116,139,0.3)' }}>
                DISABLED
              </span>
            )}
          </div>
          <h3 style={{ fontSize: '1rem', fontWeight: '600', margin: '0.25rem 0' }}>
            {agent.codename || agent.focus + ' ' + agent.role}
          </h3>
          <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', margin: 0 }}>
            {agent.system_name}
          </p>
        </div>
        <div style={{ display: 'flex', gap: '0.25rem' }}>
          <button
            onClick={() => { setSelectedAgent(agent); setShowDetailModal(true); }}
            style={{ ...styles.btn, ...styles.btnSecondary, padding: '0.25rem 0.5rem', fontSize: '0.7rem' }}
          >
            View
          </button>
        </div>
      </div>

      <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: '0.75rem', lineHeight: 1.4 }}>
        {agent.description?.substring(0, 100)}{agent.description?.length > 100 ? '...' : ''}
      </p>

      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div style={{ display: 'flex', gap: '0.5rem', fontSize: '0.7rem', color: 'var(--text-muted)' }}>
          <span>Focus: {agent.focus}</span>
          <span>|</span>
          <span>{agent.permissions?.applications?.length || 0} apps</span>
        </div>
        <div style={{ display: 'flex', gap: '0.25rem' }}>
          <button
            onClick={() => handleToggleAgent(agent)}
            style={{
              ...styles.btn,
              padding: '0.2rem 0.4rem',
              fontSize: '0.65rem',
              background: agent.enabled ? 'rgba(234, 179, 8, 0.2)' : 'rgba(34, 197, 94, 0.2)',
              color: agent.enabled ? '#eab308' : '#22c55e',
              border: `1px solid ${agent.enabled ? 'rgba(234, 179, 8, 0.3)' : 'rgba(34, 197, 94, 0.3)'}`
            }}
          >
            {agent.enabled ? 'Disable' : 'Enable'}
          </button>
          <button
            onClick={() => handleDeleteAgent(agent)}
            style={{ ...styles.btn, ...styles.btnDanger, padding: '0.2rem 0.4rem', fontSize: '0.65rem' }}
          >
            Delete
          </button>
        </div>
      </div>
    </div>
  );

  const renderCreateWizard = () => (
    <div style={styles.modal} onClick={() => { setShowCreateModal(false); resetWizard(); }}>
      <div style={styles.modalContent} onClick={e => e.stopPropagation()}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
          <h2 style={{ margin: 0, fontSize: '1.2rem' }}>Create Agent - Step {wizardStep} of 3</h2>
          <button onClick={() => { setShowCreateModal(false); resetWizard(); }} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', fontSize: '1.2rem' }}>x</button>
        </div>

        {/* Progress bar */}
        <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '1.5rem' }}>
          {[1, 2, 3].map(step => (
            <div key={step} style={{ flex: 1, height: '4px', borderRadius: '2px', background: step <= wizardStep ? '#3b82f6' : 'rgba(255,255,255,0.1)' }} />
          ))}
        </div>

        {/* Step 1: Choose Tier */}
        {wizardStep === 1 && (
          <div>
            <h3 style={{ fontSize: '0.9rem', marginBottom: '1rem', color: 'var(--text-muted)' }}>Choose Agent Tier</h3>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
              {[1, 2, 3].map(tier => (
                <div
                  key={tier}
                  style={styles.wizardCard(wizardData.tier === tier)}
                  onClick={() => setWizardData({ ...wizardData, tier, role: roleOptions[tier][0] })}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.25rem' }}>
                        <span style={{ fontWeight: '600' }}>{tierInfo[tier].label}</span>
                        <span style={styles.tierBadge(tier)}>{tierInfo[tier].risk}</span>
                      </div>
                      <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', margin: 0 }}>{tierInfo[tier].name}</p>
                    </div>
                    <div style={{ width: '20px', height: '20px', borderRadius: '50%', border: `2px solid ${wizardData.tier === tier ? '#3b82f6' : 'rgba(255,255,255,0.2)'}`, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                      {wizardData.tier === tier && <div style={{ width: '10px', height: '10px', borderRadius: '50%', background: '#3b82f6' }} />}
                    </div>
                  </div>
                  <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginTop: '0.5rem', marginBottom: 0 }}>
                    {tierInfo[tier].description}
                  </p>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Step 2: Choose Template */}
        {wizardStep === 2 && (
          <div>
            <h3 style={{ fontSize: '0.9rem', marginBottom: '1rem', color: 'var(--text-muted)' }}>Choose Template</h3>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
              {templates.filter(t => t.tier === wizardData.tier).map(template => (
                <div
                  key={template.template_id}
                  style={styles.wizardCard(wizardData.templateId === template.template_id)}
                  onClick={() => {
                    setWizardData({ ...wizardData, templateId: template.template_id, focus: template.focus, role: template.role });
                    setSelectedTemplate(template);
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <div>
                      <h4 style={{ margin: '0 0 0.25rem 0', fontSize: '0.9rem' }}>{template.name}</h4>
                      <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', margin: 0 }}>
                        {template.focus} | {template.role} | {template.permissions?.applications?.length || 0} integrations
                      </p>
                    </div>
                    <div style={{ width: '20px', height: '20px', borderRadius: '50%', border: `2px solid ${wizardData.templateId === template.template_id ? '#3b82f6' : 'rgba(255,255,255,0.2)'}`, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                      {wizardData.templateId === template.template_id && <div style={{ width: '10px', height: '10px', borderRadius: '50%', background: '#3b82f6' }} />}
                    </div>
                  </div>
                  <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginTop: '0.5rem', marginBottom: 0 }}>
                    {template.description?.substring(0, 150)}...
                  </p>
                </div>
              ))}
              {templates.filter(t => t.tier === wizardData.tier).length === 0 && (
                <p style={{ color: 'var(--text-muted)', textAlign: 'center', padding: '2rem' }}>
                  No templates available for Tier {wizardData.tier}
                </p>
              )}
            </div>
          </div>
        )}

        {/* Step 3: Customize */}
        {wizardStep === 3 && (
          <div>
            <h3 style={{ fontSize: '0.9rem', marginBottom: '1rem', color: 'var(--text-muted)' }}>Customize Agent</h3>

            {/* AI Model Selection */}
            <div style={{ marginBottom: '1rem', padding: '1rem', background: 'rgba(59, 130, 246, 0.1)', borderRadius: '8px', border: '1px solid rgba(59, 130, 246, 0.3)' }}>
              <label style={{ display: 'block', fontSize: '0.85rem', fontWeight: '600', marginBottom: '0.75rem' }}>
                AI Model Configuration
              </label>

              {aiProviders.length === 0 ? (
                <div style={{ padding: '1rem', textAlign: 'center', color: 'var(--text-muted)' }}>
                  <p style={{ marginBottom: '0.5rem' }}>No AI providers configured.</p>
                  <a href="/settings" style={{ color: '#3b82f6', textDecoration: 'underline' }}>
                    Configure AI Providers in Settings
                  </a>
                </div>
              ) : (
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
                  <div>
                    <label style={{ display: 'block', fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '0.25rem' }}>
                      Provider
                    </label>
                    <select
                      value={wizardData.selectedProviderId}
                      onChange={(e) => {
                        const provider = aiProviders.find(p => p.id === e.target.value);
                        setWizardData({
                          ...wizardData,
                          selectedProviderId: e.target.value,
                          selectedModel: provider?.models?.[0]?.id || ''
                        });
                      }}
                      style={styles.input}
                    >
                      <option value="">Select Provider...</option>
                      {aiProviders.map(provider => (
                        <option key={provider.id} value={provider.id}>
                          {provider.name} {provider.is_default ? '(Default)' : ''}
                        </option>
                      ))}
                    </select>
                  </div>

                  <div>
                    <label style={{ display: 'block', fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '0.25rem' }}>
                      Model
                    </label>
                    <select
                      value={wizardData.selectedModel}
                      onChange={(e) => setWizardData({ ...wizardData, selectedModel: e.target.value })}
                      style={styles.input}
                      disabled={!wizardData.selectedProviderId}
                    >
                      <option value="">Select Model...</option>
                      {aiProviders.find(p => p.id === wizardData.selectedProviderId)?.models?.map(model => (
                        <option key={model.id} value={model.id}>
                          {model.name || model.id}
                        </option>
                      ))}
                    </select>
                  </div>
                </div>
              )}

              {wizardData.selectedProviderId && wizardData.selectedModel && (
                <div style={{ marginTop: '0.75rem', padding: '0.5rem', background: 'rgba(34, 197, 94, 0.1)', borderRadius: '4px', fontSize: '0.75rem', color: '#22c55e' }}>
                  Agent will use: <strong>{wizardData.selectedModel}</strong> via {aiProviders.find(p => p.id === wizardData.selectedProviderId)?.name}
                </div>
              )}
            </div>

            <div style={{ marginBottom: '1rem' }}>
              <label style={{ display: 'block', fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '0.25rem' }}>
                Codename (Optional)
              </label>
              <input
                type="text"
                placeholder="e.g., Sentinel, Nightfall, Watchdog"
                value={wizardData.codename}
                onChange={(e) => setWizardData({ ...wizardData, codename: e.target.value })}
                style={styles.input}
              />
              <p style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: '0.25rem' }}>
                Cosmetic only. Does not affect permissions.
              </p>
            </div>

            <div style={{ marginBottom: '1rem' }}>
              <label style={{ display: 'block', fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '0.25rem' }}>
                Description (Optional Override)
              </label>
              <textarea
                placeholder={selectedTemplate?.description || 'Agent description...'}
                value={wizardData.description}
                onChange={(e) => setWizardData({ ...wizardData, description: e.target.value })}
                style={{ ...styles.input, minHeight: '80px', resize: 'vertical' }}
              />
            </div>

            {/* Summary */}
            <div style={{ background: 'var(--bg-tertiary)', borderRadius: '8px', padding: '1rem', marginTop: '1rem' }}>
              <h4 style={{ fontSize: '0.85rem', marginBottom: '0.75rem' }}>Agent Summary</h4>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.5rem', fontSize: '0.8rem' }}>
                <div><span style={{ color: 'var(--text-muted)' }}>Tier:</span> {wizardData.tier}</div>
                <div><span style={{ color: 'var(--text-muted)' }}>Risk:</span> <span style={{ color: tierInfo[wizardData.tier].color }}>{tierInfo[wizardData.tier].risk}</span></div>
                <div><span style={{ color: 'var(--text-muted)' }}>Focus:</span> {wizardData.focus}</div>
                <div><span style={{ color: 'var(--text-muted)' }}>Role:</span> {wizardData.role}</div>
                <div style={{ gridColumn: '1 / -1' }}><span style={{ color: 'var(--text-muted)' }}>Template:</span> {selectedTemplate?.name}</div>
                {wizardData.selectedModel && <div style={{ gridColumn: '1 / -1' }}><span style={{ color: 'var(--text-muted)' }}>Model:</span> {wizardData.selectedModel}</div>}
                {wizardData.codename && <div style={{ gridColumn: '1 / -1' }}><span style={{ color: 'var(--text-muted)' }}>Codename:</span> {wizardData.codename}</div>}
              </div>
            </div>
          </div>
        )}

        {/* Navigation */}
        <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: '1.5rem' }}>
          <button
            onClick={() => wizardStep > 1 ? setWizardStep(wizardStep - 1) : setShowCreateModal(false)}
            style={{ ...styles.btn, ...styles.btnSecondary }}
          >
            {wizardStep === 1 ? 'Cancel' : 'Back'}
          </button>
          <button
            onClick={() => {
              if (wizardStep < 3) {
                setWizardStep(wizardStep + 1);
              } else {
                handleCreateFromTemplate();
              }
            }}
            disabled={wizardStep === 2 && !wizardData.templateId}
            style={{
              ...styles.btn,
              ...styles.btnPrimary,
              opacity: (wizardStep === 2 && !wizardData.templateId) ? 0.5 : 1
            }}
          >
            {wizardStep === 3 ? 'Create Agent' : 'Next'}
          </button>
        </div>
      </div>
    </div>
  );

  const renderDetailModal = () => (
    <div style={styles.modal} onClick={() => { setShowDetailModal(false); setSelectedAgent(null); }}>
      <div style={{ ...styles.modalContent, width: '700px' }} onClick={e => e.stopPropagation()}>
        {/* Warning Banner */}
        <div style={{
          background: 'rgba(234, 179, 8, 0.15)',
          border: '1px solid rgba(234, 179, 8, 0.3)',
          borderRadius: '8px',
          padding: '0.75rem 1rem',
          marginBottom: '1rem',
          display: 'flex',
          alignItems: 'flex-start',
          gap: '0.75rem'
        }}>
          <span style={{ fontSize: '1.2rem' }}>⚠️</span>
          <div style={{ fontSize: '0.8rem' }}>
            <strong style={{ color: '#eab308' }}>System Prompts Locked</strong>
            <p style={{ margin: '0.25rem 0 0 0', color: 'var(--text-secondary)', lineHeight: 1.4 }}>
              Agent prompts are managed by the system and cannot be edited by users.
              Modifying agent prompts can cause unpredictable behavior, analysis failures, or security issues.
              Contact your administrator if prompt changes are required.
            </p>
          </div>
        </div>

        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.25rem' }}>
              <span style={styles.tierBadge(selectedAgent?.tier)}>
                TIER {selectedAgent?.tier} - {tierInfo[selectedAgent?.tier]?.risk}
              </span>
              {!selectedAgent?.enabled && (
                <span style={{ ...styles.tierBadge(1), background: 'rgba(100,116,139,0.2)', color: '#64748b' }}>DISABLED</span>
              )}
            </div>
            <h2 style={{ margin: 0, fontSize: '1.2rem' }}>
              {selectedAgent?.codename || `${selectedAgent?.focus} ${selectedAgent?.role}`}
            </h2>
            <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', margin: '0.25rem 0 0 0' }}>
              {selectedAgent?.system_name}
            </p>
          </div>
          <button onClick={() => { setShowDetailModal(false); setSelectedAgent(null); }} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', fontSize: '1.2rem' }}>x</button>
        </div>

        <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: '1rem' }}>
          {selectedAgent?.description}
        </p>

        {/* Permissions */}
        <div style={{ marginBottom: '1rem' }}>
          <h4 style={{ fontSize: '0.85rem', marginBottom: '0.5rem' }}>Permitted Applications</h4>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
            {selectedAgent?.permissions?.applications?.map((app, i) => (
              <div key={i} style={{ background: 'var(--bg-tertiary)', padding: '0.5rem 0.75rem', borderRadius: '4px', fontSize: '0.75rem' }}>
                <strong>{app.name}</strong>
                <div style={{ color: 'var(--text-muted)', marginTop: '0.25rem' }}>
                  {app.actions?.map(a => a.action).join(', ')}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Guardrails */}
        <div style={{ marginBottom: '1rem' }}>
          <h4 style={{ fontSize: '0.85rem', marginBottom: '0.5rem' }}>Guardrails</h4>
          <div style={{ background: 'var(--bg-tertiary)', padding: '0.75rem', borderRadius: '6px', fontSize: '0.8rem' }}>
            <div style={{ marginBottom: '0.5rem' }}>
              <span style={{ color: 'var(--text-muted)' }}>Confidence Threshold:</span> {(selectedAgent?.guardrails?.confidence_threshold * 100)?.toFixed(0)}%
            </div>
            {selectedAgent?.guardrails?.never_rules?.length > 0 && (
              <div>
                <span style={{ color: 'var(--text-muted)' }}>Never Rules:</span>
                <ul style={{ margin: '0.25rem 0 0 1rem', paddingLeft: 0 }}>
                  {selectedAgent.guardrails.never_rules.map((rule, i) => (
                    <li key={i} style={{ fontSize: '0.75rem', color: '#dc2626' }}>{rule}</li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        </div>

        {/* Auto-Close Policy */}
        <div style={{ marginBottom: '1rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
            <h4 style={{ fontSize: '0.85rem', margin: 0 }}>Auto-Close Policy</h4>
            <button
              onClick={() => {
                // Initialize from current agent's policy
                const currentPolicy = selectedAgent?.guardrails?.auto_close_policy || {};
                setAutoClosePolicy({
                  enabled: currentPolicy.enabled || false,
                  allowed_verdicts: currentPolicy.allowed_verdicts || ['benign', 'false_positive'],
                  min_confidence: currentPolicy.min_confidence || 0.8,
                  close_alert: currentPolicy.close_alert !== false,
                  close_investigation: currentPolicy.close_investigation !== false,
                  require_no_iocs: currentPolicy.require_no_iocs || false
                });
                setEditingAutoClose(!editingAutoClose);
              }}
              style={{ ...styles.btn, ...styles.btnSecondary, padding: '0.2rem 0.5rem', fontSize: '0.7rem' }}
            >
              {editingAutoClose ? 'Cancel' : 'Configure'}
            </button>
          </div>

          {editingAutoClose ? (
            <div style={{ background: 'rgba(59, 130, 246, 0.1)', padding: '1rem', borderRadius: '6px', border: '1px solid rgba(59, 130, 246, 0.3)' }}>
              <div style={{ marginBottom: '1rem' }}>
                <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer' }}>
                  <input
                    type="checkbox"
                    checked={autoClosePolicy.enabled}
                    onChange={(e) => setAutoClosePolicy({ ...autoClosePolicy, enabled: e.target.checked })}
                    style={{ width: '16px', height: '16px' }}
                  />
                  <span style={{ fontWeight: '600', color: autoClosePolicy.enabled ? '#22c55e' : 'var(--text-muted)' }}>
                    Enable Auto-Close
                  </span>
                </label>
                <p style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: '0.25rem', marginLeft: '1.5rem' }}>
                  Automatically close alerts and investigations when agent determines benign/false positive
                </p>
              </div>

              {autoClosePolicy.enabled && (
                <>
                  <div style={{ marginBottom: '0.75rem' }}>
                    <label style={{ display: 'block', fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '0.25rem' }}>
                      Minimum Confidence: {(autoClosePolicy.min_confidence * 100).toFixed(0)}%
                    </label>
                    <input
                      type="range"
                      min="0.5"
                      max="1"
                      step="0.05"
                      value={autoClosePolicy.min_confidence}
                      onChange={(e) => setAutoClosePolicy({ ...autoClosePolicy, min_confidence: parseFloat(e.target.value) })}
                      style={{ width: '100%' }}
                    />
                  </div>

                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.5rem', marginBottom: '0.75rem' }}>
                    <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.75rem' }}>
                      <input
                        type="checkbox"
                        checked={autoClosePolicy.close_alert}
                        onChange={(e) => setAutoClosePolicy({ ...autoClosePolicy, close_alert: e.target.checked })}
                      />
                      Close Alert
                    </label>
                    <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.75rem' }}>
                      <input
                        type="checkbox"
                        checked={autoClosePolicy.close_investigation}
                        onChange={(e) => setAutoClosePolicy({ ...autoClosePolicy, close_investigation: e.target.checked })}
                      />
                      Close Investigation
                    </label>
                  </div>

                  <div style={{ marginBottom: '0.75rem' }}>
                    <label style={{ display: 'block', fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '0.25rem' }}>
                      Allowed Verdicts for Auto-Close:
                    </label>
                    <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
                      {['benign', 'false_positive'].map(verdict => (
                        <label key={verdict} style={{ display: 'flex', alignItems: 'center', gap: '0.25rem', fontSize: '0.75rem', background: 'var(--bg-tertiary)', padding: '0.25rem 0.5rem', borderRadius: '4px' }}>
                          <input
                            type="checkbox"
                            checked={autoClosePolicy.allowed_verdicts.includes(verdict)}
                            onChange={(e) => {
                              if (e.target.checked) {
                                setAutoClosePolicy({ ...autoClosePolicy, allowed_verdicts: [...autoClosePolicy.allowed_verdicts, verdict] });
                              } else {
                                setAutoClosePolicy({ ...autoClosePolicy, allowed_verdicts: autoClosePolicy.allowed_verdicts.filter(v => v !== verdict) });
                              }
                            }}
                          />
                          {verdict.replace('_', ' ')}
                        </label>
                      ))}
                    </div>
                  </div>
                </>
              )}

              <div style={{ display: 'flex', gap: '0.5rem', justifyContent: 'flex-end' }}>
                <button onClick={() => setEditingAutoClose(false)} style={{ ...styles.btn, ...styles.btnSecondary }}>
                  Cancel
                </button>
                <button
                  onClick={() => handleUpdateAutoClosePolicy(selectedAgent.id, autoClosePolicy)}
                  style={{ ...styles.btn, ...styles.btnPrimary }}
                >
                  Save Policy
                </button>
              </div>
            </div>
          ) : (
            <div style={{ background: 'var(--bg-tertiary)', padding: '0.75rem', borderRadius: '6px', fontSize: '0.75rem' }}>
              {selectedAgent?.guardrails?.auto_close_policy?.enabled ? (
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.5rem' }}>
                    <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#22c55e' }}></span>
                    <span style={{ color: '#22c55e', fontWeight: '600' }}>Auto-Close Enabled</span>
                  </div>
                  <div style={{ color: 'var(--text-muted)', fontSize: '0.7rem' }}>
                    Min confidence: {((selectedAgent?.guardrails?.auto_close_policy?.min_confidence || 0.8) * 100).toFixed(0)}% |
                    Verdicts: {(selectedAgent?.guardrails?.auto_close_policy?.allowed_verdicts || ['benign', 'false_positive']).join(', ')}
                  </div>
                </div>
              ) : (
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: 'var(--text-muted)' }}></span>
                  <span style={{ color: 'var(--text-muted)' }}>Auto-Close Disabled</span>
                  <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>(alerts require human review)</span>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Model Config */}
        <div>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
            <h4 style={{ fontSize: '0.85rem', margin: 0 }}>AI Configuration</h4>
            <button
              onClick={() => setEditingModelConfig(!editingModelConfig)}
              style={{ ...styles.btn, ...styles.btnSecondary, padding: '0.2rem 0.5rem', fontSize: '0.7rem' }}
            >
              {editingModelConfig ? 'Cancel' : 'Edit Model'}
            </button>
          </div>

          {editingModelConfig ? (
            <div style={{ background: 'rgba(59, 130, 246, 0.1)', padding: '1rem', borderRadius: '6px', border: '1px solid rgba(59, 130, 246, 0.3)' }}>
              <ModelConfigEditor
                aiProviders={aiProviders}
                currentConfig={selectedAgent?.model_config}
                onSave={(providerId, modelId) => handleUpdateAgentModel(selectedAgent.id, providerId, modelId)}
                onCancel={() => setEditingModelConfig(false)}
                styles={styles}
              />
            </div>
          ) : (
            <div style={{ background: 'var(--bg-tertiary)', padding: '0.75rem', borderRadius: '6px', fontSize: '0.75rem', display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.5rem' }}>
              <div><span style={{ color: 'var(--text-muted)' }}>Provider:</span> {selectedAgent?.model_config?.provider}</div>
              <div><span style={{ color: 'var(--text-muted)' }}>Model:</span> {selectedAgent?.model_config?.model}</div>
              <div><span style={{ color: 'var(--text-muted)' }}>Temperature:</span> {selectedAgent?.model_config?.temperature}</div>
              <div><span style={{ color: 'var(--text-muted)' }}>Max Cost:</span> ${selectedAgent?.model_config?.max_cost_per_run}</div>
              {selectedAgent?.model_config?.base_url && (
                <div style={{ gridColumn: '1 / -1' }}><span style={{ color: 'var(--text-muted)' }}>Base URL:</span> {selectedAgent?.model_config?.base_url}</div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );

  if (loading) {
    return <div style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-muted)' }}>Loading agents...</div>;
  }

  return (
    <div style={styles.container} className="fade-in">
      {/* Header */}
      <div style={styles.header}>
        <div>
          <h2 style={{ fontSize: '1.2rem', fontWeight: '600', marginBottom: '0.25rem' }}>AI Agents</h2>
          <p style={{ color: 'var(--text-muted)', fontSize: '0.8rem', margin: 0 }}>
            Configure and manage autonomous SOC agents
          </p>
        </div>
        <button onClick={() => setShowCreateModal(true)} style={{ ...styles.btn, ...styles.btnPrimary }}>
          + Create Agent
        </button>
      </div>

      {/* Stats */}
      {stats && (
        <div style={styles.statsGrid}>
          <div style={styles.statCard}>
            <span style={{ ...styles.statValue, color: 'var(--text-primary)' }}>{stats.total_agents}</span>
            <span style={styles.statLabel}>Total Agents</span>
          </div>
          <div style={styles.statCard}>
            <span style={{ ...styles.statValue, color: '#22c55e' }}>{stats.enabled_agents}</span>
            <span style={styles.statLabel}>Active</span>
          </div>
          <div style={styles.statCard}>
            <span style={{ ...styles.statValue, color: tierInfo[1].color }}>{stats.by_tier?.tier_1 || 0}</span>
            <span style={styles.statLabel}>Tier 1</span>
          </div>
          <div style={styles.statCard}>
            <span style={{ ...styles.statValue, color: tierInfo[2].color }}>{stats.by_tier?.tier_2 || 0}</span>
            <span style={styles.statLabel}>Tier 2</span>
          </div>
          <div style={styles.statCard}>
            <span style={{ ...styles.statValue, color: tierInfo[3].color }}>{stats.by_tier?.tier_3 || 0}</span>
            <span style={styles.statLabel}>Tier 3</span>
          </div>
        </div>
      )}

      {/* Pending Approvals */}
      {pendingApprovals.length > 0 && (
        <div style={{ marginBottom: '1rem' }}>
          <h3 style={{ fontSize: '0.9rem', marginBottom: '0.5rem', color: '#eab308' }}>
            Pending Approvals ({pendingApprovals.length})
          </h3>
          {pendingApprovals.slice(0, 3).map(approval => (
            <div key={approval.request_id} style={styles.approvalCard}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div>
                  <strong style={{ fontSize: '0.85rem' }}>{approval.action}</strong>
                  <span style={{ color: 'var(--text-muted)', marginLeft: '0.5rem', fontSize: '0.75rem' }}>
                    on {approval.target_type}: {approval.target_id}
                  </span>
                  <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', margin: '0.25rem 0 0 0' }}>
                    {approval.reasoning?.substring(0, 100)}...
                  </p>
                </div>
                <div style={{ display: 'flex', gap: '0.5rem' }}>
                  <button
                    onClick={() => handleApproval(approval.request_id, true)}
                    style={{ ...styles.btn, background: '#22c55e', color: 'white', padding: '0.3rem 0.6rem', fontSize: '0.75rem' }}
                  >
                    Approve
                  </button>
                  <button
                    onClick={() => handleApproval(approval.request_id, false)}
                    style={{ ...styles.btn, ...styles.btnDanger, padding: '0.3rem 0.6rem', fontSize: '0.75rem' }}
                  >
                    Deny
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Filter Bar */}
      <div style={styles.filterBar}>
        <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Filter:</span>
        <select
          value={filterTier}
          onChange={(e) => setFilterTier(e.target.value)}
          style={styles.select}
        >
          <option value="all">All Tiers</option>
          <option value="1">Tier 1 - Triage</option>
          <option value="2">Tier 2 - Investigation</option>
          <option value="3">Tier 3 - Response</option>
        </select>
      </div>

      {/* Agent Grid */}
      {agents.length === 0 ? (
        <div style={{ textAlign: 'center', padding: '3rem', background: 'var(--bg-tertiary)', borderRadius: '8px' }}>
          <p style={{ color: 'var(--text-muted)', marginBottom: '1rem' }}>No agents configured yet</p>
          <button onClick={() => setShowCreateModal(true)} style={{ ...styles.btn, ...styles.btnPrimary }}>
            Create Your First Agent
          </button>
        </div>
      ) : (
        <div style={styles.agentGrid}>
          {agents.map(renderAgentCard)}
        </div>
      )}

      {/* Modals */}
      {showCreateModal && renderCreateWizard()}
      {showDetailModal && selectedAgent && renderDetailModal()}
    </div>
  );
}

export default AgentManager;


