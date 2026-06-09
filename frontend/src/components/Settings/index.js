/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

import React, { useState, useEffect } from 'react';
import { Settings as SettingsIcon } from 'lucide-react';
import { useToast } from '../ui/Toast';
import { usePreferences } from '../../hooks/usePreferences';
import AIProvidersSettings from './AIProvidersSettings';
import NotificationSettings from './NotificationSettings';
import { API_BASE_URL, getAuthHeaders, getAuthHeader, inputStyle, getActionButtonStyle, authFetch } from './settingsUtils';
import { PLATFORM_OWNER_TENANT_ID } from '../../config/platform';
import './Settings.css';

// Re-export for backwards compatibility
export { default as AIProvidersSettings } from './AIProvidersSettings';
export { default as NotificationSettings } from './NotificationSettings';

function Settings({ user }) {
  const toast = useToast();
  const [config, setConfig] = useState(null);
  const [loading, setLoading] = useState(true);
  const isPlatformTenant = user?.tenant_id === PLATFORM_OWNER_TENANT_ID;
  const [activeTab, setActiveTab] = useState('general');

  const { preferences, updatePreference, saving: savingPrefs } = usePreferences();

  const [exclusions, setExclusions] = useState([]);
  const [loadingExclusions, setLoadingExclusions] = useState(true);
  const [exclusionStats, setExclusionStats] = useState(null);
  const [showAddExclusion, setShowAddExclusion] = useState(false);
  const [newExclusion, setNewExclusion] = useState({
    ioc_type: 'ip', ioc_value: '', match_type: 'exact', reason: '', category: 'custom'
  });
  const [bulkExclusionInput, setBulkExclusionInput] = useState('');
  const [showBulkImport, setShowBulkImport] = useState(false);

  const [dedupeRules, setDedupeRules] = useState([]);
  const [loadingDedupe, setLoadingDedupe] = useState(true);
  const [dedupeStats, setDedupeStats] = useState(null);
  const [showAddDedupeRule, setShowAddDedupeRule] = useState(false);
  const [newDedupeRule, setNewDedupeRule] = useState({
    name: '', description: '', fingerprint_fields: ['source', 'signature', 'src_ip'],
    window_minutes: 60, action: 'group', priority: 100, enabled: true
  });

  const [enrichmentStats, setEnrichmentStats] = useState(null);
  const [loadingEnrichment, setLoadingEnrichment] = useState(true);
  const [enrichmentTTL, setEnrichmentTTL] = useState({ ip: 7, domain: 14, hash: 30, url: 1, email: 30 });

  const [trustedSenders, setTrustedSenders] = useState([]);
  const [phishingTests, setPhishingTests] = useState([]);
  const [loadingSenderTrust, setLoadingSenderTrust] = useState(true);

  const [triageConfig, setTriageConfig] = useState(null);
  const [savingTriageConfig, setSavingTriageConfig] = useState(false);

  const [aiConfig, setAiConfig] = useState(null);
  const [savingAiConfig, setSavingAiConfig] = useState(false);
  const [aiConfigError, setAiConfigError] = useState(null);

  const [piiPatterns, setPiiPatterns] = useState([]);
  const [piiPatternsLoading, setPiiPatternsLoading] = useState(false);

  const [correlationSettings, setCorrelationSettings] = useState(null);
  const [loadingCorrelation, setLoadingCorrelation] = useState(true);
  const [highRiskEntities, setHighRiskEntities] = useState([]);
  const [savingCorrelation, setSavingCorrelation] = useState(false);

  const [licenseInfo, setLicenseInfo] = useState(null);
  const [loadingLicense, setLoadingLicense] = useState(true);
  const [activatingLicense, setActivatingLicense] = useState(false);
  const [licenseKey, setLicenseKey] = useState('');
  const [licenseToken, setLicenseToken] = useState('');
  const [licenseError, setLicenseError] = useState(null);
  const [licenseSuccess, setLicenseSuccess] = useState(null);

  const [newDisposition, setNewDisposition] = useState({ value: '', label: '', color: '#6b7280', description: '' });
  const [newSeverity, setNewSeverity] = useState({ value: '', label: '', color: '#6b7280', threshold: 50 });

  const getAuthHeaderLocal = () => getAuthHeader();

  useEffect(() => {
    fetchConfig();
    fetchLicenseInfo();
    fetchExclusions();
    fetchExclusionStats();
    fetchDedupeRules();
    fetchDedupeStats();
    fetchEnrichmentStats();
    fetchEnrichmentTTL();
    fetchSenderTrust();
    fetchCorrelationSettings();
    fetchHighRiskEntities();
    fetchTriageConfig();
    fetchAiConfig();
    fetchPiiPatterns();
  }, []);

  const fetchPiiPatterns = async () => {
    try {
      setPiiPatternsLoading(true);
      const r = await authFetch(`${API_BASE_URL}/api/v1/pii-patterns`, { headers: getAuthHeaderLocal() });
      if (r.ok) setPiiPatterns((await r.json()).patterns || []);
    } catch {} finally { setPiiPatternsLoading(false); }
  };

  const createPiiPattern = async (payload) => {
    const r = await authFetch(`${API_BASE_URL}/api/v1/pii-patterns`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...getAuthHeaderLocal() },
      body: JSON.stringify(payload),
    });
    const data = await r.json();
    if (r.ok) { toast.success('Pattern added'); fetchPiiPatterns(); return true; }
    toast.error(data?.detail || 'Failed to add pattern');
    return false;
  };

  const updatePiiPattern = async (id, payload) => {
    const r = await authFetch(`${API_BASE_URL}/api/v1/pii-patterns/${id}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json', ...getAuthHeaderLocal() },
      body: JSON.stringify(payload),
    });
    const data = await r.json();
    if (r.ok) { fetchPiiPatterns(); return true; }
    toast.error(data?.detail || 'Failed to update pattern');
    return false;
  };

  const deletePiiPattern = async (id) => {
    if (!window.confirm('Delete this pattern?')) return;
    const r = await authFetch(`${API_BASE_URL}/api/v1/pii-patterns/${id}`, {
      method: 'DELETE', headers: getAuthHeaderLocal(),
    });
    if (r.ok) { toast.success('Pattern deleted'); fetchPiiPatterns(); }
    else { toast.error('Failed to delete pattern'); }
  };

  const testPiiPattern = async ({ pattern, mode, sample_text }) => {
    try {
      const r = await authFetch(`${API_BASE_URL}/api/v1/pii-patterns/test`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...getAuthHeaderLocal() },
        body: JSON.stringify({ pattern, mode, sample_text }),
      });
      if (!r.ok) {
        const data = await r.json().catch(() => ({}));
        return { ok: false, error: data?.detail || `HTTP ${r.status}`, matches: [], match_count: 0, obfuscated_text: sample_text };
      }
      return await r.json();
    } catch (e) {
      return { ok: false, error: 'Request failed', matches: [], match_count: 0, obfuscated_text: sample_text };
    }
  };

  const fetchAiConfig = async () => {
    try {
      const r = await authFetch(`${API_BASE_URL}/api/v1/ai-config`, { headers: getAuthHeaderLocal() });
      if (r.ok) setAiConfig(await r.json());
    } catch {}
  };

  const saveAiConfig = async (updates) => {
    try {
      setSavingAiConfig(true);
      setAiConfigError(null);
      const r = await authFetch(`${API_BASE_URL}/api/v1/ai-config`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', ...getAuthHeaderLocal() },
        body: JSON.stringify(updates),
      });
      const data = await r.json();
      if (r.ok) {
        setAiConfig(data);
        toast.success('AI config saved');
      } else {
        const detail = data?.detail || 'Failed to save';
        setAiConfigError(detail);
        toast.error(detail);
      }
    } catch (e) {
      setAiConfigError('Save failed');
      toast.error('Save failed');
    } finally {
      setSavingAiConfig(false);
    }
  };

  const testAiConfig = async (payload) => {
    try {
      const r = await authFetch(`${API_BASE_URL}/api/v1/ai-config/test`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...getAuthHeaderLocal() },
        body: JSON.stringify(payload),
      });
      const data = await r.json();
      if (r.ok) {
        const detail = data.dimensions ? ` (${data.dimensions} dims)` : '';
        toast.success(`Probe OK${detail}`);
        return data;
      }
      toast.error(data?.detail || 'Probe failed');
      return null;
    } catch {
      toast.error('Probe failed');
      return null;
    }
  };

  const fetchTriageConfig = async () => {
    try {
      const r = await authFetch(`${API_BASE_URL}/api/v1/triage-config`, { headers: getAuthHeaderLocal() });
      if (r.ok) setTriageConfig(await r.json());
    } catch {}
  };

  const saveTriageConfig = async (updates) => {
    try {
      setSavingTriageConfig(true);
      const r = await authFetch(`${API_BASE_URL}/api/v1/triage-config`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', ...getAuthHeaderLocal() },
        body: JSON.stringify(updates),
      });
      if (r.ok) {
        setTriageConfig(await r.json());
        toast.success('Triage thresholds saved');
      } else {
        toast.error('Failed to save thresholds');
      }
    } catch {
      toast.error('Failed to save thresholds');
    } finally {
      setSavingTriageConfig(false);
    }
  };

  const fetchConfig = async () => {
    try {
      const response = await authFetch(`${API_BASE_URL}/api/v1/config`, { headers: getAuthHeaderLocal() });
      if (response.ok) setConfig(await response.json());
    } catch (error) { console.error('Settings fetch error:', error); } finally { setLoading(false); }
  };

  const fetchLicenseInfo = async () => {
    try {
      setLoadingLicense(true);
      const response = await authFetch(`${API_BASE_URL}/api/v1/licensing/current`, { headers: getAuthHeaderLocal() });
      if (response.ok) setLicenseInfo(await response.json());
    } catch (error) { console.error('License fetch error:', error); } finally { setLoadingLicense(false); }
  };

  const activateLicense = async () => {
    if (!licenseKey && !licenseToken) { setLicenseError('Please enter a license key or paste a license token'); return; }
    try {
      setActivatingLicense(true); setLicenseError(null); setLicenseSuccess(null);
      const response = await authFetch(`${API_BASE_URL}/api/v1/licensing/activate`, {
        method: 'POST', headers: { 'Content-Type': 'application/json', ...getAuthHeaderLocal() },
        body: JSON.stringify({ license_key: licenseKey || null, license_token: licenseToken || null })
      });
      const data = await response.json();
      if (response.ok) { setLicenseSuccess(`License activated! Tier: ${data.tier}`); setLicenseKey(''); setLicenseToken(''); fetchLicenseInfo(); }
      else { setLicenseError(data.detail || 'Failed to activate license'); }
    } catch (error) { setLicenseError('Failed to connect to server'); } finally { setActivatingLicense(false); }
  };

  const fetchExclusions = async () => {
    try { setLoadingExclusions(true); const r = await authFetch(`${API_BASE_URL}/api/v1/exclusions`, { headers: getAuthHeaderLocal() }); if (r.ok) setExclusions((await r.json()).exclusions || []); } catch {} finally { setLoadingExclusions(false); }
  };
  const fetchExclusionStats = async () => {
    try { const r = await authFetch(`${API_BASE_URL}/api/v1/exclusions/stats`, { headers: getAuthHeaderLocal() }); if (r.ok) setExclusionStats(await r.json()); } catch {}
  };
  const addExclusion = async () => {
    try { const r = await authFetch(`${API_BASE_URL}/api/v1/exclusions`, { method: 'POST', headers: { 'Content-Type': 'application/json', ...getAuthHeaderLocal() }, body: JSON.stringify(newExclusion) }); if (r.ok) { setShowAddExclusion(false); setNewExclusion({ ioc_type: 'ip', ioc_value: '', match_type: 'exact', reason: '', category: 'custom' }); fetchExclusions(); fetchExclusionStats(); } } catch {}
  };
  const deleteExclusion = async (id) => {
    if (!window.confirm('Remove this exclusion?')) return;
    try { const r = await authFetch(`${API_BASE_URL}/api/v1/exclusions/${id}`, { method: 'DELETE', headers: getAuthHeaderLocal() }); if (r.ok) { fetchExclusions(); fetchExclusionStats(); } } catch {}
  };
  const bulkImportExclusions = async () => {
    try { const r = await authFetch(`${API_BASE_URL}/api/v1/exclusions/bulk`, { method: 'POST', headers: { 'Content-Type': 'application/json', ...getAuthHeaderLocal() }, body: JSON.stringify({ raw_input: bulkExclusionInput }) }); if (r.ok) { setShowBulkImport(false); setBulkExclusionInput(''); fetchExclusions(); fetchExclusionStats(); } } catch {}
  };

  const fetchDedupeRules = async () => {
    try { setLoadingDedupe(true); const r = await authFetch(`${API_BASE_URL}/api/v1/deduplication/rules?include_disabled=true`, { headers: getAuthHeaderLocal() }); if (r.ok) { const d = await r.json(); setDedupeRules(Array.isArray(d) ? d : []); } } catch {} finally { setLoadingDedupe(false); }
  };
  const fetchDedupeStats = async () => {
    try { const r = await authFetch(`${API_BASE_URL}/api/v1/deduplication/stats`, { headers: getAuthHeaderLocal() }); if (r.ok) { const d = await r.json(); const s = d.stats?.session || {}; const db = d.stats?.database || {}; setDedupeStats({ total_checks: s.checks || 0, duplicates_found: s.duplicates_found || 0, alerts_suppressed: db.duplicates_suppressed || s.suppressed || 0, alerts_grouped: s.grouped || 0, total_groups: db.total_groups || 0, rules_loaded: d.stats?.rules_loaded || 0 }); } } catch {}
  };
  const addDedupeRule = async () => {
    try {
      const r = await authFetch(`${API_BASE_URL}/api/v1/deduplication/rules`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...getAuthHeaderLocal() },
        body: JSON.stringify(newDedupeRule),
      });
      const data = await r.json().catch(() => ({}));
      if (r.ok) {
        toast.success(`Dedupe rule "${newDedupeRule.name}" saved`);
        setShowAddDedupeRule(false);
        setNewDedupeRule({ name: '', description: '', fingerprint_fields: ['source', 'signature', 'src_ip'], window_minutes: 60, action: 'group', priority: 100, enabled: true });
        fetchDedupeRules();
        fetchDedupeStats();
      } else {
        toast.error(data?.detail || `Failed to add rule (HTTP ${r.status})`);
      }
    } catch (e) {
      toast.error('Failed to add rule');
    }
  };
  const addQuickDedupeRule = async (preset) => {
    try {
      const r = await authFetch(`${API_BASE_URL}/api/v1/deduplication/rules/quick-add/${preset}`, {
        method: 'POST', headers: getAuthHeaderLocal(),
      });
      const data = await r.json().catch(() => ({}));
      if (r.ok) {
        toast.success(data?.message || 'Rule added');
        fetchDedupeRules();
        fetchDedupeStats();
      } else {
        toast.error(data?.detail || `Failed to add rule (HTTP ${r.status})`);
      }
    } catch {
      toast.error('Failed to add rule');
    }
  };
  const toggleDedupeRule = async (id, enabled) => {
    try {
      const r = await authFetch(`${API_BASE_URL}/api/v1/deduplication/rules/${id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json', ...getAuthHeaderLocal() },
        body: JSON.stringify({ enabled }),
      });
      if (r.ok) { fetchDedupeRules(); }
      else { toast.error('Failed to toggle rule'); }
    } catch { toast.error('Failed to toggle rule'); }
  };
  const deleteDedupeRule = async (id, name) => {
    if (!window.confirm(`Delete dedupe rule "${name}"?`)) return;
    try {
      const r = await authFetch(`${API_BASE_URL}/api/v1/deduplication/rules/${id}`, {
        method: 'DELETE', headers: getAuthHeaderLocal(),
      });
      if (r.ok) { toast.success('Rule deleted'); fetchDedupeRules(); fetchDedupeStats(); }
      else { toast.error('Failed to delete rule'); }
    } catch { toast.error('Failed to delete rule'); }
  };

  const fetchEnrichmentStats = async () => {
    try { setLoadingEnrichment(true); const r = await authFetch(`${API_BASE_URL}/api/v1/enrichment/cache/stats`, { headers: getAuthHeaderLocal() }); if (r.ok) setEnrichmentStats(await r.json()); } catch {} finally { setLoadingEnrichment(false); }
  };
  const fetchEnrichmentTTL = async () => {
    try {
      const r = await authFetch(`${API_BASE_URL}/api/v1/enrichment/cache/ttl`, { headers: getAuthHeaderLocal() });
      if (r.ok) {
        const d = await r.json();
        if (d?.ttl_config) setEnrichmentTTL(d.ttl_config);
      }
    } catch {}
  };
  const cleanupExpiredCache = async () => {
    try { const r = await authFetch(`${API_BASE_URL}/api/v1/enrichment/cache/cleanup`, { method: 'POST', headers: getAuthHeaderLocal() }); if (r.ok) fetchEnrichmentStats(); } catch {}
  };
  // Persist TTL changes to the backend. Updates local state immediately
  // for snappy UX; the POST runs in the background and toasts on failure.
  const updateTTL = async (iocType, days) => {
    const clamped = Math.max(1, Math.min(365, parseInt(days, 10) || 1));
    setEnrichmentTTL((prev) => ({ ...prev, [iocType]: clamped }));
    try {
      const r = await authFetch(`${API_BASE_URL}/api/v1/enrichment/cache/ttl`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...getAuthHeaderLocal() },
        body: JSON.stringify({ ioc_type: iocType, ttl_days: clamped }),
      });
      if (!r.ok) toast.error(`Failed to save ${iocType} TTL`);
    } catch {
      toast.error(`Failed to save ${iocType} TTL`);
    }
  };

  const fetchSenderTrust = async () => {
    try {
      setLoadingSenderTrust(true);
      const [sR, tR] = await Promise.all([
        authFetch(`${API_BASE_URL}/api/v1/sender-trust/trusted-senders`, { headers: getAuthHeaderLocal() }),
        authFetch(`${API_BASE_URL}/api/v1/sender-trust/phishing-tests`, { headers: getAuthHeaderLocal() }),
      ]);
      if (sR.ok) setTrustedSenders((await sR.json()).trusted_senders || []);
      if (tR.ok) setPhishingTests((await tR.json()).phishing_tests || []);
    } catch {} finally { setLoadingSenderTrust(false); }
  };

  const addTrustedSender = async (payload) => {
    const r = await authFetch(`${API_BASE_URL}/api/v1/sender-trust/trusted-senders`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...getAuthHeaderLocal() },
      body: JSON.stringify(payload),
    });
    if (r.ok) { toast.success('Trusted sender added'); fetchSenderTrust(); return true; }
    const data = await r.json().catch(() => ({}));
    toast.error(data?.detail || 'Failed to add sender');
    return false;
  };

  const deleteTrustedSender = async (id) => {
    if (!window.confirm('Remove this trusted sender?')) return;
    const r = await authFetch(`${API_BASE_URL}/api/v1/sender-trust/trusted-senders/${id}`, {
      method: 'DELETE', headers: getAuthHeaderLocal(),
    });
    if (r.ok) { toast.success('Sender removed'); fetchSenderTrust(); }
    else { toast.error('Failed to remove sender'); }
  };

  const addPhishingTest = async (payload) => {
    const r = await authFetch(`${API_BASE_URL}/api/v1/sender-trust/phishing-tests`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...getAuthHeaderLocal() },
      body: JSON.stringify(payload),
    });
    if (r.ok) { toast.success('Phishing test pattern added'); fetchSenderTrust(); return true; }
    const data = await r.json().catch(() => ({}));
    toast.error(data?.detail || 'Failed to add pattern');
    return false;
  };

  const deletePhishingTest = async (id) => {
    if (!window.confirm('Remove this phishing test pattern?')) return;
    const r = await authFetch(`${API_BASE_URL}/api/v1/sender-trust/phishing-tests/${id}`, {
      method: 'DELETE', headers: getAuthHeaderLocal(),
    });
    if (r.ok) { toast.success('Pattern removed'); fetchSenderTrust(); }
    else { toast.error('Failed to remove pattern'); }
  };

  // Test helpers run an email/subject through the saved rules and
  // return whether they would match. Both backend endpoints take
  // query params, hence the URLSearchParams dance.
  const testTrustedSender = async (email) => {
    try {
      const qs = new URLSearchParams({ email }).toString();
      const r = await authFetch(`${API_BASE_URL}/api/v1/sender-trust/trusted-senders/check?${qs}`, {
        method: 'POST', headers: getAuthHeaderLocal(),
      });
      if (r.ok) return await r.json();
      return { is_trusted: false, _error: `HTTP ${r.status}` };
    } catch {
      return { is_trusted: false, _error: 'Request failed' };
    }
  };

  const testPhishingPattern = async (sender, subject) => {
    try {
      const qs = new URLSearchParams({ sender, subject }).toString();
      const r = await authFetch(`${API_BASE_URL}/api/v1/sender-trust/phishing-tests/check?${qs}`, {
        method: 'POST', headers: getAuthHeaderLocal(),
      });
      if (r.ok) return await r.json();
      return { is_phishing_test: false, _error: `HTTP ${r.status}` };
    } catch {
      return { is_phishing_test: false, _error: 'Request failed' };
    }
  };

  const fetchCorrelationSettings = async () => {
    try {
      setLoadingCorrelation(true);
      const r = await authFetch(`${API_BASE_URL}/api/v1/correlation/settings`, { headers: getAuthHeaderLocal() });
      if (r.ok) setCorrelationSettings(await r.json());
    } catch {} finally { setLoadingCorrelation(false); }
  };
  const fetchHighRiskEntities = async () => {
    try {
      const r = await authFetch(`${API_BASE_URL}/api/v1/correlation/entity-risk?limit=20`, { headers: getAuthHeaderLocal() });
      if (r.ok) { const d = await r.json(); setHighRiskEntities(d.entities || []); }
    } catch {}
  };
  const updateCorrelationSetting = async (updates) => {
    try {
      setSavingCorrelation(true);
      const r = await authFetch(`${API_BASE_URL}/api/v1/correlation/settings`, {
        method: 'PATCH', headers: { 'Content-Type': 'application/json', ...getAuthHeaderLocal() },
        body: JSON.stringify(updates)
      });
      if (r.ok) { const d = await r.json(); setCorrelationSettings(d.settings || d); }
    } catch {} finally { setSavingCorrelation(false); }
  };
  const resetEntityRisk = async (entityType, entityValue) => {
    try {
      const r = await authFetch(`${API_BASE_URL}/api/v1/correlation/entity-risk/reset`, {
        method: 'POST', headers: { 'Content-Type': 'application/json', ...getAuthHeaderLocal() },
        body: JSON.stringify({ entity_type: entityType, entity_value: entityValue })
      });
      if (r.ok) fetchHighRiskEntities();
    } catch {}
  };

  const addDisposition = async () => {
    try { const r = await authFetch(`${API_BASE_URL}/api/v1/config/dispositions`, { method: 'POST', headers: getAuthHeaders(), body: JSON.stringify(newDisposition) }); if (r.ok) { await fetchConfig(); setNewDisposition({ value: '', label: '', color: '#6b7280', description: '' }); } else { toast.error('Failed to add disposition'); } } catch { toast.error('Failed to add disposition'); }
  };
  const addSeverity = async () => {
    try { const r = await authFetch(`${API_BASE_URL}/api/v1/config/severities`, { method: 'POST', headers: getAuthHeaders(), body: JSON.stringify(newSeverity) }); if (r.ok) { await fetchConfig(); setNewSeverity({ value: '', label: '', color: '#6b7280', threshold: 50 }); } else { toast.error('Failed to add severity'); } } catch { toast.error('Failed to add severity'); }
  };
  const toggleConfidenceMode = async () => {
    const newMode = config.confidence.display_mode === 'label' ? 'numeric' : 'label';
    try { const r = await authFetch(`${API_BASE_URL}/api/v1/config/confidence/display-mode`, { method: 'PATCH', headers: getAuthHeaders(), body: JSON.stringify({ mode: newMode }) }); if (r.ok) await fetchConfig(); } catch {}
  };

  if (loading) return <div className="settings-page"><div className="settings-loading"><div className="spinner"></div></div></div>;

  const tabs = [
    { id: 'general', label: 'General' },
    { id: 'alerts', label: 'Alert Processing' },
    { id: 'investigations', label: 'Investigations' },
    { id: 'advanced', label: 'Integrations' },
  ];

  return (
    <div className="settings-page">
      <div className="settings-header">
        <div className="settings-header-left">
          <div className="settings-header-icon"><SettingsIcon size={22} /></div>
          <div>
            <h1 className="settings-title">Settings</h1>
            <p className="settings-subtitle">Configure preferences, alert processing, and investigation defaults</p>
          </div>
        </div>
      </div>

      <div className="settings-tabs">
        {tabs.map(tab => (
          <button key={tab.id} onClick={() => setActiveTab(tab.id)}
            className={`settings-tab ${activeTab === tab.id ? 'settings-tab--active' : ''}`}>{tab.label}</button>
        ))}
      </div>

      {activeTab === 'general' && (
        <div className="settings-tab-body">
          <PreferencesSection preferences={preferences} updatePreference={updatePreference} savingPrefs={savingPrefs} />
          <LicenseSection licenseInfo={licenseInfo} loadingLicense={loadingLicense} activatingLicense={activatingLicense} licenseKey={licenseKey} setLicenseKey={setLicenseKey} licenseToken={licenseToken} setLicenseToken={setLicenseToken} licenseError={licenseError} licenseSuccess={licenseSuccess} activateLicense={activateLicense} />
        </div>
      )}

      {activeTab === 'alerts' && (
        <div className="settings-tab-body">
          <div className="settings-card" style={{ background: 'var(--bg-tertiary)', borderLeft: '3px solid var(--primary)' }}>
            <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', lineHeight: 1.6, margin: 0 }}>
              Configure how incoming alerts are processed before they reach your triage queue.
              Set up deduplication rules to reduce noise, exclusion lists to skip known-benign IOCs,
              enrichment cache settings, trusted sender lists, and correlation engine parameters.
            </p>
          </div>
          <AutoCloseSection triageConfig={triageConfig} aiConfig={aiConfig} saving={savingTriageConfig} onSave={saveTriageConfig} />
          <CustomPIIPatternsSection
            patterns={piiPatterns}
            loading={piiPatternsLoading}
            onCreate={createPiiPattern}
            onUpdate={updatePiiPattern}
            onDelete={deletePiiPattern}
            onTest={testPiiPattern}
          />
          <DeduplicationSection dedupeRules={dedupeRules} dedupeStats={dedupeStats} loadingDedupe={loadingDedupe} showAddDedupeRule={showAddDedupeRule} setShowAddDedupeRule={setShowAddDedupeRule} newDedupeRule={newDedupeRule} setNewDedupeRule={setNewDedupeRule} addDedupeRule={addDedupeRule} addQuickDedupeRule={addQuickDedupeRule} toggleDedupeRule={toggleDedupeRule} deleteDedupeRule={deleteDedupeRule} />
          <ExclusionsSection exclusions={exclusions} exclusionStats={exclusionStats} loadingExclusions={loadingExclusions} showAddExclusion={showAddExclusion} setShowAddExclusion={setShowAddExclusion} showBulkImport={showBulkImport} setShowBulkImport={setShowBulkImport} newExclusion={newExclusion} setNewExclusion={setNewExclusion} bulkExclusionInput={bulkExclusionInput} setBulkExclusionInput={setBulkExclusionInput} addExclusion={addExclusion} deleteExclusion={deleteExclusion} bulkImportExclusions={bulkImportExclusions} />
          <EnrichmentSection enrichmentStats={enrichmentStats} enrichmentTTL={enrichmentTTL} updateTTL={updateTTL} cleanupExpiredCache={cleanupExpiredCache} />
          <SenderTrustSection
            trustedSenders={trustedSenders}
            phishingTests={phishingTests}
            loadingSenderTrust={loadingSenderTrust}
            onAddSender={addTrustedSender}
            onDeleteSender={deleteTrustedSender}
            onAddPhishingTest={addPhishingTest}
            onDeletePhishingTest={deletePhishingTest}
            onTestSender={testTrustedSender}
            onTestPhishingPattern={testPhishingPattern}
          />
          <CorrelationEngineSection settings={correlationSettings} loading={loadingCorrelation} saving={savingCorrelation} onUpdate={updateCorrelationSetting} />
          <EntityRiskSection settings={correlationSettings} loading={loadingCorrelation} saving={savingCorrelation} onUpdate={updateCorrelationSetting} highRiskEntities={highRiskEntities} onResetRisk={resetEntityRisk} />
        </div>
      )}

      {activeTab === 'investigations' && (
        <div className="settings-tab-body">
          {config ? (
            <>
              <DispositionsSection config={config} newDisposition={newDisposition} setNewDisposition={setNewDisposition} addDisposition={addDisposition} />
              <SeveritiesSection config={config} newSeverity={newSeverity} setNewSeverity={setNewSeverity} addSeverity={addSeverity} />
              <ConfidenceSection config={config} toggleConfidenceMode={toggleConfidenceMode} />
            </>
          ) : (
            <div className="settings-card">
              <div className="settings-empty">
                <div className="settings-empty-title">Unable to load investigation configuration</div>
                <p className="settings-empty-desc">The system configuration could not be retrieved. Try refreshing the page.</p>
                <button onClick={fetchConfig} className="button button-primary" style={{ marginTop: '1rem' }}>Retry</button>
              </div>
            </div>
          )}
        </div>
      )}

      {activeTab === 'advanced' && (
        <div className="settings-tab-body">
          <div className="settings-card" style={{ background: 'var(--bg-tertiary)', borderLeft: '3px solid var(--primary)' }}>
            <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', lineHeight: 1.6, margin: 0 }}>
              Configure external service integrations: AI model providers for Riggs analysis,
              and notification channels (Slack, email, webhooks) for alert and investigation updates.
            </p>
          </div>
          {isPlatformTenant && <AIProvidersSettings />}
          <AIModelSection
            aiConfig={aiConfig}
            saving={savingAiConfig}
            error={aiConfigError}
            onSave={saveAiConfig}
            onTest={testAiConfig}
          />
          <NotificationSettings isPlatformTenant={isPlatformTenant} />
        </div>
      )}

    </div>
  );
}

function StatCard({ value, label, color }) {
  return (
    <div className="settings-stat">
      <div className="settings-stat-value" style={{ color }}>{value}</div>
      <div className="settings-stat-label">{label}</div>
    </div>
  );
}

function ExclusionsSection({ exclusions, exclusionStats, loadingExclusions, showAddExclusion, setShowAddExclusion, showBulkImport, setShowBulkImport, newExclusion, setNewExclusion, bulkExclusionInput, setBulkExclusionInput, addExclusion, deleteExclusion, bulkImportExclusions }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
      <div className="settings-stats">
        <StatCard value={exclusionStats?.total_exclusions || 0} label="Total Exclusions" color="var(--primary)" />
        <StatCard value={exclusionStats?.active_exclusions || 0} label="Active" color="var(--primary)" />
        <StatCard value={exclusionStats?.total_hits || 0} label="Total Hits" color="var(--text-secondary)" />
      </div>
      <div className="settings-card">
        <div className="settings-card-header">
          <div>
            <h3 className="settings-card-title">IOC Exclusion List</h3>
            <p className="settings-card-desc">IOCs in this list will not be enriched (private IPs, internal domains, false positives)</p>
          </div>
          <div className="settings-btn-row">
            <button onClick={() => setShowBulkImport(true)} className="button button-secondary">Bulk Import</button>
            <button onClick={() => setShowAddExclusion(true)} className="button button-primary">+ Add Exclusion</button>
          </div>
        </div>
        {loadingExclusions ? <div className="settings-loading"><div className="spinner"></div></div>
        : exclusions.length === 0 ? (
          <div className="settings-empty">
            <div className="settings-empty-title">No exclusions configured</div>
            <p className="settings-empty-desc">Add RFC1918 private IPs, internal domains, and known false positives</p>
          </div>
        ) : (
          <table className="settings-table">
            <thead><tr><th>Type</th><th>Value</th><th>Match</th><th>Reason</th><th>Actions</th></tr></thead>
            <tbody>
              {exclusions.map(exc => (
                <tr key={exc.id}>
                  <td><span className="settings-ioc-badge">{exc.ioc_type}</span></td>
                  <td className="settings-mono">{exc.ioc_value}</td>
                  <td style={{ color: 'var(--text-secondary)' }}>{exc.match_type}</td>
                  <td style={{ color: 'var(--text-muted)' }}>{exc.reason || '-'}</td>
                  <td><button onClick={() => deleteExclusion(exc.id)} style={getActionButtonStyle('red')}>Delete</button></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

function CustomPIIPatternsSection({ patterns, loading, onCreate, onUpdate, onDelete, onTest }) {
  // editingId: null = form collapsed, 'new' = creating, <pattern_id> = editing existing
  const [editingId, setEditingId] = useState(null);
  const [newLabel, setNewLabel] = useState('');
  const [newPattern, setNewPattern] = useState('');
  const [newMode, setNewMode] = useState('mask');
  const [sampleText, setSampleText] = useState('');
  const [testResult, setTestResult] = useState(null);
  const [testing, setTesting] = useState(false);

  const labelStyle = { fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block', marginBottom: '0.25rem' };
  const inputStyleLocal = {
    width: '100%', padding: '0.5rem', background: 'var(--bg-tertiary)',
    border: '1px solid var(--border-color)', borderRadius: 'var(--radius-md)',
    color: 'var(--text-primary)', fontSize: '0.85rem', boxSizing: 'border-box',
  };

  const resetForm = () => {
    setEditingId(null);
    setNewLabel(''); setNewPattern(''); setNewMode('mask');
    setSampleText(''); setTestResult(null);
  };

  const openNew = () => {
    setEditingId('new');
    setNewLabel(''); setNewPattern(''); setNewMode('mask');
    setSampleText(''); setTestResult(null);
  };

  const openEdit = (p) => {
    setEditingId(p.id);
    setNewLabel(p.label);
    setNewPattern(p.pattern);
    setNewMode(p.mode || 'mask');
    setSampleText(''); setTestResult(null);
  };

  const submit = async (e) => {
    e.preventDefault();
    if (!newLabel.trim() || !newPattern.trim()) return;
    const payload = { label: newLabel.trim(), pattern: newPattern.trim(), mode: newMode };
    let ok;
    if (editingId === 'new') {
      ok = await onCreate(payload);
    } else {
      ok = await onUpdate(editingId, payload);
    }
    if (ok) resetForm();
  };

  const runTest = async () => {
    if (!newPattern.trim() || !sampleText.trim()) return;
    setTesting(true);
    try {
      const res = await onTest({ pattern: newPattern.trim(), mode: newMode, sample_text: sampleText });
      setTestResult(res);
    } finally {
      setTesting(false);
    }
  };

  // Build the sample text view with highlights wrapped around each match.
  // Walk forward through sorted ranges so we keep the original order.
  const renderHighlightedSample = () => {
    if (!testResult || !testResult.matches || testResult.matches.length === 0) {
      return <span>{sampleText}</span>;
    }
    const segments = [];
    let cursor = 0;
    for (const m of testResult.matches) {
      if (m.start > cursor) {
        segments.push(<span key={`s${cursor}`}>{sampleText.slice(cursor, m.start)}</span>);
      }
      segments.push(
        <mark
          key={`m${m.start}`}
          style={{
            background: 'rgba(34, 197, 94, 0.25)',
            color: 'var(--text-primary)',
            padding: '0 2px',
            borderRadius: '2px',
          }}
        >
          {sampleText.slice(m.start, m.end)}
        </mark>
      );
      cursor = m.end;
    }
    if (cursor < sampleText.length) {
      segments.push(<span key={`s${cursor}`}>{sampleText.slice(cursor)}</span>);
    }
    return <>{segments}</>;
  };

  return (
    <div className="settings-card">
      <div className="settings-card-header">
        <div>
          <h3 className="settings-card-title">Custom PII patterns</h3>
          <p className="settings-card-desc">
            Regex patterns layered on top of the built-in PII detectors (credit cards, SSNs, emails).
            Matched values are obfuscated before alerts are stored or sent to the LLM.
          </p>
        </div>
      </div>

      {loading ? <div className="settings-loading"><div className="spinner"></div></div> : (
        patterns.length === 0 ? (
          <div className="settings-empty">
            <div className="settings-empty-title">No custom patterns defined</div>
            <p className="settings-empty-desc">
              Add a pattern below — useful for internal customer/employee IDs or any tenant-specific
              identifier the built-in detectors don't recognize.
            </p>
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', marginBottom: '0.75rem' }}>
            {patterns.map(p => {
              const isEditingThis = editingId === p.id;
              return (
                <div key={p.id} className={`settings-item-card ${p.enabled ? 'settings-item-card--active' : 'settings-item-card--disabled'}`}
                     style={{
                       display: 'grid',
                       gridTemplateColumns: '1fr 2fr auto auto auto auto',
                       gap: '0.5rem',
                       alignItems: 'center',
                       outline: isEditingThis ? '2px solid var(--primary)' : 'none',
                     }}>
                  <div>
                    <div className="settings-item-name">{p.label}</div>
                    <div className="settings-item-meta">mode: {p.mode}</div>
                  </div>
                  <code style={{ fontFamily: 'monospace', fontSize: '0.75rem', color: 'var(--text-secondary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {p.pattern}
                  </code>
                  <span className={`settings-badge ${p.enabled ? 'settings-badge--active' : 'settings-badge--disabled'}`}>
                    {p.enabled ? 'ACTIVE' : 'OFF'}
                  </span>
                  <button
                    onClick={() => onUpdate(p.id, { enabled: !p.enabled })}
                    disabled={editingId !== null && !isEditingThis}
                    style={{ ...inputStyleLocal, padding: '0.25rem 0.5rem', width: 'auto', cursor: 'pointer' }}
                  >
                    {p.enabled ? 'Disable' : 'Enable'}
                  </button>
                  <button
                    onClick={() => openEdit(p)}
                    disabled={editingId !== null && !isEditingThis}
                    style={{ ...inputStyleLocal, padding: '0.25rem 0.5rem', width: 'auto', cursor: 'pointer' }}
                  >
                    {isEditingThis ? 'Editing…' : 'Edit'}
                  </button>
                  <button
                    onClick={() => onDelete(p.id)}
                    disabled={editingId !== null && !isEditingThis}
                    style={getActionButtonStyle('red')}
                  >
                    Delete
                  </button>
                </div>
              );
            })}
          </div>
        )
      )}

      {editingId === null ? (
        <button
          type="button"
          className="button button-primary"
          onClick={openNew}
        >
          + Add pattern
        </button>
      ) : (
      <form onSubmit={submit} style={{
        padding: '0.75rem', border: '1px dashed var(--border-color)',
        borderRadius: 'var(--radius-md)', background: 'var(--bg-tertiary)',
        display: 'flex', flexDirection: 'column', gap: '0.75rem',
      }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <strong style={{ fontSize: '0.85rem' }}>
            {editingId === 'new' ? 'New pattern' : 'Edit pattern'}
          </strong>
          <button
            type="button"
            onClick={resetForm}
            style={{ ...inputStyleLocal, padding: '0.25rem 0.5rem', width: 'auto', cursor: 'pointer' }}
          >
            Cancel
          </button>
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 2fr 110px', gap: '0.5rem', alignItems: 'end' }}>
          <div>
            <label style={labelStyle}>Label</label>
            <input style={inputStyleLocal} type="text" value={newLabel} required
              placeholder="Customer ID"
              onChange={(e) => setNewLabel(e.target.value)} />
          </div>
          <div>
            <label style={labelStyle}>Regex pattern</label>
            <input style={{ ...inputStyleLocal, fontFamily: 'monospace' }} type="text"
              value={newPattern} required
              placeholder="\\bCUST-[0-9]{6}\\b"
              onChange={(e) => setNewPattern(e.target.value)} />
          </div>
          <div>
            <label style={labelStyle}>Mode</label>
            <select style={inputStyleLocal} value={newMode} onChange={(e) => setNewMode(e.target.value)}>
              <option value="mask">Mask</option>
              <option value="redact">Redact</option>
              <option value="hash">Hash</option>
            </select>
          </div>
        </div>

        <div>
          <label style={labelStyle}>Sample text (paste anything to verify the regex catches it)</label>
          <textarea
            rows={3}
            style={{ ...inputStyleLocal, fontFamily: 'monospace', resize: 'vertical' }}
            value={sampleText}
            placeholder="Customer CUST-123456 reported issues on order #98765..."
            onChange={(e) => setSampleText(e.target.value)}
          />
        </div>

        <div style={{ display: 'flex', gap: '0.5rem' }}>
          <button
            type="button"
            className="button button-secondary"
            disabled={!newPattern.trim() || !sampleText.trim() || testing}
            onClick={runTest}
          >
            {testing ? 'Testing...' : 'Test pattern'}
          </button>
          <button type="submit" className="button button-primary">
            {editingId === 'new' ? '+ Add pattern' : 'Save changes'}
          </button>
        </div>

        {testResult && (
          <div style={{
            padding: '0.75rem', borderRadius: 'var(--radius-md)',
            background: 'var(--bg-secondary)',
            border: `1px solid ${testResult.ok === false ? '#ef4444' : 'var(--border-color)'}`,
          }}>
            {testResult.ok === false ? (
              <div style={{ color: '#ef4444', fontSize: '0.85rem' }}>
                <strong>Invalid regex:</strong> {testResult.error}
              </div>
            ) : (
              <>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
                  <strong style={{ fontSize: '0.85rem' }}>
                    {testResult.match_count === 0 ? 'No matches' : `${testResult.match_count} match${testResult.match_count === 1 ? '' : 'es'}`}
                  </strong>
                  {testResult.truncated && (
                    <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>(showing first 200)</span>
                  )}
                </div>

                <div style={{ marginBottom: '0.5rem' }}>
                  <div style={labelStyle}>Sample text (matches highlighted)</div>
                  <div style={{
                    padding: '0.5rem', background: 'var(--bg-tertiary)',
                    borderRadius: 'var(--radius-sm)', fontFamily: 'monospace',
                    fontSize: '0.8rem', whiteSpace: 'pre-wrap', wordBreak: 'break-word',
                    maxHeight: '160px', overflowY: 'auto',
                  }}>
                    {renderHighlightedSample()}
                  </div>
                </div>

                {testResult.match_count > 0 && (
                  <div>
                    <div style={labelStyle}>Obfuscated preview ({newMode})</div>
                    <div style={{
                      padding: '0.5rem', background: 'var(--bg-tertiary)',
                      borderRadius: 'var(--radius-sm)', fontFamily: 'monospace',
                      fontSize: '0.8rem', whiteSpace: 'pre-wrap', wordBreak: 'break-word',
                      maxHeight: '160px', overflowY: 'auto', color: 'var(--text-secondary)',
                    }}>
                      {testResult.obfuscated_text}
                    </div>
                  </div>
                )}
              </>
            )}
          </div>
        )}
      </form>
      )}
    </div>
  );
}

function AIModelSection({ aiConfig, saving, error, onSave, onTest }) {
  const allowed = !!aiConfig?.byo_allowed;
  const [enabled, setEnabled] = useState(false);
  const [chatProvider, setChatProvider] = useState('anthropic');
  const [chatApiStyle, setChatApiStyle] = useState('anthropic');
  const [chatKey, setChatKey] = useState('');
  const [chatModel, setChatModel] = useState('');
  const [chatBaseUrl, setChatBaseUrl] = useState('');
  const [chatMaxTokens, setChatMaxTokens] = useState('');

  const [embedProvider, setEmbedProvider] = useState('disabled');
  const [embedKey, setEmbedKey] = useState('');
  const [embedModel, setEmbedModel] = useState('');
  const [embedBaseUrl, setEmbedBaseUrl] = useState('');

  useEffect(() => {
    if (!aiConfig) return;
    setEnabled(!!aiConfig.byo_enabled);
    setChatProvider(aiConfig.chat_provider || 'anthropic');
    setChatApiStyle(aiConfig.chat_api_style || (aiConfig.chat_provider === 'openai' ? 'openai' : 'anthropic'));
    setChatModel(aiConfig.chat_model || '');
    setChatBaseUrl(aiConfig.chat_base_url || '');
    setChatMaxTokens(aiConfig.chat_max_tokens ? String(aiConfig.chat_max_tokens) : '');
    setEmbedProvider(aiConfig.embed_provider || 'disabled');
    setEmbedModel(aiConfig.embed_model || '');
    setEmbedBaseUrl(aiConfig.embed_base_url || '');
  }, [aiConfig]);

  if (!aiConfig) {
    return (
      <div className="settings-card">
        <h3 className="settings-card-title">AI model (BYO LLM)</h3>
        <div className="settings-empty">Loading...</div>
      </div>
    );
  }

  if (!allowed) {
    return (
      <div className="settings-card">
        <h3 className="settings-card-title">AI model (BYO LLM)</h3>
        <p className="settings-card-desc">
          This tenant is using T1 Agentics managed AI. Contact your administrator
          to enable BYO LLM and configure your own provider key.
        </p>
      </div>
    );
  }

  const labelStyle = { fontSize: '0.8rem', color: 'var(--text-muted)', display: 'block', marginBottom: '0.25rem' };
  const inputStyleLocal = {
    width: '100%', padding: '0.5rem', background: 'var(--bg-tertiary)',
    border: '1px solid var(--border-color)', borderRadius: 'var(--radius-md)',
    color: 'var(--text-primary)', fontSize: '0.85rem', boxSizing: 'border-box',
  };
  const subCard = {
    marginTop: '1rem', padding: '0.75rem 1rem', border: '1px solid var(--border-color)',
    borderRadius: 'var(--radius-md)', background: 'var(--bg-secondary)',
  };

  const chatNeedsStyle = chatProvider === 'self_hosted';
  const chatKeyStatus = aiConfig.chat_key_status === 'set' ? 'set' : 'unset';
  const embedKeyStatus = aiConfig.embed_key_status === 'set' ? 'set' : 'unset';

  const save = () => {
    const parsedMaxTokens = chatMaxTokens === '' ? null : Math.max(100, Math.min(16000, parseInt(chatMaxTokens, 10) || 0));
    const updates = {
      byo_enabled: enabled,
      chat_provider: chatProvider,
      chat_model: chatModel || null,
      chat_base_url: chatBaseUrl || null,
      chat_api_style: chatNeedsStyle ? chatApiStyle : null,
      chat_max_tokens: parsedMaxTokens || null,
      embed_provider: embedProvider,
      embed_model: embedModel || null,
      embed_base_url: embedBaseUrl || null,
    };
    if (chatKey !== '') updates.chat_api_key = chatKey;
    if (embedKey !== '') updates.embed_api_key = embedKey;
    onSave(updates).then?.(() => { setChatKey(''); setEmbedKey(''); });
  };

  return (
    <div className="settings-card">
      <div className="settings-card-header">
        <div>
          <h3 className="settings-card-title">AI model (BYO LLM)</h3>
          <p className="settings-card-desc">
            Bring your own provider key. Calls run against your Anthropic, OpenAI,
            or self-hosted endpoint and bypass T1's daily cap and monthly quota.
          </p>
        </div>
      </div>

      <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.75rem' }}>
        <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
        <span>Use my own LLM</span>
        {aiConfig.last_validated_at && (
          <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginLeft: 'auto' }}>
            Last validated {new Date(aiConfig.last_validated_at).toLocaleString()}
          </span>
        )}
      </label>

      {error && (
        <div style={{
          padding: '0.5rem 0.75rem', marginBottom: '0.75rem',
          background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.3)',
          borderRadius: 'var(--radius-md)', fontSize: '0.8rem', color: '#ef4444',
        }}>{error}</div>
      )}

      <div style={subCard}>
        <strong style={{ fontSize: '0.85rem' }}>Chat / triage</strong>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem', marginTop: '0.5rem' }}>
          <div>
            <label style={labelStyle}>Provider</label>
            <select style={inputStyleLocal} value={chatProvider}
              onChange={(e) => {
                setChatProvider(e.target.value);
                if (e.target.value === 'anthropic') setChatApiStyle('anthropic');
                else if (e.target.value === 'openai') setChatApiStyle('openai');
              }}>
              <option value="anthropic">Anthropic</option>
              <option value="openai">OpenAI</option>
              <option value="self_hosted">Self-hosted</option>
            </select>
          </div>
          <div>
            <label style={labelStyle}>Model</label>
            <input style={inputStyleLocal} type="text" value={chatModel}
              placeholder={chatProvider === 'anthropic' ? 'claude-sonnet-4-5-20250929' : 'gpt-4o-mini'}
              onChange={(e) => setChatModel(e.target.value)} />
          </div>
          <div>
            <label style={labelStyle}>Max output tokens (optional)</label>
            <input style={inputStyleLocal} type="number" min="100" max="16000"
              value={chatMaxTokens}
              placeholder="caller default"
              onChange={(e) => setChatMaxTokens(e.target.value)} />
            <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: '0.25rem' }}>
              Raise this if Riggs is truncating mid-JSON on your model. 100-16000.
            </div>
          </div>
          {chatNeedsStyle && (
            <div>
              <label style={labelStyle}>Request shape</label>
              <select style={inputStyleLocal} value={chatApiStyle} onChange={(e) => setChatApiStyle(e.target.value)}>
                <option value="openai">OpenAI-compatible (LM Studio, Ollama, vLLM)</option>
                <option value="anthropic">Anthropic-compatible</option>
              </select>
            </div>
          )}
          {(chatProvider === 'self_hosted' || chatBaseUrl) && (
            <div>
              <label style={labelStyle}>Base URL{chatProvider === 'self_hosted' ? ' (required)' : ' (optional, for proxy)'}</label>
              <input style={inputStyleLocal} type="text" value={chatBaseUrl}
                placeholder="https://your-proxy.example.com"
                onChange={(e) => setChatBaseUrl(e.target.value)} />
            </div>
          )}
          <div style={{ gridColumn: '1 / -1' }}>
            <label style={labelStyle}>API key {chatKeyStatus === 'set' && '• stored'}</label>
            <input style={inputStyleLocal} type="password" value={chatKey}
              placeholder={chatKeyStatus === 'set' ? '•••••• (leave blank to keep)' : 'sk-...'}
              onChange={(e) => setChatKey(e.target.value)} />
          </div>
        </div>
        <div style={{ display: 'flex', gap: '0.5rem', marginTop: '0.75rem' }}>
          <button
            className="button button-secondary"
            disabled={!chatKey || saving}
            onClick={() => onTest({
              target: 'chat',
              provider: chatProvider,
              api_key: chatKey,
              model: chatModel || null,
              base_url: chatBaseUrl || null,
              api_style: chatNeedsStyle ? chatApiStyle : null,
            })}
          >
            Test chat
          </button>
        </div>
      </div>

      <div style={subCard}>
        <strong style={{ fontSize: '0.85rem' }}>Embeddings (knowledge base semantic search)</strong>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem', marginTop: '0.5rem' }}>
          <div>
            <label style={labelStyle}>Provider</label>
            <select style={inputStyleLocal} value={embedProvider} onChange={(e) => setEmbedProvider(e.target.value)}>
              <option value="disabled">Disabled (use FTS only)</option>
              <option value="openai">OpenAI</option>
              <option value="self_hosted">Self-hosted (OpenAI-compatible)</option>
            </select>
          </div>
          {embedProvider !== 'disabled' && (
            <>
              <div>
                <label style={labelStyle}>Model</label>
                <input style={inputStyleLocal} type="text" value={embedModel}
                  placeholder="text-embedding-3-small"
                  onChange={(e) => setEmbedModel(e.target.value)} />
              </div>
              {embedProvider === 'self_hosted' && (
                <div style={{ gridColumn: '1 / -1' }}>
                  <label style={labelStyle}>Base URL (required)</label>
                  <input style={inputStyleLocal} type="text" value={embedBaseUrl}
                    placeholder="https://your-embed-proxy.example.com"
                    onChange={(e) => setEmbedBaseUrl(e.target.value)} />
                </div>
              )}
              <div style={{ gridColumn: '1 / -1' }}>
                <label style={labelStyle}>API key {embedKeyStatus === 'set' && '• stored'}</label>
                <input style={inputStyleLocal} type="password" value={embedKey}
                  placeholder={embedKeyStatus === 'set' ? '•••••• (leave blank to keep)' : 'sk-...'}
                  onChange={(e) => setEmbedKey(e.target.value)} />
              </div>
              <div style={{ gridColumn: '1 / -1', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                KB column is sized for 1536-dim vectors. Models producing other dimensions
                will be skipped (FTS still works).
              </div>
            </>
          )}
        </div>
        {embedProvider !== 'disabled' && (
          <div style={{ display: 'flex', gap: '0.5rem', marginTop: '0.75rem' }}>
            <button
              className="button button-secondary"
              disabled={!embedKey || saving}
              onClick={() => onTest({
                target: 'embed',
                provider: embedProvider,
                api_key: embedKey,
                model: embedModel || null,
                base_url: embedBaseUrl || null,
              })}
            >
              Test embeddings
            </button>
          </div>
        )}
      </div>

      <div style={{ display: 'flex', gap: '0.5rem', marginTop: '1rem' }}>
        <button className="button button-primary" disabled={saving} onClick={save}>
          {saving ? 'Saving...' : 'Save AI config'}
        </button>
      </div>
    </div>
  );
}

function AutoCloseSection({ triageConfig, aiConfig, saving, onSave }) {
  const conf = triageConfig?.auto_close_min_confidence ?? 0.9;
  const fp = triageConfig?.auto_close_min_fp_likelihood ?? 0.0;
  const forceAll = triageConfig?.force_all_to_investigation ?? false;
  const [localConf, setLocalConf] = useState(conf);
  const [localFp, setLocalFp] = useState(fp);
  const [localForceAll, setLocalForceAll] = useState(forceAll);

  // Force-all-to-investigation is BYO-gated — it bypasses auto-close,
  // which raises the number of Riggs deep-dive calls. Only safe to enable
  // when the tenant is on their own LLM bill.
  const byoEffective = !!(aiConfig?.byo_allowed && aiConfig?.byo_enabled && aiConfig?.chat_key_status === 'set');

  useEffect(() => {
    setLocalConf(conf);
    setLocalFp(fp);
    setLocalForceAll(forceAll);
  }, [conf, fp, forceAll]);

  const dirty =
    Math.abs(localConf - conf) > 0.0001 ||
    Math.abs(localFp - fp) > 0.0001 ||
    localForceAll !== forceAll;

  return (
    <div className="settings-card">
      <div className="settings-card-header">
        <div>
          <h3 className="settings-card-title">Auto-close thresholds</h3>
          <p className="settings-card-desc">
            Controls when T1 triage closes a BENIGN / FALSE_POSITIVE alert without analyst review.
            Higher values mean fewer auto-closes; raise these if you'd rather see borderline alerts in the queue.
          </p>
        </div>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem', marginTop: '0.5rem' }}>
        <div>
          <label style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.85rem', marginBottom: '0.375rem' }}>
            <span>Minimum confidence for auto-close</span>
            <strong style={{ color: 'var(--primary)' }}>{(localConf * 100).toFixed(0)}%</strong>
          </label>
          <input
            type="range" min="0.5" max="1.0" step="0.01"
            value={localConf}
            onChange={(e) => setLocalConf(parseFloat(e.target.value))}
            style={{ width: '100%' }}
          />
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.25rem' }}>
            Riggs verdict confidence required before a BENIGN / FALSE_POSITIVE alert auto-closes.
            Default 90%.
          </div>
        </div>

        <div>
          <label style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.85rem', marginBottom: '0.375rem' }}>
            <span>Minimum false-positive likelihood (optional)</span>
            <strong style={{ color: 'var(--primary)' }}>
              {localFp <= 0 ? 'Off' : `${(localFp * 100).toFixed(0)}%`}
            </strong>
          </label>
          <input
            type="range" min="0.0" max="1.0" step="0.01"
            value={localFp}
            onChange={(e) => setLocalFp(parseFloat(e.target.value))}
            style={{ width: '100%' }}
          />
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.25rem' }}>
            Set to 0 to leave this gate off (default). When non-zero, the triage result must also
            report at least this much false-positive likelihood before auto-closing.
          </div>
        </div>

        {byoEffective && (
          <div style={{
            padding: '0.75rem', border: '1px dashed var(--border-color)',
            borderRadius: 'var(--radius-md)', background: 'var(--bg-tertiary)',
          }}>
            <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.85rem' }}>
              <input
                type="checkbox"
                checked={localForceAll}
                onChange={(e) => setLocalForceAll(e.target.checked)}
              />
              <span><strong>Force every alert to investigation</strong> (BYO LLM only)</span>
            </label>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.375rem' }}>
              When on, no alert auto-closes — every triage opens an investigation regardless of
              the thresholds above. Useful for evaluation periods. Disabled for platform-key
              tenants because it raises Claude spend.
            </div>
          </div>
        )}

        <div style={{ display: 'flex', gap: '0.5rem' }}>
          <button
            className="button button-primary"
            disabled={!dirty || saving}
            onClick={() => onSave({
              auto_close_min_confidence: localConf,
              auto_close_min_fp_likelihood: localFp,
              force_all_to_investigation: byoEffective ? localForceAll : false,
            })}
          >
            {saving ? 'Saving...' : 'Save thresholds'}
          </button>
          <button
            className="button button-secondary"
            disabled={!dirty || saving}
            onClick={() => { setLocalConf(conf); setLocalFp(fp); setLocalForceAll(forceAll); }}
          >
            Reset
          </button>
        </div>
      </div>
    </div>
  );
}

function DeduplicationSection({ dedupeRules, dedupeStats, loadingDedupe, showAddDedupeRule, setShowAddDedupeRule, newDedupeRule, setNewDedupeRule, addDedupeRule, addQuickDedupeRule, toggleDedupeRule, deleteDedupeRule }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
      <div className="settings-stats">
        <StatCard value={dedupeStats?.total_checks || 0} label="Total Checks" color="var(--primary)" />
        <StatCard value={dedupeStats?.duplicates_found || 0} label="Duplicates Found" color="var(--primary)" />
        <StatCard value={dedupeStats?.alerts_suppressed || 0} label="Suppressed" color="var(--text-secondary)" />
        <StatCard value={dedupeStats?.alerts_grouped || 0} label="Grouped" color="var(--primary)" />
      </div>
      <div className="settings-card">
        <h3 className="settings-card-title" style={{ marginBottom: '0.75rem' }}>Quick Add Common Rules</h3>
        <div className="settings-quick-actions">
          <button onClick={() => addQuickDedupeRule('network-scan')} className="button button-secondary">+ Network Scan Dedup</button>
          <button onClick={() => addQuickDedupeRule('auth-failure')} className="button button-secondary">+ Auth Failure Dedup</button>
          <button onClick={() => addQuickDedupeRule('malware-detection')} className="button button-secondary">+ Malware Detection Dedup</button>
        </div>
      </div>
      <div className="settings-card">
        <div className="settings-card-header">
          <div>
            <h3 className="settings-card-title">Deduplication Rules</h3>
            <p className="settings-card-desc">Configure how similar alerts are grouped or suppressed</p>
          </div>
          <button
            onClick={() => setShowAddDedupeRule(!showAddDedupeRule)}
            className="button button-primary"
          >
            {showAddDedupeRule ? 'Cancel' : '+ Add Rule'}
          </button>
        </div>

        {showAddDedupeRule && (
          <form
            onSubmit={(e) => { e.preventDefault(); addDedupeRule(); }}
            style={{
              padding: '0.75rem',
              marginBottom: '0.75rem',
              border: '1px dashed var(--border-color)',
              borderRadius: 'var(--radius-md)',
              background: 'var(--bg-tertiary)',
              display: 'flex',
              flexDirection: 'column',
              gap: '0.75rem',
            }}
          >
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.5rem' }}>
              <div>
                <label style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block', marginBottom: '0.25rem' }}>Name *</label>
                <input
                  type="text"
                  required
                  value={newDedupeRule.name}
                  placeholder="e.g. Failed SSH from same IP"
                  onChange={(e) => setNewDedupeRule({ ...newDedupeRule, name: e.target.value })}
                  style={{ width: '100%', padding: '0.5rem', background: 'var(--bg-secondary)', border: '1px solid var(--border-color)', borderRadius: 'var(--radius-md)', color: 'var(--text-primary)', fontSize: '0.85rem', boxSizing: 'border-box' }}
                />
              </div>
              <div>
                <label style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block', marginBottom: '0.25rem' }}>Description</label>
                <input
                  type="text"
                  value={newDedupeRule.description}
                  placeholder="Optional"
                  onChange={(e) => setNewDedupeRule({ ...newDedupeRule, description: e.target.value })}
                  style={{ width: '100%', padding: '0.5rem', background: 'var(--bg-secondary)', border: '1px solid var(--border-color)', borderRadius: 'var(--radius-md)', color: 'var(--text-primary)', fontSize: '0.85rem', boxSizing: 'border-box' }}
                />
              </div>
            </div>

            <div>
              <label style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block', marginBottom: '0.25rem' }}>Fingerprint fields (comma-separated) *</label>
              <input
                type="text"
                required
                value={(newDedupeRule.fingerprint_fields || []).join(', ')}
                placeholder="source, signature, src_ip"
                onChange={(e) => setNewDedupeRule({
                  ...newDedupeRule,
                  fingerprint_fields: e.target.value.split(',').map(s => s.trim()).filter(Boolean),
                })}
                style={{ width: '100%', padding: '0.5rem', background: 'var(--bg-secondary)', border: '1px solid var(--border-color)', borderRadius: 'var(--radius-md)', color: 'var(--text-primary)', fontSize: '0.85rem', fontFamily: 'monospace', boxSizing: 'border-box' }}
              />
              <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: '0.25rem' }}>
                Alerts with identical values for these fields will be deduplicated together.
              </div>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '0.5rem' }}>
              <div>
                <label style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block', marginBottom: '0.25rem' }}>Window (minutes)</label>
                <input
                  type="number" min="1" max="10080"
                  value={newDedupeRule.window_minutes}
                  onChange={(e) => setNewDedupeRule({ ...newDedupeRule, window_minutes: parseInt(e.target.value, 10) || 60 })}
                  style={{ width: '100%', padding: '0.5rem', background: 'var(--bg-secondary)', border: '1px solid var(--border-color)', borderRadius: 'var(--radius-md)', color: 'var(--text-primary)', fontSize: '0.85rem', boxSizing: 'border-box' }}
                />
              </div>
              <div>
                <label style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block', marginBottom: '0.25rem' }}>Action</label>
                <select
                  value={newDedupeRule.action}
                  onChange={(e) => setNewDedupeRule({ ...newDedupeRule, action: e.target.value })}
                  style={{ width: '100%', padding: '0.5rem', background: 'var(--bg-secondary)', border: '1px solid var(--border-color)', borderRadius: 'var(--radius-md)', color: 'var(--text-primary)', fontSize: '0.85rem', boxSizing: 'border-box' }}
                >
                  <option value="group">group</option>
                  <option value="suppress">suppress</option>
                  <option value="merge">merge</option>
                  <option value="count_only">count_only</option>
                </select>
              </div>
              <div>
                <label style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block', marginBottom: '0.25rem' }}>Priority</label>
                <input
                  type="number" min="0" max="1000"
                  value={newDedupeRule.priority}
                  onChange={(e) => setNewDedupeRule({ ...newDedupeRule, priority: parseInt(e.target.value, 10) || 100 })}
                  style={{ width: '100%', padding: '0.5rem', background: 'var(--bg-secondary)', border: '1px solid var(--border-color)', borderRadius: 'var(--radius-md)', color: 'var(--text-primary)', fontSize: '0.85rem', boxSizing: 'border-box' }}
                />
              </div>
            </div>

            <div style={{ display: 'flex', gap: '0.5rem' }}>
              <button type="submit" className="button button-primary" disabled={!newDedupeRule.name || !newDedupeRule.fingerprint_fields?.length}>
                + Save rule
              </button>
              <button type="button" className="button button-secondary" onClick={() => setShowAddDedupeRule(false)}>
                Cancel
              </button>
            </div>
          </form>
        )}

        {loadingDedupe ? <div className="settings-loading"><div className="spinner"></div></div>
        : dedupeRules.length === 0 ? (
          <div className="settings-empty">
            <div className="settings-empty-title">No deduplication rules configured</div>
            <p className="settings-empty-desc">Use the Quick Add buttons above or create a custom rule</p>
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
            {dedupeRules.map(rule => (
              <div key={rule.id} className={`settings-item-card ${rule.enabled ? 'settings-item-card--active' : 'settings-item-card--disabled'}`}
                   style={{ display: 'grid', gridTemplateColumns: '1fr auto auto auto', gap: '0.5rem', alignItems: 'center' }}>
                <div>
                  <div className="settings-item-name">{rule.name}</div>
                  <div className="settings-item-meta">Window: {rule.window_minutes}m | Action: {rule.action} | Fields: {(rule.fingerprint_fields || []).join(', ')}</div>
                </div>
                <span className={`settings-badge ${rule.enabled ? 'settings-badge--active' : 'settings-badge--disabled'}`}>{rule.enabled ? 'ACTIVE' : 'DISABLED'}</span>
                {toggleDedupeRule && (
                  <button
                    className="pa-btn-sm"
                    onClick={() => toggleDedupeRule(rule.id, !rule.enabled)}
                  >
                    {rule.enabled ? 'Disable' : 'Enable'}
                  </button>
                )}
                {deleteDedupeRule && (
                  <button onClick={() => deleteDedupeRule(rule.id, rule.name)} style={getActionButtonStyle('red')}>Delete</button>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function EnrichmentSection({ enrichmentStats, enrichmentTTL, updateTTL, cleanupExpiredCache }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
      <div className="settings-stats">
        <StatCard value={enrichmentStats?.total_cached || 0} label="Cached Enrichments" color="var(--primary)" />
        <StatCard value={enrichmentStats?.cache_hits || 0} label="Cache Hits" color="var(--primary)" />
        <StatCard value={enrichmentStats?.cache_misses || 0} label="Cache Misses" color="var(--text-secondary)" />
        <StatCard value={enrichmentStats?.hit_rate ? `${(enrichmentStats.hit_rate * 100).toFixed(1)}%` : '0%'} label="Hit Rate" color="var(--primary)" />
      </div>
      <div className="settings-card">
        <div className="settings-card-header">
          <div>
            <h3 className="settings-card-title">Cache TTL Configuration</h3>
            <p className="settings-card-desc">How long enrichment results are cached before refreshing</p>
          </div>
          <button onClick={cleanupExpiredCache} className="button button-secondary">Cleanup Expired</button>
        </div>
        <div className="settings-ttl-grid">
          {Object.entries(enrichmentTTL).map(([iocType, days]) => (
            <div key={iocType} className="settings-ttl-item">
              <div className="settings-ttl-label">{iocType}</div>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '0.35rem' }}>
                <input type="number" value={days} onChange={(e) => updateTTL(iocType, parseInt(e.target.value) || 1)} min="1" max="365" className="settings-ttl-input" />
                <span className="settings-ttl-suffix">days</span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function SenderTrustSection({
  trustedSenders, phishingTests, loadingSenderTrust,
  onAddSender, onDeleteSender, onAddPhishingTest, onDeletePhishingTest,
  onTestSender, onTestPhishingPattern,
}) {
  const [showAddSender, setShowAddSender] = useState(false);
  const [senderForm, setSenderForm] = useState({
    domain: '', sender_pattern: '', trust_level: 'trusted',
    organization: '', category: '', reason: '',
  });

  const [showAddTest, setShowAddTest] = useState(false);
  const [testForm, setTestForm] = useState({
    sender_pattern: '', subject_pattern: '', match_type: 'contains',
    test_name: '', vendor: '',
  });

  // Test panel state — checks a given email/subject against the saved rules.
  // Hidden by default so the "no rules configured yet" page is uncluttered.
  const [showSenderTest, setShowSenderTest] = useState(false);
  const [senderTestEmail, setSenderTestEmail] = useState('');
  const [senderTestResult, setSenderTestResult] = useState(null);
  const [senderTesting, setSenderTesting] = useState(false);

  const [showPhishTest, setShowPhishTest] = useState(false);
  const [phishTestSender, setPhishTestSender] = useState('');
  const [phishTestSubject, setPhishTestSubject] = useState('');
  const [phishTestResult, setPhishTestResult] = useState(null);
  const [phishTesting, setPhishTesting] = useState(false);

  const runSenderTest = async () => {
    if (!senderTestEmail.trim()) return;
    setSenderTesting(true);
    try {
      setSenderTestResult(await onTestSender(senderTestEmail.trim()));
    } finally {
      setSenderTesting(false);
    }
  };

  const runPhishTest = async () => {
    if (!phishTestSender.trim() || !phishTestSubject.trim()) return;
    setPhishTesting(true);
    try {
      setPhishTestResult(await onTestPhishingPattern(phishTestSender.trim(), phishTestSubject.trim()));
    } finally {
      setPhishTesting(false);
    }
  };

  const labelStyle = { fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block', marginBottom: '0.25rem' };
  const inputStyleLocal = {
    width: '100%', padding: '0.5rem', background: 'var(--bg-tertiary)',
    border: '1px solid var(--border-color)', borderRadius: 'var(--radius-md)',
    color: 'var(--text-primary)', fontSize: '0.85rem', boxSizing: 'border-box',
  };

  const submitSender = async (e) => {
    e.preventDefault();
    if (!senderForm.domain.trim()) return;
    const ok = await onAddSender({
      domain: senderForm.domain.trim(),
      sender_pattern: senderForm.sender_pattern.trim() || null,
      trust_level: senderForm.trust_level,
      organization: senderForm.organization.trim() || null,
      category: senderForm.category.trim() || null,
      reason: senderForm.reason.trim() || null,
    });
    if (ok) {
      setShowAddSender(false);
      setSenderForm({ domain: '', sender_pattern: '', trust_level: 'trusted', organization: '', category: '', reason: '' });
    }
  };

  const submitTest = async (e) => {
    e.preventDefault();
    if (!testForm.sender_pattern.trim() || !testForm.subject_pattern.trim()) return;
    const ok = await onAddPhishingTest({
      sender_pattern: testForm.sender_pattern.trim(),
      subject_pattern: testForm.subject_pattern.trim(),
      match_type: testForm.match_type,
      test_name: testForm.test_name.trim() || null,
      vendor: testForm.vendor.trim() || null,
    });
    if (ok) {
      setShowAddTest(false);
      setTestForm({ sender_pattern: '', subject_pattern: '', match_type: 'contains', test_name: '', vendor: '' });
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
      <div className="settings-stats">
        <StatCard value={trustedSenders.length} label="Trusted Senders" color="var(--primary)" />
        <StatCard value={phishingTests.length} label="Phishing Test Patterns" color="var(--text-secondary)" />
      </div>

      {/* ── Trusted Senders ────────────────────────────────────────── */}
      <div className="settings-card">
        <div className="settings-card-header">
          <div>
            <h3 className="settings-card-title">Trusted Senders</h3>
            <p className="settings-card-desc">Domains and senders that are automatically trusted during analysis</p>
          </div>
          <button
            type="button"
            className="pa-btn-sm"
            onClick={() => {
              setShowSenderTest(!showSenderTest);
              if (showSenderTest) { setSenderTestResult(null); setSenderTestEmail(''); }
            }}
            disabled={trustedSenders.length === 0}
            title={trustedSenders.length === 0 ? 'Add a trusted sender first' : 'Try an email against your saved rules'}
          >
            {showSenderTest ? 'Hide test' : 'Test an email'}
          </button>
        </div>

        {/* Collapsible test panel — hidden by default so the list is the focus */}
        {showSenderTest && (
        <div style={{
          padding: '0.625rem 0.75rem', marginBottom: '0.75rem',
          border: '1px solid var(--border-color)', borderRadius: 'var(--radius-md)',
          background: 'var(--bg-secondary)',
          display: 'flex', gap: '0.5rem', alignItems: 'end', flexWrap: 'wrap',
        }}>
          <div style={{ flex: '1 1 280px' }}>
            <label style={labelStyle}>Test an email against your saved trust rules</label>
            <input style={inputStyleLocal} type="text" value={senderTestEmail}
              placeholder="noreply@discord.com"
              onChange={(e) => setSenderTestEmail(e.target.value)}
              onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); runSenderTest(); } }} />
          </div>
          <button type="button" className="button button-secondary"
            disabled={!senderTestEmail.trim() || senderTesting}
            onClick={runSenderTest}>
            {senderTesting ? 'Testing…' : 'Test'}
          </button>
          {senderTestResult && (
            <div style={{
              flex: '1 1 100%',
              padding: '0.5rem 0.75rem',
              borderRadius: 'var(--radius-sm)',
              background: senderTestResult.is_trusted ? 'rgba(34, 197, 94, 0.15)' : 'var(--bg-tertiary)',
              border: `1px solid ${senderTestResult.is_trusted ? 'rgba(34, 197, 94, 0.4)' : 'var(--border-color)'}`,
              fontSize: '0.85rem',
            }}>
              {senderTestResult._error ? (
                <span style={{ color: '#ef4444' }}>Error: {senderTestResult._error}</span>
              ) : senderTestResult.is_trusted ? (
                <span>
                  <strong style={{ color: '#22c55e' }}>✓ Trusted</strong>
                  {' '}as <strong>{senderTestResult.trust_level}</strong>
                  {senderTestResult.organization && <> • {senderTestResult.organization}</>}
                  {senderTestResult.category && <> • {senderTestResult.category}</>}
                  {senderTestResult.reason && (
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.25rem' }}>
                      {senderTestResult.reason}
                    </div>
                  )}
                </span>
              ) : (
                <span style={{ color: 'var(--text-muted)' }}>
                  ✗ Not matched by any saved trust rule — would be analyzed normally
                </span>
              )}
            </div>
          )}
        </div>
        )}

        {loadingSenderTrust ? <div className="settings-loading"><div className="spinner"></div></div>
        : trustedSenders.length === 0 ? <div className="settings-empty">No trusted senders configured yet</div>
        : <div style={{ display: 'flex', flexDirection: 'column', gap: '0.4rem', marginBottom: '0.75rem' }}>
            {trustedSenders.map((s) => (
              <div key={s.id || s.domain} className="settings-item-card"
                   style={{ display: 'grid', gridTemplateColumns: '2fr 1fr auto auto', gap: '0.5rem', alignItems: 'center' }}>
                <div>
                  <div className="settings-item-name settings-mono">{s.domain || s.sender_pattern}</div>
                  {(s.organization || s.category) && (
                    <div className="settings-item-meta">{[s.organization, s.category].filter(Boolean).join(' • ')}</div>
                  )}
                </div>
                <span className={`settings-badge ${s.is_active === false ? 'settings-badge--disabled' : 'settings-badge--active'}`}>
                  {s.trust_level || 'trusted'}
                </span>
                <span style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>
                  {s.added_by ? `by ${s.added_by}` : ''}
                </span>
                <button onClick={() => onDeleteSender(s.id)} style={getActionButtonStyle('red')}>Remove</button>
              </div>
            ))}
          </div>}

        {!showAddSender ? (
          <button type="button" className="button button-primary" onClick={() => setShowAddSender(true)}>
            + Add trusted sender
          </button>
        ) : (
          <form onSubmit={submitSender} style={{
            padding: '0.75rem', border: '1px dashed var(--border-color)',
            borderRadius: 'var(--radius-md)', background: 'var(--bg-tertiary)',
            display: 'flex', flexDirection: 'column', gap: '0.75rem',
          }}>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 140px', gap: '0.5rem' }}>
              <div>
                <label style={labelStyle}>Domain *</label>
                <input style={inputStyleLocal} type="text" required value={senderForm.domain}
                  placeholder="discord.com"
                  onChange={(e) => setSenderForm({ ...senderForm, domain: e.target.value })} />
              </div>
              <div>
                <label style={labelStyle}>Sender pattern (optional)</label>
                <input style={inputStyleLocal} type="text" value={senderForm.sender_pattern}
                  placeholder="noreply@discord.com"
                  onChange={(e) => setSenderForm({ ...senderForm, sender_pattern: e.target.value })} />
              </div>
              <div>
                <label style={labelStyle}>Trust level</label>
                <select style={inputStyleLocal} value={senderForm.trust_level}
                  onChange={(e) => setSenderForm({ ...senderForm, trust_level: e.target.value })}>
                  <option value="verified">verified</option>
                  <option value="trusted">trusted</option>
                  <option value="known">known</option>
                </select>
              </div>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.5rem' }}>
              <div>
                <label style={labelStyle}>Organization (optional)</label>
                <input style={inputStyleLocal} type="text" value={senderForm.organization}
                  placeholder="Discord Inc."
                  onChange={(e) => setSenderForm({ ...senderForm, organization: e.target.value })} />
              </div>
              <div>
                <label style={labelStyle}>Category (optional)</label>
                <input style={inputStyleLocal} type="text" value={senderForm.category}
                  placeholder="social_media"
                  onChange={(e) => setSenderForm({ ...senderForm, category: e.target.value })} />
              </div>
            </div>
            <div>
              <label style={labelStyle}>Reason (optional)</label>
              <input style={inputStyleLocal} type="text" value={senderForm.reason}
                placeholder="Why this sender is trusted"
                onChange={(e) => setSenderForm({ ...senderForm, reason: e.target.value })} />
            </div>
            <div style={{ display: 'flex', gap: '0.5rem' }}>
              <button type="submit" className="button button-primary">+ Add sender</button>
              <button type="button" className="button button-secondary" onClick={() => setShowAddSender(false)}>Cancel</button>
            </div>
          </form>
        )}
      </div>

      {/* ── Phishing Test Patterns ─────────────────────────────────── */}
      <div className="settings-card">
        <div className="settings-card-header">
          <div>
            <h3 className="settings-card-title">Phishing Test Patterns</h3>
            <p className="settings-card-desc">
              Patterns that identify simulated-phishing emails from training vendors (KnowBe4,
              Proofpoint PSAT, etc.). Matching alerts auto-close as benign and <strong>skip IOC
              enrichment</strong> so the test URLs aren't visited by our scanners (which would
              auto-fail the employee).
            </p>
          </div>
          <button
            type="button"
            className="pa-btn-sm"
            onClick={() => {
              setShowPhishTest(!showPhishTest);
              if (showPhishTest) { setPhishTestResult(null); setPhishTestSender(''); setPhishTestSubject(''); }
            }}
            disabled={phishingTests.length === 0}
            title={phishingTests.length === 0 ? 'Add a phishing test pattern first' : 'Try a sender/subject against your saved rules'}
          >
            {showPhishTest ? 'Hide test' : 'Test an email'}
          </button>
        </div>

        {/* Collapsible test panel — hidden by default */}
        {showPhishTest && (
        <div style={{
          padding: '0.625rem 0.75rem', marginBottom: '0.75rem',
          border: '1px solid var(--border-color)', borderRadius: 'var(--radius-md)',
          background: 'var(--bg-secondary)',
          display: 'grid', gridTemplateColumns: '1fr 1fr auto', gap: '0.5rem', alignItems: 'end',
        }}>
          <div>
            <label style={labelStyle}>Test sender</label>
            <input style={inputStyleLocal} type="text" value={phishTestSender}
              placeholder="security@knowbe4.com"
              onChange={(e) => setPhishTestSender(e.target.value)} />
          </div>
          <div>
            <label style={labelStyle}>Test subject</label>
            <input style={inputStyleLocal} type="text" value={phishTestSubject}
              placeholder="Your account has been suspended"
              onChange={(e) => setPhishTestSubject(e.target.value)}
              onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); runPhishTest(); } }} />
          </div>
          <button type="button" className="button button-secondary"
            disabled={!phishTestSender.trim() || !phishTestSubject.trim() || phishTesting}
            onClick={runPhishTest}>
            {phishTesting ? 'Testing…' : 'Test'}
          </button>
          {phishTestResult && (
            <div style={{
              gridColumn: '1 / -1',
              padding: '0.5rem 0.75rem',
              borderRadius: 'var(--radius-sm)',
              background: phishTestResult.is_phishing_test ? 'rgba(34, 197, 94, 0.15)' : 'var(--bg-tertiary)',
              border: `1px solid ${phishTestResult.is_phishing_test ? 'rgba(34, 197, 94, 0.4)' : 'var(--border-color)'}`,
              fontSize: '0.85rem',
            }}>
              {phishTestResult._error ? (
                <span style={{ color: '#ef4444' }}>Error: {phishTestResult._error}</span>
              ) : phishTestResult.is_phishing_test ? (
                <span>
                  <strong style={{ color: '#22c55e' }}>✓ Matched as phishing test</strong>
                  {phishTestResult.test_name && <> — {phishTestResult.test_name}</>}
                  {phishTestResult.vendor && <> ({phishTestResult.vendor})</>}
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.25rem' }}>
                    {phishTestResult.auto_close ? 'Auto-closes as ' : 'Would be dispositioned as '}
                    <strong>{phishTestResult.disposition || 'BENIGN_POSITIVE'}</strong> • enrichment skipped
                  </div>
                </span>
              ) : (
                <span style={{ color: 'var(--text-muted)' }}>
                  ✗ No phishing-test pattern matched — this would proceed to normal triage and enrichment
                </span>
              )}
            </div>
          )}
        </div>
        )}

        {phishingTests.length === 0 ? <div className="settings-empty">No phishing test patterns configured yet</div>
        : <div style={{ display: 'flex', flexDirection: 'column', gap: '0.4rem', marginBottom: '0.75rem' }}>
            {phishingTests.map((t) => (
              <div key={t.id || `${t.sender_pattern}-${t.subject_pattern}`} className="settings-item-card"
                   style={{ display: 'grid', gridTemplateColumns: '2fr 2fr 1fr auto', gap: '0.5rem', alignItems: 'center' }}>
                <div>
                  <div className="settings-item-name">{t.test_name || t.vendor || 'Unnamed'}</div>
                  <div className="settings-item-meta">match: {t.match_type}</div>
                </div>
                <code style={{ fontFamily: 'monospace', fontSize: '0.75rem', color: 'var(--text-secondary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  from: {t.sender_pattern} / subj: {t.subject_pattern}
                </code>
                <span className="settings-badge settings-badge--active">{t.vendor || 'custom'}</span>
                <button onClick={() => onDeletePhishingTest(t.id)} style={getActionButtonStyle('red')}>Remove</button>
              </div>
            ))}
          </div>}

        {!showAddTest ? (
          <button type="button" className="button button-primary" onClick={() => setShowAddTest(true)}>
            + Add phishing test pattern
          </button>
        ) : (
          <form onSubmit={submitTest} style={{
            padding: '0.75rem', border: '1px dashed var(--border-color)',
            borderRadius: 'var(--radius-md)', background: 'var(--bg-tertiary)',
            display: 'flex', flexDirection: 'column', gap: '0.75rem',
          }}>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 140px', gap: '0.5rem' }}>
              <div>
                <label style={labelStyle}>Sender pattern *</label>
                <input style={inputStyleLocal} type="text" required value={testForm.sender_pattern}
                  placeholder="@knowbe4.com"
                  onChange={(e) => setTestForm({ ...testForm, sender_pattern: e.target.value })} />
              </div>
              <div>
                <label style={labelStyle}>Subject pattern *</label>
                <input style={inputStyleLocal} type="text" required value={testForm.subject_pattern}
                  placeholder="Phishing test"
                  onChange={(e) => setTestForm({ ...testForm, subject_pattern: e.target.value })} />
              </div>
              <div>
                <label style={labelStyle}>Match type</label>
                <select style={inputStyleLocal} value={testForm.match_type}
                  onChange={(e) => setTestForm({ ...testForm, match_type: e.target.value })}>
                  <option value="contains">contains</option>
                  <option value="exact">exact</option>
                  <option value="regex">regex</option>
                </select>
              </div>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.5rem' }}>
              <div>
                <label style={labelStyle}>Test name (optional)</label>
                <input style={inputStyleLocal} type="text" value={testForm.test_name}
                  placeholder="Q1 2026 simulation"
                  onChange={(e) => setTestForm({ ...testForm, test_name: e.target.value })} />
              </div>
              <div>
                <label style={labelStyle}>Vendor (optional)</label>
                <input style={inputStyleLocal} type="text" value={testForm.vendor}
                  placeholder="KnowBe4"
                  onChange={(e) => setTestForm({ ...testForm, vendor: e.target.value })} />
              </div>
            </div>
            <div style={{ display: 'flex', gap: '0.5rem' }}>
              <button type="submit" className="button button-primary">+ Add pattern</button>
              <button type="button" className="button button-secondary" onClick={() => setShowAddTest(false)}>Cancel</button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
}

function PreferencesSection({ preferences, updatePreference, savingPrefs }) {
  return (
    <div className="settings-card">
      <h3 className="settings-card-title">User Preferences</h3>
      <p className="settings-card-desc" style={{ marginBottom: '1.25rem' }}>Customize your display and notification preferences</p>
      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
        <div className="settings-pref-row">
          <div><div className="settings-pref-label">Theme</div><div className="settings-pref-desc">Switch between dark and light mode</div></div>
          <select value={preferences?.theme || 'dark'} onChange={(e) => updatePreference('theme', e.target.value)} disabled={savingPrefs} className="settings-pref-select">
            <option value="dark">Dark</option><option value="light">Light</option>
          </select>
        </div>
        <div className="settings-pref-row">
          <div><div className="settings-pref-label">Default Dashboard View</div><div className="settings-pref-desc">Choose which view appears on the dashboard by default</div></div>
          <select value={preferences?.default_view || 'alerts'} onChange={(e) => updatePreference('default_view', e.target.value)} disabled={savingPrefs} className="settings-pref-select">
            <option value="alerts">Alerts Queue</option><option value="investigations">Investigations</option><option value="dashboard">Dashboard</option>
          </select>
        </div>
        <div className="settings-pref-row">
          <div><div className="settings-pref-label">Page Size</div><div className="settings-pref-desc">Number of items per page in list views</div></div>
          <select value={preferences?.page_size || 25} onChange={(e) => updatePreference('page_size', parseInt(e.target.value))} disabled={savingPrefs} className="settings-pref-select">
            <option value={10}>10</option><option value={25}>25</option><option value={50}>50</option><option value={100}>100</option>
          </select>
        </div>
      </div>
    </div>
  );
}

function LicenseSection({ licenseInfo, loadingLicense, activatingLicense, licenseKey, setLicenseKey, licenseToken, setLicenseToken, licenseError, licenseSuccess, activateLicense }) {
  const getTierDisplay = (tier) => tier ? tier.charAt(0).toUpperCase() + tier.slice(1) : 'Unknown';
  return (
    <div className="settings-card">
      <h3 className="settings-card-title">License Management</h3>
      <p className="settings-card-desc" style={{ marginBottom: '1.25rem' }}>Activate a license key to unlock additional features</p>
      {loadingLicense ? <div className="settings-loading"><div className="spinner"></div></div> : (
        <div>
          <div className="settings-license-current">
            <div style={{ fontWeight: '600', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              Current License: <span className="settings-license-tier">{getTierDisplay(licenseInfo?.tier)}</span>
            </div>
            <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginTop: '0.5rem' }}>Status: {licenseInfo?.status === 'active' ? 'Active' : licenseInfo?.status || 'Unknown'}</div>
            {licenseInfo?.tenant_name && <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.25rem' }}>Tenant: {licenseInfo.tenant_name}</div>}
          </div>
          <div className="settings-form-group">
            <label className="settings-form-label">License Key</label>
            <input type="text" value={licenseKey} onChange={(e) => setLicenseKey(e.target.value)} placeholder="Enter your license key" className="settings-form-input" />
          </div>
          <div className="settings-btn-row" style={{ marginBottom: '1rem' }}>
            <button onClick={activateLicense} disabled={activatingLicense} className="button button-primary">{activatingLicense ? 'Activating...' : 'Activate License'}</button>
          </div>
          {licenseError && <div className="settings-alert settings-alert--error">{licenseError}</div>}
          {licenseSuccess && <div className="settings-alert settings-alert--success">{licenseSuccess}</div>}
        </div>
      )}
    </div>
  );
}

function DispositionsSection({ config, newDisposition, setNewDisposition, addDisposition }) {
  return (
    <div className="settings-card">
      <h3 className="settings-card-title">Disposition Types</h3>
      <p className="settings-card-desc" style={{ marginBottom: '1.25rem' }}>Configure the disposition options for investigations</p>
      <div className="settings-chip-row">
        {config?.dispositions?.map(d => (<span key={d.value} className="settings-chip" style={{ background: `${d.color}20`, color: d.color }}>{d.label}</span>))}
      </div>
      <div style={{ padding: '1.25rem', background: 'var(--bg-tertiary)', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-subtle)' }}>
        <h4 style={{ fontSize: '0.9rem', fontWeight: '600', marginBottom: '1rem' }}>Add New Disposition</h4>
        <div className="settings-form-row-3">
          <div><label className="settings-form-label">Value</label><input type="text" value={newDisposition.value} onChange={(e) => setNewDisposition({ ...newDisposition, value: e.target.value })} placeholder="e.g. ESCALATED" className="settings-form-input" /></div>
          <div><label className="settings-form-label">Label</label><input type="text" value={newDisposition.label} onChange={(e) => setNewDisposition({ ...newDisposition, label: e.target.value })} placeholder="e.g. Escalated" className="settings-form-input" /></div>
          <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'flex-end' }}>
            <input type="color" value={newDisposition.color} onChange={(e) => setNewDisposition({ ...newDisposition, color: e.target.value })} style={{ width: '40px', height: '38px', border: 'none', borderRadius: 'var(--radius-sm)', cursor: 'pointer', background: 'transparent' }} />
            <button onClick={addDisposition} className="button button-primary" style={{ whiteSpace: 'nowrap' }}>+ Add</button>
          </div>
        </div>
      </div>
    </div>
  );
}

function SeveritiesSection({ config, newSeverity, setNewSeverity, addSeverity }) {
  return (
    <div className="settings-card">
      <h3 className="settings-card-title">Severity Levels</h3>
      <p className="settings-card-desc" style={{ marginBottom: '1.25rem' }}>Configure severity levels for alerts and investigations</p>
      <div className="settings-chip-row">
        {config?.severities?.map(s => (<span key={s.value} className="settings-chip" style={{ background: `${s.color}20`, color: s.color }}>{s.label}</span>))}
      </div>
      <div style={{ padding: '1.25rem', background: 'var(--bg-tertiary)', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-subtle)' }}>
        <h4 style={{ fontSize: '0.9rem', fontWeight: '600', marginBottom: '1rem' }}>Add New Severity</h4>
        <div className="settings-form-row-4">
          <div><label className="settings-form-label">Value</label><input type="text" value={newSeverity.value} onChange={(e) => setNewSeverity({ ...newSeverity, value: e.target.value })} placeholder="e.g. CRITICAL" className="settings-form-input" /></div>
          <div><label className="settings-form-label">Label</label><input type="text" value={newSeverity.label} onChange={(e) => setNewSeverity({ ...newSeverity, label: e.target.value })} placeholder="e.g. Critical" className="settings-form-input" /></div>
          <div><label className="settings-form-label">Threshold</label><input type="number" value={newSeverity.threshold} onChange={(e) => setNewSeverity({ ...newSeverity, threshold: parseInt(e.target.value) || 0 })} min="0" max="100" className="settings-form-input" /></div>
          <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'flex-end' }}>
            <input type="color" value={newSeverity.color} onChange={(e) => setNewSeverity({ ...newSeverity, color: e.target.value })} style={{ width: '40px', height: '38px', border: 'none', borderRadius: 'var(--radius-sm)', cursor: 'pointer', background: 'transparent' }} />
            <button onClick={addSeverity} className="button button-primary" style={{ whiteSpace: 'nowrap' }}>+ Add</button>
          </div>
        </div>
      </div>
    </div>
  );
}

function ConfidenceSection({ config, toggleConfidenceMode }) {
  return (
    <div className="settings-card">
      <h3 className="settings-card-title">Confidence Display</h3>
      <p className="settings-card-desc" style={{ marginBottom: '1.25rem' }}>Configure how confidence scores are displayed</p>
      <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
        <span style={{ fontSize: '0.85rem' }}>Display Mode:</span>
        <button onClick={toggleConfidenceMode} className="button button-secondary">{config?.confidence?.display_mode === 'label' ? 'Labels' : 'Numeric'}</button>
      </div>
    </div>
  );
}

function CorrelationEngineSection({ settings, loading, saving, onUpdate }) {
  if (loading) return <div className="settings-card"><div className="settings-loading"><div className="spinner"></div></div></div>;
  const s = settings || {};
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
      <div className="settings-card">
        <h3 className="settings-card-title">Correlation Engine</h3>
        <p className="settings-card-desc" style={{ marginBottom: '1.25rem' }}>Configure how alerts are correlated into investigations</p>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
          <div className="settings-pref-row">
            <div><div className="settings-pref-label">Correlation Enabled</div><div className="settings-pref-desc">Automatically correlate alerts into investigations</div></div>
            <button onClick={() => onUpdate({ correlation_enabled: !s.correlation_enabled })} disabled={saving}
              className={`button ${s.correlation_enabled !== false ? 'button-primary' : 'button-secondary'}`}>
              {s.correlation_enabled !== false ? 'ON' : 'OFF'}
            </button>
          </div>
          <div className="settings-pref-row">
            <div><div className="settings-pref-label">AI Hypothesis Generation</div><div className="settings-pref-desc">Use Claude to evaluate alert-to-hypothesis support (uses token quota)</div></div>
            <button onClick={() => onUpdate({ ai_hypothesis_enabled: !s.ai_hypothesis_enabled })} disabled={saving}
              className={`button ${s.ai_hypothesis_enabled !== false ? 'button-primary' : 'button-secondary'}`}>
              {s.ai_hypothesis_enabled !== false ? 'ON' : 'OFF'}
            </button>
          </div>
          <div className="settings-pref-row">
            <div><div className="settings-pref-label">Entity Risk Accumulation</div><div className="settings-pref-desc">Track entity risk scores across alerts and trigger correlation when thresholds are breached</div></div>
            <button onClick={() => onUpdate({ entity_risk_enabled: !s.entity_risk_enabled })} disabled={saving}
              className={`button ${s.entity_risk_enabled !== false ? 'button-primary' : 'button-secondary'}`}>
              {s.entity_risk_enabled !== false ? 'ON' : 'OFF'}
            </button>
          </div>
          <div className="settings-pref-row">
            <div><div className="settings-pref-label">Cross-Domain Correlation</div><div className="settings-pref-desc">Allow correlation across threat domains (email, endpoint, identity, network, cloud)</div></div>
            <button onClick={() => onUpdate({ allow_cross_domain: !s.allow_cross_domain })} disabled={saving}
              className={`button ${s.allow_cross_domain ? 'button-primary' : 'button-secondary'}`}>
              {s.allow_cross_domain ? 'ON' : 'OFF'}
            </button>
          </div>
        </div>
        <div style={{ marginTop: '1.25rem', display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))', gap: '0.75rem' }}>
          <div>
            <label className="settings-form-label">Time Window (hours)</label>
            <input type="number" value={s.time_window_hours ?? 24} min={1} max={168}
              onChange={(e) => onUpdate({ time_window_hours: parseInt(e.target.value) || 24 })}
              className="settings-form-input" disabled={saving} />
          </div>
          <div>
            <label className="settings-form-label">Min Evidence Score (0-100)</label>
            <input type="number" value={s.min_evidence_score ?? 40} min={0} max={100}
              onChange={(e) => onUpdate({ min_evidence_score: parseInt(e.target.value) || 40 })}
              className="settings-form-input" disabled={saving} />
          </div>
          <div>
            <label className="settings-form-label">Auto-Confirm Threshold (0-100)</label>
            <input type="number" value={s.auto_confirm_threshold ?? 100} min={0} max={100}
              onChange={(e) => onUpdate({ auto_confirm_threshold: parseInt(e.target.value) || 100 })}
              className="settings-form-input" disabled={saving} />
          </div>
          <div>
            <label className="settings-form-label">Max Alerts per Investigation</label>
            <input type="number" value={s.max_alerts_per_investigation ?? 25} min={5} max={100}
              onChange={(e) => onUpdate({ max_alerts_per_investigation: parseInt(e.target.value) || 25 })}
              className="settings-form-input" disabled={saving} />
          </div>
        </div>
      </div>
    </div>
  );
}

function EntityRiskSection({ settings, loading, saving, onUpdate, highRiskEntities, onResetRisk }) {
  if (loading) return null;
  const s = settings || {};
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
      <div className="settings-card">
        <h3 className="settings-card-title">Entity Risk Tuning</h3>
        <p className="settings-card-desc" style={{ marginBottom: '1.25rem' }}>Configure how entity risk scores are accumulated and decayed</p>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))', gap: '0.75rem' }}>
          <div>
            <label className="settings-form-label">Risk Threshold</label>
            <input type="number" value={s.entity_risk_threshold ?? 75} min={10} max={200}
              onChange={(e) => onUpdate({ entity_risk_threshold: parseInt(e.target.value) || 75 })}
              className="settings-form-input" disabled={saving} />
          </div>
          <div>
            <label className="settings-form-label">Decay Period (hours)</label>
            <input type="number" value={s.entity_risk_decay_hours ?? 72} min={1} max={720}
              onChange={(e) => onUpdate({ entity_risk_decay_hours: parseInt(e.target.value) || 72 })}
              className="settings-form-input" disabled={saving} />
          </div>
          <div>
            <label className="settings-form-label">User Weight</label>
            <input type="number" value={s.user_weight ?? 30} min={0} max={100}
              onChange={(e) => onUpdate({ user_weight: parseInt(e.target.value) || 30 })}
              className="settings-form-input" disabled={saving} />
          </div>
          <div>
            <label className="settings-form-label">Host Weight</label>
            <input type="number" value={s.host_weight ?? 25} min={0} max={100}
              onChange={(e) => onUpdate({ host_weight: parseInt(e.target.value) || 25 })}
              className="settings-form-input" disabled={saving} />
          </div>
          <div>
            <label className="settings-form-label">IP Weight</label>
            <input type="number" value={s.ip_weight ?? 15} min={0} max={100}
              onChange={(e) => onUpdate({ ip_weight: parseInt(e.target.value) || 15 })}
              className="settings-form-input" disabled={saving} />
          </div>
          <div>
            <label className="settings-form-label">IOC Weight</label>
            <input type="number" value={s.ioc_weight ?? 20} min={0} max={100}
              onChange={(e) => onUpdate({ ioc_weight: parseInt(e.target.value) || 20 })}
              className="settings-form-input" disabled={saving} />
          </div>
        </div>
      </div>
      {highRiskEntities.length > 0 && (
        <div className="settings-card">
          <h3 className="settings-card-title">High Risk Entities</h3>
          <p className="settings-card-desc" style={{ marginBottom: '0.75rem' }}>
            Entities that have breached the risk threshold. Breached entities auto-open an investigation that groups their contributing alerts.
          </p>
          <table className="settings-table">
            <thead><tr><th>Type</th><th>Value</th><th>Risk Score</th><th>Alerts</th><th>Last Seen</th><th>Investigation</th><th>Actions</th></tr></thead>
            <tbody>
              {highRiskEntities.map((e, i) => (
                <tr key={i}>
                  <td><span className="settings-ioc-badge">{e.entity_type}</span></td>
                  <td className="settings-mono">{e.entity_value}</td>
                  <td style={{ fontWeight: 600, color: e.threshold_breached ? 'var(--destructive, #ef4444)' : 'var(--text-primary)' }}>
                    {typeof e.risk_score === 'number' ? e.risk_score.toFixed(1) : e.risk_score}
                  </td>
                  <td>{e.alert_count}</td>
                  <td style={{ color: 'var(--text-muted)', fontSize: '0.8rem' }}>
                    {e.last_seen ? new Date(e.last_seen).toLocaleString() : '-'}
                  </td>
                  <td>
                    {e.investigation_id ? (
                      <a
                        href={`/investigation/${e.investigation_id}`}
                        style={{ color: 'var(--primary)', textDecoration: 'none', fontFamily: 'monospace', fontSize: '0.8rem' }}
                        title="Open the auto-created investigation"
                      >
                        {e.investigation_id} →
                      </a>
                    ) : (
                      <span style={{ color: 'var(--text-muted)', fontSize: '0.8rem' }}>
                        {e.threshold_breached ? '(pending)' : '—'}
                      </span>
                    )}
                  </td>
                  <td><button onClick={() => onResetRisk(e.entity_type, e.entity_value)} style={getActionButtonStyle('red')}>Reset</button></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

export default Settings;
