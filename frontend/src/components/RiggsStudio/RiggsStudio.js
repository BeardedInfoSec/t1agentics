/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

/**
 * Automation Studio - AI-Powered Security Automation Platform
 *
 * A comprehensive interface for:
 * - AI-powered alert analysis and triage
 * - Building playbooks with AI assistance
 * - Managing and monitoring automated responses
 * - Viewing intelligence and metrics
 */

import React, { useState, useEffect, useCallback } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import {
  Bot, Brain, Zap,
  Play, BarChart3, LayoutGrid,
  CheckCircle, XCircle, AlertTriangle, RefreshCw,
  Target, FileText, Sparkles, ArrowRight, Search,
  TrendingUp, Upload, ChevronDown, ChevronUp,
  BookOpen, ShieldCheck, Clock, Plus, ExternalLink, FolderInput, FileUp,
  Download
} from 'lucide-react';
import { getLicenseTier } from '../../utils/licenseCache';
import { authFetch } from '../../utils/api';
import PlaybookMarketplace from '../PlaybookMarketplace';
import PlaybookConverterCodex from '../../pages/PlaybookConverterCodex';
import './RiggsStudio.css';

const API_BASE = process.env.REACT_APP_API_URL || '';

// Tab configuration. `path` is the canonical URL for each tab so the
// browser's back/forward + bookmarks stay in sync; the tab is selected
// based on the current URL, not internal state.
const TABS = [
  { id: 'playbooks',    label: 'My Playbooks', icon: BookOpen,    accent: 'blue',   path: '/playbooks' },
  { id: 'build',        label: 'Build with Riggs', icon: Zap,     accent: 'amber',  path: '/automation-studio' },
  { id: 'marketplace',  label: 'Marketplace',  icon: LayoutGrid,  accent: 'blue',   path: '/playbook-marketplace' },
  { id: 'import',       label: 'Import',       icon: Download,    accent: 'amber',  path: '/playbooks/import-soar' },
  { id: 'intelligence', label: 'Intelligence', icon: BarChart3,   accent: 'purple', path: '/playbooks/intelligence' },
];

function tabFromPath(pathname) {
  if (pathname.startsWith('/automation-studio')) return 'build';
  if (pathname.startsWith('/playbook-marketplace')) return 'marketplace';
  if (pathname.startsWith('/playbooks/import-soar')) return 'import';
  if (pathname.startsWith('/playbooks/intelligence')) return 'intelligence';
  return 'playbooks';
}

export default function RiggsStudio() {
  const navigate = useNavigate();
  const location = useLocation();
  const activeTab = tabFromPath(location.pathname);

  const switchTab = (tabId) => {
    const tab = TABS.find((t) => t.id === tabId);
    if (tab && tab.path !== location.pathname) navigate(tab.path);
  };

  return (
    <div className="riggs-studio">
      {/* Compact Header + Tabs Row */}
      <div className="riggs-topbar">
        <div className="riggs-brand">
          <div className="riggs-logo">
            <Bot size={18} />
          </div>
          <span className="riggs-wordmark">Playbooks</span>
        </div>

        <nav className="riggs-tabs">
          {TABS.map((tab) => (
            <button
              key={tab.id}
              className={`riggs-tab ${activeTab === tab.id ? 'active' : ''} tab-accent-${tab.accent}`}
              onClick={() => switchTab(tab.id)}
              data-tour={`playbooks-tab-${tab.id}`}
            >
              <tab.icon size={15} />
              <span>{tab.label}</span>
            </button>
          ))}
        </nav>
      </div>

      {/* Content */}
      <main className="riggs-content">
        {activeTab === 'playbooks' && <MyPlaybooksTab navigate={navigate} onSwitchTab={switchTab} />}
        {activeTab === 'build' && <PlaybookBuilderTab navigate={navigate} />}
        {activeTab === 'marketplace' && <PlaybookMarketplace />}
        {activeTab === 'import' && <PlaybookConverterCodex />}
        {activeTab === 'intelligence' && <IntelligenceTab />}
      </main>
    </div>
  );
}

// ============================================================================
// Playbook Builder Tab
// ============================================================================

// Build steps mapped to estimated progress brackets. We cannot get
// real percent-complete from the LLM, so we use elapsed time as a proxy:
// progress climbs to 95% over ~18s and snaps to 100% when the response
// arrives. This makes the wait feel intentional rather than looped.
const RIGGS_BUILD_STEPS = [
  { upTo: 0.15, text: 'Reading your requirements...' },
  { upTo: 0.30, text: 'Checking your configured connectors...' },
  { upTo: 0.50, text: 'Picking node types and flow shape...' },
  { upTo: 0.70, text: 'Wiring conditions and approval gates...' },
  { upTo: 0.90, text: 'Validating the playbook structure...' },
  { upTo: 1.01, text: 'Almost done, saving to your gallery...' },
];
const RIGGS_BUILD_ESTIMATED_MS = 18000;

function PlaybookBuilderTab({ navigate }) {
  const [prompt, setPrompt] = useState('');
  const [isGenerating, setIsGenerating] = useState(false);
  const [generatedPlaybook, setGeneratedPlaybook] = useState(null);
  const [licenseData, setLicenseData] = useState(null);
  const [progress, setProgress] = useState(0);

  useEffect(() => {
    getLicenseTier().then(setLicenseData).catch(e => console.error('License tier error:', e));
  }, []);

  // Drive the loading progress with elapsed time as a percent-complete
  // proxy. Asymptotically approaches 95% and lets the actual response
  // bump it to 100% when generation finishes.
  useEffect(() => {
    if (!isGenerating) {
      setProgress(0);
      return undefined;
    }
    const startedAt = Date.now();
    const tick = () => {
      const elapsed = Date.now() - startedAt;
      // Smooth easing toward 0.95 -- never reach 1.0 from elapsed alone.
      const ratio = Math.min(elapsed / RIGGS_BUILD_ESTIMATED_MS, 1);
      const eased = 0.95 * (1 - Math.pow(1 - ratio, 1.8));
      setProgress(eased);
    };
    tick();
    const interval = setInterval(tick, 200);
    return () => clearInterval(interval);
  }, [isGenerating]);

  // Pick the message for the current progress bracket.
  const currentStep = RIGGS_BUILD_STEPS.find((s) => progress < s.upTo) || RIGGS_BUILD_STEPS[RIGGS_BUILD_STEPS.length - 1];
  const progressPct = Math.round(progress * 100);

  const pbUsage = licenseData?.riggs_usage?.playbook_create;
  const pbLimit = licenseData?.riggs_limits?.playbook_creations_per_month || 0;
  const isUnlimited = pbUsage?.unlimited !== false;
  const pbUsed = pbUsage?.used || 0;
  const isPbLimited = !isUnlimited && pbLimit > 0 && pbUsed >= pbLimit;

  const quickPrompts = [
    { label: 'Phishing Response', desc: 'Enrich sender domain, check reputation, block if malicious', full: 'Create a phishing response playbook that enriches sender domain, checks reputation, and blocks if malicious' },
    { label: 'Suspicious Login', desc: 'Verify user location, trigger MFA if anomalous', full: 'Build a suspicious login playbook that verifies user location and triggers MFA if anomalous' },
    { label: 'Malware Detection', desc: 'Isolate host, create ticket for investigation', full: 'Design a malware detection playbook that isolates host and creates a ticket for investigation' },
    { label: 'Alert Triage', desc: 'Enrich IOCs, escalate based on severity', full: 'Create an alert triage playbook that enriches IOCs and escalates based on severity' },
  ];

  const generatePlaybook = async () => {
    if (!prompt.trim()) return;
    if (isPbLimited) {
      setGeneratedPlaybook({
        error: true,
        message: `Monthly AI playbook limit reached (${pbUsed}/${pbLimit}). Upgrade to Pro for unlimited access.`,
      });
      return;
    }

    setIsGenerating(true);
    setGeneratedPlaybook(null);

    try {
      // Pre-flight: hand Riggs the tenant's actual configured connectors
      // and the list of IOC types the platform auto-enriches. Without this
      // context the model invents fictitious vendors and pads the playbook
      // with redundant enrich nodes.
      let availableConnectors = [];
      try {
        const cRes = await authFetch(`${API_BASE}/api/v1/connect/instances`);
        if (cRes.ok) {
          const cData = await cRes.json();
          const list = Array.isArray(cData) ? cData : (cData.instances || cData.items || []);
          availableConnectors = list
            .filter((inst) => inst.enabled !== false)
            .map((inst) => ({
              id: inst.id || inst.instance_id,
              connector_name: inst.connector_name || inst.name,
              vendor: inst.vendor,
              category: inst.category,
              actions: inst.actions || inst.connector_actions || [],
            }));
        }
      } catch (e) {
        // Non-fatal; fall through with empty list. Riggs handles the empty
        // case explicitly (uses generic action types).
      }

      const response = await authFetch(`${API_BASE}/api/v1/riggs/builder/generate`, {
        method: 'POST',
        body: JSON.stringify({
          requirements: prompt,
          // Auto-enrichment is a platform-level capability, so the builder
          // skips the redundant per-IOC-type enrich nodes.
          include_enrichment: false,
          include_approval_gates: true,
          // Tenant context that lets Riggs build something usable: the
          // connectors that are actually wired up + the IOC types the
          // platform auto-enriches before any playbook ever runs.
          available_connectors: availableConnectors,
          auto_enriched_ioc_types: ['ip', 'domain', 'url', 'hash', 'email'],
        }),
      });

      if (response.status === 429) {
        const err = await response.json();
        setGeneratedPlaybook({
          error: true,
          message: err.detail?.message || 'Monthly AI playbook limit reached. Upgrade to Pro for unlimited access.',
        });
        return;
      }

      if (response.status === 403) {
        const err = await response.json();
        setGeneratedPlaybook({
          error: true,
          message: err.detail?.message || 'This feature is not available on your current plan.',
        });
        return;
      }

      if (response.ok) {
        const result = await response.json();
        if (result?.success === false) {
          setGeneratedPlaybook({
            error: true,
            message: result.message || 'Failed to generate playbook. Please try again.',
          });
          return;
        }
        const playbook = result?.playbook || result;
        // Snap to 100% briefly so the bar visibly completes before the
        // result card replaces the working panel.
        setProgress(1);
        setGeneratedPlaybook(playbook);
      } else {
        throw new Error('Generation failed');
      }
    } catch (err) {
      setGeneratedPlaybook({
        error: true,
        message: 'Failed to generate playbook. Please try again.',
      });
    } finally {
      setIsGenerating(false);
    }
  };

  const openInEditor = () => {
    const playbookId = generatedPlaybook?.id;
    if (playbookId) {
      navigate(`/playbooks/${playbookId}`);
    } else if (generatedPlaybook?.canvas_data) {
      sessionStorage.setItem('riggs_generated_playbook', JSON.stringify(generatedPlaybook));
      navigate('/playbooks/new?from=riggs');
    }
  };

  return (
    <div className="builder-layout">
      <div className="builder-card">
        <div className="builder-card-header">
          <div className="builder-icon">
            <Zap size={20} />
          </div>
          <div>
            <h2>AI Playbook Builder</h2>
            <p>Describe your automation goal and Riggs will generate a complete playbook</p>
          </div>
        </div>

        <div className="builder-input-area">
          <textarea
            value={prompt}
            onChange={(e) => setPrompt(e.target.value)}
            placeholder="Describe the security automation you want to create...&#10;&#10;Example: Create a playbook that handles phishing alerts by enriching the sender domain with VirusTotal, checking if it's on our allowlist, and if malicious, blocking the sender and creating a Jira ticket."
            rows={5}
          />
          <div className="builder-input-footer">
            {!isUnlimited && pbLimit > 0 && (
              <span className={`builder-quota ${isPbLimited ? 'exhausted' : ''}`}>
                {isPbLimited
                  ? `Limit reached (${pbUsed}/${pbLimit})`
                  : `${pbLimit - pbUsed} of ${pbLimit} remaining`}
              </span>
            )}
            <button
              className="generate-btn"
              onClick={generatePlaybook}
              disabled={isGenerating || !prompt.trim() || isPbLimited}
            >
              {isGenerating ? (
                <>
                  <RefreshCw className="spin" size={15} />
                  Generating...
                </>
              ) : isPbLimited ? (
                <>
                  <XCircle size={15} />
                  Limit Reached
                </>
              ) : (
                <>
                  <Sparkles size={15} />
                  Generate Playbook
                </>
              )}
            </button>
          </div>
        </div>

        <div className="quick-prompts">
          <span className="quick-prompts-label">Quick start</span>
          <div className="quick-grid">
            {quickPrompts.map((qp, i) => (
              <button
                key={i}
                className="quick-card"
                onClick={() => setPrompt(qp.full)}
              >
                <span className="quick-card-name">{qp.label}</span>
                <span className="quick-card-desc">{qp.desc}</span>
              </button>
            ))}
          </div>
        </div>
      </div>

      {isGenerating && (
        <div className="builder-result">
          <div className="riggs-working">
            <img
              src="/riggs_investigating.png"
              alt=""
              className="riggs-working-img"
              aria-hidden="true"
            />
            <div className="riggs-working-text">
              <div className="riggs-working-title-row">
                <div className="riggs-working-title">Riggs is building your playbook</div>
                <div className="riggs-working-pct" aria-live="polite">{progressPct}%</div>
              </div>
              <div className="riggs-working-step">{currentStep.text}</div>
              <div
                className="riggs-working-bar"
                role="progressbar"
                aria-valuemin={0}
                aria-valuemax={100}
                aria-valuenow={progressPct}
              >
                <span
                  className="riggs-working-bar-fill"
                  style={{ width: `${progressPct}%` }}
                />
              </div>
            </div>
          </div>
        </div>
      )}

      {generatedPlaybook && !isGenerating && (
        <div className="builder-result">
          {generatedPlaybook.error ? (
            <div className="result-error-card">
              <XCircle size={18} />
              <span>{generatedPlaybook.message}</span>
            </div>
          ) : (
            <div className="result-playbook-card">
              <div className="result-playbook-header">
                <div>
                  <h3>{generatedPlaybook.name || generatedPlaybook.playbook?.name || 'Generated Playbook'}</h3>
                  <p>{generatedPlaybook.description || generatedPlaybook.playbook?.description}</p>
                  {generatedPlaybook.generation_source && (
                    <div className={`gen-source ${generatedPlaybook.generation_source === 'template' ? 'template' : ''}`}>
                      {generatedPlaybook.generation_source === 'llm' ? 'AI Generated' : 'Template Fallback'}
                      {generatedPlaybook.generation_reason ? ` — ${generatedPlaybook.generation_reason}` : ''}
                    </div>
                  )}
                  {generatedPlaybook.saved && (
                    <div className="gen-saved">
                      <CheckCircle size={12} /> Saved to gallery
                    </div>
                  )}
                </div>
                <button className="open-editor-btn" onClick={openInEditor}>
                  Open in Editor
                  <ArrowRight size={14} />
                </button>
              </div>

              {(generatedPlaybook.canvas_data?.nodes || generatedPlaybook.nodes) && (
                <div className="result-nodes">
                  <h4>Playbook Structure</h4>
                  <div className="node-list">
                    {(generatedPlaybook.canvas_data?.nodes || generatedPlaybook.nodes).map((node, i) => (
                      <div key={i} className="node-item">
                        <span className={`node-type nt-${node.type || node.kind}`}>
                          {node.type || node.kind}
                        </span>
                        <span className="node-label">
                          {node.data?.label || node.data?.title || node.label || 'Node'}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {generatedPlaybook.explanation && (
                <div className="result-explanation">
                  <h4>How it works</h4>
                  <p>{generatedPlaybook.explanation}</p>
                </div>
              )}
            </div>
          )}
        </div>
      )}

    </div>
  );
}

// ============================================================================
// My Playbooks Tab
// ============================================================================

function MyPlaybooksTab({ navigate, onSwitchTab }) {
  const [playbooks, setPlaybooks] = useState([]);
  const [isLoading, setIsLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [filter, setFilter] = useState('all');
  const [showImport, setShowImport] = useState(false);

  useEffect(() => { fetchPlaybooks(); }, []);

  const fetchPlaybooks = async () => {
    setIsLoading(true);
    try {
      const res = await authFetch(`${API_BASE}/api/v1/playbooks?limit=100`);
      if (res.ok) {
        const data = await res.json();
        setPlaybooks(data.playbooks || data || []);
      }
    } catch (err) {
      console.error('Failed to fetch playbooks:', err);
    } finally {
      setIsLoading(false);
    }
  };

  const filtered = playbooks.filter(pb => {
    if (search) {
      const q = search.toLowerCase();
      if (!(pb.name || '').toLowerCase().includes(q) && !(pb.description || '').toLowerCase().includes(q)) return false;
    }
    if (filter === 'active') return pb.is_enabled;
    if (filter === 'inactive') return !pb.is_enabled;
    return true;
  });

  return (
    <div className="gallery-layout">
      <div className="gallery-toolbar">
        <div className="gallery-search">
          <Search size={14} />
          <input
            type="text"
            placeholder="Search playbooks..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>

        <div className="gallery-filter-group">
          {['all', 'active', 'inactive'].map(f => (
            <button key={f} className={`filter-pill ${filter === f ? 'active' : ''}`} onClick={() => setFilter(f)}>
              {f === 'all' ? 'All' : f === 'active' ? 'Active' : 'Inactive'}
            </button>
          ))}
        </div>

        <button
          className={`create-btn import-toggle-btn ${showImport ? 'active' : ''}`}
          onClick={() => setShowImport(!showImport)}
        >
          <FolderInput size={14} />
          Import
        </button>
        <button className="create-btn" onClick={() => navigate('/playbooks/new')}>
          <Plus size={14} />
          Create New
        </button>
      </div>

      {showImport && (
        <ImportTab navigate={navigate} onDone={() => { setShowImport(false); fetchPlaybooks(); }} />
      )}

      <div className="gallery-grid">
        {isLoading ? (
          <div className="gallery-state">
            <RefreshCw className="spin" size={20} />
            <span>Loading playbooks...</span>
          </div>
        ) : filtered.length === 0 && search ? (
          <div className="gallery-empty">
            <div className="gallery-empty-icon"><Search size={24} /></div>
            <h3>No matches</h3>
            <p>Try a different search term</p>
          </div>
        ) : filtered.length === 0 ? (
          <div className="gallery-onboard">
            <div className="gallery-onboard-hero">
              <div className="gallery-onboard-icon"><Zap size={28} /></div>
              <h2>Get started with automation</h2>
              <p>Build playbooks from scratch, import from your existing SOAR, or install ready-made templates from the Marketplace.</p>
            </div>
            <div className="gallery-onboard-cards">
              <button className="onboard-card" onClick={() => setShowImport(true)}>
                <div className="onboard-card-icon import"><FolderInput size={22} /></div>
                <h3>Import from SOAR</h3>
                <p>Bring your Splunk SOAR, Sentinel, Palo Alto XSOAR, and 15+ other platform playbooks directly in.</p>
                <span className="onboard-card-cta">Select platform &rarr;</span>
              </button>
              <button className="onboard-card" onClick={() => onSwitchTab?.('marketplace')}>
                <div className="onboard-card-icon marketplace"><LayoutGrid size={22} /></div>
                <h3>Browse Marketplace</h3>
                <p>200+ pre-built playbooks for phishing, malware, identity threats, compliance, and more.</p>
                <span className="onboard-card-cta">Explore templates &rarr;</span>
              </button>
              <button className="onboard-card" onClick={() => navigate('/playbooks/new')}>
                <div className="onboard-card-icon create"><Sparkles size={22} /></div>
                <h3>Build with AI</h3>
                <p>Describe what you need in plain English and let AI generate a complete playbook for you.</p>
                <span className="onboard-card-cta">Start building &rarr;</span>
              </button>
            </div>
          </div>
        ) : (
          filtered.map(pb => (
            <div key={pb.id} className="pb-card" onClick={() => navigate(`/playbooks/${pb.id}`)}>
              <div className="pb-card-top">
                <h3>{pb.name}</h3>
                <div className="pb-badges">
                  <span className={`pb-badge ${pb.is_enabled ? 'active' : 'inactive'}`}>
                    {pb.is_enabled ? 'Active' : 'Draft'}
                  </span>
                  {pb.riggs_allowed && <span className="pb-badge ai">AI</span>}
                </div>
              </div>
              <p className="pb-desc">{pb.description || 'No description'}</p>
              <div className="pb-footer">
                <span className="pb-date">
                  <Clock size={11} />
                  {new Date(pb.updated_at || pb.created_at).toLocaleDateString()}
                </span>
                <div className="pb-tags">
                  {(pb.tags || []).slice(0, 2).map((tag, i) => (
                    <span key={i} className="pb-tag">{tag}</span>
                  ))}
                  {(pb.tags || []).length > 2 && <span className="pb-tag">+{pb.tags.length - 2}</span>}
                </div>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}

// ============================================================================
// Approvals Tab
// ============================================================================

function ApprovalsTab() {
  const [requests, setRequests] = useState([]);
  const [isLoading, setIsLoading] = useState(true);
  const [actionInProgress, setActionInProgress] = useState(null);

  useEffect(() => { fetchQueue(); }, []);

  const fetchQueue = async () => {
    setIsLoading(true);
    try {
      const res = await authFetch(`${API_BASE}/api/v1/actions/requests/queue?limit=50`);
      if (res.ok) {
        const data = await res.json();
        setRequests(data.requests || []);
      }
    } catch (err) {
      console.error('Failed to fetch approvals:', err);
    } finally {
      setIsLoading(false);
    }
  };

  const handleAction = async (requestId, action) => {
    setActionInProgress(requestId);
    try {
      const res = await authFetch(`${API_BASE}/api/v1/actions/requests/${requestId}/${action}`, {
        method: 'POST',
        body: JSON.stringify(action === 'approve'
          ? { execute_immediately: true }
          : { denial_reason: 'Denied from Automation Studio' }
        ),
      });
      if (res.ok) {
        setRequests(prev => prev.filter(r => r.request_id !== requestId));
      }
    } catch (err) {
      console.error(`Failed to ${action}:`, err);
    } finally {
      setActionInProgress(null);
    }
  };

  const priorityColor = (p) => {
    switch (p) {
      case 'critical': return '#ef4444';
      case 'high': return '#f97316';
      case 'medium': return '#eab308';
      default: return '#3b82f6';
    }
  };

  if (isLoading) {
    return (
      <div className="intel-layout">
        <div className="intel-loading">
          <RefreshCw className="spin" size={24} />
          <span>Loading pending approvals...</span>
        </div>
      </div>
    );
  }

  return (
    <div className="gallery-layout">
      <div className="gallery-toolbar">
        <h2 style={{ fontSize: 16, fontWeight: 600, margin: 0, color: 'var(--text-primary, #e6edf3)' }}>
          Pending Approvals
        </h2>
        <button className="icon-btn" onClick={fetchQueue} title="Refresh">
          <RefreshCw size={14} />
        </button>
      </div>

      {requests.length === 0 ? (
        <div className="gallery-empty">
          <div className="gallery-empty-icon"><ShieldCheck size={24} /></div>
          <h3>No pending approvals</h3>
          <p>All action requests have been processed</p>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {requests.map(req => (
            <div key={req.request_id} className="builder-card" style={{ padding: 16 }}>
              <div style={{ display: 'flex', alignItems: 'flex-start', gap: 14 }}>
                <div style={{
                  width: 36, height: 36, borderRadius: 10, display: 'flex', alignItems: 'center', justifyContent: 'center',
                  background: `${priorityColor(req.priority)}18`, border: `1px solid ${priorityColor(req.priority)}30`,
                  color: priorityColor(req.priority), flexShrink: 0,
                }}>
                  <ShieldCheck size={18} />
                </div>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                    <span style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-primary, #e6edf3)' }}>
                      {req.action_display_name || req.action_type}
                    </span>
                    <span style={{
                      fontSize: 10, fontWeight: 700, textTransform: 'uppercase', padding: '2px 8px',
                      borderRadius: 4, background: `${priorityColor(req.priority)}18`,
                      color: priorityColor(req.priority),
                    }}>
                      {req.priority}
                    </span>
                    {req.inv_number && (
                      <span style={{ fontSize: 11, color: 'var(--text-muted, #6e7681)' }}>{req.inv_number}</span>
                    )}
                  </div>
                  <div style={{ fontSize: 13, color: 'var(--text-secondary, #8b949e)', marginBottom: 6 }}>
                    <strong>{req.target_type}:</strong> {req.target_value}
                  </div>
                  {req.reasoning && (
                    <div style={{ fontSize: 12, color: 'var(--text-muted, #6e7681)', lineHeight: 1.5, marginBottom: 8 }}>
                      {req.reasoning.length > 200 ? req.reasoning.slice(0, 200) + '...' : req.reasoning}
                    </div>
                  )}
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <button
                      className="generate-btn"
                      style={{ padding: '5px 14px', fontSize: 12 }}
                      disabled={actionInProgress === req.request_id}
                      onClick={() => handleAction(req.request_id, 'approve')}
                    >
                      <CheckCircle size={13} /> Approve
                    </button>
                    <button
                      className="feedback-btn"
                      style={{ padding: '5px 14px' }}
                      disabled={actionInProgress === req.request_id}
                      onClick={() => handleAction(req.request_id, 'deny')}
                    >
                      <XCircle size={13} /> Deny
                    </button>
                    <span style={{ marginLeft: 'auto', fontSize: 11, color: 'var(--text-muted, #6e7681)' }}>
                      {new Date(req.created_at).toLocaleString()}
                    </span>
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ============================================================================
// Import Tab — Convert playbooks from external SOAR platforms
// ============================================================================

const IMPORT_PLATFORMS = [
  { id: 'splunk_soar', name: 'Splunk SOAR', vendor: 'Cisco / Splunk', accept: '.tgz,.tar.gz,.gz,.json', hint: 'Upload .tgz archive or .json export', formats: ['TGZ', 'JSON'] },
  { id: 'xsoar', name: 'Cortex XSOAR', vendor: 'Palo Alto Networks', accept: '.yml,.yaml,.json', hint: 'Upload YAML or JSON playbook export', formats: ['YAML', 'JSON'] },
  { id: 'sentinel', name: 'Microsoft Sentinel', vendor: 'Microsoft', accept: '.json', hint: 'Upload ARM template or Logic App .json', formats: ['JSON'] },
  { id: 'chronicle_soar', name: 'Chronicle SOAR', vendor: 'Google', accept: '.json,.yml,.yaml', hint: 'Upload playbook export', formats: ['JSON', 'YAML'] },
  { id: 'qradar_soar', name: 'QRadar SOAR', vendor: 'IBM', accept: '.json,.res', hint: 'Upload playbook .json or .res export', formats: ['JSON', 'RES'] },
  { id: 'fortisoar', name: 'FortiSOAR', vendor: 'Fortinet', accept: '.json', hint: 'Upload workflow .json export', formats: ['JSON'] },
  { id: 'tines', name: 'Tines', vendor: 'Tines', accept: '.json', hint: 'Upload story .json export', formats: ['JSON'] },
  { id: 'swimlane', name: 'Swimlane', vendor: 'Swimlane', accept: '.json', hint: 'Upload workflow .json export', formats: ['JSON'] },
  { id: 'insight_connect', name: 'InsightConnect', vendor: 'Rapid7', accept: '.json,.icon', hint: 'Upload workflow .json or .icon export', formats: ['JSON', 'ICON'] },
  { id: 'shuffle', name: 'Shuffle', vendor: 'Open Source', accept: '.json', hint: 'Upload workflow .json export', formats: ['JSON'] },
  { id: 'torq', name: 'Torq', vendor: 'Torq', accept: '.json,.yml,.yaml', hint: 'Upload workflow export', formats: ['JSON', 'YAML'] },
  { id: 'servicenow_secops', name: 'ServiceNow SecOps', vendor: 'ServiceNow', accept: '.json', hint: 'Upload Flow Designer .json export', formats: ['JSON'] },
  { id: 'exabeam', name: 'Exabeam', vendor: 'Exabeam', accept: '.json', hint: 'Upload playbook .json export', formats: ['JSON'] },
  { id: 'blinkops', name: 'BlinkOps', vendor: 'Blink', accept: '.json,.yml,.yaml', hint: 'Upload automation export', formats: ['JSON', 'YAML'] },
  { id: 'd3_security', name: 'D3 Security', vendor: 'D3 Security', accept: '.json', hint: 'Upload Smart SOAR .json export', formats: ['JSON'] },
  { id: 'thehive', name: 'TheHive / Cortex', vendor: 'StrangeBee', accept: '.json', hint: 'Upload case template or analyzer .json', formats: ['JSON'] },
  { id: 'logichub', name: 'LogicHub', vendor: 'LogicHub', accept: '.json', hint: 'Upload playbook .json export', formats: ['JSON'] },
  { id: 'resolve', name: 'Resolve', vendor: 'Resolve Systems', accept: '.json', hint: 'Upload runbook .json export', formats: ['JSON'] },
];

function ImportTab({ navigate, onDone }) {
  const [platform, setPlatform] = useState(null);
  const [files, setFiles] = useState([]);          // Array of File objects
  const [importing, setImporting] = useState(false);
  const [results, setResults] = useState([]);       // { name, id, steps, total, status, error }
  const [currentIdx, setCurrentIdx] = useState(-1); // Index currently being imported

  const currentPlatform = IMPORT_PLATFORMS.find(p => p.id === platform);

  const resetState = () => {
    setFiles([]);
    setResults([]);
    setCurrentIdx(-1);
  };

  const handleFiles = (e) => {
    const picked = Array.from(e.target.files || []);
    if (picked.length) { setFiles(prev => [...prev, ...picked]); setResults([]); setCurrentIdx(-1); }
  };

  const handleDrop = (e) => {
    e.preventDefault();
    const picked = Array.from(e.dataTransfer.files || []);
    if (picked.length) { setFiles(prev => [...prev, ...picked]); setResults([]); setCurrentIdx(-1); }
  };

  const removeFile = (idx) => {
    setFiles(prev => prev.filter((_, i) => i !== idx));
    setResults([]);
    setCurrentIdx(-1);
  };

  const convertSingleFile = async (file) => {
    let content;
    const isArchive = /\.(tgz|tar\.gz|gz)$/i.test(file.name);

    if (isArchive) {
      const arrayBuffer = await file.arrayBuffer();
      const bytes = new Uint8Array(arrayBuffer);
      let binary = '';
      for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
      content = btoa(binary);
    } else {
      content = await file.text();
    }

    const res = await authFetch(`${API_BASE}/api/v1/playbooks/import/preview`, {
      method: 'POST',
      body: JSON.stringify({ content, source_platform: platform }),
    });

    if (!res.ok) {
      const errData = await res.json().catch(() => null);
      throw new Error(errData?.detail || errData?.message || `Conversion failed (${res.status})`);
    }

    const data = await res.json();
    const playbook = data.playbook || data;

    const saveRes = await authFetch(`${API_BASE}/api/v1/playbooks`, {
      method: 'POST',
      body: JSON.stringify({
        name: playbook.name || `Imported from ${file.name}`,
        description: playbook.description || `Imported from ${currentPlatform?.name || platform}`,
        trigger_conditions: {},
        canvas_data: playbook.canvas_data || { nodes: [], edges: [] },
        tags: ['imported', platform],
        alert_types: [],
        severity_filter: [],
        data_sources: [],
        priority: 50,
      }),
    });

    if (!saveRes.ok) throw new Error('Failed to save playbook');
    const saved = await saveRes.json();
    return {
      name: playbook.name || file.name,
      id: saved.id || saved.playbook_id,
      steps: data.report?.converted_steps || playbook.canvas_data?.nodes?.length || 0,
      total: data.report?.total_steps || 0,
      status: 'success',
    };
  };

  const handleConvertAll = async () => {
    if (!files.length || !platform) return;
    setImporting(true);
    setResults([]);

    const allResults = [];
    for (let i = 0; i < files.length; i++) {
      setCurrentIdx(i);
      try {
        const r = await convertSingleFile(files[i]);
        allResults.push(r);
      } catch (err) {
        allResults.push({ name: files[i].name, status: 'error', error: err.message });
      }
      setResults([...allResults]);
    }

    setCurrentIdx(-1);
    setImporting(false);
  };

  const successCount = results.filter(r => r.status === 'success').length;
  const errorCount = results.filter(r => r.status === 'error').length;
  const isDone = results.length === files.length && files.length > 0;

  return (
    <div className="import-tab">
      <div className="import-header">
        <FolderInput size={22} className="import-header-icon" />
        <div>
          <h2>Import Playbooks</h2>
          <p>Convert and import playbooks from external SOAR platforms into T1 Agentics</p>
        </div>
      </div>

      {/* Platform grid */}
      <div className="import-platform-grid">
        {IMPORT_PLATFORMS.map(p => (
          <button
            key={p.id}
            className={`import-platform-card ${platform === p.id ? 'active' : ''}`}
            onClick={() => { setPlatform(p.id); resetState(); }}
          >
            <div className="import-platform-name">{p.name}</div>
            <div className="import-platform-vendor">{p.vendor}</div>
            <div className="import-platform-formats">
              {p.formats.map(f => <span key={f} className="import-format-tag">{f}</span>)}
            </div>
          </button>
        ))}
      </div>

      {/* Upload area - visible when platform is selected */}
      {platform && (
        <div className="import-upload-section">
          <div className="import-upload-header">
            <span className="import-selected-platform">{currentPlatform?.name}</span>
            <button className="import-change-btn" onClick={() => { setPlatform(null); resetState(); }}>Change</button>
          </div>

          <div
            className={`import-dropzone ${files.length ? 'has-file' : ''}`}
            onDragOver={(e) => e.preventDefault()}
            onDrop={handleDrop}
            onClick={() => document.getElementById('import-file-input')?.click()}
          >
            <FileUp size={28} className="import-dropzone-icon" />
            <div className="import-dropzone-text">
              {files.length
                ? `${files.length} file${files.length > 1 ? 's' : ''} selected — click or drop to add more`
                : currentPlatform?.hint || 'Drop files here or click to browse'}
            </div>
            <input
              id="import-file-input"
              type="file"
              accept={currentPlatform?.accept}
              onChange={handleFiles}
              multiple
              style={{ position: 'absolute', inset: 0, opacity: 0, cursor: 'pointer' }}
            />
          </div>

          {/* File list */}
          {files.length > 0 && (
            <div className="import-file-list">
              {files.map((f, i) => {
                const r = results[i];
                return (
                  <div key={`${f.name}-${i}`} className={`import-file-row ${r?.status || ''} ${currentIdx === i ? 'importing' : ''}`}>
                    <div className="import-file-info">
                      <span className="import-file-name">{f.name}</span>
                      <span className="import-file-size">{(f.size / 1024).toFixed(1)} KB</span>
                    </div>
                    <div className="import-file-status">
                      {currentIdx === i && <RefreshCw className="spin" size={14} />}
                      {r?.status === 'success' && (
                        <>
                          <CheckCircle size={14} className="import-status-success" />
                          <span className="import-steps-count">{r.steps} steps</span>
                          <button className="import-open-btn-sm" onClick={() => navigate(`/playbooks/${r.id}`)}>
                            Open <ExternalLink size={12} />
                          </button>
                        </>
                      )}
                      {r?.status === 'error' && (
                        <>
                          <XCircle size={14} className="import-status-error" />
                          <span className="import-error-text" title={r.error}>{r.error}</span>
                        </>
                      )}
                      {!r && currentIdx !== i && !importing && (
                        <button className="import-remove-btn" onClick={(e) => { e.stopPropagation(); removeFile(i); }} title="Remove">
                          <XCircle size={14} />
                        </button>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          )}

          {/* Summary after batch completes */}
          {isDone && (
            <div className={`import-message ${errorCount ? 'import-warning' : 'import-success'}`}>
              <CheckCircle size={15} />
              <div>
                <strong>{successCount}</strong> of {files.length} playbook{files.length > 1 ? 's' : ''} imported successfully
                {errorCount > 0 && <span> — {errorCount} failed</span>}
              </div>
              <button className="import-reset-btn" onClick={resetState}>Import More</button>
            </div>
          )}

          {files.length > 0 && !isDone && (
            <button
              className="import-convert-btn"
              onClick={handleConvertAll}
              disabled={importing}
            >
              {importing
                ? <><RefreshCw className="spin" size={15} /> Converting {currentIdx + 1} of {files.length}...</>
                : <><Upload size={15} /> Convert & Import {files.length > 1 ? `All ${files.length}` : ''}</>
              }
            </button>
          )}
        </div>
      )}
    </div>
  );
}

// ============================================================================
// Intelligence Tab
// ============================================================================

function IntelligenceTab() {
  const [stats, setStats] = useState(null);
  const [isLoading, setIsLoading] = useState(true);
  const [timeRange, setTimeRange] = useState('7d');

  useEffect(() => {
    fetchStats();
  }, [timeRange]);

  const fetchStats = async () => {
    setIsLoading(true);
    try {
      const response = await authFetch(
        `${API_BASE}/api/v1/riggs/playbooks/analytics?time_range=${timeRange}`
      );
      if (response.ok) {
        const data = await response.json();
        setStats(data);
      } else {
        setStats(emptyStats());
      }
    } catch (err) {
      setStats(emptyStats());
    } finally {
      setIsLoading(false);
    }
  };

  if (isLoading) {
    return (
      <div className="intel-layout">
        <div className="intel-loading">
          <RefreshCw className="spin" size={24} />
          <span>Loading intelligence data...</span>
        </div>
      </div>
    );
  }

  return (
    <div className="intel-layout">
      <div className="intel-toolbar">
        <h2>Intelligence Dashboard</h2>
        <div className="time-pills">
          {['24h', '7d', '30d', '90d'].map((range) => (
            <button
              key={range}
              className={`time-pill ${timeRange === range ? 'active' : ''}`}
              onClick={() => setTimeRange(range)}
            >
              {range}
            </button>
          ))}
        </div>
      </div>

      <div className="kpi-row">
        <KpiCard icon={Brain} label="Total Analyses" value={stats?.total_analyses?.toLocaleString() || '0'} accent="blue" />
        <KpiCard icon={Target} label="Accuracy Rate" value={`${Math.round((stats?.accuracy_rate || 0) * 100)}%`} accent="emerald" />
        <KpiCard icon={Zap} label="Avg Response" value={`${stats?.avg_response_time_ms || 0}ms`} accent="amber" />
        <KpiCard icon={CheckCircle} label="Auto-Resolved" value={stats?.auto_resolved?.toLocaleString() || '0'} accent="emerald" />
      </div>

      <div className="intel-panels">
        <div className="intel-card">
          <h3>Verdict Distribution</h3>
          <div className="verdict-bars">
            {stats?.verdicts && Object.entries(stats.verdicts).map(([verdict, count]) => {
              const total = Object.values(stats.verdicts).reduce((a, b) => a + b, 0);
              const pct = total > 0 ? (count / total) * 100 : 0;
              return (
                <div key={verdict} className="vbar-row">
                  <span className="vbar-label">{verdict}</span>
                  <div className="vbar-track">
                    <div className={`vbar-fill vbar-${verdict}`} style={{ width: `${pct}%` }} />
                  </div>
                  <span className="vbar-count">{count}</span>
                </div>
              );
            })}
          </div>
        </div>

        <div className="intel-card">
          <h3>Top Performing Playbooks</h3>
          <div className="top-pb-list">
            {stats?.top_playbooks?.length > 0 ? stats.top_playbooks.map((pb, i) => (
              <div key={i} className="top-pb-item">
                <span className="top-pb-rank">#{i + 1}</span>
                <div className="top-pb-info">
                  <span className="top-pb-name">{pb.name}</span>
                  <span className="top-pb-execs">{pb.executions} executions</span>
                </div>
                <div className="top-pb-rate">
                  <span className={pb.success_rate >= 0.9 ? 'rate-high' : 'rate-mid'}>
                    {Math.round(pb.success_rate * 100)}%
                  </span>
                </div>
              </div>
            )) : (
              <div className="top-pb-empty">No playbook data yet</div>
            )}
          </div>
        </div>
      </div>

      <div className="intel-card">
        <h3>Recent Activity</h3>
        <div className="activity-list">
          {(!stats?.recent_activity || stats.recent_activity.length === 0) ? (
            <div className="activity-empty">No recent activity</div>
          ) : (
            stats.recent_activity.map((item, i) => (
              <div className="activity-item" key={i}>
                <div className={`activity-dot ${item.type || 'info'}`}>
                  {item.type === 'success' ? <CheckCircle size={12} /> :
                   item.type === 'warning' ? <AlertTriangle size={12} /> :
                   <Play size={12} />}
                </div>
                <span className="activity-title">{item.title}</span>
                <span className="activity-time">{item.time}</span>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}

function emptyStats() {
  return {
    total_analyses: 0,
    accuracy_rate: 0,
    avg_response_time_ms: 0,
    verdicts: { malicious: 0, suspicious: 0, benign: 0, unknown: 0 },
    playbook_executions: 0,
    auto_resolved: 0,
    escalated: 0,
    top_playbooks: [],
  };
}

function KpiCard({ icon: Icon, label, value, accent }) {
  return (
    <div className={`kpi-card kpi-${accent}`}>
      <div className="kpi-icon">
        <Icon size={20} />
      </div>
      <div className="kpi-data">
        <span className="kpi-value">{value}</span>
        <span className="kpi-label">{label}</span>
      </div>
    </div>
  );
}
