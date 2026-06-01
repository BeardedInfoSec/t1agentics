/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

/**
 * PlaybookMarketplace - Browse and install playbook templates.
 * Displays a searchable, filterable grid of available playbook templates.
 * Click any card to view full details, check integration deps, and install.
 */

import React, { useState, useEffect, useCallback, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { authFetch, API_BASE_URL } from '../utils/api';

// ────────────────────────────────────────────────────────────
// SVG Icons
// ────────────────────────────────────────────────────────────

const SearchIcon = ({ size = 16 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <circle cx="11" cy="11" r="8" /><path d="M21 21l-4.35-4.35" />
  </svg>
);

const XIcon = ({ size = 14 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M18 6L6 18" /><path d="M6 6l12 12" />
  </svg>
);

const ArrowLeftIcon = ({ size = 16 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M19 12H5" /><path d="M12 19l-7-7 7-7" />
  </svg>
);

const CheckCircleIcon = ({ size = 16 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" /><polyline points="22 4 12 14.01 9 11.01" />
  </svg>
);

const AlertCircleIcon = ({ size = 16 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <circle cx="12" cy="12" r="10" /><line x1="12" y1="8" x2="12" y2="12" /><line x1="12" y1="16" x2="12.01" y2="16" />
  </svg>
);

const DownloadIcon = ({ size = 16 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" /><polyline points="7 10 12 15 17 10" /><line x1="12" y1="15" x2="12" y2="3" />
  </svg>
);

const ClockIcon = ({ size = 14 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <circle cx="12" cy="12" r="10" /><polyline points="12 6 12 12 16 14" />
  </svg>
);

const PlugIcon = ({ size = 14 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M12 22v-5" /><path d="M9 8V2" /><path d="M15 8V2" /><path d="M18 8v5a6 6 0 0 1-12 0V8h12z" />
  </svg>
);

const ChevronLeftIcon = ({ size = 16 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M15 18l-6-6 6-6" />
  </svg>
);

const ChevronRightIcon = ({ size = 16 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M9 18l6-6-6-6" />
  </svg>
);


// ────────────────────────────────────────────────────────────
// Constants
// ────────────────────────────────────────────────────────────

const CATEGORIES = [
  { label: 'All',               value: null },
  { label: 'Phishing & Email',  value: 'phishing_email' },
  { label: 'Malware & Ransomware', value: 'malware_ransomware' },
  { label: 'Threat Intel',      value: 'threat_intelligence' },
  { label: 'Vulnerability Mgmt', value: 'vulnerability_management' },
  { label: 'Identity & Access', value: 'identity_access' },
  { label: 'Network Security',  value: 'network_security' },
  { label: 'Cloud Security',    value: 'cloud_security' },
  { label: 'IT Operations',     value: 'it_operations' },
  { label: 'Compliance & Audit', value: 'compliance_audit' },
  { label: 'Ticketing & Notifications', value: 'ticketing_notifications' },
];

const DIFFICULTY_OPTIONS = [
  { label: 'All Levels', value: null },
  { label: 'Beginner',   value: 'beginner' },
  { label: 'Intermediate', value: 'intermediate' },
  { label: 'Advanced',   value: 'advanced' },
];

const DIFFICULTY_COLORS = {
  beginner:     { bg: '#10b981', text: '#fff' },
  intermediate: { bg: '#f59e0b', text: '#000' },
  advanced:     { bg: '#ef4444', text: '#fff' },
};

// SVG category icons (no emoji)
const CategoryIcon = ({ category, size = 20 }) => {
  const props = { width: size, height: size, viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', strokeWidth: '2', strokeLinecap: 'round', strokeLinejoin: 'round' };
  switch (category) {
    case 'phishing_email':
      return <svg {...props}><rect x="2" y="4" width="20" height="16" rx="2" /><path d="M22 7l-10 7L2 7" /></svg>;
    case 'malware_ransomware':
      return <svg {...props}><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /></svg>;
    case 'threat_intelligence':
      return <svg {...props}><circle cx="11" cy="11" r="8" /><path d="M21 21l-4.35-4.35" /></svg>;
    case 'vulnerability_management':
      return <svg {...props}><rect x="3" y="11" width="18" height="11" rx="2" ry="2" /><path d="M7 11V7a5 5 0 0 1 10 0v4" /></svg>;
    case 'identity_access':
      return <svg {...props}><path d="M19 21v-2a4 4 0 0 0-4-4H9a4 4 0 0 0-4 4v2" /><circle cx="12" cy="7" r="4" /></svg>;
    case 'network_security':
      return <svg {...props}><circle cx="12" cy="12" r="10" /><path d="M2 12h20" /><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" /></svg>;
    case 'cloud_security':
      return <svg {...props}><path d="M18 10h-1.26A8 8 0 1 0 9 20h9a5 5 0 0 0 0-10z" /></svg>;
    case 'it_operations':
      return <svg {...props}><circle cx="12" cy="12" r="3" /><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z" /></svg>;
    case 'compliance_audit':
      return <svg {...props}><path d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2" /><rect x="8" y="2" width="8" height="4" rx="1" ry="1" /></svg>;
    case 'ticketing_notifications':
      return <svg {...props}><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z" /><polyline points="22,6 12,13 2,6" /></svg>;
    default:
      return <svg {...props}><path d="M2 3h6a4 4 0 0 1 4 4v14a3 3 0 0 0-3-3H2z" /><path d="M22 3h-6a4 4 0 0 0-4 4v14a3 3 0 0 1 3-3h7z" /></svg>;
  }
};

const PER_PAGE = 24;


// ────────────────────────────────────────────────────────────
// Workflow Preview (pure SVG, no ReactFlow)
// ────────────────────────────────────────────────────────────

const NODE_COLORS = {
  trigger: '#10b981',
  enrich: '#3b82f6',
  enrichment: '#3b82f6',
  riggs_analyze: '#8b5cf6',
  analyze: '#8b5cf6',
  condition: '#f59e0b',
  decision: '#f59e0b',
  action: '#f97316',
  integration: '#f97316',
  notification: '#ec4899',
  notify: '#ec4899',
  code: '#a78bfa',
  loop: '#06b6d4',
  end: '#64748b',
};

const NODE_TYPE_LABELS = {
  trigger: 'Trigger',
  enrich: 'Enrich',
  enrichment: 'Enrich',
  riggs_analyze: 'AI Analysis',
  analyze: 'AI Analysis',
  condition: 'Condition',
  decision: 'Condition',
  action: 'Action',
  integration: 'Action',
  notification: 'Notify',
  notify: 'Notify',
  code: 'Code',
  loop: 'Loop',
  end: 'End',
};

function WorkflowPreview({ canvasData }) {
  const nodes = canvasData?.nodes || [];
  const edges = canvasData?.edges || [];

  if (nodes.length === 0) {
    return (
      <div className="pb-mkt-preview-empty">
        <span>No workflow preview available</span>
      </div>
    );
  }

  // Sort nodes by Y position to get execution order
  const sorted = [...nodes].sort((a, b) => {
    const ay = a.position?.y ?? 0, by = b.position?.y ?? 0;
    if (ay !== by) return ay - by;
    return (a.position?.x ?? 0) - (b.position?.x ?? 0);
  });

  // Build adjacency from edges for branching labels
  const edgeLabelMap = {};
  edges.forEach(e => {
    if (e.label) {
      if (!edgeLabelMap[e.source]) edgeLabelMap[e.source] = [];
      edgeLabelMap[e.source].push({ target: e.target, label: e.label });
    }
  });

  return (
    <div className="pb-mkt-preview-container">
      <div className="pb-mkt-step-list">
        {sorted.map((node, idx) => {
          const kind = node.data?.kind || (node.type !== 'signal' ? node.type : '') || 'action';
          const color = NODE_COLORS[kind] || '#64748b';
          const typeLabel = NODE_TYPE_LABELS[kind] || kind;
          const title = node.data?.title || node.data?.label || '';
          const summary = node.data?.summary || '';
          const branches = edgeLabelMap[node.id];
          const isLast = idx === sorted.length - 1;

          return (
            <div key={node.id} className="pb-mkt-step-row">
              {/* Timeline connector */}
              <div className="pb-mkt-step-timeline">
                <div className="pb-mkt-step-dot" style={{ backgroundColor: color, boxShadow: `0 0 8px ${color}40` }} />
                {!isLast && <div className="pb-mkt-step-line" />}
              </div>
              {/* Step content */}
              <div className="pb-mkt-step-content">
                <div className="pb-mkt-step-header">
                  <span className="pb-mkt-step-badge" style={{ backgroundColor: `${color}18`, color, borderColor: `${color}30` }}>
                    {typeLabel}
                  </span>
                  <span className="pb-mkt-step-num">#{idx + 1}</span>
                </div>
                <div className="pb-mkt-step-title">{title}</div>
                {summary && <div className="pb-mkt-step-summary">{summary}</div>}
                {branches && branches.length > 0 && (
                  <div className="pb-mkt-step-branches">
                    {branches.map((b, i) => (
                      <span key={i} className="pb-mkt-step-branch">{b.label}</span>
                    ))}
                  </div>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}


// ────────────────────────────────────────────────────────────
// Template Detail Drawer
// ────────────────────────────────────────────────────────────

function TemplateDetail({ template, onClose, onInstall }) {
  const [depCheck, setDepCheck] = useState(null);
  const [depLoading, setDepLoading] = useState(false);
  const [installing, setInstalling] = useState(false);
  const [installResult, setInstallResult] = useState(null);
  const [fullTemplate, setFullTemplate] = useState(null);
  const [fullLoading, setFullLoading] = useState(true);
  const [showMapping, setShowMapping] = useState(false);
  const [integrationMappings, setIntegrationMappings] = useState({});
  const navigate = useNavigate();

  // Fetch full template detail (includes canvas_data)
  useEffect(() => {
    setFullLoading(true);
    setFullTemplate(null);
    authFetch(`${API_BASE_URL}/api/v1/playbooks/marketplace/${template.id}`)
      .then(res => res.ok ? res.json() : null)
      .then(data => { if (data) setFullTemplate(data); })
      .catch(e => console.error('Marketplace template error:', e))
      .finally(() => setFullLoading(false));
  }, [template.id]);

  // Defensive parsing — JSONB fields may arrive as strings
  const requiredIntegrations = (() => {
    const raw = template.required_integrations;
    if (Array.isArray(raw)) return raw;
    if (typeof raw === 'string') { try { return JSON.parse(raw); } catch { return []; } }
    return [];
  })();
  const tags = Array.isArray(template.tags) ? template.tags : [];
  const canvasData = (() => {
    const raw = (fullTemplate || template).canvas_data;
    if (raw && typeof raw === 'object' && !Array.isArray(raw)) return raw;
    if (typeof raw === 'string') { try { return JSON.parse(raw); } catch { return null; } }
    return null;
  })();
  const nodeCount = canvasData?.nodes?.length || 0;
  const alertTypes = Array.isArray(template.alert_types) ? template.alert_types : [];
  const severityFilter = Array.isArray(template.severity_filter) ? template.severity_filter : [];

  // Check integration dependencies
  useEffect(() => {
    if (requiredIntegrations.length === 0) return;
    setDepLoading(true);
    authFetch(`${API_BASE_URL}/api/v1/playbooks/marketplace/${template.id}/check-integrations`)
      .then(res => res.ok ? res.json() : null)
      .then(data => { if (data) setDepCheck(data); })
      .catch(e => console.error('Integration check error:', e))
      .finally(() => setDepLoading(false));
  }, [template.id, requiredIntegrations.length]);

  // Initialize mapping selections when depCheck arrives
  useEffect(() => {
    if (!depCheck?.mapping_proposal) return;
    setIntegrationMappings(depCheck.mapping_proposal);
  }, [depCheck]);

  const hasMappableGaps = depCheck?.missing?.some(d => d.alternatives?.length > 0);

  const doInstall = async (mapOverride) => {
    setInstalling(true);
    try {
      const finalMap = mapOverride || integrationMappings;
      const res = await authFetch(`${API_BASE_URL}/api/v1/playbooks/marketplace/${template.id}/install`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          integration_map: Object.keys(finalMap).length > 0 ? finalMap : null,
        }),
      });
      if (res.ok) {
        const data = await res.json();
        setInstallResult(data);
        setShowMapping(false);
        if (onInstall) onInstall(data);
      } else {
        const err = await res.json().catch(() => ({}));
        setInstallResult({ error: err.detail || 'Install failed' });
      }
    } catch {
      setInstallResult({ error: 'Network error' });
    } finally {
      setInstalling(false);
    }
  };

  const handleInstall = () => {
    // If there are missing deps with alternatives, show the mapping panel
    if (hasMappableGaps && !showMapping) {
      setShowMapping(true);
      return;
    }
    doInstall();
  };

  return (
    <div className="pb-mkt-detail-overlay" onClick={onClose}>
      <div className="pb-mkt-detail-drawer" onClick={e => e.stopPropagation()}>
        {/* Header */}
        <div className="pb-mkt-detail-header">
          <button className="pb-mkt-detail-back" onClick={onClose}>
            <ArrowLeftIcon size={16} />
            <span>Back to Marketplace</span>
          </button>
          {!installResult?.playbook_id && (
            <button
              className="pb-mkt-btn pb-mkt-btn-primary"
              onClick={handleInstall}
              disabled={installing}
            >
              <DownloadIcon size={14} />
              {installing ? 'Installing...' : 'Install Playbook'}
            </button>
          )}
          {installResult?.playbook_id && (
            <button
              className="pb-mkt-btn pb-mkt-btn-success"
              onClick={() => navigate(`/playbooks/${installResult.playbook_id}`)}
            >
              Open in Editor
            </button>
          )}
        </div>

        {/* Install result banner */}
        {installResult && (
          <div className={`pb-mkt-banner ${installResult.error ? 'pb-mkt-banner-error' : 'pb-mkt-banner-success'}`}>
            {installResult.error ? (
              <><AlertCircleIcon size={16} /> {installResult.error}</>
            ) : (
              <><CheckCircleIcon size={16} /> {installResult.message}</>
            )}
          </div>
        )}

        {/* Integration Mapping Panel */}
        {showMapping && !installResult?.playbook_id && (
          <div className="pb-mkt-mapping-panel">
            <div className="pb-mkt-mapping-header">
              <PlugIcon size={16} />
              <div>
                <h4>Integration Mapping</h4>
                <p>This playbook uses integrations you don't have installed. Select substitutes from your available integrations:</p>
              </div>
            </div>

            <div className="pb-mkt-mapping-list">
              {(depCheck?.missing || []).filter(d => d.alternatives?.length > 0).map(dep => (
                <div key={dep.connector_id} className="pb-mkt-mapping-row">
                  <div className="pb-mkt-mapping-source">
                    <span className="pb-mkt-mapping-name">{dep.name}</span>
                    <span className="pb-mkt-mapping-cat">{dep.category}</span>
                  </div>
                  <span className="pb-mkt-mapping-arrow">&rarr;</span>
                  <select
                    className="pb-mkt-mapping-select"
                    value={integrationMappings[dep.connector_id] || ''}
                    onChange={e => setIntegrationMappings(prev => ({
                      ...prev,
                      [dep.connector_id]: e.target.value || undefined,
                    }))}
                  >
                    <option value="">— Skip (no mapping) —</option>
                    {dep.alternatives.map(alt => (
                      <option key={alt.instance_id} value={alt.instance_id}>
                        {alt.name} ({alt.connector_id})
                      </option>
                    ))}
                  </select>
                </div>
              ))}

              {(depCheck?.missing || []).filter(d => !d.alternatives?.length).map(dep => (
                <div key={dep.connector_id} className="pb-mkt-mapping-row pb-mkt-mapping-unavail">
                  <div className="pb-mkt-mapping-source">
                    <span className="pb-mkt-mapping-name">{dep.name}</span>
                    <span className="pb-mkt-mapping-cat">{dep.category}</span>
                  </div>
                  <span className="pb-mkt-mapping-arrow">&rarr;</span>
                  <span className="pb-mkt-mapping-none">No matching integration installed</span>
                </div>
              ))}
            </div>

            <div className="pb-mkt-mapping-actions">
              <button
                className="pb-mkt-btn pb-mkt-btn-primary"
                onClick={() => doInstall()}
                disabled={installing}
              >
                <DownloadIcon size={14} />
                {installing ? 'Installing...' : 'Install with Mappings'}
              </button>
              <button
                className="pb-mkt-btn pb-mkt-btn-ghost"
                onClick={() => doInstall({})}
                disabled={installing}
              >
                Skip &amp; Install Without Mapping
              </button>
              <button
                className="pb-mkt-btn pb-mkt-btn-ghost"
                onClick={() => setShowMapping(false)}
              >
                Cancel
              </button>
            </div>
          </div>
        )}

        {/* Template info */}
        <div className="pb-mkt-detail-info">
          <div className="pb-mkt-detail-title-row">
            <span className="pb-mkt-detail-icon"><CategoryIcon category={template.category} size={28} /></span>
            <div>
              <h2 className="pb-mkt-detail-name">{template.name}</h2>
              <span className="pb-mkt-detail-author">by {template.author || 'T1 Agentics'}</span>
            </div>
            <span
              className="pb-mkt-difficulty-badge"
              style={{
                backgroundColor: (DIFFICULTY_COLORS[template.difficulty] || DIFFICULTY_COLORS.intermediate).bg,
                color: (DIFFICULTY_COLORS[template.difficulty] || DIFFICULTY_COLORS.intermediate).text,
              }}
            >
              {template.difficulty || 'intermediate'}
            </span>
          </div>

          <p className="pb-mkt-detail-desc">{template.description || 'No description available.'}</p>

          <div className="pb-mkt-detail-meta">
            <div className="pb-mkt-detail-meta-item">
              <span className="pb-mkt-meta-label">Category</span>
              <span className="pb-mkt-meta-value">{(template.category || 'general').replace(/_/g, ' ')}</span>
            </div>
            {template.subcategory && (
              <div className="pb-mkt-detail-meta-item">
                <span className="pb-mkt-meta-label">Subcategory</span>
                <span className="pb-mkt-meta-value">{template.subcategory.replace(/_/g, ' ')}</span>
              </div>
            )}
            <div className="pb-mkt-detail-meta-item">
              <span className="pb-mkt-meta-label">Nodes</span>
              <span className="pb-mkt-meta-value">{nodeCount}</span>
            </div>
            {template.estimated_time && (
              <div className="pb-mkt-detail-meta-item">
                <span className="pb-mkt-meta-label">Est. Time</span>
                <span className="pb-mkt-meta-value">{template.estimated_time}</span>
              </div>
            )}
            <div className="pb-mkt-detail-meta-item">
              <span className="pb-mkt-meta-label">Version</span>
              <span className="pb-mkt-meta-value">{template.version || '1.0.0'}</span>
            </div>
            <div className="pb-mkt-detail-meta-item">
              <span className="pb-mkt-meta-label">Installs</span>
              <span className="pb-mkt-meta-value">{template.install_count || 0}</span>
            </div>
          </div>

          {/* Tags */}
          {tags.length > 0 && (
            <div className="pb-mkt-detail-tags">
              {tags.map(tag => (
                <span key={tag} className="pb-mkt-tag">{tag}</span>
              ))}
            </div>
          )}
        </div>

        {/* Workflow Preview */}
        <div className="pb-mkt-detail-preview">
          <h3 className="pb-mkt-section-title">Workflow Preview</h3>
          {fullLoading ? (
            <div className="pb-mkt-preview-loading">
              <div className="pb-mkt-spinner" style={{ width: 20, height: 20 }} />
              <span>Loading preview...</span>
            </div>
          ) : (
            <WorkflowPreview canvasData={canvasData} />
          )}
        </div>

        {/* Trigger Configuration */}
        {(alertTypes.length > 0 || severityFilter.length > 0) && (
          <div className="pb-mkt-detail-trigger">
            <h3 className="pb-mkt-section-title">Trigger Configuration</h3>
            <div className="pb-mkt-trigger-rows">
              {alertTypes.length > 0 && (
                <div className="pb-mkt-trigger-row">
                  <span className="pb-mkt-meta-label">Alert Types</span>
                  <div className="pb-mkt-trigger-tags">
                    {alertTypes.map(at => (
                      <span key={at} className="pb-mkt-trigger-tag">{at.replace(/_/g, ' ')}</span>
                    ))}
                  </div>
                </div>
              )}
              {severityFilter.length > 0 && (
                <div className="pb-mkt-trigger-row">
                  <span className="pb-mkt-meta-label">Severity</span>
                  <div className="pb-mkt-trigger-tags">
                    {severityFilter.map(sev => (
                      <span key={sev} className={`pb-mkt-severity-tag pb-mkt-sev-${sev}`}>{sev}</span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Integration Dependencies */}
        {requiredIntegrations.length > 0 && (
          <div className="pb-mkt-detail-deps">
            <h3 className="pb-mkt-section-title">
              <PlugIcon size={16} />
              Required Integrations
              <span className="pb-mkt-dep-count">{requiredIntegrations.length}</span>
            </h3>

            {depLoading ? (
              <div className="pb-mkt-dep-loading">Checking your integrations...</div>
            ) : depCheck ? (
              <>
                {depCheck.all_satisfied ? (
                  <div className="pb-mkt-dep-status pb-mkt-dep-ok">
                    <CheckCircleIcon size={16} /> All required integrations are configured
                  </div>
                ) : (
                  <div className="pb-mkt-dep-status pb-mkt-dep-warn">
                    <AlertCircleIcon size={16} /> {depCheck.missing?.length} integration{depCheck.missing?.length !== 1 ? 's' : ''} not configured
                  </div>
                )}

                <div className="pb-mkt-dep-list">
                  {(depCheck.satisfied || []).map(dep => (
                    <div key={dep.connector_id} className="pb-mkt-dep-item pb-mkt-dep-satisfied">
                      <CheckCircleIcon size={14} />
                      <span className="pb-mkt-dep-name">{dep.name}</span>
                      <span className="pb-mkt-dep-reason">{dep.reason}</span>
                      <span className="pb-mkt-dep-health" data-status={dep.health_status}>
                        {dep.health_status}
                      </span>
                    </div>
                  ))}
                  {(depCheck.missing || []).map(dep => (
                    <div key={dep.connector_id} className="pb-mkt-dep-item pb-mkt-dep-missing">
                      <AlertCircleIcon size={14} />
                      <span className="pb-mkt-dep-name">{dep.name}</span>
                      <span className="pb-mkt-dep-reason">{dep.reason}</span>
                      <button
                        className="pb-mkt-dep-configure"
                        onClick={() => navigate(dep.marketplace_url || '/connect?tab=marketplace')}
                      >
                        Configure
                      </button>
                    </div>
                  ))}
                </div>
              </>
            ) : (
              <div className="pb-mkt-dep-list">
                {requiredIntegrations.map((req, i) => (
                  <div key={req.connector_id || i} className="pb-mkt-dep-item">
                    <PlugIcon size={14} />
                    <span className="pb-mkt-dep-name">{req.name || req.connector_id}</span>
                    <span className="pb-mkt-dep-reason">{req.reason}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}


// ────────────────────────────────────────────────────────────
// Main Marketplace Component
// ────────────────────────────────────────────────────────────

export default function PlaybookMarketplace() {
  const [templates, setTemplates] = useState([]);
  const [search, setSearch] = useState('');
  const [debouncedSearch, setDebouncedSearch] = useState('');
  const [category, setCategory] = useState(null);
  const [difficulty, setDifficulty] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [totalCount, setTotalCount] = useState(0);
  const [selectedTemplate, setSelectedTemplate] = useState(null);
  const [stats, setStats] = useState(null);
  const searchRef = useRef(null);
  const mountedRef = useRef(true);
  const debounceRef = useRef(null);

  useEffect(() => {
    mountedRef.current = true;
    return () => { mountedRef.current = false; };
  }, []);

  // Debounce search input
  useEffect(() => {
    if (debounceRef.current) clearTimeout(debounceRef.current);
    debounceRef.current = setTimeout(() => {
      setDebouncedSearch(search);
      setPage(1);
    }, 300);
    return () => {
      if (debounceRef.current) clearTimeout(debounceRef.current);
    };
  }, [search]);

  // Reset page on filter changes
  useEffect(() => { setPage(1); }, [category, difficulty]);

  // Close detail drawer on Escape
  useEffect(() => {
    const handleEsc = (e) => {
      if (e.key === 'Escape' && selectedTemplate) setSelectedTemplate(null);
    };
    document.addEventListener('keydown', handleEsc);
    return () => document.removeEventListener('keydown', handleEsc);
  }, [selectedTemplate]);

  // Fetch stats on mount
  useEffect(() => {
    authFetch(`${API_BASE_URL}/api/v1/playbooks/marketplace/stats`)
      .then(res => res.ok ? res.json() : null)
      .then(data => { if (data && mountedRef.current) setStats(data); })
      .catch(e => console.error('Marketplace stats error:', e));
  }, []);

  // Fetch templates
  const fetchTemplates = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const params = new URLSearchParams();
      if (debouncedSearch) params.set('search', debouncedSearch);
      if (category) params.set('category', category);
      if (difficulty) params.set('difficulty', difficulty);
      params.set('page', page.toString());
      params.set('per_page', PER_PAGE.toString());

      const res = await authFetch(`${API_BASE_URL}/api/v1/playbooks/marketplace/browse?${params.toString()}`);
      if (!mountedRef.current) return;

      if (res.ok) {
        const data = await res.json();
        setTemplates(data.templates || []);
        setTotalPages(data.total_pages || 1);
        setTotalCount(data.total || 0);
      } else {
        const errData = await res.json().catch(() => ({}));
        setError(errData.detail || 'Failed to load marketplace');
      }
    } catch (err) {
      if (mountedRef.current) {
        setError(err.message || 'Network error');
      }
    } finally {
      if (mountedRef.current) setLoading(false);
    }
  }, [debouncedSearch, category, difficulty, page]);

  useEffect(() => { fetchTemplates(); }, [fetchTemplates]);

  // Handle successful install
  const handleInstall = () => {
    fetchTemplates(); // Refresh to update install counts
  };

  // ────────────────────────────────────────────────────────
  // Render
  // ────────────────────────────────────────────────────────

  return (
    <div className="pb-mkt-container">
      {/* Header */}
      <div className="pb-mkt-header">
        <div className="pb-mkt-header-left">
          <h1 className="pb-mkt-title">Playbook Marketplace</h1>
          {stats && (
            <span className="pb-mkt-count-badge">
              {stats.total_templates} templates
            </span>
          )}
        </div>

        {/* Search bar */}
        <div className="pb-mkt-search-container">
          <SearchIcon size={16} />
          <input
            ref={searchRef}
            className="pb-mkt-search-input"
            type="text"
            placeholder="Search playbooks..."
            value={search}
            onChange={e => setSearch(e.target.value)}
          />
          {search && (
            <button className="pb-mkt-search-clear" onClick={() => setSearch('')}>
              <XIcon size={12} />
            </button>
          )}
        </div>
      </div>

      {/* Filters */}
      <div className="pb-mkt-filters">
        {/* Category pills */}
        <div className="pb-mkt-category-pills">
          {CATEGORIES.map(cat => (
            <button
              key={cat.value || 'all'}
              className={`pb-mkt-pill ${category === cat.value ? 'pb-mkt-pill-active' : ''}`}
              onClick={() => setCategory(cat.value)}
            >
              {cat.label}
            </button>
          ))}
        </div>

        {/* Difficulty filter */}
        <div className="pb-mkt-difficulty-filter">
          {DIFFICULTY_OPTIONS.map(opt => (
            <button
              key={opt.value || 'all'}
              className={`pb-mkt-diff-btn ${difficulty === opt.value ? 'pb-mkt-diff-btn-active' : ''}`}
              onClick={() => setDifficulty(opt.value)}
            >
              {opt.value && (
                <span
                  className="pb-mkt-diff-dot"
                  style={{ backgroundColor: (DIFFICULTY_COLORS[opt.value] || {}).bg }}
                />
              )}
              {opt.label}
            </button>
          ))}
        </div>
      </div>

      {/* Results info */}
      {!loading && !error && (
        <div className="pb-mkt-results-info">
          Showing {templates.length} of {totalCount} playbook{totalCount !== 1 ? 's' : ''}
          {(category || difficulty || debouncedSearch) && (
            <button className="pb-mkt-clear-filters" onClick={() => { setCategory(null); setDifficulty(null); setSearch(''); }}>
              Clear filters
            </button>
          )}
        </div>
      )}

      {/* Error state */}
      {error && (
        <div className="pb-mkt-error">
          <AlertCircleIcon size={20} />
          <span>{error}</span>
          <button onClick={fetchTemplates}>Retry</button>
        </div>
      )}

      {/* Loading state */}
      {loading && (
        <div className="pb-mkt-loading">
          <div className="pb-mkt-spinner" />
          <span>Loading playbook templates...</span>
        </div>
      )}

      {/* Empty state */}
      {!loading && !error && templates.length === 0 && (
        <div className="pb-mkt-empty">
          <span className="pb-mkt-empty-icon"><CategoryIcon category="default" size={48} /></span>
          <h3>No playbooks found</h3>
          <p>Try adjusting your filters or search terms.</p>
        </div>
      )}

      {/* Template Grid */}
      {!loading && !error && templates.length > 0 && (
        <div className="pb-mkt-grid">
          {templates.map(tmpl => (
            <div
              key={tmpl.id}
              className="pb-mkt-card"
              onClick={() => setSelectedTemplate(tmpl)}
            >
              <div className="pb-mkt-card-header">
                <span className="pb-mkt-card-icon">
                  <CategoryIcon category={tmpl.category} size={22} />
                </span>
                <span
                  className="pb-mkt-difficulty-badge pb-mkt-difficulty-badge-sm"
                  style={{
                    backgroundColor: (DIFFICULTY_COLORS[tmpl.difficulty] || DIFFICULTY_COLORS.intermediate).bg,
                    color: (DIFFICULTY_COLORS[tmpl.difficulty] || DIFFICULTY_COLORS.intermediate).text,
                  }}
                >
                  {tmpl.difficulty || 'intermediate'}
                </span>
              </div>

              <h3 className="pb-mkt-card-title">{tmpl.name}</h3>
              <p className="pb-mkt-card-desc">
                {(tmpl.description || '').length > 120
                  ? tmpl.description.substring(0, 120) + '...'
                  : tmpl.description || 'No description'}
              </p>

              {/* Tags */}
              <div className="pb-mkt-card-tags">
                {(tmpl.tags || []).slice(0, 3).map(tag => (
                  <span key={tag} className="pb-mkt-tag-sm">{tag}</span>
                ))}
                {(tmpl.tags || []).length > 3 && (
                  <span className="pb-mkt-tag-sm pb-mkt-tag-more">+{tmpl.tags.length - 3}</span>
                )}
              </div>

              {/* Footer */}
              <div className="pb-mkt-card-footer">
                <div className="pb-mkt-card-meta">
                  {tmpl.estimated_time && (
                    <span className="pb-mkt-card-time">
                      <ClockIcon size={12} /> {tmpl.estimated_time}
                    </span>
                  )}
                  {(tmpl.required_integrations || []).length > 0 && (
                    <span className="pb-mkt-card-deps">
                      <PlugIcon size={12} /> {tmpl.required_integrations.length}
                    </span>
                  )}
                </div>
                <span className="pb-mkt-card-installs">
                  <DownloadIcon size={12} /> {tmpl.install_count || 0}
                </span>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="pb-mkt-pagination">
          <button
            className="pb-mkt-page-btn"
            disabled={page <= 1}
            onClick={() => setPage(p => Math.max(1, p - 1))}
          >
            <ChevronLeftIcon size={14} /> Previous
          </button>
          <span className="pb-mkt-page-info">
            Page {page} of {totalPages}
          </span>
          <button
            className="pb-mkt-page-btn"
            disabled={page >= totalPages}
            onClick={() => setPage(p => Math.min(totalPages, p + 1))}
          >
            Next <ChevronRightIcon size={14} />
          </button>
        </div>
      )}

      {/* Detail Drawer */}
      {selectedTemplate && (
        <TemplateDetail
          template={selectedTemplate}
          onClose={() => setSelectedTemplate(null)}
          onInstall={handleInstall}
        />
      )}

      {/* ──── Styles ──── */}
      <style>{`
        .pb-mkt-container {
          padding: 24px;
          max-width: 1400px;
          margin: 0 auto;
        }

        /* Header */
        .pb-mkt-header {
          display: flex;
          align-items: center;
          justify-content: space-between;
          margin-bottom: 20px;
          gap: 16px;
          flex-wrap: wrap;
        }
        .pb-mkt-header-left {
          display: flex;
          align-items: center;
          gap: 12px;
        }
        .pb-mkt-title {
          font-size: 24px;
          font-weight: 700;
          color: var(--text-primary, #f0f0f0);
          margin: 0;
        }
        .pb-mkt-count-badge {
          background: var(--accent-primary, #3b82f6);
          color: #fff;
          padding: 4px 10px;
          border-radius: 12px;
          font-size: 12px;
          font-weight: 600;
        }

        /* Search */
        .pb-mkt-search-container {
          display: flex;
          align-items: center;
          gap: 8px;
          background: var(--bg-secondary, #1e293b);
          border: 1px solid var(--border-primary, #334155);
          border-radius: 8px;
          padding: 8px 12px;
          min-width: 280px;
        }
        .pb-mkt-search-container svg { color: var(--text-muted, #64748b); flex-shrink: 0; }
        .pb-mkt-search-input {
          flex: 1;
          background: transparent;
          border: none;
          outline: none;
          color: var(--text-primary, #f0f0f0);
          font-size: 14px;
        }
        .pb-mkt-search-input::placeholder { color: var(--text-muted, #64748b); }
        .pb-mkt-search-clear {
          background: none;
          border: none;
          color: var(--text-muted, #64748b);
          cursor: pointer;
          padding: 2px;
          display: flex;
        }
        .pb-mkt-search-clear:hover { color: var(--text-primary, #f0f0f0); }

        /* Filters */
        .pb-mkt-filters {
          margin-bottom: 16px;
        }
        .pb-mkt-category-pills {
          display: flex;
          gap: 6px;
          flex-wrap: wrap;
          margin-bottom: 10px;
        }
        .pb-mkt-pill {
          padding: 6px 14px;
          border-radius: 16px;
          border: 1px solid var(--border-primary, #334155);
          background: var(--bg-secondary, #1e293b);
          color: var(--text-secondary, #94a3b8);
          font-size: 13px;
          cursor: pointer;
          transition: all 0.15s;
          white-space: nowrap;
        }
        .pb-mkt-pill:hover {
          border-color: var(--accent-primary, #3b82f6);
          color: var(--text-primary, #f0f0f0);
        }
        .pb-mkt-pill-active {
          background: var(--accent-primary, #3b82f6);
          border-color: var(--accent-primary, #3b82f6);
          color: #fff;
        }
        .pb-mkt-difficulty-filter {
          display: flex;
          gap: 6px;
        }
        .pb-mkt-diff-btn {
          padding: 5px 12px;
          border-radius: 6px;
          border: 1px solid var(--border-primary, #334155);
          background: var(--bg-secondary, #1e293b);
          color: var(--text-secondary, #94a3b8);
          font-size: 12px;
          cursor: pointer;
          display: flex;
          align-items: center;
          gap: 5px;
          transition: all 0.15s;
        }
        .pb-mkt-diff-btn:hover { border-color: var(--accent-primary, #3b82f6); }
        .pb-mkt-diff-btn-active {
          background: var(--bg-tertiary, #0f172a);
          border-color: var(--accent-primary, #3b82f6);
          color: var(--text-primary, #f0f0f0);
        }
        .pb-mkt-diff-dot {
          width: 8px;
          height: 8px;
          border-radius: 50%;
          display: inline-block;
        }

        /* Results info */
        .pb-mkt-results-info {
          font-size: 13px;
          color: var(--text-muted, #64748b);
          margin-bottom: 16px;
          display: flex;
          align-items: center;
          gap: 12px;
        }
        .pb-mkt-clear-filters {
          background: none;
          border: none;
          color: var(--accent-primary, #3b82f6);
          cursor: pointer;
          font-size: 12px;
          text-decoration: underline;
        }

        /* Grid */
        .pb-mkt-grid {
          display: grid;
          grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
          gap: 16px;
        }

        /* Card */
        .pb-mkt-card {
          background: var(--bg-secondary, #1e293b);
          border: 1px solid var(--border-primary, #334155);
          border-radius: 10px;
          padding: 16px;
          cursor: pointer;
          transition: all 0.2s;
          display: flex;
          flex-direction: column;
        }
        .pb-mkt-card:hover {
          border-color: var(--accent-primary, #3b82f6);
          transform: translateY(-2px);
          box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
        }
        .pb-mkt-card-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          margin-bottom: 10px;
        }
        .pb-mkt-card-icon {
          color: var(--text-muted, #64748b);
          display: flex;
          align-items: center;
        }
        .pb-mkt-card-title {
          font-size: 15px;
          font-weight: 600;
          color: var(--text-primary, #f0f0f0);
          margin: 0 0 6px 0;
          line-height: 1.3;
        }
        .pb-mkt-card-desc {
          font-size: 13px;
          color: var(--text-secondary, #94a3b8);
          margin: 0 0 10px 0;
          line-height: 1.4;
          flex: 1;
        }
        .pb-mkt-card-tags {
          display: flex;
          flex-wrap: wrap;
          gap: 4px;
          margin-bottom: 10px;
        }
        .pb-mkt-tag-sm {
          padding: 2px 7px;
          border-radius: 4px;
          background: var(--bg-tertiary, #0f172a);
          color: var(--text-muted, #64748b);
          font-size: 11px;
        }
        .pb-mkt-tag-more {
          color: var(--accent-primary, #3b82f6);
        }
        .pb-mkt-card-footer {
          display: flex;
          justify-content: space-between;
          align-items: center;
          padding-top: 10px;
          border-top: 1px solid var(--border-primary, #1e293b);
        }
        .pb-mkt-card-meta {
          display: flex;
          gap: 10px;
          align-items: center;
        }
        .pb-mkt-card-time, .pb-mkt-card-deps, .pb-mkt-card-installs {
          display: flex;
          align-items: center;
          gap: 4px;
          font-size: 12px;
          color: var(--text-muted, #64748b);
        }

        /* Difficulty badge */
        .pb-mkt-difficulty-badge {
          padding: 3px 8px;
          border-radius: 4px;
          font-size: 11px;
          font-weight: 600;
          text-transform: capitalize;
        }
        .pb-mkt-difficulty-badge-sm {
          padding: 2px 6px;
          font-size: 10px;
        }

        /* States */
        .pb-mkt-loading, .pb-mkt-empty, .pb-mkt-error {
          display: flex;
          flex-direction: column;
          align-items: center;
          justify-content: center;
          padding: 60px 20px;
          color: var(--text-muted, #64748b);
          text-align: center;
          gap: 12px;
        }
        .pb-mkt-spinner {
          width: 32px;
          height: 32px;
          border: 3px solid var(--border-primary, #334155);
          border-top: 3px solid var(--accent-primary, #3b82f6);
          border-radius: 50%;
          animation: pb-mkt-spin 0.8s linear infinite;
        }
        @keyframes pb-mkt-spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
        .pb-mkt-empty-icon { color: var(--text-muted, #64748b); display: flex; align-items: center; }
        .pb-mkt-empty h3 { margin: 0; color: var(--text-primary, #f0f0f0); }
        .pb-mkt-empty p { margin: 0; }
        .pb-mkt-error { color: #ef4444; }
        .pb-mkt-error button {
          padding: 6px 16px;
          border-radius: 6px;
          border: 1px solid #ef4444;
          background: transparent;
          color: #ef4444;
          cursor: pointer;
        }

        /* Pagination */
        .pb-mkt-pagination {
          display: flex;
          justify-content: center;
          align-items: center;
          gap: 16px;
          margin-top: 24px;
          padding-top: 16px;
          border-top: 1px solid var(--border-primary, #334155);
        }
        .pb-mkt-page-btn {
          display: flex;
          align-items: center;
          gap: 4px;
          padding: 6px 14px;
          border-radius: 6px;
          border: 1px solid var(--border-primary, #334155);
          background: var(--bg-secondary, #1e293b);
          color: var(--text-secondary, #94a3b8);
          cursor: pointer;
          font-size: 13px;
        }
        .pb-mkt-page-btn:hover:not(:disabled) { border-color: var(--accent-primary, #3b82f6); color: var(--text-primary, #f0f0f0); }
        .pb-mkt-page-btn:disabled { opacity: 0.4; cursor: default; }
        .pb-mkt-page-info { font-size: 13px; color: var(--text-muted, #64748b); }

        /* ──── Detail Drawer ──── */
        .pb-mkt-detail-overlay {
          position: fixed;
          top: 0; left: 0; right: 0; bottom: 0;
          background: rgba(0, 0, 0, 0.6);
          z-index: 1000;
          display: flex;
          justify-content: flex-end;
          animation: pb-mkt-fadeIn 0.15s ease;
        }
        @keyframes pb-mkt-fadeIn { from { opacity: 0; } to { opacity: 1; } }
        .pb-mkt-detail-drawer {
          width: 640px;
          max-width: 90vw;
          height: 100vh;
          background: var(--bg-primary, #0f172a);
          border-left: 1px solid var(--border-primary, #334155);
          overflow-y: auto;
          padding: 20px;
          animation: pb-mkt-slideIn 0.2s ease;
        }
        @keyframes pb-mkt-slideIn { from { transform: translateX(100%); } to { transform: translateX(0); } }
        .pb-mkt-detail-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          margin-bottom: 20px;
        }
        .pb-mkt-detail-back {
          display: flex;
          align-items: center;
          gap: 6px;
          background: none;
          border: none;
          color: var(--text-muted, #64748b);
          cursor: pointer;
          font-size: 13px;
        }
        .pb-mkt-detail-back:hover { color: var(--text-primary, #f0f0f0); }

        /* Buttons */
        .pb-mkt-btn {
          display: flex;
          align-items: center;
          gap: 6px;
          padding: 8px 16px;
          border-radius: 6px;
          border: none;
          font-size: 13px;
          font-weight: 600;
          cursor: pointer;
          transition: all 0.15s;
        }
        .pb-mkt-btn:disabled { opacity: 0.5; cursor: default; }
        .pb-mkt-btn-primary {
          background: var(--accent-primary, #3b82f6);
          color: #fff;
        }
        .pb-mkt-btn-primary:hover:not(:disabled) { background: #2563eb; }
        .pb-mkt-btn-success {
          background: #10b981;
          color: #fff;
        }
        .pb-mkt-btn-success:hover { background: #059669; }
        .pb-mkt-btn-ghost {
          background: transparent;
          color: var(--text-muted, #64748b);
          border: 1px solid var(--border-primary, #334155);
        }
        .pb-mkt-btn-ghost:hover:not(:disabled) {
          color: var(--text-primary, #f0f0f0);
          border-color: var(--text-muted, #64748b);
        }

        /* Banners */
        .pb-mkt-banner {
          padding: 10px 14px;
          border-radius: 8px;
          font-size: 13px;
          display: flex;
          align-items: center;
          gap: 8px;
          margin-bottom: 16px;
        }
        .pb-mkt-banner-success {
          background: rgba(16, 185, 129, 0.1);
          border: 1px solid rgba(16, 185, 129, 0.3);
          color: #10b981;
        }
        .pb-mkt-banner-error {
          background: rgba(239, 68, 68, 0.1);
          border: 1px solid rgba(239, 68, 68, 0.3);
          color: #ef4444;
        }

        /* Detail info */
        .pb-mkt-detail-info {
          margin-bottom: 24px;
        }
        .pb-mkt-detail-title-row {
          display: flex;
          align-items: flex-start;
          gap: 12px;
          margin-bottom: 12px;
        }
        .pb-mkt-detail-icon { color: var(--text-muted, #94a3b8); display: flex; align-items: center; }
        .pb-mkt-detail-name {
          font-size: 20px;
          font-weight: 700;
          color: var(--text-primary, #f0f0f0);
          margin: 0;
        }
        .pb-mkt-detail-author {
          font-size: 12px;
          color: var(--text-muted, #64748b);
        }
        .pb-mkt-detail-desc {
          font-size: 14px;
          color: var(--text-secondary, #94a3b8);
          line-height: 1.6;
          margin: 0 0 16px 0;
        }
        .pb-mkt-detail-meta {
          display: grid;
          grid-template-columns: repeat(auto-fill, minmax(140px, 1fr));
          gap: 12px;
        }
        .pb-mkt-detail-meta-item {
          display: flex;
          flex-direction: column;
          gap: 2px;
        }
        .pb-mkt-meta-label {
          font-size: 11px;
          color: var(--text-muted, #64748b);
          text-transform: uppercase;
          letter-spacing: 0.5px;
        }
        .pb-mkt-meta-value {
          font-size: 14px;
          color: var(--text-primary, #f0f0f0);
          text-transform: capitalize;
        }
        .pb-mkt-detail-tags {
          display: flex;
          flex-wrap: wrap;
          gap: 6px;
          margin-top: 14px;
        }
        .pb-mkt-tag {
          padding: 3px 10px;
          border-radius: 4px;
          background: var(--bg-secondary, #1e293b);
          color: var(--text-secondary, #94a3b8);
          font-size: 12px;
        }

        /* Dependencies section */
        .pb-mkt-detail-deps {
          border-top: 1px solid var(--border-primary, #334155);
          padding-top: 20px;
        }
        .pb-mkt-section-title {
          display: flex;
          align-items: center;
          gap: 8px;
          font-size: 15px;
          font-weight: 600;
          color: var(--text-primary, #f0f0f0);
          margin: 0 0 12px 0;
        }
        .pb-mkt-dep-count {
          background: var(--bg-tertiary, #0f172a);
          padding: 2px 8px;
          border-radius: 10px;
          font-size: 11px;
          color: var(--text-muted, #64748b);
        }
        .pb-mkt-dep-loading {
          font-size: 13px;
          color: var(--text-muted, #64748b);
          padding: 10px;
        }
        .pb-mkt-dep-status {
          display: flex;
          align-items: center;
          gap: 8px;
          padding: 10px 12px;
          border-radius: 8px;
          font-size: 13px;
          margin-bottom: 12px;
        }
        .pb-mkt-dep-ok {
          background: rgba(16, 185, 129, 0.1);
          border: 1px solid rgba(16, 185, 129, 0.2);
          color: #10b981;
        }
        .pb-mkt-dep-warn {
          background: rgba(245, 158, 11, 0.1);
          border: 1px solid rgba(245, 158, 11, 0.2);
          color: #f59e0b;
        }
        .pb-mkt-dep-list {
          display: flex;
          flex-direction: column;
          gap: 8px;
        }
        .pb-mkt-dep-item {
          display: flex;
          align-items: center;
          gap: 8px;
          padding: 10px 12px;
          border-radius: 6px;
          background: var(--bg-secondary, #1e293b);
          font-size: 13px;
        }
        .pb-mkt-dep-satisfied svg { color: #10b981; }
        .pb-mkt-dep-missing svg { color: #ef4444; }
        .pb-mkt-dep-name {
          font-weight: 600;
          color: var(--text-primary, #f0f0f0);
        }
        .pb-mkt-dep-reason {
          flex: 1;
          color: var(--text-muted, #64748b);
          font-size: 12px;
        }
        .pb-mkt-dep-health {
          font-size: 11px;
          padding: 2px 6px;
          border-radius: 3px;
          text-transform: capitalize;
        }
        .pb-mkt-dep-health[data-status="healthy"] { background: rgba(16,185,129,0.15); color: #10b981; }
        .pb-mkt-dep-health[data-status="error"] { background: rgba(239,68,68,0.15); color: #ef4444; }
        .pb-mkt-dep-health[data-status="unknown"] { background: rgba(100,116,139,0.15); color: #64748b; }
        .pb-mkt-dep-configure {
          padding: 4px 10px;
          border-radius: 4px;
          border: 1px solid var(--accent-primary, #3b82f6);
          background: transparent;
          color: var(--accent-primary, #3b82f6);
          font-size: 11px;
          cursor: pointer;
          white-space: nowrap;
        }
        .pb-mkt-dep-configure:hover {
          background: var(--accent-primary, #3b82f6);
          color: #fff;
        }

        /* Integration Mapping Panel */
        .pb-mkt-mapping-panel {
          margin: 0 24px 20px;
          padding: 16px;
          border-radius: 8px;
          background: var(--bg-tertiary, #0f172a);
          border: 1px solid var(--accent-primary, #3b82f6);
        }
        .pb-mkt-mapping-header {
          display: flex;
          gap: 10px;
          align-items: flex-start;
          margin-bottom: 14px;
        }
        .pb-mkt-mapping-header svg {
          color: var(--accent-primary, #3b82f6);
          flex-shrink: 0;
          margin-top: 2px;
        }
        .pb-mkt-mapping-header h4 {
          margin: 0 0 4px;
          font-size: 14px;
          font-weight: 600;
          color: var(--text-primary, #f0f0f0);
        }
        .pb-mkt-mapping-header p {
          margin: 0;
          font-size: 12px;
          color: var(--text-muted, #64748b);
          line-height: 1.4;
        }
        .pb-mkt-mapping-list {
          display: flex;
          flex-direction: column;
          gap: 8px;
          margin-bottom: 14px;
        }
        .pb-mkt-mapping-row {
          display: flex;
          align-items: center;
          gap: 10px;
          padding: 10px 12px;
          border-radius: 6px;
          background: var(--bg-secondary, #1e293b);
        }
        .pb-mkt-mapping-source {
          display: flex;
          align-items: center;
          gap: 6px;
          min-width: 140px;
        }
        .pb-mkt-mapping-name {
          font-weight: 600;
          font-size: 13px;
          color: var(--text-primary, #f0f0f0);
        }
        .pb-mkt-mapping-cat {
          font-size: 10px;
          padding: 1px 5px;
          border-radius: 3px;
          background: rgba(59,130,246,0.12);
          color: var(--accent-primary, #3b82f6);
          text-transform: uppercase;
          letter-spacing: 0.5px;
          white-space: nowrap;
        }
        .pb-mkt-mapping-arrow {
          color: var(--text-muted, #64748b);
          font-size: 14px;
          flex-shrink: 0;
        }
        .pb-mkt-mapping-select {
          flex: 1;
          padding: 6px 10px;
          border-radius: 5px;
          border: 1px solid var(--border-primary, #334155);
          background: var(--bg-primary, #0f172a);
          color: var(--text-primary, #f0f0f0);
          font-size: 12px;
          cursor: pointer;
        }
        .pb-mkt-mapping-select:focus {
          outline: none;
          border-color: var(--accent-primary, #3b82f6);
        }
        .pb-mkt-mapping-none {
          flex: 1;
          font-size: 12px;
          color: var(--text-muted, #64748b);
          font-style: italic;
        }
        .pb-mkt-mapping-unavail {
          opacity: 0.6;
        }
        .pb-mkt-mapping-actions {
          display: flex;
          gap: 8px;
          flex-wrap: wrap;
        }

        /* Workflow Preview */
        .pb-mkt-detail-preview {
          border-top: 1px solid var(--border-primary, #334155);
          padding-top: 20px;
          margin-bottom: 24px;
        }
        .pb-mkt-preview-container {
          background: var(--bg-tertiary, #0f172a);
          border: 1px solid var(--border-primary, #334155);
          border-radius: 8px;
          overflow: hidden;
        }
        .pb-mkt-step-list {
          padding: 16px 16px 8px;
        }
        .pb-mkt-step-row {
          display: flex;
          gap: 14px;
        }
        .pb-mkt-step-timeline {
          display: flex;
          flex-direction: column;
          align-items: center;
          flex-shrink: 0;
          width: 16px;
        }
        .pb-mkt-step-dot {
          width: 10px;
          height: 10px;
          border-radius: 50%;
          flex-shrink: 0;
          margin-top: 4px;
        }
        .pb-mkt-step-line {
          width: 2px;
          flex: 1;
          background: var(--border-primary, #334155);
          min-height: 16px;
        }
        .pb-mkt-step-content {
          flex: 1;
          min-width: 0;
          padding-bottom: 16px;
        }
        .pb-mkt-step-header {
          display: flex;
          align-items: center;
          gap: 8px;
          margin-bottom: 3px;
        }
        .pb-mkt-step-badge {
          display: inline-flex;
          align-items: center;
          padding: 1px 8px;
          font-size: 10px;
          font-weight: 600;
          text-transform: uppercase;
          letter-spacing: 0.5px;
          border-radius: 4px;
          border: 1px solid;
        }
        .pb-mkt-step-num {
          font-size: 10px;
          color: var(--text-muted, #64748b);
        }
        .pb-mkt-step-title {
          font-size: 13px;
          font-weight: 600;
          color: var(--text-primary, #e2e8f0);
          line-height: 1.3;
        }
        .pb-mkt-step-summary {
          font-size: 12px;
          color: var(--text-muted, #94a3b8);
          line-height: 1.4;
          margin-top: 2px;
        }
        .pb-mkt-step-branches {
          display: flex;
          gap: 6px;
          margin-top: 5px;
          flex-wrap: wrap;
        }
        .pb-mkt-step-branch {
          font-size: 10px;
          padding: 1px 7px;
          border-radius: 3px;
          background: rgba(245, 158, 11, 0.1);
          color: #fbbf24;
          border: 1px solid rgba(245, 158, 11, 0.2);
        }
        .pb-mkt-preview-empty {
          display: flex;
          align-items: center;
          justify-content: center;
          height: 120px;
          border: 1px dashed var(--border-primary, #334155);
          border-radius: 8px;
          color: var(--text-muted, #64748b);
          font-size: 13px;
        }
        .pb-mkt-preview-loading {
          display: flex;
          align-items: center;
          justify-content: center;
          gap: 8px;
          height: 120px;
          color: var(--text-muted, #64748b);
          font-size: 13px;
        }

        /* Trigger Configuration */
        .pb-mkt-detail-trigger {
          border-top: 1px solid var(--border-primary, #334155);
          padding-top: 20px;
          margin-bottom: 24px;
        }
        .pb-mkt-trigger-rows {
          display: flex;
          flex-direction: column;
          gap: 12px;
        }
        .pb-mkt-trigger-row {
          display: flex;
          flex-direction: column;
          gap: 6px;
        }
        .pb-mkt-trigger-tags {
          display: flex;
          flex-wrap: wrap;
          gap: 6px;
        }
        .pb-mkt-trigger-tag {
          padding: 3px 10px;
          border-radius: 4px;
          background: var(--bg-secondary, #1e293b);
          color: var(--text-secondary, #94a3b8);
          font-size: 12px;
          text-transform: capitalize;
        }
        .pb-mkt-severity-tag {
          padding: 3px 10px;
          border-radius: 4px;
          font-size: 12px;
          font-weight: 600;
          text-transform: capitalize;
        }
        .pb-mkt-sev-critical { background: rgba(239, 68, 68, 0.15); color: #ef4444; }
        .pb-mkt-sev-high { background: rgba(245, 158, 11, 0.15); color: #f59e0b; }
        .pb-mkt-sev-medium { background: rgba(59, 130, 246, 0.15); color: #3b82f6; }
        .pb-mkt-sev-low { background: rgba(16, 185, 129, 0.15); color: #10b981; }
        .pb-mkt-sev-informational { background: rgba(100, 116, 139, 0.15); color: #94a3b8; }

        /* ──── Light Theme ──── */
        [data-theme="light"] .pb-mkt-title { color: #1e293b; }
        [data-theme="light"] .pb-mkt-search-container { background: #f8fafc; border-color: #e2e8f0; }
        [data-theme="light"] .pb-mkt-search-input { color: #1e293b; }
        [data-theme="light"] .pb-mkt-pill { background: #f8fafc; border-color: #e2e8f0; color: #64748b; }
        [data-theme="light"] .pb-mkt-pill:hover { border-color: #3b82f6; color: #1e293b; }
        [data-theme="light"] .pb-mkt-pill-active { background: #3b82f6; border-color: #3b82f6; color: #fff; }
        [data-theme="light"] .pb-mkt-diff-btn { background: #f8fafc; border-color: #e2e8f0; color: #64748b; }
        [data-theme="light"] .pb-mkt-diff-btn-active { background: #eff6ff; border-color: #3b82f6; color: #1e293b; }
        [data-theme="light"] .pb-mkt-card { background: #fff; border-color: #e2e8f0; }
        [data-theme="light"] .pb-mkt-card:hover { border-color: #3b82f6; box-shadow: 0 4px 12px rgba(0,0,0,0.08); }
        [data-theme="light"] .pb-mkt-card-title { color: #1e293b; }
        [data-theme="light"] .pb-mkt-card-desc { color: #64748b; }
        [data-theme="light"] .pb-mkt-tag-sm { background: #f1f5f9; color: #475569; }
        [data-theme="light"] .pb-mkt-card-footer { border-top-color: #f1f5f9; }
        [data-theme="light"] .pb-mkt-detail-drawer { background: #fff; border-left-color: #e2e8f0; }
        [data-theme="light"] .pb-mkt-detail-name { color: #1e293b; }
        [data-theme="light"] .pb-mkt-detail-desc { color: #475569; }
        [data-theme="light"] .pb-mkt-tag { background: #f1f5f9; color: #475569; }
        [data-theme="light"] .pb-mkt-dep-item { background: #f8fafc; }
        [data-theme="light"] .pb-mkt-dep-name { color: #1e293b; }
        [data-theme="light"] .pb-mkt-section-title { color: #1e293b; }
        [data-theme="light"] .pb-mkt-empty h3 { color: #1e293b; }
        [data-theme="light"] .pb-mkt-page-btn { background: #fff; border-color: #e2e8f0; color: #475569; }
        [data-theme="light"] .pb-mkt-preview-container { background: #f8fafc; border-color: #e2e8f0; }
        [data-theme="light"] .pb-mkt-preview-empty { border-color: #cbd5e1; color: #64748b; }
        [data-theme="light"] .pb-mkt-step-title { color: #1e293b; }
        [data-theme="light"] .pb-mkt-step-summary { color: #64748b; }
        [data-theme="light"] .pb-mkt-step-line { background: #e2e8f0; }
        [data-theme="light"] .pb-mkt-trigger-tag { background: #f1f5f9; color: #475569; }
        [data-theme="light"] .pb-mkt-detail-preview { border-top-color: #e2e8f0; }
        [data-theme="light"] .pb-mkt-detail-trigger { border-top-color: #e2e8f0; }
        [data-theme="light"] .pb-mkt-mapping-panel { background: #f8fafc; border-color: #3b82f6; }
        [data-theme="light"] .pb-mkt-mapping-header h4 { color: #1e293b; }
        [data-theme="light"] .pb-mkt-mapping-row { background: #fff; }
        [data-theme="light"] .pb-mkt-mapping-name { color: #1e293b; }
        [data-theme="light"] .pb-mkt-mapping-select { background: #fff; border-color: #e2e8f0; color: #1e293b; }
        [data-theme="light"] .pb-mkt-btn-ghost { border-color: #e2e8f0; color: #64748b; }
        [data-theme="light"] .pb-mkt-btn-ghost:hover:not(:disabled) { color: #1e293b; border-color: #94a3b8; }
      `}</style>
    </div>
  );
}
