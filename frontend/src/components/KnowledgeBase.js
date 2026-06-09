/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

import React, { useState, useEffect, useCallback } from 'react';
import { Card, Badge, Button, Tabs, Modal, Input, Select, Textarea, InlineAlert } from './ui';
import {
  BookOpen, Upload, Plus, Trash2, CheckCircle, XCircle, FileText,
  Shield, Workflow, Rss, Plug, List, ChevronDown, ChevronRight, ChevronLeft,
  Search, X, Clock, Cpu, Bot, Zap, AlertTriangle, Info,
  Target, BarChart3, ClipboardList, Settings, ArrowRight, Send, Eye
} from 'lucide-react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { authFetch, getCsrfToken } from '../utils/api';
import { PLATFORM_OWNER_TENANT_ID } from '../config/platform';
import './KnowledgeBase.css';

// Content type icons (using Lucide)
const contentTypeIconMap = {
  sop: ClipboardList,
  playbook: Workflow,
  escalation: AlertTriangle,
  compliance: CheckCircle,
  permission: Shield,
  approval_rule: CheckCircle,
  handling_rule: FileText,
  runbook: Settings,
  policy: BookOpen,
  procedure: FileText,
};

// Category config with colors and labels
const categoryConfig = {
  integrations:      { color: '#8b5cf6', label: 'Integrations', icon: Plug },
  incident_response: { color: '#ef4444', label: 'Incident Response', icon: AlertTriangle },
  threat_detection:  { color: '#f97316', label: 'Threat Detection', icon: Target },
  malware_analysis:  { color: '#eab308', label: 'Malware Analysis', icon: Cpu },
  phishing:          { color: '#22c55e', label: 'Phishing', icon: Shield },
  data_loss:         { color: '#06b6d4', label: 'Data Loss', icon: AlertTriangle },
  insider_threat:    { color: '#3b82f6', label: 'Insider Threat', icon: Shield },
  network_security:  { color: '#3CB371', label: 'Network Security', icon: Shield },
  endpoint_security: { color: '#ec4899', label: 'Endpoint Security', icon: Cpu },
  cloud_security:    { color: '#14b8a6', label: 'Cloud Security', icon: Shield },
  identity_access:   { color: '#f59e0b', label: 'Identity & Access', icon: Shield },
  compliance:        { color: '#3CB371', label: 'Compliance', icon: CheckCircle },
  escalation:        { color: '#dc2626', label: 'Escalation', icon: AlertTriangle },
  communication:     { color: '#0ea5e9', label: 'Communication', icon: Rss },
  documentation:     { color: '#84cc16', label: 'Documentation', icon: BookOpen },
  general:           { color: '#6b7280', label: 'General', icon: FileText },
};

// Backward-compat color map
const categoryColors = Object.fromEntries(
  Object.entries(categoryConfig).map(([k, v]) => [k, v.color])
);

// ============================================================================
// GETTING STARTED HOW-TO CONTENT
// ============================================================================
const gettingStartedGuides = [
  {
    id: 'security-queue',
    title: 'Using the Security Queue',
    icon: Shield,
    category: 'Triage & Investigations',
    content: [
      {
        heading: 'Overview',
        text: 'The Security Queue (Work Queue) is the central hub for triaging alerts and managing investigations. It provides a prioritized view of all incoming security events that require analyst attention.',
      },
      {
        heading: 'Triaging Alerts',
        text: 'Navigate to the Work Queue from the sidebar. Alerts are sorted by severity and age. Click on any alert to open the details drawer, which shows the full event context, related IOCs, and AI-generated recommendations. From here you can change the status (New, In Progress, Resolved, False Positive), assign an owner, or escalate to an investigation.',
      },
      {
        heading: 'Creating Investigations',
        text: 'When an alert warrants deeper analysis, click "Escalate to Investigation" in the alert details. This creates an investigation workspace where you can aggregate related alerts, add notes, collaborate with team members, and track the full incident lifecycle from detection through remediation.',
      },
      {
        heading: 'Bulk Operations',
        text: 'Select multiple alerts using the checkboxes, then use the bulk action bar to change status, assign owners, or merge related alerts into a single investigation. This is useful for handling alert storms or correlated events.',
      },
    ],
  },
  {
    id: 'playbooks',
    title: 'Creating Playbooks',
    icon: Workflow,
    category: 'Automation',
    content: [
      {
        heading: 'Overview',
        text: 'Playbooks define automated or semi-automated response workflows that execute when specific conditions are met. They help standardize incident response procedures and reduce manual toil.',
      },
      {
        heading: 'Creating a Playbook',
        text: 'Navigate to Playbooks from the sidebar. Click "New Playbook" to open the builder. Start by naming your playbook and selecting a trigger type (manual, alert-based, or scheduled). Then add steps using the visual builder or write them in YAML.',
      },
      {
        heading: 'Playbook Steps',
        text: 'Each step can be an enrichment action (IP lookup, domain reputation), a containment action (block IP, isolate host), a notification (email, Slack), or a conditional branch. Steps can reference data from previous steps using template variables.',
      },
      {
        heading: 'Testing and Deployment',
        text: 'Use the "Test Run" feature to execute your playbook against a sample alert without performing real containment actions. Once validated, enable the playbook and set its trigger conditions. All executions are logged in the playbook history for audit purposes.',
      },
    ],
  },
  {
    id: 'threat-intel',
    title: 'Setting Up Threat Intel Feeds',
    icon: Rss,
    category: 'Threat Intelligence',
    content: [
      {
        heading: 'Overview',
        text: 'Threat intelligence feeds provide curated lists of indicators of compromise (IOCs) including malicious IPs, domains, URLs, and file hashes. T1 Agentics ships with preconfigured open-source feeds and supports custom feed sources.',
      },
      {
        heading: 'Enabling Built-in Feeds',
        text: 'Navigate to Threat Intel > Feeds from the sidebar. The feed library shows all available sources. Toggle the switch next to any feed to enable it. Once enabled, the feed will be polled automatically on the configured schedule.',
      },
      {
        heading: 'Adding Custom Feeds',
        text: 'Click "Add Feed" to configure a custom source. Supported formats include STIX/TAXII, CSV, JSON, and plain text (one IOC per line). Provide the URL, authentication credentials if needed, and set the polling interval. The system will auto-detect the format on first pull.',
      },
      {
        heading: 'IOC Matching',
        text: 'Enabled feeds are automatically matched against incoming alerts. When an IOC from a feed matches an observable in an alert, the alert is enriched with the threat intel context including threat actor attribution, confidence scores, and related campaigns.',
      },
    ],
  },
  {
    id: 'integrations',
    title: 'Configuring Integrations',
    icon: Plug,
    category: 'Platform Setup',
    content: [
      {
        heading: 'Overview',
        text: 'Integrations connect T1 Agentics to your existing security stack. This includes SIEM log sources, EDR platforms, firewalls, ticketing systems, and communication tools.',
      },
      {
        heading: 'Adding an Integration',
        text: 'Navigate to Integrations from the sidebar. Browse the integration catalog or search for your tool. Click "Configure" to open the setup wizard. Each integration requires specific credentials (API keys, OAuth tokens, or service accounts) and connection details.',
      },
      {
        heading: 'Alert Ingestion',
        text: 'For log and alert sources (SIEM, EDR, cloud), configure the ingest settings including polling interval, alert filters, and field mappings. Test the connection to verify alerts flow correctly. The system normalizes all ingested data into a common schema for cross-source correlation.',
      },
      {
        heading: 'Response Actions',
        text: 'For response platforms (firewall, EDR, IAM), configure the action capabilities. Each integration defines the actions it supports (block IP, isolate host, disable account). These actions become available in playbooks and for AI-recommended responses.',
      },
    ],
  },
  {
    id: 'edl',
    title: 'Managing External Dynamic Lists',
    icon: List,
    category: 'Firewall Integration',
    content: [
      {
        heading: 'Overview',
        text: 'External Dynamic Lists (EDLs) are live-updating blocklists served via HTTP that your firewalls can consume. T1 Agentics can generate and serve EDLs based on threat intelligence, manual entries, or investigation findings.',
      },
      {
        heading: 'Creating an EDL',
        text: 'Navigate to Threat Intel > EDL Management from the sidebar. Click "Create List" and choose the list type (IP, Domain, or URL). Give it a name and optional description. The system generates a unique delivery URL that your firewall will poll.',
      },
      {
        heading: 'Populating the List',
        text: 'Add IOCs to your EDL manually, from investigation findings, or by linking threat intel feeds. Items can have expiration dates for automatic cleanup. The delivery endpoint always returns the current set of active items in plain text format.',
      },
      {
        heading: 'Firewall Configuration',
        text: 'Copy the delivery URL from the EDL detail view and configure it in your firewall external blocklist settings. Supported platforms include Palo Alto Networks, Fortinet FortiGate, and Cisco Firepower. Set the firewall poll interval to match your EDL update frequency.',
      },
      {
        heading: 'Access Control',
        text: 'Protect EDL endpoints with token authentication, basic auth, or IP allowlists. Navigate to the Credentials tab within an EDL to manage access. This prevents unauthorized access to your blocklist contents.',
      },
    ],
  },
];


// ============================================================================
// GETTING STARTED COMPONENT
// ============================================================================
function GettingStartedGuides() {
  const [expandedGuide, setExpandedGuide] = useState(null);
  const [dismissed, setDismissed] = useState(() => {
    try { return localStorage.getItem('kb-getting-started-dismissed') === 'true'; } catch { return false; }
  });
  const [collapsed, setCollapsed] = useState(true);

  const handleDismiss = () => {
    setDismissed(true);
    try { localStorage.setItem('kb-getting-started-dismissed', 'true'); } catch { /* silent */ }
  };

  if (dismissed) return null;

  return (
    <div className="kb-getting-started">
      <div className="kb-getting-started-header">
        <button
          className="kb-getting-started-toggle"
          onClick={() => setCollapsed(!collapsed)}
        >
          <div className="kb-getting-started-icon">
            <Info size={20} />
          </div>
          <div>
            <h2 className="kb-getting-started-title">Getting Started with T1 Agentics</h2>
            {collapsed && (
              <p className="kb-getting-started-subtitle">
                Quick guides to help you get started. Click to expand.
              </p>
            )}
          </div>
          <div className={`kb-guide-chevron ${!collapsed ? 'kb-guide-chevron--open' : ''}`}>
            <ChevronDown size={16} />
          </div>
        </button>
        <button
          className="kb-getting-started-dismiss"
          onClick={handleDismiss}
          title="Dismiss getting started guides"
        >
          <X size={14} />
        </button>
      </div>

      {!collapsed && (
        <div className="kb-guides-grid">
          {gettingStartedGuides.map((guide) => {
            const IconComponent = guide.icon;
            const isExpanded = expandedGuide === guide.id;

            return (
              <div
                key={guide.id}
                className={`kb-guide-card ${isExpanded ? 'kb-guide-card--expanded' : ''}`}
              >
                <button
                  className="kb-guide-card-header"
                  onClick={() => setExpandedGuide(isExpanded ? null : guide.id)}
                >
                  <div className="kb-guide-card-header-left">
                    <div className="kb-guide-icon">
                      <IconComponent size={18} />
                    </div>
                    <div>
                      <div className="kb-guide-card-title">{guide.title}</div>
                      <div className="kb-guide-card-category">{guide.category}</div>
                    </div>
                  </div>
                  <div className={`kb-guide-chevron ${isExpanded ? 'kb-guide-chevron--open' : ''}`}>
                    <ChevronDown size={16} />
                  </div>
                </button>

                {isExpanded && (
                  <div className="kb-guide-card-body">
                    {guide.content.map((section, idx) => (
                      <div key={idx} className="kb-guide-section">
                        <h4 className="kb-guide-section-heading">{section.heading}</h4>
                        <p className="kb-guide-section-text">{section.text}</p>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}


// ============================================================================
// PAGINATION CONTROLS
// ============================================================================
function PaginationControls({ currentPage, totalCount, pageSize, onPageChange }) {
  const totalPages = Math.ceil(totalCount / pageSize);
  if (totalPages <= 1) return null;

  // Build page number array with ellipsis
  const getPageNumbers = () => {
    const pages = [];
    const maxVisible = 7;
    if (totalPages <= maxVisible) {
      for (let i = 1; i <= totalPages; i++) pages.push(i);
    } else {
      pages.push(1);
      if (currentPage > 3) pages.push('...');
      const start = Math.max(2, currentPage - 1);
      const end = Math.min(totalPages - 1, currentPage + 1);
      for (let i = start; i <= end; i++) pages.push(i);
      if (currentPage < totalPages - 2) pages.push('...');
      pages.push(totalPages);
    }
    return pages;
  };

  const startItem = (currentPage - 1) * pageSize + 1;
  const endItem = Math.min(currentPage * pageSize, totalCount);

  return (
    <div className="kb-pagination">
      <div className="kb-pagination-info">
        Showing {startItem}-{endItem} of {totalCount}
      </div>
      <div className="kb-pagination-controls">
        <button
          className="kb-pagination-btn"
          disabled={currentPage === 1}
          onClick={() => onPageChange(currentPage - 1)}
        >
          <ChevronLeft size={14} />
        </button>
        {getPageNumbers().map((page, idx) =>
          page === '...' ? (
            <span key={`ellipsis-${idx}`} className="kb-pagination-ellipsis">...</span>
          ) : (
            <button
              key={page}
              className={`kb-pagination-btn ${page === currentPage ? 'kb-pagination-btn--active' : ''}`}
              onClick={() => onPageChange(page)}
            >
              {page}
            </button>
          )
        )}
        <button
          className="kb-pagination-btn"
          disabled={currentPage === totalPages}
          onClick={() => onPageChange(currentPage + 1)}
        >
          <ChevronRight size={14} />
        </button>
      </div>
    </div>
  );
}


// ============================================================================
// MAIN KNOWLEDGE BASE COMPONENT
// ============================================================================

function KnowledgeBase({ user }) {
  const isPlatformOwner = user?.tenant_id === PLATFORM_OWNER_TENANT_ID;
  const [entries, setEntries] = useState([]);
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedType, setSelectedType] = useState('');
  const [selectedCategory, setSelectedCategory] = useState('');
  const [selectedSubcategory, setSelectedSubcategory] = useState('');
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [showUploadModal, setShowUploadModal] = useState(false);
  const [showDetailModal, setShowDetailModal] = useState(false);
  const [selectedEntry, setSelectedEntry] = useState(null);
  const [activeTab, setActiveTab] = useState('community');
  const [riggsDraftsCount, setRiggsDraftsCount] = useState(0);
  const [actionApprovalsCount, setActionApprovalsCount] = useState(0);
  const [mySubmissions, setMySubmissions] = useState([]);
  const [submittingKbId, setSubmittingKbId] = useState(null);
  const [currentPage, setCurrentPage] = useState(1);
  const [totalCount, setTotalCount] = useState(0);
  const PAGE_SIZE = 25;

  // Determine source filter from active tab
  const sourceForTab = activeTab === 'community' ? 'builtin' : activeTab === 'organization' ? 'user' : null;

  // Fetch entries
  const fetchEntries = useCallback(async () => {
    try {
      const params = new URLSearchParams();
      if (searchQuery) params.append('search', searchQuery);
      if (selectedType) params.append('content_type', selectedType);
      if (selectedCategory) params.append('category', selectedCategory);
      if (selectedSubcategory) params.append('subcategory', selectedSubcategory);
      if (sourceForTab) params.append('source', sourceForTab);
      params.append('limit', String(PAGE_SIZE));
      params.append('offset', String((currentPage - 1) * PAGE_SIZE));

      const response = await authFetch(`/api/v1/knowledge-base/?${params}`);
      if (!response.ok) throw new Error('Failed to fetch entries');
      const data = await response.json();
      setEntries(data.entries || []);
      setTotalCount(data.total_count || 0);
    } catch (err) {
      setError(err.message);
    }
  }, [searchQuery, selectedType, selectedCategory, selectedSubcategory, sourceForTab, currentPage]);

  // Fetch stats
  const fetchStats = useCallback(async () => {
    try {
      const statsParams = sourceForTab ? `?source=${sourceForTab}` : '';
      const response = await authFetch(`/api/v1/knowledge-base/stats${statsParams}`);
      if (!response.ok) throw new Error('Failed to fetch stats');
      const data = await response.json();
      setStats(data);
    } catch (err) {
      // silent
    }
  }, [sourceForTab]);

  // Fetch Riggs drafts count
  const fetchRiggsDraftsCount = useCallback(async () => {
    try {
      const response = await authFetch('/api/v1/knowledge-base/riggs/drafts?limit=1');
      if (response.ok) {
        const data = await response.json();
        setRiggsDraftsCount(data.count || 0);
      }
    } catch (err) {
      // silent
    }
  }, []);

  // Fetch action approvals count
  const fetchActionApprovalsCount = useCallback(async () => {
    try {
      const response = await authFetch('/api/v1/action-approvals/');
      if (response.ok) {
        const data = await response.json();
        setActionApprovalsCount(data.count || 0);
      }
    } catch (err) {
      // silent
    }
  }, []);

  // Fetch my community submissions
  const fetchMySubmissions = useCallback(async () => {
    try {
      const response = await authFetch('/api/v1/knowledge-base/community-submissions/mine');
      if (response.ok) {
        const data = await response.json();
        setMySubmissions(data.submissions || []);
      }
    } catch (err) {
      // silent
    }
  }, []);

  useEffect(() => {
    const loadData = async () => {
      setLoading(true);
      await Promise.all([fetchEntries(), fetchStats(), fetchRiggsDraftsCount(), fetchActionApprovalsCount(), fetchMySubmissions()]);
      setLoading(false);
    };
    loadData();
  }, [fetchEntries, fetchStats, fetchRiggsDraftsCount, fetchActionApprovalsCount, fetchMySubmissions]);

  // Reset to page 1 when filters change
  useEffect(() => {
    setCurrentPage(1);
  }, [searchQuery, selectedType, selectedCategory, selectedSubcategory]);

  // Search with debounce
  useEffect(() => {
    const timer = setTimeout(() => {
      fetchEntries();
    }, 300);
    return () => clearTimeout(timer);
  }, [searchQuery, selectedType, selectedCategory, selectedSubcategory, currentPage, fetchEntries]);

  const handleViewEntry = (entry) => {
    setSelectedEntry(entry);
    setShowDetailModal(true);
  };

  // Submit article to community
  const handleSubmitToCommunity = async (kbId) => {
    setSubmittingKbId(kbId);
    try {
      const response = await authFetch('/api/v1/knowledge-base/community-submissions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': getCsrfToken() },
        body: JSON.stringify({ kb_id: kbId }),
      });
      if (!response.ok) {
        const data = await response.json();
        throw new Error(data.detail || 'Failed to submit');
      }
      fetchMySubmissions();
    } catch (err) {
      setError(err.message);
    } finally {
      setSubmittingKbId(null);
    }
  };

  // Get submission status for a kb_id
  const getSubmissionStatus = (kbId) => {
    const sub = mySubmissions.find(s => s.kb_id === kbId);
    return sub ? sub.status : null;
  };

  const handleApprove = async (kbId) => {
    try {
      const response = await authFetch(`/api/v1/knowledge-base/${kbId}/approve`, {
        method: 'POST',
        headers: { 'X-CSRF-Token': getCsrfToken() }
      });
      if (!response.ok) throw new Error('Failed to approve entry');
      fetchEntries();
      fetchStats();
    } catch (err) {
      setError(err.message);
    }
  };

  const handleDelete = async (kbId) => {
    if (!window.confirm('Are you sure you want to delete this entry?')) return;
    try {
      const response = await authFetch(`/api/v1/knowledge-base/${kbId}`, {
        method: 'DELETE',
        headers: { 'X-CSRF-Token': getCsrfToken() }
      });
      if (response.status === 403) {
        setError('Builtin knowledge base articles cannot be deleted');
        return;
      }
      if (!response.ok) throw new Error('Failed to delete entry');
      fetchEntries();
      fetchStats();
      setShowDetailModal(false);
    } catch (err) {
      setError(err.message);
    }
  };

  // Handle tab change — reset filters when switching source tabs
  const handleTabChange = useCallback((tabId) => {
    setActiveTab(tabId);
    setCurrentPage(1);
    // Reset filters when switching between community/organization
    if (tabId === 'community' || tabId === 'organization') {
      setSearchQuery('');
      setSelectedType('');
      setSelectedCategory('');
      setSelectedSubcategory('');
    }
  }, []);

  const tabItems = [
    { id: 'community', label: 'Community Library' },
    { id: 'organization', label: 'Organization KB' },
    { id: 'uploads', label: 'Uploads' },
    {
      id: 'riggs-drafts',
      label: riggsDraftsCount > 0 ? `Riggs Drafts (${riggsDraftsCount})` : 'Riggs Drafts',
    },
    {
      id: 'action-approvals',
      label: actionApprovalsCount > 0 ? `Action Approvals (${actionApprovalsCount})` : 'Action Approvals',
    },
    ...(isPlatformOwner ? [{ id: 'community-submissions', label: 'Community Submissions' }] : []),
  ];

  // Show action buttons only on Organization KB tab (or Community for platform owner)
  const showActions = activeTab === 'organization' || (activeTab === 'community' && isPlatformOwner);
  const isEntriesTab = activeTab === 'community' || activeTab === 'organization';

  return (
    <div className="kb-page">
      {/* Tab Header: tabs left, action buttons right */}
      <div className="kb-tab-header">
        <Tabs items={tabItems} active={activeTab} onChange={handleTabChange} />
        {showActions && (
          <div className="kb-tab-actions">
            <Button variant="ghost" onClick={() => setShowUploadModal(true)} icon={<Upload size={15} />}>
              Upload Document
            </Button>
            <Button variant="primary" onClick={() => setShowCreateModal(true)} icon={<Plus size={15} />}>
              New Entry
            </Button>
          </div>
        )}
      </div>

      {/* Stats Cards — only on entry tabs */}
      {stats && isEntriesTab && (
        <div className="kb-stats-row">
          <div className="kb-stat-card">
            <div className="kb-stat-value">{stats.total_entries || 0}</div>
            <div className="kb-stat-label">Total Entries</div>
          </div>
          <div className="kb-stat-card">
            <div className="kb-stat-value kb-stat-value--success">{stats.ai_processed || 0}</div>
            <div className="kb-stat-label">AI Processed</div>
          </div>
          <div className="kb-stat-card">
            <div className="kb-stat-value kb-stat-value--warning">{stats.pending_approval || 0}</div>
            <div className="kb-stat-label">Pending Approval</div>
          </div>
          <div className="kb-stat-card">
            <div className="kb-stat-value">{Object.keys(stats.by_category || {}).length}</div>
            <div className="kb-stat-label">Categories</div>
          </div>
        </div>
      )}

      {/* Search + Type Filter + Category pills — only on entry tabs */}
      {isEntriesTab && (
        <>
          <div className="kb-filters">
            <div className="kb-search-wrapper">
              <Search size={15} className="kb-search-icon" />
              <input
                type="text"
                placeholder="Search by title, tags, or content..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="kb-search-input"
              />
              {searchQuery && (
                <button className="kb-search-clear" onClick={() => setSearchQuery('')}>
                  <X size={14} />
                </button>
              )}
            </div>
            <select
              value={selectedType}
              onChange={(e) => setSelectedType(e.target.value)}
              className="kb-filter-select"
            >
              <option value="">All Types</option>
              {stats?.content_types?.map((type) => (
                <option key={type} value={type}>{type.replace(/_/g, ' ')}</option>
              ))}
            </select>
          </div>

          {/* Category Pills */}
          {stats && (
            <div className="kb-category-pills">
              <button
                className={`kb-category-pill ${!selectedCategory ? 'kb-category-pill--active' : ''}`}
                onClick={() => { setSelectedCategory(''); setSelectedSubcategory(''); }}
              >
                All
                <span className="kb-pill-count">{stats.total_entries || 0}</span>
              </button>
              {Object.entries(stats.by_category || {})
                .sort((a, b) => b[1] - a[1])
                .map(([cat, count]) => {
                  const cfg = categoryConfig[cat] || { color: '#6b7280', label: cat.replace(/_/g, ' ') };
                  return (
                    <button
                      key={cat}
                      className={`kb-category-pill ${selectedCategory === cat ? 'kb-category-pill--active' : ''}`}
                      style={selectedCategory === cat ? { borderColor: cfg.color, background: `${cfg.color}15` } : {}}
                      onClick={() => {
                        setSelectedCategory(selectedCategory === cat ? '' : cat);
                        setSelectedSubcategory('');
                      }}
                    >
                      <span style={{ color: selectedCategory === cat ? cfg.color : undefined }}>
                        {cfg.label}
                      </span>
                      <span className="kb-pill-count">{count}</span>
                    </button>
                  );
                })}
            </div>
          )}

          {/* Subcategory Pills (when a category is selected) */}
          {selectedCategory && stats?.subcategories_by_category?.[selectedCategory] && (
            <div className="kb-subcategory-pills">
              <button
                className={`kb-subcategory-pill ${!selectedSubcategory ? 'kb-subcategory-pill--active' : ''}`}
                onClick={() => setSelectedSubcategory('')}
              >
                All {categoryConfig[selectedCategory]?.label || selectedCategory.replace(/_/g, ' ')}
              </button>
              {stats.subcategories_by_category[selectedCategory].map(({ subcategory: sub, count }) => (
                <button
                  key={sub}
                  className={`kb-subcategory-pill ${selectedSubcategory === sub ? 'kb-subcategory-pill--active' : ''}`}
                  onClick={() => setSelectedSubcategory(selectedSubcategory === sub ? '' : sub)}
                >
                  {sub.replace(/_/g, ' ')}
                  <span className="kb-pill-count">{count}</span>
                </button>
              ))}
            </div>
          )}

          {/* Search result count */}
          {(searchQuery || selectedCategory || selectedSubcategory) && !loading && (
            <div className="kb-results-count">
              {totalCount} result{totalCount !== 1 ? 's' : ''}
              {searchQuery && <> for "<strong>{searchQuery}</strong>"</>}
              {selectedCategory && !searchQuery && <> in <strong>{categoryConfig[selectedCategory]?.label || selectedCategory}</strong></>}
              {selectedSubcategory && <> &rarr; <strong>{selectedSubcategory.replace(/_/g, ' ')}</strong></>}
              {(searchQuery || selectedCategory || selectedSubcategory) && (
                <button
                  className="kb-results-clear"
                  onClick={() => { setSearchQuery(''); setSelectedCategory(''); setSelectedSubcategory(''); setSelectedType(''); }}
                >
                  Clear filters
                </button>
              )}
            </div>
          )}
        </>
      )}

      {/* Error Display */}
      {error && (
        <div className="kb-error-bar">
          <AlertTriangle size={14} />
          <span>{error}</span>
          <button onClick={() => setError(null)} className="kb-error-dismiss">
            <X size={14} />
          </button>
        </div>
      )}

      {/* Loading */}
      {loading && (
        <div className="kb-loading">
          <div className="kb-loading-spinner" />
          Loading knowledge base...
        </div>
      )}

      {/* Entries List — Community Library or Organization KB */}
      {!loading && isEntriesTab && (
        <>
          {entries.length === 0 ? (
            <div className="kb-empty-state">
              <div className="kb-empty-icon">
                <BookOpen size={32} />
              </div>
              <div className="kb-empty-text">
                {searchQuery || selectedCategory
                  ? 'No entries match your filters. Try adjusting your search or category.'
                  : activeTab === 'community'
                    ? 'No community articles available yet.'
                    : 'No organization articles yet. Create your first article or upload a document.'}
              </div>
              {!searchQuery && !selectedCategory && activeTab === 'organization' && <GettingStartedGuides />}
            </div>
          ) : (
            <Card padding="compact">
              <div className="kb-table-wrapper">
                <table className="kb-table">
                  <thead>
                    <tr>
                      <th>Type</th>
                      <th>Title</th>
                      <th>Category</th>
                      <th>Status</th>
                      <th>Tags</th>
                      <th className="kb-th-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {entries.map((entry) => {
                      const TypeIcon = contentTypeIconMap[entry.content_type] || FileText;
                      return (
                        <tr
                          key={entry.kb_id}
                          onClick={() => handleViewEntry(entry)}
                          className="kb-table-row"
                        >
                          <td>
                            <div className="kb-type-icon">
                              <TypeIcon size={16} />
                            </div>
                          </td>
                          <td>
                            <div className="kb-entry-title">{entry.title}</div>
                            <div className="kb-entry-id">{entry.kb_id}</div>
                          </td>
                          <td>
                            <div className="kb-category-cell">
                              {entry.category && (
                                <span
                                  className="kb-category-badge"
                                  style={{
                                    background: `${categoryColors[entry.category] || '#6b7280'}20`,
                                    color: categoryColors[entry.category] || '#6b7280',
                                  }}
                                >
                                  {(categoryConfig[entry.category]?.label || entry.category).replace(/_/g, ' ')}
                                </span>
                              )}
                              {entry.subcategory && (
                                <span className="kb-subcategory-label">
                                  {entry.subcategory.replace(/_/g, ' ')}
                                </span>
                              )}
                            </div>
                          </td>
                          <td>
                            <div className="kb-status-badges">
                              {entry.ai_processed && <Badge variant="success">AI</Badge>}
                              {activeTab === 'community' ? (
                                <Badge variant="info">Community</Badge>
                              ) : entry.approved_at ? (
                                <Badge variant="info">Approved</Badge>
                              ) : (
                                <Badge variant="warning">Pending</Badge>
                              )}
                            </div>
                          </td>
                          <td>
                            <div className="kb-tags">
                              {(entry.tags || []).slice(0, 3).map((tag, i) => (
                                <span key={i} className="kb-tag">{tag}</span>
                              ))}
                              {(entry.tags || []).length > 3 && (
                                <span className="kb-tag-more">+{entry.tags.length - 3}</span>
                              )}
                            </div>
                          </td>
                          <td className="kb-td-right">
                            {activeTab === 'organization' && (() => {
                              const subStatus = getSubmissionStatus(entry.kb_id);
                              return (
                                <div className="kb-action-buttons">
                                  {!subStatus && (
                                    <Button
                                      variant="ghost"
                                      size="sm"
                                      onClick={(e) => { e.stopPropagation(); handleSubmitToCommunity(entry.kb_id); }}
                                      icon={<Send size={12} />}
                                      disabled={submittingKbId === entry.kb_id}
                                    >
                                      {submittingKbId === entry.kb_id ? 'Submitting...' : 'Submit to Community'}
                                    </Button>
                                  )}
                                  {subStatus === 'pending' && (
                                    <Badge variant="warning">Pending Review</Badge>
                                  )}
                                  {subStatus === 'approved' && (
                                    <Badge variant="success">Published</Badge>
                                  )}
                                  {subStatus === 'rejected' && (
                                    <Badge variant="error">Rejected</Badge>
                                  )}
                                  {!entry.approved_at && (
                                    <Button
                                      variant="primary"
                                      size="sm"
                                      onClick={(e) => { e.stopPropagation(); handleApprove(entry.kb_id); }}
                                    >
                                      Approve
                                    </Button>
                                  )}
                                  <Button
                                    variant="danger"
                                    size="sm"
                                    onClick={(e) => { e.stopPropagation(); handleDelete(entry.kb_id); }}
                                    icon={<Trash2 size={12} />}
                                  >
                                    Delete
                                  </Button>
                                </div>
                              );
                            })()}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>

              {/* Pagination controls */}
              {totalCount > PAGE_SIZE && (
                <PaginationControls
                  currentPage={currentPage}
                  totalCount={totalCount}
                  pageSize={PAGE_SIZE}
                  onPageChange={setCurrentPage}
                />
              )}
            </Card>
          )}
        </>
      )}

      {/* Uploads Tab */}
      {!loading && activeTab === 'uploads' && <UploadsTab />}

      {/* Riggs Drafts Tab */}
      {!loading && activeTab === 'riggs-drafts' && (
        <RiggsDraftsTab onUpdate={() => { fetchEntries(); fetchStats(); fetchRiggsDraftsCount(); }} />
      )}

      {/* Action Approvals Tab */}
      {!loading && activeTab === 'action-approvals' && (
        <ActionApprovalsTab onUpdate={() => { fetchActionApprovalsCount(); }} />
      )}

      {/* Community Submissions Tab — Platform Admin only */}
      {!loading && activeTab === 'community-submissions' && isPlatformOwner && (
        <CommunitySubmissionsTab onUpdate={() => { fetchEntries(); fetchStats(); }} />
      )}

      {/* Create Modal */}
      {showCreateModal && (
        <CreateEntryModal
          onClose={() => setShowCreateModal(false)}
          onCreated={() => { fetchEntries(); fetchStats(); setShowCreateModal(false); }}
          contentTypes={stats?.content_types || []}
          categories={stats?.categories || []}
        />
      )}

      {/* Upload Modal */}
      {showUploadModal && (
        <UploadDocumentModal
          onClose={() => setShowUploadModal(false)}
          onUploaded={() => { fetchEntries(); fetchStats(); setShowUploadModal(false); }}
        />
      )}

      {/* Detail Modal */}
      {showDetailModal && selectedEntry && (
        <EntryDetailModal
          entry={selectedEntry}
          onClose={() => setShowDetailModal(false)}
          onUpdate={() => { fetchEntries(); fetchStats(); }}
          onDelete={handleDelete}
        />
      )}
    </div>
  );
}


// ============================================================================
// UPLOADS TAB
// ============================================================================
function UploadsTab() {
  const [uploads, setUploads] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchUploads = async () => {
      try {
        const response = await authFetch('/api/v1/knowledge-base/uploads');
        if (!response.ok) throw new Error('Failed to fetch uploads');
        const data = await response.json();
        setUploads(data.uploads || []);
      } catch (err) {
        // silent
      } finally {
        setLoading(false);
      }
    };
    fetchUploads();
  }, []);

  if (loading) {
    return (
      <div className="kb-loading">
        <div className="kb-loading-spinner" />
        Loading uploads...
      </div>
    );
  }

  if (uploads.length === 0) {
    return (
      <Card>
        <div className="kb-empty-state-inline">
          <Upload size={28} className="kb-empty-icon-inline" />
          <div className="kb-empty-text">No document uploads yet.</div>
        </div>
      </Card>
    );
  }

  return (
    <Card padding="compact">
      <div className="kb-table-wrapper">
        <table className="kb-table">
          <thead>
            <tr>
              <th>Filename</th>
              <th>Type</th>
              <th>Status</th>
              <th>Entries Created</th>
              <th>Uploaded</th>
            </tr>
          </thead>
          <tbody>
            {uploads.map((upload) => (
              <tr key={upload.upload_id}>
                <td>
                  <div className="kb-entry-title">{upload.filename}</div>
                  <div className="kb-entry-id">{upload.upload_id}</div>
                </td>
                <td className="kb-cell-secondary">{upload.file_type}</td>
                <td>
                  <Badge
                    variant={upload.status === 'completed' ? 'success' : upload.status === 'failed' ? 'error' : 'warning'}
                  >
                    {upload.status}
                  </Badge>
                </td>
                <td className="kb-cell-secondary">
                  {(upload.resulting_kb_ids || []).length}
                </td>
                <td className="kb-cell-secondary kb-cell-small">
                  {new Date(upload.created_at).toLocaleString()}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  );
}


// ============================================================================
// RIGGS DRAFTS TAB
// ============================================================================
function RiggsDraftsTab({ onUpdate }) {
  const [drafts, setDrafts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedDraft, setSelectedDraft] = useState(null);
  const [actionLoading, setActionLoading] = useState(null);

  const fetchDrafts = async () => {
    try {
      const response = await authFetch('/api/v1/knowledge-base/riggs/drafts');
      if (!response.ok) throw new Error('Failed to fetch drafts');
      const data = await response.json();
      setDrafts(data.drafts || []);
    } catch (err) {
      // silent
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchDrafts(); }, []);

  const handleApprove = async (kbId) => {
    setActionLoading(kbId);
    try {
      const response = await authFetch(`/api/v1/knowledge-base/riggs/drafts/${kbId}/approve`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': getCsrfToken() },
        body: JSON.stringify({}),
      });
      if (!response.ok) throw new Error('Failed to approve draft');
      fetchDrafts();
      onUpdate();
      setSelectedDraft(null);
    } catch (err) {
      // silent
    } finally {
      setActionLoading(null);
    }
  };

  const handleReject = async (kbId, reason = '') => {
    setActionLoading(kbId);
    try {
      const response = await authFetch(`/api/v1/knowledge-base/riggs/drafts/${kbId}/reject`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': getCsrfToken() },
        body: JSON.stringify({ reason }),
      });
      if (!response.ok) throw new Error('Failed to reject draft');
      fetchDrafts();
      onUpdate();
      setSelectedDraft(null);
    } catch (err) {
      // silent
    } finally {
      setActionLoading(null);
    }
  };

  if (loading) {
    return (
      <div className="kb-loading">
        <div className="kb-loading-spinner" />
        Loading Riggs drafts...
      </div>
    );
  }

  if (drafts.length === 0) {
    return (
      <Card>
        <div className="kb-empty-state-inline">
          <Bot size={28} className="kb-empty-icon-inline" />
          <div className="kb-empty-text">No pending Riggs drafts. Riggs will propose KB entries based on patterns found during investigations.</div>
        </div>
      </Card>
    );
  }

  return (
    <div>
      <Card padding="compact">
        <div className="kb-table-wrapper">
          <table className="kb-table">
            <thead>
              <tr>
                <th>Title</th>
                <th>Category</th>
                <th>Related Alerts</th>
                <th>Created</th>
                <th className="kb-th-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {drafts.map((draft) => (
                <tr
                  key={draft.kb_id}
                  onClick={() => setSelectedDraft(draft)}
                  className="kb-table-row"
                >
                  <td>
                    <div className="kb-entry-row-flex">
                      <div className="kb-type-icon kb-type-icon--bot">
                        <Bot size={14} />
                      </div>
                      <div>
                        <div className="kb-entry-title">{draft.title}</div>
                        <div className="kb-entry-id">{draft.kb_id}</div>
                      </div>
                    </div>
                  </td>
                  <td>
                    {draft.category && (
                      <span className="kb-category-badge" style={{ background: '#6b728020', color: '#9ca3af' }}>
                        {draft.category?.replace(/_/g, ' ')}
                      </span>
                    )}
                  </td>
                  <td className="kb-cell-secondary">{(draft.related_alerts || []).length} alerts</td>
                  <td className="kb-cell-secondary kb-cell-small">
                    {draft.created_at ? new Date(draft.created_at).toLocaleString() : '-'}
                  </td>
                  <td className="kb-td-right">
                    <Button
                      variant="primary"
                      size="sm"
                      onClick={(e) => { e.stopPropagation(); handleApprove(draft.kb_id); }}
                      disabled={actionLoading === draft.kb_id}
                    >
                      {actionLoading === draft.kb_id ? '...' : 'Approve'}
                    </Button>
                    <Button
                      variant="danger"
                      size="sm"
                      onClick={(e) => { e.stopPropagation(); handleReject(draft.kb_id); }}
                      disabled={actionLoading === draft.kb_id}
                    >
                      Reject
                    </Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>

      {/* Draft Detail Modal */}
      {selectedDraft && (
        <div className="kb-modal-overlay" onClick={() => setSelectedDraft(null)}>
          <div className="kb-modal-panel kb-modal-panel--md" onClick={(e) => e.stopPropagation()}>
            <div className="kb-modal-header">
              <div>
                <div className="kb-modal-header-row">
                  <div className="kb-type-icon kb-type-icon--bot"><Bot size={16} /></div>
                  <h2 className="kb-modal-title">{selectedDraft.title}</h2>
                </div>
                <div className="kb-modal-subtitle">Draft proposed by Riggs -- {selectedDraft.kb_id}</div>
              </div>
              <button onClick={() => setSelectedDraft(null)} className="kb-modal-close"><X size={18} /></button>
            </div>

            <div className="kb-modal-body">
              {/* Meta Info */}
              <div className="kb-meta-grid">
                <div className="kb-meta-item">
                  <div className="kb-meta-label">Category</div>
                  <div className="kb-meta-value">{selectedDraft.category || 'Uncategorized'}</div>
                </div>
                <div className="kb-meta-item">
                  <div className="kb-meta-label">Content Type</div>
                  <div className="kb-meta-value">{selectedDraft.content_type || 'sop'}</div>
                </div>
                <div className="kb-meta-item">
                  <div className="kb-meta-label">Related Alerts</div>
                  <div className="kb-meta-value">{(selectedDraft.related_alerts || []).length}</div>
                </div>
              </div>

              {/* Suggested Tags */}
              {selectedDraft.tags && selectedDraft.tags.length > 0 && (
                <div className="kb-detail-section">
                  <div className="kb-meta-label">Suggested Tags</div>
                  <div className="kb-tags">
                    {selectedDraft.tags.map((tag, i) => (
                      <span key={i} className="kb-tag">{tag}</span>
                    ))}
                  </div>
                </div>
              )}

              {/* MITRE Techniques */}
              {selectedDraft.mitre_techniques && selectedDraft.mitre_techniques.length > 0 && (
                <div className="kb-detail-section">
                  <div className="kb-meta-label">MITRE Techniques</div>
                  <div className="kb-tags">
                    {selectedDraft.mitre_techniques.map((tech, i) => (
                      <span key={i} className="kb-tag kb-tag--mitre">{tech}</span>
                    ))}
                  </div>
                </div>
              )}

              {/* Content */}
              <div className="kb-detail-section">
                <div className="kb-meta-label">Proposed Content</div>
                <div className="kb-content-block kb-content-rendered">
                  <ReactMarkdown remarkPlugins={[remarkGfm]}>{selectedDraft.content}</ReactMarkdown>
                </div>
              </div>
            </div>

            <div className="kb-modal-footer">
              <Button
                variant="danger"
                onClick={() => handleReject(selectedDraft.kb_id, 'Rejected during review')}
                disabled={actionLoading === selectedDraft.kb_id}
              >
                Reject Draft
              </Button>
              <Button
                variant="primary"
                onClick={() => handleApprove(selectedDraft.kb_id)}
                disabled={actionLoading === selectedDraft.kb_id}
              >
                {actionLoading === selectedDraft.kb_id ? 'Processing...' : 'Approve & Publish'}
              </Button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}


// ============================================================================
// ACTION APPROVALS TAB
// ============================================================================
function ActionApprovalsTab({ onUpdate }) {
  const [approvals, setApprovals] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedApproval, setSelectedApproval] = useState(null);
  const [actionLoading, setActionLoading] = useState(null);

  const fetchApprovals = async () => {
    try {
      const response = await authFetch('/api/v1/action-approvals/');
      if (!response.ok) throw new Error('Failed to fetch approvals');
      const data = await response.json();
      setApprovals(data.approvals || []);
    } catch (err) {
      // silent
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchApprovals(); }, []);

  const handleApprove = async (approvalId) => {
    setActionLoading(approvalId);
    try {
      const response = await authFetch(`/api/v1/action-approvals/${approvalId}/approve`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': getCsrfToken() },
        body: JSON.stringify({ execute_immediately: true }),
      });
      if (!response.ok) throw new Error('Failed to approve action');
      fetchApprovals();
      onUpdate();
      setSelectedApproval(null);
    } catch (err) {
      // silent
    } finally {
      setActionLoading(null);
    }
  };

  const handleReject = async (approvalId, reason = '') => {
    setActionLoading(approvalId);
    try {
      const response = await authFetch(`/api/v1/action-approvals/${approvalId}/reject`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': getCsrfToken() },
        body: JSON.stringify({ reason }),
      });
      if (!response.ok) throw new Error('Failed to reject action');
      fetchApprovals();
      onUpdate();
      setSelectedApproval(null);
    } catch (err) {
      // silent
    } finally {
      setActionLoading(null);
    }
  };

  if (loading) {
    return (
      <div className="kb-loading">
        <div className="kb-loading-spinner" />
        Loading action approvals...
      </div>
    );
  }

  if (approvals.length === 0) {
    return (
      <Card>
        <div className="kb-empty-state-inline">
          <Zap size={28} className="kb-empty-icon-inline" />
          <div className="kb-empty-text">No pending action approvals. Riggs will request approval when response actions are needed.</div>
        </div>
      </Card>
    );
  }

  return (
    <div>
      <Card padding="compact">
        <div className="kb-table-wrapper">
          <table className="kb-table">
            <thead>
              <tr>
                <th>Priority</th>
                <th>Action</th>
                <th>Target</th>
                <th>Integration</th>
                <th>Confidence</th>
                <th>Expires</th>
                <th className="kb-th-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {approvals.map((approval) => (
                <tr
                  key={approval.approval_id}
                  onClick={() => setSelectedApproval(approval)}
                  className="kb-table-row"
                >
                  <td>
                    <Badge variant={approval.priority || 'medium'}>
                      {approval.priority}
                    </Badge>
                  </td>
                  <td>
                    <div className="kb-entry-title">{approval.action_name?.replace(/_/g, ' ')}</div>
                    <div className="kb-entry-id">{approval.approval_id}</div>
                  </td>
                  <td>
                    <div className="kb-entry-title">{approval.target_identifier}</div>
                    <div className="kb-entry-id">{approval.target_type}</div>
                  </td>
                  <td className="kb-cell-secondary">{approval.integration_name}</td>
                  <td>
                    {approval.riggs_confidence !== null && (
                      <Badge variant={approval.riggs_confidence > 0.8 ? 'success' : approval.riggs_confidence > 0.5 ? 'warning' : 'error'}>
                        {Math.round(approval.riggs_confidence * 100)}%
                      </Badge>
                    )}
                  </td>
                  <td className="kb-cell-secondary kb-cell-small">
                    {approval.expires_at ? new Date(approval.expires_at).toLocaleString() : '-'}
                  </td>
                  <td className="kb-td-right">
                    <Button
                      variant="primary"
                      size="sm"
                      onClick={(e) => { e.stopPropagation(); handleApprove(approval.approval_id); }}
                      disabled={actionLoading === approval.approval_id}
                    >
                      {actionLoading === approval.approval_id ? '...' : 'Execute'}
                    </Button>
                    <Button
                      variant="danger"
                      size="sm"
                      onClick={(e) => { e.stopPropagation(); handleReject(approval.approval_id); }}
                      disabled={actionLoading === approval.approval_id}
                    >
                      Reject
                    </Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>

      {/* Approval Detail Modal */}
      {selectedApproval && (
        <div className="kb-modal-overlay" onClick={() => setSelectedApproval(null)}>
          <div className="kb-modal-panel kb-modal-panel--md" onClick={(e) => e.stopPropagation()}>
            <div className="kb-modal-header">
              <div>
                <div className="kb-modal-header-row">
                  <Badge variant={selectedApproval.priority || 'medium'}>
                    {selectedApproval.priority}
                  </Badge>
                  <h2 className="kb-modal-title">{selectedApproval.action_name?.replace(/_/g, ' ')}</h2>
                </div>
                <div className="kb-modal-subtitle">Requested by Riggs -- {selectedApproval.approval_id}</div>
              </div>
              <button onClick={() => setSelectedApproval(null)} className="kb-modal-close"><X size={18} /></button>
            </div>

            <div className="kb-modal-body">
              {/* Target Info */}
              <div className="kb-target-card">
                <div className="kb-target-label">Target</div>
                <div className="kb-target-value">{selectedApproval.target_identifier}</div>
                <div className="kb-target-type">Type: {selectedApproval.target_type}</div>
              </div>

              {/* Meta Info */}
              <div className="kb-meta-grid">
                <div className="kb-meta-item">
                  <div className="kb-meta-label">Integration</div>
                  <div className="kb-meta-value">{selectedApproval.integration_name}</div>
                </div>
                <div className="kb-meta-item">
                  <div className="kb-meta-label">Riggs Confidence</div>
                  <div className="kb-meta-value">
                    {selectedApproval.riggs_confidence ? `${Math.round(selectedApproval.riggs_confidence * 100)}%` : 'N/A'}
                  </div>
                </div>
                <div className="kb-meta-item">
                  <div className="kb-meta-label">Expires</div>
                  <div className="kb-meta-value">
                    {selectedApproval.expires_at ? new Date(selectedApproval.expires_at).toLocaleString() : 'Never'}
                  </div>
                </div>
              </div>

              {/* Reason */}
              <div className="kb-detail-section">
                <div className="kb-meta-label">Reason</div>
                <div className="kb-content-block">{selectedApproval.reason}</div>
              </div>

              {/* Evidence */}
              {selectedApproval.evidence && Object.keys(selectedApproval.evidence).length > 0 && (
                <div className="kb-detail-section">
                  <div className="kb-meta-label">Evidence</div>
                  <div className="kb-content-block kb-content-block--mono">
                    {JSON.stringify(selectedApproval.evidence, null, 2)}
                  </div>
                </div>
              )}

              {/* Alert/Investigation Links */}
              <div className="kb-links-row">
                {selectedApproval.alert_id && (
                  <div className="kb-link-chip">
                    <span className="kb-link-chip-label">Alert:</span>
                    <span className="kb-link-chip-value">{selectedApproval.alert_id}</span>
                  </div>
                )}
                {selectedApproval.investigation_id && (
                  <div className="kb-link-chip">
                    <span className="kb-link-chip-label">Investigation:</span>
                    <span className="kb-link-chip-value">{selectedApproval.investigation_id}</span>
                  </div>
                )}
              </div>
            </div>

            <div className="kb-modal-footer">
              <Button
                variant="danger"
                onClick={() => handleReject(selectedApproval.approval_id, 'Rejected during review')}
                disabled={actionLoading === selectedApproval.approval_id}
              >
                Reject Action
              </Button>
              <Button
                variant="primary"
                onClick={() => handleApprove(selectedApproval.approval_id)}
                disabled={actionLoading === selectedApproval.approval_id}
              >
                {actionLoading === selectedApproval.approval_id ? 'Executing...' : 'Approve & Execute'}
              </Button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}


// ============================================================================
// CREATE ENTRY MODAL
// ============================================================================
function CreateEntryModal({ onClose, onCreated, contentTypes, categories }) {
  const [formData, setFormData] = useState({
    title: '',
    content: '',
    content_type: 'sop',
    category: '',
    tags: '',
    severity_filter: [],
    incident_types: '',
    priority: 100,
  });
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState(null);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setSubmitting(true);
    setError(null);

    try {
      const response = await authFetch('/api/v1/knowledge-base/', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': getCsrfToken() },
        body: JSON.stringify({
          ...formData,
          tags: formData.tags.split(',').map(t => t.trim()).filter(Boolean),
          incident_types: formData.incident_types.split(',').map(t => t.trim()).filter(Boolean),
        }),
      });

      if (!response.ok) {
        const data = await response.json();
        throw new Error(data.detail || 'Failed to create entry');
      }

      onCreated();
    } catch (err) {
      setError(err.message);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="kb-modal-overlay" onClick={onClose}>
      <div className="kb-modal-panel kb-modal-panel--form" onClick={(e) => e.stopPropagation()}>
        <div className="kb-modal-header">
          <h2 className="kb-modal-title">Create Knowledge Base Entry</h2>
          <button onClick={onClose} className="kb-modal-close"><X size={18} /></button>
        </div>

        <div className="kb-modal-body">
          {error && (
            <div className="kb-error-bar" style={{ marginBottom: '1rem' }}>
              <AlertTriangle size={14} />
              <span>{error}</span>
            </div>
          )}

          <form onSubmit={handleSubmit} id="create-entry-form">
            <div className="kb-form-field">
              <label className="kb-form-label">Title *</label>
              <input
                type="text"
                value={formData.title}
                onChange={(e) => setFormData({ ...formData, title: e.target.value })}
                required
                className="kb-form-input"
              />
            </div>

            <div className="kb-form-row">
              <div className="kb-form-field">
                <label className="kb-form-label">Content Type</label>
                <select
                  value={formData.content_type}
                  onChange={(e) => setFormData({ ...formData, content_type: e.target.value })}
                  className="kb-form-input"
                >
                  {contentTypes.map((type) => (
                    <option key={type} value={type}>{type}</option>
                  ))}
                </select>
              </div>
              <div className="kb-form-field">
                <label className="kb-form-label">Category</label>
                <select
                  value={formData.category}
                  onChange={(e) => setFormData({ ...formData, category: e.target.value })}
                  className="kb-form-input"
                >
                  <option value="">Select category...</option>
                  {categories.map((cat) => (
                    <option key={cat} value={cat}>{cat.replace(/_/g, ' ')}</option>
                  ))}
                </select>
              </div>
            </div>

            <div className="kb-form-field">
              <label className="kb-form-label">Content *</label>
              <textarea
                value={formData.content}
                onChange={(e) => setFormData({ ...formData, content: e.target.value })}
                required
                rows={8}
                className="kb-form-textarea"
                placeholder="Enter the SOP content, procedures, or rules..."
              />
            </div>

            <div className="kb-form-row">
              <div className="kb-form-field">
                <label className="kb-form-label">Tags (comma-separated)</label>
                <input
                  type="text"
                  value={formData.tags}
                  onChange={(e) => setFormData({ ...formData, tags: e.target.value })}
                  placeholder="phishing, email, outlook"
                  className="kb-form-input"
                />
              </div>
              <div className="kb-form-field">
                <label className="kb-form-label">Priority (1-1000)</label>
                <input
                  type="number"
                  value={formData.priority}
                  onChange={(e) => setFormData({ ...formData, priority: parseInt(e.target.value) || 100 })}
                  min={1}
                  max={1000}
                  className="kb-form-input"
                />
              </div>
            </div>

            <div className="kb-form-field">
              <label className="kb-form-label">Severity Filter</label>
              <div className="kb-checkbox-row">
                {['low', 'medium', 'high', 'critical'].map((sev) => (
                  <label key={sev} className="kb-checkbox-label">
                    <input
                      type="checkbox"
                      checked={formData.severity_filter.includes(sev)}
                      onChange={(e) => {
                        if (e.target.checked) {
                          setFormData({ ...formData, severity_filter: [...formData.severity_filter, sev] });
                        } else {
                          setFormData({ ...formData, severity_filter: formData.severity_filter.filter(s => s !== sev) });
                        }
                      }}
                    />
                    {sev}
                  </label>
                ))}
              </div>
            </div>
          </form>
        </div>

        <div className="kb-modal-footer">
          <Button variant="ghost" onClick={onClose}>Cancel</Button>
          <Button
            variant="primary"
            type="submit"
            form="create-entry-form"
            disabled={submitting}
          >
            {submitting ? 'Creating...' : 'Create Entry'}
          </Button>
        </div>
      </div>
    </div>
  );
}


// ============================================================================
// UPLOAD DOCUMENT MODAL
// ============================================================================
function UploadDocumentModal({ onClose, onUploaded }) {
  const [files, setFiles] = useState([]);
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState(null);
  const [result, setResult] = useState(null);

  const handleUpload = async (e) => {
    e.preventDefault();
    if (files.length === 0) return;

    setUploading(true);
    setError(null);

    try {
      const formData = new FormData();
      files.forEach((file) => { formData.append('files', file); });

      const response = await authFetch('/api/v1/knowledge-base/upload', {
        method: 'POST',
        headers: { 'X-CSRF-Token': getCsrfToken() },
        body: formData,
      });

      if (!response.ok) {
        const data = await response.json();
        throw new Error(data.detail || 'Upload failed');
      }

      const data = await response.json();
      setResult(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setUploading(false);
    }
  };

  const removeFile = (index) => { setFiles(files.filter((_, i) => i !== index)); };
  const totalSize = files.reduce((sum, f) => sum + f.size, 0);

  return (
    <div className="kb-modal-overlay" onClick={onClose}>
      <div className="kb-modal-panel kb-modal-panel--form" onClick={(e) => e.stopPropagation()}>
        <div className="kb-modal-header">
          <h2 className="kb-modal-title">Upload Documents</h2>
          <button onClick={onClose} className="kb-modal-close"><X size={18} /></button>
        </div>

        <div className="kb-modal-body">
          {error && (
            <div className="kb-error-bar" style={{ marginBottom: '1rem' }}>
              <AlertTriangle size={14} />
              <span>{error}</span>
            </div>
          )}

          {result ? (
            <div>
              <div className="kb-upload-success">
                <CheckCircle size={18} />
                <div>
                  <div className="kb-upload-success-title">Upload Complete</div>
                  <div className="kb-upload-success-detail">
                    {result.successful} of {result.total_files} files processed successfully
                  </div>
                </div>
              </div>

              {result.errors && result.errors.length > 0 && (
                <div className="kb-detail-section">
                  <div className="kb-meta-label" style={{ color: '#ef4444' }}>Failed:</div>
                  {result.errors.map((err, i) => (
                    <div key={i} className="kb-upload-error-item">
                      <div className="kb-upload-error-file">{err.filename}</div>
                      <div className="kb-upload-error-msg">{err.error}</div>
                    </div>
                  ))}
                </div>
              )}

              {result.uploads && result.uploads.length > 0 && (
                <div className="kb-detail-section">
                  <div className="kb-meta-label">Processed Files:</div>
                  {result.uploads.map((upload, i) => (
                    <div key={i} className="kb-upload-result-item">
                      <div className="kb-entry-title">{upload.filename}</div>
                      <div className="kb-entry-id">{upload.entries_count || 0} entries created</div>
                    </div>
                  ))}
                </div>
              )}

              <Button variant="primary" fullWidth onClick={onUploaded} style={{ marginTop: '1rem' }}>
                Done
              </Button>
            </div>
          ) : (
            <form onSubmit={handleUpload}>
              <div
                className="kb-upload-dropzone"
                onClick={() => document.getElementById('file-input').click()}
                onDragOver={(e) => { e.preventDefault(); e.currentTarget.classList.add('kb-upload-dropzone--active'); }}
                onDragLeave={(e) => { e.preventDefault(); e.currentTarget.classList.remove('kb-upload-dropzone--active'); }}
                onDrop={(e) => {
                  e.preventDefault();
                  e.currentTarget.classList.remove('kb-upload-dropzone--active');
                  const droppedFiles = Array.from(e.dataTransfer.files);
                  setFiles(prev => [...prev, ...droppedFiles]);
                }}
              >
                <Upload size={24} className="kb-upload-dropzone-icon" />
                <div className="kb-upload-dropzone-text">Click or drag files here</div>
                <div className="kb-upload-dropzone-hint">MD, TXT, JSON, PDF, CSV, YAML, HTML, DOCX, PPTX</div>
              </div>
              <input
                id="file-input"
                type="file"
                multiple
                accept=".md,.txt,.json,.pdf,.csv,.yaml,.yml,.html,.docx,.pptx"
                onChange={(e) => {
                  const newFiles = Array.from(e.target.files || []);
                  setFiles(prev => [...prev, ...newFiles]);
                  e.target.value = '';
                }}
                style={{ display: 'none' }}
              />

              {files.length > 0 && (
                <div className="kb-upload-file-list">
                  <div className="kb-upload-file-list-header">
                    <span className="kb-cell-secondary">
                      {files.length} file{files.length !== 1 ? 's' : ''} selected ({(totalSize / 1024).toFixed(1)} KB total)
                    </span>
                    <button type="button" onClick={() => setFiles([])} className="kb-upload-clear-btn">
                      Clear all
                    </button>
                  </div>
                  {files.map((file, index) => (
                    <div key={index} className="kb-upload-file-item">
                      <div className="kb-upload-file-info">
                        <FileText size={14} />
                        <div>
                          <div className="kb-entry-title">{file.name}</div>
                          <div className="kb-entry-id">{(file.size / 1024).toFixed(1)} KB</div>
                        </div>
                      </div>
                      <button type="button" onClick={() => removeFile(index)} className="kb-upload-file-remove">
                        <X size={14} />
                      </button>
                    </div>
                  ))}
                </div>
              )}

              <p className="kb-upload-note">
                Documents will be processed by AI to extract SOPs, procedures, and rules.
              </p>

              <div className="kb-modal-footer" style={{ padding: 0, marginTop: '1rem' }}>
                <Button variant="ghost" onClick={onClose}>Cancel</Button>
                <Button
                  variant="primary"
                  type="submit"
                  disabled={files.length === 0 || uploading}
                >
                  {uploading ? 'Processing...' : `Upload ${files.length} File${files.length !== 1 ? 's' : ''}`}
                </Button>
              </div>
            </form>
          )}
        </div>
      </div>
    </div>
  );
}


// ============================================================================
// ENTRY DETAIL MODAL
// ============================================================================
function EntryDetailModal({ entry, onClose, onUpdate, onDelete }) {
  const [versions, setVersions] = useState([]);
  const [showVersions, setShowVersions] = useState(false);

  const TypeIcon = contentTypeIconMap[entry.content_type] || FileText;

  useEffect(() => {
    const fetchVersions = async () => {
      try {
        const response = await authFetch(`/api/v1/knowledge-base/${entry.kb_id}/versions`);
        if (response.ok) {
          const data = await response.json();
          setVersions(data.versions || []);
        }
      } catch (err) {
        // silent
      }
    };
    fetchVersions();
  }, [entry.kb_id]);

  return (
    <div className="kb-modal-overlay" onClick={onClose}>
      <div className="kb-modal-panel kb-modal-panel--lg" onClick={(e) => e.stopPropagation()}>
        {/* Header */}
        <div className="kb-modal-header kb-modal-header--sticky">
          <div>
            <div className="kb-modal-header-row">
              <div className="kb-type-icon"><TypeIcon size={18} /></div>
              <h2 className="kb-modal-title">{entry.title}</h2>
            </div>
            <div className="kb-modal-subtitle">{entry.kb_id} -- Version {entry.version || 1}</div>
          </div>
          <button onClick={onClose} className="kb-modal-close"><X size={18} /></button>
        </div>

        {/* Content */}
        <div className="kb-modal-body">
          {/* Meta Info */}
          <div className="kb-meta-grid kb-meta-grid--4">
            <div className="kb-meta-item">
              <div className="kb-meta-label">Content Type</div>
              <div className="kb-meta-value">{entry.content_type}</div>
            </div>
            <div className="kb-meta-item">
              <div className="kb-meta-label">Category</div>
              <div className="kb-meta-value">{entry.category || 'None'}</div>
            </div>
            <div className="kb-meta-item">
              <div className="kb-meta-label">Priority</div>
              <div className="kb-meta-value">{entry.priority}</div>
            </div>
            <div className="kb-meta-item">
              <div className="kb-meta-label">Status</div>
              <div className="kb-status-badges">
                {entry.ai_processed && <Badge variant="success">AI</Badge>}
                {entry.source === 'builtin' ? <Badge variant="info">T1 Provided</Badge> : entry.approved_at ? <Badge variant="info">Approved</Badge> : <Badge variant="warning">Pending</Badge>}
              </div>
            </div>
          </div>

          {/* Tags */}
          {entry.tags && entry.tags.length > 0 && (
            <div className="kb-detail-section">
              <div className="kb-meta-label">Tags</div>
              <div className="kb-tags">
                {entry.tags.map((tag, i) => (
                  <span key={i} className="kb-tag">{tag}</span>
                ))}
              </div>
            </div>
          )}

          {/* AI Summary */}
          {entry.ai_summary && (
            <div className="kb-detail-section">
              <div className="kb-meta-label">AI Summary</div>
              <div className="kb-ai-summary">{entry.ai_summary}</div>
            </div>
          )}

          {/* AI Extracted Rules */}
          {entry.ai_extracted_rules && entry.ai_extracted_rules.length > 0 && (
            <div className="kb-detail-section">
              <div className="kb-meta-label">AI Extracted Rules</div>
              <div className="kb-rules-list">
                <ul>
                  {entry.ai_extracted_rules.map((rule, i) => (
                    <li key={i}>{rule}</li>
                  ))}
                </ul>
              </div>
            </div>
          )}

          {/* Content */}
          <div className="kb-detail-section">
            <div className="kb-meta-label">Content</div>
            <div className="kb-content-block kb-content-rendered">
              <ReactMarkdown remarkPlugins={[remarkGfm]}>{entry.content}</ReactMarkdown>
            </div>
          </div>

          {/* Versions */}
          <div className="kb-detail-section">
            <button
              onClick={() => setShowVersions(!showVersions)}
              className="kb-versions-toggle"
            >
              {showVersions ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
              Version History ({versions.length})
            </button>
            {showVersions && versions.length > 0 && (
              <div className="kb-versions-list">
                {versions.map((v) => (
                  <div key={v.version} className="kb-version-item">
                    <div className="kb-version-item-header">
                      <span className="kb-meta-value">Version {v.version}</span>
                      <span className="kb-cell-secondary kb-cell-small">{new Date(v.created_at).toLocaleString()}</span>
                    </div>
                    {v.change_reason && <div className="kb-cell-secondary">{v.change_reason}</div>}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Footer */}
        <div className="kb-modal-footer">
          {entry.source !== 'builtin' && (
            <Button variant="danger" onClick={() => onDelete(entry.kb_id)} icon={<Trash2 size={14} />}>
              Delete
            </Button>
          )}
          <Button variant="ghost" onClick={onClose}>
            Close
          </Button>
        </div>
      </div>
    </div>
  );
}


// ============================================================================
// COMMUNITY SUBMISSIONS TAB (Platform Admin)
// ============================================================================
function CommunitySubmissionsTab({ onUpdate }) {
  const [submissions, setSubmissions] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedSubmission, setSelectedSubmission] = useState(null);
  const [reviewNotes, setReviewNotes] = useState('');
  const [actionLoading, setActionLoading] = useState(null);
  const [previewEntry, setPreviewEntry] = useState(null);
  const [statusFilter, setStatusFilter] = useState('pending');

  const fetchSubmissions = async () => {
    try {
      const response = await authFetch(`/api/v1/knowledge-base/community-submissions?status=${statusFilter}`);
      if (!response.ok) throw new Error('Failed to fetch submissions');
      const data = await response.json();
      setSubmissions(data.submissions || []);
    } catch (err) {
      // silent
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { setLoading(true); fetchSubmissions(); }, [statusFilter]);

  const handlePreview = async (submission) => {
    setSelectedSubmission(submission);
    try {
      const response = await authFetch(`/api/v1/knowledge-base/${submission.kb_id}`);
      if (response.ok) {
        const data = await response.json();
        setPreviewEntry(data);
      }
    } catch (err) {
      // silent
    }
  };

  const handleApprove = async (submissionId) => {
    setActionLoading(submissionId);
    try {
      const response = await authFetch(`/api/v1/knowledge-base/community-submissions/${submissionId}/approve`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': getCsrfToken() },
        body: JSON.stringify({ reviewer_notes: reviewNotes || null }),
      });
      if (!response.ok) throw new Error('Failed to approve');
      setSelectedSubmission(null);
      setPreviewEntry(null);
      setReviewNotes('');
      fetchSubmissions();
      onUpdate();
    } catch (err) {
      // silent
    } finally {
      setActionLoading(null);
    }
  };

  const handleReject = async (submissionId) => {
    setActionLoading(submissionId);
    try {
      const response = await authFetch(`/api/v1/knowledge-base/community-submissions/${submissionId}/reject`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': getCsrfToken() },
        body: JSON.stringify({ reviewer_notes: reviewNotes || null }),
      });
      if (!response.ok) throw new Error('Failed to reject');
      setSelectedSubmission(null);
      setPreviewEntry(null);
      setReviewNotes('');
      fetchSubmissions();
    } catch (err) {
      // silent
    } finally {
      setActionLoading(null);
    }
  };

  if (loading) {
    return (
      <div className="kb-loading">
        <div className="kb-loading-spinner" />
        Loading submissions...
      </div>
    );
  }

  return (
    <>
      <div className="kb-submissions-filters">
        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          className="kb-filter-select"
        >
          <option value="pending">Pending</option>
          <option value="approved">Approved</option>
          <option value="rejected">Rejected</option>
        </select>
      </div>

      {submissions.length === 0 ? (
        <Card>
          <div className="kb-empty-state-inline">
            <Send size={28} className="kb-empty-icon-inline" />
            <div className="kb-empty-text">No {statusFilter} community submissions.</div>
          </div>
        </Card>
      ) : (
        <Card padding="compact">
          <div className="kb-table-wrapper">
            <table className="kb-table">
              <thead>
                <tr>
                  <th>Article</th>
                  <th>Submitted By</th>
                  <th>Date</th>
                  <th>Status</th>
                  <th className="kb-th-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                {submissions.map((sub) => (
                  <tr key={sub.id} className="kb-table-row" onClick={() => handlePreview(sub)}>
                    <td>
                      <div className="kb-entry-title">{sub.article_title || sub.kb_id}</div>
                      <div className="kb-entry-id">{sub.category || ''} {sub.content_type ? `(${sub.content_type})` : ''}</div>
                    </td>
                    <td className="kb-cell-secondary">{sub.submitted_by}</td>
                    <td className="kb-cell-secondary kb-cell-small">
                      {sub.created_at ? new Date(sub.created_at).toLocaleDateString() : ''}
                    </td>
                    <td>
                      <Badge variant={sub.status === 'pending' ? 'warning' : sub.status === 'approved' ? 'success' : 'error'}>
                        {sub.status}
                      </Badge>
                    </td>
                    <td className="kb-td-right">
                      {sub.status === 'pending' && (
                        <div className="kb-action-buttons">
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={(e) => { e.stopPropagation(); handlePreview(sub); }}
                            icon={<Eye size={12} />}
                          >
                            Review
                          </Button>
                        </div>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}

      {/* Review Modal */}
      {selectedSubmission && (
        <div className="kb-modal-overlay" onClick={() => { setSelectedSubmission(null); setPreviewEntry(null); setReviewNotes(''); }}>
          <div className="kb-modal-panel kb-modal-panel--wide" onClick={(e) => e.stopPropagation()}>
            <div className="kb-modal-header">
              <div>
                <h2 className="kb-modal-title">Review Submission</h2>
                <p className="kb-modal-subtitle">
                  Submitted by {selectedSubmission.submitted_by} on{' '}
                  {selectedSubmission.created_at ? new Date(selectedSubmission.created_at).toLocaleDateString() : 'N/A'}
                </p>
              </div>
              <button className="kb-modal-close" onClick={() => { setSelectedSubmission(null); setPreviewEntry(null); setReviewNotes(''); }}>
                <X size={18} />
              </button>
            </div>

            <div className="kb-modal-body" style={{ maxHeight: '60vh', overflow: 'auto' }}>
              {previewEntry ? (
                <>
                  <h3 style={{ margin: '0 0 0.5rem 0', color: 'var(--text-primary, #f0f6fc)' }}>
                    {previewEntry.title}
                  </h3>
                  <div className="kb-meta-grid" style={{ marginBottom: '1rem' }}>
                    <div>
                      <span className="kb-meta-label">Type: </span>
                      <span className="kb-meta-value">{previewEntry.content_type}</span>
                    </div>
                    <div>
                      <span className="kb-meta-label">Category: </span>
                      <span className="kb-meta-value">{previewEntry.category}</span>
                    </div>
                  </div>
                  <div className="kb-content-block kb-content-rendered" style={{ maxHeight: '300px', overflow: 'auto' }}>
                    <ReactMarkdown remarkPlugins={[remarkGfm]}>{previewEntry.content}</ReactMarkdown>
                  </div>
                </>
              ) : (
                <div className="kb-loading">
                  <div className="kb-loading-spinner" />
                  Loading article...
                </div>
              )}

              {selectedSubmission.status === 'pending' && (
                <div style={{ marginTop: '1rem' }}>
                  <label className="kb-form-label">Reviewer Notes (optional)</label>
                  <textarea
                    className="kb-form-textarea"
                    value={reviewNotes}
                    onChange={(e) => setReviewNotes(e.target.value)}
                    placeholder="Add notes for the submitter..."
                    rows={3}
                  />
                </div>
              )}
            </div>

            <div className="kb-modal-footer">
              {selectedSubmission.status === 'pending' && (
                <>
                  <Button
                    variant="danger"
                    onClick={() => handleReject(selectedSubmission.id)}
                    disabled={actionLoading === selectedSubmission.id}
                    icon={<XCircle size={14} />}
                  >
                    Reject
                  </Button>
                  <Button
                    variant="primary"
                    onClick={() => handleApprove(selectedSubmission.id)}
                    disabled={actionLoading === selectedSubmission.id}
                    icon={<CheckCircle size={14} />}
                  >
                    Approve & Publish
                  </Button>
                </>
              )}
              <Button variant="ghost" onClick={() => { setSelectedSubmission(null); setPreviewEntry(null); setReviewNotes(''); }}>
                Close
              </Button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}


export default KnowledgeBase;
