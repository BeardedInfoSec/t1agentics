/**
 * Copyright (c) 2025-2026 T1 Agentics LLC. SPDX-License-Identifier: Apache-2.0
 */

/**
 * ConnectMarketplace - Browse and install connectors from the marketplace.
 * Displays a searchable, filterable grid of available connectors.
 * Click any card to view full details and actions.
 */

import React, { useState, useEffect, useCallback, useRef } from 'react';
import { authFetch, API_BASE_URL } from '../../utils/api';

// SVG icons
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

const ArrowLeftIcon = ({ size = 16 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M19 12H5" /><path d="M12 19l-7-7 7-7" />
  </svg>
);

const CATEGORIES = [
  { label: 'All',              value: null },
  { label: 'Threat Intel',     value: 'threat_intel' },
  { label: 'SIEM',             value: 'siem' },
  { label: 'EDR / XDR',        value: 'edr' },
  { label: 'SOAR',             value: 'soar' },
  { label: 'Email Security',   value: 'email_security' },
  { label: 'NDR',              value: 'ndr' },
  { label: 'Network',          value: 'network' },
  { label: 'IAM / PAM',        value: 'identity' },
  { label: 'Ticketing',        value: 'ticketing' },
  { label: 'Sandbox',          value: 'sandbox' },
  { label: 'Vulnerability',    value: 'vulnerability_management' },
  { label: 'Cloud Security',   value: 'cloud_security' },
  { label: 'ASM',              value: 'asm' },
  { label: 'Code Security',    value: 'code_security' },
  { label: 'DLP',              value: 'dlp' },
  { label: 'Container',        value: 'container_security' },
  { label: 'Secrets Mgmt',     value: 'secrets_management' },
  { label: 'Firewall',         value: 'firewall' },
  { label: 'AWS Security',     value: 'aws_security' },
  { label: 'Azure Security',   value: 'azure_security' },
  { label: 'GCP Security',     value: 'gcp_security' },
  { label: 'GRC',              value: 'grc' },
  { label: 'WAF',              value: 'waf' },
  { label: 'Backup',           value: 'backup' },
  { label: 'DB Security',      value: 'database_security' },
  { label: 'DNS Security',     value: 'dns_security' },
  { label: 'Deception',        value: 'deception' },
  { label: 'Communication',    value: 'communication' },
  { label: 'DevOps',           value: 'devops' },
  { label: 'Utilities',        value: 'utility' },
];

const AUTH_TYPE_LABELS = {
  api_key: 'API Key',
  bearer: 'Bearer',
  basic: 'Basic Auth',
  oauth2_client: 'OAuth2',
  custom_header: 'Custom Headers',
  none: 'No Auth',
};

const ACTION_TYPE_ICONS = {
  investigate: { color: '#60a5fa', label: 'Investigate' },
  contain:     { color: '#f97316', label: 'Contain' },
  correct:     { color: '#a78bfa', label: 'Correct' },
  ingest:      { color: '#34d399', label: 'Ingest' },
  generic:     { color: '#94a3b8', label: 'Generic' },
};

const PER_PAGE = 24;

// ────────────────────────────────────────────────────────────
// Connector detail drawer
// ────────────────────────────────────────────────────────────
function ConnectorDetail({ connector, onClose, onInstall, user }) {
  const actions = connector.actions || [];

  // Group actions by type
  const grouped = {};
  actions.forEach(a => {
    const type = a.type || a.action_type || 'generic';
    if (!grouped[type]) grouped[type] = [];
    grouped[type].push(a);
  });

  return (
    <div className="connector-detail-overlay" onClick={onClose}>
      <div className="connector-detail-drawer" onClick={e => e.stopPropagation()}>
        {/* Header */}
        <div className="connector-detail-header">
          <button className="connector-detail-back" onClick={onClose}>
            <ArrowLeftIcon size={16} />
            <span>Back to Marketplace</span>
          </button>
          {(user?.role === 'admin' || user?.role === 'platform_owner') && (
            <button
              className="connect-btn connect-btn-primary connect-btn-sm"
              onClick={() => { onInstall(connector); onClose(); }}
            >
              Install
            </button>
          )}
        </div>

        {/* Connector info */}
        <div className="connector-detail-info">
          <h2 className="connector-detail-name">{connector.name}</h2>
          <span className="connector-detail-vendor">{connector.vendor || 'Community'}</span>
          <p className="connector-detail-desc">
            {connector.description || 'No description available.'}
          </p>

          <div className="connector-detail-meta">
            <div className="connector-detail-meta-item">
              <span className="connector-detail-meta-label">Category</span>
              <span className="connector-detail-meta-value">{connector.category || 'General'}</span>
            </div>
            <div className="connector-detail-meta-item">
              <span className="connector-detail-meta-label">Auth Type</span>
              <span className="connector-detail-meta-value">
                {AUTH_TYPE_LABELS[connector.auth_type] || connector.auth_type || 'Unknown'}
              </span>
            </div>
            <div className="connector-detail-meta-item">
              <span className="connector-detail-meta-label">Version</span>
              <span className="connector-detail-meta-value">{connector.version || '1.0.0'}</span>
            </div>
            {connector.base_url && (
              <div className="connector-detail-meta-item">
                <span className="connector-detail-meta-label">Base URL</span>
                <span className="connector-detail-meta-value connector-detail-url">{connector.base_url}</span>
              </div>
            )}
            {connector.documentation_url && (
              <div className="connector-detail-meta-item">
                <span className="connector-detail-meta-label">Vendor Docs</span>
                <a
                  href={connector.documentation_url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="connector-detail-meta-value connector-detail-url"
                  style={{ color: 'var(--primary, #3CB371)', textDecoration: 'none' }}
                >
                  {connector.documentation_url.replace(/^https?:\/\//, '').replace(/\/$/, '')} ↗
                </a>
              </div>
            )}
          </div>
        </div>

        {/* Actions list */}
        <div className="connector-detail-actions">
          <h3 className="connector-detail-section-title">
            Actions
            <span className="connector-detail-action-count">{actions.length}</span>
          </h3>

          {actions.length === 0 ? (
            <div className="connector-detail-empty">
              No actions defined for this connector.
            </div>
          ) : (
            <div className="connector-detail-actions-list">
              {Object.entries(grouped).map(([type, typeActions]) => (
                <div key={type} className="connector-detail-action-group">
                  <div className="connector-detail-action-type">
                    <span
                      className="connector-detail-type-dot"
                      style={{ backgroundColor: (ACTION_TYPE_ICONS[type] || ACTION_TYPE_ICONS.generic).color }}
                    />
                    <span className="connector-detail-type-label">
                      {(ACTION_TYPE_ICONS[type] || ACTION_TYPE_ICONS.generic).label}
                    </span>
                    <span className="connector-detail-type-count">{typeActions.length}</span>
                  </div>
                  {typeActions.map((action, i) => (
                    <div key={action.id || i} className="connector-detail-action-row">
                      <div className="connector-detail-action-info">
                        <span className="connector-detail-action-name">
                          {action.name || action.id}
                        </span>
                        {action.description && (
                          <span className="connector-detail-action-desc">{action.description}</span>
                        )}
                      </div>
                      <div className="connector-detail-action-badges">
                        {(action.http_method || action.method) && (
                          <span className={`connector-detail-method method-${(action.http_method || action.method || '').toLowerCase()}`}>
                            {action.http_method || action.method}
                          </span>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ────────────────────────────────────────────────────────────
// Main marketplace component
// ────────────────────────────────────────────────────────────
export default function ConnectMarketplace({ onInstall, user }) {
  const [connectors, setConnectors] = useState([]);
  const [search, setSearch] = useState('');
  const [debouncedSearch, setDebouncedSearch] = useState('');
  const [category, setCategory] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [totalCount, setTotalCount] = useState(0);
  const [selectedConnector, setSelectedConnector] = useState(null);
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

  // Reset page when category changes
  useEffect(() => {
    setPage(1);
  }, [category]);

  // Close detail drawer on Escape key
  useEffect(() => {
    const handleEsc = (e) => {
      if (e.key === 'Escape' && selectedConnector) setSelectedConnector(null);
    };
    document.addEventListener('keydown', handleEsc);
    return () => document.removeEventListener('keydown', handleEsc);
  }, [selectedConnector]);

  // Fetch connectors
  const fetchConnectors = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const params = new URLSearchParams();
      if (debouncedSearch) params.set('search', debouncedSearch);
      if (category) params.set('category', category);
      params.set('page', page.toString());
      params.set('per_page', PER_PAGE.toString());

      const res = await authFetch(`${API_BASE_URL}/api/v1/connect/marketplace?${params.toString()}`);
      if (!mountedRef.current) return;

      if (res.ok) {
        const data = await res.json();
        setConnectors(data.connectors || data.items || data || []);
        setTotalPages(data.total_pages || Math.ceil((data.total || 0) / PER_PAGE) || 1);
        setTotalCount(data.total || (data.connectors || data.items || data || []).length);
      } else {
        const errData = await res.json().catch(() => ({}));
        setError(errData.detail || 'Failed to load marketplace');
      }
    } catch (err) {
      if (mountedRef.current) {
        setError(err.message || 'Network error loading marketplace');
      }
    } finally {
      if (mountedRef.current) setLoading(false);
    }
  }, [debouncedSearch, category, page]);

  useEffect(() => {
    fetchConnectors();
  }, [fetchConnectors]);

  const getCategoryBadgeClass = (cat) => {
    if (!cat) return 'badge badge-category';
    const slug = cat.toLowerCase().replace(/\s+/g, '_');
    return `badge badge-${slug}`;
  };

  const getActionCount = (connector) =>
    connector.action_count || (connector.actions && connector.actions.length) || 0;

  return (
    <div className="marketplace-container">
      {/* Detail drawer */}
      {selectedConnector && (
        <ConnectorDetail
          connector={selectedConnector}
          onClose={() => setSelectedConnector(null)}
          onInstall={onInstall}
          user={user}
        />
      )}

      {/* Search and toolbar */}
      <div className="marketplace-toolbar">
        <div className="marketplace-search" data-tour="connect-marketplace-search">
          <span className="marketplace-search-icon">
            <SearchIcon size={14} />
          </span>
          <input
            ref={searchRef}
            type="text"
            placeholder="Search connectors..."
            value={search}
            onChange={e => setSearch(e.target.value)}
            data-tour="connect-search-input"
          />
          {search && (
            <button className="marketplace-search-clear" onClick={() => setSearch('')}>
              <XIcon size={12} />
            </button>
          )}
        </div>
        <span className="marketplace-result-count">
          {totalCount} connector{totalCount !== 1 ? 's' : ''}
        </span>
      </div>

      {/* Category pills */}
      <div className="marketplace-categories">
        {CATEGORIES.map(cat => (
          <button
            key={cat.label}
            className={`marketplace-category-pill ${category === cat.value ? 'active' : ''}`}
            onClick={() => setCategory(cat.value)}
          >
            {cat.label}
          </button>
        ))}
      </div>

      {/* Error state */}
      {error && (
        <div className="connect-error">
          <span>{error}</span>
          <button className="connect-btn-icon" onClick={() => setError(null)} style={{ marginLeft: 'auto' }}>
            &times;
          </button>
        </div>
      )}

      {/* Loading state */}
      {loading && (
        <div className="connect-loading">
          <div className="connect-spinner lg" />
          <p>Loading marketplace...</p>
        </div>
      )}

      {/* Empty state */}
      {!loading && !error && connectors.length === 0 && (
        <div className="connect-empty">
          <div className="connect-empty-icon">
            <SearchIcon size={24} />
          </div>
          <h3>No connectors found</h3>
          <p>
            {debouncedSearch || category
              ? 'Try adjusting your search or category filter.'
              : 'No connectors are available in the marketplace yet.'}
          </p>
        </div>
      )}

      {/* Connector grid */}
      {!loading && !error && connectors.length > 0 && (
        <>
          <div className="marketplace-grid" data-tour="connect-marketplace">
            {connectors.map(connector => {
              // Tag the cards the GuidedTour cares about so the spotlight
              // can land on the right place during the VT / Inbox sub-tours.
              const name = (connector.name || '').toLowerCase();
              const vendor = (connector.vendor || '').toLowerCase();
              const codename = (connector.codename || '').toLowerCase();
              let tourTag;
              // VirusTotal: tag the v3 card specifically (v2 is legacy / less capable)
              if (
                name.includes('virustotal v3')
                || codename.includes('virustotal_v3')
                || codename === 'virustotal3'
                || (name.includes('virustotal') && (name.includes('v3') || name.includes(' 3')))
              ) {
                tourTag = 'connect-vt-card';
              } else if (
                name.includes('gmail') || vendor.includes('gmail')
                || name.includes('office 365') || name.includes('microsoft 365') || vendor.includes('microsoft')
                || codename === 'email_inbox' || name.includes('email inbox')
                || name.includes('imap')
              ) {
                tourTag = 'connect-inbox-card';
              }
              return (
              <div
                key={connector.id}
                data-tour={tourTag}
                className="marketplace-card marketplace-card-clickable"
                onClick={() => setSelectedConnector(connector)}
                role="button"
                tabIndex={0}
                onKeyDown={e => { if (e.key === 'Enter') setSelectedConnector(connector); }}
              >
                <div className="marketplace-card-header">
                  <div className="marketplace-card-header-left">
                    <h3 className="marketplace-card-name">{connector.name}</h3>
                    <span className="marketplace-card-vendor">{connector.vendor || 'Community'}</span>
                  </div>
                </div>

                <div className="marketplace-card-body">
                  <p className="marketplace-card-desc">
                    {connector.description || 'No description available.'}
                  </p>
                  <div className="marketplace-card-meta">
                    <span className={getCategoryBadgeClass(connector.category)}>
                      {connector.category || 'General'}
                    </span>
                    <span className="badge badge-auth">
                      {AUTH_TYPE_LABELS[connector.auth_type] || connector.auth_type || 'Unknown'}
                    </span>
                  </div>
                </div>

                <div className="marketplace-card-footer">
                  <span className="marketplace-card-actions-count">
                    {getActionCount(connector)} action{getActionCount(connector) !== 1 ? 's' : ''}
                  </span>
                  {(user?.role === 'admin' || user?.role === 'platform_owner') && (
                    <button
                      className="connect-btn connect-btn-primary connect-btn-sm"
                      onClick={(e) => { e.stopPropagation(); onInstall(connector); }}
                    >
                      Install
                    </button>
                  )}
                </div>
              </div>
              );
            })}
          </div>

          {/* Pagination */}
          {totalPages > 1 && (
            <div className="marketplace-pagination">
              <button
                className="connect-btn connect-btn-outline connect-btn-sm"
                disabled={page <= 1}
                onClick={() => setPage(p => Math.max(1, p - 1))}
              >
                <ChevronLeftIcon size={14} />
              </button>
              <span className="marketplace-pagination-info">
                Page {page} of {totalPages}
              </span>
              <button
                className="connect-btn connect-btn-outline connect-btn-sm"
                disabled={page >= totalPages}
                onClick={() => setPage(p => Math.min(totalPages, p + 1))}
              >
                <ChevronRightIcon size={14} />
              </button>
            </div>
          )}
        </>
      )}
    </div>
  );
}
