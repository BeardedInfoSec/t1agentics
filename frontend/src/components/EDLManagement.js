/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

import React, { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { API_BASE_URL } from '../utils/api';
import { copyToClipboard } from '../utils/clipboard';
import { useToast } from './ui/Toast';
import './ThreatIntelShell.css';
import ThreatIntelTabs from './ThreatIntelTabs';

/**
 * EDL Management - External Dynamic List Management
 *
 * Full CRUD for EDL lists consumed by firewalls (Palo Alto, Fortinet, Cisco).
 * Features:
 * - Create/edit/delete EDL lists (type-restricted: IP, Domain, URL)
 * - Add/remove IOCs from lists
 * - Manage access credentials (token, basic, IP allowlist)
 * - View access logs and change history
 * - Copy firewall-ready delivery URLs
 */
function EDLManagement() {
  const navigate = useNavigate();
  const toast = useToast();

  // List state
  const [lists, setLists] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [typeFilter, setTypeFilter] = useState(null);
  const [sortConfig, setSortConfig] = useState({ key: 'name', direction: 'asc' });

  // Modals
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [selectedList, setSelectedList] = useState(null);
  const [showItemsPanel, setShowItemsPanel] = useState(null);
  const [showCredsPanel, setShowCredsPanel] = useState(null);
  const [showAddItemsModal, setShowAddItemsModal] = useState(null);
  const [showCreateCredModal, setShowCreateCredModal] = useState(null);
  const [showAccessLog, setShowAccessLog] = useState(null);

  // Pagination
  const [currentPage, setCurrentPage] = useState(1);
  const [rowsPerPage] = useState(20);

  // Tenant slug — used to build EDL delivery URLs that point at the
  // tenant subdomain (e.g. barbas-rooster-co.t1agentics.ai/v1/lists/...).
  // The apex domain accepts the request and the tenant middleware
  // resolves the tenant correctly either way, but firewalls SHOULD be
  // configured against the tenant subdomain so cross-tenant isolation
  // is explicit at the URL level.
  const [tenantSlug, setTenantSlug] = useState(null);

  useEffect(() => {
    let cancelled = false;
    fetch(`${API_BASE_URL}/api/v1/admin/me/tenant`, { credentials: 'include' })
      .then((r) => (r.ok ? r.json() : null))
      .then((data) => { if (!cancelled && data?.slug) setTenantSlug(data.slug); })
      .catch(() => {});
    return () => { cancelled = true; };
  }, []);

  // ============================================================================
  // DATA FETCHING
  // ============================================================================

  const fetchLists = useCallback(async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/api/v1/edl/lists`, {
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
      });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const data = await response.json();
      setLists(data.lists || []);
      setLoading(false);
    } catch (err) {
      setError(err.message);
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchLists();
  }, [fetchLists]);

  // ============================================================================
  // ACTIONS
  // ============================================================================

  const deleteList = async (listId) => {
    if (!window.confirm('Delete this EDL list? All items, credentials, and logs will be removed.')) return;
    try {
      await fetch(`${API_BASE_URL}/api/v1/edl/lists/${listId}`, {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
      });
      fetchLists();
    } catch (err) {
      toast.error(`Failed to delete: ${err.message}`);
    }
  };

  const toggleList = async (listId, enabled) => {
    try {
      await fetch(`${API_BASE_URL}/api/v1/edl/lists/${listId}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ enabled }),
      });
      setLists(prev => prev.map(l =>
        l.list_id === listId ? { ...l, enabled } : l
      ));
    } catch (err) {
      toast.error(`Failed to update: ${err.message}`);
    }
  };

  const regenerateList = async (listId) => {
    try {
      const response = await fetch(`${API_BASE_URL}/api/v1/edl/lists/${listId}/regenerate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
      });
      const data = await response.json();
      toast.success(`Regenerated: ${data.items_generated} items`);
      fetchLists();
    } catch (err) {
      toast.error(`Failed to regenerate: ${err.message}`);
    }
  };

  // Build the EDL delivery URL using the tenant subdomain (not the apex
  // domain that the user happens to be browsing from). This is what the
  // firewall should be configured against.
  const buildDeliveryUrl = (slug) => {
    const { protocol, hostname, port } = window.location;
    if (!tenantSlug) {
      // Fallback to current origin if the tenant lookup hasn't completed —
      // the apex still routes correctly via TenantMiddleware, but it's not
      // the ideal value to copy. Caller can re-copy once tenant loads.
      return `${window.location.origin}/v1/lists/${slug}`;
    }
    // Replace the leftmost label of the hostname with the tenant slug.
    // - barbas-rooster-co.t1agentics.ai → barbas-rooster-co.t1agentics.ai (no change)
    // - t1agentics.ai                    → barbas-rooster-co.t1agentics.ai
    // - localhost                        → barbas-rooster-co.localhost
    let host = hostname;
    const parts = hostname.split('.');
    const isIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname);
    if (!isIp) {
      if (parts.length >= 3 && parts[0] !== tenantSlug) {
        // Has a subdomain already (could be www, app, or another tenant) — replace it
        host = `${tenantSlug}.${parts.slice(1).join('.')}`;
      } else if (parts.length === 2) {
        // Apex (t1agentics.ai) — prefix with tenant slug
        host = `${tenantSlug}.${hostname}`;
      } else if (parts.length === 1) {
        // localhost or single-label — prefix
        host = `${tenantSlug}.${hostname}`;
      }
    }
    const portSuffix = port && port !== '80' && port !== '443' ? `:${port}` : '';
    return `${protocol}//${host}${portSuffix}/v1/lists/${slug}`;
  };

  const copyDeliveryUrl = async (slug) => {
    const url = buildDeliveryUrl(slug);
    await copyToClipboard(url);
    toast.success(`Copied: ${url}`);
  };

  // ============================================================================
  // FILTERING & SORTING
  // ============================================================================

  const filteredLists = lists
    .filter(l => {
      if (searchTerm && !l.name.toLowerCase().includes(searchTerm.toLowerCase()) &&
          !l.slug.toLowerCase().includes(searchTerm.toLowerCase())) return false;
      if (typeFilter && l.ioc_type !== typeFilter) return false;
      return true;
    })
    .sort((a, b) => {
      const dir = sortConfig.direction === 'asc' ? 1 : -1;
      if (sortConfig.key === 'name') return dir * a.name.localeCompare(b.name);
      if (sortConfig.key === 'item_count') return dir * ((a.item_count || 0) - (b.item_count || 0));
      if (sortConfig.key === 'ioc_type') return dir * a.ioc_type.localeCompare(b.ioc_type);
      if (sortConfig.key === 'created_at') return dir * (new Date(a.created_at) - new Date(b.created_at));
      return 0;
    });

  const totalPages = Math.ceil(filteredLists.length / rowsPerPage);
  const paginatedLists = filteredLists.slice(
    (currentPage - 1) * rowsPerPage,
    currentPage * rowsPerPage
  );

  const handleSort = (key) => {
    setSortConfig(prev => ({
      key,
      direction: prev.key === key && prev.direction === 'asc' ? 'desc' : 'asc',
    }));
  };

  const sortArrow = (key) => {
    if (sortConfig.key !== key) return '';
    return sortConfig.direction === 'asc' ? ' \u2191' : ' \u2193';
  };

  // ============================================================================
  // STATS
  // ============================================================================

  const totalItems = lists.reduce((sum, l) => sum + (l.item_count || 0), 0);
  const enabledCount = lists.filter(l => l.enabled).length;
  const typeCounts = { ip: 0, domain: 0, url: 0 };
  lists.forEach(l => { typeCounts[l.ioc_type] = (typeCounts[l.ioc_type] || 0) + 1; });

  // ============================================================================
  // TYPE BADGE
  // ============================================================================

  const typeColors = { ip: '#3b82f6', domain: '#8b5cf6', url: '#f97316' };

  const TypeBadge = ({ type }) => (
    <span style={{
      display: 'inline-block',
      padding: '0.15rem 0.5rem',
      borderRadius: '4px',
      fontSize: '0.7rem',
      fontWeight: '600',
      textTransform: 'uppercase',
      background: `${typeColors[type] || '#64748b'}20`,
      color: typeColors[type] || '#64748b',
      border: `1px solid ${typeColors[type] || '#64748b'}40`,
    }}>
      {type}
    </span>
  );

  // ============================================================================
  // RENDER
  // ============================================================================

  if (loading) {
    return (
      <div className="threat-intel-shell">
        <div className="ti-shell">
          <div style={{ display: 'flex', justifyContent: 'center', padding: '4rem' }}>
            <div className="spinner" />
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="threat-intel-shell">
      <div className="ti-shell">
        {/* Header */}
        <header className="ti-topbar">
          <div className="ti-title-group">
            <span className="ti-badge">Threat Intel</span>
            <div>
              <div className="ti-title">EDL Management</div>
              <div className="ti-subtitle">External Dynamic Lists for firewall consumption</div>
            </div>
          </div>
          <div className="ti-topbar-actions">
            <span className="ti-pill">Lists: {lists.length}</span>
            <span className="ti-pill">IOCs: {totalItems.toLocaleString()}</span>
          </div>
        </header>

        <div className="ti-panel">
          <div style={{ padding: '0' }}>
            {/* Tab Navigation */}
            <ThreatIntelTabs
              active="edl"
              onNavigate={(item) => navigate(item.path)}
              items={[
                { id: 'database', label: 'IOC Database', path: '/threat-intel/database' },
                { id: 'lookup', label: 'Lookup & Enrich', path: '/threat-intel/lookup' },
                { id: 'submit', label: 'Submit IOCs', path: '/threat-intel/submit' },
                { id: 'whitelist', label: 'Whitelist', path: '/threat-intel/whitelist' },
                { id: 'feeds', label: 'Threat Feeds', path: '/threat-intel/feeds' },
                { id: 'edl', label: 'EDL Lists', path: '/threat-intel/edl' },
              ]}
            />

            {/* Stats Row */}
            <div style={{ display: 'flex', gap: '0.75rem', marginBottom: '0.75rem' }}>
              <StatCard value={lists.length} label="Lists" color="#3b82f6" />
              <StatCard value={enabledCount} label="Enabled" color="#22c55e" />
              <StatCard value={totalItems.toLocaleString()} label="Total IOCs" color="#3CB371" />
              <StatCard value={typeCounts.ip} label="IP Lists" color={typeColors.ip} />
              <StatCard value={typeCounts.domain} label="Domain Lists" color={typeColors.domain} />
              <StatCard value={typeCounts.url} label="URL Lists" color={typeColors.url} />
            </div>

            {/* Action Bar */}
            <div style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              marginBottom: '0.75rem',
            }}>
              <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
                {/* Search */}
                <input
                  type="text"
                  placeholder="Search lists..."
                  value={searchTerm}
                  onChange={(e) => { setSearchTerm(e.target.value); setCurrentPage(1); }}
                  style={{
                    padding: '0.5rem 0.75rem',
                    background: 'var(--bg-primary)',
                    border: '1px solid var(--bg-tertiary)',
                    borderRadius: '6px',
                    color: 'var(--text-primary)',
                    fontSize: '0.8rem',
                    width: '220px',
                  }}
                />
                {/* Type Filter */}
                <select
                  value={typeFilter || ''}
                  onChange={(e) => { setTypeFilter(e.target.value || null); setCurrentPage(1); }}
                  style={{
                    padding: '0.5rem',
                    background: 'var(--bg-primary)',
                    border: '1px solid var(--bg-tertiary)',
                    borderRadius: '6px',
                    color: 'var(--text-primary)',
                    fontSize: '0.8rem',
                  }}
                >
                  <option value="">All Types</option>
                  <option value="ip">IP</option>
                  <option value="domain">Domain</option>
                  <option value="url">URL</option>
                </select>
              </div>
              <button
                onClick={() => setShowCreateModal(true)}
                style={{
                  padding: '0.5rem 1rem',
                  background: 'linear-gradient(135deg, #3CB371 0%, #2e8b57 100%)',
                  border: 'none',
                  borderRadius: '6px',
                  color: 'white',
                  fontWeight: '600',
                  cursor: 'pointer',
                  fontSize: '0.8rem',
                  boxShadow: '0 2px 8px rgba(60, 179, 113, 0.3)',
                }}
              >
                + Create EDL List
              </button>
            </div>

            {/* Error */}
            {error && (
              <div style={{
                padding: '0.75rem',
                background: 'rgba(239, 68, 68, 0.1)',
                border: '1px solid rgba(239, 68, 68, 0.3)',
                borderRadius: '6px',
                color: '#ef4444',
                fontSize: '0.8rem',
                marginBottom: '0.75rem',
              }}>
                {error}
              </div>
            )}

            {/* Table */}
            <div style={{
              borderRadius: '10px',
              overflow: 'hidden',
              border: '1px solid var(--bg-tertiary)',
            }}>
              <table className="ti-table" style={{ width: '100%', borderCollapse: 'collapse' }}>
                <thead>
                  <tr style={{ background: 'var(--bg-primary)' }}>
                    <th style={thStyle} onClick={() => handleSort('enabled')}>Status{sortArrow('enabled')}</th>
                    <th style={thStyle} onClick={() => handleSort('name')}>Name{sortArrow('name')}</th>
                    <th style={thStyle} onClick={() => handleSort('ioc_type')}>Type{sortArrow('ioc_type')}</th>
                    <th style={thStyle}>Slug / Delivery URL</th>
                    <th style={thStyle} onClick={() => handleSort('item_count')}>Items{sortArrow('item_count')}</th>
                    <th style={thStyle}>Last Generated</th>
                    <th style={thStyle}>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {paginatedLists.length === 0 && (
                    <tr>
                      <td colSpan="7" style={{ textAlign: 'center', padding: '2rem', color: 'var(--text-muted)', fontSize: '0.85rem' }}>
                        {lists.length === 0 ? 'No EDL lists yet. Create one to get started.' : 'No lists match your filters.'}
                      </td>
                    </tr>
                  )}
                  {paginatedLists.map((edl) => (
                    <tr key={edl.list_id} style={{ borderBottom: '1px solid var(--bg-tertiary)' }}>
                      {/* Status Toggle */}
                      <td style={tdStyle}>
                        <label style={{ position: 'relative', display: 'inline-block', width: '36px', height: '20px' }}>
                          <input
                            type="checkbox"
                            checked={edl.enabled}
                            onChange={(e) => toggleList(edl.list_id, e.target.checked)}
                            style={{ opacity: 0, width: 0, height: 0 }}
                          />
                          <span style={{
                            position: 'absolute',
                            cursor: 'pointer',
                            top: 0, left: 0, right: 0, bottom: 0,
                            background: edl.enabled ? '#3CB371' : 'var(--bg-tertiary)',
                            borderRadius: '10px',
                            transition: '0.2s',
                          }}>
                            <span style={{
                              position: 'absolute',
                              height: '16px', width: '16px',
                              left: edl.enabled ? '18px' : '2px',
                              bottom: '2px',
                              background: 'white',
                              borderRadius: '50%',
                              transition: '0.2s',
                            }} />
                          </span>
                        </label>
                      </td>

                      {/* Name */}
                      <td style={tdStyle}>
                        <div
                          onClick={() => setShowItemsPanel(edl)}
                          style={{ fontWeight: '600', fontSize: '0.8rem', color: '#3CB371', cursor: 'pointer' }}
                          title="Click to view & manage items"
                        >
                          {edl.name}
                        </div>
                        {edl.description && (
                          <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: '2px' }}>
                            {edl.description}
                          </div>
                        )}
                      </td>

                      {/* Type */}
                      <td style={tdStyle}>
                        <TypeBadge type={edl.ioc_type} />
                      </td>

                      {/* Slug / URL */}
                      <td style={tdStyle}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                          <code style={{
                            fontSize: '0.7rem',
                            background: 'var(--bg-primary)',
                            padding: '0.2rem 0.4rem',
                            borderRadius: '4px',
                            color: 'var(--text-secondary)',
                          }} title={tenantSlug ? buildDeliveryUrl(edl.slug) : 'Loading tenant info…'}>
                            {tenantSlug ? `${tenantSlug}.t1agentics.ai/v1/lists/${edl.slug}` : `/v1/lists/${edl.slug}`}
                          </code>
                          <button
                            onClick={() => copyDeliveryUrl(edl.slug)}
                            title="Copy delivery URL"
                            style={{
                              background: 'none',
                              border: 'none',
                              cursor: 'pointer',
                              color: 'var(--text-muted)',
                              fontSize: '0.75rem',
                              padding: '2px',
                            }}
                          >
                            Copy
                          </button>
                        </div>
                      </td>

                      {/* Items */}
                      <td style={tdStyle}>
                        <span style={{ fontSize: '0.85rem', fontWeight: '600', color: 'var(--text-primary)' }}>
                          {(edl.item_count || 0).toLocaleString()}
                        </span>
                      </td>

                      {/* Last Generated */}
                      <td style={tdStyle}>
                        <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>
                          {edl.last_generated_at
                            ? new Date(edl.last_generated_at).toLocaleString()
                            : 'Never'}
                        </span>
                      </td>

                      {/* Actions */}
                      <td style={tdStyle}>
                        <div style={{ display: 'flex', gap: '0.3rem' }}>
                          <ActionBtn label="Items" onClick={() => setShowItemsPanel(edl)} />
                          <ActionBtn label="Keys" onClick={() => setShowCredsPanel(edl)} />
                          <ActionBtn label="Log" onClick={() => setShowAccessLog(edl)} />
                          <ActionBtn label="Regen" onClick={() => regenerateList(edl.list_id)} color="#3b82f6" />
                          <ActionBtn label="Del" onClick={() => deleteList(edl.list_id)} color="#ef4444" />
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* Pagination */}
            {totalPages > 1 && (
              <div style={{
                display: 'flex',
                justifyContent: 'center',
                alignItems: 'center',
                gap: '0.5rem',
                padding: '0.75rem',
                fontSize: '0.8rem',
                color: 'var(--text-secondary)',
              }}>
                <button
                  onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
                  disabled={currentPage === 1}
                  style={pageBtnStyle}
                >
                  Prev
                </button>
                <span>Page {currentPage} of {totalPages}</span>
                <button
                  onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))}
                  disabled={currentPage === totalPages}
                  style={pageBtnStyle}
                >
                  Next
                </button>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* MODALS */}
      {showCreateModal && (
        <CreateListModal
          onClose={() => setShowCreateModal(false)}
          onCreated={() => { setShowCreateModal(false); fetchLists(); }}
        />
      )}
      {showItemsPanel && (
        <ItemsPanel
          edl={showItemsPanel}
          onClose={() => setShowItemsPanel(null)}
          onChanged={fetchLists}
        />
      )}
      {showCredsPanel && (
        <CredentialsPanel
          edl={showCredsPanel}
          onClose={() => setShowCredsPanel(null)}
        />
      )}
      {showAccessLog && (
        <AccessLogPanel
          edl={showAccessLog}
          onClose={() => setShowAccessLog(null)}
        />
      )}
    </div>
  );
}


// ============================================================================
// SHARED STYLES
// ============================================================================

const thStyle = {
  padding: '0.6rem 0.75rem',
  textAlign: 'left',
  fontSize: '0.7rem',
  fontWeight: '600',
  color: 'var(--text-muted)',
  textTransform: 'uppercase',
  letterSpacing: '0.5px',
  cursor: 'pointer',
  userSelect: 'none',
};

const tdStyle = {
  padding: '0.5rem 0.75rem',
  fontSize: '0.8rem',
  color: 'var(--text-secondary)',
};

const pageBtnStyle = {
  padding: '0.3rem 0.6rem',
  background: 'var(--bg-primary)',
  border: '1px solid var(--bg-tertiary)',
  borderRadius: '4px',
  color: 'var(--text-secondary)',
  cursor: 'pointer',
  fontSize: '0.75rem',
};

const modalOverlay = {
  position: 'fixed',
  top: 0, left: 0, right: 0, bottom: 0,
  background: 'rgba(0,0,0,0.7)',
  display: 'flex',
  justifyContent: 'center',
  alignItems: 'flex-start',
  paddingTop: '6vh',
  zIndex: 1000,
};

const modalBox = {
  background: 'var(--bg-primary)',
  border: '1px solid var(--bg-tertiary)',
  borderRadius: '10px',
  width: '520px',
  maxHeight: '80vh',
  overflow: 'auto',
  boxShadow: '0 8px 40px rgba(0,0,0,0.5)',
};

const modalHeader = {
  display: 'flex',
  justifyContent: 'space-between',
  alignItems: 'center',
  padding: '1rem 1.25rem',
  borderBottom: '1px solid var(--bg-tertiary)',
};

const modalBody = { padding: '1.25rem' };

const labelStyle = {
  display: 'block',
  fontSize: '0.75rem',
  fontWeight: '600',
  color: 'var(--text-secondary)',
  marginBottom: '0.3rem',
  marginTop: '0.75rem',
};

const inputStyle = {
  width: '100%',
  padding: '0.5rem 0.6rem',
  background: 'var(--bg-secondary)',
  border: '1px solid var(--bg-tertiary)',
  borderRadius: '6px',
  color: 'var(--text-primary)',
  fontSize: '0.8rem',
  boxSizing: 'border-box',
};

const selectStyle = { ...inputStyle };

const submitBtnStyle = {
  width: '100%',
  marginTop: '1rem',
  padding: '0.6rem',
  background: 'linear-gradient(135deg, #3CB371 0%, #2e8b57 100%)',
  border: 'none',
  borderRadius: '6px',
  color: 'white',
  fontWeight: '600',
  cursor: 'pointer',
  fontSize: '0.85rem',
};


// ============================================================================
// SMALL COMPONENTS
// ============================================================================

function StatCard({ value, label, color }) {
  return (
    <div style={{
      background: `${color}14`,
      border: `1px solid ${color}33`,
      borderRadius: '6px',
      padding: '0.5rem 0.75rem',
      display: 'flex',
      alignItems: 'center',
      gap: '0.5rem',
    }}>
      <span style={{ fontSize: '1.1rem', fontWeight: '700', color }}>{value}</span>
      <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>{label}</span>
    </div>
  );
}

function ActionBtn({ label, onClick, color = 'var(--text-muted)' }) {
  return (
    <button
      onClick={onClick}
      style={{
        padding: '0.25rem 0.5rem',
        background: 'transparent',
        border: `1px solid ${color}40`,
        borderRadius: '4px',
        color,
        fontSize: '0.7rem',
        cursor: 'pointer',
        fontWeight: '500',
      }}
    >
      {label}
    </button>
  );
}


// ============================================================================
// CREATE LIST MODAL
// ============================================================================

function CreateListModal({ onClose, onCreated }) {
  const toast = useToast();
  const [form, setForm] = useState({
    name: '',
    slug: '',
    ioc_type: 'ip',
    list_type: 'static',
    description: '',
    max_items: 150000,
    ttl_default_seconds: 0,
    include_comments: true,
    tags: '',
  });
  const [authConfig, setAuthConfig] = useState({
    enabled: false,
    auth_type: 'token',
    cred_name: '',
    basic_username: '',
    basic_password: '',
    ip_allowlist: '',
  });
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState(null);
  const [createdToken, setCreatedToken] = useState(null);

  const autoSlug = (name) => name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');

  const handleSubmit = async (e) => {
    e.preventDefault();
    setSaving(true);
    setError(null);
    try {
      const payload = { ...form };
      // Convert comma-separated tags string to array
      if (payload.tags && typeof payload.tags === 'string') {
        payload.tags = payload.tags.split(',').map(t => t.trim()).filter(Boolean);
      } else {
        delete payload.tags;
      }
      const response = await fetch(`${API_BASE_URL}/api/v1/edl/lists`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify(payload),
      });
      if (!response.ok) {
        const data = await response.json();
        throw new Error(data.detail || `HTTP ${response.status}`);
      }
      const listData = await response.json();
      const newListId = listData.list_id || listData.list?.list_id;

      // If auth is configured, create the credential as a follow-up call
      if (authConfig.enabled && authConfig.auth_type !== 'none' && newListId) {
        try {
          const credBody = {
            name: authConfig.cred_name || `${form.name} - ${authConfig.auth_type}`,
            auth_type: authConfig.auth_type,
          };
          if (authConfig.auth_type === 'basic') {
            credBody.basic_username = authConfig.basic_username;
            credBody.basic_password = authConfig.basic_password;
          }
          if (authConfig.auth_type === 'ip_allowlist') {
            credBody.ip_allowlist = authConfig.ip_allowlist
              .split('\n')
              .map(s => s.trim())
              .filter(Boolean);
          }

          const credResponse = await fetch(
            `${API_BASE_URL}/api/v1/edl/lists/${newListId}/credentials`,
            {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              credentials: 'include',
              body: JSON.stringify(credBody),
            }
          );
          const credData = await credResponse.json();
          // If a token was generated, show it to the user before closing
          if (credData.credential?.token) {
            setCreatedToken(credData.credential.token);
            setSaving(false);
            return; // Don't close yet -- let user copy the token
          }
        } catch (credErr) {
          // List was created but credential failed -- warn but don't block
          toast.warning(`List created, but credential setup failed: ${credErr.message}. You can add credentials from the Keys panel.`);
        }
      }

      onCreated();
    } catch (err) {
      setError(err.message);
      setSaving(false);
    }
  };

  // If a token was just created, show the token display instead of the form
  if (createdToken) {
    return (
      <div style={modalOverlay} onClick={() => {}}>
        <div style={{ ...modalBox, width: '560px' }} onClick={e => e.stopPropagation()}>
          <div style={modalHeader}>
            <span style={{ fontSize: '1rem', fontWeight: '600', color: 'var(--text-primary)' }}>List Created - Save Your Token</span>
          </div>
          <div style={modalBody}>
            <div style={{
              padding: '0.75rem',
              background: 'rgba(59, 130, 246, 0.1)',
              border: '1px solid rgba(59, 130, 246, 0.3)',
              borderRadius: '6px',
              marginBottom: '0.75rem',
            }}>
              <div style={{ fontWeight: '600', fontSize: '0.8rem', color: '#3b82f6', marginBottom: '0.3rem' }}>
                Bearer token generated -- copy it now (shown only once)
              </div>
              <code style={{
                display: 'block',
                padding: '0.5rem',
                background: 'var(--bg-primary)',
                borderRadius: '4px',
                fontSize: '0.75rem',
                color: 'var(--text-primary)',
                wordBreak: 'break-all',
              }}>
                {createdToken}
              </code>
              <div style={{ display: 'flex', gap: '0.5rem', marginTop: '0.75rem' }}>
                <button
                  onClick={() => copyToClipboard(createdToken)}
                  style={{ ...pageBtnStyle, color: '#3b82f6', borderColor: '#3b82f640' }}
                >
                  Copy Token
                </button>
                <button
                  onClick={() => { setCreatedToken(null); onCreated(); }}
                  style={submitBtnStyle}
                >
                  Done
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div style={modalOverlay} onClick={onClose}>
      <div style={{ ...modalBox, width: '560px' }} onClick={e => e.stopPropagation()}>
        <div style={modalHeader}>
          <span style={{ fontSize: '1rem', fontWeight: '600', color: 'var(--text-primary)' }}>Create EDL List</span>
          <button onClick={onClose} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', fontSize: '1.2rem', cursor: 'pointer' }}>x</button>
        </div>
        <div style={modalBody}>
          <form onSubmit={handleSubmit}>
            <label style={labelStyle}>Name</label>
            <input
              style={inputStyle}
              value={form.name}
              onChange={(e) => setForm({ ...form, name: e.target.value, slug: autoSlug(e.target.value) })}
              placeholder="Malicious IPs - High Confidence"
              required
            />

            <label style={labelStyle}>Slug (URL identifier)</label>
            <input
              style={inputStyle}
              value={form.slug}
              onChange={(e) => setForm({ ...form, slug: e.target.value })}
              placeholder="malicious-ips-high"
              pattern="^[a-z0-9][a-z0-9\-]*[a-z0-9]$"
              required
            />
            <div style={{ fontSize: '0.65rem', color: 'var(--text-muted)', marginTop: '0.2rem' }}>
              Delivery URL path: /v1/lists/{form.slug || '...'}
            </div>

            <label style={labelStyle}>IOC Type</label>
            <select
              style={selectStyle}
              value={form.ioc_type}
              onChange={(e) => setForm({ ...form, ioc_type: e.target.value })}
            >
              <option value="ip">IP Address</option>
              <option value="domain">Domain</option>
              <option value="url">URL</option>
            </select>
            <div style={{ fontSize: '0.65rem', color: 'var(--text-muted)', marginTop: '0.2rem' }}>
              Type is locked after creation. Only matching IOCs can be added.
            </div>

            <label style={labelStyle}>Description</label>
            <textarea
              style={{ ...inputStyle, minHeight: '60px', resize: 'vertical' }}
              value={form.description}
              onChange={(e) => setForm({ ...form, description: e.target.value })}
              placeholder="High-confidence malicious IPs from threat feeds and investigations"
            />

            <label style={labelStyle}>Tags</label>
            <input
              style={inputStyle}
              value={form.tags}
              onChange={(e) => setForm({ ...form, tags: e.target.value })}
              placeholder="e.g. ransomware, c2, firewall-block (comma-separated)"
            />
            <div style={{ fontSize: '0.65rem', color: 'var(--text-muted)', marginTop: '0.2rem' }}>
              Categorize this list with tags for filtering and organization.
            </div>

            <div style={{ display: 'flex', gap: '0.75rem', marginTop: '0.5rem' }}>
              <div style={{ flex: 1 }}>
                <label style={labelStyle}>Max Items</label>
                <input
                  style={inputStyle}
                  type="number"
                  value={form.max_items}
                  onChange={(e) => setForm({ ...form, max_items: parseInt(e.target.value) || 150000 })}
                  min="1"
                  max="1000000"
                />
              </div>
              <div style={{ flex: 1 }}>
                <label style={labelStyle}>Default TTL (seconds)</label>
                <input
                  style={inputStyle}
                  type="number"
                  value={form.ttl_default_seconds}
                  onChange={(e) => setForm({ ...form, ttl_default_seconds: parseInt(e.target.value) || 0 })}
                  min="0"
                />
                <div style={{ fontSize: '0.65rem', color: 'var(--text-muted)', marginTop: '0.2rem' }}>
                  0 = no expiration
                </div>
              </div>
            </div>

            {/* Authentication Setup Section */}
            <div style={{
              marginTop: '1rem',
              padding: '0.75rem',
              background: 'var(--bg-secondary)',
              borderRadius: '6px',
              border: '1px solid var(--bg-tertiary)',
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.25rem' }}>
                <label style={{ position: 'relative', display: 'inline-block', width: '36px', height: '20px', flexShrink: 0 }}>
                  <input
                    type="checkbox"
                    checked={authConfig.enabled}
                    onChange={(e) => setAuthConfig({ ...authConfig, enabled: e.target.checked })}
                    style={{ opacity: 0, width: 0, height: 0 }}
                  />
                  <span style={{
                    position: 'absolute',
                    cursor: 'pointer',
                    top: 0, left: 0, right: 0, bottom: 0,
                    background: authConfig.enabled ? '#3CB371' : 'var(--bg-tertiary)',
                    borderRadius: '10px',
                    transition: '0.2s',
                  }}>
                    <span style={{
                      position: 'absolute',
                      height: '16px', width: '16px',
                      left: authConfig.enabled ? '18px' : '2px',
                      bottom: '2px',
                      background: 'white',
                      borderRadius: '50%',
                      transition: '0.2s',
                    }} />
                  </span>
                </label>
                <span style={{ fontSize: '0.8rem', fontWeight: '600', color: 'var(--text-primary)' }}>
                  Set Up Authentication
                </span>
              </div>
              <div style={{ fontSize: '0.65rem', color: 'var(--text-muted)', marginBottom: authConfig.enabled ? '0.5rem' : 0 }}>
                {authConfig.enabled
                  ? 'Configure access credentials for this list.'
                  : 'List will be publicly accessible. You can add credentials later from the Keys panel.'}
              </div>

              {authConfig.enabled && (
                <>
                  <label style={labelStyle}>Auth Type</label>
                  <select
                    style={selectStyle}
                    value={authConfig.auth_type}
                    onChange={(e) => setAuthConfig({ ...authConfig, auth_type: e.target.value })}
                  >
                    <option value="token">Bearer Token (auto-generated)</option>
                    <option value="basic">Basic Auth (username + password)</option>
                    <option value="ip_allowlist">IP Allowlist</option>
                    <option value="none">Public (no auth)</option>
                  </select>

                  {authConfig.auth_type !== 'none' && (
                    <>
                      <label style={labelStyle}>Credential Name</label>
                      <input
                        style={inputStyle}
                        value={authConfig.cred_name}
                        onChange={(e) => setAuthConfig({ ...authConfig, cred_name: e.target.value })}
                        placeholder="e.g. Production Firewall"
                      />
                      <div style={{ fontSize: '0.65rem', color: 'var(--text-muted)', marginTop: '0.2rem' }}>
                        Optional. Defaults to list name + auth type.
                      </div>
                    </>
                  )}

                  {authConfig.auth_type === 'token' && (
                    <div style={{
                      marginTop: '0.5rem',
                      padding: '0.5rem',
                      background: 'rgba(59, 130, 246, 0.08)',
                      border: '1px solid rgba(59, 130, 246, 0.2)',
                      borderRadius: '4px',
                      fontSize: '0.7rem',
                      color: '#3b82f6',
                    }}>
                      A bearer token will be auto-generated on creation. You will be shown the token once -- make sure to copy it.
                    </div>
                  )}

                  {authConfig.auth_type === 'basic' && (
                    <div style={{ display: 'flex', gap: '0.5rem' }}>
                      <div style={{ flex: 1 }}>
                        <label style={labelStyle}>Username</label>
                        <input
                          style={inputStyle}
                          value={authConfig.basic_username}
                          onChange={(e) => setAuthConfig({ ...authConfig, basic_username: e.target.value })}
                          placeholder="firewall-user"
                        />
                      </div>
                      <div style={{ flex: 1 }}>
                        <label style={labelStyle}>Password</label>
                        <input
                          style={inputStyle}
                          type="password"
                          value={authConfig.basic_password}
                          onChange={(e) => setAuthConfig({ ...authConfig, basic_password: e.target.value })}
                          placeholder="secure-password"
                        />
                      </div>
                    </div>
                  )}

                  {authConfig.auth_type === 'ip_allowlist' && (
                    <>
                      <label style={labelStyle}>Allowed IPs / CIDRs (one per line)</label>
                      <textarea
                        style={{ ...inputStyle, minHeight: '60px' }}
                        value={authConfig.ip_allowlist}
                        onChange={(e) => setAuthConfig({ ...authConfig, ip_allowlist: e.target.value })}
                        placeholder={'10.0.0.0/24\n192.168.1.100\n172.16.0.0/16'}
                      />
                    </>
                  )}
                </>
              )}
            </div>

            {error && (
              <div style={{ color: '#ef4444', fontSize: '0.8rem', marginTop: '0.75rem' }}>{error}</div>
            )}

            <button type="submit" disabled={saving} style={submitBtnStyle}>
              {saving ? 'Creating...' : 'Create List'}
            </button>
          </form>
        </div>
      </div>
    </div>
  );
}


// ============================================================================
// ITEMS PANEL (Slide-over)
// ============================================================================

function ItemsPanel({ edl, onClose, onChanged }) {
  const toast = useToast();
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);
  const [showAdd, setShowAdd] = useState(false);
  const [addValues, setAddValues] = useState('');
  const [addComment, setAddComment] = useState('');
  const [addClassification, setAddClassification] = useState('blacklist');
  const [addConfidence, setAddConfidence] = useState('high');
  const [addSource, setAddSource] = useState('');
  const [addTags, setAddTags] = useState('');
  const [adding, setAdding] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const [searchDebounce, setSearchDebounce] = useState('');

  const fetchItems = async () => {
    try {
      const params = new URLSearchParams({ page, limit: 50 });
      if (searchDebounce) params.set('search', searchDebounce);
      const response = await fetch(
        `${API_BASE_URL}/api/v1/edl/lists/${edl.list_id}/items?${params}`,
        { headers: { 'Content-Type': 'application/json' }, credentials: 'include' }
      );
      const data = await response.json();
      setItems(data.items || []);
      setTotal(data.total || 0);
      setLoading(false);
    } catch (err) {
      setLoading(false);
    }
  };

  useEffect(() => { fetchItems(); }, [page, searchDebounce]);

  // Debounce search input
  useEffect(() => {
    const timer = setTimeout(() => {
      setSearchDebounce(searchTerm);
      setPage(1);
    }, 300);
    return () => clearTimeout(timer);
  }, [searchTerm]);

  const addItems = async () => {
    setAdding(true);
    try {
      const tagsList = addTags.trim()
        ? addTags.split(',').map(t => t.trim()).filter(Boolean)
        : [];
      await fetch(`${API_BASE_URL}/api/v1/edl/lists/${edl.list_id}/items/bulk`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({
          values: addValues,
          comment: addComment,
          source_type: addSource.trim() || 'manual',
          classification: addClassification,
          confidence: addConfidence,
          tags: tagsList,
        }),
      });
      setAddValues('');
      setAddComment('');
      setAddClassification('blacklist');
      setAddConfidence('high');
      setAddSource('');
      setAddTags('');
      setShowAdd(false);
      fetchItems();
      if (onChanged) onChanged();
    } catch (err) {
      toast.error(`Failed: ${err.message}`);
    }
    setAdding(false);
  };

  const removeItem = async (iocValue) => {
    if (!window.confirm(`Remove ${iocValue} from list?`)) return;
    try {
      await fetch(`${API_BASE_URL}/api/v1/edl/lists/${edl.list_id}/items`, {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ ioc_value: iocValue }),
      });
      fetchItems();
      if (onChanged) onChanged();
    } catch (err) {
      toast.error(`Failed: ${err.message}`);
    }
  };

  return (
    <div style={modalOverlay} onClick={onClose}>
      <div style={{ ...modalBox, width: '860px' }} onClick={e => e.stopPropagation()}>
        <div style={modalHeader}>
          <div>
            <span style={{ fontSize: '1rem', fontWeight: '600', color: 'var(--text-primary)' }}>
              {edl.name} - Items
            </span>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginLeft: '0.5rem' }}>
              ({total} total)
            </span>
          </div>
          <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
            <button onClick={() => setShowAdd(!showAdd)} style={{ ...pageBtnStyle, color: '#3CB371', borderColor: '#3CB37140' }}>
              + Add IOCs
            </button>
            <button onClick={onClose} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', fontSize: '1.2rem', cursor: 'pointer' }}>x</button>
          </div>
        </div>
        <div style={modalBody}>
          {/* Search */}
          <div style={{ marginBottom: '0.75rem' }}>
            <input
              type="text"
              placeholder="Search IOCs..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              style={{
                ...inputStyle,
                width: '100%',
              }}
            />
          </div>

          {/* Add IOCs form */}
          {showAdd && (
            <div style={{
              padding: '0.75rem',
              background: 'var(--bg-secondary)',
              borderRadius: '6px',
              marginBottom: '0.75rem',
              border: '1px solid var(--bg-tertiary)',
            }}>
              {/* CSV Upload */}
              <label style={labelStyle}>Upload CSV File</label>
              <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center', marginBottom: '0.5rem' }}>
                <input
                  type="file"
                  accept=".csv,.txt"
                  onChange={(e) => {
                    const file = e.target.files?.[0];
                    if (!file) return;
                    const reader = new FileReader();
                    reader.onload = (ev) => {
                      const text = ev.target.result;
                      // Parse CSV: extract first column (IOC value) from each row
                      const lines = text.split('\n');
                      const values = [];
                      for (const line of lines) {
                        const trimmed = line.trim();
                        if (!trimmed || trimmed.startsWith('#')) continue;
                        // Check if it's CSV with commas inside a structured row
                        const cols = trimmed.split(',');
                        const candidate = cols[0].trim().replace(/^["']|["']$/g, '');
                        // Skip header rows
                        if (candidate.toLowerCase() === 'ip' || candidate.toLowerCase() === 'ioc' ||
                            candidate.toLowerCase() === 'indicator' || candidate.toLowerCase() === 'value' ||
                            candidate.toLowerCase() === 'domain' || candidate.toLowerCase() === 'url' ||
                            candidate.toLowerCase() === 'address') continue;
                        if (candidate) values.push(candidate);
                      }
                      setAddValues(prev => prev ? prev + '\n' + values.join('\n') : values.join('\n'));
                    };
                    reader.readAsText(file);
                    e.target.value = '';
                  }}
                  style={{
                    fontSize: '0.75rem',
                    color: 'var(--text-secondary)',
                  }}
                />
                <span style={{ fontSize: '0.65rem', color: 'var(--text-muted)' }}>
                  First column is used as the IOC value
                </span>
              </div>

              <label style={labelStyle}>IOC Values (one per line, or comma-separated)</label>
              <textarea
                style={{ ...inputStyle, minHeight: '80px' }}
                value={addValues}
                onChange={(e) => setAddValues(e.target.value)}
                placeholder={edl.ioc_type === 'ip' ? '192.168.1.1\n10.0.0.0/24\n203.0.113.42' :
                             edl.ioc_type === 'domain' ? 'evil.com\nmalware.xyz\nbad-domain.net' :
                             'https://evil.com/payload\nhttp://malware.xyz/c2'}
              />
              <label style={labelStyle}>Comment</label>
              <input
                style={inputStyle}
                value={addComment}
                onChange={(e) => setAddComment(e.target.value)}
                placeholder="Reason for adding"
              />

              {/* Classification & Confidence row */}
              <div style={{ display: 'flex', gap: '0.75rem' }}>
                <div style={{ flex: 1 }}>
                  <label style={labelStyle}>Classification</label>
                  <select
                    style={selectStyle}
                    value={addClassification}
                    onChange={(e) => setAddClassification(e.target.value)}
                  >
                    <option value="blacklist">Blacklist</option>
                    <option value="whitelist">Whitelist</option>
                    <option value="suspicious">Suspicious</option>
                  </select>
                </div>
                <div style={{ flex: 1 }}>
                  <label style={labelStyle}>Confidence</label>
                  <select
                    style={selectStyle}
                    value={addConfidence}
                    onChange={(e) => setAddConfidence(e.target.value)}
                  >
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                  </select>
                </div>
              </div>

              <label style={labelStyle}>Source</label>
              <input
                style={inputStyle}
                value={addSource}
                onChange={(e) => setAddSource(e.target.value)}
                placeholder="e.g. AlienVault OTX, Investigation #1042, manual entry"
              />
              <div style={{ fontSize: '0.65rem', color: 'var(--text-muted)', marginTop: '0.2rem' }}>
                Where this IOC came from. Leave blank for "manual".
              </div>

              <label style={labelStyle}>Tags</label>
              <input
                style={inputStyle}
                value={addTags}
                onChange={(e) => setAddTags(e.target.value)}
                placeholder="e.g. ransomware, c2, phishing (comma-separated)"
              />
              <div style={{ fontSize: '0.65rem', color: 'var(--text-muted)', marginTop: '0.2rem' }}>
                Comma-separated list of tags to apply to all added IOCs.
              </div>

              <button onClick={addItems} disabled={adding || !addValues.trim()} style={{ ...submitBtnStyle, marginTop: '0.5rem' }}>
                {adding ? 'Adding...' : 'Add to List'}
              </button>
            </div>
          )}

          {/* Items table */}
          {loading ? (
            <div style={{ textAlign: 'center', padding: '2rem', color: 'var(--text-muted)' }}>Loading...</div>
          ) : items.length === 0 ? (
            <div style={{ textAlign: 'center', padding: '2rem', color: 'var(--text-muted)' }}>No items in this list</div>
          ) : (
            <table style={{ width: '100%', borderCollapse: 'collapse' }}>
              <thead>
                <tr>
                  <th style={thStyle}>Value</th>
                  <th style={thStyle}>Classification</th>
                  <th style={thStyle}>Confidence</th>
                  <th style={thStyle}>Source</th>
                  <th style={thStyle}>Added</th>
                  <th style={thStyle}>Expires</th>
                  <th style={thStyle}></th>
                </tr>
              </thead>
              <tbody>
                {items.map((item) => {
                  const classColors = {
                    blacklist: '#ef4444',
                    whitelist: '#22c55e',
                    suspicious: '#f59e0b',
                  };
                  const confColors = {
                    high: '#22c55e',
                    medium: '#f59e0b',
                    low: '#94a3b8',
                  };
                  const cls = item.classification || '';
                  const conf = item.confidence || '';
                  return (
                  <tr key={item.id} style={{ borderBottom: '1px solid var(--bg-tertiary)' }}>
                    <td style={tdStyle}>
                      <code style={{ fontSize: '0.75rem', color: 'var(--text-primary)' }}>{item.ioc_value}</code>
                    </td>
                    <td style={tdStyle}>
                      {cls ? (
                        <span style={{
                          display: 'inline-block',
                          padding: '0.1rem 0.4rem',
                          borderRadius: '4px',
                          fontSize: '0.65rem',
                          fontWeight: '600',
                          textTransform: 'uppercase',
                          background: `${classColors[cls] || '#64748b'}18`,
                          color: classColors[cls] || '#64748b',
                          border: `1px solid ${classColors[cls] || '#64748b'}40`,
                        }}>
                          {cls}
                        </span>
                      ) : (
                        <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>-</span>
                      )}
                    </td>
                    <td style={tdStyle}>
                      {conf ? (
                        <span style={{
                          display: 'inline-block',
                          padding: '0.1rem 0.4rem',
                          borderRadius: '4px',
                          fontSize: '0.65rem',
                          fontWeight: '600',
                          textTransform: 'uppercase',
                          background: `${confColors[conf] || '#64748b'}18`,
                          color: confColors[conf] || '#64748b',
                          border: `1px solid ${confColors[conf] || '#64748b'}40`,
                        }}>
                          {conf}
                        </span>
                      ) : (
                        <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>-</span>
                      )}
                    </td>
                    <td style={tdStyle}>
                      <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>{item.source_type}</span>
                    </td>
                    <td style={tdStyle}>
                      <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>
                        {new Date(item.added_at).toLocaleDateString()}
                      </span>
                    </td>
                    <td style={tdStyle}>
                      <span style={{ fontSize: '0.7rem', color: item.expires_at ? '#f59e0b' : 'var(--text-muted)' }}>
                        {item.expires_at ? new Date(item.expires_at).toLocaleDateString() : 'Never'}
                      </span>
                    </td>
                    <td style={tdStyle}>
                      <button
                        onClick={() => removeItem(item.ioc_value)}
                        style={{ background: 'none', border: 'none', color: '#ef4444', cursor: 'pointer', fontSize: '0.7rem' }}
                      >
                        Remove
                      </button>
                    </td>
                  </tr>
                  );
                })}
              </tbody>
            </table>
          )}

          {/* Pagination */}
          {total > 50 && (
            <div style={{ display: 'flex', justifyContent: 'center', gap: '0.5rem', padding: '0.75rem' }}>
              <button onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page === 1} style={pageBtnStyle}>Prev</button>
              <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>Page {page}</span>
              <button onClick={() => setPage(p => p + 1)} disabled={items.length < 50} style={pageBtnStyle}>Next</button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}


// ============================================================================
// CREDENTIALS PANEL
// ============================================================================

function CredentialsPanel({ edl, onClose }) {
  const toast = useToast();
  const [creds, setCreds] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showCreate, setShowCreate] = useState(false);
  const [newToken, setNewToken] = useState(null);
  const [form, setForm] = useState({
    name: '',
    auth_type: 'token',
    description: '',
    ip_allowlist: '',
    basic_username: '',
    basic_password: '',
  });
  const [creating, setCreating] = useState(false);

  const fetchCreds = async () => {
    try {
      const response = await fetch(
        `${API_BASE_URL}/api/v1/edl/lists/${edl.list_id}/credentials`,
        { headers: { 'Content-Type': 'application/json' }, credentials: 'include' }
      );
      const data = await response.json();
      setCreds(data.credentials || []);
      setLoading(false);
    } catch (err) {
      setLoading(false);
    }
  };

  useEffect(() => { fetchCreds(); }, []);

  const createCred = async () => {
    setCreating(true);
    try {
      const body = {
        name: form.name,
        auth_type: form.auth_type,
        description: form.description || undefined,
      };
      if (form.auth_type === 'ip_allowlist') {
        body.ip_allowlist = form.ip_allowlist.split('\n').map(s => s.trim()).filter(Boolean);
      }
      if (form.auth_type === 'basic') {
        body.basic_username = form.basic_username;
        body.basic_password = form.basic_password;
      }

      const response = await fetch(`${API_BASE_URL}/api/v1/edl/lists/${edl.list_id}/credentials`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify(body),
      });
      const data = await response.json();
      if (data.credential?.token) {
        setNewToken(data.credential.token);
      }
      setShowCreate(false);
      setForm({ name: '', auth_type: 'token', description: '', ip_allowlist: '', basic_username: '', basic_password: '' });
      fetchCreds();
    } catch (err) {
      toast.error(`Failed: ${err.message}`);
    }
    setCreating(false);
  };

  const deleteCred = async (credId) => {
    if (!window.confirm('Delete this credential?')) return;
    try {
      await fetch(`${API_BASE_URL}/api/v1/edl/lists/${edl.list_id}/credentials/${credId}`, {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
      });
      fetchCreds();
    } catch (err) {
      toast.error(`Failed: ${err.message}`);
    }
  };

  const rotateCred = async (credId) => {
    try {
      const response = await fetch(`${API_BASE_URL}/api/v1/edl/lists/${edl.list_id}/credentials/${credId}/rotate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
      });
      const data = await response.json();
      if (data.credential?.token) {
        setNewToken(data.credential.token);
      }
      fetchCreds();
    } catch (err) {
      toast.error(`Failed: ${err.message}`);
    }
  };

  return (
    <div style={modalOverlay} onClick={onClose}>
      <div style={{ ...modalBox, width: '620px' }} onClick={e => e.stopPropagation()}>
        <div style={modalHeader}>
          <span style={{ fontSize: '1rem', fontWeight: '600', color: 'var(--text-primary)' }}>
            {edl.name} - Credentials
          </span>
          <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
            <button onClick={() => setShowCreate(!showCreate)} style={{ ...pageBtnStyle, color: '#3CB371', borderColor: '#3CB37140' }}>
              + New Credential
            </button>
            <button onClick={onClose} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', fontSize: '1.2rem', cursor: 'pointer' }}>x</button>
          </div>
        </div>
        <div style={modalBody}>
          {/* New token alert */}
          {newToken && (
            <div style={{
              padding: '0.75rem',
              background: 'rgba(59, 130, 246, 0.1)',
              border: '1px solid rgba(59, 130, 246, 0.3)',
              borderRadius: '6px',
              marginBottom: '0.75rem',
            }}>
              <div style={{ fontWeight: '600', fontSize: '0.8rem', color: '#3b82f6', marginBottom: '0.3rem' }}>
                Token created - copy it now (shown only once)
              </div>
              <code style={{
                display: 'block',
                padding: '0.5rem',
                background: 'var(--bg-primary)',
                borderRadius: '4px',
                fontSize: '0.75rem',
                color: 'var(--text-primary)',
                wordBreak: 'break-all',
              }}>
                {newToken}
              </code>
              <div style={{ display: 'flex', gap: '0.5rem', marginTop: '0.5rem' }}>
                <button
                  onClick={() => { copyToClipboard(newToken); }}
                  style={{ ...pageBtnStyle, color: '#3b82f6' }}
                >
                  Copy Token
                </button>
                <button onClick={() => setNewToken(null)} style={pageBtnStyle}>Dismiss</button>
              </div>
            </div>
          )}

          {/* Create form */}
          {showCreate && (
            <div style={{
              padding: '0.75rem',
              background: 'var(--bg-secondary)',
              borderRadius: '6px',
              marginBottom: '0.75rem',
              border: '1px solid var(--bg-tertiary)',
            }}>
              <label style={labelStyle}>Name</label>
              <input style={inputStyle} value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} placeholder="Production Firewall Cluster" required />

              <label style={labelStyle}>Auth Type</label>
              <select style={selectStyle} value={form.auth_type} onChange={e => setForm({ ...form, auth_type: e.target.value })}>
                <option value="token">Bearer Token</option>
                <option value="basic">Basic Auth</option>
                <option value="ip_allowlist">IP Allowlist</option>
                <option value="none">Public (No Auth)</option>
              </select>

              {form.auth_type === 'ip_allowlist' && (
                <>
                  <label style={labelStyle}>Allowed IPs/CIDRs (one per line)</label>
                  <textarea
                    style={{ ...inputStyle, minHeight: '60px' }}
                    value={form.ip_allowlist}
                    onChange={e => setForm({ ...form, ip_allowlist: e.target.value })}
                    placeholder="10.0.0.0/24&#10;192.168.1.100"
                  />
                </>
              )}

              {form.auth_type === 'basic' && (
                <div style={{ display: 'flex', gap: '0.5rem' }}>
                  <div style={{ flex: 1 }}>
                    <label style={labelStyle}>Username</label>
                    <input style={inputStyle} value={form.basic_username} onChange={e => setForm({ ...form, basic_username: e.target.value })} />
                  </div>
                  <div style={{ flex: 1 }}>
                    <label style={labelStyle}>Password</label>
                    <input style={inputStyle} type="password" value={form.basic_password} onChange={e => setForm({ ...form, basic_password: e.target.value })} />
                  </div>
                </div>
              )}

              <label style={labelStyle}>Description</label>
              <input style={inputStyle} value={form.description} onChange={e => setForm({ ...form, description: e.target.value })} placeholder="Optional description" />

              <button onClick={createCred} disabled={creating || !form.name} style={submitBtnStyle}>
                {creating ? 'Creating...' : 'Create Credential'}
              </button>
            </div>
          )}

          {/* Credentials list */}
          {loading ? (
            <div style={{ textAlign: 'center', padding: '1rem', color: 'var(--text-muted)' }}>Loading...</div>
          ) : creds.length === 0 ? (
            <div style={{ textAlign: 'center', padding: '2rem', color: 'var(--text-muted)', fontSize: '0.85rem' }}>
              No credentials. This list is publicly accessible.
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
              {creds.map(cred => (
                <div key={cred.credential_id} style={{
                  padding: '0.75rem',
                  background: 'var(--bg-secondary)',
                  borderRadius: '6px',
                  border: `1px solid ${cred.enabled ? 'var(--bg-tertiary)' : 'rgba(239,68,68,0.3)'}`,
                }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <div>
                      <div style={{ fontWeight: '600', fontSize: '0.85rem', color: 'var(--text-primary)' }}>{cred.name}</div>
                      <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: '0.15rem' }}>
                        {cred.auth_type.toUpperCase()}
                        {cred.token_prefix && ` (${cred.token_prefix}...)`}
                        {cred.basic_username && ` (user: ${cred.basic_username})`}
                        {cred.last_used_at && ` | Last used: ${new Date(cred.last_used_at).toLocaleDateString()}`}
                        {cred.use_count > 0 && ` | ${cred.use_count} uses`}
                      </div>
                    </div>
                    <div style={{ display: 'flex', gap: '0.3rem' }}>
                      {cred.auth_type === 'token' && (
                        <ActionBtn label="Rotate" onClick={() => rotateCred(cred.credential_id)} color="#3b82f6" />
                      )}
                      <ActionBtn label="Delete" onClick={() => deleteCred(cred.credential_id)} color="#ef4444" />
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}


// ============================================================================
// ACCESS LOG PANEL
// ============================================================================

function AccessLogPanel({ edl, onClose }) {
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);

  const fetchLogs = async () => {
    try {
      const response = await fetch(
        `${API_BASE_URL}/api/v1/edl/lists/${edl.list_id}/access-log?page=${page}&limit=30`,
        { headers: { 'Content-Type': 'application/json' }, credentials: 'include' }
      );
      const data = await response.json();
      setLogs(data.logs || []);
      setTotal(data.total || 0);
      setLoading(false);
    } catch (err) {
      setLoading(false);
    }
  };

  useEffect(() => { fetchLogs(); }, [page]);

  return (
    <div style={modalOverlay} onClick={onClose}>
      <div style={{ ...modalBox, width: '750px' }} onClick={e => e.stopPropagation()}>
        <div style={modalHeader}>
          <span style={{ fontSize: '1rem', fontWeight: '600', color: 'var(--text-primary)' }}>
            {edl.name} - Access Log ({total} entries)
          </span>
          <button onClick={onClose} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', fontSize: '1.2rem', cursor: 'pointer' }}>x</button>
        </div>
        <div style={modalBody}>
          {loading ? (
            <div style={{ textAlign: 'center', padding: '2rem', color: 'var(--text-muted)' }}>Loading...</div>
          ) : logs.length === 0 ? (
            <div style={{ textAlign: 'center', padding: '2rem', color: 'var(--text-muted)' }}>No access logs yet</div>
          ) : (
            <table style={{ width: '100%', borderCollapse: 'collapse' }}>
              <thead>
                <tr>
                  <th style={thStyle}>Time</th>
                  <th style={thStyle}>Client IP</th>
                  <th style={thStyle}>Status</th>
                  <th style={thStyle}>Auth</th>
                  <th style={thStyle}>Items</th>
                  <th style={thStyle}>Latency</th>
                  <th style={thStyle}>Cache</th>
                </tr>
              </thead>
              <tbody>
                {logs.map(log => (
                  <tr key={log.id} style={{ borderBottom: '1px solid var(--bg-tertiary)' }}>
                    <td style={tdStyle}>
                      <span style={{ fontSize: '0.7rem' }}>{new Date(log.accessed_at).toLocaleString()}</span>
                    </td>
                    <td style={tdStyle}>
                      <code style={{ fontSize: '0.7rem' }}>{log.client_ip}</code>
                    </td>
                    <td style={tdStyle}>
                      <span style={{
                        fontSize: '0.7rem',
                        fontWeight: '600',
                        color: log.status_code === 200 ? '#22c55e' :
                               log.status_code === 304 ? '#3b82f6' :
                               log.status_code === 401 ? '#ef4444' :
                               log.status_code === 429 ? '#f59e0b' : 'var(--text-muted)',
                      }}>
                        {log.status_code}
                      </span>
                    </td>
                    <td style={tdStyle}>
                      <span style={{ fontSize: '0.7rem' }}>{log.auth_method || '-'}</span>
                    </td>
                    <td style={tdStyle}>
                      <span style={{ fontSize: '0.7rem' }}>{log.items_returned || '-'}</span>
                    </td>
                    <td style={tdStyle}>
                      <span style={{ fontSize: '0.7rem' }}>{log.response_time_ms}ms</span>
                    </td>
                    <td style={tdStyle}>
                      <span style={{ fontSize: '0.7rem', color: log.cache_hit ? '#22c55e' : 'var(--text-muted)' }}>
                        {log.cache_hit ? 'HIT' : 'MISS'}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}

          {total > 30 && (
            <div style={{ display: 'flex', justifyContent: 'center', gap: '0.5rem', padding: '0.75rem' }}>
              <button onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page === 1} style={pageBtnStyle}>Prev</button>
              <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>Page {page}</span>
              <button onClick={() => setPage(p => p + 1)} disabled={logs.length < 30} style={pageBtnStyle}>Next</button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}


export default EDLManagement;
