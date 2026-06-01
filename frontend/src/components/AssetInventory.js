/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

import React, { useState, useEffect, useCallback } from 'react';
import './AssetInventory.css';
import { API_BASE_URL } from '../utils/api';
import { useToast } from './ui/Toast';

const API_BASE = `${API_BASE_URL}/api/v1`;

const getAuthHeaders = () => {return {
    'Content-Type': 'application/json',
  };
};

// Criticality badge colors
const CRITICALITY_COLORS = {
  tier1: { bg: '#dc2626', text: '#fff', label: 'Critical' },
  tier2: { bg: '#f59e0b', text: '#000', label: 'High' },
  tier3: { bg: '#3b82f6', text: '#fff', label: 'Standard' },
  tier4: { bg: '#6b7280', text: '#fff', label: 'Low' }
};

// Asset type icons
const ASSET_TYPE_ICONS = {
  server: '🖥️',
  workstation: '💻',
  laptop: '💻',
  network_device: '🔌',
  virtual_machine: '☁️',
  container: '📦',
  cloud_instance: '☁️',
  mobile: '📱',
  iot: '🔗',
  unknown: '❓'
};

// Status badges
const STATUS_COLORS = {
  active: { bg: '#10b981', text: '#fff' },
  inactive: { bg: '#6b7280', text: '#fff' },
  maintenance: { bg: '#f59e0b', text: '#000' },
  decommissioned: { bg: '#ef4444', text: '#fff' }
};

function AssetInventory() {
  const toast = useToast();
  // View state
  const [mainView, setMainView] = useState('list'); // list, discovery, detail

  // Assets state
  const [assets, setAssets] = useState([]);
  const [totalCount, setTotalCount] = useState(0);
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Filters
  const [searchTerm, setSearchTerm] = useState('');
  const [filters, setFilters] = useState({
    asset_type: '',
    criticality: '',
    status: '',
    environment: '',
    department: ''
  });

  // Pagination
  const [currentPage, setCurrentPage] = useState(1);
  const [rowsPerPage, setRowsPerPage] = useState(() => {
    const saved = localStorage.getItem('assetInventoryRowsPerPage');
    return saved ? parseInt(saved, 10) : 25;
  });

  // Selection for bulk operations
  const [selectedAssets, setSelectedAssets] = useState(new Set());

  // Detail view
  const [selectedAsset, setSelectedAsset] = useState(null);
  const [assetDetail, setAssetDetail] = useState(null);

  // Discovery sources
  const [discoverySources, setDiscoverySources] = useState([]);
  const [discoveryStats, setDiscoveryStats] = useState(null);

  // Create asset modal
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [newAsset, setNewAsset] = useState({
    hostname: '',
    fqdn: '',
    display_name: '',
    asset_type: 'unknown',
    ip_addresses: '',
    os_family: '',
    os_name: '',
    criticality: 'tier3',
    environment: 'production',
    owner: '',
    owner_team: '',
    department: ''
  });

  // Save rowsPerPage
  useEffect(() => {
    localStorage.setItem('assetInventoryRowsPerPage', rowsPerPage.toString());
  }, [rowsPerPage]);

  // Fetch assets
  const fetchAssets = useCallback(async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams();
      params.append('limit', rowsPerPage);
      params.append('offset', (currentPage - 1) * rowsPerPage);

      if (searchTerm) params.append('search', searchTerm);
      if (filters.asset_type) params.append('asset_type', filters.asset_type);
      if (filters.criticality) params.append('criticality', filters.criticality);
      if (filters.status) params.append('status', filters.status);
      if (filters.environment) params.append('environment', filters.environment);
      if (filters.department) params.append('department', filters.department);

      const response = await fetch(`${API_BASE}/assets?${params}`, {
        headers: getAuthHeaders()
      });

      if (!response.ok) throw new Error('Failed to fetch assets');

      const data = await response.json();
      setAssets(data.assets || []);
      setTotalCount(data.total || 0);
      setError(null);
    } catch (err) {
      setError(err.message);
      setAssets([]);
    } finally {
      setLoading(false);
    }
  }, [currentPage, rowsPerPage, searchTerm, filters]);

  // Fetch stats
  const fetchStats = useCallback(async () => {
    try {
      const response = await fetch(`${API_BASE}/assets/stats`, {
        headers: getAuthHeaders()
      });
      if (response.ok) {
        const data = await response.json();
        setStats(data);
      }
    } catch (err) {
    }
  }, []);

  // Fetch discovery sources
  const fetchDiscoverySources = useCallback(async () => {
    try {
      const response = await fetch(`${API_BASE}/asset-discovery/sources`, {
        headers: getAuthHeaders()
      });
      if (response.ok) {
        const data = await response.json();
        setDiscoverySources(data.sources || []);
      }
    } catch (err) {
    }
  }, []);

  // Fetch discovery stats
  const fetchDiscoveryStats = useCallback(async () => {
    try {
      const response = await fetch(`${API_BASE}/asset-discovery/stats`, {
        headers: getAuthHeaders()
      });
      if (response.ok) {
        const data = await response.json();
        setDiscoveryStats(data);
      }
    } catch (err) {
    }
  }, []);

  // Initial load
  useEffect(() => {
    fetchAssets();
    fetchStats();
    fetchDiscoverySources();
    fetchDiscoveryStats();
  }, [fetchAssets, fetchStats, fetchDiscoverySources, fetchDiscoveryStats]);

  // Refetch on filter changes
  useEffect(() => {
    setCurrentPage(1);
  }, [searchTerm, filters]);

  // Handle asset selection
  const toggleAssetSelection = (assetId) => {
    setSelectedAssets(prev => {
      const newSet = new Set(prev);
      if (newSet.has(assetId)) {
        newSet.delete(assetId);
      } else {
        newSet.add(assetId);
      }
      return newSet;
    });
  };

  // Select all on current page
  const toggleSelectAll = () => {
    if (selectedAssets.size === assets.length) {
      setSelectedAssets(new Set());
    } else {
      setSelectedAssets(new Set(assets.map(a => a.id)));
    }
  };

  // View asset detail
  const viewAssetDetail = async (asset) => {
    setSelectedAsset(asset);
    try {
      const response = await fetch(`${API_BASE}/assets/${asset.id}`, {
        headers: getAuthHeaders()
      });
      if (response.ok) {
        const data = await response.json();
        setAssetDetail(data);
      }
    } catch (err) {
    }
  };

  // Create new asset
  const handleCreateAsset = async () => {
    try {
      const payload = {
        ...newAsset,
        ip_addresses: newAsset.ip_addresses.split(',').map(ip => ip.trim()).filter(Boolean)
      };

      const response = await fetch(`${API_BASE}/assets`, {
        method: 'POST',
        headers: getAuthHeaders(),
        body: JSON.stringify(payload)
      });

      if (!response.ok) throw new Error('Failed to create asset');

      setShowCreateModal(false);
      setNewAsset({
        hostname: '',
        fqdn: '',
        display_name: '',
        asset_type: 'unknown',
        ip_addresses: '',
        os_family: '',
        os_name: '',
        criticality: 'tier3',
        environment: 'production',
        owner: '',
        owner_team: '',
        department: ''
      });
      fetchAssets();
      fetchStats();
    } catch (err) {
      toast.error('Failed to create asset: ' + err.message);
    }
  };

  // Run discovery
  const runDiscovery = async (sourceId) => {
    try {
      const response = await fetch(`${API_BASE}/asset-discovery/run/${sourceId}?triggered_by=ui`, {
        method: 'POST',
        headers: getAuthHeaders()
      });

      if (response.ok) {
        const result = await response.json();
        toast.success(`Discovery completed: ${result.created || 0} created, ${result.updated || 0} updated`);
        fetchAssets();
        fetchStats();
        fetchDiscoveryStats();
      } else {
        const err = await response.json();
        toast.error('Discovery failed: ' + (err.detail || 'Unknown error'));
      }
    } catch (err) {
      toast.error('Discovery failed: ' + err.message);
    }
  };

  // Render stats cards
  const renderStats = () => {
    if (!stats) return null;

    return (
      <div className="asset-stats">
        <div className="stat-card">
          <div className="stat-value">{stats.total_assets || 0}</div>
          <div className="stat-label">Total Assets</div>
        </div>
        <div className="stat-card">
          <div className="stat-value critical">{stats.by_criticality?.tier1 || 0}</div>
          <div className="stat-label">Critical (Tier 1)</div>
        </div>
        <div className="stat-card">
          <div className="stat-value warning">{stats.by_criticality?.tier2 || 0}</div>
          <div className="stat-label">High (Tier 2)</div>
        </div>
        <div className="stat-card">
          <div className="stat-value">{stats.active_assets || stats.by_status?.active || 0}</div>
          <div className="stat-label">Active</div>
        </div>
        <div className="stat-card">
          <div className="stat-value">{discoveryStats?.sources?.enabled || 0}</div>
          <div className="stat-label">Discovery Sources</div>
        </div>
      </div>
    );
  };

  // Render filters
  const renderFilters = () => (
    <div className="asset-filters">
      <div className="search-box">
        <input
          type="text"
          placeholder="Search by hostname, IP, owner..."
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          className="search-input"
        />
      </div>

      <select
        value={filters.asset_type}
        onChange={(e) => setFilters(prev => ({ ...prev, asset_type: e.target.value }))}
        className="filter-select"
      >
        <option value="">All Types</option>
        <option value="server">Server</option>
        <option value="workstation">Workstation</option>
        <option value="laptop">Laptop</option>
        <option value="network_device">Network Device</option>
        <option value="virtual_machine">Virtual Machine</option>
        <option value="container">Container</option>
        <option value="cloud_instance">Cloud Instance</option>
      </select>

      <select
        value={filters.criticality}
        onChange={(e) => setFilters(prev => ({ ...prev, criticality: e.target.value }))}
        className="filter-select"
      >
        <option value="">All Criticality</option>
        <option value="tier1">Tier 1 - Critical</option>
        <option value="tier2">Tier 2 - High</option>
        <option value="tier3">Tier 3 - Standard</option>
        <option value="tier4">Tier 4 - Low</option>
      </select>

      <select
        value={filters.environment}
        onChange={(e) => setFilters(prev => ({ ...prev, environment: e.target.value }))}
        className="filter-select"
      >
        <option value="">All Environments</option>
        <option value="production">Production</option>
        <option value="staging">Staging</option>
        <option value="development">Development</option>
        <option value="test">Test</option>
      </select>

      <select
        value={filters.status}
        onChange={(e) => setFilters(prev => ({ ...prev, status: e.target.value }))}
        className="filter-select"
      >
        <option value="">All Status</option>
        <option value="active">Active</option>
        <option value="inactive">Inactive</option>
        <option value="maintenance">Maintenance</option>
      </select>

      <button
        className="btn-secondary"
        onClick={() => {
          setFilters({ asset_type: '', criticality: '', status: '', environment: '', department: '' });
          setSearchTerm('');
        }}
      >
        Clear Filters
      </button>
    </div>
  );

  // Render asset table
  const renderAssetTable = () => (
    <div className="asset-table-container">
      <table className="asset-table">
        <thead>
          <tr>
            <th className="checkbox-col">
              <input
                type="checkbox"
                checked={selectedAssets.size === assets.length && assets.length > 0}
                onChange={toggleSelectAll}
              />
            </th>
            <th>Asset</th>
            <th>Type</th>
            <th>IP Addresses</th>
            <th>Criticality</th>
            <th>Environment</th>
            <th>Owner</th>
            <th>Status</th>
            <th>Last Seen</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {assets.map(asset => (
            <tr
              key={asset.id}
              className={selectedAssets.has(asset.id) ? 'selected' : ''}
              onClick={() => viewAssetDetail(asset)}
            >
              <td className="checkbox-col" onClick={(e) => e.stopPropagation()}>
                <input
                  type="checkbox"
                  checked={selectedAssets.has(asset.id)}
                  onChange={() => toggleAssetSelection(asset.id)}
                />
              </td>
              <td>
                <div className="asset-name-cell">
                  <span className="asset-icon">{ASSET_TYPE_ICONS[asset.asset_type] || '❓'}</span>
                  <div>
                    <div className="asset-hostname">{asset.display_name || asset.hostname || asset.fqdn}</div>
                    {asset.fqdn && asset.fqdn !== asset.hostname && (
                      <div className="asset-fqdn">{asset.fqdn}</div>
                    )}
                  </div>
                </div>
              </td>
              <td>
                <span className="asset-type-badge">{asset.asset_type || 'unknown'}</span>
              </td>
              <td>
                <div className="ip-list">
                  {(asset.ip_addresses || []).slice(0, 2).map((ip, idx) => (
                    <span key={idx} className="ip-badge">{ip}</span>
                  ))}
                  {(asset.ip_addresses || []).length > 2 && (
                    <span className="ip-more">+{asset.ip_addresses.length - 2}</span>
                  )}
                </div>
              </td>
              <td>
                <span
                  className="criticality-badge"
                  style={{
                    backgroundColor: CRITICALITY_COLORS[asset.criticality]?.bg || '#6b7280',
                    color: CRITICALITY_COLORS[asset.criticality]?.text || '#fff'
                  }}
                >
                  {CRITICALITY_COLORS[asset.criticality]?.label || asset.criticality}
                </span>
              </td>
              <td>{asset.environment || '-'}</td>
              <td>{asset.owner || asset.owner_team || '-'}</td>
              <td>
                <span
                  className="status-badge"
                  style={{
                    backgroundColor: STATUS_COLORS[asset.status]?.bg || '#6b7280',
                    color: STATUS_COLORS[asset.status]?.text || '#fff'
                  }}
                >
                  {asset.status || 'unknown'}
                </span>
              </td>
              <td className="last-seen">
                {asset.last_seen ? new Date(asset.last_seen).toLocaleDateString() : '-'}
              </td>
              <td onClick={(e) => e.stopPropagation()}>
                <button
                  className="btn-icon"
                  onClick={() => viewAssetDetail(asset)}
                  title="View Details"
                >
                  👁️
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      {assets.length === 0 && !loading && (
        <div className="empty-state">
          <span className="empty-icon">📦</span>
          <h3>No Assets Found</h3>
          <p>Try adjusting your filters or add new assets manually.</p>
        </div>
      )}
    </div>
  );

  // Render pagination
  const renderPagination = () => {
    const totalPages = Math.ceil(totalCount / rowsPerPage);

    return (
      <div className="pagination">
        <div className="pagination-info">
          Showing {((currentPage - 1) * rowsPerPage) + 1} - {Math.min(currentPage * rowsPerPage, totalCount)} of {totalCount}
        </div>
        <div className="pagination-controls">
          <select
            value={rowsPerPage}
            onChange={(e) => setRowsPerPage(parseInt(e.target.value))}
            className="rows-select"
          >
            <option value={10}>10 per page</option>
            <option value={25}>25 per page</option>
            <option value={50}>50 per page</option>
            <option value={100}>100 per page</option>
          </select>
          <button
            onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
            disabled={currentPage === 1}
            className="page-btn"
          >
            ← Prev
          </button>
          <span className="page-info">Page {currentPage} of {totalPages || 1}</span>
          <button
            onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))}
            disabled={currentPage >= totalPages}
            className="page-btn"
          >
            Next →
          </button>
        </div>
      </div>
    );
  };

  // Render asset detail panel
  const renderAssetDetail = () => {
    if (!selectedAsset) return null;
    const asset = assetDetail || selectedAsset;

    return (
      <div className="asset-detail-overlay" onClick={() => setSelectedAsset(null)}>
        <div className="asset-detail-panel" onClick={(e) => e.stopPropagation()}>
          <div className="detail-header">
            <div className="detail-title">
              <span className="detail-icon">{ASSET_TYPE_ICONS[asset.asset_type] || '❓'}</span>
              <div>
                <h2>{asset.display_name || asset.hostname}</h2>
                <p className="detail-subtitle">{asset.fqdn}</p>
              </div>
            </div>
            <button className="close-btn" onClick={() => setSelectedAsset(null)}>✕</button>
          </div>

          <div className="detail-content">
            <div className="detail-section">
              <h3>Overview</h3>
              <div className="detail-grid">
                <div className="detail-item">
                  <label>Type</label>
                  <span>{asset.asset_type}</span>
                </div>
                <div className="detail-item">
                  <label>Criticality</label>
                  <span
                    className="criticality-badge"
                    style={{
                      backgroundColor: CRITICALITY_COLORS[asset.criticality]?.bg,
                      color: CRITICALITY_COLORS[asset.criticality]?.text
                    }}
                  >
                    {CRITICALITY_COLORS[asset.criticality]?.label}
                  </span>
                </div>
                <div className="detail-item">
                  <label>Status</label>
                  <span
                    className="status-badge"
                    style={{
                      backgroundColor: STATUS_COLORS[asset.status]?.bg,
                      color: STATUS_COLORS[asset.status]?.text
                    }}
                  >
                    {asset.status}
                  </span>
                </div>
                <div className="detail-item">
                  <label>Environment</label>
                  <span>{asset.environment || '-'}</span>
                </div>
              </div>
            </div>

            <div className="detail-section">
              <h3>Network</h3>
              <div className="detail-grid">
                <div className="detail-item full-width">
                  <label>IP Addresses</label>
                  <div className="ip-list">
                    {(asset.ip_addresses || []).map((ip, idx) => (
                      <span key={idx} className="ip-badge">{ip}</span>
                    ))}
                  </div>
                </div>
                <div className="detail-item full-width">
                  <label>MAC Addresses</label>
                  <div className="ip-list">
                    {(asset.mac_addresses || []).map((mac, idx) => (
                      <span key={idx} className="ip-badge">{mac}</span>
                    ))}
                    {(!asset.mac_addresses || asset.mac_addresses.length === 0) && <span>-</span>}
                  </div>
                </div>
              </div>
            </div>

            <div className="detail-section">
              <h3>Operating System</h3>
              <div className="detail-grid">
                <div className="detail-item">
                  <label>OS Family</label>
                  <span>{asset.os_family || '-'}</span>
                </div>
                <div className="detail-item">
                  <label>OS Name</label>
                  <span>{asset.os_name || '-'}</span>
                </div>
                <div className="detail-item">
                  <label>OS Version</label>
                  <span>{asset.os_version || '-'}</span>
                </div>
              </div>
            </div>

            <div className="detail-section">
              <h3>Ownership</h3>
              <div className="detail-grid">
                <div className="detail-item">
                  <label>Owner</label>
                  <span>{asset.owner || '-'}</span>
                </div>
                <div className="detail-item">
                  <label>Team</label>
                  <span>{asset.owner_team || '-'}</span>
                </div>
                <div className="detail-item">
                  <label>Department</label>
                  <span>{asset.department || '-'}</span>
                </div>
                <div className="detail-item">
                  <label>Location</label>
                  <span>{asset.location || '-'}</span>
                </div>
              </div>
            </div>

            {(asset.compliance_tags?.length > 0 || asset.custom_tags?.length > 0) && (
              <div className="detail-section">
                <h3>Tags</h3>
                <div className="tags-container">
                  {(asset.compliance_tags || []).map((tag, idx) => (
                    <span key={`c-${idx}`} className="tag compliance-tag">{tag}</span>
                  ))}
                  {(asset.custom_tags || []).map((tag, idx) => (
                    <span key={`t-${idx}`} className="tag custom-tag">{tag}</span>
                  ))}
                </div>
              </div>
            )}

            <div className="detail-section">
              <h3>Metadata</h3>
              <div className="detail-grid">
                <div className="detail-item">
                  <label>First Seen</label>
                  <span>{asset.first_seen ? new Date(asset.first_seen).toLocaleString() : '-'}</span>
                </div>
                <div className="detail-item">
                  <label>Last Seen</label>
                  <span>{asset.last_seen ? new Date(asset.last_seen).toLocaleString() : '-'}</span>
                </div>
                <div className="detail-item">
                  <label>Created</label>
                  <span>{asset.created_at ? new Date(asset.created_at).toLocaleString() : '-'}</span>
                </div>
                <div className="detail-item">
                  <label>Updated</label>
                  <span>{asset.updated_at ? new Date(asset.updated_at).toLocaleString() : '-'}</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    );
  };

  // Render discovery view
  const renderDiscoveryView = () => (
    <div className="discovery-view">
      <div className="discovery-header">
        <h2>Asset Discovery</h2>
        <p className="subtitle">Configure and run asset discovery from various sources</p>
      </div>

      {discoveryStats && (
        <div className="discovery-stats">
          <div className="stat-card">
            <div className="stat-value">{discoveryStats.sources?.total || 0}</div>
            <div className="stat-label">Total Sources</div>
          </div>
          <div className="stat-card">
            <div className="stat-value">{discoveryStats.sources?.enabled || 0}</div>
            <div className="stat-label">Enabled</div>
          </div>
          <div className="stat-card">
            <div className="stat-value">{discoveryStats.last_7_days?.total_discovered || 0}</div>
            <div className="stat-label">Discovered (7d)</div>
          </div>
          <div className="stat-card">
            <div className="stat-value">{discoveryStats.pending_conflicts || 0}</div>
            <div className="stat-label">Pending Conflicts</div>
          </div>
        </div>
      )}

      <div className="discovery-sources">
        <h3>Discovery Sources</h3>
        {discoverySources.length === 0 ? (
          <div className="empty-state small">
            <p>No discovery sources configured yet.</p>
          </div>
        ) : (
          <div className="source-cards">
            {discoverySources.map(source => (
              <div key={source.id} className={`source-card ${source.enabled ? '' : 'disabled'}`}>
                <div className="source-header">
                  <span className="source-icon">
                    {source.source_type === 'crowdstrike' && '🦅'}
                    {source.source_type === 'aws' && '☁️'}
                    {source.source_type === 'azure' && '🔷'}
                    {source.source_type === 'active_directory' && '📁'}
                    {source.source_type === 'vmware' && '🖥️'}
                    {source.source_type === 'network_scan' && '🔍'}
                    {!['crowdstrike', 'aws', 'azure', 'active_directory', 'vmware', 'network_scan'].includes(source.source_type) && '🔌'}
                  </span>
                  <div className="source-info">
                    <h4>{source.name}</h4>
                    <span className="source-type">{source.source_type}</span>
                  </div>
                  <span className={`source-status ${source.enabled ? 'enabled' : 'disabled'}`}>
                    {source.enabled ? 'Enabled' : 'Disabled'}
                  </span>
                </div>
                <div className="source-meta">
                  <div>Priority: {source.source_priority || source.priority || 50}</div>
                  <div>Last Sync: {source.last_sync ? new Date(source.last_sync).toLocaleString() : 'Never'}</div>
                </div>
                <div className="source-actions">
                  <button
                    className="btn-primary btn-sm"
                    onClick={() => runDiscovery(source.id)}
                    disabled={!source.enabled}
                  >
                    Run Now
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );

  // Render create modal
  const renderCreateModal = () => {
    if (!showCreateModal) return null;

    return (
      <div className="modal-overlay" onClick={() => setShowCreateModal(false)}>
        <div className="modal-content" onClick={(e) => e.stopPropagation()}>
          <div className="modal-header">
            <h2>Add New Asset</h2>
            <button className="close-btn" onClick={() => setShowCreateModal(false)}>✕</button>
          </div>
          <div className="modal-body">
            <div className="form-grid">
              <div className="form-group">
                <label>Hostname *</label>
                <input
                  type="text"
                  value={newAsset.hostname}
                  onChange={(e) => setNewAsset(prev => ({ ...prev, hostname: e.target.value }))}
                  placeholder="e.g., srv-web-01"
                />
              </div>
              <div className="form-group">
                <label>FQDN</label>
                <input
                  type="text"
                  value={newAsset.fqdn}
                  onChange={(e) => setNewAsset(prev => ({ ...prev, fqdn: e.target.value }))}
                  placeholder="e.g., srv-web-01.corp.local"
                />
              </div>
              <div className="form-group">
                <label>Display Name</label>
                <input
                  type="text"
                  value={newAsset.display_name}
                  onChange={(e) => setNewAsset(prev => ({ ...prev, display_name: e.target.value }))}
                  placeholder="e.g., Production Web Server 01"
                />
              </div>
              <div className="form-group">
                <label>Asset Type</label>
                <select
                  value={newAsset.asset_type}
                  onChange={(e) => setNewAsset(prev => ({ ...prev, asset_type: e.target.value }))}
                >
                  <option value="server">Server</option>
                  <option value="workstation">Workstation</option>
                  <option value="laptop">Laptop</option>
                  <option value="network_device">Network Device</option>
                  <option value="virtual_machine">Virtual Machine</option>
                  <option value="container">Container</option>
                  <option value="cloud_instance">Cloud Instance</option>
                  <option value="unknown">Unknown</option>
                </select>
              </div>
              <div className="form-group full-width">
                <label>IP Addresses (comma-separated)</label>
                <input
                  type="text"
                  value={newAsset.ip_addresses}
                  onChange={(e) => setNewAsset(prev => ({ ...prev, ip_addresses: e.target.value }))}
                  placeholder="e.g., 192.168.1.10, 10.0.0.50"
                />
              </div>
              <div className="form-group">
                <label>OS Family</label>
                <select
                  value={newAsset.os_family}
                  onChange={(e) => setNewAsset(prev => ({ ...prev, os_family: e.target.value }))}
                >
                  <option value="">Select...</option>
                  <option value="windows">Windows</option>
                  <option value="linux">Linux</option>
                  <option value="macos">macOS</option>
                  <option value="unix">Unix</option>
                </select>
              </div>
              <div className="form-group">
                <label>OS Name</label>
                <input
                  type="text"
                  value={newAsset.os_name}
                  onChange={(e) => setNewAsset(prev => ({ ...prev, os_name: e.target.value }))}
                  placeholder="e.g., Windows Server 2022"
                />
              </div>
              <div className="form-group">
                <label>Criticality</label>
                <select
                  value={newAsset.criticality}
                  onChange={(e) => setNewAsset(prev => ({ ...prev, criticality: e.target.value }))}
                >
                  <option value="tier1">Tier 1 - Critical</option>
                  <option value="tier2">Tier 2 - High</option>
                  <option value="tier3">Tier 3 - Standard</option>
                  <option value="tier4">Tier 4 - Low</option>
                </select>
              </div>
              <div className="form-group">
                <label>Environment</label>
                <select
                  value={newAsset.environment}
                  onChange={(e) => setNewAsset(prev => ({ ...prev, environment: e.target.value }))}
                >
                  <option value="production">Production</option>
                  <option value="staging">Staging</option>
                  <option value="development">Development</option>
                  <option value="test">Test</option>
                </select>
              </div>
              <div className="form-group">
                <label>Owner</label>
                <input
                  type="text"
                  value={newAsset.owner}
                  onChange={(e) => setNewAsset(prev => ({ ...prev, owner: e.target.value }))}
                  placeholder="e.g., John Smith"
                />
              </div>
              <div className="form-group">
                <label>Owner Team</label>
                <input
                  type="text"
                  value={newAsset.owner_team}
                  onChange={(e) => setNewAsset(prev => ({ ...prev, owner_team: e.target.value }))}
                  placeholder="e.g., Infrastructure"
                />
              </div>
              <div className="form-group">
                <label>Department</label>
                <input
                  type="text"
                  value={newAsset.department}
                  onChange={(e) => setNewAsset(prev => ({ ...prev, department: e.target.value }))}
                  placeholder="e.g., IT"
                />
              </div>
            </div>
          </div>
          <div className="modal-footer">
            <button className="btn-secondary" onClick={() => setShowCreateModal(false)}>Cancel</button>
            <button
              className="btn-primary"
              onClick={handleCreateAsset}
              disabled={!newAsset.hostname}
            >
              Create Asset
            </button>
          </div>
        </div>
      </div>
    );
  };

  return (
    <div className="asset-inventory">
      <div className="page-header">
        <div>
          <h1>Asset Inventory</h1>
          <p className="subtitle">CMDB - Manage and discover your infrastructure assets</p>
        </div>
        <div className="header-actions">
          <div className="view-tabs">
            <button
              className={`tab-btn ${mainView === 'list' ? 'active' : ''}`}
              onClick={() => setMainView('list')}
            >
              📋 Assets
            </button>
            <button
              className={`tab-btn ${mainView === 'discovery' ? 'active' : ''}`}
              onClick={() => setMainView('discovery')}
            >
              🔍 Discovery
            </button>
          </div>
          <button className="btn-primary" onClick={() => setShowCreateModal(true)}>
            + Add Asset
          </button>
        </div>
      </div>

      {error && (
        <div className="error-banner">
          <span className="error-icon">⚠️</span>
          <span>{error}</span>
        </div>
      )}

      {mainView === 'list' && (
        <>
          {renderStats()}
          {renderFilters()}
          {loading ? (
            <div className="loading">Loading assets...</div>
          ) : (
            <>
              {renderAssetTable()}
              {renderPagination()}
            </>
          )}
        </>
      )}

      {mainView === 'discovery' && renderDiscoveryView()}

      {renderAssetDetail()}
      {renderCreateModal()}
    </div>
  );
}

export default AssetInventory;


