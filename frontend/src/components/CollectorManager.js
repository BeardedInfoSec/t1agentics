/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

import React, { useState, useEffect, useCallback } from 'react';
import { authFetch, API_BASE_URL } from '../utils/api';
import './CollectorManager.css';

// Category icons and colors
const categoryConfig = {
  endpoint: { icon: '💻', color: '#3b82f6', label: 'Endpoint' },
  network: { icon: '🌐', color: '#8b5cf6', label: 'Network' },
  cloud: { icon: '☁️', color: '#06b6d4', label: 'Cloud' },
  application: { icon: '📱', color: '#f59e0b', label: 'Application' },
  identity: { icon: '🔐', color: '#10b981', label: 'Identity' },
  email: { icon: '📧', color: '#ec4899', label: 'Email' },
  database: { icon: '🗄️', color: '#6366f1', label: 'Database' },
  custom: { icon: '⚙️', color: '#64748b', label: 'Custom' }
};

// Status badge component
function StatusBadge({ status }) {
  const statusColors = {
    active: { bg: 'rgba(34, 197, 94, 0.15)', color: '#22c55e' },
    inactive: { bg: 'rgba(239, 68, 68, 0.15)', color: '#ef4444' },
    maintenance: { bg: 'rgba(234, 179, 8, 0.15)', color: '#eab308' },
    paused: { bg: 'rgba(234, 179, 8, 0.15)', color: '#eab308' },
    error: { bg: 'rgba(239, 68, 68, 0.15)', color: '#ef4444' },
    configuring: { bg: 'rgba(59, 130, 246, 0.15)', color: '#3b82f6' }
  };
  const style = statusColors[status] || statusColors.inactive;

  return (
    <span className="collector-status-badge" style={{ background: style.bg, color: style.color }}>
      {status}
    </span>
  );
}

// Source Assignment Modal
function AssignSourceModal({ collector, sourceTypes, onAssign, onClose }) {
  const [selectedSources, setSelectedSources] = useState([]);
  const [filterCategory, setFilterCategory] = useState('all');
  const [searchTerm, setSearchTerm] = useState('');

  // Filter out already assigned sources
  const assignedSourceTypes = collector.source_assignments?.map(a => a.source_type) || [];
  const availableSources = sourceTypes.filter(s =>
    !assignedSourceTypes.includes(s.source_type) &&
    (filterCategory === 'all' || s.category === filterCategory) &&
    (searchTerm === '' ||
      s.display_name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      s.source_type.toLowerCase().includes(searchTerm.toLowerCase()) ||
      (s.vendor || '').toLowerCase().includes(searchTerm.toLowerCase())
    )
  );

  const toggleSource = (sourceType) => {
    setSelectedSources(prev =>
      prev.includes(sourceType)
        ? prev.filter(s => s !== sourceType)
        : [...prev, sourceType]
    );
  };

  const handleAssign = () => {
    if (selectedSources.length > 0) {
      onAssign(selectedSources);
    }
  };

  const categories = ['all', ...Object.keys(categoryConfig)];

  return (
    <div className="collector-modal-overlay" onClick={onClose}>
      <div className="collector-modal" onClick={e => e.stopPropagation()}>
        <div className="collector-modal-header">
          <h3>Assign Log Sources to {collector.hostname}</h3>
          <button className="collector-modal-close" onClick={onClose}>&times;</button>
        </div>

        <div className="collector-modal-body">
          {/* Filters */}
          <div className="collector-source-filters">
            <input
              type="text"
              placeholder="Search sources..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="collector-search-input"
            />
            <div className="collector-category-pills">
              {categories.map(cat => (
                <button
                  key={cat}
                  className={`collector-category-pill ${filterCategory === cat ? 'active' : ''}`}
                  onClick={() => setFilterCategory(cat)}
                  style={filterCategory === cat && cat !== 'all' ? {
                    borderColor: categoryConfig[cat]?.color,
                    background: `${categoryConfig[cat]?.color}20`
                  } : {}}
                >
                  {cat === 'all' ? 'All' : (
                    <>
                      <span>{categoryConfig[cat]?.icon}</span>
                      {categoryConfig[cat]?.label}
                    </>
                  )}
                </button>
              ))}
            </div>
          </div>

          {/* Source List */}
          <div className="collector-source-list">
            {availableSources.length === 0 ? (
              <div className="collector-empty-state">
                {assignedSourceTypes.length === sourceTypes.length
                  ? 'All available sources are already assigned to this collector'
                  : 'No sources match your filter criteria'}
              </div>
            ) : (
              availableSources.map(source => {
                const catConfig = categoryConfig[source.category] || categoryConfig.custom;
                const isSelected = selectedSources.includes(source.source_type);

                return (
                  <div
                    key={source.source_type}
                    className={`collector-source-item ${isSelected ? 'selected' : ''}`}
                    onClick={() => toggleSource(source.source_type)}
                  >
                    <div className="collector-source-checkbox">
                      {isSelected && <span>✓</span>}
                    </div>
                    <div className="collector-source-icon" style={{ color: catConfig.color }}>
                      {catConfig.icon}
                    </div>
                    <div className="collector-source-info">
                      <div className="collector-source-name">{source.display_name}</div>
                      <div className="collector-source-meta">
                        {source.vendor && <span className="collector-source-vendor">{source.vendor}</span>}
                        <span className="collector-source-type">{source.source_type}</span>
                        <span className="collector-source-index">→ {source.default_index_name || 'main'}</span>
                      </div>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>

        <div className="collector-modal-footer">
          <span className="collector-selected-count">
            {selectedSources.length} source{selectedSources.length !== 1 ? 's' : ''} selected
          </span>
          <div className="collector-modal-actions">
            <button className="collector-btn collector-btn-secondary" onClick={onClose}>
              Cancel
            </button>
            <button
              className="collector-btn collector-btn-primary"
              onClick={handleAssign}
              disabled={selectedSources.length === 0}
            >
              Assign Sources
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

// Collector Detail Panel
function CollectorDetailPanel({ collector, sourceTypes, onUpdate, onClose }) {
  const [activeTab, setActiveTab] = useState('sources');
  const [showAssignModal, setShowAssignModal] = useState(false);
  const [loading, setLoading] = useState(false);

  const handleAssignSources = async (sourceTypeList) => {
    setLoading(true);
    try {
      const assignments = sourceTypeList.map(source_type => ({
        source_type,
        is_enabled: true
      }));

      await authFetch(`${API_BASE_URL}/api/v1/collectors/${collector.id}/sources/bulk`, {
        method: 'POST',
        body: JSON.stringify({ assignments })
      });

      onUpdate();
      setShowAssignModal(false);
    } catch (err) {
      console.error('Source assign error:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleToggleSource = async (sourceType, enabled) => {
    try {
      await authFetch(`${API_BASE_URL}/api/v1/collectors/${collector.id}/sources/${sourceType}`, {
        method: 'PATCH',
        body: JSON.stringify({ is_enabled: enabled })
      });
      onUpdate();
    } catch (err) {
      console.error('Source toggle error:', err);
    }
  };

  const handleRemoveSource = async (sourceType) => {
    if (!window.confirm(`Remove ${sourceType} from this collector?`)) return;

    try {
      await authFetch(`${API_BASE_URL}/api/v1/collectors/${collector.id}/sources/${sourceType}`, {
        method: 'DELETE'
      });
      onUpdate();
    } catch (err) {
      console.error('Source remove error:', err);
    }
  };

  return (
    <div className="collector-detail-panel">
      <div className="collector-detail-header">
        <div className="collector-detail-title">
          <h2>{collector.hostname}</h2>
          <StatusBadge status={collector.status} />
        </div>
        <button className="collector-detail-close" onClick={onClose}>&times;</button>
      </div>

      {/* Collector Info */}
      <div className="collector-detail-info">
        <div className="collector-info-grid">
          <div className="collector-info-item">
            <span className="collector-info-label">Agent ID</span>
            <span className="collector-info-value">{collector.agent_id}</span>
          </div>
          <div className="collector-info-item">
            <span className="collector-info-label">OS</span>
            <span className="collector-info-value">{collector.os_type} {collector.os_version}</span>
          </div>
          <div className="collector-info-item">
            <span className="collector-info-label">IP Address</span>
            <span className="collector-info-value">{collector.ip_address || 'N/A'}</span>
          </div>
          <div className="collector-info-item">
            <span className="collector-info-label">Version</span>
            <span className="collector-info-value">{collector.agent_version || 'N/A'}</span>
          </div>
          <div className="collector-info-item">
            <span className="collector-info-label">Last Heartbeat</span>
            <span className="collector-info-value">
              {collector.last_heartbeat
                ? new Date(collector.last_heartbeat).toLocaleString()
                : 'Never'}
            </span>
          </div>
          <div className="collector-info-item">
            <span className="collector-info-label">Events Received</span>
            <span className="collector-info-value">{(collector.events_received_total || 0).toLocaleString()}</span>
          </div>
        </div>
        {collector.tags && collector.tags.length > 0 && (
          <div className="collector-tags">
            {collector.tags.map(tag => (
              <span key={tag} className="collector-tag">{tag}</span>
            ))}
          </div>
        )}
      </div>

      {/* Tabs */}
      <div className="collector-detail-tabs">
        <button
          className={`collector-tab ${activeTab === 'sources' ? 'active' : ''}`}
          onClick={() => setActiveTab('sources')}
        >
          Log Sources ({collector.source_assignments?.length || 0})
        </button>
        <button
          className={`collector-tab ${activeTab === 'config' ? 'active' : ''}`}
          onClick={() => setActiveTab('config')}
        >
          Configuration
        </button>
      </div>

      {/* Tab Content */}
      <div className="collector-detail-content">
        {activeTab === 'sources' && (
          <div className="collector-sources-tab">
            <div className="collector-sources-header">
              <h3>Assigned Log Sources</h3>
              <button
                className="collector-btn collector-btn-primary"
                onClick={() => setShowAssignModal(true)}
              >
                + Add Sources
              </button>
            </div>

            {!collector.source_assignments || collector.source_assignments.length === 0 ? (
              <div className="collector-empty-state">
                <div className="collector-empty-icon">📥</div>
                <p>No log sources assigned to this collector yet.</p>
                <button
                  className="collector-btn collector-btn-primary"
                  onClick={() => setShowAssignModal(true)}
                >
                  Assign Log Sources
                </button>
              </div>
            ) : (
              <div className="collector-assignments-list">
                {collector.source_assignments.map(assignment => {
                  const sourceInfo = sourceTypes.find(s => s.source_type === assignment.source_type);
                  const catConfig = categoryConfig[sourceInfo?.category] || categoryConfig.custom;

                  return (
                    <div key={assignment.id} className="collector-assignment-card">
                      <div className="collector-assignment-main">
                        <div className="collector-assignment-icon" style={{ color: catConfig.color }}>
                          {catConfig.icon}
                        </div>
                        <div className="collector-assignment-info">
                          <div className="collector-assignment-name">
                            {assignment.source_display_name || assignment.source_type}
                          </div>
                          <div className="collector-assignment-meta">
                            <span>→ {assignment.target_index_name || 'default'}</span>
                            <span>{(assignment.events_collected || 0).toLocaleString()} events</span>
                            {assignment.last_event_at && (
                              <span>Last: {new Date(assignment.last_event_at).toLocaleString()}</span>
                            )}
                          </div>
                        </div>
                      </div>
                      <div className="collector-assignment-actions">
                        <StatusBadge status={assignment.status} />
                        <label className="collector-toggle">
                          <input
                            type="checkbox"
                            checked={assignment.is_enabled}
                            onChange={(e) => handleToggleSource(assignment.source_type, e.target.checked)}
                          />
                          <span className="collector-toggle-slider"></span>
                        </label>
                        <button
                          className="collector-btn-icon"
                          onClick={() => handleRemoveSource(assignment.source_type)}
                          title="Remove source"
                        >
                          🗑️
                        </button>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        )}

        {activeTab === 'config' && (
          <div className="collector-config-tab">
            <div className="collector-config-section">
              <h4>Agent Configuration</h4>
              <pre className="collector-config-json">
                {JSON.stringify(collector.metadata || {}, null, 2)}
              </pre>
            </div>
          </div>
        )}
      </div>

      {showAssignModal && (
        <AssignSourceModal
          collector={collector}
          sourceTypes={sourceTypes}
          onAssign={handleAssignSources}
          onClose={() => setShowAssignModal(false)}
        />
      )}
    </div>
  );
}

// Main Component
function CollectorManager() {
  const [collectors, setCollectors] = useState([]);
  const [sourceTypes, setSourceTypes] = useState([]);
  const [summary, setSummary] = useState(null);
  const [loading, setLoading] = useState(true);
  const [selectedCollector, setSelectedCollector] = useState(null);
  const [filterStatus, setFilterStatus] = useState('all');
  const [filterOS, setFilterOS] = useState('all');
  const [searchTerm, setSearchTerm] = useState('');
  const [activeView, setActiveView] = useState('collectors'); // 'collectors' or 'sources'

  const fetchData = useCallback(async () => {
    try {
      const [collectorsRes, sourcesRes, summaryRes] = await Promise.all([
        authFetch(`${API_BASE_URL}/api/v1/collectors`),
        authFetch(`${API_BASE_URL}/api/v1/collectors/source-types`),
        authFetch(`${API_BASE_URL}/api/v1/collectors/summary`)
      ]);

      if (collectorsRes.ok) {
        setCollectors(await collectorsRes.json());
      }
      if (sourcesRes.ok) {
        setSourceTypes(await sourcesRes.json());
      }
      if (summaryRes.ok) {
        setSummary(await summaryRes.json());
      }
    } catch (err) {
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
    // Refresh every 30 seconds
    const interval = setInterval(fetchData, 30000);
    return () => clearInterval(interval);
  }, [fetchData]);

  const handleCollectorUpdate = async () => {
    // Refresh collector data after an update
    if (selectedCollector) {
      const res = await authFetch(`${API_BASE_URL}/api/v1/collectors/${selectedCollector.id}`);
      if (res.ok) {
        const updated = await res.json();
        setSelectedCollector(updated);
        setCollectors(prev => prev.map(c => c.id === updated.id ? updated : c));
      }
    }
    // Also refresh summary
    const summaryRes = await authFetch(`${API_BASE_URL}/api/v1/collectors/summary`);
    if (summaryRes.ok) {
      setSummary(await summaryRes.json());
    }
  };

  // Filter collectors
  const filteredCollectors = collectors.filter(c => {
    if (filterStatus !== 'all' && c.status !== filterStatus) return false;
    if (filterOS !== 'all' && c.os_type !== filterOS) return false;
    if (searchTerm && !c.hostname.toLowerCase().includes(searchTerm.toLowerCase()) &&
        !c.agent_id.toLowerCase().includes(searchTerm.toLowerCase())) return false;
    return true;
  });

  // Group source types by category
  const sourcesByCategory = sourceTypes.reduce((acc, source) => {
    const cat = source.category || 'custom';
    if (!acc[cat]) acc[cat] = [];
    acc[cat].push(source);
    return acc;
  }, {});

  if (loading) {
    return (
      <div className="collector-manager">
        <div className="collector-loading">
          <div className="collector-spinner"></div>
          <p>Loading collectors...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="collector-manager">
      {/* Header */}
      <div className="collector-header">
        <div className="collector-header-left">
          <h1>Collector Management</h1>
          <p>Configure log collection sources and routing for your agents</p>
        </div>
        <div className="collector-view-toggle">
          <button
            className={`collector-view-btn ${activeView === 'collectors' ? 'active' : ''}`}
            onClick={() => setActiveView('collectors')}
          >
            Collectors
          </button>
          <button
            className={`collector-view-btn ${activeView === 'sources' ? 'active' : ''}`}
            onClick={() => setActiveView('sources')}
          >
            Source Catalog
          </button>
        </div>
      </div>

      {/* Summary Stats */}
      {summary && (
        <div className="collector-stats">
          <div className="collector-stat-card">
            <div className="collector-stat-value">{summary.collectors.total}</div>
            <div className="collector-stat-label">Total Collectors</div>
            <div className="collector-stat-detail">
              <span className="collector-stat-online">{summary.collectors.online} online</span>
            </div>
          </div>
          <div className="collector-stat-card">
            <div className="collector-stat-value">{summary.source_types.total}</div>
            <div className="collector-stat-label">Source Types</div>
            <div className="collector-stat-detail">
              {summary.source_types.builtin} built-in, {summary.source_types.custom} custom
            </div>
          </div>
          <div className="collector-stat-card">
            <div className="collector-stat-value">{summary.assignments.total}</div>
            <div className="collector-stat-label">Active Assignments</div>
            <div className="collector-stat-detail">
              {summary.assignments.error > 0 && (
                <span className="collector-stat-error">{summary.assignments.error} errors</span>
              )}
            </div>
          </div>
          <div className="collector-stat-card">
            <div className="collector-stat-value">
              {(summary.assignments.total_events || 0).toLocaleString()}
            </div>
            <div className="collector-stat-label">Events Collected</div>
          </div>
        </div>
      )}

      {/* Collectors View */}
      {activeView === 'collectors' && (
        <div className="collector-main-content">
          {/* Filters */}
          <div className="collector-filters">
            <input
              type="text"
              placeholder="Search by hostname or agent ID..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="collector-search-input"
            />
            <select
              value={filterStatus}
              onChange={(e) => setFilterStatus(e.target.value)}
              className="collector-filter-select"
            >
              <option value="all">All Status</option>
              <option value="active">Active</option>
              <option value="inactive">Inactive</option>
              <option value="maintenance">Maintenance</option>
            </select>
            <select
              value={filterOS}
              onChange={(e) => setFilterOS(e.target.value)}
              className="collector-filter-select"
            >
              <option value="all">All OS</option>
              <option value="windows">Windows</option>
              <option value="linux">Linux</option>
              <option value="macos">macOS</option>
            </select>
          </div>

          {/* Collectors List */}
          <div className="collector-list-container">
            <div className={`collector-list ${selectedCollector ? 'with-detail' : ''}`}>
              {filteredCollectors.length === 0 ? (
                <div className="collector-empty-state">
                  <div className="collector-empty-icon">🖥️</div>
                  <h3>No collectors found</h3>
                  <p>
                    {collectors.length === 0
                      ? 'No log collectors have registered yet. Deploy agents to your endpoints to start collecting logs.'
                      : 'No collectors match your current filters.'}
                  </p>
                </div>
              ) : (
                filteredCollectors.map(collector => (
                  <div
                    key={collector.id}
                    className={`collector-card ${selectedCollector?.id === collector.id ? 'selected' : ''}`}
                    onClick={() => setSelectedCollector(collector)}
                  >
                    <div className="collector-card-header">
                      <div className="collector-card-icon">
                        {collector.os_type === 'windows' ? '🪟' :
                         collector.os_type === 'linux' ? '🐧' :
                         collector.os_type === 'macos' ? '🍎' : '🖥️'}
                      </div>
                      <div className="collector-card-info">
                        <div className="collector-card-hostname">{collector.hostname}</div>
                        <div className="collector-card-meta">
                          {collector.os_type} • {collector.ip_address || 'No IP'}
                        </div>
                      </div>
                      <StatusBadge status={collector.status} />
                    </div>
                    <div className="collector-card-stats">
                      <div className="collector-card-stat">
                        <span className="collector-card-stat-value">
                          {collector.source_assignments?.length || 0}
                        </span>
                        <span className="collector-card-stat-label">sources</span>
                      </div>
                      <div className="collector-card-stat">
                        <span className="collector-card-stat-value">
                          {((collector.events_received_total || 0) / 1000).toFixed(1)}k
                        </span>
                        <span className="collector-card-stat-label">events</span>
                      </div>
                    </div>
                    {collector.tags && collector.tags.length > 0 && (
                      <div className="collector-card-tags">
                        {collector.tags.slice(0, 3).map(tag => (
                          <span key={tag} className="collector-mini-tag">{tag}</span>
                        ))}
                        {collector.tags.length > 3 && (
                          <span className="collector-mini-tag">+{collector.tags.length - 3}</span>
                        )}
                      </div>
                    )}
                  </div>
                ))
              )}
            </div>

            {/* Detail Panel */}
            {selectedCollector && (
              <CollectorDetailPanel
                collector={selectedCollector}
                sourceTypes={sourceTypes}
                onUpdate={handleCollectorUpdate}
                onClose={() => setSelectedCollector(null)}
              />
            )}
          </div>
        </div>
      )}

      {/* Source Catalog View */}
      {activeView === 'sources' && (
        <div className="collector-source-catalog">
          <div className="collector-catalog-header">
            <h2>Available Log Source Types</h2>
            <p>These are the log source types that can be assigned to collectors</p>
          </div>

          {Object.entries(sourcesByCategory).map(([category, sources]) => {
            const catConfig = categoryConfig[category] || categoryConfig.custom;

            return (
              <div key={category} className="collector-category-section">
                <div className="collector-category-header" style={{ borderLeftColor: catConfig.color }}>
                  <span className="collector-category-icon">{catConfig.icon}</span>
                  <h3>{catConfig.label}</h3>
                  <span className="collector-category-count">{sources.length} sources</span>
                </div>

                <div className="collector-source-grid">
                  {sources.map(source => (
                    <div key={source.source_type} className="collector-source-card">
                      <div className="collector-source-card-header">
                        <span className="collector-source-card-name">{source.display_name}</span>
                        {source.is_builtin && (
                          <span className="collector-builtin-badge">Built-in</span>
                        )}
                      </div>
                      <p className="collector-source-card-desc">{source.description}</p>
                      <div className="collector-source-card-meta">
                        {source.vendor && (
                          <span className="collector-source-card-vendor">{source.vendor}</span>
                        )}
                        <span className="collector-source-card-parser">{source.parser_type}</span>
                        <span className="collector-source-card-index">→ {source.default_index_name}</span>
                      </div>
                      <div className="collector-source-card-platforms">
                        {source.supported_platforms?.map(p => (
                          <span key={p} className="collector-platform-badge">
                            {p === 'windows' ? '🪟' : p === 'linux' ? '🐧' : p === 'macos' ? '🍎' : '💻'} {p}
                          </span>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

export default CollectorManager;


