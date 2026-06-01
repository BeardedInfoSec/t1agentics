/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

import React, { useState, useEffect, useCallback } from 'react';
import { apiClient } from '../utils/api';
import { useToast } from './ui/Toast';

// Tab navigation component
const TabNav = ({ tabs, activeTab, onChange }) => (
  <div style={{
    display: 'flex',
    gap: 'var(--space-xs)',
    marginBottom: 'var(--space-xl)',
    background: 'var(--bg-secondary)',
    padding: 'var(--space-xs)',
    borderRadius: 'var(--radius-lg)',
    border: '1px solid var(--border-color)'
  }}>
    {tabs.map(tab => (
      <button
        key={tab.id}
        onClick={() => onChange(tab.id)}
        style={{
          padding: '0.6rem 1.25rem',
          background: activeTab === tab.id ? 'var(--primary)' : 'transparent',
          color: activeTab === tab.id ? '#0f172a' : 'var(--text-secondary)',
          border: 'none',
          borderRadius: 'var(--radius-md)',
          cursor: 'pointer',
          fontSize: 'var(--text-base)',
          fontWeight: activeTab === tab.id ? '600' : '400',
          transition: 'all var(--transition-base)',
          letterSpacing: '0.01em'
        }}
      >
        {tab.label}
      </button>
    ))}
  </div>
);

// Stat card component
const StatCard = ({ title, value, color = 'primary' }) => (
  <div style={{
    background: 'var(--glass-bg-solid)',
    border: '1px solid var(--glass-border)',
    borderRadius: 'var(--radius-lg)',
    padding: 'var(--space-lg)',
    textAlign: 'center',
    boxShadow: 'var(--glass-shadow)',
    transition: 'all var(--transition-base)'
  }}>
    <div style={{
      fontSize: 'var(--text-sm)',
      color: 'var(--text-muted)',
      marginBottom: 'var(--space-xs)',
      textTransform: 'uppercase',
      letterSpacing: '0.5px',
      fontWeight: '500'
    }}>
      {title}
    </div>
    <div style={{
      fontSize: 'var(--text-2xl)',
      fontWeight: '700',
      color: color === 'primary' ? 'var(--primary)' : color === 'danger' ? 'var(--danger)' : color
    }}>
      {value ?? '--'}
    </div>
  </div>
);

// ==================== DEDUPLICATION RULES TAB ====================
const DeduplicationRulesTab = () => {
  const toast = useToast();
  const [rules, setRules] = useState([]);
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [showAddModal, setShowAddModal] = useState(false);
  const [newRule, setNewRule] = useState({
    name: '',
    description: '',
    fingerprint_fields: 'source,category,title',
    window_minutes: 60,
    action: 'group',
    source_filter: '',
    category_filter: '',
    priority: 100
  });

  const fetchRules = useCallback(async () => {
    try {
      const [rulesRes, statsRes] = await Promise.all([
        apiClient.get(`/api/v1/deduplication/rules?include_disabled=true`),
        apiClient.get(`/api/v1/deduplication/stats`)
      ]);
      setRules(rulesRes.data);
      setStats(statsRes.data.stats);
    } catch (err) {
      console.error('Dedup rules fetch error:', err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchRules();
  }, [fetchRules]);

  const handleCreateRule = async () => {
    try {
      await apiClient.post(`/api/v1/deduplication/rules`, {
        ...newRule,
        fingerprint_fields: newRule.fingerprint_fields.split(',').map(f => f.trim()).filter(Boolean),
        source_filter: newRule.source_filter || null,
        category_filter: newRule.category_filter || null
      });

      setShowAddModal(false);
      setNewRule({
        name: '',
        description: '',
        fingerprint_fields: 'source,category,title',
        window_minutes: 60,
        action: 'group',
        source_filter: '',
        category_filter: '',
        priority: 100
      });
      fetchRules();
    } catch (err) {
      toast.error('Error creating rule: ' + (err.response?.data?.detail || err.message));
    }
  };

  const handleQuickAdd = async (type) => {
    try {
      await apiClient.post(`/api/v1/deduplication/rules/quick-add/${type}`, {});
      fetchRules();
    } catch (err) {
      toast.error('Error: ' + (err.response?.data?.detail || err.message));
    }
  };

  if (loading) {
    return <div style={{ padding: 'var(--space-2xl)', textAlign: 'center', color: 'var(--text-muted)' }}>Loading...</div>;
  }

  return (
    <div>
      {/* Stats */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))', gap: 'var(--space-lg)', marginBottom: 'var(--space-xl)' }}>
        <StatCard title="Total Rules" value={stats?.total_rules || 0} />
        <StatCard title="Active Rules" value={stats?.active_rules || 0} />
        <StatCard title="Total Matches" value={stats?.total_matches?.toLocaleString() || 0} />
        <StatCard title="Duplicates Suppressed" value={stats?.total_suppressed?.toLocaleString() || 0} color="danger" />
      </div>

      {/* Quick Add */}
      <div style={{
        background: 'var(--glass-bg-solid)',
        border: '1px solid var(--glass-border)',
        borderRadius: 'var(--radius-lg)',
        padding: 'var(--space-lg)',
        marginBottom: 'var(--space-xl)',
        boxShadow: 'var(--glass-shadow)'
      }}>
        <div style={{
          fontSize: 'var(--text-base)',
          fontWeight: '600',
          marginBottom: 'var(--space-md)',
          color: 'var(--text-primary)'
        }}>
          Quick Add Templates
        </div>
        <div style={{ display: 'flex', gap: 'var(--space-sm)', flexWrap: 'wrap' }}>
          <button onClick={() => handleQuickAdd('network-scan')} style={quickBtnStyle}>
            + Network Scan
          </button>
          <button onClick={() => handleQuickAdd('auth-failure')} style={quickBtnStyle}>
            + Auth Failure
          </button>
          <button onClick={() => handleQuickAdd('malware-detection')} style={quickBtnStyle}>
            + Malware Detection
          </button>
          <button onClick={() => setShowAddModal(true)} style={primaryBtnStyle}>
            + Custom Rule
          </button>
        </div>
      </div>

      {/* Rules Table */}
      <div style={{
        background: 'var(--glass-bg-solid)',
        border: '1px solid var(--glass-border)',
        borderRadius: 'var(--radius-lg)',
        overflow: 'hidden',
        boxShadow: 'var(--glass-shadow)'
      }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 'var(--text-base)' }}>
          <thead>
            <tr style={{ borderBottom: '1px solid var(--glass-border)', background: 'var(--bg-tertiary)' }}>
              <th style={thStyle}>Name</th>
              <th style={thStyle}>Fingerprint Fields</th>
              <th style={thStyle}>Window</th>
              <th style={thStyle}>Action</th>
              <th style={thStyle}>Matches</th>
              <th style={thStyle}>Suppressed</th>
              <th style={thStyle}>Status</th>
            </tr>
          </thead>
          <tbody>
            {rules.length === 0 ? (
              <tr>
                <td colSpan={7} style={{ padding: 'var(--space-2xl)', textAlign: 'center', color: 'var(--text-muted)' }}>
                  No deduplication rules configured. Use Quick Add to get started.
                </td>
              </tr>
            ) : (
              rules.map(rule => (
                <tr key={rule.id} style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                  <td style={tdStyle}>
                    <div style={{ fontWeight: '500', color: 'var(--text-primary)' }}>{rule.name}</div>
                    {rule.description && (
                      <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)', marginTop: '2px' }}>{rule.description}</div>
                    )}
                  </td>
                  <td style={tdStyle}>
                    <code style={{
                      fontSize: 'var(--text-sm)',
                      background: 'var(--bg-tertiary)',
                      padding: '2px 6px',
                      borderRadius: 'var(--radius-sm)',
                      fontFamily: 'var(--font-mono)'
                    }}>
                      {rule.fingerprint_fields?.join(', ')}
                    </code>
                  </td>
                  <td style={tdStyle}>{rule.window_minutes}m</td>
                  <td style={tdStyle}>
                    <span style={{
                      padding: '2px 8px',
                      borderRadius: 'var(--radius-full)',
                      fontSize: 'var(--text-sm)',
                      background: rule.action === 'suppress' ? 'var(--danger-light)' : 'var(--info-light)',
                      color: rule.action === 'suppress' ? 'var(--danger)' : 'var(--info)'
                    }}>
                      {rule.action}
                    </span>
                  </td>
                  <td style={tdStyle}>{rule.total_matches?.toLocaleString() || 0}</td>
                  <td style={tdStyle}>{rule.duplicates_suppressed?.toLocaleString() || 0}</td>
                  <td style={tdStyle}>
                    <span style={{
                      padding: '2px 8px',
                      borderRadius: 'var(--radius-full)',
                      fontSize: 'var(--text-sm)',
                      background: rule.enabled ? 'var(--success-light)' : 'rgba(107, 114, 128, 0.15)',
                      color: rule.enabled ? 'var(--success)' : 'var(--text-muted)'
                    }}>
                      {rule.enabled ? 'Active' : 'Disabled'}
                    </span>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Add Rule Modal */}
      {showAddModal && (
        <div style={modalOverlay}>
          <div style={modalContent}>
            <div style={modalHeader}>
              <h3 style={{ margin: 0, fontSize: '1.1rem', fontWeight: '600', color: 'var(--text-primary)' }}>
                Create Deduplication Rule
              </h3>
              <button onClick={() => setShowAddModal(false)} style={modalCloseBtn}>x</button>
            </div>

            <div style={modalBody}>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-lg)' }}>
                <div>
                  <label style={labelStyle}>Name *</label>
                  <input
                    type="text"
                    value={newRule.name}
                    onChange={e => setNewRule({ ...newRule, name: e.target.value })}
                    style={inputStyle}
                    placeholder="e.g., Network Scan Dedup"
                  />
                </div>

                <div>
                  <label style={labelStyle}>Description</label>
                  <input
                    type="text"
                    value={newRule.description}
                    onChange={e => setNewRule({ ...newRule, description: e.target.value })}
                    style={inputStyle}
                    placeholder="Optional description"
                  />
                </div>

                <div>
                  <label style={labelStyle}>Fingerprint Fields * (comma-separated)</label>
                  <input
                    type="text"
                    value={newRule.fingerprint_fields}
                    onChange={e => setNewRule({ ...newRule, fingerprint_fields: e.target.value })}
                    style={inputStyle}
                    placeholder="source, category, title"
                  />
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 'var(--space-lg)' }}>
                  <div>
                    <label style={labelStyle}>Time Window (minutes)</label>
                    <input
                      type="number"
                      value={newRule.window_minutes}
                      onChange={e => setNewRule({ ...newRule, window_minutes: parseInt(e.target.value) || 60 })}
                      style={inputStyle}
                      min={1}
                      max={10080}
                    />
                  </div>

                  <div>
                    <label style={labelStyle}>Action</label>
                    <select
                      value={newRule.action}
                      onChange={e => setNewRule({ ...newRule, action: e.target.value })}
                      style={inputStyle}
                    >
                      <option value="group">Group</option>
                      <option value="suppress">Suppress</option>
                      <option value="merge">Merge</option>
                      <option value="count_only">Count Only</option>
                    </select>
                  </div>
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 'var(--space-lg)' }}>
                  <div>
                    <label style={labelStyle}>Source Filter (optional)</label>
                    <input
                      type="text"
                      value={newRule.source_filter}
                      onChange={e => setNewRule({ ...newRule, source_filter: e.target.value })}
                      style={inputStyle}
                      placeholder="e.g., firewall-*"
                    />
                  </div>

                  <div>
                    <label style={labelStyle}>Category Filter (optional)</label>
                    <input
                      type="text"
                      value={newRule.category_filter}
                      onChange={e => setNewRule({ ...newRule, category_filter: e.target.value })}
                      style={inputStyle}
                      placeholder="e.g., network_scan"
                    />
                  </div>
                </div>
              </div>
            </div>

            <div style={modalFooter}>
              <button onClick={() => setShowAddModal(false)} style={cancelBtnStyle}>Cancel</button>
              <button onClick={handleCreateRule} style={saveBtnStyle} disabled={!newRule.name}>Create Rule</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

// ==================== EXCLUSION LIST TAB ====================
const ExclusionListTab = () => {
  const toast = useToast();
  const [exclusions, setExclusions] = useState([]);
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState({ type: '', category: '' });
  const [showAddModal, setShowAddModal] = useState(false);
  const [newExclusion, setNewExclusion] = useState({
    ioc_value: '',
    ioc_type: 'ip',
    match_type: 'exact',
    reason: '',
    category: 'custom'
  });

  const fetchExclusions = useCallback(async () => {
    try {
      let url = `/api/v1/exclusions?include_inactive=true`;
      if (filter.type) url += `&ioc_type=${filter.type}`;
      if (filter.category) url += `&category=${filter.category}`;

      const [exclRes, statsRes] = await Promise.all([
        apiClient.get(url),
        apiClient.get(`/api/v1/exclusions/stats`)
      ]);
      setExclusions(exclRes.data);
      setStats(statsRes.data);
    } catch (err) {
      console.error('Exclusions fetch error:', err);
    } finally {
      setLoading(false);
    }
  }, [filter]);

  useEffect(() => {
    fetchExclusions();
  }, [fetchExclusions]);

  const handleAddExclusion = async () => {
    try {
      await apiClient.post(`/api/v1/exclusions`, newExclusion);
      setShowAddModal(false);
      setNewExclusion({
        ioc_value: '',
        ioc_type: 'ip',
        match_type: 'exact',
        reason: '',
        category: 'custom'
      });
      fetchExclusions();
    } catch (err) {
      toast.error('Error: ' + (err.response?.data?.detail || err.message));
    }
  };

  const handleDelete = async (id) => {
    if (!window.confirm('Remove this exclusion?')) return;
    try {
      await apiClient.delete(`/api/v1/exclusions/${id}`);
      fetchExclusions();
    } catch (err) {
      toast.error('Error: ' + (err.response?.data?.detail || err.message));
    }
  };

  const handleQuickAdd = async (type) => {
    if (type === 'rfc1918') {
      // Add all RFC1918 ranges
      const ranges = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'];
      for (const cidr of ranges) {
        await apiClient.post(`/api/v1/exclusions/add-cidr?cidr=${encodeURIComponent(cidr)}&reason=RFC1918 Private Network&category=internal`, {});
      }
      fetchExclusions();
      return;
    }
    if (type === 'localhost') {
      await apiClient.post(`/api/v1/exclusions/add-cidr?cidr=127.0.0.0/8&reason=Localhost&category=internal`, {});
      fetchExclusions();
      return;
    }
  };

  if (loading) {
    return <div style={{ padding: 'var(--space-2xl)', textAlign: 'center', color: 'var(--text-muted)' }}>Loading...</div>;
  }

  return (
    <div>
      {/* Stats */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))', gap: 'var(--space-lg)', marginBottom: 'var(--space-xl)' }}>
        <StatCard title="Total Exclusions" value={stats?.total_exclusions || 0} />
        <StatCard title="Active" value={stats?.active_exclusions || 0} />
        <StatCard title="Total Hits" value={stats?.total_hits?.toLocaleString() || 0} />
        <StatCard title="By IP/CIDR" value={stats?.by_type?.ip || 0} />
      </div>

      {/* Quick Add */}
      <div style={{
        background: 'var(--glass-bg-solid)',
        border: '1px solid var(--glass-border)',
        borderRadius: 'var(--radius-lg)',
        padding: 'var(--space-lg)',
        marginBottom: 'var(--space-xl)',
        boxShadow: 'var(--glass-shadow)'
      }}>
        <div style={{
          fontSize: 'var(--text-base)',
          fontWeight: '600',
          marginBottom: 'var(--space-md)',
          color: 'var(--text-primary)'
        }}>
          Quick Add
        </div>
        <div style={{ display: 'flex', gap: 'var(--space-sm)', flexWrap: 'wrap' }}>
          <button onClick={() => handleQuickAdd('rfc1918')} style={quickBtnStyle}>
            + RFC1918 (Private IPs)
          </button>
          <button onClick={() => handleQuickAdd('localhost')} style={quickBtnStyle}>
            + Localhost
          </button>
          <button onClick={() => setShowAddModal(true)} style={primaryBtnStyle}>
            + Custom Exclusion
          </button>
        </div>
      </div>

      {/* Filters */}
      <div style={{ display: 'flex', gap: 'var(--space-lg)', marginBottom: 'var(--space-lg)' }}>
        <select
          value={filter.type}
          onChange={e => setFilter({ ...filter, type: e.target.value })}
          style={{ ...inputStyle, width: '150px' }}
        >
          <option value="">All Types</option>
          <option value="ip">IP</option>
          <option value="domain">Domain</option>
          <option value="cidr">CIDR</option>
          <option value="hash">Hash</option>
          <option value="email">Email</option>
        </select>
        <select
          value={filter.category}
          onChange={e => setFilter({ ...filter, category: e.target.value })}
          style={{ ...inputStyle, width: '150px' }}
        >
          <option value="">All Categories</option>
          <option value="internal">Internal</option>
          <option value="vendor">Vendor</option>
          <option value="false_positive">False Positive</option>
          <option value="whitelist">Whitelist</option>
          <option value="custom">Custom</option>
        </select>
      </div>

      {/* Exclusions Table */}
      <div style={{
        background: 'var(--glass-bg-solid)',
        border: '1px solid var(--glass-border)',
        borderRadius: 'var(--radius-lg)',
        overflow: 'hidden',
        boxShadow: 'var(--glass-shadow)'
      }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 'var(--text-base)' }}>
          <thead>
            <tr style={{ borderBottom: '1px solid var(--glass-border)', background: 'var(--bg-tertiary)' }}>
              <th style={thStyle}>Value</th>
              <th style={thStyle}>Type</th>
              <th style={thStyle}>Match</th>
              <th style={thStyle}>Category</th>
              <th style={thStyle}>Reason</th>
              <th style={thStyle}>Hits</th>
              <th style={thStyle}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {exclusions.length === 0 ? (
              <tr>
                <td colSpan={7} style={{ padding: 'var(--space-2xl)', textAlign: 'center', color: 'var(--text-muted)' }}>
                  No exclusions configured.
                </td>
              </tr>
            ) : (
              exclusions.map(excl => (
                <tr key={excl.id} style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                  <td style={tdStyle}>
                    <code style={{
                      fontSize: 'var(--text-base)',
                      fontFamily: 'var(--font-mono)',
                      background: 'var(--bg-tertiary)',
                      padding: '2px 6px',
                      borderRadius: 'var(--radius-sm)'
                    }}>
                      {excl.ioc_value}
                    </code>
                  </td>
                  <td style={tdStyle}>{excl.ioc_type}</td>
                  <td style={tdStyle}>{excl.match_type}</td>
                  <td style={tdStyle}>
                    <span style={{
                      padding: '2px 8px',
                      borderRadius: 'var(--radius-full)',
                      fontSize: 'var(--text-sm)',
                      background: excl.category === 'internal' ? 'var(--info-light)' :
                                 excl.category === 'false_positive' ? 'var(--warning-light)' :
                                 'rgba(107, 114, 128, 0.15)',
                      color: excl.category === 'internal' ? 'var(--info)' :
                             excl.category === 'false_positive' ? 'var(--warning)' : 'var(--text-muted)'
                    }}>
                      {excl.category}
                    </span>
                  </td>
                  <td style={{ ...tdStyle, maxWidth: '200px', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                    {excl.reason || '-'}
                  </td>
                  <td style={tdStyle}>{excl.hit_count || 0}</td>
                  <td style={tdStyle}>
                    <button
                      onClick={() => handleDelete(excl.id)}
                      style={{
                        padding: '4px 8px',
                        background: 'var(--danger-light)',
                        border: '1px solid rgba(239, 68, 68, 0.3)',
                        borderRadius: 'var(--radius-sm)',
                        color: 'var(--danger)',
                        cursor: 'pointer',
                        fontSize: 'var(--text-sm)',
                        transition: 'all var(--transition-fast)'
                      }}
                    >
                      Remove
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Add Exclusion Modal */}
      {showAddModal && (
        <div style={modalOverlay}>
          <div style={modalContent}>
            <div style={modalHeader}>
              <h3 style={{ margin: 0, fontSize: '1.1rem', fontWeight: '600', color: 'var(--text-primary)' }}>
                Add Exclusion
              </h3>
              <button onClick={() => setShowAddModal(false)} style={modalCloseBtn}>x</button>
            </div>

            <div style={modalBody}>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-lg)' }}>
                <div>
                  <label style={labelStyle}>IOC Value *</label>
                  <input
                    type="text"
                    value={newExclusion.ioc_value}
                    onChange={e => setNewExclusion({ ...newExclusion, ioc_value: e.target.value })}
                    style={inputStyle}
                    placeholder="e.g., 192.168.0.0/16 or *.internal.corp"
                  />
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 'var(--space-lg)' }}>
                  <div>
                    <label style={labelStyle}>IOC Type</label>
                    <select
                      value={newExclusion.ioc_type}
                      onChange={e => setNewExclusion({ ...newExclusion, ioc_type: e.target.value })}
                      style={inputStyle}
                    >
                      <option value="ip">IP</option>
                      <option value="domain">Domain</option>
                      <option value="cidr">CIDR</option>
                      <option value="hash">Hash</option>
                      <option value="email">Email</option>
                      <option value="regex">Regex</option>
                    </select>
                  </div>

                  <div>
                    <label style={labelStyle}>Match Type</label>
                    <select
                      value={newExclusion.match_type}
                      onChange={e => setNewExclusion({ ...newExclusion, match_type: e.target.value })}
                      style={inputStyle}
                    >
                      <option value="exact">Exact</option>
                      <option value="prefix">Prefix</option>
                      <option value="suffix">Suffix</option>
                      <option value="contains">Contains</option>
                      <option value="cidr">CIDR</option>
                      <option value="regex">Regex</option>
                    </select>
                  </div>
                </div>

                <div>
                  <label style={labelStyle}>Category</label>
                  <select
                    value={newExclusion.category}
                    onChange={e => setNewExclusion({ ...newExclusion, category: e.target.value })}
                    style={inputStyle}
                  >
                    <option value="internal">Internal</option>
                    <option value="vendor">Vendor</option>
                    <option value="false_positive">False Positive</option>
                    <option value="whitelist">Whitelist</option>
                    <option value="custom">Custom</option>
                  </select>
                </div>

                <div>
                  <label style={labelStyle}>Reason</label>
                  <input
                    type="text"
                    value={newExclusion.reason}
                    onChange={e => setNewExclusion({ ...newExclusion, reason: e.target.value })}
                    style={inputStyle}
                    placeholder="Why is this excluded?"
                  />
                </div>
              </div>
            </div>

            <div style={modalFooter}>
              <button onClick={() => setShowAddModal(false)} style={cancelBtnStyle}>Cancel</button>
              <button onClick={handleAddExclusion} style={saveBtnStyle} disabled={!newExclusion.ioc_value}>Add Exclusion</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

// ==================== MAIN COMPONENT ====================
const AlertTuning = () => {
  const [activeTab, setActiveTab] = useState('deduplication');

  const tabs = [
    { id: 'deduplication', label: 'Deduplication Rules' },
    { id: 'exclusions', label: 'Exclusion List' }
  ];

  return (
    <div style={{ padding: 'var(--space-xl)', maxWidth: '1400px', margin: '0 auto' }}>
      {/* Header */}
      <div style={{ marginBottom: 'var(--space-xl)' }}>
        <h1 style={{
          margin: 0,
          fontSize: 'var(--text-2xl)',
          color: 'var(--text-primary)',
          fontWeight: '700'
        }}>
          Alert Tuning
        </h1>
        <p style={{
          margin: 'var(--space-xs) 0 0 0',
          fontSize: 'var(--text-base)',
          color: 'var(--text-secondary)'
        }}>
          Configure deduplication rules and IOC exclusions to reduce alert noise
        </p>
      </div>

      <TabNav tabs={tabs} activeTab={activeTab} onChange={setActiveTab} />

      {activeTab === 'deduplication' && <DeduplicationRulesTab />}
      {activeTab === 'exclusions' && <ExclusionListTab />}
    </div>
  );
};

// ==================== STYLES ====================
const thStyle = {
  padding: '0.6rem 0.75rem',
  textAlign: 'left',
  color: 'var(--text-secondary)',
  fontWeight: '600',
  fontSize: 'var(--text-sm)',
  textTransform: 'uppercase',
  letterSpacing: '0.5px'
};

const tdStyle = {
  padding: '0.5rem 0.75rem',
  color: 'var(--text-primary)',
  fontSize: 'var(--text-base)'
};

const quickBtnStyle = {
  padding: '0.5rem 1rem',
  background: 'var(--bg-tertiary)',
  border: '1px solid var(--border-color)',
  borderRadius: 'var(--radius-md)',
  color: 'var(--text-secondary)',
  cursor: 'pointer',
  fontSize: 'var(--text-base)',
  transition: 'all var(--transition-base)'
};

const primaryBtnStyle = {
  padding: '0.5rem 1rem',
  background: 'var(--btn-glass-gradient)',
  border: '1px solid var(--glass-border)',
  borderRadius: 'var(--radius-md)',
  color: '#0f172a',
  cursor: 'pointer',
  fontSize: 'var(--text-base)',
  fontWeight: '600',
  transition: 'all var(--transition-base)',
  boxShadow: '0 2px 10px rgba(60, 179, 113, 0.2)'
};

const modalOverlay = {
  position: 'fixed',
  top: 0,
  left: 0,
  right: 0,
  bottom: 0,
  background: 'rgba(0, 0, 0, 0.75)',
  display: 'flex',
  alignItems: 'center',
  justifyContent: 'center',
  zIndex: 'var(--z-modal)',
  padding: 'var(--space-lg)',
  backdropFilter: 'blur(8px)'
};

const modalContent = {
  background: 'var(--glass-bg-solid)',
  borderRadius: 'var(--radius-xl)',
  width: '90%',
  maxWidth: '500px',
  maxHeight: '90vh',
  overflow: 'auto',
  boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.9), 0 0 20px rgba(60, 179, 113, 0.15)',
  border: '1px solid var(--glass-border)',
  backdropFilter: 'blur(20px)'
};

const modalHeader = {
  display: 'flex',
  justifyContent: 'space-between',
  alignItems: 'center',
  padding: '1.25rem 1.5rem',
  borderBottom: '1px solid var(--glass-border)',
  background: 'linear-gradient(135deg, rgba(30, 41, 59, 0.6) 0%, rgba(15, 23, 42, 0.5) 100%)',
  borderRadius: 'var(--radius-xl) var(--radius-xl) 0 0'
};

const modalCloseBtn = {
  background: 'transparent',
  border: 'none',
  color: 'var(--text-muted)',
  fontSize: '1.25rem',
  cursor: 'pointer',
  padding: 'var(--space-xs)',
  borderRadius: 'var(--radius-md)',
  lineHeight: 1,
  transition: 'color var(--transition-fast)'
};

const modalBody = {
  padding: 'var(--space-xl)'
};

const modalFooter = {
  display: 'flex',
  justifyContent: 'flex-end',
  gap: 'var(--space-md)',
  padding: '1rem 1.5rem',
  borderTop: '1px solid var(--glass-border)',
  background: 'linear-gradient(135deg, rgba(30, 41, 59, 0.6) 0%, rgba(15, 23, 42, 0.5) 100%)',
  borderRadius: '0 0 var(--radius-xl) var(--radius-xl)'
};

const labelStyle = {
  display: 'block',
  fontSize: 'var(--text-base)',
  fontWeight: '500',
  color: 'var(--text-secondary)',
  marginBottom: 'var(--space-xs)'
};

const inputStyle = {
  width: '100%',
  padding: '0.6rem 0.75rem',
  background: 'var(--bg-tertiary)',
  border: '1px solid var(--border-color)',
  borderRadius: 'var(--radius-md)',
  color: 'var(--text-primary)',
  fontSize: 'var(--text-base)',
  transition: 'border-color var(--transition-fast), box-shadow var(--transition-fast)',
  boxSizing: 'border-box'
};

const cancelBtnStyle = {
  padding: '0.5rem 1rem',
  background: 'transparent',
  border: '1px solid var(--border-color)',
  borderRadius: 'var(--radius-md)',
  color: 'var(--text-secondary)',
  cursor: 'pointer',
  fontSize: 'var(--text-base)',
  transition: 'all var(--transition-fast)'
};

const saveBtnStyle = {
  padding: '0.5rem 1rem',
  background: 'var(--btn-glass-gradient)',
  border: '1px solid var(--glass-border)',
  borderRadius: 'var(--radius-md)',
  color: '#0f172a',
  cursor: 'pointer',
  fontSize: 'var(--text-base)',
  fontWeight: '600',
  transition: 'all var(--transition-base)',
  boxShadow: '0 2px 10px rgba(60, 179, 113, 0.2)'
};

export default AlertTuning;
