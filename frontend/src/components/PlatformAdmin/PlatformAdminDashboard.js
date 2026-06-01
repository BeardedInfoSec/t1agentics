/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

import React, { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import PlatformTokenUsage from './PlatformTokenUsage';
import './PlatformAdminDashboard.css';

const API_BASE_URL = process.env.REACT_APP_API_URL || '';

// In-memory token storage — survives navigation but not page refresh (security tradeoff)
let _platformAdminToken = null;
let _platformAdmin = null;

function getCsrfToken() {
  const match = document.cookie.match(/(?:^|;\s*)t1_csrf=([^;]*)/);
  return match ? decodeURIComponent(match[1]) : '';
}

function PlatformAdminDashboard() {
  const navigate = useNavigate();
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [admin, setAdmin] = useState(null);
  const [activeTab, setActiveTab] = useState('overview');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);


  // Data state
  const [overview, setOverview] = useState(null);
  const [tenants, setTenants] = useState([]);
  const [licenses, setLicenses] = useState([]);
  const [expiringLicenses, setExpiringLicenses] = useState([]);
  const [auditLog, setAuditLog] = useState([]);
  const [selectedTenant, setSelectedTenant] = useState(null);

  // Filters
  const [tenantSearch, setTenantSearch] = useState('');
  const [tenantStatusFilter, setTenantStatusFilter] = useState('');
  const [tenantPlanFilter, setTenantPlanFilter] = useState('');

  // Overview - Most Active Tenants filters
  const [overviewDays, setOverviewDays] = useState(1);
  const [overviewSearch, setOverviewSearch] = useState('');
  const [overviewPage, setOverviewPage] = useState(0);
  const [overviewSortDir, setOverviewSortDir] = useState('desc');

  // Create Tenant Modal
  const [showCreateTenantModal, setShowCreateTenantModal] = useState(false);
  const [createTenantForm, setCreateTenantForm] = useState({
    slug: '',
    name: '',
    plan: 'community',
    expires_in_days: '',
    admin_email: '',
    admin_name: '',
  });
  const [createTenantLoading, setCreateTenantLoading] = useState(false);
  const [createTenantError, setCreateTenantError] = useState(null);

  // Generate License Modal
  const [showGenerateLicenseModal, setShowGenerateLicenseModal] = useState(false);
  const [generateLicenseForm, setGenerateLicenseForm] = useState({
    tenant_id: '',
    tier: 'professional',
    expires_in_days: '',
  });
  const [generateLicenseLoading, setGenerateLicenseLoading] = useState(false);
  const [generateLicenseError, setGenerateLicenseError] = useState(null);
  const [generatedLicense, setGeneratedLicense] = useState(null);

  // Delete Tenant Modal
  const [showDeleteTenantModal, setShowDeleteTenantModal] = useState(false);
  const [deleteTenantTarget, setDeleteTenantTarget] = useState(null);
  const [deleteTenantConfirmSlug, setDeleteTenantConfirmSlug] = useState('');
  const [deleteTenantLoading, setDeleteTenantLoading] = useState(false);
  const [deleteTenantError, setDeleteTenantError] = useState(null);

  // Upgrade License Modal
  const [showUpgradeModal, setShowUpgradeModal] = useState(false);
  const [upgradeTarget, setUpgradeTarget] = useState(null);
  const [upgradeTier, setUpgradeTier] = useState('professional');
  const [upgradeExpiresDays, setUpgradeExpiresDays] = useState('');
  const [upgradeLoading, setUpgradeLoading] = useState(false);

  // Usage expansion in tenant detail
  const [expandedUsage, setExpandedUsage] = useState(null);

  // Toast notification
  const [toast, setToast] = useState(null);
  const showToast = (message, type = 'success') => {
    setToast({ message, type });
    setTimeout(() => setToast(null), 5000);
  };

  // Check for existing token or try to elevate from tenant session
  useEffect(() => {
    const checkAuth = async () => {
      const token = _platformAdminToken;
      const savedAdmin = _platformAdmin;

      // If we have an existing token, verify it's still valid
      if (token && savedAdmin) {
        try {
          const verifyResponse = await fetch(`${API_BASE_URL}/api/v1/platform/me`, {
            headers: { 'Authorization': `Bearer ${token}` },
          });

          if (verifyResponse.ok) {
            setIsAuthenticated(true);
            setAdmin(savedAdmin);
            setLoading(false);
            return;
          } else {
            // Token is invalid/expired - clear it
            _platformAdminToken = null;
            _platformAdmin = null;
          }
        } catch (err) {
          // Token verification failed - clear it
          _platformAdminToken = null;
          _platformAdmin = null;
        }
      }

      // Try to elevate from tenant session (for platform owner tenant admins)
      try {
        const response = await fetch(`${API_BASE_URL}/api/v1/platform/elevate`, {
          method: 'POST',
          credentials: 'include',
          headers: { 'Content-Type': 'application/json' },
        });

        if (response.ok) {
          const data = await response.json();
          _platformAdminToken = data.token;
          _platformAdmin = data.admin;
          setIsAuthenticated(true);
          setAdmin(data.admin);
          setLoading(false);
          return;
        }
      } catch (err) {
        // Elevation failed
      }

      // Not authenticated and can't elevate — redirect to login
      navigate('/login', { replace: true });
      return;
    };

    checkAuth();
  }, []);

  const getAuthHeaders = () => ({
    'Authorization': `Bearer ${_platformAdminToken}`,
    'Content-Type': 'application/json',
    'X-CSRF-Token': getCsrfToken(),
  });

  const handleLogout = () => {
    _platformAdminToken = null;
    _platformAdmin = null;
    setIsAuthenticated(false);
    setAdmin(null);
    setOverview(null);
    setTenants([]);
  };

  // Fetch overview data
  const fetchOverview = useCallback(async () => {
    try {
      const params = new URLSearchParams();
      params.append('days', overviewDays);
      if (overviewSearch.trim()) params.append('search', overviewSearch.trim());
      const response = await fetch(`${API_BASE_URL}/api/v1/platform/analytics/overview?${params}`, {
        headers: getAuthHeaders(),
      });
      if (!response.ok) throw new Error('Failed to fetch overview');
      const data = await response.json();
      setOverview(data);
    } catch (err) {
      setError(err.message);
    }
  }, [overviewDays, overviewSearch]);

  // Fetch tenants
  const fetchTenants = useCallback(async () => {
    try {
      const params = new URLSearchParams();
      if (tenantSearch) params.append('search', tenantSearch);
      if (tenantStatusFilter) params.append('status', tenantStatusFilter);
      if (tenantPlanFilter) params.append('plan', tenantPlanFilter);

      const response = await fetch(
        `${API_BASE_URL}/api/v1/platform/tenants?${params}`,
        { headers: getAuthHeaders() }
      );
      if (!response.ok) throw new Error('Failed to fetch tenants');
      const data = await response.json();
      setTenants(data.tenants || []);
    } catch (err) {
      setError(err.message);
    }
  }, [tenantSearch, tenantStatusFilter, tenantPlanFilter]);

  // Fetch licenses
  const fetchLicenses = useCallback(async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/api/v1/platform/licenses`, {
        headers: getAuthHeaders(),
      });
      if (!response.ok) throw new Error('Failed to fetch licenses');
      const data = await response.json();
      setLicenses(data.licenses || []);
    } catch (err) {
      setError(err.message);
    }
  }, []);

  // Fetch audit log
  const fetchAuditLog = useCallback(async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/api/v1/platform/audit-log?limit=50`, {
        headers: getAuthHeaders(),
      });
      if (!response.ok) throw new Error('Failed to fetch audit log');
      const data = await response.json();
      setAuditLog(data.audit_log || []);
    } catch (err) {
      setError(err.message);
    }
  }, []);

  // Fetch expiring licenses (within 30 days)
  const fetchExpiringLicenses = useCallback(async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/api/v1/platform/licenses/expiring?days=30`, {
        headers: getAuthHeaders(),
      });
      if (!response.ok) throw new Error('Failed to fetch expiring licenses');
      const data = await response.json();
      setExpiringLicenses(data.licenses || []);
    } catch (err) {
      // Silent fail - not critical
    }
  }, []);

  // Load data when tab changes
  useEffect(() => {
    if (!isAuthenticated) return;

    switch (activeTab) {
      case 'overview':
        fetchOverview();
        fetchExpiringLicenses();
        break;
      case 'tenants':
        fetchTenants();
        break;
      case 'licenses':
        fetchLicenses();
        break;
      case 'audit':
        fetchAuditLog();
        break;
      default:
        break;
    }
  }, [isAuthenticated, activeTab, fetchOverview, fetchTenants, fetchLicenses, fetchAuditLog, fetchExpiringLicenses]);

  // Tenant actions
  const suspendTenant = async (tenantId, reason) => {
    if (!window.confirm('Are you sure you want to suspend this tenant?')) return;

    try {
      const response = await fetch(
        `${API_BASE_URL}/api/v1/platform/tenants/${tenantId}/suspend?reason=${encodeURIComponent(reason || 'Administrative action')}`,
        { method: 'POST', headers: getAuthHeaders() }
      );
      if (!response.ok) throw new Error('Failed to suspend tenant');
      fetchTenants();
      showToast('Tenant suspended');
    } catch (err) {
      showToast(err.message, 'error');
    }
  };

  const toggleByoAllowed = async (tenantId, allowed) => {
    const action = allowed ? 'allow' : 'disallow';
    if (!window.confirm(`${allowed ? 'Allow' : 'Disallow'} this tenant to bring their own LLM?`)) return;
    try {
      const response = await fetch(
        `${API_BASE_URL}/api/v1/platform/tenants/${tenantId}/byo-allowed`,
        {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
          body: JSON.stringify({ allowed }),
        },
      );
      if (!response.ok) throw new Error(`Failed to ${action} BYO`);
      fetchTenants();
      showToast(`BYO ${allowed ? 'allowed' : 'disallowed'}`);
    } catch (err) {
      showToast(err.message, 'error');
    }
  };

  const reactivateTenant = async (tenantId) => {
    try {
      const response = await fetch(
        `${API_BASE_URL}/api/v1/platform/tenants/${tenantId}/reactivate`,
        { method: 'POST', headers: getAuthHeaders() }
      );
      if (!response.ok) throw new Error('Failed to reactivate tenant');
      fetchTenants();
      showToast('Tenant reactivated');
    } catch (err) {
      showToast(err.message, 'error');
    }
  };

  const viewTenantDetails = async (tenantId) => {
    try {
      const response = await fetch(
        `${API_BASE_URL}/api/v1/platform/tenants/${tenantId}`,
        { headers: getAuthHeaders() }
      );
      if (!response.ok) throw new Error('Failed to fetch tenant details');
      const data = await response.json();
      setSelectedTenant(data);
      setExpandedUsage(null);
    } catch (err) {
      showToast(err.message, 'error');
    }
  };

  const openDeleteTenantModal = (tenant) => {
    setDeleteTenantTarget(tenant);
    setDeleteTenantConfirmSlug('');
    setDeleteTenantError(null);
    setShowDeleteTenantModal(true);
  };

  const handleDeleteTenant = async (e) => {
    e.preventDefault();
    if (!deleteTenantTarget) return;

    if (deleteTenantConfirmSlug !== deleteTenantTarget.slug) {
      setDeleteTenantError(`Please type "${deleteTenantTarget.slug}" to confirm deletion`);
      return;
    }

    setDeleteTenantLoading(true);
    setDeleteTenantError(null);

    try {
      const response = await fetch(
        `${API_BASE_URL}/api/v1/platform/tenants/${deleteTenantTarget.id}`,
        {
          method: 'DELETE',
          headers: getAuthHeaders(),
          body: JSON.stringify({ confirm_slug: deleteTenantConfirmSlug }),
        }
      );

      if (!response.ok) {
        const data = await response.json();
        throw new Error(data.detail || 'Failed to delete tenant');
      }

      const result = await response.json();
      setShowDeleteTenantModal(false);
      setSelectedTenant(null);
      setDeleteTenantTarget(null);
      fetchTenants();
      fetchOverview();
      showToast(`Tenant "${result.deleted_data.tenant_name}" has been permanently deleted.`);
    } catch (err) {
      setDeleteTenantError(err.message);
    } finally {
      setDeleteTenantLoading(false);
    }
  };

  // License actions
  const openUpgradeModal = (license) => {
    setUpgradeTarget(license);
    setUpgradeTier('professional');
    setUpgradeExpiresDays('365');
    setUpgradeLoading(false);
    setShowUpgradeModal(true);
  };

  const handleUpgradeLicense = async (e) => {
    e.preventDefault();
    if (!upgradeTarget) return;
    setUpgradeLoading(true);

    try {
      const payload = {
        tenant_id: upgradeTarget.tenant_id,
        tier: upgradeTier,
      };
      if (upgradeExpiresDays) {
        payload.expires_in_days = parseInt(upgradeExpiresDays, 10);
      }

      const response = await fetch(`${API_BASE_URL}/api/v1/platform/licenses`, {
        method: 'POST',
        headers: getAuthHeaders(),
        body: JSON.stringify(payload),
      });
      if (!response.ok) {
        const data = await response.json();
        throw new Error(data.detail || 'Failed to upgrade license');
      }
      setShowUpgradeModal(false);
      setUpgradeTarget(null);
      fetchLicenses();
      fetchTenants();
      showToast(`License upgraded to ${upgradeTier}`);
    } catch (err) {
      showToast(err.message, 'error');
    } finally {
      setUpgradeLoading(false);
    }
  };

  const revokeLicense = async (licenseId, reason) => {
    if (!window.confirm('Revoke this license? Tenant will be downgraded to Community.')) return;

    try {
      const response = await fetch(
        `${API_BASE_URL}/api/v1/platform/licenses/${licenseId}/revoke?reason=${encodeURIComponent(reason || 'Administrative action')}`,
        { method: 'POST', headers: getAuthHeaders() }
      );
      if (!response.ok) throw new Error('Failed to revoke license');
      fetchLicenses();
      fetchTenants();
    } catch (err) {
      showToast(err.message, 'error');
    }
  };

  // Create tenant
  const handleCreateTenant = async (e) => {
    e.preventDefault();
    setCreateTenantLoading(true);
    setCreateTenantError(null);

    try {
      const payload = {
        slug: createTenantForm.slug.toLowerCase().trim(),
        name: createTenantForm.name.trim(),
        plan: createTenantForm.plan,
      };
      if (createTenantForm.expires_in_days) {
        payload.expires_in_days = parseInt(createTenantForm.expires_in_days, 10);
      }
      if (createTenantForm.admin_email) {
        payload.admin_email = createTenantForm.admin_email.trim();
        payload.admin_name = createTenantForm.admin_name.trim() || null;
      }

      const response = await fetch(`${API_BASE_URL}/api/v1/platform/tenants`, {
        method: 'POST',
        headers: getAuthHeaders(),
        body: JSON.stringify(payload),
      });

      if (!response.ok) {
        const data = await response.json();
        throw new Error(data.detail || 'Failed to create tenant');
      }

      const data = await response.json();
      showToast(`Tenant "${data.name}" created successfully (${data.plan})`);
      setShowCreateTenantModal(false);
      setCreateTenantForm({ slug: '', name: '', plan: 'community', expires_in_days: '', admin_email: '', admin_name: '' });
      fetchTenants();
      fetchLicenses();
    } catch (err) {
      setCreateTenantError(err.message);
    } finally {
      setCreateTenantLoading(false);
    }
  };

  // Generate license
  const handleGenerateLicense = async (e) => {
    e.preventDefault();
    setGenerateLicenseLoading(true);
    setGenerateLicenseError(null);
    setGeneratedLicense(null);

    try {
      const payload = {
        tenant_id: generateLicenseForm.tenant_id,
        tier: generateLicenseForm.tier,
      };
      if (generateLicenseForm.expires_in_days) {
        payload.expires_in_days = parseInt(generateLicenseForm.expires_in_days, 10);
      }

      const response = await fetch(`${API_BASE_URL}/api/v1/platform/licenses`, {
        method: 'POST',
        headers: getAuthHeaders(),
        body: JSON.stringify(payload),
      });

      if (!response.ok) {
        const data = await response.json();
        throw new Error(data.detail || 'Failed to generate license');
      }

      const data = await response.json();
      setGeneratedLicense(data);
      fetchLicenses();
      fetchTenants();
    } catch (err) {
      setGenerateLicenseError(err.message);
    } finally {
      setGenerateLicenseLoading(false);
    }
  };

  const closeGenerateLicenseModal = () => {
    setShowGenerateLicenseModal(false);
    setGenerateLicenseForm({ tenant_id: '', tier: 'professional', expires_in_days: '' });
    setGeneratedLicense(null);
    setGenerateLicenseError(null);
  };

  // Open Generate License modal (fetch tenants if needed)
  const openGenerateLicenseModal = async () => {
    setShowGenerateLicenseModal(true);
    if (tenants.length === 0) {
      try {
        const response = await fetch(
          `${API_BASE_URL}/api/v1/platform/tenants?limit=100`,
          { headers: getAuthHeaders() }
        );
        if (response.ok) {
          const data = await response.json();
          setTenants(data.tenants || []);
        }
      } catch (err) {
        // Silent fail - user will see empty dropdown
      }
    }
  };

  // Loading state
  if (loading) {
    return (
      <div className="pa-loading">
        <div className="pa-spinner"></div>
        <p>Loading Platform Admin...</p>
      </div>
    );
  }

  // Not authenticated — redirect is handled in useEffect, show nothing while it fires
  if (!isAuthenticated) {
    return null;
  }

  // Main dashboard
  return (
    <div className="pa-dashboard">
      {/* Header */}
      <header className="pa-header">
        <div className="pa-header-left">
          <h1>T1 Agentics Platform Admin</h1>
        </div>
        <div className="pa-header-right">
          <a href="/dashboard" className="pa-dashboard-link">Dashboard</a>
          <span className="pa-admin-name">{admin?.name || admin?.email}</span>
          <button onClick={handleLogout} className="pa-logout-btn">Logout</button>
        </div>
      </header>

      {/* Navigation */}
      <nav className="pa-nav">
        <button
          className={`pa-nav-btn ${activeTab === 'overview' ? 'active' : ''}`}
          onClick={() => setActiveTab('overview')}
        >
          Overview
        </button>
        <button
          className={`pa-nav-btn ${activeTab === 'tenants' ? 'active' : ''}`}
          onClick={() => setActiveTab('tenants')}
        >
          Tenants
        </button>
        <button
          className={`pa-nav-btn ${activeTab === 'licenses' ? 'active' : ''}`}
          onClick={() => setActiveTab('licenses')}
        >
          Licenses
        </button>
        <button
          className={`pa-nav-btn ${activeTab === 'audit' ? 'active' : ''}`}
          onClick={() => setActiveTab('audit')}
        >
          Audit Log
        </button>
        <button
          className={`pa-nav-btn ${activeTab === 'token-usage' ? 'active' : ''}`}
          onClick={() => setActiveTab('token-usage')}
        >
          Token Usage
        </button>
      </nav>

      {/* Content */}
      <main className="pa-content">
        {error && <div className="pa-error">{error}</div>}

        {/* Overview Tab */}
        {activeTab === 'overview' && overview && (
          <div className="pa-overview">
            <div className="pa-stats-grid">
              <div className="pa-stat-card">
                <div className="pa-stat-value">{overview.stats.active_tenants}</div>
                <div className="pa-stat-label">Active Tenants</div>
              </div>
              <div className="pa-stat-card">
                <div className="pa-stat-value">{overview.stats.suspended_tenants}</div>
                <div className="pa-stat-label">Suspended</div>
              </div>
              <div className="pa-stat-card">
                <div className="pa-stat-value">{overview.stats.new_tenants_30d}</div>
                <div className="pa-stat-label">New (30d)</div>
              </div>
              <div className="pa-stat-card">
                <div className="pa-stat-value">{overview.stats.total_users}</div>
                <div className="pa-stat-label">Total Users</div>
              </div>
              <div className="pa-stat-card">
                <div className="pa-stat-value">{overview.stats.total_alerts?.toLocaleString()}</div>
                <div className="pa-stat-label">Total Alerts</div>
              </div>
              <div className="pa-stat-card">
                <div className="pa-stat-value">{overview.stats.total_playbooks}</div>
                <div className="pa-stat-label">Total Playbooks</div>
              </div>
            </div>

            {/* Expiring Licenses Alert */}
            {expiringLicenses.length > 0 && (
              <div className="pa-alert pa-alert-warning">
                <div className="pa-alert-header">
                  <span className="pa-alert-icon">⚠</span>
                  <span className="pa-alert-title">{expiringLicenses.length} License{expiringLicenses.length > 1 ? 's' : ''} Expiring Soon</span>
                </div>
                <div className="pa-alert-body">
                  <table className="pa-table pa-table-compact">
                    <thead>
                      <tr>
                        <th>Tenant</th>
                        <th>Tier</th>
                        <th>Days Remaining</th>
                        <th>Expires</th>
                      </tr>
                    </thead>
                    <tbody>
                      {expiringLicenses.map((license) => (
                        <tr key={license.license_id}>
                          <td>{license.tenant_name} <span className="pa-slug">({license.tenant_slug})</span></td>
                          <td><span className={`pa-badge tier-${license.tier}`}>{license.tier}</span></td>
                          <td className={license.days_remaining <= 7 ? 'pa-text-danger' : license.days_remaining <= 14 ? 'pa-text-warning' : ''}>
                            {license.days_remaining} day{license.days_remaining !== 1 ? 's' : ''}
                          </td>
                          <td>{new Date(license.expires_at).toLocaleDateString()}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            <div className="pa-section">
              <h2>License Distribution</h2>
              <div className="pa-license-dist">
                {overview.license_distribution?.map((item) => (
                  <div key={item.tier} className={`pa-license-bar tier-${item.tier}`}>
                    <span className="pa-license-tier">{item.tier}</span>
                    <span className="pa-license-count">{item.count}</span>
                  </div>
                ))}
              </div>
            </div>

            <div className="pa-section">
              <h2>Most Active Tenants</h2>
              <div className="pa-filters">
                <input
                  type="text"
                  className="pa-search"
                  placeholder="Search tenants..."
                  value={overviewSearch}
                  onChange={(e) => { setOverviewSearch(e.target.value); setOverviewPage(0); }}
                />
                <select
                  value={overviewDays}
                  onChange={(e) => { setOverviewDays(Number(e.target.value)); setOverviewPage(0); }}
                >
                  <option value={1}>Last 24 hours</option>
                  <option value={7}>Last 7 days</option>
                  <option value={30}>Last 30 days</option>
                  <option value={90}>Last 90 days</option>
                  <option value={180}>Last 180 days</option>
                  <option value={365}>Last 365 days</option>
                </select>
                <button onClick={fetchOverview} className="pa-btn">Refresh</button>
              </div>
              {(() => {
                const allTenants = overview.most_active_tenants || [];
                const sorted = [...allTenants].sort((a, b) =>
                  overviewSortDir === 'desc' ? b.alert_count - a.alert_count : a.alert_count - b.alert_count
                );
                const pageSize = 10;
                const totalPages = Math.max(1, Math.ceil(sorted.length / pageSize));
                const paged = sorted.slice(overviewPage * pageSize, (overviewPage + 1) * pageSize);

                return paged.length > 0 ? (
                  <>
                    <table className="pa-table">
                      <thead>
                        <tr>
                          <th>Tenant</th>
                          <th>Plan</th>
                          <th
                            className="pa-sortable"
                            onClick={() => setOverviewSortDir((d) => d === 'desc' ? 'asc' : 'desc')}
                          >
                            Alerts
                            <span
                              className="pa-sort-icon active"
                              dangerouslySetInnerHTML={{ __html: overviewSortDir === 'asc' ? '&#9650;' : '&#9660;' }}
                            />
                          </th>
                        </tr>
                      </thead>
                      <tbody>
                        {paged.map((tenant) => (
                          <tr key={tenant.slug}>
                            <td>{tenant.name} <span className="pa-slug">({tenant.slug})</span></td>
                            <td><span className={`pa-badge plan-${tenant.plan || 'community'}`}>{tenant.plan || 'community'}</span></td>
                            <td>{tenant.alert_count}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                    {sorted.length > pageSize && (
                      <div className="pa-pagination">
                        <span className="pa-pagination-info">
                          Showing {overviewPage * pageSize + 1}–{Math.min((overviewPage + 1) * pageSize, sorted.length)} of {sorted.length}
                        </span>
                        <div className="pa-pagination-controls">
                          <button className="pa-btn-sm" disabled={overviewPage === 0} onClick={() => setOverviewPage(0)}>First</button>
                          <button className="pa-btn-sm" disabled={overviewPage === 0} onClick={() => setOverviewPage((p) => p - 1)}>Prev</button>
                          <span className="pa-pagination-page">Page {overviewPage + 1} of {totalPages}</span>
                          <button className="pa-btn-sm" disabled={overviewPage >= totalPages - 1} onClick={() => setOverviewPage((p) => p + 1)}>Next</button>
                          <button className="pa-btn-sm" disabled={overviewPage >= totalPages - 1} onClick={() => setOverviewPage(totalPages - 1)}>Last</button>
                        </div>
                      </div>
                    )}
                  </>
                ) : (
                  <p className="pa-text-muted" style={{ padding: '1rem 0' }}>No tenant activity for this period.</p>
                );
              })()}
            </div>
          </div>
        )}

        {/* Tenants Tab */}
        {activeTab === 'tenants' && (
          <div className="pa-tenants">
            <div className="pa-filters">
              <input
                type="text"
                placeholder="Search tenants..."
                value={tenantSearch}
                onChange={(e) => setTenantSearch(e.target.value)}
                className="pa-search"
              />
              <select
                value={tenantStatusFilter}
                onChange={(e) => setTenantStatusFilter(e.target.value)}
              >
                <option value="">All Statuses</option>
                <option value="active">Active</option>
                <option value="suspended">Suspended</option>
                <option value="pending">Pending</option>
              </select>
              <select
                value={tenantPlanFilter}
                onChange={(e) => setTenantPlanFilter(e.target.value)}
              >
                <option value="">All Plans</option>
                <option value="community">Community</option>
                <option value="professional">Professional</option>
                <option value="enterprise">Enterprise</option>
              </select>
              <button onClick={fetchTenants} className="pa-btn">Refresh</button>
              <button onClick={() => setShowCreateTenantModal(true)} className="pa-btn pa-btn-primary">
                + Create Tenant
              </button>
            </div>

            <table className="pa-table">
              <thead>
                <tr>
                  <th>Tenant</th>
                  <th>Plan</th>
                  <th>Status</th>
                  <th>Users</th>
                  <th>Alerts</th>
                  <th>BYO LLM</th>
                  <th>Created</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {tenants.map((tenant) => (
                  <tr key={tenant.id} className={tenant.is_platform_owner ? 'pa-platform-owner' : ''}>
                    <td>
                      <strong>{tenant.name}</strong>
                      <br />
                      <span className="pa-slug">{tenant.slug}</span>
                      {tenant.is_platform_owner && <span className="pa-badge platform">Platform Owner</span>}
                    </td>
                    <td>
                      <span className={`pa-badge plan-${tenant.plan}`}>{tenant.plan}</span>
                    </td>
                    <td>
                      <span className={`pa-badge status-${tenant.status}`}>{tenant.status}</span>
                    </td>
                    <td>{tenant.user_count}</td>
                    <td>{tenant.alert_count?.toLocaleString()}</td>
                    <td>
                      {!tenant.is_platform_owner && (
                        <button
                          onClick={() => toggleByoAllowed(tenant.id, !tenant.byo_allowed)}
                          className={`pa-btn-sm ${tenant.byo_allowed ? 'success' : ''}`}
                          title={
                            tenant.byo_allowed
                              ? (tenant.byo_enabled ? 'BYO allowed and enabled by tenant' : 'BYO allowed; tenant has not enabled it')
                              : 'Click to allow this tenant to BYO LLM'
                          }
                        >
                          {tenant.byo_allowed
                            ? (tenant.byo_enabled ? 'On' : 'Allowed')
                            : 'Off'}
                        </button>
                      )}
                    </td>
                    <td>{new Date(tenant.created_at).toLocaleDateString()}</td>
                    <td className="pa-actions">
                      <button onClick={() => viewTenantDetails(tenant.id)} className="pa-btn-sm">
                        View
                      </button>
                      {!tenant.is_platform_owner && (
                        <>
                          {tenant.status === 'active' ? (
                            <button
                              onClick={() => suspendTenant(tenant.id, 'Manual suspension')}
                              className="pa-btn-sm danger"
                            >
                              Suspend
                            </button>
                          ) : (
                            <button
                              onClick={() => reactivateTenant(tenant.id)}
                              className="pa-btn-sm success"
                            >
                              Reactivate
                            </button>
                          )}
                        </>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Licenses Tab */}
        {activeTab === 'licenses' && (
          <div className="pa-licenses">
            <div className="pa-filters">
              <button onClick={fetchLicenses} className="pa-btn">Refresh</button>
              <button onClick={openGenerateLicenseModal} className="pa-btn pa-btn-primary">
                + Generate License
              </button>
            </div>
            <table className="pa-table">
              <thead>
                <tr>
                  <th>Tenant</th>
                  <th>Tier</th>
                  <th>Status</th>
                  <th>Expires</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {licenses.filter(l => l.is_active).map((license) => (
                  <tr key={license.id}>
                    <td>
                      <strong>{license.tenant_name}</strong>
                      <br />
                      <span className="pa-slug">{license.tenant_slug}</span>
                    </td>
                    <td>
                      <span className={`pa-badge plan-${license.tier}`}>{license.tier}</span>
                    </td>
                    <td>
                      <span className="pa-badge status-active">Active</span>
                    </td>
                    <td>
                      {license.expires_at
                        ? new Date(license.expires_at).toLocaleDateString()
                        : 'Never'}
                    </td>
                    <td className="pa-actions">
                      {license.tier === 'platform' ? (
                        <span className="pa-text-muted" style={{ fontSize: '0.8rem' }}>Protected</span>
                      ) : (
                        <>
                          <button
                            onClick={() => openUpgradeModal(license)}
                            className="pa-btn-sm success"
                          >
                            Change Tier
                          </button>
                          {license.tier !== 'community' && (
                            <button
                              onClick={() => revokeLicense(license.id, 'Manual revocation')}
                              className="pa-btn-sm danger"
                            >
                              Revoke
                            </button>
                          )}
                        </>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Audit Log Tab */}
        {activeTab === 'audit' && (
          <div className="pa-audit">
            <table className="pa-table">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Admin</th>
                  <th>Action</th>
                  <th>Target</th>
                  <th>Details</th>
                </tr>
              </thead>
              <tbody>
                {auditLog.map((entry) => (
                  <tr key={entry.id}>
                    <td>{new Date(entry.created_at).toLocaleString()}</td>
                    <td>{entry.admin_email || 'System'}</td>
                    <td>
                      <span className={`pa-badge action-${entry.action}`}>
                        {entry.action.replace(/_/g, ' ')}
                      </span>
                    </td>
                    <td>{entry.target_type} {entry.target_id?.slice(0, 8)}</td>
                    <td className="pa-details">
                      {JSON.stringify(entry.details || {}).slice(0, 100)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {activeTab === 'token-usage' && (
          <PlatformTokenUsage getAuthHeaders={getAuthHeaders} showToast={showToast} />
        )}
      </main>

      {/* Tenant Detail Modal */}
      {selectedTenant && (
        <div className="pa-modal-overlay" onClick={() => setSelectedTenant(null)}>
          <div className="pa-modal" onClick={(e) => e.stopPropagation()}>
            <div className="pa-modal-header">
              <h2>{selectedTenant.name}</h2>
              <button onClick={() => setSelectedTenant(null)} className="pa-modal-close">&times;</button>
            </div>
            <div className="pa-modal-body">
              <div className="pa-detail-grid">
                <div className="pa-detail-item">
                  <label>Slug</label>
                  <span>{selectedTenant.slug}</span>
                </div>
                <div className="pa-detail-item">
                  <label>Plan</label>
                  <span className={`pa-badge plan-${selectedTenant.plan}`}>{selectedTenant.plan}</span>
                </div>
                <div className="pa-detail-item">
                  <label>Status</label>
                  <span className={`pa-badge status-${selectedTenant.status}`}>{selectedTenant.status}</span>
                </div>
                <div className="pa-detail-item">
                  <label>License Tier</label>
                  <span>{selectedTenant.license_tier || 'N/A'}</span>
                </div>
                <div className="pa-detail-item">
                  <label>License Expires</label>
                  <span>{selectedTenant.license_expires ? new Date(selectedTenant.license_expires).toLocaleDateString() : 'Never'}</span>
                </div>
              </div>

              <h3>Usage</h3>
              <div className="pa-usage-grid">
                {[
                  { key: 'users', label: 'Users', value: selectedTenant.usage?.users || 0 },
                  { key: 'alerts', label: 'Alerts', value: selectedTenant.usage?.alerts?.toLocaleString() || 0 },
                  { key: 'playbooks', label: 'Playbooks', value: selectedTenant.usage?.playbooks || 0 },
                  { key: 'executions', label: 'Executions', value: selectedTenant.usage?.executions?.toLocaleString() || 0 },
                  { key: 'investigations', label: 'Investigations', value: selectedTenant.usage?.investigations || 0 },
                  { key: 'iocs', label: 'IOCs', value: selectedTenant.usage?.iocs?.toLocaleString() || 0 },
                ].flatMap(item => {
                  const breakdown = selectedTenant.usage_breakdowns?.[item.key];
                  const hasBreakdown = breakdown?.length > 0;
                  const isExpanded = expandedUsage === item.key;
                  const elements = [
                    <div
                      key={item.key}
                      className={`pa-usage-item ${hasBreakdown ? 'pa-usage-expandable' : ''} ${isExpanded ? 'pa-usage-expanded' : ''}`}
                      onClick={() => hasBreakdown && setExpandedUsage(isExpanded ? null : item.key)}
                    >
                      <span className="pa-usage-value">{item.value}</span>
                      <span className="pa-usage-label">
                        {item.label}
                        {hasBreakdown && <span className="pa-usage-chevron">{isExpanded ? '\u25B2' : '\u25BC'}</span>}
                      </span>
                    </div>
                  ];
                  if (isExpanded && hasBreakdown) {
                    elements.push(
                      <div key={`${item.key}-breakdown`} className="pa-usage-breakdown-inline">
                        {item.key === 'users' && breakdown.map((u, i) => (
                          <div key={i} className="pa-breakdown-row">
                            <div className="pa-breakdown-user-info">
                              <span className="pa-breakdown-username">{u.username}</span>
                              {u.email && <span className="pa-breakdown-email">{u.email}</span>}
                            </div>
                            <span className="pa-breakdown-badge">{u.role}</span>
                          </div>
                        ))}
                        {item.key === 'alerts' && breakdown.map((a, i) => (
                          <div key={i} className="pa-breakdown-row">
                            <span className={`pa-badge severity-${a.severity}`}>{a.severity}</span>
                            <span className="pa-breakdown-count">{a.count.toLocaleString()}</span>
                          </div>
                        ))}
                        {item.key === 'playbooks' && breakdown.map((p, i) => (
                          <div key={i} className="pa-breakdown-row">
                            <span>{p.name}</span>
                          </div>
                        ))}
                        {item.key === 'executions' && breakdown.map((e, i) => (
                          <div key={i} className="pa-breakdown-row">
                            <span className={`pa-badge state-${(e.state || '').toLowerCase()}`}>{e.state}</span>
                            <span className="pa-breakdown-count">{e.count.toLocaleString()}</span>
                          </div>
                        ))}
                        {item.key === 'investigations' && breakdown.map((inv, i) => (
                          <div key={i} className="pa-breakdown-row">
                            <span className="pa-badge">{inv.state}</span>
                            <span className="pa-breakdown-count">{inv.count.toLocaleString()}</span>
                          </div>
                        ))}
                        {item.key === 'iocs' && breakdown.map((ioc, i) => (
                          <div key={i} className="pa-breakdown-row">
                            <span>{ioc.type}</span>
                            <span className="pa-breakdown-count">{ioc.count.toLocaleString()}</span>
                          </div>
                        ))}
                      </div>
                    );
                  }
                  return elements;
                })}
              </div>

              {/* Locked Accounts */}
              <div className="pa-locked-accounts-card">
                <h3>Locked Accounts <span className="pa-locked-count">{selectedTenant.locked_accounts?.length || 0}</span></h3>
                {selectedTenant.locked_accounts?.length > 0 ? (
                  <table className="pa-table pa-table-sm">
                    <thead>
                      <tr>
                        <th>Username</th>
                        <th>Attempts</th>
                        <th>Locked Until</th>
                        <th>Action</th>
                      </tr>
                    </thead>
                    <tbody>
                      {selectedTenant.locked_accounts.map((acct) => (
                        <tr key={acct.username}>
                          <td>
                            <div className="pa-locked-user">
                              <span>{acct.username}</span>
                              {acct.email && <span className="pa-locked-email">{acct.email}</span>}
                            </div>
                          </td>
                          <td><span className="pa-badge severity-high">{acct.failed_attempts}/3</span></td>
                          <td>{acct.locked_until ? new Date(acct.locked_until).toLocaleString() : '-'}</td>
                          <td>
                            <button
                              className="pa-btn-sm pa-btn-unlock"
                              onClick={async () => {
                                try {
                                  const res = await fetch(
                                    `${API_BASE_URL}/api/v1/platform/tenants/${selectedTenant.id}/users/${acct.username}/unlock`,
                                    { method: 'POST', headers: getAuthHeaders() }
                                  );
                                  if (!res.ok) throw new Error('Failed to unlock');
                                  showToast(`Unlocked ${acct.username}`);
                                  viewTenantDetails(selectedTenant.id);
                                } catch (err) {
                                  showToast(err.message, 'error');
                                }
                              }}
                            >
                              Unlock
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                ) : (
                  <div className="pa-locked-empty">No locked accounts</div>
                )}
              </div>

              {selectedTenant.recent_alerts?.length > 0 && (
                <>
                  <h3>Recent Alerts</h3>
                  <table className="pa-table pa-table-sm">
                    <thead>
                      <tr>
                        <th>Severity</th>
                        <th>Status</th>
                        <th>Created</th>
                      </tr>
                    </thead>
                    <tbody>
                      {selectedTenant.recent_alerts.map((alert) => (
                        <tr key={alert.id}>
                          <td><span className={`pa-badge severity-${alert.severity}`}>{alert.severity}</span></td>
                          <td>{alert.status}</td>
                          <td>{new Date(alert.created_at).toLocaleString()}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </>
              )}

              {/* License History */}
              {licenses.filter(l => l.tenant_id === selectedTenant.id).length > 0 && (
                <>
                  <h3>License History</h3>
                  <table className="pa-table pa-table-sm">
                    <thead>
                      <tr>
                        <th>Tier</th>
                        <th>Status</th>
                        <th>Expires</th>
                        <th>Issued</th>
                      </tr>
                    </thead>
                    <tbody>
                      {licenses
                        .filter(l => l.tenant_id === selectedTenant.id)
                        .sort((a, b) => new Date(b.created_at) - new Date(a.created_at))
                        .map((license) => (
                          <tr key={license.id} className={license.is_active ? 'pa-row-active' : 'pa-row-inactive'}>
                            <td><span className={`pa-badge plan-${license.tier}`}>{license.tier}</span></td>
                            <td>
                              <span className={`pa-badge ${license.is_active ? 'status-active' : 'status-revoked'}`}>
                                {license.is_active ? 'Active' : 'Revoked'}
                              </span>
                            </td>
                            <td>{license.expires_at ? new Date(license.expires_at).toLocaleDateString() : 'Never'}</td>
                            <td>{license.created_at ? new Date(license.created_at).toLocaleDateString() : 'N/A'}</td>
                          </tr>
                        ))}
                    </tbody>
                  </table>
                </>
              )}

              {/* Danger Zone */}
              {selectedTenant.slug !== 'default' && selectedTenant.slug !== 'platform' && (
                <div className="pa-danger-zone">
                  <h3>Danger Zone</h3>
                  <div className="pa-danger-zone-content">
                    <div className="pa-danger-zone-info">
                      <strong>Delete this tenant</strong>
                      <p>Permanently delete this tenant and all associated data including users, alerts, playbooks, and licenses. This action cannot be undone.</p>
                    </div>
                    <button
                      type="button"
                      className="pa-btn pa-btn-danger"
                      onClick={() => openDeleteTenantModal(selectedTenant)}
                    >
                      Delete Tenant
                    </button>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Create Tenant Modal */}
      {showCreateTenantModal && (
        <div className="pa-modal-overlay" onClick={() => setShowCreateTenantModal(false)}>
          <div className="pa-modal" onClick={(e) => e.stopPropagation()}>
            <div className="pa-modal-header">
              <h2>Create New Tenant</h2>
              <button onClick={() => setShowCreateTenantModal(false)} className="pa-modal-close">&times;</button>
            </div>
            <form onSubmit={handleCreateTenant} className="pa-modal-body">
              {createTenantError && <div className="pa-error">{createTenantError}</div>}

              <div className="pa-form-group">
                <label>Slug *</label>
                <input
                  type="text"
                  value={createTenantForm.slug}
                  onChange={(e) => setCreateTenantForm({ ...createTenantForm, slug: e.target.value.toLowerCase().replace(/[^a-z0-9-]/g, '') })}
                  placeholder="my-company"
                  minLength={3}
                  maxLength={50}
                  required
                />
                <small>Lowercase letters, numbers, and hyphens only. Used in URLs.</small>
              </div>

              <div className="pa-form-group">
                <label>Name *</label>
                <input
                  type="text"
                  value={createTenantForm.name}
                  onChange={(e) => setCreateTenantForm({ ...createTenantForm, name: e.target.value })}
                  placeholder="My Company Inc."
                  required
                />
              </div>

              <div className="pa-form-group">
                <label>License Tier</label>
                <select
                  value={createTenantForm.plan}
                  onChange={(e) => {
                    const plan = e.target.value;
                    const defaultDays = {
                      community: '',
                      poc: '30',
                      professional: '365',
                      enterprise: '',
                    };
                    setCreateTenantForm({
                      ...createTenantForm,
                      plan,
                      expires_in_days: defaultDays[plan] || '',
                    });
                  }}
                >
                  <option value="community">Community (Free)</option>
                  <option value="poc">POC (30 days)</option>
                  <option value="professional">Professional (1 year)</option>
                  <option value="enterprise">Enterprise (Unlimited)</option>
                </select>
              </div>

              <div className="pa-form-group">
                <label>License Expires In (days)</label>
                <input
                  type="number"
                  value={createTenantForm.expires_in_days}
                  onChange={(e) => setCreateTenantForm({ ...createTenantForm, expires_in_days: e.target.value })}
                  placeholder={createTenantForm.plan === 'enterprise' || createTenantForm.plan === 'community' ? 'Never expires' : 'Enter days'}
                  min="1"
                  max="3650"
                />
                <small>
                  {createTenantForm.plan === 'community' && 'Community licenses never expire.'}
                  {createTenantForm.plan === 'poc' && 'Default: 30 days for evaluation.'}
                  {createTenantForm.plan === 'professional' && 'Default: 1 year.'}
                  {createTenantForm.plan === 'enterprise' && 'Enterprise licenses typically never expire.'}
                </small>
              </div>

              <hr className="pa-divider" />
              <h3>Initial Admin User (Optional)</h3>

              <div className="pa-form-group">
                <label>Admin Email</label>
                <input
                  type="email"
                  value={createTenantForm.admin_email}
                  onChange={(e) => setCreateTenantForm({ ...createTenantForm, admin_email: e.target.value })}
                  placeholder="admin@company.com"
                />
                <small>If provided, creates an initial admin user for this tenant.</small>
              </div>

              <div className="pa-form-group">
                <label>Admin Name</label>
                <input
                  type="text"
                  value={createTenantForm.admin_name}
                  onChange={(e) => setCreateTenantForm({ ...createTenantForm, admin_name: e.target.value })}
                  placeholder="John Doe"
                />
              </div>

              <div className="pa-modal-footer">
                <button type="button" onClick={() => setShowCreateTenantModal(false)} className="pa-btn">
                  Cancel
                </button>
                <button type="submit" className="pa-btn pa-btn-primary" disabled={createTenantLoading}>
                  {createTenantLoading ? 'Creating...' : 'Create Tenant'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Generate License Modal */}
      {showGenerateLicenseModal && (
        <div className="pa-modal-overlay" onClick={closeGenerateLicenseModal}>
          <div className="pa-modal" onClick={(e) => e.stopPropagation()}>
            <div className="pa-modal-header">
              <h2>Generate License Key</h2>
              <button onClick={closeGenerateLicenseModal} className="pa-modal-close">&times;</button>
            </div>
            <div className="pa-modal-body">
              {generateLicenseError && <div className="pa-error">{generateLicenseError}</div>}

              {generatedLicense ? (
                <div className="pa-license-result">
                  <div className="pa-success-message">License generated successfully!</div>
                  <div className="pa-detail-grid">
                    <div className="pa-detail-item">
                      <label>Tier</label>
                      <span className={`pa-badge plan-${generatedLicense.tier}`}>{generatedLicense.tier}</span>
                    </div>
                    <div className="pa-detail-item">
                      <label>Expires</label>
                      <span>{generatedLicense.expires_at ? new Date(generatedLicense.expires_at).toLocaleDateString() : 'Never'}</span>
                    </div>
                  </div>
                  <div className="pa-modal-footer">
                    <button type="button" onClick={closeGenerateLicenseModal} className="pa-btn pa-btn-primary">
                      Done
                    </button>
                  </div>
                </div>
              ) : (
                <form onSubmit={handleGenerateLicense}>
                  <div className="pa-form-group">
                    <label>Tenant *</label>
                    <select
                      value={generateLicenseForm.tenant_id}
                      onChange={(e) => setGenerateLicenseForm({ ...generateLicenseForm, tenant_id: e.target.value })}
                      required
                    >
                      <option value="">Select a tenant...</option>
                      {tenants.map((tenant) => (
                        <option key={tenant.id} value={tenant.id}>
                          {tenant.name} ({tenant.slug})
                        </option>
                      ))}
                    </select>
                  </div>

                  <div className="pa-form-group">
                    <label>License Tier *</label>
                    <select
                      value={generateLicenseForm.tier}
                      onChange={(e) => {
                        const tier = e.target.value;
                        const defaultDays = {
                          community: '',
                          poc: '30',
                          professional: '365',
                          enterprise: '',
                        };
                        setGenerateLicenseForm({
                          ...generateLicenseForm,
                          tier,
                          expires_in_days: defaultDays[tier] || '',
                        });
                      }}
                      required
                    >
                      <option value="community">Community (Free)</option>
                      <option value="poc">POC (30 days)</option>
                      <option value="professional">Professional (1 year)</option>
                      <option value="enterprise">Enterprise (Unlimited)</option>
                    </select>
                  </div>

                  <div className="pa-form-group">
                    <label>Expires In (days)</label>
                    <input
                      type="number"
                      value={generateLicenseForm.expires_in_days}
                      onChange={(e) => setGenerateLicenseForm({ ...generateLicenseForm, expires_in_days: e.target.value })}
                      placeholder={generateLicenseForm.tier === 'enterprise' || generateLicenseForm.tier === 'community' ? 'Never expires' : 'Enter days'}
                      min="1"
                      max="3650"
                    />
                    <small>
                      {generateLicenseForm.tier === 'community' && 'Community licenses never expire.'}
                      {generateLicenseForm.tier === 'poc' && 'Default: 30 days. Extend as needed for evaluation.'}
                      {generateLicenseForm.tier === 'professional' && 'Default: 1 year. Adjust as needed.'}
                      {generateLicenseForm.tier === 'enterprise' && 'Enterprise licenses typically never expire.'}
                    </small>
                  </div>

                  <div className="pa-modal-footer">
                    <button type="button" onClick={closeGenerateLicenseModal} className="pa-btn">
                      Cancel
                    </button>
                    <button type="submit" className="pa-btn pa-btn-primary" disabled={generateLicenseLoading}>
                      {generateLicenseLoading ? 'Generating...' : 'Generate License'}
                    </button>
                  </div>
                </form>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Upgrade License Modal */}
      {showUpgradeModal && upgradeTarget && (
        <div className="pa-modal-overlay" onClick={() => setShowUpgradeModal(false)}>
          <div className="pa-modal" onClick={(e) => e.stopPropagation()} style={{ maxWidth: '460px' }}>
            <div className="pa-modal-header">
              <h2>Change License Tier</h2>
              <button onClick={() => setShowUpgradeModal(false)} className="pa-modal-close">&times;</button>
            </div>
            <form onSubmit={handleUpgradeLicense} className="pa-modal-body">
              <div className="pa-detail-grid" style={{ marginBottom: '1rem' }}>
                <div className="pa-detail-item">
                  <label>Tenant</label>
                  <span><strong>{upgradeTarget.tenant_name}</strong> ({upgradeTarget.tenant_slug})</span>
                </div>
                <div className="pa-detail-item">
                  <label>Current Tier</label>
                  <span className={`pa-badge plan-${upgradeTarget.tier}`}>{upgradeTarget.tier}</span>
                </div>
              </div>

              <div className="pa-form-group">
                <label>New Tier</label>
                <select
                  value={upgradeTier}
                  onChange={(e) => {
                    const tier = e.target.value;
                    const defaultDays = {
                      community: '',
                      trial: '30',
                      professional: '365',
                      enterprise: '365',
                    };
                    setUpgradeTier(tier);
                    setUpgradeExpiresDays(defaultDays[tier] || '');
                  }}
                >
                  <option value="community">Community (Free)</option>
                  <option value="trial">Trial (30 days)</option>
                  <option value="professional">Professional (1 year)</option>
                  <option value="enterprise">Enterprise (1 year)</option>
                </select>
              </div>

              <div className="pa-form-group">
                <label>Expires In (days)</label>
                <input
                  type="number"
                  value={upgradeExpiresDays}
                  onChange={(e) => setUpgradeExpiresDays(e.target.value)}
                  placeholder={upgradeTier === 'community' ? 'Never expires' : 'Enter days'}
                  min="1"
                  max="3650"
                />
                <small>
                  {upgradeTier === 'community' && 'Leave empty for no expiry.'}
                  {upgradeTier === 'trial' && 'Default: 30 days.'}
                  {upgradeTier === 'professional' && 'Default: 1 year.'}
                  {upgradeTier === 'enterprise' && 'Default: 1 year.'}
                </small>
              </div>

              <div className="pa-modal-footer">
                <button type="button" onClick={() => setShowUpgradeModal(false)} className="pa-btn">
                  Cancel
                </button>
                <button type="submit" className="pa-btn pa-btn-primary" disabled={upgradeLoading}>
                  {upgradeLoading ? 'Updating...' : 'Update License'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Toast Notification */}
      {toast && (
        <div className={`pa-toast pa-toast-${toast.type}`} onClick={() => setToast(null)}>
          <span>{toast.message}</span>
          <button className="pa-toast-close" onClick={() => setToast(null)}>&times;</button>
        </div>
      )}

      {/* Delete Tenant Confirmation Modal */}
      {showDeleteTenantModal && deleteTenantTarget && (
        <div className="pa-modal-overlay" onClick={() => setShowDeleteTenantModal(false)}>
          <div className="pa-modal pa-modal-danger" onClick={(e) => e.stopPropagation()}>
            <div className="pa-modal-header pa-modal-header-danger">
              <h2>Delete Tenant Permanently</h2>
              <button onClick={() => setShowDeleteTenantModal(false)} className="pa-modal-close">&times;</button>
            </div>
            <form onSubmit={handleDeleteTenant} className="pa-modal-body">
              {deleteTenantError && <div className="pa-error">{deleteTenantError}</div>}

              <div className="pa-delete-warning">
                <div className="pa-delete-warning-icon">⚠</div>
                <div className="pa-delete-warning-text">
                  <strong>This action is irreversible!</strong>
                  <p>You are about to permanently delete the tenant <strong>{deleteTenantTarget.name}</strong> and ALL associated data including:</p>
                  <ul>
                    <li>All users and their accounts</li>
                    <li>All alerts and investigations</li>
                    <li>All playbooks and execution history</li>
                    <li>All integration configurations</li>
                    <li>All licenses</li>
                  </ul>
                </div>
              </div>

              <div className="pa-form-group">
                <label>To confirm, type the tenant slug: <strong>{deleteTenantTarget.slug}</strong></label>
                <input
                  type="text"
                  value={deleteTenantConfirmSlug}
                  onChange={(e) => setDeleteTenantConfirmSlug(e.target.value)}
                  placeholder={deleteTenantTarget.slug}
                  autoComplete="off"
                  spellCheck="false"
                  required
                />
              </div>

              <div className="pa-modal-footer">
                <button type="button" onClick={() => setShowDeleteTenantModal(false)} className="pa-btn">
                  Cancel
                </button>
                <button
                  type="submit"
                  className="pa-btn pa-btn-danger"
                  disabled={deleteTenantLoading || deleteTenantConfirmSlug !== deleteTenantTarget.slug}
                >
                  {deleteTenantLoading ? 'Deleting...' : 'Delete Tenant Forever'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}

export default PlatformAdminDashboard;
