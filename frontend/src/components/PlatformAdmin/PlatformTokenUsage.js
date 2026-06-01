/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

import React, { useState, useEffect, useCallback, useMemo } from 'react';
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, BarChart, Bar, Cell,
} from 'recharts';

const API_BASE_URL = process.env.REACT_APP_API_URL || '';
const PAGE_SIZE = 10;

const TOOLTIP_STYLE = {
  background: 'rgba(15, 23, 42, 0.95)',
  border: '1px solid rgba(148, 163, 184, 0.2)',
  borderRadius: 10,
  fontSize: 12,
  color: '#e2e8f0',
};

function formatTokens(v) {
  if (v >= 1_000_000) return `${(v / 1_000_000).toFixed(1)}M`;
  if (v >= 1_000) return `${(v / 1_000).toFixed(0)}K`;
  return String(v);
}

function formatDate(d) {
  return new Date(d).toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
}

function SortIcon({ column, sortCol, sortDir }) {
  if (sortCol !== column) return <span className="pa-sort-icon" dangerouslySetInnerHTML={{ __html: '&#8693;' }} />;
  return <span className="pa-sort-icon active" dangerouslySetInnerHTML={{ __html: sortDir === 'asc' ? '&#9650;' : '&#9660;' }} />;
}

function PlatformTokenUsage({ getAuthHeaders, showToast }) {
  const [loading, setLoading] = useState(true);
  const [days, setDays] = useState(30);
  const [usageData, setUsageData] = useState(null);
  const [selectedTenantId, setSelectedTenantId] = useState(null);
  const [tenantDetail, setTenantDetail] = useState(null);
  const [tenantDetailLoading, setTenantDetailLoading] = useState(false);

  // Search, sort, pagination for tenant table
  const [search, setSearch] = useState('');
  const [sortCol, setSortCol] = useState('total_tokens');
  const [sortDir, setSortDir] = useState('desc');
  const [page, setPage] = useState(0);
  const [planFilter, setPlanFilter] = useState('');

  const fetchTokenUsage = useCallback(async () => {
    setLoading(true);
    try {
      const response = await fetch(
        `${API_BASE_URL}/api/v1/platform/analytics/token-usage?days=${days}`,
        { headers: getAuthHeaders() }
      );
      if (!response.ok) throw new Error('Failed to fetch token usage');
      const data = await response.json();
      setUsageData(data);
    } catch (err) {
      showToast(err.message, 'error');
    } finally {
      setLoading(false);
    }
  }, [days, getAuthHeaders, showToast]);

  useEffect(() => { fetchTokenUsage(); }, [fetchTokenUsage]);

  // Reset page when filters change
  useEffect(() => { setPage(0); }, [search, sortCol, sortDir, planFilter, days]);

  const fetchTenantDetail = async (tenantId) => {
    setSelectedTenantId(tenantId);
    setTenantDetailLoading(true);
    try {
      const response = await fetch(
        `${API_BASE_URL}/api/v1/platform/tenants/${tenantId}/token-usage?days=${days}`,
        { headers: getAuthHeaders() }
      );
      if (!response.ok) throw new Error('Failed to fetch tenant token detail');
      const data = await response.json();
      setTenantDetail(data);
    } catch (err) {
      showToast(err.message, 'error');
    } finally {
      setTenantDetailLoading(false);
    }
  };

  const closeDetail = () => {
    setSelectedTenantId(null);
    setTenantDetail(null);
  };

  // Filtered + sorted + paginated tenant list
  const { displayed, totalFiltered, totalPages } = useMemo(() => {
    let list = usageData?.by_tenant || [];

    // Search filter
    if (search.trim()) {
      const q = search.trim().toLowerCase();
      list = list.filter(
        (t) =>
          t.name.toLowerCase().includes(q) ||
          t.slug.toLowerCase().includes(q)
      );
    }

    // Plan filter
    if (planFilter) {
      list = list.filter((t) => t.plan === planFilter);
    }

    // Sort
    list = [...list].sort((a, b) => {
      let av = a[sortCol];
      let bv = b[sortCol];
      if (typeof av === 'string') {
        av = av.toLowerCase();
        bv = bv.toLowerCase();
      }
      if (av < bv) return sortDir === 'asc' ? -1 : 1;
      if (av > bv) return sortDir === 'asc' ? 1 : -1;
      return 0;
    });

    const totalFiltered = list.length;
    const totalPages = Math.max(1, Math.ceil(totalFiltered / PAGE_SIZE));
    const displayed = list.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);
    return { displayed, totalFiltered, totalPages };
  }, [usageData, search, planFilter, sortCol, sortDir, page]);

  const toggleSort = (col) => {
    if (sortCol === col) {
      setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'));
    } else {
      setSortCol(col);
      setSortDir('desc');
    }
  };

  // Unique plans for filter dropdown
  const plans = useMemo(() => {
    const set = new Set((usageData?.by_tenant || []).map((t) => t.plan));
    return [...set].sort();
  }, [usageData]);

  if (loading && !usageData) {
    return <div className="pa-loading-inline"><div className="pa-spinner" /><p>Loading token usage...</p></div>;
  }

  const s = usageData?.summary || {};

  return (
    <div className="pa-token-usage">
      {/* Filters */}
      <div className="pa-days-filter">
        <label>Time range:</label>
        <select value={days} onChange={(e) => setDays(Number(e.target.value))}>
          <option value={1}>Last 24 hours</option>
          <option value={7}>Last 7 days</option>
          <option value={14}>Last 14 days</option>
          <option value={30}>Last 30 days</option>
          <option value={60}>Last 60 days</option>
          <option value={90}>Last 90 days</option>
          <option value={180}>Last 180 days</option>
          <option value={365}>Last 365 days</option>
        </select>
        <button onClick={fetchTokenUsage} className="pa-btn">Refresh</button>
      </div>

      {/* Summary cards */}
      <div className="pa-stats-grid">
        <div className="pa-stat-card">
          <div className="pa-stat-value">{formatTokens(s.total_tokens || 0)}</div>
          <div className="pa-stat-label">Total Tokens</div>
        </div>
        <div className="pa-stat-card cyan">
          <div className="pa-stat-value">${(s.total_cost_usd || 0).toFixed(2)}</div>
          <div className="pa-stat-label">Total Cost</div>
        </div>
        <div className="pa-stat-card">
          <div className="pa-stat-value">{(s.total_requests || 0).toLocaleString()}</div>
          <div className="pa-stat-label">Total Requests</div>
        </div>
        <div className="pa-stat-card">
          <div className="pa-stat-value">{s.active_tenants || 0}</div>
          <div className="pa-stat-label">Active Tenants</div>
        </div>
      </div>

      {/* Daily trend chart */}
      {usageData?.daily_trend?.length > 0 && (
        <div className="pa-section">
          <h2>Daily Token Usage</h2>
          <div className="pa-chart-container">
            <ResponsiveContainer width="100%" height={280}>
              <AreaChart data={usageData.daily_trend}>
                <defs>
                  <linearGradient id="tokenGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#3CB371" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#3CB371" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.1)" />
                <XAxis
                  dataKey="date"
                  stroke="#6b7c93"
                  fontSize={11}
                  tickFormatter={formatDate}
                />
                <YAxis
                  stroke="#6b7c93"
                  fontSize={11}
                  tickFormatter={formatTokens}
                />
                <Tooltip
                  contentStyle={TOOLTIP_STYLE}
                  formatter={(v, name) => [
                    name === 'tokens' ? formatTokens(v) : `$${v.toFixed(2)}`,
                    name === 'tokens' ? 'Tokens' : 'Cost',
                  ]}
                  labelFormatter={formatDate}
                />
                <Area
                  type="monotone"
                  dataKey="tokens"
                  stroke="#3CB371"
                  fill="url(#tokenGrad)"
                  strokeWidth={2}
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>
      )}

      {/* Per-tenant table */}
      <div className="pa-section">
        <h2>Usage by Tenant</h2>

        {/* Search + plan filter */}
        <div className="pa-filters">
          <input
            type="text"
            className="pa-search"
            placeholder="Search tenants..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
          <select value={planFilter} onChange={(e) => setPlanFilter(e.target.value)}>
            <option value="">All Plans</option>
            {plans.map((p) => (
              <option key={p} value={p}>{p}</option>
            ))}
          </select>
        </div>

        {displayed.length > 0 ? (
          <>
            <table className="pa-table">
              <thead>
                <tr>
                  <th className="pa-sortable" onClick={() => toggleSort('name')}>
                    Tenant <SortIcon column="name" sortCol={sortCol} sortDir={sortDir} />
                  </th>
                  <th className="pa-sortable" onClick={() => toggleSort('plan')}>
                    Plan <SortIcon column="plan" sortCol={sortCol} sortDir={sortDir} />
                  </th>
                  <th className="pa-sortable" onClick={() => toggleSort('request_count')}>
                    Requests <SortIcon column="request_count" sortCol={sortCol} sortDir={sortDir} />
                  </th>
                  <th className="pa-sortable" onClick={() => toggleSort('total_tokens')}>
                    Tokens <SortIcon column="total_tokens" sortCol={sortCol} sortDir={sortDir} />
                  </th>
                  <th className="pa-sortable" onClick={() => toggleSort('cost_usd')}>
                    Cost <SortIcon column="cost_usd" sortCol={sortCol} sortDir={sortDir} />
                  </th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {displayed.map((t) => (
                  <tr key={t.tenant_id}>
                    <td>
                      <strong>{t.name}</strong>
                      <br />
                      <span className="pa-slug">{t.slug}</span>
                    </td>
                    <td><span className={`pa-badge plan-${t.plan}`}>{t.plan}</span></td>
                    <td>{t.request_count.toLocaleString()}</td>
                    <td>{formatTokens(t.total_tokens)}</td>
                    <td>${t.cost_usd.toFixed(2)}</td>
                    <td>
                      <button
                        className="pa-btn-sm"
                        onClick={() => fetchTenantDetail(t.tenant_id)}
                      >
                        View Details
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>

            {/* Pagination */}
            <div className="pa-pagination">
              <span className="pa-pagination-info">
                Showing {page * PAGE_SIZE + 1}–{Math.min((page + 1) * PAGE_SIZE, totalFiltered)} of {totalFiltered}
              </span>
              <div className="pa-pagination-controls">
                <button
                  className="pa-btn-sm"
                  disabled={page === 0}
                  onClick={() => setPage(0)}
                >
                  First
                </button>
                <button
                  className="pa-btn-sm"
                  disabled={page === 0}
                  onClick={() => setPage((p) => p - 1)}
                >
                  Prev
                </button>
                <span className="pa-pagination-page">
                  Page {page + 1} of {totalPages}
                </span>
                <button
                  className="pa-btn-sm"
                  disabled={page >= totalPages - 1}
                  onClick={() => setPage((p) => p + 1)}
                >
                  Next
                </button>
                <button
                  className="pa-btn-sm"
                  disabled={page >= totalPages - 1}
                  onClick={() => setPage(totalPages - 1)}
                >
                  Last
                </button>
              </div>
            </div>
          </>
        ) : (
          <p className="pa-text-muted" style={{ padding: '1rem 0' }}>
            {search || planFilter ? 'No tenants match your filters.' : 'No token usage data for this period.'}
          </p>
        )}
      </div>

      {/* Tenant detail modal */}
      {selectedTenantId && (
        <div className="pa-modal-overlay" onClick={closeDetail}>
          <div className="pa-modal pa-modal-large" onClick={(e) => e.stopPropagation()}>
            <div className="pa-modal-header">
              <h3>{tenantDetail?.tenant?.name || 'Tenant'} — Token Usage Detail</h3>
              <button className="pa-modal-close" onClick={closeDetail}>&times;</button>
            </div>

            {tenantDetailLoading ? (
              <div className="pa-loading-inline"><div className="pa-spinner" /><p>Loading...</p></div>
            ) : tenantDetail ? (
              <div className="pa-modal-body">
                {/* Monthly summary */}
                {tenantDetail.monthly_summary?.length > 0 && (
                  <div className="pa-section">
                    <h4>Monthly Summary</h4>
                    <table className="pa-table pa-table-compact">
                      <thead>
                        <tr>
                          <th>Month</th>
                          <th>Tokens</th>
                          <th>Input</th>
                          <th>Output</th>
                          <th>Cost</th>
                          <th>Overage</th>
                        </tr>
                      </thead>
                      <tbody>
                        {tenantDetail.monthly_summary.map((m) => (
                          <tr key={m.month_start}>
                            <td>{new Date(m.month_start).toLocaleDateString('en-US', { year: 'numeric', month: 'short' })}</td>
                            <td>{formatTokens(m.total_tokens)}</td>
                            <td>{formatTokens(m.total_input_tokens)}</td>
                            <td>{formatTokens(m.total_output_tokens)}</td>
                            <td>${m.cost_usd.toFixed(2)}</td>
                            <td>{m.overage_tokens > 0 ? formatTokens(m.overage_tokens) : '—'}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}

                {/* Daily chart */}
                {tenantDetail.daily_breakdown?.length > 0 && (
                  <div className="pa-section">
                    <h4>Daily Breakdown</h4>
                    <div className="pa-chart-container">
                      <ResponsiveContainer width="100%" height={200}>
                        <BarChart data={tenantDetail.daily_breakdown}>
                          <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.1)" />
                          <XAxis dataKey="date" stroke="#6b7c93" fontSize={10} tickFormatter={formatDate} />
                          <YAxis stroke="#6b7c93" fontSize={10} tickFormatter={formatTokens} />
                          <Tooltip contentStyle={TOOLTIP_STYLE} formatter={(v) => [formatTokens(v), 'Tokens']} labelFormatter={formatDate} />
                          <Bar dataKey="tokens" radius={[4, 4, 0, 0]}>
                            {tenantDetail.daily_breakdown.map((_, i) => (
                              <Cell key={i} fill="rgba(60,179,113,0.6)" />
                            ))}
                          </Bar>
                        </BarChart>
                      </ResponsiveContainer>
                    </div>
                  </div>
                )}

                {/* By model */}
                {tenantDetail.by_model?.length > 0 && (
                  <div className="pa-section">
                    <h4>By Model</h4>
                    <table className="pa-table pa-table-compact">
                      <thead>
                        <tr><th>Provider</th><th>Model</th><th>Requests</th><th>Tokens</th><th>Cost</th></tr>
                      </thead>
                      <tbody>
                        {tenantDetail.by_model.map((m, i) => (
                          <tr key={i}>
                            <td>{m.provider}</td>
                            <td style={{ fontFamily: 'monospace', fontSize: '0.8rem' }}>{m.model}</td>
                            <td>{m.requests}</td>
                            <td>{formatTokens(m.tokens)}</td>
                            <td>${m.cost_usd.toFixed(4)}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}

                {/* By request type */}
                {tenantDetail.by_request_type?.length > 0 && (
                  <div className="pa-section">
                    <h4>By Request Type</h4>
                    <table className="pa-table pa-table-compact">
                      <thead>
                        <tr><th>Type</th><th>Requests</th><th>Tokens</th></tr>
                      </thead>
                      <tbody>
                        {tenantDetail.by_request_type.map((t, i) => (
                          <tr key={i}>
                            <td>{t.request_type || 'unknown'}</td>
                            <td>{t.requests}</td>
                            <td>{formatTokens(t.tokens)}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}

                {/* Recent requests */}
                {tenantDetail.recent_requests?.length > 0 && (
                  <div className="pa-section">
                    <h4>Recent Requests</h4>
                    <table className="pa-table pa-table-compact">
                      <thead>
                        <tr><th>Time</th><th>Model</th><th>Type</th><th>Tokens</th><th>Cost</th><th>Status</th><th>Latency</th></tr>
                      </thead>
                      <tbody>
                        {tenantDetail.recent_requests.map((r, i) => (
                          <tr key={i}>
                            <td style={{ fontSize: '0.75rem', whiteSpace: 'nowrap' }}>
                              {r.created_at ? new Date(r.created_at).toLocaleString() : '—'}
                            </td>
                            <td style={{ fontFamily: 'monospace', fontSize: '0.75rem' }}>{r.model}</td>
                            <td>{r.request_type || '—'}</td>
                            <td>{(r.total_tokens || 0).toLocaleString()}</td>
                            <td>${r.cost_usd?.toFixed(4)}</td>
                            <td><span className={`pa-badge status-${r.status}`}>{r.status}</span></td>
                            <td>{r.response_time_ms ? `${r.response_time_ms}ms` : '—'}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}

                {!tenantDetail.monthly_summary?.length && !tenantDetail.daily_breakdown?.length && (
                  <p className="pa-text-muted" style={{ padding: '2rem 0', textAlign: 'center' }}>
                    No token usage data for this tenant.
                  </p>
                )}
              </div>
            ) : null}
          </div>
        </div>
      )}
    </div>
  );
}

export default PlatformTokenUsage;
