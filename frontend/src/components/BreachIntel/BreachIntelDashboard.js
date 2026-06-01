/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

/**
 * BreachIntelDashboard
 *
 * Real-time breach intelligence feed. Displays security incidents sourced
 * from public disclosures, government alerts, and threat-intel feeds.
 * Designed for non-security-experts -- anyone should be able to scan the
 * feed and understand the risk at a glance.
 */

import React, { useState, useEffect, useCallback, useRef } from 'react';
import { authFetch } from '../../utils/api';
import styles from './BreachIntelDashboard.module.css';

/* ── Constants ── */

const INCIDENT_TYPES = [
  { value: 'all', label: 'All Types' },
  { value: 'data_breach', label: 'Data Breach' },
  { value: 'ransomware', label: 'Ransomware' },
  { value: 'vulnerability', label: 'Vulnerability' },
  { value: 'apt_campaign', label: 'APT Campaign' },
  { value: 'supply_chain', label: 'Supply Chain' },
  { value: 'government_alert', label: 'Government Alert' },
];

const SEVERITY_OPTIONS = [
  { value: 'all', label: 'All Severities' },
  { value: 'critical', label: 'Critical' },
  { value: 'high', label: 'High' },
  { value: 'medium', label: 'Medium' },
  { value: 'low', label: 'Low' },
];

const DATE_RANGES = [
  { value: '7', label: '7d' },
  { value: '30', label: '30d' },
  { value: '90', label: '90d' },
  { value: 'all', label: 'All' },
];

const PAGE_SIZE = 25;
const POLL_INTERVAL_MS = 5 * 60 * 1000; // 5 minutes

/* ── Helpers ── */

function formatRelativeDate(dateStr) {
  if (!dateStr) return '';
  const date = new Date(dateStr);
  const now = new Date();
  const diffMs = now - date;
  const diffMin = Math.floor(diffMs / 60000);
  const diffHr = Math.floor(diffMs / 3600000);
  const diffDay = Math.floor(diffMs / 86400000);

  if (diffMin < 1) return 'just now';
  if (diffMin < 60) return `${diffMin}m ago`;
  if (diffHr < 24) return `${diffHr}h ago`;
  if (diffDay < 7) return `${diffDay}d ago`;

  return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
}

function formatRecords(count) {
  if (!count && count !== 0) return null;
  if (count >= 1_000_000_000) return `${(count / 1_000_000_000).toFixed(1)}B records`;
  if (count >= 1_000_000) return `${(count / 1_000_000).toFixed(1)}M records`;
  if (count >= 1_000) return `${(count / 1_000).toFixed(1)}K records`;
  return `${count} records`;
}

function formatNumber(n) {
  if (n == null) return '--';
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
  return String(n);
}

function severityStripClass(severity) {
  switch ((severity || '').toLowerCase()) {
    case 'critical': return styles.severityCritical;
    case 'high': return styles.severityHigh;
    case 'medium': return styles.severityMedium;
    case 'low': return styles.severityLow;
    default: return styles.severityInfo;
  }
}

function incidentTypeLabel(type) {
  const match = INCIDENT_TYPES.find((t) => t.value === type);
  return match ? match.label : (type || '').replace(/_/g, ' ');
}

function formatDate(dateStr) {
  if (!dateStr) return '--';
  return new Date(dateStr).toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  });
}

/* ── Main Component ── */

function BreachIntelDashboard() {
  // Data
  const [incidents, setIncidents] = useState([]);
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [totalCount, setTotalCount] = useState(0);
  const [currentPage, setCurrentPage] = useState(1);

  // Filters
  const [typeFilter, setTypeFilter] = useState('all');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [dateRange, setDateRange] = useState('all');

  // Expand
  const [expandedId, setExpandedId] = useState(null);

  // Refs for polling / debounce
  const pollTimer = useRef(null);
  const searchDebounce = useRef(null);
  const lastUpdated = useRef(null);

  const totalPages = Math.max(1, Math.ceil(totalCount / PAGE_SIZE));

  /* ── Build query params ── */
  const buildParams = useCallback(
    (page) => {
      const params = new URLSearchParams();
      if (typeFilter !== 'all') params.append('incident_type', typeFilter);
      if (severityFilter !== 'all') params.append('severity', severityFilter);
      if (searchQuery) params.append('search', searchQuery);
      if (dateRange !== 'all') {
        const d = new Date();
        d.setDate(d.getDate() - parseInt(dateRange, 10));
        params.append('date_from', d.toISOString().split('T')[0]);
      }
      params.append('limit', String(PAGE_SIZE));
      params.append('offset', String((page - 1) * PAGE_SIZE));
      return params;
    },
    [typeFilter, severityFilter, searchQuery, dateRange]
  );

  /* ── Fetch stats ── */
  const fetchStats = useCallback(async () => {
    try {
      const res = await authFetch('/api/v1/breach-intel/stats');
      if (res.ok) {
        const data = await res.json();
        setStats(data);
      }
    } catch {
      // stats are non-critical; swallow
    }
  }, []);

  /* ── Fetch incidents for a given page ── */
  const fetchIncidents = useCallback(
    async (page = 1) => {
      setLoading(true);
      setError(null);

      try {
        const params = buildParams(page);
        const res = await authFetch(`/api/v1/breach-intel?${params}`);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();

        const list = Array.isArray(data) ? data : data.items || data.incidents || data.results || [];
        const total = data.total ?? list.length;

        setIncidents(list);
        setTotalCount(total);
        lastUpdated.current = new Date();
      } catch (err) {
        setError(err.message || 'Failed to load breach intelligence');
      } finally {
        setLoading(false);
      }
    },
    [buildParams]
  );

  /* ── Initial load + filter changes → reset to page 1 ── */
  useEffect(() => {
    setCurrentPage(1);
    fetchIncidents(1);
    fetchStats();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [typeFilter, severityFilter, dateRange]);

  /* ── Debounced search → reset to page 1 ── */
  useEffect(() => {
    if (searchDebounce.current) clearTimeout(searchDebounce.current);
    searchDebounce.current = setTimeout(() => {
      setCurrentPage(1);
      fetchIncidents(1);
      fetchStats();
    }, 400);
    return () => clearTimeout(searchDebounce.current);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [searchQuery]);

  /* ── Auto-refresh polling (current page) ── */
  useEffect(() => {
    pollTimer.current = setInterval(() => {
      fetchIncidents(currentPage);
      fetchStats();
    }, POLL_INTERVAL_MS);
    return () => clearInterval(pollTimer.current);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [currentPage, typeFilter, severityFilter, searchQuery, dateRange]);

  /* ── Page change ── */
  const goToPage = (page) => {
    const p = Math.max(1, Math.min(page, totalPages));
    setCurrentPage(p);
    setExpandedId(null);
    fetchIncidents(p);
    // Scroll to top of feed
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  /* ── Manual refresh ── */
  const handleRefresh = () => {
    fetchIncidents(currentPage);
    fetchStats();
  };

  /* ── Toggle expanded card ── */
  const toggleExpand = (id) => {
    setExpandedId((prev) => (prev === id ? null : id));
  };

  /* ── Build page numbers for pagination ── */
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

  // Derived: showing range
  const showingFrom = incidents.length > 0 ? (currentPage - 1) * PAGE_SIZE + 1 : 0;
  const showingTo = showingFrom + incidents.length - 1;

  /* ── Render ── */
  return (
    <div className={styles.container}>
      {/* Header */}
      <div className={styles.header}>
        <div>
          <h1 className={styles.title}>Breach Intelligence</h1>
          {lastUpdated.current && (
            <span className={styles.lastUpdated}>
              Last updated: {formatRelativeDate(lastUpdated.current.toISOString())}
            </span>
          )}
        </div>
        <button className={styles.refreshButton} onClick={handleRefresh}>
          Refresh
        </button>
      </div>

      {/* Stat Cards */}
      <div className={styles.statsRow}>
        <div className={styles.statCard}>
          <span className={styles.statLabel}>Total Incidents</span>
          <span className={styles.statValue}>
            {stats ? formatNumber(stats.total_incidents) : '--'}
          </span>
        </div>
        <div className={styles.statCard}>
          <span className={styles.statLabel}>Critical / High</span>
          <span className={styles.statValueCritical}>
            {stats ? formatNumber(
              (stats.by_severity?.critical || 0) + (stats.by_severity?.high || 0)
            ) : '--'}
          </span>
        </div>
        <div className={styles.statCard}>
          <span className={styles.statLabel}>Last 7 Days</span>
          <span className={styles.statValuePrimary}>
            {stats ? formatNumber(stats.last_7_days) : '--'}
          </span>
        </div>
        <div className={styles.statCard}>
          <span className={styles.statLabel}>Active Sources</span>
          <span className={styles.statValue}>
            {stats ? formatNumber(stats.sources_active) : '--'}
          </span>
        </div>
      </div>

      {/* Filter Bar */}
      <div className={styles.filterBar}>
        <select
          className={styles.filterSelect}
          value={typeFilter}
          onChange={(e) => setTypeFilter(e.target.value)}
        >
          {INCIDENT_TYPES.map((t) => (
            <option key={t.value} value={t.value}>
              {t.label}
            </option>
          ))}
        </select>

        <select
          className={styles.filterSelect}
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value)}
        >
          {SEVERITY_OPTIONS.map((s) => (
            <option key={s.value} value={s.value}>
              {s.label}
            </option>
          ))}
        </select>

        <input
          type="text"
          className={styles.searchInput}
          placeholder="Search title, organization, summary..."
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
        />

        <div className={styles.dateChips}>
          {DATE_RANGES.map((dr) => (
            <button
              key={dr.value}
              className={dateRange === dr.value ? styles.dateChipActive : styles.dateChip}
              onClick={() => setDateRange(dr.value)}
            >
              {dr.label}
            </button>
          ))}
        </div>
      </div>

      {/* Feed */}
      {loading && !incidents.length ? (
        <div className={styles.loadingContainer}>Loading breach intelligence...</div>
      ) : error && !incidents.length ? (
        <div className={styles.errorContainer}>
          <div>{error}</div>
          <button className={styles.retryButton} onClick={handleRefresh}>
            Retry
          </button>
        </div>
      ) : incidents.length === 0 ? (
        <div className={styles.feedEmpty}>
          No incidents match the current filters.
        </div>
      ) : (
        <>
          <div className={styles.feed}>
            {incidents.map((inc) => (
              <IncidentCard
                key={inc.id}
                incident={inc}
                expanded={expandedId === inc.id}
                onToggle={() => toggleExpand(inc.id)}
              />
            ))}
          </div>

          {/* Pagination */}
          <div className={styles.pagination}>
            <span className={styles.paginationInfo}>
              {showingFrom}-{showingTo} of {formatNumber(totalCount)}
            </span>

            <div className={styles.paginationControls}>
              <button
                className={styles.pageButton}
                onClick={() => goToPage(currentPage - 1)}
                disabled={currentPage <= 1}
              >
                Prev
              </button>

              {getPageNumbers().map((p, i) =>
                p === '...' ? (
                  <span key={`ellipsis-${i}`} className={styles.pageEllipsis}>...</span>
                ) : (
                  <button
                    key={p}
                    className={`${styles.pageButton} ${p === currentPage ? styles.pageButtonActive : ''}`}
                    onClick={() => goToPage(p)}
                  >
                    {p}
                  </button>
                )
              )}

              <button
                className={styles.pageButton}
                onClick={() => goToPage(currentPage + 1)}
                disabled={currentPage >= totalPages}
              >
                Next
              </button>
            </div>
          </div>
        </>
      )}
    </div>
  );
}

/* ── Incident Card ── */

function IncidentCard({ incident, expanded, onToggle }) {
  const {
    id,
    title,
    severity,
    incident_type,
    affected_org,
    sector,
    incident_date,
    disclosure_date,
    discovered_date,
    published_at,
    records_affected,
    summary,
    ai_summary,
    source,
    source_url,
    cves,
    apt_groups,
    malware,
    tags,
    created_at,
  } = incident;

  const displayDate = published_at || incident_date || disclosure_date || created_at;
  const recordsLabel = formatRecords(records_affected);

  return (
    <div className={styles.card} onClick={onToggle} role="button" tabIndex={0}>
      <div className={`${styles.severityStrip} ${severityStripClass(severity)}`} />
      <div className={styles.cardBody}>
        {/* Top row */}
        <div className={styles.cardTopRow}>
          <h3 className={styles.cardTitle}>{title}</h3>
          <span className={styles.cardDate}>{formatRelativeDate(displayDate)}</span>
        </div>

        {/* Meta */}
        <div className={styles.cardMeta}>
          {affected_org && <span className={styles.orgName}>{affected_org}</span>}
          {sector && <span className={styles.badgeSector}>{sector}</span>}
          {incident_type && (
            <span className={styles.badgeType}>{incidentTypeLabel(incident_type)}</span>
          )}
          {recordsLabel && <span className={styles.badgeRecords}>{recordsLabel}</span>}
        </div>

        {/* Summary - truncate when collapsed, full when expanded */}
        {summary && (
          <p className={styles.cardSummary}>
            {!expanded && summary.length > 200 ? summary.slice(0, 200) + '...' : summary}
          </p>
        )}

        {/* Source */}
        {source && (
          <div className={styles.cardSource}>
            Source: {source_url ? (
              <a
                href={source_url}
                target="_blank"
                rel="noopener noreferrer"
                onClick={(e) => e.stopPropagation()}
              >
                {source}
              </a>
            ) : (
              source
            )}
          </div>
        )}

        {/* Expandable detail */}
        <div className={expanded ? styles.detailWrapperOpen : styles.detailWrapper}>
          <div className={styles.detailPanel}>
            {/* AI summary - only show if different from the card summary */}
            {ai_summary && ai_summary !== summary && (
              <div className={styles.detailSection}>
                <div className={styles.detailLabel}>AI Summary</div>
                <div className={styles.detailText}>{ai_summary}</div>
              </div>
            )}

            {/* CVEs */}
            {cves && cves.length > 0 && (
              <div className={styles.detailSection}>
                <div className={styles.detailLabel}>Related CVEs</div>
                <div className={styles.chipList}>
                  {cves.map((cve) => (
                    <span key={cve} className={styles.chipCve}>{cve}</span>
                  ))}
                </div>
              </div>
            )}

            {/* APT Groups */}
            {apt_groups && apt_groups.length > 0 && (
              <div className={styles.detailSection}>
                <div className={styles.detailLabel}>APT Groups</div>
                <div className={styles.chipList}>
                  {apt_groups.map((g) => (
                    <span key={g} className={styles.chipApt}>{g}</span>
                  ))}
                </div>
              </div>
            )}

            {/* Malware */}
            {malware && malware.length > 0 && (
              <div className={styles.detailSection}>
                <div className={styles.detailLabel}>Malware</div>
                <div className={styles.chipList}>
                  {malware.map((m) => (
                    <span key={m} className={styles.chipMalware}>{m}</span>
                  ))}
                </div>
              </div>
            )}

            {/* Tags */}
            {tags && tags.length > 0 && (
              <div className={styles.detailSection}>
                <div className={styles.detailLabel}>Tags</div>
                <div className={styles.chipList}>
                  {tags.map((tag) => (
                    <span key={tag} className={styles.chip}>{tag}</span>
                  ))}
                </div>
              </div>
            )}

            {/* Dates */}
            {(published_at || incident_date || disclosure_date || discovered_date) && (
            <div className={styles.detailSection}>
              <div className={styles.detailLabel}>Timeline</div>
              <div className={styles.detailDates}>
                {published_at && (
                  <span className={styles.detailDateItem}>
                    <strong>Published:</strong> {formatDate(published_at)}
                  </span>
                )}
                {incident_date && (
                  <span className={styles.detailDateItem}>
                    <strong>Incident:</strong> {formatDate(incident_date)}
                  </span>
                )}
                {disclosure_date && (
                  <span className={styles.detailDateItem}>
                    <strong>Disclosed:</strong> {formatDate(disclosure_date)}
                  </span>
                )}
                {discovered_date && (
                  <span className={styles.detailDateItem}>
                    <strong>Discovered:</strong> {formatDate(discovered_date)}
                  </span>
                )}
              </div>
            </div>
            )}

            {/* Source link */}
            {source_url && (
              <div className={styles.detailSection}>
                <a
                  className={styles.detailSourceLink}
                  href={source_url}
                  target="_blank"
                  rel="noopener noreferrer"
                  onClick={(e) => e.stopPropagation()}
                >
                  View Original Source
                </a>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

export default BreachIntelDashboard;
