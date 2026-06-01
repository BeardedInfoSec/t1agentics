/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

import React, { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { API_BASE_URL } from '../utils/api';
import './ThreatIntelShell.css';
import ThreatIntelTabs from './ThreatIntelTabs';

/**
 * ThreatFeeds - Threat Intelligence Feed Library
 *
 * Compact table view for laptop-friendly display.
 * Features:
 * - Enable/disable feeds with auto-poll on enable
 * - Manual poll trigger
 * - View feed statistics
 * - Add custom feeds
 * - Pagination with row limit options
 * - Column filter dropdowns
 */
function ThreatFeeds() {
  const navigate = useNavigate();
  const [feeds, setFeeds] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [showAddModal, setShowAddModal] = useState(false);
  const [selectedFeed, setSelectedFeed] = useState(null);
  const [pollingFeed, setPollingFeed] = useState(null);
  const [togglingFeed, setTogglingFeed] = useState(null);
  const [pollResult, setPollResult] = useState(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [formatOptions, setFormatOptions] = useState(null);
  const [sortConfig, setSortConfig] = useState({ key: 'name', direction: 'asc' });

  // Scheduler state
  const [scheduler, setScheduler] = useState({
    running: false,
    current_feed: null,
    last_run_at: null,
    feeds_polled: 0,
    feeds_failed: 0,
    interval_minutes: 60,
    delay_between_feeds: 5,
    max_feeds_per_cycle: 10
  });
  const [pollingAll, setPollingAll] = useState(false);
  const [showSchedulerSettings, setShowSchedulerSettings] = useState(false);
  const [schedulerConfig, setSchedulerConfig] = useState({
    interval_minutes: 60,
    delay_between_feeds: 5,
    max_feeds_per_cycle: 10
  });

  // Pagination state
  const [currentPage, setCurrentPage] = useState(1);
  const [rowsPerPage, setRowsPerPage] = useState(20);

  // Column filter state
  const [columnFilters, setColumnFilters] = useState({
    enabled: null,      // null = all, true = enabled, false = disabled
    category: null,     // null = all, or specific category
    severity: null,     // null = all, or specific severity
    type: null          // null = all, 'preconfigured' or 'custom'
  });

  // Active column filter dropdown
  const [activeFilterColumn, setActiveFilterColumn] = useState(null);

  useEffect(() => {
    fetchFeeds();
    fetchFormatOptions();
    fetchSchedulerStatus();
    // Refresh every 30 seconds to update stats and scheduler status
    const interval = setInterval(() => {
      fetchFeeds();
      fetchSchedulerStatus();
    }, 30000);
    return () => clearInterval(interval);
  }, []);

  // Close filter dropdown when clicking outside
  useEffect(() => {
    const handleClickOutside = (e) => {
      if (activeFilterColumn && !e.target.closest('.column-filter-dropdown')) {
        setActiveFilterColumn(null);
      }
    };
    document.addEventListener('click', handleClickOutside);
    return () => document.removeEventListener('click', handleClickOutside);
  }, [activeFilterColumn]);

  const fetchFeeds = async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/api/v1/threat-feeds`, {
        credentials: 'include',
      });

      if (!response.ok) throw new Error('Failed to fetch feeds');

      const data = await response.json();
      setFeeds(data.feeds || []);
      setLoading(false);
    } catch (err) {
      setError(err.message);
      setLoading(false);
    }
  };

  const fetchFormatOptions = async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/api/v1/threat-feeds/formats/available`, {
        credentials: 'include',
      });

      if (response.ok) {
        const data = await response.json();
        setFormatOptions(data);
      }
    } catch (err) {
    }
  };

  const fetchSchedulerStatus = async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/api/v1/threat-feeds/scheduler/status`, {
        credentials: 'include',
      });

      if (response.ok) {
        const data = await response.json();
        setScheduler(data);
      }
    } catch (err) {
    }
  };

  const toggleScheduler = async () => {
    try {
      const endpoint = scheduler.running ? 'stop' : 'start';
      const body = endpoint === 'start' ? JSON.stringify(schedulerConfig) : '{}';
      const response = await fetch(`${API_BASE_URL}/api/v1/threat-feeds/scheduler/${endpoint}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        credentials: 'include',
        body
      });

      if (response.ok) {
        await fetchSchedulerStatus();
        setShowSchedulerSettings(false);
      }
    } catch (err) {
    }
  };

  const pollAllFeeds = async () => {
    setPollingAll(true);
    setPollResult(null);
    try {
      const response = await fetch(`${API_BASE_URL}/api/v1/threat-feeds/scheduler/poll-all`, {
        method: 'POST',
        credentials: 'include',
      });

      if (response.ok) {
        const result = await response.json();
        setPollResult({
          success: true,
          iocs_new: result.results.reduce((sum, r) => sum + (r.iocs_new || 0), 0),
          iocs_updated: 0,
          iocs_skipped: 0,
          duration_ms: 0,
          message: `Polled ${result.feeds_polled} feeds successfully`
        });
        await fetchFeeds();
      }
    } catch (err) {
      setPollResult({ success: false, error: err.message });
    } finally {
      setPollingAll(false);
    }
  };

  const toggleFeed = async (feedId, enabled) => {
    setTogglingFeed(feedId);
    try {
      const response = await fetch(`${API_BASE_URL}/api/v1/threat-feeds/${feedId}/enable`, {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
        },
        credentials: 'include',
        body: JSON.stringify({ enabled })
      });

      if (response.ok) {
        // Update local state
        setFeeds(prev => prev.map(f =>
          f.feed_id === feedId ? { ...f, enabled } : f
        ));

        // If enabling, trigger a poll immediately
        if (enabled) {
          await pollFeed(feedId, true); // silent = true
        }
      }
    } catch (err) {
    } finally {
      setTogglingFeed(null);
    }
  };

  const pollFeed = async (feedId, silent = false) => {
    if (!silent) setPollingFeed(feedId);
    setPollResult(null);

    try {
      const response = await fetch(`${API_BASE_URL}/api/v1/threat-feeds/${feedId}/poll`, {
        method: 'POST',
        credentials: 'include',
      });

      if (response.ok) {
        const result = await response.json();
        if (!silent) setPollResult(result);
        await fetchFeeds(); // Refresh to get updated stats
        return result;
      }
    } catch (err) {
      if (!silent) setPollResult({ success: false, error: err.message });
    } finally {
      if (!silent) setPollingFeed(null);
    }
    return null;
  };

  const deleteFeed = async (feedId) => {
    if (!window.confirm('Are you sure you want to delete this custom feed?')) return;

    try {
      const response = await fetch(`${API_BASE_URL}/api/v1/threat-feeds/${feedId}`, {
        method: 'DELETE',
        credentials: 'include',
      });

      if (response.ok) {
        fetchFeeds();
      }
    } catch (err) {
    }
  };

  const getCategoryColor = (category) => {
    const colors = {
      'ip_blocklist': '#3b82f6',
      'domain_blocklist': '#3CB371',
      'url_blocklist': '#ec4899',
      'hash_list': '#f97316',
      'mixed': '#6b7280',
      'cve': '#ef4444',
      'other': '#6b7280'
    };
    return colors[category] || '#6b7280';
  };

  const getSeverityColor = (severity) => {
    const colors = {
      'critical': '#dc2626',
      'high': '#ea580c',
      'medium': '#eab308',
      'low': '#22c55e'
    };
    return colors[severity] || '#6b7280';
  };

  const formatTimeAgo = (dateStr) => {
    if (!dateStr) return 'Never';
    const date = new Date(dateStr);
    const now = new Date();
    const diffMs = now - date;
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMs / 3600000);
    const diffDays = Math.floor(diffMs / 86400000);

    if (diffMins < 1) return 'Just now';
    if (diffMins < 60) return `${diffMins}m ago`;
    if (diffHours < 24) return `${diffHours}h ago`;
    if (diffDays < 7) return `${diffDays}d ago`;
    return date.toLocaleDateString();
  };

  const formatNumber = (num) => {
    if (num === null || num === undefined) return '-';
    if (num >= 1000000) return `${(num / 1000000).toFixed(1)}M`;
    if (num >= 1000) return `${(num / 1000).toFixed(1)}K`;
    return num.toLocaleString();
  };

  // Sorting
  const handleSort = (key) => {
    setSortConfig(prev => ({
      key,
      direction: prev.key === key && prev.direction === 'asc' ? 'desc' : 'asc'
    }));
  };

  // Get unique values for filter dropdowns
  const categories = [...new Set(feeds.map(f => f.category))].filter(Boolean);
  const severities = [...new Set(feeds.map(f => f.default_severity))].filter(Boolean);

  // Filter and sort feeds
  const filteredFeeds = feeds
    .filter(feed => {
      // Search filter
      if (searchTerm && !feed.name.toLowerCase().includes(searchTerm.toLowerCase())) return false;

      // Column filters
      if (columnFilters.enabled !== null && feed.enabled !== columnFilters.enabled) return false;
      if (columnFilters.category && feed.category !== columnFilters.category) return false;
      if (columnFilters.severity && feed.default_severity !== columnFilters.severity) return false;
      if (columnFilters.type === 'preconfigured' && !feed.is_preconfigured) return false;
      if (columnFilters.type === 'custom' && feed.is_preconfigured) return false;

      return true;
    })
    .sort((a, b) => {
      const direction = sortConfig.direction === 'asc' ? 1 : -1;
      if (sortConfig.key === 'name') {
        return direction * a.name.localeCompare(b.name);
      }
      if (sortConfig.key === 'total_iocs_ingested') {
        return direction * ((a.total_iocs_ingested || 0) - (b.total_iocs_ingested || 0));
      }
      if (sortConfig.key === 'last_poll_at') {
        const aDate = a.last_poll_at ? new Date(a.last_poll_at) : new Date(0);
        const bDate = b.last_poll_at ? new Date(b.last_poll_at) : new Date(0);
        return direction * (aDate - bDate);
      }
      if (sortConfig.key === 'enabled') {
        return direction * ((a.enabled ? 1 : 0) - (b.enabled ? 1 : 0));
      }
      return 0;
    });

  // Pagination
  const totalPages = Math.ceil(filteredFeeds.length / rowsPerPage);
  const paginatedFeeds = filteredFeeds.slice(
    (currentPage - 1) * rowsPerPage,
    currentPage * rowsPerPage
  );

  // Reset to page 1 when filters change
  useEffect(() => {
    setCurrentPage(1);
  }, [searchTerm, columnFilters, rowsPerPage]);

  const enabledCount = feeds.filter(f => f.enabled).length;
  const totalIOCs = feeds.reduce((sum, f) => sum + (f.total_iocs_ingested || 0), 0);

  // Count active filters
  const activeFilterCount = Object.values(columnFilters).filter(v => v !== null).length;

  // Clear all filters
  const clearAllFilters = () => {
    setColumnFilters({
      enabled: null,
      category: null,
      severity: null,
      type: null
    });
    setSearchTerm('');
  };

  // Toggle column filter dropdown
  const toggleFilterDropdown = (column, e) => {
    e.stopPropagation();
    setActiveFilterColumn(activeFilterColumn === column ? null : column);
  };

  if (loading) {
    return (
      <div className="threat-intel-shell">
        <div className="ti-shell">
          <header className="ti-topbar">
            <div className="ti-title-group">
              <span className="ti-badge">Threat Intel</span>
              <div>
                <div className="ti-title">Threat Feeds</div>
                <div className="ti-subtitle">Curate feeds, schedule polling, and track ingest volume.</div>
              </div>
            </div>
          </header>
          <div className="ti-panel" style={{ display: 'grid', placeItems: 'center' }}>
            <div style={{ fontSize: '1.1rem', color: 'var(--text-secondary)' }}>Loading threat feeds...</div>
          </div>
        </div>
      </div>
    );
  }

  // Calculate stats for cards
  const highSeverityFeeds = feeds.filter(f => f.default_severity === 'high' || f.default_severity === 'critical').length;
  const recentlyPolled = feeds.filter(f => {
    if (!f.last_poll_at) return false;
    const hourAgo = new Date(Date.now() - 3600000);
    return new Date(f.last_poll_at) > hourAgo;
  }).length;
  const failedFeeds = feeds.filter(f => f.last_poll_status === 'failed').length;

  return (
    <div className="threat-intel-shell">
      <div className="ti-shell">
        <header className="ti-topbar">
          <div className="ti-title-group">
            <span className="ti-badge">Threat Intel</span>
            <div>
              <div className="ti-title">Threat Feeds</div>
              <div className="ti-subtitle">Curate feeds, schedule polling, and track ingest volume.</div>
            </div>
          </div>
          <div className="ti-topbar-actions">
            <span className="ti-pill">Feeds: {feeds.length}</span>
            <span className="ti-pill">Scheduler: {scheduler.running ? 'Running' : 'Paused'}</span>
          </div>
        </header>
        <div className="ti-panel">
          <div style={{ padding: '0' }}>
      {/* Tab Navigation */}
      <ThreatIntelTabs
        active="feeds"
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

      {/* Stats Cards Row - Compact */}
      <div style={{
        display: 'flex',
        gap: '0.75rem',
        marginBottom: '0.75rem'
      }}>
        {/* Total Feeds */}
        <div style={{
          background: 'rgba(59, 130, 246, 0.08)',
          border: '1px solid rgba(59, 130, 246, 0.2)',
          borderRadius: '6px',
          padding: '0.5rem 0.75rem',
          display: 'flex',
          alignItems: 'center',
          gap: '0.5rem'
        }}>
          <span style={{ fontSize: '1.1rem', fontWeight: '700', color: '#3b82f6' }}>{feeds.length}</span>
          <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>Feeds</span>
        </div>

        {/* Enabled */}
        <div style={{
          background: 'rgba(34, 197, 94, 0.08)',
          border: '1px solid rgba(34, 197, 94, 0.2)',
          borderRadius: '6px',
          padding: '0.5rem 0.75rem',
          display: 'flex',
          alignItems: 'center',
          gap: '0.5rem'
        }}>
          <span style={{ fontSize: '1.1rem', fontWeight: '700', color: '#22c55e' }}>{enabledCount}</span>
          <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>Enabled</span>
        </div>

        {/* Total IOCs */}
        <div style={{
          background: 'rgba(60, 179, 113, 0.08)',
          border: '1px solid rgba(60, 179, 113, 0.2)',
          borderRadius: '6px',
          padding: '0.5rem 0.75rem',
          display: 'flex',
          alignItems: 'center',
          gap: '0.5rem'
        }}>
          <span style={{ fontSize: '1.1rem', fontWeight: '700', color: '#3CB371' }}>{formatNumber(totalIOCs)}</span>
          <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>IOCs</span>
        </div>

        {/* High/Critical */}
        <div style={{
          background: 'rgba(249, 115, 22, 0.08)',
          border: '1px solid rgba(249, 115, 22, 0.2)',
          borderRadius: '6px',
          padding: '0.5rem 0.75rem',
          display: 'flex',
          alignItems: 'center',
          gap: '0.5rem'
        }}>
          <span style={{ fontSize: '1.1rem', fontWeight: '700', color: '#f97316' }}>{highSeverityFeeds}</span>
          <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>High/Critical</span>
        </div>

        {/* Scheduler Status */}
        <div style={{
          background: scheduler.running ? 'rgba(34, 197, 94, 0.08)' : 'rgba(107, 114, 128, 0.08)',
          border: `1px solid ${scheduler.running ? 'rgba(34, 197, 94, 0.2)' : 'rgba(107, 114, 128, 0.2)'}`,
          borderRadius: '6px',
          padding: '0.5rem 0.75rem',
          display: 'flex',
          alignItems: 'center',
          gap: '0.5rem'
        }}>
          <span style={{
            width: '8px',
            height: '8px',
            borderRadius: '50%',
            background: scheduler.running ? '#22c55e' : '#6b7280',
            boxShadow: scheduler.running ? '0 0 6px rgba(34, 197, 94, 0.5)' : 'none'
          }} />
          <span style={{ fontSize: '0.75rem', fontWeight: '600', color: scheduler.running ? '#22c55e' : '#6b7280' }}>
            {scheduler.running ? 'Scheduler On' : 'Scheduler Off'}
          </span>
        </div>
      </div>

      {/* Action Bar */}
      <div style={{
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        marginBottom: '1rem',
        background: 'var(--bg-secondary)',
        padding: '0.75rem 1rem',
        borderRadius: '8px',
        border: '1px solid var(--bg-tertiary)'
      }}>
        {/* Left side - Search */}
        <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center' }}>
          <div style={{ position: 'relative' }}>
            <span style={{
              position: 'absolute',
              left: '0.75rem',
              top: '50%',
              transform: 'translateY(-50%)',
              color: 'var(--text-muted)',
              fontSize: '0.85rem'
            }}>🔍</span>
            <input
              type="text"
              placeholder="Search feeds..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              style={{
                padding: '0.5rem 0.75rem 0.5rem 2rem',
                background: 'var(--bg-primary)',
                border: '1px solid var(--bg-tertiary)',
                borderRadius: '6px',
                color: 'var(--text-primary)',
                fontSize: '0.8rem',
                width: '220px'
              }}
            />
          </div>

          {/* Scheduler Controls */}
          <div style={{ position: 'relative' }}>
            <button
              onClick={toggleScheduler}
              style={{
                padding: '0.5rem 0.85rem',
                background: scheduler.running ? 'rgba(239, 68, 68, 0.1)' : 'rgba(34, 197, 94, 0.1)',
                border: `1px solid ${scheduler.running ? 'rgba(239, 68, 68, 0.3)' : 'rgba(34, 197, 94, 0.3)'}`,
                borderRadius: '6px',
                color: scheduler.running ? '#ef4444' : '#22c55e',
                fontSize: '0.8rem',
                fontWeight: '600',
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: '0.4rem'
              }}
            >
              {scheduler.running ? '⏹ Stop Scheduler' : '▶ Start Scheduler'}
            </button>

            <button
              onClick={() => setShowSchedulerSettings(!showSchedulerSettings)}
              style={{
                position: 'absolute',
                right: '-28px',
                top: '50%',
                transform: 'translateY(-50%)',
                padding: '0.35rem',
                background: 'transparent',
                border: '1px solid var(--bg-tertiary)',
                borderRadius: '4px',
                color: 'var(--text-muted)',
                fontSize: '0.7rem',
                cursor: 'pointer'
              }}
              title="Scheduler Settings"
            >
              ⚙️
            </button>

            {/* Scheduler Settings Dropdown */}
            {showSchedulerSettings && (
              <div style={{
                position: 'absolute',
                top: '100%',
                left: 0,
                marginTop: '0.5rem',
                background: 'var(--bg-primary)',
                border: '1px solid var(--bg-tertiary)',
                borderRadius: '8px',
                padding: '1rem',
                zIndex: 100,
                minWidth: '280px',
                boxShadow: '0 4px 20px rgba(0,0,0,0.4)'
              }}>
                <div style={{ fontSize: '0.85rem', fontWeight: '600', marginBottom: '0.75rem', color: 'var(--text-primary)' }}>
                  Scheduler Settings
                </div>

                <div style={{ marginBottom: '0.75rem' }}>
                  <label style={{ display: 'block', fontSize: '0.7rem', color: 'var(--text-muted)', marginBottom: '0.25rem' }}>
                    Cycle Interval (minutes)
                  </label>
                  <input
                    type="number"
                    value={schedulerConfig.interval_minutes}
                    onChange={(e) => setSchedulerConfig(prev => ({ ...prev, interval_minutes: parseInt(e.target.value) || 60 }))}
                    style={{
                      width: '100%',
                      padding: '0.4rem',
                      background: 'var(--bg-secondary)',
                      border: '1px solid var(--bg-tertiary)',
                      borderRadius: '4px',
                      color: 'var(--text-primary)',
                      fontSize: '0.8rem'
                    }}
                    min="5"
                    max="1440"
                  />
                </div>

                <div style={{ marginBottom: '0.75rem' }}>
                  <label style={{ display: 'block', fontSize: '0.7rem', color: 'var(--text-muted)', marginBottom: '0.25rem' }}>
                    Delay Between Feeds (seconds)
                  </label>
                  <input
                    type="number"
                    value={schedulerConfig.delay_between_feeds}
                    onChange={(e) => setSchedulerConfig(prev => ({ ...prev, delay_between_feeds: parseInt(e.target.value) || 5 }))}
                    style={{
                      width: '100%',
                      padding: '0.4rem',
                      background: 'var(--bg-secondary)',
                      border: '1px solid var(--bg-tertiary)',
                      borderRadius: '4px',
                      color: 'var(--text-primary)',
                      fontSize: '0.8rem'
                    }}
                    min="1"
                    max="60"
                  />
                </div>

                <div style={{ marginBottom: '0.75rem' }}>
                  <label style={{ display: 'block', fontSize: '0.7rem', color: 'var(--text-muted)', marginBottom: '0.25rem' }}>
                    Max Feeds Per Cycle
                  </label>
                  <input
                    type="number"
                    value={schedulerConfig.max_feeds_per_cycle}
                    onChange={(e) => setSchedulerConfig(prev => ({ ...prev, max_feeds_per_cycle: parseInt(e.target.value) || 10 }))}
                    style={{
                      width: '100%',
                      padding: '0.4rem',
                      background: 'var(--bg-secondary)',
                      border: '1px solid var(--bg-tertiary)',
                      borderRadius: '4px',
                      color: 'var(--text-primary)',
                      fontSize: '0.8rem'
                    }}
                    min="1"
                    max="50"
                  />
                </div>

                <div style={{ display: 'flex', gap: '0.5rem', justifyContent: 'flex-end' }}>
                  <button
                    onClick={() => setShowSchedulerSettings(false)}
                    style={{
                      padding: '0.4rem 0.75rem',
                      background: 'var(--bg-tertiary)',
                      border: 'none',
                      borderRadius: '4px',
                      color: 'var(--text-secondary)',
                      fontSize: '0.75rem',
                      cursor: 'pointer'
                    }}
                  >
                    Close
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Right side - Actions */}
        <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
          {/* Poll All Button */}
          <button
            onClick={pollAllFeeds}
            disabled={pollingAll}
            style={{
              padding: '0.5rem 0.85rem',
              background: pollingAll ? 'var(--bg-tertiary)' : 'rgba(59, 130, 246, 0.1)',
              border: '1px solid rgba(59, 130, 246, 0.3)',
              borderRadius: '6px',
              color: pollingAll ? 'var(--text-muted)' : '#3b82f6',
              fontWeight: '600',
              cursor: pollingAll ? 'not-allowed' : 'pointer',
              fontSize: '0.8rem',
              display: 'flex',
              alignItems: 'center',
              gap: '0.4rem'
            }}
          >
            {pollingAll ? '⏳ Polling...' : '🔄 Poll All'}
          </button>

          {/* Add Feed Button */}
          <button
            onClick={() => setShowAddModal(true)}
            style={{
              padding: '0.5rem 1rem',
              background: 'linear-gradient(135deg, #3CB371 0%, #2e8b57 100%)',
              border: 'none',
              borderRadius: '6px',
              color: 'white',
              fontWeight: '600',
              cursor: 'pointer',
              fontSize: '0.8rem',
              display: 'flex',
              alignItems: 'center',
              gap: '0.4rem',
              boxShadow: '0 2px 8px rgba(60, 179, 113, 0.3)'
            }}
          >
            + Add Custom Feed
          </button>
        </div>
      </div>

      {/* Active Filters Row */}
      <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap', alignItems: 'center', marginBottom: '0.75rem' }}>

          {/* Active Filters Display */}
          {(activeFilterCount > 0 || searchTerm) && (
            <div style={{ display: 'flex', gap: '0.35rem', alignItems: 'center', flexWrap: 'wrap' }}>
              {searchTerm && (
                <span style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '0.35rem',
                  padding: '0.25rem 0.5rem',
                  background: 'rgba(59, 130, 246, 0.15)',
                  border: '1px solid rgba(59, 130, 246, 0.3)',
                  borderRadius: '4px',
                  fontSize: '0.7rem',
                  color: '#3b82f6'
                }}>
                  Search: "{searchTerm}"
                  <button
                    onClick={() => setSearchTerm('')}
                    style={{ background: 'none', border: 'none', color: '#3b82f6', cursor: 'pointer', padding: 0, fontSize: '0.9rem' }}
                  >×</button>
                </span>
              )}
              {columnFilters.enabled !== null && (
                <span style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '0.35rem',
                  padding: '0.25rem 0.5rem',
                  background: 'rgba(34, 197, 94, 0.15)',
                  border: '1px solid rgba(34, 197, 94, 0.3)',
                  borderRadius: '4px',
                  fontSize: '0.7rem',
                  color: '#22c55e'
                }}>
                  Status: {columnFilters.enabled ? 'Enabled' : 'Disabled'}
                  <button
                    onClick={() => setColumnFilters(prev => ({ ...prev, enabled: null }))}
                    style={{ background: 'none', border: 'none', color: '#22c55e', cursor: 'pointer', padding: 0, fontSize: '0.9rem' }}
                  >×</button>
                </span>
              )}
              {columnFilters.category && (
                <span style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '0.35rem',
                  padding: '0.25rem 0.5rem',
                  background: `${getCategoryColor(columnFilters.category)}20`,
                  border: `1px solid ${getCategoryColor(columnFilters.category)}50`,
                  borderRadius: '4px',
                  fontSize: '0.7rem',
                  color: getCategoryColor(columnFilters.category)
                }}>
                  Category: {columnFilters.category.replace('_', ' ')}
                  <button
                    onClick={() => setColumnFilters(prev => ({ ...prev, category: null }))}
                    style={{ background: 'none', border: 'none', color: getCategoryColor(columnFilters.category), cursor: 'pointer', padding: 0, fontSize: '0.9rem' }}
                  >×</button>
                </span>
              )}
              {columnFilters.severity && (
                <span style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '0.35rem',
                  padding: '0.25rem 0.5rem',
                  background: `${getSeverityColor(columnFilters.severity)}20`,
                  border: `1px solid ${getSeverityColor(columnFilters.severity)}50`,
                  borderRadius: '4px',
                  fontSize: '0.7rem',
                  color: getSeverityColor(columnFilters.severity)
                }}>
                  Severity: {columnFilters.severity}
                  <button
                    onClick={() => setColumnFilters(prev => ({ ...prev, severity: null }))}
                    style={{ background: 'none', border: 'none', color: getSeverityColor(columnFilters.severity), cursor: 'pointer', padding: 0, fontSize: '0.9rem' }}
                  >×</button>
                </span>
              )}
              {columnFilters.type && (
                <span style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '0.35rem',
                  padding: '0.25rem 0.5rem',
                  background: 'rgba(139, 92, 246, 0.15)',
                  border: '1px solid rgba(139, 92, 246, 0.3)',
                  borderRadius: '4px',
                  fontSize: '0.7rem',
                  color: '#3CB371'
                }}>
                  Type: {columnFilters.type}
                  <button
                    onClick={() => setColumnFilters(prev => ({ ...prev, type: null }))}
                    style={{ background: 'none', border: 'none', color: '#3CB371', cursor: 'pointer', padding: 0, fontSize: '0.9rem' }}
                  >×</button>
                </span>
              )}
              <button
                onClick={clearAllFilters}
                style={{
                  padding: '0.25rem 0.5rem',
                  background: 'rgba(239, 68, 68, 0.1)',
                  border: '1px solid rgba(239, 68, 68, 0.3)',
                  borderRadius: '4px',
                  fontSize: '0.7rem',
                  color: '#ef4444',
                  cursor: 'pointer',
                  fontWeight: '600'
                }}
              >
                Clear All
              </button>
            </div>
          )}
      </div>

      {/* Poll Result Notification */}
      {pollResult && (
        <div style={{
          padding: '0.75rem 1rem',
          marginBottom: '0.75rem',
          background: pollResult.success ? 'rgba(34, 197, 94, 0.1)' : 'rgba(239, 68, 68, 0.1)',
          border: `1px solid ${pollResult.success ? 'rgba(34, 197, 94, 0.3)' : 'rgba(239, 68, 68, 0.3)'}`,
          borderRadius: '6px',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          fontSize: '0.8rem'
        }}>
          <div>
            <strong style={{ color: pollResult.success ? '#22c55e' : '#ef4444' }}>
              {pollResult.success ? 'Poll Complete' : 'Poll Failed'}
            </strong>
            {pollResult.success ? (
              <span style={{ marginLeft: '0.75rem', color: 'var(--text-secondary)' }}>
                {pollResult.iocs_new} new, {pollResult.iocs_updated} updated, {pollResult.iocs_skipped} skipped
                ({pollResult.duration_ms}ms)
              </span>
            ) : (
              <span style={{ marginLeft: '0.75rem', color: 'var(--text-secondary)' }}>
                {pollResult.error}
              </span>
            )}
          </div>
          <button
            onClick={() => setPollResult(null)}
            style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', fontSize: '1rem' }}
          >
            ×
          </button>
        </div>
      )}

      {/* Table */}
      <div style={{
        background: 'var(--bg-secondary)',
        borderRadius: '10px',
        border: '1px solid var(--bg-tertiary)',
        overflow: 'hidden',
        boxShadow: '0 2px 8px rgba(0, 0, 0, 0.15)'
      }}>
        <table className="ti-table">
          <thead>
            <tr style={{ background: 'var(--bg-primary)', borderBottom: '2px solid var(--bg-tertiary)' }}>
              {/* Status Column with Filter */}
              <th style={{ ...thStyle, width: '60px', position: 'relative' }} className="column-filter-dropdown">
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '0.25rem' }}>
                  <span
                    onClick={() => handleSort('enabled')}
                    style={{ cursor: 'pointer' }}
                  >
                    Status {sortConfig.key === 'enabled' && (sortConfig.direction === 'asc' ? '↑' : '↓')}
                  </span>
                  <button
                    onClick={(e) => toggleFilterDropdown('enabled', e)}
                    style={{
                      background: columnFilters.enabled !== null ? 'rgba(34, 197, 94, 0.2)' : 'transparent',
                      border: 'none',
                      color: columnFilters.enabled !== null ? '#22c55e' : 'var(--text-muted)',
                      cursor: 'pointer',
                      fontSize: '0.7rem',
                      padding: '0.1rem 0.2rem',
                      borderRadius: '3px'
                    }}
                  >▼</button>
                </div>
                {activeFilterColumn === 'enabled' && (
                  <div style={dropdownStyle}>
                    <div
                      onClick={() => { setColumnFilters(prev => ({ ...prev, enabled: null })); setActiveFilterColumn(null); }}
                      style={{ ...dropdownItemStyle, fontWeight: columnFilters.enabled === null ? '700' : '400' }}
                    >All</div>
                    <div
                      onClick={() => { setColumnFilters(prev => ({ ...prev, enabled: true })); setActiveFilterColumn(null); }}
                      style={{ ...dropdownItemStyle, fontWeight: columnFilters.enabled === true ? '700' : '400' }}
                    >Enabled</div>
                    <div
                      onClick={() => { setColumnFilters(prev => ({ ...prev, enabled: false })); setActiveFilterColumn(null); }}
                      style={{ ...dropdownItemStyle, fontWeight: columnFilters.enabled === false ? '700' : '400' }}
                    >Disabled</div>
                  </div>
                )}
              </th>

              {/* Feed Name Column with Type Filter */}
              <th style={{ ...thStyle, textAlign: 'left', position: 'relative' }} className="column-filter-dropdown">
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
                  <span
                    onClick={() => handleSort('name')}
                    style={{ cursor: 'pointer' }}
                  >
                    Feed Name {sortConfig.key === 'name' && (sortConfig.direction === 'asc' ? '↑' : '↓')}
                  </span>
                  <button
                    onClick={(e) => toggleFilterDropdown('type', e)}
                    style={{
                      background: columnFilters.type !== null ? 'rgba(139, 92, 246, 0.2)' : 'transparent',
                      border: 'none',
                      color: columnFilters.type !== null ? '#3CB371' : 'var(--text-muted)',
                      cursor: 'pointer',
                      fontSize: '0.7rem',
                      padding: '0.1rem 0.2rem',
                      borderRadius: '3px'
                    }}
                  >▼</button>
                </div>
                {activeFilterColumn === 'type' && (
                  <div style={dropdownStyle}>
                    <div
                      onClick={() => { setColumnFilters(prev => ({ ...prev, type: null })); setActiveFilterColumn(null); }}
                      style={{ ...dropdownItemStyle, fontWeight: columnFilters.type === null ? '700' : '400' }}
                    >All</div>
                    <div
                      onClick={() => { setColumnFilters(prev => ({ ...prev, type: 'preconfigured' })); setActiveFilterColumn(null); }}
                      style={{ ...dropdownItemStyle, fontWeight: columnFilters.type === 'preconfigured' ? '700' : '400' }}
                    >Preconfigured</div>
                    <div
                      onClick={() => { setColumnFilters(prev => ({ ...prev, type: 'custom' })); setActiveFilterColumn(null); }}
                      style={{ ...dropdownItemStyle, fontWeight: columnFilters.type === 'custom' ? '700' : '400' }}
                    >Custom</div>
                  </div>
                )}
              </th>

              {/* Category Column with Filter */}
              <th style={{ ...thStyle, width: '120px', position: 'relative' }} className="column-filter-dropdown">
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '0.25rem' }}>
                  <span>Category</span>
                  <button
                    onClick={(e) => toggleFilterDropdown('category', e)}
                    style={{
                      background: columnFilters.category !== null ? `${getCategoryColor(columnFilters.category)}30` : 'transparent',
                      border: 'none',
                      color: columnFilters.category !== null ? getCategoryColor(columnFilters.category) : 'var(--text-muted)',
                      cursor: 'pointer',
                      fontSize: '0.7rem',
                      padding: '0.1rem 0.2rem',
                      borderRadius: '3px'
                    }}
                  >▼</button>
                </div>
                {activeFilterColumn === 'category' && (
                  <div style={dropdownStyle}>
                    <div
                      onClick={() => { setColumnFilters(prev => ({ ...prev, category: null })); setActiveFilterColumn(null); }}
                      style={{ ...dropdownItemStyle, fontWeight: columnFilters.category === null ? '700' : '400' }}
                    >All Categories</div>
                    {categories.map(cat => (
                      <div
                        key={cat}
                        onClick={() => { setColumnFilters(prev => ({ ...prev, category: cat })); setActiveFilterColumn(null); }}
                        style={{ ...dropdownItemStyle, fontWeight: columnFilters.category === cat ? '700' : '400', color: getCategoryColor(cat) }}
                      >{cat.replace('_', ' ')}</div>
                    ))}
                  </div>
                )}
              </th>

              {/* Severity Column with Filter */}
              <th style={{ ...thStyle, width: '80px', position: 'relative' }} className="column-filter-dropdown">
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '0.25rem' }}>
                  <span>Severity</span>
                  <button
                    onClick={(e) => toggleFilterDropdown('severity', e)}
                    style={{
                      background: columnFilters.severity !== null ? `${getSeverityColor(columnFilters.severity)}30` : 'transparent',
                      border: 'none',
                      color: columnFilters.severity !== null ? getSeverityColor(columnFilters.severity) : 'var(--text-muted)',
                      cursor: 'pointer',
                      fontSize: '0.7rem',
                      padding: '0.1rem 0.2rem',
                      borderRadius: '3px'
                    }}
                  >▼</button>
                </div>
                {activeFilterColumn === 'severity' && (
                  <div style={dropdownStyle}>
                    <div
                      onClick={() => { setColumnFilters(prev => ({ ...prev, severity: null })); setActiveFilterColumn(null); }}
                      style={{ ...dropdownItemStyle, fontWeight: columnFilters.severity === null ? '700' : '400' }}
                    >All Severities</div>
                    {severities.map(sev => (
                      <div
                        key={sev}
                        onClick={() => { setColumnFilters(prev => ({ ...prev, severity: sev })); setActiveFilterColumn(null); }}
                        style={{ ...dropdownItemStyle, fontWeight: columnFilters.severity === sev ? '700' : '400', color: getSeverityColor(sev) }}
                      >{sev}</div>
                    ))}
                  </div>
                )}
              </th>

              <th style={{ ...thStyle, width: '70px' }}>Interval</th>
              <th
                onClick={() => handleSort('last_poll_at')}
                style={{ ...thStyle, width: '90px', cursor: 'pointer' }}
              >
                Last Poll {sortConfig.key === 'last_poll_at' && (sortConfig.direction === 'asc' ? '↑' : '↓')}
              </th>
              <th style={{ ...thStyle, width: '70px' }}>Last #</th>
              <th
                onClick={() => handleSort('total_iocs_ingested')}
                style={{ ...thStyle, width: '80px', cursor: 'pointer' }}
              >
                Total IOCs {sortConfig.key === 'total_iocs_ingested' && (sortConfig.direction === 'asc' ? '↑' : '↓')}
              </th>
              <th style={{ ...thStyle, width: '120px' }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {paginatedFeeds.map((feed, idx) => (
              <tr
                key={feed.feed_id}
                style={{
                  borderBottom: '1px solid var(--bg-tertiary)',
                  background: idx % 2 === 0 ? 'transparent' : 'rgba(0, 0, 0, 0.08)',
                  opacity: feed.enabled ? 1 : 0.6,
                  transition: 'background 0.15s ease'
                }}
                onMouseEnter={(e) => e.currentTarget.style.background = 'rgba(59, 130, 246, 0.08)'}
                onMouseLeave={(e) => e.currentTarget.style.background = idx % 2 === 0 ? 'transparent' : 'rgba(0, 0, 0, 0.08)'}
              >
                {/* Enable Toggle */}
                <td style={{ ...tdStyle, textAlign: 'center' }}>
                  <label style={{
                    position: 'relative',
                    display: 'inline-block',
                    width: '36px',
                    height: '20px',
                    cursor: togglingFeed === feed.feed_id ? 'wait' : 'pointer'
                  }}>
                    <input
                      type="checkbox"
                      checked={feed.enabled}
                      disabled={togglingFeed === feed.feed_id}
                      onChange={(e) => toggleFeed(feed.feed_id, e.target.checked)}
                      style={{ opacity: 0, width: 0, height: 0 }}
                    />
                    <span style={{
                      position: 'absolute',
                      top: 0, left: 0, right: 0, bottom: 0,
                      background: togglingFeed === feed.feed_id ? '#6b7280' : (feed.enabled ? '#22c55e' : '#475569'),
                      borderRadius: '20px',
                      transition: 'all 0.3s ease'
                    }}>
                      <span style={{
                        position: 'absolute',
                        width: '16px',
                        height: '16px',
                        background: 'white',
                        borderRadius: '50%',
                        top: '2px',
                        left: feed.enabled ? '18px' : '2px',
                        transition: 'all 0.3s ease'
                      }} />
                    </span>
                  </label>
                </td>

                {/* Feed Name */}
                <td style={{ ...tdStyle, textAlign: 'left' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    <span style={{ fontWeight: '500', color: 'var(--text-primary)' }}>{feed.name}</span>
                    {!feed.is_preconfigured && (
                      <span style={{
                        fontSize: '0.6rem',
                        padding: '0.1rem 0.3rem',
                        background: 'rgba(139, 92, 246, 0.2)',
                        color: '#3CB371',
                        borderRadius: '3px',
                        fontWeight: '600'
                      }}>
                        CUSTOM
                      </span>
                    )}
                  </div>
                </td>

                {/* Category */}
                <td style={{ ...tdStyle, textAlign: 'center' }}>
                  <span style={{
                    fontSize: '0.65rem',
                    padding: '0.2rem 0.4rem',
                    background: `${getCategoryColor(feed.category)}20`,
                    color: getCategoryColor(feed.category),
                    borderRadius: '3px',
                    fontWeight: '600',
                    textTransform: 'uppercase',
                    whiteSpace: 'nowrap'
                  }}>
                    {feed.category.replace('_', ' ')}
                  </span>
                </td>

                {/* Severity */}
                <td style={{ ...tdStyle, textAlign: 'center' }}>
                  <span style={{
                    fontSize: '0.65rem',
                    padding: '0.2rem 0.4rem',
                    background: `${getSeverityColor(feed.default_severity)}20`,
                    color: getSeverityColor(feed.default_severity),
                    borderRadius: '3px',
                    fontWeight: '600',
                    textTransform: 'uppercase'
                  }}>
                    {feed.default_severity}
                  </span>
                </td>

                {/* Poll Interval */}
                <td style={{ ...tdStyle, textAlign: 'center', color: 'var(--text-muted)' }}>
                  {feed.poll_interval_minutes >= 1440
                    ? `${Math.floor(feed.poll_interval_minutes / 1440)}d`
                    : feed.poll_interval_minutes >= 60
                    ? `${Math.floor(feed.poll_interval_minutes / 60)}h`
                    : `${feed.poll_interval_minutes}m`}
                </td>

                {/* Last Poll */}
                <td style={{ ...tdStyle, textAlign: 'center' }}>
                  <span style={{
                    color: feed.last_poll_status === 'success' ? 'var(--text-secondary)' :
                           feed.last_poll_status === 'failed' ? '#ef4444' : 'var(--text-muted)'
                  }}>
                    {formatTimeAgo(feed.last_poll_at)}
                  </span>
                </td>

                {/* Last Poll Count */}
                <td style={{ ...tdStyle, textAlign: 'center', color: 'var(--text-secondary)' }}>
                  {formatNumber(feed.last_poll_ioc_count)}
                </td>

                {/* Total IOCs */}
                <td style={{ ...tdStyle, textAlign: 'center' }}>
                  <span style={{
                    fontWeight: '600',
                    color: feed.total_iocs_ingested > 0 ? '#22c55e' : 'var(--text-muted)'
                  }}>
                    {formatNumber(feed.total_iocs_ingested)}
                  </span>
                </td>

                {/* Actions */}
                <td style={{ ...tdStyle, textAlign: 'center' }}>
                  <div style={{ display: 'flex', gap: '0.35rem', justifyContent: 'center' }}>
                    <button
                      onClick={() => pollFeed(feed.feed_id)}
                      disabled={pollingFeed === feed.feed_id}
                      title="Poll Now"
                      style={{
                        padding: '0.25rem 0.5rem',
                        background: pollingFeed === feed.feed_id ? 'rgba(59, 130, 246, 0.3)' : 'rgba(59, 130, 246, 0.1)',
                        border: '1px solid rgba(59, 130, 246, 0.3)',
                        borderRadius: '4px',
                        color: '#3b82f6',
                        fontSize: '0.7rem',
                        fontWeight: '600',
                        cursor: pollingFeed === feed.feed_id ? 'wait' : 'pointer'
                      }}
                    >
                      {pollingFeed === feed.feed_id ? '...' : 'Poll'}
                    </button>
                    <button
                      onClick={() => setSelectedFeed(feed)}
                      title="View Details"
                      style={{
                        padding: '0.25rem 0.5rem',
                        background: 'rgba(100, 116, 139, 0.1)',
                        border: '1px solid rgba(100, 116, 139, 0.3)',
                        borderRadius: '4px',
                        color: 'var(--text-secondary)',
                        fontSize: '0.7rem',
                        fontWeight: '600',
                        cursor: 'pointer'
                      }}
                    >
                      Info
                    </button>
                    {!feed.is_preconfigured && (
                      <button
                        onClick={() => deleteFeed(feed.feed_id)}
                        title="Delete"
                        style={{
                          padding: '0.25rem 0.5rem',
                          background: 'rgba(239, 68, 68, 0.1)',
                          border: '1px solid rgba(239, 68, 68, 0.3)',
                          borderRadius: '4px',
                          color: '#ef4444',
                          fontSize: '0.7rem',
                          fontWeight: '600',
                          cursor: 'pointer'
                        }}
                      >
                        ×
                      </button>
                    )}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>

        {filteredFeeds.length === 0 && (
          <div style={{
            textAlign: 'center',
            padding: '2rem',
            color: 'var(--text-muted)'
          }}>
            No feeds match your filters.
          </div>
        )}

        {/* Pagination */}
        {filteredFeeds.length > 0 && (
          <div style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            padding: '0.75rem 1rem',
            borderTop: '1px solid var(--bg-tertiary)',
            background: 'var(--bg-primary)'
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.8rem', color: 'var(--text-muted)' }}>
              <span>Show</span>
              <select
                value={rowsPerPage}
                onChange={(e) => setRowsPerPage(parseInt(e.target.value))}
                style={{
                  padding: '0.25rem 0.5rem',
                  background: 'var(--bg-secondary)',
                  border: '1px solid var(--bg-tertiary)',
                  borderRadius: '4px',
                  color: 'var(--text-primary)',
                  fontSize: '0.8rem'
                }}
              >
                <option value={10}>10</option>
                <option value={20}>20</option>
                <option value={30}>30</option>
                <option value={40}>40</option>
                <option value={50}>50</option>
              </select>
              <span>rows</span>
              <span style={{ marginLeft: '0.5rem', color: 'var(--text-secondary)' }}>
                | Showing {((currentPage - 1) * rowsPerPage) + 1}-{Math.min(currentPage * rowsPerPage, filteredFeeds.length)} of {filteredFeeds.length}
              </span>
            </div>

            <div style={{ display: 'flex', gap: '0.25rem' }}>
              <button
                onClick={() => setCurrentPage(1)}
                disabled={currentPage === 1}
                style={{
                  padding: '0.35rem 0.6rem',
                  background: currentPage === 1 ? 'var(--bg-tertiary)' : 'var(--bg-secondary)',
                  border: '1px solid var(--bg-tertiary)',
                  borderRadius: '4px',
                  color: currentPage === 1 ? 'var(--text-muted)' : 'var(--text-primary)',
                  fontSize: '0.75rem',
                  cursor: currentPage === 1 ? 'not-allowed' : 'pointer'
                }}
              >
                ««
              </button>
              <button
                onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
                disabled={currentPage === 1}
                style={{
                  padding: '0.35rem 0.6rem',
                  background: currentPage === 1 ? 'var(--bg-tertiary)' : 'var(--bg-secondary)',
                  border: '1px solid var(--bg-tertiary)',
                  borderRadius: '4px',
                  color: currentPage === 1 ? 'var(--text-muted)' : 'var(--text-primary)',
                  fontSize: '0.75rem',
                  cursor: currentPage === 1 ? 'not-allowed' : 'pointer'
                }}
              >
                ‹
              </button>
              <span style={{
                padding: '0.35rem 0.75rem',
                background: 'rgba(102, 126, 234, 0.15)',
                border: '1px solid rgba(102, 126, 234, 0.3)',
                borderRadius: '4px',
                color: '#3CB371',
                fontSize: '0.75rem',
                fontWeight: '600'
              }}>
                {currentPage} / {totalPages || 1}
              </span>
              <button
                onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))}
                disabled={currentPage >= totalPages}
                style={{
                  padding: '0.35rem 0.6rem',
                  background: currentPage >= totalPages ? 'var(--bg-tertiary)' : 'var(--bg-secondary)',
                  border: '1px solid var(--bg-tertiary)',
                  borderRadius: '4px',
                  color: currentPage >= totalPages ? 'var(--text-muted)' : 'var(--text-primary)',
                  fontSize: '0.75rem',
                  cursor: currentPage >= totalPages ? 'not-allowed' : 'pointer'
                }}
              >
                ›
              </button>
              <button
                onClick={() => setCurrentPage(totalPages)}
                disabled={currentPage >= totalPages}
                style={{
                  padding: '0.35rem 0.6rem',
                  background: currentPage >= totalPages ? 'var(--bg-tertiary)' : 'var(--bg-secondary)',
                  border: '1px solid var(--bg-tertiary)',
                  borderRadius: '4px',
                  color: currentPage >= totalPages ? 'var(--text-muted)' : 'var(--text-primary)',
                  fontSize: '0.75rem',
                  cursor: currentPage >= totalPages ? 'not-allowed' : 'pointer'
                }}
              >
                »»
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Add Feed Modal */}
      {showAddModal && (
        <AddFeedModal
          formatOptions={formatOptions}
          onClose={() => setShowAddModal(false)}
          onSave={() => {
            setShowAddModal(false);
            fetchFeeds();
          }}
        />
      )}

      {/* Feed Details Modal */}
      {selectedFeed && (
        <FeedDetailsModal
          feed={selectedFeed}
          onClose={() => setSelectedFeed(null)}
        />
      )}
          </div>
        </div>
      </div>
    </div>
  );
}

// Table styles
const thStyle = {
  padding: '0.75rem 0.6rem',
  fontWeight: '600',
  color: 'var(--text-muted)',
  textAlign: 'center',
  fontSize: '0.7rem',
  textTransform: 'uppercase',
  letterSpacing: '0.05em',
  background: 'var(--bg-primary)'
};

const tdStyle = {
  padding: '0.65rem 0.5rem',
  verticalAlign: 'middle'
};

const dropdownStyle = {
  position: 'absolute',
  top: '100%',
  left: '50%',
  transform: 'translateX(-50%)',
  background: 'var(--bg-primary)',
  border: '1px solid var(--bg-tertiary)',
  borderRadius: '6px',
  boxShadow: '0 4px 12px rgba(0,0,0,0.3)',
  zIndex: 100,
  minWidth: '120px',
  maxHeight: '200px',
  overflowY: 'auto',
  marginTop: '0.25rem'
};

const dropdownItemStyle = {
  padding: '0.5rem 0.75rem',
  cursor: 'pointer',
  fontSize: '0.75rem',
  color: 'var(--text-secondary)',
  borderBottom: '1px solid var(--bg-tertiary)',
  textTransform: 'capitalize',
  whiteSpace: 'nowrap'
};


// ============================================================================
// ADD FEED MODAL
// ============================================================================

function AddFeedModal({ formatOptions, onClose, onSave }) {
  const [form, setForm] = useState({
    name: '',
    url: '',
    description: '',
    format: 'txt_lines',
    category: 'mixed',
    poll_interval_minutes: 60,
    default_severity: 'medium',
    ioc_type: '',
    drop_private_ips: true,
    drop_internal_domains: true
  });
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState(null);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setSaving(true);
    setError(null);

    try {
      const response = await fetch(`${API_BASE_URL}/api/v1/threat-feeds`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          ...form,
          ioc_type: form.ioc_type || null
        })
      });

      if (!response.ok) {
        const data = await response.json();
        throw new Error(data.detail || 'Failed to create feed');
      }

      onSave();
    } catch (err) {
      setError(err.message);
    } finally {
      setSaving(false);
    }
  };

  return (
    <div style={{
      position: 'fixed',
      top: 0, left: 0, right: 0, bottom: 0,
      background: 'rgba(0, 0, 0, 0.7)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      zIndex: 1000
    }}>
      <div style={{
        background: 'var(--bg-primary)',
        borderRadius: '10px',
        width: '100%',
        maxWidth: '500px',
        maxHeight: '85vh',
        overflow: 'auto',
        border: '1px solid var(--bg-tertiary)'
      }}>
        <div style={{
          padding: '1rem 1.25rem',
          borderBottom: '1px solid var(--bg-tertiary)',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center'
        }}>
          <h2 style={{ margin: 0, fontSize: '1.1rem', fontWeight: '700' }}>Add Custom Feed</h2>
          <button onClick={onClose} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', fontSize: '1.25rem', cursor: 'pointer' }}>
            ×
          </button>
        </div>

        <form onSubmit={handleSubmit} style={{ padding: '1.25rem' }}>
          {error && (
            <div style={{
              padding: '0.6rem',
              background: 'rgba(239, 68, 68, 0.1)',
              border: '1px solid rgba(239, 68, 68, 0.3)',
              borderRadius: '6px',
              color: '#ef4444',
              marginBottom: '1rem',
              fontSize: '0.8rem'
            }}>
              {error}
            </div>
          )}

          <div style={{ display: 'grid', gap: '0.75rem' }}>
            <div>
              <label style={labelStyle}>Feed Name *</label>
              <input
                type="text"
                value={form.name}
                onChange={(e) => setForm({ ...form, name: e.target.value })}
                required
                placeholder="My Custom Feed"
                style={inputStyle}
              />
            </div>

            <div>
              <label style={labelStyle}>Feed URL *</label>
              <input
                type="url"
                value={form.url}
                onChange={(e) => setForm({ ...form, url: e.target.value })}
                required
                placeholder="https://example.com/feed.txt"
                style={inputStyle}
              />
            </div>

            <div>
              <label style={labelStyle}>Description</label>
              <input
                type="text"
                value={form.description}
                onChange={(e) => setForm({ ...form, description: e.target.value })}
                placeholder="What does this feed contain?"
                style={inputStyle}
              />
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
              <div>
                <label style={labelStyle}>Format</label>
                <select
                  value={form.format}
                  onChange={(e) => setForm({ ...form, format: e.target.value })}
                  style={inputStyle}
                >
                  {formatOptions?.formats?.map(f => (
                    <option key={f.id} value={f.id}>{f.name}</option>
                  )) || (
                    <>
                      <option value="txt_lines">Plain Text</option>
                      <option value="csv">CSV</option>
                      <option value="json">JSON</option>
                      <option value="json_lines">JSON Lines</option>
                    </>
                  )}
                </select>
              </div>

              <div>
                <label style={labelStyle}>Category</label>
                <select
                  value={form.category}
                  onChange={(e) => setForm({ ...form, category: e.target.value })}
                  style={inputStyle}
                >
                  {formatOptions?.categories?.map(c => (
                    <option key={c.id} value={c.id}>{c.name}</option>
                  )) || (
                    <>
                      <option value="ip_blocklist">IP Blocklist</option>
                      <option value="domain_blocklist">Domain Blocklist</option>
                      <option value="url_blocklist">URL Blocklist</option>
                      <option value="hash_list">Hash List</option>
                      <option value="mixed">Mixed</option>
                      <option value="cve">CVE</option>
                    </>
                  )}
                </select>
              </div>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
              <div>
                <label style={labelStyle}>Poll Interval (min)</label>
                <input
                  type="number"
                  value={form.poll_interval_minutes}
                  onChange={(e) => setForm({ ...form, poll_interval_minutes: parseInt(e.target.value) || 60 })}
                  min={5}
                  max={10080}
                  style={inputStyle}
                />
              </div>

              <div>
                <label style={labelStyle}>Default Severity</label>
                <select
                  value={form.default_severity}
                  onChange={(e) => setForm({ ...form, default_severity: e.target.value })}
                  style={inputStyle}
                >
                  <option value="critical">Critical</option>
                  <option value="high">High</option>
                  <option value="medium">Medium</option>
                  <option value="low">Low</option>
                </select>
              </div>
            </div>

            <div>
              <label style={labelStyle}>IOC Type (auto-detect if empty)</label>
              <select
                value={form.ioc_type}
                onChange={(e) => setForm({ ...form, ioc_type: e.target.value })}
                style={inputStyle}
              >
                <option value="">Auto-detect</option>
                {formatOptions?.ioc_types?.map(t => (
                  <option key={t.id} value={t.id}>{t.name}</option>
                )) || (
                  <>
                    <option value="ip">IP Address</option>
                    <option value="domain">Domain</option>
                    <option value="url">URL</option>
                    <option value="hash_sha256">SHA256 Hash</option>
                    <option value="hash_md5">MD5 Hash</option>
                  </>
                )}
              </select>
            </div>

            <div style={{ display: 'flex', gap: '1.5rem' }}>
              <label style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', cursor: 'pointer' }}>
                <input
                  type="checkbox"
                  checked={form.drop_private_ips}
                  onChange={(e) => setForm({ ...form, drop_private_ips: e.target.checked })}
                />
                <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>Drop private IPs</span>
              </label>
              <label style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', cursor: 'pointer' }}>
                <input
                  type="checkbox"
                  checked={form.drop_internal_domains}
                  onChange={(e) => setForm({ ...form, drop_internal_domains: e.target.checked })}
                />
                <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>Drop internal domains</span>
              </label>
            </div>
          </div>

          <div style={{ display: 'flex', gap: '0.75rem', marginTop: '1.25rem', justifyContent: 'flex-end' }}>
            <button
              type="button"
              onClick={onClose}
              style={{
                padding: '0.5rem 1rem',
                background: 'var(--bg-secondary)',
                border: '1px solid var(--bg-tertiary)',
                borderRadius: '6px',
                color: 'var(--text-secondary)',
                fontWeight: '600',
                cursor: 'pointer',
                fontSize: '0.8rem'
              }}
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={saving}
              style={{
                padding: '0.5rem 1rem',
                background: 'linear-gradient(135deg, #3CB371 0%, #2e8b57 100%)',
                border: 'none',
                borderRadius: '6px',
                color: 'white',
                fontWeight: '600',
                cursor: saving ? 'wait' : 'pointer',
                opacity: saving ? 0.7 : 1,
                fontSize: '0.8rem'
              }}
            >
              {saving ? 'Creating...' : 'Create Feed'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

const labelStyle = {
  display: 'block',
  fontSize: '0.75rem',
  fontWeight: '600',
  marginBottom: '0.35rem',
  color: 'var(--text-primary)'
};

const inputStyle = {
  width: '100%',
  padding: '0.5rem 0.75rem',
  background: 'var(--bg-secondary)',
  border: '1px solid var(--bg-tertiary)',
  borderRadius: '6px',
  color: 'var(--text-primary)',
  fontSize: '0.8rem'
};


// ============================================================================
// FEED DETAILS MODAL
// ============================================================================

function FeedDetailsModal({ feed, onClose }) {
  return (
    <div style={{
      position: 'fixed',
      top: 0, left: 0, right: 0, bottom: 0,
      background: 'rgba(0, 0, 0, 0.7)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      zIndex: 1000
    }}>
      <div style={{
        background: 'var(--bg-primary)',
        borderRadius: '10px',
        width: '100%',
        maxWidth: '450px',
        maxHeight: '85vh',
        overflow: 'auto',
        border: '1px solid var(--bg-tertiary)'
      }}>
        <div style={{
          padding: '1rem 1.25rem',
          borderBottom: '1px solid var(--bg-tertiary)',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center'
        }}>
          <h2 style={{ margin: 0, fontSize: '1.1rem', fontWeight: '700' }}>Feed Details</h2>
          <button onClick={onClose} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', fontSize: '1.25rem', cursor: 'pointer' }}>
            ×
          </button>
        </div>

        <div style={{ padding: '1.25rem' }}>
          <h3 style={{ margin: '0 0 0.35rem 0', fontSize: '1rem', color: 'var(--text-primary)' }}>{feed.name}</h3>
          <p style={{ margin: '0 0 1rem 0', fontSize: '0.8rem', color: 'var(--text-muted)' }}>{feed.description || 'No description'}</p>

          <div style={{ display: 'grid', gap: '0.75rem', fontSize: '0.8rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', padding: '0.5rem', background: 'var(--bg-secondary)', borderRadius: '4px' }}>
              <span style={{ color: 'var(--text-muted)' }}>Feed ID</span>
              <code style={{ color: 'var(--text-secondary)', fontSize: '0.75rem' }}>{feed.feed_id}</code>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', padding: '0.5rem', background: 'var(--bg-secondary)', borderRadius: '4px' }}>
              <span style={{ color: 'var(--text-muted)' }}>URL</span>
              <span style={{ color: 'var(--text-secondary)', maxWidth: '200px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{feed.url}</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', padding: '0.5rem', background: 'var(--bg-secondary)', borderRadius: '4px' }}>
              <span style={{ color: 'var(--text-muted)' }}>Format</span>
              <span style={{ color: 'var(--text-secondary)' }}>{feed.format}</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', padding: '0.5rem', background: 'var(--bg-secondary)', borderRadius: '4px' }}>
              <span style={{ color: 'var(--text-muted)' }}>Category</span>
              <span style={{ color: 'var(--text-secondary)' }}>{feed.category}</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', padding: '0.5rem', background: 'var(--bg-secondary)', borderRadius: '4px' }}>
              <span style={{ color: 'var(--text-muted)' }}>IOC Type</span>
              <span style={{ color: 'var(--text-secondary)' }}>{feed.ioc_type || 'Auto-detect'}</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', padding: '0.5rem', background: 'var(--bg-secondary)', borderRadius: '4px' }}>
              <span style={{ color: 'var(--text-muted)' }}>Poll Interval</span>
              <span style={{ color: 'var(--text-secondary)' }}>{feed.poll_interval_minutes} minutes</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', padding: '0.5rem', background: 'var(--bg-secondary)', borderRadius: '4px' }}>
              <span style={{ color: 'var(--text-muted)' }}>Total IOCs Ingested</span>
              <span style={{ color: '#22c55e', fontWeight: '600' }}>{feed.total_iocs_ingested || 0}</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', padding: '0.5rem', background: 'var(--bg-secondary)', borderRadius: '4px' }}>
              <span style={{ color: 'var(--text-muted)' }}>Last Poll</span>
              <span style={{ color: 'var(--text-secondary)' }}>{feed.last_poll_at ? new Date(feed.last_poll_at).toLocaleString() : 'Never'}</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', padding: '0.5rem', background: 'var(--bg-secondary)', borderRadius: '4px' }}>
              <span style={{ color: 'var(--text-muted)' }}>Type</span>
              <span style={{ color: feed.is_preconfigured ? '#3b82f6' : '#3CB371', fontWeight: '600' }}>
                {feed.is_preconfigured ? 'Preconfigured' : 'Custom'}
              </span>
            </div>
          </div>

          <div style={{ marginTop: '1.25rem' }}>
            <button
              onClick={onClose}
              style={{
                width: '100%',
                padding: '0.5rem',
                background: 'var(--bg-secondary)',
                border: '1px solid var(--bg-tertiary)',
                borderRadius: '6px',
                color: 'var(--text-secondary)',
                fontWeight: '600',
                cursor: 'pointer',
                fontSize: '0.8rem'
              }}
            >
              Close
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

export default ThreatFeeds;


