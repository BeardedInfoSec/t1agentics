/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

import React, { useState, useEffect, useCallback, useRef } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { User, Settings, LogOut, Compass } from 'lucide-react';
import Button from './ui/Button';
import { startTour } from './GuidedTour';
import { usePreferences } from '../hooks/usePreferences';
import { useKeyboardShortcuts } from '../hooks/useKeyboardShortcuts';
import { API_BASE_URL, getCsrfToken } from '../utils/api';
import TopBarTicker from './BreachIntel/TopBarTicker';

const RECENT_SEARCHES_KEY = 'globalSearchRecent';
const RECENT_SEARCHES_MAX = 8;

function _loadRecentSearches() {
  try {
    const raw = localStorage.getItem(RECENT_SEARCHES_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed.filter(s => typeof s === 'string' && s.trim()) : [];
  } catch { return []; }
}

function _saveRecentSearch(query) {
  const q = (query || '').trim();
  if (!q) return;
  try {
    const current = _loadRecentSearches();
    const deduped = [q, ...current.filter(s => s.toLowerCase() !== q.toLowerCase())].slice(0, RECENT_SEARCHES_MAX);
    localStorage.setItem(RECENT_SEARCHES_KEY, JSON.stringify(deduped));
  } catch { /* silent */ }
}

function TopBarImproved({ user, onLogout, isMobile, onToggleMobileMenu }) {
  const [searchQuery, setSearchQuery] = useState('');
  const [showUserMenu, setShowUserMenu] = useState(false);
  const [showNotifications, setShowNotifications] = useState(false);
  const [showRecent, setShowRecent] = useState(false);
  const [recentSearches, setRecentSearches] = useState(() => _loadRecentSearches());
  const [notifications, setNotifications] = useState([]);
  const [unreadCount, setUnreadCount] = useState(0);
  const [notifTab, setNotifTab] = useState('notifications'); // 'notifications' | 'approvals'
  const [notifCategoryFilter, setNotifCategoryFilter] = useState('all'); // 'all' | 'alert' | 'investigation' | 'system'
  const [expandedGroups, setExpandedGroups] = useState({}); // { [groupKey]: true }
  const [approvals, setApprovals] = useState([]);
  const [approvalCount, setApprovalCount] = useState(0);
  const [approvalAction, setApprovalAction] = useState(null); // {id, type} while in-flight
  const notifRef = useRef(null);
  const searchFormRef = useRef(null);
  const searchInputRef = useRef(null);
  const navigate = useNavigate();
  const location = useLocation();
  const { preferences, updatePreference } = usePreferences();
  const { setShowHelp } = useKeyboardShortcuts();
  const isDarkMode = preferences.theme !== 'light';

  // Fetch unread count on mount + every 60s
  const fetchUnreadCount = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE_URL}/api/v1/notifications/inbox/count`, {
        credentials: 'include',
      });
      if (res.ok) {
        const data = await res.json();
        setUnreadCount(data.unread_count || 0);
      }
    } catch { /* silent */ }
  }, []);

  const fetchApprovalCount = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE_URL}/api/v1/actions/requests/queue?limit=1`, {
        credentials: 'include',
      });
      if (res.ok) {
        const data = await res.json();
        setApprovalCount(data.count || data.requests?.length || 0);
      }
    } catch { /* silent */ }
  }, []);

  useEffect(() => {
    fetchUnreadCount();
    fetchApprovalCount();
    const interval = setInterval(() => { fetchUnreadCount(); fetchApprovalCount(); }, 60000);
    return () => clearInterval(interval);
  }, [fetchUnreadCount, fetchApprovalCount]);

  const fetchNotifications = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE_URL}/api/v1/notifications/inbox?limit=20`, {
        credentials: 'include',
      });
      if (res.ok) {
        const data = await res.json();
        setNotifications(data.notifications || []);
      }
    } catch { /* silent */ }
  }, []);

  const fetchApprovals = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE_URL}/api/v1/actions/requests/queue?limit=20`, {
        credentials: 'include',
      });
      if (res.ok) {
        const data = await res.json();
        setApprovals(data.requests || []);
        setApprovalCount(data.count || data.requests?.length || 0);
      }
    } catch { /* silent */ }
  }, []);

  const handleApprovalAction = async (requestId, action) => {
    setApprovalAction({ id: requestId, type: action });
    try {
      const url = `${API_BASE_URL}/api/v1/actions/requests/${requestId}/${action}`;
      const body = action === 'approve'
        ? { execute_immediately: true }
        : { denial_reason: 'Denied from notification panel' };
      await fetch(url, {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': getCsrfToken() },
        body: JSON.stringify(body),
      });
      setApprovals(prev => prev.filter(r => r.id !== requestId));
      setApprovalCount(prev => Math.max(0, prev - 1));
    } catch { /* silent */ }
    setApprovalAction(null);
  };

  const handleBellClick = () => {
    if (!showNotifications) {
      fetchNotifications();
      fetchApprovals();
    }
    setShowNotifications(!showNotifications);
    setShowUserMenu(false);
  };

  const handleMarkAllRead = async () => {
    try {
      await fetch(`${API_BASE_URL}/api/v1/notifications/inbox/read-all`, {
        method: 'POST',
        credentials: 'include',
        headers: { 'X-CSRF-Token': getCsrfToken() },
      });
      setNotifications(prev => prev.map(n => ({ ...n, read: true })));
      setUnreadCount(0);
    } catch { /* silent */ }
  };

  const handleNotificationClick = async (notif) => {
    if (!notif.read) {
      try {
        await fetch(`${API_BASE_URL}/api/v1/notifications/inbox/${notif.id}/read`, {
          method: 'POST',
          credentials: 'include',
          headers: { 'X-CSRF-Token': getCsrfToken() },
        });
        setNotifications(prev => prev.map(n => n.id === notif.id ? { ...n, read: true } : n));
        setUnreadCount(prev => Math.max(0, prev - 1));
      } catch { /* silent */ }
    }
    if (notif.link) {
      navigate(notif.link);
      setShowNotifications(false);
    }
  };

  const toggleTheme = () => {
    updatePreference('theme', isDarkMode ? 'light' : 'dark');
  };

  const handleSearch = (e) => {
    e.preventDefault();
    const q = searchQuery.trim();
    if (q) {
      _saveRecentSearch(q);
      setRecentSearches(_loadRecentSearches());
      setShowRecent(false);
      navigate(`/search?q=${encodeURIComponent(q)}`);
    }
  };

  // Debounce: as the user types, softly update the /search URL `q` param
  // (replace history, no fetch-per-keystroke). Only kicks in when we are
  // already on the /search page so we don't auto-navigate away from
  // unrelated pages mid-keystroke.
  useEffect(() => {
    if (location.pathname !== '/search') return undefined;
    const q = searchQuery.trim();
    const timer = setTimeout(() => {
      const current = new URLSearchParams(location.search).get('q') || '';
      if (q && q !== current) {
        navigate(`/search?q=${encodeURIComponent(q)}`, { replace: true });
        _saveRecentSearch(q);
        setRecentSearches(_loadRecentSearches());
      }
    }, 300);
    return () => clearTimeout(timer);
  }, [searchQuery, location.pathname, location.search, navigate]);

  // Sync input value from URL when landing on /search (e.g. deep-link).
  useEffect(() => {
    if (location.pathname === '/search') {
      const urlQ = new URLSearchParams(location.search).get('q') || '';
      setSearchQuery(prev => (prev === '' ? urlQ : prev));
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [location.pathname]);

  // Close the recents dropdown on click outside the search form.
  useEffect(() => {
    if (!showRecent) return undefined;
    const handler = (e) => {
      if (searchFormRef.current && !searchFormRef.current.contains(e.target)) {
        setShowRecent(false);
      }
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, [showRecent]);

  const handleRecentSelect = (q) => {
    setSearchQuery(q);
    setShowRecent(false);
    _saveRecentSearch(q);
    setRecentSearches(_loadRecentSearches());
    navigate(`/search?q=${encodeURIComponent(q)}`);
  };

  const handleSearchKeyDown = (e) => {
    // Pressing ArrowDown in an empty input opens the global-search
    // keyboard-nav flow on the /search page (the page itself listens
    // for arrow keys once a result is focused). We surface the recents
    // dropdown when the input is empty.
    if (e.key === 'ArrowDown' && !searchQuery.trim() && recentSearches.length > 0) {
      setShowRecent(true);
    } else if (e.key === 'Escape') {
      setShowRecent(false);
    }
  };

  return (
    <header className="app-topbar" role="banner">
      {/* Hamburger (mobile only) */}
      {isMobile && (
        <button
          className="topbar-icon-button"
          onClick={onToggleMobileMenu}
          aria-label="Toggle navigation menu"
          style={{ width: '36px', height: '36px', marginRight: '0.25rem', flexShrink: 0 }}
        >
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M3 12h18M3 6h18M3 18h18"/>
          </svg>
        </button>
      )}

      {/* Left group — brand + search held together so they don't drift
          apart on wide screens (the topbar uses justify-content:
          space-between, which otherwise pushes them to opposite ends). */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '1.25rem', flexShrink: 0 }}>
      <div className="topbar-brand" style={{ gap: '0.5rem', fontSize: '1rem' }}>
        <img src="/T1_Agentics_Logo-removebg-preview.png" alt="T1 Agentics" className="t1-logo-dark" style={{ height: '28px', width: 'auto', cursor: 'pointer' }} onClick={() => navigate('/queue')} />
        <img src="/T1_Agentics_Light_Logo.png" alt="T1 Agentics" className="t1-logo-light" style={{ height: '28px', width: 'auto', cursor: 'pointer' }} onClick={() => navigate('/queue')} />
        {user?.license_tier && (
        <div className="topbar-env-badge" style={{
          background: ({
            platform: 'rgba(168, 85, 247, 0.2)',
            enterprise: 'rgba(34, 197, 94, 0.2)',
            professional: 'rgba(60, 179, 113, 0.2)',
            pro: 'rgba(60, 179, 113, 0.2)',
            dev: 'rgba(245, 158, 11, 0.2)',
            unlimited: 'rgba(168, 85, 247, 0.2)',
            trial: 'rgba(245, 158, 11, 0.2)',
            community: 'rgba(107, 114, 128, 0.2)',
            free: 'rgba(107, 114, 128, 0.2)',
          })[user.license_tier] || 'rgba(107, 114, 128, 0.2)',
          color: ({
            platform: '#a855f7',
            enterprise: '#22c55e',
            professional: '#3CB371',
            pro: '#3CB371',
            dev: '#f59e0b',
            unlimited: '#a855f7',
            trial: '#f59e0b',
            community: '#6b7280',
            free: '#6b7280',
          })[user.license_tier] || '#6b7280',
          padding: '2px 8px',
          fontSize: '0.65rem'
        }}>
          {({ pro: 'PROFESSIONAL', dev: 'DEVELOPER' })[user.license_tier] || user.license_tier.toUpperCase()}
        </div>
        )}
      </div>
      
      {/* Search */}
      <form
        ref={searchFormRef}
        onSubmit={handleSearch}
        className="topbar-search"
        data-tour="topbar-search"
        role="search"
        aria-label="Global search"
        style={isMobile ? { position: 'relative' } : { width: '340px', flexShrink: 0, position: 'relative' }}
      >
        <span className="topbar-search-icon" aria-hidden="true">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <circle cx="11" cy="11" r="8"/>
            <path d="M21 21l-4.35-4.35"/>
          </svg>
        </span>
        <input
          ref={searchInputRef}
          type="text"
          placeholder="Search alerts, IOCs, playbooks... (/)"
          aria-label="Search alerts, IOCs, and investigations"
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          onFocus={() => { if (!searchQuery.trim() && recentSearches.length > 0) setShowRecent(true); }}
          onKeyDown={handleSearchKeyDown}
          data-shortcut-target="search"
          autoComplete="off"
          style={{ padding: '0.4rem 0.6rem 0.4rem 2.1rem', fontSize: '0.8rem' }}
        />
        {showRecent && !searchQuery.trim() && recentSearches.length > 0 && (
          <div
            role="listbox"
            aria-label="Recent searches"
            style={{
              position: 'absolute',
              top: 'calc(100% + 0.25rem)',
              left: 0,
              right: 0,
              background: 'linear-gradient(159.02deg, rgba(15, 20, 53, 0.97) 14.12%, rgba(8, 13, 38, 0.99) 86.47%)',
              backdropFilter: 'blur(120px)',
              WebkitBackdropFilter: 'blur(120px)',
              border: '1px solid rgba(255, 255, 255, 0.08)',
              borderRadius: '10px',
              boxShadow: '0 10px 30px rgba(0, 0, 0, 0.5)',
              zIndex: 'var(--z-toast, 1100)',
              padding: '0.35rem 0',
              maxHeight: '260px',
              overflowY: 'auto',
            }}
          >
            <div style={{
              fontSize: '0.6rem',
              textTransform: 'uppercase',
              letterSpacing: '0.06em',
              color: 'var(--text-muted)',
              padding: '0.25rem 0.75rem 0.35rem',
            }}>
              Recent searches
            </div>
            {recentSearches.map((rq) => (
              <button
                key={rq}
                type="button"
                role="option"
                onMouseDown={(e) => { e.preventDefault(); handleRecentSelect(rq); }}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.5rem',
                  width: '100%',
                  background: 'transparent',
                  border: 'none',
                  color: 'var(--text-primary)',
                  fontSize: '0.78rem',
                  textAlign: 'left',
                  padding: '0.45rem 0.75rem',
                  cursor: 'pointer',
                }}
                onMouseEnter={(e) => { e.currentTarget.style.background = 'rgba(102, 126, 234, 0.12)'; }}
                onMouseLeave={(e) => { e.currentTarget.style.background = 'transparent'; }}
              >
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ opacity: 0.55, flexShrink: 0 }}>
                  <circle cx="12" cy="12" r="10"/>
                  <path d="M12 6v6l4 2"/>
                </svg>
                <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{rq}</span>
              </button>
            ))}
          </div>
        )}
      </form>
      </div>
      {/* /Left group */}

      {/* Latest RSS ticker — one headline at a time with fade in/out.
          Reuses the breach-intel feed. Hidden on mobile to keep the
          topbar tidy. */}
      {!isMobile && <TopBarTicker />}

      {/* Actions */}
      <div className="topbar-actions" style={{ gap: '0.5rem' }}>
        {/* Keyboard Shortcuts Help (hidden on mobile) */}
        {!isMobile && (
          <button
            className="topbar-icon-button"
            title="Keyboard Shortcuts (?)"
            aria-label="Show keyboard shortcuts"
            onClick={() => setShowHelp(true)}
            style={{ width: '32px', height: '32px' }}
          >
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <rect x="2" y="4" width="20" height="16" rx="2"/>
              <path d="M6 8h.01M10 8h.01M14 8h.01M18 8h.01M6 12h.01M10 12h.01M14 12h.01M18 12h.01M8 16h8"/>
            </svg>
          </button>
        )}

        {/* Theme Toggle (hidden on mobile) */}
        {!isMobile && (
          <button
            className="topbar-icon-button"
            title={isDarkMode ? 'Switch to Light Mode (Ctrl+Shift+L)' : 'Switch to Dark Mode (Ctrl+Shift+L)'}
            aria-label={isDarkMode ? 'Switch to light mode' : 'Switch to dark mode'}
            onClick={toggleTheme}
            style={{ width: '32px', height: '32px' }}
          >
            {isDarkMode ? (
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <circle cx="12" cy="12" r="5"/>
                <path d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/>
              </svg>
            ) : (
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/>
              </svg>
            )}
          </button>
        )}

        {/* Notifications */}
        <div style={{ position: 'relative' }} ref={notifRef} data-tour="topbar-notifications">
          <button
            className="topbar-icon-button"
            title="Notifications"
            aria-label={`Notifications${(unreadCount + approvalCount) > 0 ? `, ${unreadCount + approvalCount} unread` : ''}`}
            aria-expanded={showNotifications}
            onClick={handleBellClick}
            style={{ width: '32px', height: '32px' }}
          >
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/>
              <path d="M13.73 21a2 2 0 0 1-3.46 0"/>
            </svg>
            {(unreadCount + approvalCount) > 0 && (
              <span className="badge" style={{ width: '14px', height: '14px', fontSize: '0.6rem' }}>
                {(unreadCount + approvalCount) > 9 ? '9+' : (unreadCount + approvalCount)}
              </span>
            )}
          </button>

          {showNotifications && (
            <div style={{
              position: 'absolute',
              top: 'calc(100% + 0.5rem)',
              right: isMobile ? '-3rem' : 0,
              background: 'linear-gradient(159.02deg, rgba(15, 20, 53, 0.97) 14.12%, rgba(8, 13, 38, 0.99) 86.47%)',
              backdropFilter: 'blur(120px)',
              WebkitBackdropFilter: 'blur(120px)',
              border: '1px solid rgba(255, 255, 255, 0.08)',
              borderRadius: '16px',
              boxShadow: '0 20px 40px rgba(0, 0, 0, 0.5), 0 0 30px rgba(60, 179, 113, 0.05)',
              width: isMobile ? 'calc(100vw - 2rem)' : '370px',
              maxHeight: '460px',
              zIndex: 'var(--z-toast)',
              animation: 'fadeIn 0.15s ease',
              display: 'flex',
              flexDirection: 'column',
            }}>
              {/* Tab switcher */}
              <div style={{
                display: 'flex',
                borderBottom: '1px solid var(--border-color)',
              }}>
                <button
                  onClick={() => setNotifTab('notifications')}
                  style={{
                    flex: 1,
                    padding: '0.6rem 0.5rem',
                    background: 'none',
                    border: 'none',
                    borderBottom: notifTab === 'notifications' ? '2px solid var(--t1-emerald)' : '2px solid transparent',
                    color: notifTab === 'notifications' ? 'var(--text-primary)' : 'var(--text-muted)',
                    fontSize: '0.75rem',
                    fontWeight: '600',
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    gap: '5px',
                  }}
                >
                  Notifications
                  {unreadCount > 0 && (
                    <span style={{
                      background: 'var(--t1-emerald)',
                      color: '#fff',
                      fontSize: '0.55rem',
                      fontWeight: '700',
                      padding: '1px 5px',
                      borderRadius: '8px',
                      minWidth: '16px',
                      textAlign: 'center',
                    }}>{unreadCount}</span>
                  )}
                </button>
                <button
                  onClick={() => { setNotifTab('approvals'); fetchApprovals(); }}
                  style={{
                    flex: 1,
                    padding: '0.6rem 0.5rem',
                    background: 'none',
                    border: 'none',
                    borderBottom: notifTab === 'approvals' ? '2px solid #f59e0b' : '2px solid transparent',
                    color: notifTab === 'approvals' ? 'var(--text-primary)' : 'var(--text-muted)',
                    fontSize: '0.75rem',
                    fontWeight: '600',
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    gap: '5px',
                  }}
                >
                  Approvals
                  {approvalCount > 0 && (
                    <span style={{
                      background: '#f59e0b',
                      color: '#fff',
                      fontSize: '0.55rem',
                      fontWeight: '700',
                      padding: '1px 5px',
                      borderRadius: '8px',
                      minWidth: '16px',
                      textAlign: 'center',
                    }}>{approvalCount}</span>
                  )}
                </button>
              </div>

              {/* Tab content */}
              <div style={{ overflowY: 'auto', flex: 1, maxHeight: '350px' }}>
                {notifTab === 'notifications' ? (
                  <>
                    {/* Category filter pill row */}
                    <div
                      role="group"
                      aria-label="Filter notifications by category"
                      style={{
                        display: 'flex',
                        gap: '4px',
                        padding: '8px 1rem',
                        borderBottom: '1px solid var(--border-color)',
                        flexWrap: 'wrap',
                      }}
                    >
                      {[
                        { key: 'all', label: 'All' },
                        { key: 'alert', label: 'Alerts' },
                        { key: 'investigation', label: 'Investigations' },
                        { key: 'system', label: 'System' },
                      ].map(pill => {
                        const active = notifCategoryFilter === pill.key;
                        return (
                          <button
                            key={pill.key}
                            type="button"
                            aria-pressed={active}
                            onClick={() => setNotifCategoryFilter(pill.key)}
                            style={{
                              padding: '2px 8px',
                              fontSize: '0.6rem',
                              fontWeight: '600',
                              borderRadius: '10px',
                              border: '1px solid ' + (active ? 'var(--t1-emerald)' : 'var(--border-color)'),
                              background: active ? 'rgba(60, 179, 113, 0.12)' : 'transparent',
                              color: active ? 'var(--t1-emerald)' : 'var(--text-muted)',
                              cursor: 'pointer',
                              lineHeight: '1.4',
                            }}
                          >
                            {pill.label}
                          </button>
                        );
                      })}
                    </div>
                    {unreadCount > 0 && (
                      <div style={{ padding: '6px 1rem', borderBottom: '1px solid var(--border-color)', textAlign: 'right' }}>
                        <button onClick={handleMarkAllRead} style={{ background: 'none', border: 'none', color: 'var(--t1-emerald)', fontSize: '0.65rem', cursor: 'pointer' }}>
                          Mark all read
                        </button>
                      </div>
                    )}
                    {(() => {
                      // Filter by category
                      const filtered = notifCategoryFilter === 'all'
                        ? notifications
                        : notifications.filter(n => (n.category || '') === notifCategoryFilter);

                      // Group items sharing the same deep-link target. Order is
                      // preserved; the first occurrence (most recent from the
                      // API) becomes the group head, the rest collapse behind a
                      // "+ N more" pill. Items without a link never group.
                      const groups = [];
                      const seenLinks = new Map();
                      filtered.forEach(n => {
                        const link = n.link || '';
                        if (!link) {
                          groups.push({ key: `single-${n.id}`, link: '', head: n, others: [] });
                          return;
                        }
                        if (seenLinks.has(link)) {
                          groups[seenLinks.get(link)].others.push(n);
                        } else {
                          seenLinks.set(link, groups.length);
                          groups.push({ key: `grp-${link}`, link, head: n, others: [] });
                        }
                      });

                      if (groups.length === 0) {
                        return (
                          <div style={{ padding: '2rem 1rem', textAlign: 'center', color: 'var(--text-muted)', fontSize: '0.75rem' }}>
                            No notifications
                          </div>
                        );
                      }

                      const sevColor = (sev) => {
                        switch ((sev || '').toLowerCase()) {
                          case 'critical': return '#ef4444';
                          case 'high': return '#f97316';
                          case 'medium': return '#eab308';
                          case 'low': return '#3b82f6';
                          case 'info': return '#94a3b8';
                          // legacy fallbacks
                          case 'error': return '#f97316';
                          case 'warning': return '#eab308';
                          default: return '#94a3b8';
                        }
                      };

                      const isUnread = (n) => !(n.read || n.read_at);

                      const renderItem = (notif, isNested) => (
                        <div
                          key={notif.id}
                          className="topbar-notif-item"
                          onClick={() => handleNotificationClick(notif)}
                          style={{
                            position: 'relative',
                            padding: '0.65rem 1rem 0.65rem calc(1rem + 7px)',
                            borderBottom: '1px solid var(--border-color)',
                            cursor: notif.link ? 'pointer' : 'default',
                            background: isNested
                              ? 'rgba(255,255,255,0.02)'
                              : (isUnread(notif) ? 'rgba(60, 179, 113, 0.06)' : 'transparent'),
                            transition: 'background 0.15s',
                          }}
                        >
                          {/* Severity color bar (3px) */}
                          <div
                            aria-hidden="true"
                            style={{
                              position: 'absolute',
                              left: 0,
                              top: 0,
                              bottom: 0,
                              width: '3px',
                              background: sevColor(notif.severity),
                            }}
                          />
                          <div style={{ flex: 1, minWidth: 0 }}>
                            <div style={{ fontSize: '0.75rem', fontWeight: isUnread(notif) ? '600' : '400', color: 'var(--text-primary)', marginBottom: '2px', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', paddingRight: '70px' }}>
                              {notif.title}
                            </div>
                            {notif.message && (
                              <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', overflow: 'hidden', textOverflow: 'ellipsis', display: '-webkit-box', WebkitLineClamp: 2, WebkitBoxOrient: 'vertical' }}>
                                {notif.message}
                              </div>
                            )}
                            <div style={{ fontSize: '0.6rem', color: 'var(--text-muted)', marginTop: '3px' }}>
                              {notif.created_at ? _timeAgo(notif.created_at) : ''}
                            </div>
                          </div>
                        </div>
                      );

                      return groups.map(group => {
                        const expanded = !!expandedGroups[group.key];
                        const extraCount = group.others.length;
                        return (
                          <div key={group.key}>
                            <div style={{ position: 'relative' }}>
                              {renderItem(group.head, false)}
                              {extraCount > 0 && (
                                <button
                                  type="button"
                                  aria-expanded={expanded}
                                  aria-label={expanded ? `Collapse ${extraCount} similar notifications` : `Show ${extraCount} more similar notifications`}
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    setExpandedGroups(prev => ({ ...prev, [group.key]: !prev[group.key] }));
                                  }}
                                  style={{
                                    position: 'absolute',
                                    right: '0.75rem',
                                    top: '0.6rem',
                                    padding: '1px 7px',
                                    fontSize: '0.55rem',
                                    fontWeight: '700',
                                    borderRadius: '10px',
                                    border: '1px solid var(--border-color)',
                                    background: 'rgba(255,255,255,0.05)',
                                    color: 'var(--text-muted)',
                                    cursor: 'pointer',
                                    lineHeight: '1.4',
                                    whiteSpace: 'nowrap',
                                  }}
                                >
                                  {expanded ? `Hide ${extraCount}` : `+ ${extraCount} more`}
                                </button>
                              )}
                            </div>
                            {expanded && group.others.map(n => renderItem(n, true))}
                          </div>
                        );
                      });
                    })()}
                  </>
                ) : (
                  <>
                    {approvals.length === 0 ? (
                      <div style={{ padding: '2rem 1rem', textAlign: 'center', color: 'var(--text-muted)', fontSize: '0.75rem' }}>
                        No pending approvals
                      </div>
                    ) : (
                      approvals.map(req => (
                        <div key={req.id} style={{
                          padding: '0.65rem 1rem',
                          borderBottom: '1px solid var(--border-color)',
                        }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '4px' }}>
                            <span style={{
                              width: '6px', height: '6px', borderRadius: '50%', flexShrink: 0,
                              background: req.priority === 'critical' ? '#ef4444' : req.priority === 'high' ? '#f59e0b' : '#3b82f6',
                            }} />
                            <span style={{ fontSize: '0.75rem', fontWeight: '600', color: 'var(--text-primary)', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                              {(req.action_type || '').replace(/_/g, ' ')}
                            </span>
                            <span style={{
                              fontSize: '0.55rem', fontWeight: '600', textTransform: 'uppercase',
                              padding: '1px 5px', borderRadius: '3px',
                              background: req.priority === 'critical' ? 'rgba(239,68,68,0.12)' : req.priority === 'high' ? 'rgba(245,158,11,0.12)' : 'rgba(59,130,246,0.12)',
                              color: req.priority === 'critical' ? '#ef4444' : req.priority === 'high' ? '#f59e0b' : '#3b82f6',
                            }}>
                              {req.priority}
                            </span>
                          </div>
                          {req.target_value && (
                            <div style={{ fontSize: '0.65rem', color: 'var(--text-muted)', marginBottom: '3px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                              {req.target_type}: {req.target_value}
                            </div>
                          )}
                          {req.reasoning && (
                            <div style={{ fontSize: '0.65rem', color: 'var(--text-muted)', marginBottom: '6px', overflow: 'hidden', textOverflow: 'ellipsis', display: '-webkit-box', WebkitLineClamp: 2, WebkitBoxOrient: 'vertical' }}>
                              {req.reasoning}
                            </div>
                          )}
                          <div style={{ display: 'flex', gap: '6px' }}>
                            <button
                              onClick={() => handleApprovalAction(req.id, 'approve')}
                              disabled={approvalAction?.id === req.id}
                              style={{
                                padding: '3px 10px', borderRadius: '4px', border: 'none',
                                background: '#10b981', color: '#fff', fontSize: '0.65rem',
                                fontWeight: '600', cursor: 'pointer', opacity: approvalAction?.id === req.id ? 0.5 : 1,
                              }}
                            >
                              {approvalAction?.id === req.id && approvalAction?.type === 'approve' ? '...' : 'Approve'}
                            </button>
                            <button
                              onClick={() => handleApprovalAction(req.id, 'deny')}
                              disabled={approvalAction?.id === req.id}
                              style={{
                                padding: '3px 10px', borderRadius: '4px',
                                background: 'transparent', border: '1px solid var(--border-color)',
                                color: 'var(--text-muted)', fontSize: '0.65rem',
                                fontWeight: '600', cursor: 'pointer', opacity: approvalAction?.id === req.id ? 0.5 : 1,
                              }}
                            >
                              {approvalAction?.id === req.id && approvalAction?.type === 'deny' ? '...' : 'Deny'}
                            </button>
                          </div>
                        </div>
                      ))
                    )}
                    {approvals.length > 0 && (
                      <div style={{ padding: '8px 1rem', textAlign: 'center', borderTop: '1px solid var(--border-color)' }}>
                        <button
                          onClick={() => { navigate('/workbench/approvals'); setShowNotifications(false); }}
                          style={{ background: 'none', border: 'none', color: 'var(--accent-primary, #3b82f6)', fontSize: '0.7rem', fontWeight: '600', cursor: 'pointer' }}
                        >
                          View all approvals &rarr;
                        </button>
                      </div>
                    )}
                  </>
                )}
              </div>
            </div>
          )}
        </div>

        {/* User Menu */}
        <div style={{ position: 'relative' }} data-tour="user-pill">
          <button
            className="topbar-icon-button"
            aria-label="User menu"
            aria-expanded={showUserMenu}
            onClick={() => setShowUserMenu(!showUserMenu)}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '0.5rem',
              padding: '0.3rem 0.6rem',
              width: 'auto',
              height: '32px'
            }}
          >
            <div style={{
              width: '24px',
              height: '24px',
              borderRadius: '50%',
              background: 'linear-gradient(135deg, var(--t1-emerald) 0%, var(--t1-emerald-dark) 100%)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              fontSize: '0.7rem',
              fontWeight: '700',
              color: 'white'
            }}>
              {(user?.username || 'A')[0].toUpperCase()}
            </div>
            <div style={{ textAlign: 'left', lineHeight: '1.1' }}>
              <div style={{ fontSize: '0.75rem', fontWeight: '600', color: 'var(--text-primary)' }}>
                {user?.username || 'Admin'}
              </div>
              <div style={{ fontSize: '0.6rem', color: 'var(--text-muted)' }}>
                {user?.role || 'admin'}
              </div>
            </div>
            <span style={{ fontSize: '0.6rem', opacity: 0.6 }}>▼</span>
          </button>
          
          {/* Dropdown Menu */}
          {showUserMenu && (
            <div
              style={{
                position: 'absolute',
                top: 'calc(100% + 0.5rem)',
                right: 0,
                background: 'linear-gradient(159.02deg, rgba(15, 20, 53, 0.97) 14.12%, rgba(8, 13, 38, 0.99) 86.47%)',
                backdropFilter: 'blur(120px)',
                WebkitBackdropFilter: 'blur(120px)',
                border: '1px solid rgba(255, 255, 255, 0.08)',
                borderRadius: '16px',
                boxShadow: '0 20px 40px rgba(0, 0, 0, 0.5), 0 0 30px rgba(60, 179, 113, 0.05)',
                minWidth: '200px',
                zIndex: 'var(--z-modal)',
                animation: 'fadeIn 0.15s ease'
              }}
            >
              <div style={{ padding: '1rem', borderBottom: '1px solid var(--border-color)' }}>
                <div style={{ fontSize: '0.875rem', fontWeight: '600', marginBottom: '0.25rem' }}>
                  {user?.username || 'Admin'}
                </div>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                  {user?.role || 'Administrator'}
                </div>
              </div>
              
              <div style={{ padding: '0.5rem' }}>
                <Button
                  variant="ghost"
                  fullWidth
                  icon={<User size={16} />}
                  onClick={() => {
                    navigate('/profile');
                    setShowUserMenu(false);
                  }}
                  style={{ justifyContent: 'flex-start' }}
                >
                  Profile
                </Button>

                <Button
                  variant="ghost"
                  fullWidth
                  icon={<Settings size={16} />}
                  onClick={() => {
                    navigate('/settings');
                    setShowUserMenu(false);
                  }}
                  style={{ justifyContent: 'flex-start' }}
                >
                  Settings
                </Button>

                <Button
                  variant="ghost"
                  fullWidth
                  icon={<Compass size={16} />}
                  onClick={() => {
                    setShowUserMenu(false);
                    // Force-clear the seen flag so the tour fires regardless,
                    // and start at the platform walk.
                    try { localStorage.removeItem('t1-app-tour-seen-v1'); } catch { /* ignore */ }
                    startTour('platform', 0);
                  }}
                  style={{ justifyContent: 'flex-start', color: 'var(--primary, #3CB371)' }}
                >
                  Replay welcome tour
                </Button>
              </div>
              
              <div style={{ padding: '0.5rem', borderTop: '1px solid var(--border-color)' }}>
                <Button
                  variant="danger"
                  fullWidth
                  icon={<LogOut size={16} />}
                  onClick={() => {
                    onLogout();
                    setShowUserMenu(false);
                  }}
                  style={{ justifyContent: 'flex-start', background: 'transparent' }}
                >
                  Logout
                </Button>
              </div>
            </div>
          )}
        </div>
      </div>
      
      {/* Click outside to close dropdowns */}
      {(showUserMenu || showNotifications) && (
        <div
          onClick={() => { setShowUserMenu(false); setShowNotifications(false); }}
          style={{
            position: 'fixed',
            inset: 0,
            zIndex: 999
          }}
        />
      )}
    </header>
  );
}

function _timeAgo(dateStr) {
  const now = new Date();
  const date = new Date(dateStr);
  const seconds = Math.floor((now - date) / 1000);
  if (seconds < 60) return 'just now';
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  if (days < 7) return `${days}d ago`;
  return date.toLocaleDateString();
}

export default TopBarImproved;
