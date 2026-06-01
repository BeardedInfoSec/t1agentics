/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

import React, { useState, useEffect, useMemo, useRef, useCallback } from 'react';
import { useSearchParams, Link, useNavigate } from 'react-router-dom';
import { getAuthHeaders, API_BASE_URL } from '../utils/api';

const FOCUSED_STYLE = {
  borderLeft: '2px solid #4ade80',
  background: 'rgba(74, 222, 128, 0.08)',
};

function GlobalSearch() {
  const [searchParams] = useSearchParams();
  const query = searchParams.get('q') || '';
  const navigate = useNavigate();
  const [results, setResults] = useState(null);
  const [loading, setLoading] = useState(true);
  const [focusedIdx, setFocusedIdx] = useState(-1);
  const resultRefs = useRef([]);
  const resultsContainerRef = useRef(null);

  useEffect(() => {
    if (query) {
      performSearch();
    }
    // Reset keyboard focus when query changes.
    setFocusedIdx(-1);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [query]);

  const performSearch = async () => {
    setLoading(true);
    try {
      const response = await fetch(`${API_BASE_URL}/api/v1/search?q=${encodeURIComponent(query)}`, { headers: getAuthHeaders() });
      const data = await response.json();
      setResults(data);
    } catch (error) {
    } finally {
      setLoading(false);
    }
  };

  // Build a flat ordered list of all focusable result rows. Order
  // matches the visual order rendered below:
  //   alerts -> investigations -> KB -> playbooks -> intake submissions
  //   -> recommended actions -> detection rules -> users -> audit logs.
  // Each entry stores an optional `to` so Enter can navigate.
  // NOTE: hooks must be declared before any early return below.
  const flatItems = useMemo(() => {
    if (!results) return [];
    const items = [];
    (results.alerts || []).forEach(a => items.push({ to: `/queue?highlight=${a.alert_id}` }));
    (results.investigations || []).forEach(inv => items.push({ to: `/investigation/${inv.investigation_id}` }));
    (results.knowledge_base || []).forEach(kb => items.push({ to: `/knowledge?kb=${kb.kb_id}` }));
    (results.playbooks || []).forEach(pb => items.push({ to: `/playbooks/${pb.id}` }));
    (results.intake_submissions || []).forEach(sub => items.push({
      to: sub.alert_id
        ? `/queue?view=alerts&search=${encodeURIComponent(sub.alert_id)}&drawer=${encodeURIComponent(sub.alert_id)}`
        : '/intake-forms',
    }));
    (results.recommended_actions || []).forEach(act => items.push({
      to: act.investigation_id ? `/investigation/${act.investigation_id}` : null,
    }));
    (results.detection_rules || []).forEach(() => items.push({ to: null }));
    (results.users || []).forEach(() => items.push({ to: null }));
    (results.audit_logs || []).forEach(() => items.push({ to: null }));
    return items;
  }, [results]);

  // Per-section starting offset within flatItems.
  const sectionOffsets = useMemo(() => {
    const o = { alerts: 0 };
    o.investigations = o.alerts + (results?.alerts?.length || 0);
    o.knowledge_base = o.investigations + (results?.investigations?.length || 0);
    o.playbooks = o.knowledge_base + (results?.knowledge_base?.length || 0);
    o.intake_submissions = o.playbooks + (results?.playbooks?.length || 0);
    o.recommended_actions = o.intake_submissions + (results?.intake_submissions?.length || 0);
    o.detection_rules = o.recommended_actions + (results?.recommended_actions?.length || 0);
    o.users = o.detection_rules + (results?.detection_rules?.length || 0);
    o.audit_logs = o.users + (results?.users?.length || 0);
    return o;
  }, [results]);

  const handleResultsKeyDown = useCallback((e) => {
    if (!flatItems.length) return;
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setFocusedIdx(prev => Math.min(flatItems.length - 1, prev + 1));
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setFocusedIdx(prev => Math.max(0, prev - 1));
    } else if (e.key === 'Enter') {
      if (focusedIdx >= 0 && focusedIdx < flatItems.length) {
        const item = flatItems[focusedIdx];
        if (item.to) {
          e.preventDefault();
          navigate(item.to);
        }
      }
    } else if (e.key === 'Escape') {
      setFocusedIdx(-1);
    }
  }, [flatItems, focusedIdx, navigate]);

  // Scroll the focused row into view as it changes.
  useEffect(() => {
    if (focusedIdx < 0) return;
    const el = resultRefs.current[focusedIdx];
    if (el && typeof el.scrollIntoView === 'function') {
      el.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
    }
  }, [focusedIdx]);

  const setRowRef = (idx) => (el) => { resultRefs.current[idx] = el; };

  const getSeverityColor = (severity) => {
    const colors = {
      'critical': '#dc2626',
      'high': '#ea580c',
      'medium': '#eab308',
      'low': '#22c55e'
    };
    return colors[severity?.toLowerCase()] || '#6b7280';
  };

  const getStatusColor = (status) => {
    const colors = {
      'open': '#3b82f6',
      'investigating': '#eab308',
      'resolved': '#22c55e',
      'closed': '#6b7280'
    };
    return colors[status?.toLowerCase()] || '#6b7280';
  };

  if (!query) {
    return (
      <div className="fade-in">
        <h1 style={{ fontSize: '1.75rem', marginBottom: '2rem' }}>Search</h1>
        <div className="card" style={{ textAlign: 'center', padding: '3rem' }}>
          <div style={{ fontSize: '3rem', marginBottom: '1rem' }}>🔍</div>
          <h3 style={{ fontSize: '1.25rem', marginBottom: '0.5rem' }}>Start Searching</h3>
          <p style={{ color: 'var(--text-secondary)' }}>
            Use the search bar above to find alerts, investigations, and IOCs
          </p>
        </div>
      </div>
    );
  }

  if (loading) {
    return (
      <div className="loading-container">
        <div className="spinner"></div>
        <p style={{ color: 'var(--text-secondary)' }}>Searching for "{query}"...</p>
      </div>
    );
  }

  const hasResults = results && (
    results.alerts?.length > 0 ||
    results.investigations?.length > 0 ||
    results.users?.length > 0 ||
    results.audit_logs?.length > 0 ||
    results.knowledge_base?.length > 0 ||
    results.playbooks?.length > 0 ||
    results.intake_submissions?.length > 0 ||
    results.recommended_actions?.length > 0 ||
    results.detection_rules?.length > 0 ||
    Object.values(results.iocs || {}).some(arr => arr.length > 0)
  );

  return (
    <div className="fade-in">
      {/* Header */}
      <div style={{ marginBottom: '2rem' }}>
        <h1 style={{ fontSize: '1.75rem', marginBottom: '0.5rem' }}>
          Search Results
        </h1>
        <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
          <span style={{ color: 'var(--text-secondary)' }}>
            Query: <code style={{ background: 'rgba(102, 126, 234, 0.1)', padding: '0.25rem 0.5rem', borderRadius: '4px' }}>"{query}"</code>
          </span>
          {results?.counts && (
            <span style={{ color: 'var(--text-muted)', fontSize: '0.875rem' }}>
              {results.counts.total} total result{results.counts.total !== 1 ? 's' : ''}
              {' '}({[
                results.counts.alerts && `${results.counts.alerts} alerts`,
                results.counts.investigations && `${results.counts.investigations} investigations`,
                results.counts.iocs && `${results.counts.iocs} IOCs`,
                results.counts.knowledge_base && `${results.counts.knowledge_base} KB articles`,
                results.counts.playbooks && `${results.counts.playbooks} playbooks`,
                results.counts.intake_submissions && `${results.counts.intake_submissions} intake submissions`,
                results.counts.recommended_actions && `${results.counts.recommended_actions} recommended actions`,
                results.counts.detection_rules && `${results.counts.detection_rules} detection rules`,
                results.counts.users && `${results.counts.users} users`,
                results.counts.audit_logs && `${results.counts.audit_logs} audit logs`,
              ].filter(Boolean).join(', ')})
            </span>
          )}
        </div>
      </div>

      {results?.error && (
        <div
          role="alert"
          style={{
            background: 'rgba(239, 68, 68, 0.08)',
            border: '1px solid rgba(239, 68, 68, 0.35)',
            borderLeft: '3px solid #ef4444',
            color: '#fca5a5',
            padding: '0.65rem 0.9rem',
            borderRadius: '6px',
            fontSize: '0.8rem',
            marginBottom: '1rem',
            display: 'flex',
            alignItems: 'center',
            gap: '0.5rem',
          }}
        >
          <strong style={{ color: '#fecaca' }}>Search error:</strong>
          <span>{String(results.error)}</span>
        </div>
      )}

      {!hasResults ? (
        <div className="card" style={{ textAlign: 'center', padding: '3rem' }}>
          <div style={{ fontSize: '3rem', marginBottom: '1rem' }}>🔍</div>
          <h3 style={{ fontSize: '1.25rem', marginBottom: '0.5rem' }}>No Results Found</h3>
          <p style={{ color: 'var(--text-secondary)' }}>
            No alerts, investigations, or IOCs match your search query
          </p>
        </div>
      ) : (
        <div
          ref={resultsContainerRef}
          tabIndex={0}
          onKeyDown={handleResultsKeyDown}
          style={{ display: 'grid', gap: '1.5rem', outline: 'none' }}
        >
          {/* Alerts */}
          {results.alerts?.length > 0 && (
            <div className="card">
              <div style={{ padding: '1rem', borderBottom: '1px solid var(--bg-tertiary)' }}>
                <h2 style={{ fontSize: '1.125rem', fontWeight: '600', margin: 0 }}>
                  🚨 Alerts <span style={{ color: 'var(--text-muted)', fontSize: '0.875rem', fontWeight: '400' }}>({results.alerts.length})</span>
                </h2>
              </div>
              <div style={{ padding: '1rem' }}>
                {results.alerts.map((alert, idx) => {
                  const flatIdx = sectionOffsets.alerts + idx;
                  const isFocused = focusedIdx === flatIdx;
                  return (
                  <Link
                    key={alert.alert_id}
                    ref={setRowRef(flatIdx)}
                    to={`/queue?highlight=${alert.alert_id}`}
                    style={{
                      display: 'block',
                      padding: '1rem',
                      borderRadius: '8px',
                      marginBottom: idx < results.alerts.length - 1 ? '0.75rem' : 0,
                      background: isFocused ? FOCUSED_STYLE.background : 'var(--bg-secondary)',
                      border: '1px solid transparent',
                      borderLeft: isFocused ? FOCUSED_STYLE.borderLeft : '1px solid transparent',
                      textDecoration: 'none',
                      transition: 'all 0.15s'
                    }}
                    onMouseEnter={(e) => {
                      if (isFocused) return;
                      e.currentTarget.style.background = 'rgba(102, 126, 234, 0.1)';
                      e.currentTarget.style.borderColor = 'rgba(102, 126, 234, 0.3)';
                    }}
                    onMouseLeave={(e) => {
                      if (isFocused) return;
                      e.currentTarget.style.background = 'var(--bg-secondary)';
                      e.currentTarget.style.borderColor = 'transparent';
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start', marginBottom: '0.5rem' }}>
                      <div style={{ flex: 1 }}>
                        <code style={{ 
                          fontSize: '0.75rem', 
                          color: '#a0e9ff',
                          background: 'rgba(102, 126, 234, 0.1)',
                          padding: '0.25rem 0.5rem',
                          borderRadius: '4px',
                          marginBottom: '0.5rem',
                          display: 'inline-block'
                        }}>
                          {alert.alert_id}
                        </code>
                        <div style={{ fontSize: '0.938rem', fontWeight: '600', color: 'var(--text-primary)', marginBottom: '0.25rem' }}>
                          {alert.title}
                        </div>
                        <div style={{ fontSize: '0.813rem', color: 'var(--text-secondary)', lineHeight: '1.4' }}>
                          {alert.description}
                        </div>
                      </div>
                      <div style={{ display: 'flex', gap: '0.5rem', marginLeft: '1rem' }}>
                        <span
                          className="badge"
                          style={{
                            background: getSeverityColor(alert.severity),
                            color: 'white',
                            fontSize: '0.688rem',
                            padding: '0.25rem 0.625rem',
                            fontWeight: '700'
                          }}
                        >
                          {alert.severity?.toUpperCase()}
                        </span>
                        <span
                          className="badge"
                          style={{
                            background: getStatusColor(alert.status),
                            color: 'white',
                            fontSize: '0.688rem',
                            padding: '0.25rem 0.625rem',
                            fontWeight: '700'
                          }}
                        >
                          {alert.status?.toUpperCase()}
                        </span>
                      </div>
                    </div>
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                      Source: {alert.source} • {new Date(alert.created_at).toLocaleString()}
                    </div>
                  </Link>
                  );
                })}
              </div>
            </div>
          )}

          {/* Investigations */}
          {results.investigations?.length > 0 && (
            <div className="card">
              <div style={{ padding: '1rem', borderBottom: '1px solid var(--bg-tertiary)' }}>
                <h2 style={{ fontSize: '1.125rem', fontWeight: '600', margin: 0 }}>
                  🔍 Investigations <span style={{ color: 'var(--text-muted)', fontSize: '0.875rem', fontWeight: '400' }}>({results.investigations.length})</span>
                </h2>
              </div>
              <div style={{ padding: '1rem' }}>
                {results.investigations.map((inv, idx) => {
                  const flatIdx = sectionOffsets.investigations + idx;
                  const isFocused = focusedIdx === flatIdx;
                  return (
                  <Link
                    key={inv.investigation_id}
                    ref={setRowRef(flatIdx)}
                    to={`/investigation/${inv.investigation_id}`}
                    style={{
                      display: 'block',
                      padding: '1rem',
                      borderRadius: '8px',
                      marginBottom: idx < results.investigations.length - 1 ? '0.75rem' : 0,
                      background: isFocused ? FOCUSED_STYLE.background : 'var(--bg-secondary)',
                      border: '1px solid transparent',
                      borderLeft: isFocused ? FOCUSED_STYLE.borderLeft : '1px solid transparent',
                      textDecoration: 'none',
                      transition: 'all 0.15s'
                    }}
                    onMouseEnter={(e) => {
                      if (isFocused) return;
                      e.currentTarget.style.background = 'rgba(102, 126, 234, 0.1)';
                      e.currentTarget.style.borderColor = 'rgba(102, 126, 234, 0.3)';
                    }}
                    onMouseLeave={(e) => {
                      if (isFocused) return;
                      e.currentTarget.style.background = 'var(--bg-secondary)';
                      e.currentTarget.style.borderColor = 'transparent';
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start' }}>
                      <div>
                        <div style={{ fontSize: '0.938rem', fontWeight: '600', color: 'var(--text-primary)', marginBottom: '0.25rem' }}>
                          {inv.title}
                        </div>
                        <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                          ID: {inv.investigation_id} • Owner: {inv.owner || 'Unassigned'}
                        </div>
                      </div>
                      <div style={{ display: 'flex', gap: '0.5rem' }}>
                        <span className="badge" style={{ background: '#3b82f6', fontSize: '0.688rem' }}>
                          {inv.state?.toUpperCase()}
                        </span>
                        {inv.disposition && (
                          <span className="badge" style={{ background: '#22c55e', fontSize: '0.688rem' }}>
                            {inv.disposition?.toUpperCase()}
                          </span>
                        )}
                      </div>
                    </div>
                  </Link>
                  );
                })}
              </div>
            </div>
          )}

          {/* IOCs */}
          {Object.values(results.iocs || {}).some(arr => arr.length > 0) && (
            <div className="card">
              <div style={{ padding: '1rem', borderBottom: '1px solid var(--bg-tertiary)' }}>
                <h2 style={{ fontSize: '1.125rem', fontWeight: '600', margin: 0 }}>
                  🎯 Indicators of Compromise <span style={{ color: 'var(--text-muted)', fontSize: '0.875rem', fontWeight: '400' }}>({results.counts?.iocs || 0})</span>
                </h2>
              </div>
              <div style={{ padding: '1rem' }}>
                {Object.entries(results.iocs).map(([type, iocs]) => 
                  iocs.length > 0 && (
                    <div key={type} style={{ marginBottom: '1rem' }}>
                      <div style={{ fontSize: '0.813rem', color: 'var(--text-muted)', marginBottom: '0.5rem', textTransform: 'uppercase', fontWeight: '600' }}>
                        {type}
                      </div>
                      {iocs.map((ioc, idx) => (
                        <div key={idx} style={{ 
                          padding: '0.75rem', 
                          background: 'var(--bg-secondary)', 
                          borderRadius: '6px',
                          marginBottom: '0.5rem'
                        }}>
                          <code style={{ color: '#a0e9ff', fontSize: '0.875rem' }}>{ioc.value}</code>
                          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.25rem' }}>
                            Found in: <Link to={`/queue?highlight=${ioc.alert_id}`} style={{ color: '#3b82f6' }}>{ioc.alert_title}</Link>
                            {ioc.severity && <span style={{ marginLeft: '0.5rem' }}>• Severity: <span style={{ color: getSeverityColor(ioc.severity), fontWeight: '600' }}>{ioc.severity.toUpperCase()}</span></span>}
                          </div>
                        </div>
                      ))}
                    </div>
                  )
                )}
              </div>
            </div>
          )}

          {/* Knowledge Base */}
          {results.knowledge_base?.length > 0 && (
            <div className="card">
              <div style={{ padding: '1rem', borderBottom: '1px solid var(--bg-tertiary)' }}>
                <h2 style={{ fontSize: '1.125rem', fontWeight: '600', margin: 0 }}>
                  Knowledge Base <span style={{ color: 'var(--text-muted)', fontSize: '0.875rem', fontWeight: '400' }}>({results.knowledge_base.length})</span>
                </h2>
              </div>
              <div style={{ padding: '1rem' }}>
                {results.knowledge_base.map((kb, idx) => {
                  const flatIdx = sectionOffsets.knowledge_base + idx;
                  const isFocused = focusedIdx === flatIdx;
                  return (
                  <Link
                    key={kb.kb_id}
                    ref={setRowRef(flatIdx)}
                    to={`/knowledge?kb=${kb.kb_id}`}
                    style={{
                      display: 'block',
                      padding: '0.875rem',
                      borderRadius: '8px',
                      marginBottom: idx < results.knowledge_base.length - 1 ? '0.5rem' : 0,
                      background: isFocused ? FOCUSED_STYLE.background : 'var(--bg-secondary)',
                      border: '1px solid transparent',
                      borderLeft: isFocused ? FOCUSED_STYLE.borderLeft : '1px solid transparent',
                      textDecoration: 'none',
                      color: 'inherit',
                    }}
                    onMouseEnter={(e) => { if (!isFocused) e.currentTarget.style.borderColor = 'rgba(102, 126, 234, 0.3)'; }}
                    onMouseLeave={(e) => { if (!isFocused) e.currentTarget.style.borderColor = 'transparent'; }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start', marginBottom: '0.25rem' }}>
                      <div style={{ fontSize: '0.938rem', fontWeight: 600, color: 'var(--text-primary)' }}>{kb.title}</div>
                      <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                        {kb.content_type} {kb.category ? `• ${kb.category}` : ''}
                      </span>
                    </div>
                    <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', lineHeight: 1.4 }}>{kb.content_excerpt}</div>
                  </Link>
                  );
                })}
              </div>
            </div>
          )}

          {/* Playbooks */}
          {results.playbooks?.length > 0 && (
            <div className="card">
              <div style={{ padding: '1rem', borderBottom: '1px solid var(--bg-tertiary)' }}>
                <h2 style={{ fontSize: '1.125rem', fontWeight: '600', margin: 0 }}>
                  Playbooks <span style={{ color: 'var(--text-muted)', fontSize: '0.875rem', fontWeight: '400' }}>({results.playbooks.length})</span>
                </h2>
              </div>
              <div style={{ padding: '1rem' }}>
                {results.playbooks.map((pb, idx) => {
                  const flatIdx = sectionOffsets.playbooks + idx;
                  const isFocused = focusedIdx === flatIdx;
                  return (
                  <Link
                    key={pb.id}
                    ref={setRowRef(flatIdx)}
                    to={`/playbooks/${pb.id}`}
                    style={{
                      display: 'block',
                      padding: '0.875rem',
                      borderRadius: '8px',
                      marginBottom: idx < results.playbooks.length - 1 ? '0.5rem' : 0,
                      background: isFocused ? FOCUSED_STYLE.background : 'var(--bg-secondary)',
                      border: '1px solid transparent',
                      borderLeft: isFocused ? FOCUSED_STYLE.borderLeft : '1px solid transparent',
                      textDecoration: 'none',
                      color: 'inherit',
                    }}
                    onMouseEnter={(e) => { if (!isFocused) e.currentTarget.style.borderColor = 'rgba(102, 126, 234, 0.3)'; }}
                    onMouseLeave={(e) => { if (!isFocused) e.currentTarget.style.borderColor = 'transparent'; }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start', marginBottom: '0.25rem' }}>
                      <div style={{ fontSize: '0.938rem', fontWeight: 600, color: 'var(--text-primary)' }}>{pb.name}</div>
                      <span style={{
                        fontSize: '0.7rem', padding: '0.2rem 0.5rem', borderRadius: 4,
                        background: pb.is_active ? 'rgba(34,197,94,0.15)' : 'rgba(148,163,184,0.15)',
                        color: pb.is_active ? '#4ade80' : 'var(--text-muted)',
                      }}>
                        {pb.is_active ? 'ACTIVE' : 'DISABLED'}
                      </span>
                    </div>
                    {pb.description && (
                      <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', lineHeight: 1.4, marginBottom: '0.35rem' }}>{pb.description}</div>
                    )}
                    {pb.tags?.length > 0 && (
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.3rem' }}>
                        {pb.tags.slice(0, 6).map((t) => (
                          <span key={t} style={{ fontSize: '0.7rem', padding: '0.15rem 0.45rem', borderRadius: 3, background: 'rgba(102,126,234,0.12)', color: '#a0e9ff' }}>{t}</span>
                        ))}
                      </div>
                    )}
                  </Link>
                  );
                })}
              </div>
            </div>
          )}

          {/* Intake Submissions */}
          {results.intake_submissions?.length > 0 && (
            <div className="card">
              <div style={{ padding: '1rem', borderBottom: '1px solid var(--bg-tertiary)' }}>
                <h2 style={{ fontSize: '1.125rem', fontWeight: '600', margin: 0 }}>
                  Intake Submissions <span style={{ color: 'var(--text-muted)', fontSize: '0.875rem', fontWeight: '400' }}>({results.intake_submissions.length})</span>
                </h2>
              </div>
              <div style={{ padding: '1rem' }}>
                {results.intake_submissions.map((sub, idx) => {
                  const flatIdx = sectionOffsets.intake_submissions + idx;
                  const isFocused = focusedIdx === flatIdx;
                  return (
                  <Link
                    key={sub.submission_id}
                    ref={setRowRef(flatIdx)}
                    to={sub.alert_id ? `/queue?view=alerts&search=${encodeURIComponent(sub.alert_id)}&drawer=${encodeURIComponent(sub.alert_id)}` : `/intake-forms`}
                    style={{
                      display: 'block',
                      padding: '0.875rem',
                      borderRadius: '8px',
                      marginBottom: idx < results.intake_submissions.length - 1 ? '0.5rem' : 0,
                      background: isFocused ? FOCUSED_STYLE.background : 'var(--bg-secondary)',
                      border: '1px solid transparent',
                      borderLeft: isFocused ? FOCUSED_STYLE.borderLeft : '1px solid transparent',
                      textDecoration: 'none',
                      color: 'inherit',
                    }}
                    onMouseEnter={(e) => { if (!isFocused) e.currentTarget.style.borderColor = 'rgba(102, 126, 234, 0.3)'; }}
                    onMouseLeave={(e) => { if (!isFocused) e.currentTarget.style.borderColor = 'transparent'; }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start', marginBottom: '0.25rem' }}>
                      <div style={{ fontSize: '0.938rem', fontWeight: 600, color: 'var(--text-primary)' }}>
                        {sub.form_title || sub.form_name || 'Submission'}
                      </div>
                      <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>{sub.status}</span>
                    </div>
                    <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
                      Submitted by <strong>{sub.submitted_by || 'unknown'}</strong>
                      {sub.created_at && <span> • {new Date(sub.created_at).toLocaleString()}</span>}
                      {sub.alert_id && <span> • alert <code style={{ color: '#a0e9ff' }}>{sub.alert_id}</code></span>}
                    </div>
                  </Link>
                  );
                })}
              </div>
            </div>
          )}

          {/* Recommended Actions */}
          {results.recommended_actions?.length > 0 && (
            <div className="card">
              <div style={{ padding: '1rem', borderBottom: '1px solid var(--bg-tertiary)' }}>
                <h2 style={{ fontSize: '1.125rem', fontWeight: '600', margin: 0 }}>
                  Recommended Actions <span style={{ color: 'var(--text-muted)', fontSize: '0.875rem', fontWeight: '400' }}>({results.recommended_actions.length})</span>
                </h2>
              </div>
              <div style={{ padding: '1rem' }}>
                {results.recommended_actions.map((act, idx) => {
                  const flatIdx = sectionOffsets.recommended_actions + idx;
                  const isFocused = focusedIdx === flatIdx;
                  return (
                  <Link
                    key={act.id}
                    ref={setRowRef(flatIdx)}
                    to={act.investigation_id ? `/investigation/${act.investigation_id}` : '#'}
                    style={{
                      display: 'block',
                      padding: '0.875rem',
                      borderRadius: '8px',
                      marginBottom: idx < results.recommended_actions.length - 1 ? '0.5rem' : 0,
                      background: isFocused ? FOCUSED_STYLE.background : 'var(--bg-secondary)',
                      border: '1px solid transparent',
                      borderLeft: isFocused ? FOCUSED_STYLE.borderLeft : '1px solid transparent',
                      textDecoration: 'none',
                      color: 'inherit',
                    }}
                    onMouseEnter={(e) => { if (!isFocused) e.currentTarget.style.borderColor = 'rgba(102, 126, 234, 0.3)'; }}
                    onMouseLeave={(e) => { if (!isFocused) e.currentTarget.style.borderColor = 'transparent'; }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start', marginBottom: '0.25rem' }}>
                      <div style={{ fontSize: '0.938rem', fontWeight: 600, color: 'var(--text-primary)' }}>{act.title}</div>
                      <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>{act.status}</span>
                    </div>
                    {act.description && (
                      <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', lineHeight: 1.4, marginBottom: '0.35rem' }}>{act.description}</div>
                    )}
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                      <code style={{ color: '#a0e9ff' }}>{act.action_type}</code>
                      {act.connector_name && <span> via {act.connector_name}</span>}
                      {act.ioc_value && <span> • IOC: {act.ioc_value}</span>}
                    </div>
                  </Link>
                  );
                })}
              </div>
            </div>
          )}

          {/* Detection Rules */}
          {results.detection_rules?.length > 0 && (
            <div className="card">
              <div style={{ padding: '1rem', borderBottom: '1px solid var(--bg-tertiary)' }}>
                <h2 style={{ fontSize: '1.125rem', fontWeight: '600', margin: 0 }}>
                  Detection Rules <span style={{ color: 'var(--text-muted)', fontSize: '0.875rem', fontWeight: '400' }}>({results.detection_rules.length})</span>
                </h2>
              </div>
              <div style={{ padding: '1rem' }}>
                {results.detection_rules.map((rule, idx) => {
                  const flatIdx = sectionOffsets.detection_rules + idx;
                  const isFocused = focusedIdx === flatIdx;
                  return (
                  <div
                    key={rule.rule_id}
                    ref={setRowRef(flatIdx)}
                    style={{
                      padding: '0.875rem',
                      borderRadius: '8px',
                      marginBottom: idx < results.detection_rules.length - 1 ? '0.5rem' : 0,
                      background: isFocused ? FOCUSED_STYLE.background : 'var(--bg-secondary)',
                      borderLeft: isFocused ? FOCUSED_STYLE.borderLeft : '2px solid transparent',
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start', marginBottom: '0.25rem' }}>
                      <div style={{ fontSize: '0.938rem', fontWeight: 600, color: 'var(--text-primary)' }}>{rule.title}</div>
                      <span style={{
                        fontSize: '0.7rem', padding: '0.2rem 0.5rem', borderRadius: 4,
                        background: rule.enabled ? 'rgba(34,197,94,0.15)' : 'rgba(148,163,184,0.15)',
                        color: rule.enabled ? '#4ade80' : 'var(--text-muted)',
                      }}>
                        {rule.enabled ? 'ENABLED' : 'DISABLED'}
                      </span>
                    </div>
                    {rule.description && (
                      <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', lineHeight: 1.4, marginBottom: '0.35rem' }}>{rule.description}</div>
                    )}
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                      <code style={{ color: '#a0e9ff' }}>{rule.rule_id}</code>
                      {rule.rule_type && <span> • {rule.rule_type}</span>}
                      {rule.severity && <span> • {rule.severity}</span>}
                    </div>
                  </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* Users */}
          {results.users?.length > 0 && (
            <div className="card">
              <div style={{ padding: '1rem', borderBottom: '1px solid var(--bg-tertiary)' }}>
                <h2 style={{ fontSize: '1.125rem', fontWeight: '600', margin: 0 }}>
                  👥 Users <span style={{ color: 'var(--text-muted)', fontSize: '0.875rem', fontWeight: '400' }}>({results.users.length})</span>
                </h2>
              </div>
              <div style={{ padding: '1rem' }}>
                {results.users.map((user, idx) => {
                  const flatIdx = sectionOffsets.users + idx;
                  const isFocused = focusedIdx === flatIdx;
                  return (
                  <div
                    key={user.username}
                    ref={setRowRef(flatIdx)}
                    style={{
                      padding: '1rem',
                      borderRadius: '8px',
                      marginBottom: idx < results.users.length - 1 ? '0.75rem' : 0,
                      background: isFocused ? FOCUSED_STYLE.background : 'var(--bg-secondary)',
                      border: '1px solid transparent',
                      borderLeft: isFocused ? FOCUSED_STYLE.borderLeft : '2px solid transparent',
                      transition: 'all 0.15s'
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start' }}>
                      <div>
                        <div style={{ fontSize: '0.938rem', fontWeight: '600', color: 'var(--text-primary)', marginBottom: '0.25rem' }}>
                          {user.full_name || user.username}
                        </div>
                        <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                          Username: {user.username} • Email: {user.email}
                        </div>
                      </div>
                      <div style={{ display: 'flex', gap: '0.5rem' }}>
                        <span className="badge" style={{ background: '#3b82f6', fontSize: '0.688rem' }}>
                          {user.role?.toUpperCase()}
                        </span>
                        {user.disabled && (
                          <span className="badge" style={{ background: '#dc2626', fontSize: '0.688rem' }}>
                            DISABLED
                          </span>
                        )}
                      </div>
                    </div>
                  </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* Audit Logs */}
          {results.audit_logs?.length > 0 && (
            <div className="card">
              <div style={{ padding: '1rem', borderBottom: '1px solid var(--bg-tertiary)' }}>
                <h2 style={{ fontSize: '1.125rem', fontWeight: '600', margin: 0 }}>
                  📜 Audit Logs <span style={{ color: 'var(--text-muted)', fontSize: '0.875rem', fontWeight: '400' }}>({results.audit_logs.length})</span>
                </h2>
              </div>
              <div style={{ padding: '1rem' }}>
                {results.audit_logs.map((log, idx) => {
                  const flatIdx = sectionOffsets.audit_logs + idx;
                  const isFocused = focusedIdx === flatIdx;
                  return (
                  <div
                    key={log.id}
                    ref={setRowRef(flatIdx)}
                    style={{
                      padding: '0.75rem',
                      borderRadius: '6px',
                      marginBottom: idx < results.audit_logs.length - 1 ? '0.5rem' : 0,
                      background: isFocused ? FOCUSED_STYLE.background : 'var(--bg-secondary)',
                      border: '1px solid rgba(255, 255, 255, 0.05)',
                      borderLeft: isFocused ? FOCUSED_STYLE.borderLeft : '1px solid rgba(255, 255, 255, 0.05)',
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start', marginBottom: '0.25rem' }}>
                      <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
                        <code style={{ fontSize: '0.75rem', color: '#a0e9ff', background: 'rgba(102, 126, 234, 0.1)', padding: '0.25rem 0.5rem', borderRadius: '4px' }}>
                          {log.action}
                        </code>
                        <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                          by <span style={{ color: 'var(--text-primary)', fontWeight: '600' }}>{log.username}</span>
                        </span>
                      </div>
                      <span style={{ fontSize: '0.688rem', color: 'var(--text-muted)' }}>
                        {new Date(log.timestamp).toLocaleString()}
                      </span>
                    </div>
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                      {log.resource_type && (
                        <span>
                          Resource: <code style={{ color: '#a0e9ff' }}>{log.resource_type}</code>
                          {log.resource_id && <span> / {log.resource_id}</span>}
                        </span>
                      )}
                    </div>
                  </div>
                  );
                })}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default GlobalSearch;
