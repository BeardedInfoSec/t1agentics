/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

import React, { useState, useEffect, useCallback } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import ColumnCustomizer from './ColumnCustomizer';
import HoverContextMenu from './HoverContextMenu';
import Badge from './ui/Badge';
import Button from './ui/Button';
import { usePreferences, formatDateTime, getTimezoneAbbr } from '../hooks/usePreferences';
import { getAuthHeaders, API_BASE_URL } from '../utils/api';
import {
  statusToBadgeVariant,
  verdictToBadgeVariant,
  priorityToBadgeVariant,
  severityToBadgeVariant
} from '../styles/colors';
import styles from './InvestigationsList.module.css';

// ═══════════════════════════════════════════════════════════════════════════════
// EXPANDED INVESTIGATION CONTENT - Inline details when row is clicked
// ═══════════════════════════════════════════════════════════════════════════════
function ExpandedInvestigationContent({ investigation, preferences }) {
  const [showAllIocs, setShowAllIocs] = useState(false);

  const investigationData = investigation.investigation_data || {};
  const tier1Analysis = investigationData.tier1_analysis || investigationData.tier1_findings || {};
  const riggsAnalysis = investigationData.riggs_analysis || investigationData.tier2_analysis || {};
  const aiTriage = investigation.ai_triage || investigation.triage_result || tier1Analysis || {};

  // Consolidated findings - normalize to strings and dedupe
  const normalizeFindings = (findings) => {
    if (!findings || !Array.isArray(findings)) return [];
    return findings.map(f => {
      if (typeof f === 'string') return f;
      if (typeof f === 'object') return f.finding || f.description || f.text || f.summary || JSON.stringify(f);
      return String(f);
    }).filter(Boolean);
  };

  const allFindings = [
    ...normalizeFindings(riggsAnalysis.key_findings),
    ...normalizeFindings(tier1Analysis.key_findings),
    ...normalizeFindings(aiTriage.key_findings || investigation.key_findings)
  ].filter((v, i, a) => a.indexOf(v) === i); // dedupe

  const recommendations = riggsAnalysis.recommendations || aiTriage.recommended_actions || investigation.recommended_actions || [];
  const affectedEntities = riggsAnalysis.affected_entities || [];
  const confidence = riggsAnalysis.confidence || tier1Analysis.confidence || investigation.ai_confidence;
  const confValue = confidence ? Math.round(confidence > 1 ? confidence : confidence * 100) : null;

  // Extract IOCs from multiple sources with fallback chain
  let iocs = riggsAnalysis.iocs || tier1Analysis.iocs || aiTriage.iocs || [];

  // Fallback to investigation_data.indicators if no structured IOCs found
  if (iocs.length === 0 && investigationData.indicators && Array.isArray(investigationData.indicators)) {
    iocs = investigationData.indicators.map(ind => ({
      type: ind.type || 'unknown',
      value: ind.value,
      verdict: ind.verdict || 'unknown',
      source: ind.source || 'investigation'
    }));
  }

  const maliciousIocs = iocs.filter(ioc => ioc.malicious || ioc.verdict === 'malicious');

  // Timeline / Attack narrative
  const timeline = riggsAnalysis.timeline || [];
  const mitreAttacks = riggsAnalysis.mitre || tier1Analysis.mitre || [];

  // Threat type for story context
  const threatType = riggsAnalysis.threat_type || aiTriage.threat_type || investigation.threat_type;
  const verdict = riggsAnalysis.verdict || aiTriage.verdict || investigation.ai_verdict;

  // Use muted colors - only highlight what matters
  const mutedText = 'var(--text-muted)';
  const secondaryText = 'var(--text-secondary)';

  // IOC type icons/colors
  const iocTypeConfig = {
    hash: { icon: '#', color: '#f59e0b' },
    domain: { icon: '@', color: '#3b82f6' },
    ip: { icon: '⬤', color: '#8b5cf6' },
    url: { icon: '🔗', color: '#06b6d4' },
    file: { icon: '📄', color: '#22c55e' },
    email: { icon: '✉', color: '#ec4899' }
  };

  // How many IOCs to show initially
  const initialIocCount = 6;
  const displayedIocs = showAllIocs ? iocs : iocs.slice(0, initialIocCount);
  const hasMoreIocs = iocs.length > initialIocCount;

  return (
    <div style={{
      padding: '1rem 1.25rem',
      background: 'var(--bg-secondary)',
      borderTop: '1px solid rgba(255,255,255,0.05)',
      fontSize: '0.75rem'
    }}>
      {/* TWO-COLUMN LAYOUT */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 280px', gap: '1.25rem' }}>

        {/* LEFT COLUMN: Analysis Summary */}
        <div>
          {/* Analysis Summary - Single consolidated block */}
          <div style={{ marginBottom: '1rem' }}>
            <div style={{
              display: 'flex',
              alignItems: 'center',
              gap: '0.5rem',
              marginBottom: '0.5rem',
              color: mutedText,
              fontSize: '0.65rem',
              textTransform: 'uppercase',
              letterSpacing: '0.05em'
            }}>
              {riggsAnalysis.summary ? 'Riggs Analysis' : 'Riggs Triage'}
              {confValue && <span style={{ color: secondaryText }}>• {confValue}% confidence</span>}
            </div>
            <div style={{
              fontSize: '0.8rem',
              color: 'var(--text-primary)',
              lineHeight: 1.6
            }}>
              {riggsAnalysis.summary || tier1Analysis.summary || investigation.executive_summary || 'Analysis in progress...'}
            </div>
          </div>

          {/* TWO-COLUMN SUB-LAYOUT: Findings/Actions on left, Timeline on right */}
          <div style={{ display: 'grid', gridTemplateColumns: timeline.length > 0 ? '1fr 280px' : '1fr', gap: '1.25rem', marginBottom: '1rem' }}>
            {/* Sub-left: Key Findings + Recommended Actions */}
            <div>
              {/* Key Findings - Clean list */}
              {allFindings.length > 0 && (
                <div style={{ marginBottom: '1rem' }}>
                  <div style={{
                    color: mutedText,
                    fontSize: '0.65rem',
                    textTransform: 'uppercase',
                    letterSpacing: '0.05em',
                    marginBottom: '0.4rem'
                  }}>
                    Key Findings
                  </div>
                  <ul style={{
                    margin: 0,
                    paddingLeft: '1.1rem',
                    color: secondaryText,
                    fontSize: '0.75rem',
                    lineHeight: 1.6
                  }}>
                    {allFindings.slice(0, 4).map((finding, idx) => (
                      <li key={idx} style={{ marginBottom: '0.25rem' }}>{finding}</li>
                    ))}
                  </ul>
                </div>
              )}

              {/* Recommended Actions - Numbered list */}
              {recommendations.length > 0 && (
                <div>
                  <div style={{
                    color: mutedText,
                    fontSize: '0.65rem',
                    textTransform: 'uppercase',
                    letterSpacing: '0.05em',
                    marginBottom: '0.4rem'
                  }}>
                    Recommended Actions
                  </div>
                  <ol style={{
                    margin: 0,
                    paddingLeft: '1.1rem',
                    color: secondaryText,
                    fontSize: '0.75rem',
                    lineHeight: 1.6
                  }}>
                    {(Array.isArray(recommendations) ? recommendations : [recommendations]).slice(0, 4).map((action, idx) => {
                      const text = typeof action === 'string' ? action : action.action || action.description || '';
                      return <li key={idx} style={{ marginBottom: '0.25rem' }}>{text}</li>;
                    })}
                  </ol>
                </div>
              )}
            </div>

            {/* Sub-right: Attack Timeline */}
            {timeline.length > 0 && (
              <div style={{
                borderLeft: '1px solid rgba(255,255,255,0.08)',
                paddingLeft: '1rem'
              }}>
                <div style={{
                  color: mutedText,
                  fontSize: '0.65rem',
                  textTransform: 'uppercase',
                  letterSpacing: '0.05em',
                  marginBottom: '0.5rem'
                }}>
                  Attack Timeline
                </div>
                <div style={{
                  borderLeft: '2px solid rgba(96, 165, 250, 0.3)',
                  paddingLeft: '0.75rem',
                  marginLeft: '0.2rem'
                }}>
                  {timeline.slice(0, 4).map((step, idx) => (
                    <div key={idx} style={{
                      position: 'relative',
                      marginBottom: '0.5rem',
                      paddingLeft: '0.5rem'
                    }}>
                      <div style={{
                        position: 'absolute',
                        left: '-0.85rem',
                        top: '0.25rem',
                        width: '6px',
                        height: '6px',
                        borderRadius: '50%',
                        background: step.status === 'observed' ? '#60a5fa' : 'rgba(96, 165, 250, 0.4)'
                      }} />
                      <div style={{ fontSize: '0.72rem', color: 'var(--text-primary)', lineHeight: 1.4 }}>
                        {step.step || step.description || step}
                      </div>
                      {step.time && (
                        <div style={{ fontSize: '0.6rem', color: mutedText, marginTop: '0.1rem' }}>
                          {step.time}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* Affected Entities - Inline, minimal */}
          {affectedEntities.length > 0 && (
            <div style={{ marginBottom: '0.75rem' }}>
              <span style={{ color: mutedText, fontSize: '0.65rem', marginRight: '0.5rem' }}>AFFECTED:</span>
              {affectedEntities.slice(0, 3).map((entity, idx) => (
                <span key={idx} style={{
                  display: 'inline-block',
                  padding: '0.15rem 0.4rem',
                  marginRight: '0.35rem',
                  background: 'rgba(255,255,255,0.05)',
                  borderRadius: '3px',
                  fontSize: '0.7rem',
                  fontFamily: 'monospace',
                  color: secondaryText
                }}>
                  {entity.value}
                </span>
              ))}
            </div>
          )}

          {/* IOCs Section - Show malicious/suspicious indicators with expand */}
          {iocs.length > 0 && (
            <div style={{ marginBottom: '1rem' }}>
              <div style={{
                color: mutedText,
                fontSize: '0.65rem',
                textTransform: 'uppercase',
                letterSpacing: '0.05em',
                marginBottom: '0.4rem',
                display: 'flex',
                alignItems: 'center',
                gap: '0.5rem'
              }}>
                Indicators of Compromise
                {maliciousIocs.length > 0 && (
                  <span style={{
                    padding: '0.1rem 0.35rem',
                    background: 'rgba(239, 68, 68, 0.25)',
                    color: '#ef4444',
                    borderRadius: '3px',
                    fontSize: '0.6rem',
                    fontWeight: '600'
                  }}>
                    {maliciousIocs.length} malicious
                  </span>
                )}
              </div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.35rem' }}>
                {displayedIocs.map((ioc, idx) => {
                  const config = iocTypeConfig[ioc.type?.toLowerCase()] || { icon: '?', color: '#6b7280' };
                  const isMalicious = ioc.malicious || ioc.verdict === 'malicious';
                  const isSuspicious = ioc.suspicious || ioc.verdict === 'suspicious';
                  const reputation = isMalicious ? 'malicious' : isSuspicious ? 'suspicious' : 'unknown';
                  return (
                    <HoverContextMenu
                      key={idx}
                      type="ioc"
                      data={{
                        value: ioc.value,
                        type: ioc.type,
                        reputation: reputation,
                        enrichment: ioc.enrichment || null
                      }}
                    >
                      <div style={{
                        display: 'inline-flex',
                        alignItems: 'center',
                        gap: '0.3rem',
                        padding: '0.25rem 0.5rem',
                        background: isMalicious ? 'rgba(239, 68, 68, 0.18)' : isSuspicious ? 'rgba(245, 158, 11, 0.12)' : 'rgba(255,255,255,0.05)',
                        border: `1px solid ${isMalicious ? 'rgba(239, 68, 68, 0.4)' : isSuspicious ? 'rgba(245, 158, 11, 0.3)' : 'rgba(255,255,255,0.08)'}`,
                        borderRadius: '4px',
                        fontSize: '0.68rem',
                        fontFamily: 'monospace',
                        color: isMalicious ? '#fca5a5' : isSuspicious ? '#fcd34d' : secondaryText,
                        maxWidth: '220px',
                        overflow: 'hidden',
                        textOverflow: 'ellipsis',
                        whiteSpace: 'nowrap',
                        cursor: 'help'
                      }}>
                        {isMalicious && (
                          <span style={{ color: '#ef4444', fontSize: '0.55rem', marginRight: '-2px' }}>●</span>
                        )}
                        <span style={{ color: config.color, fontSize: '0.6rem' }}>{config.icon}</span>
                        <span title={ioc.value}>{ioc.value?.length > 28 ? ioc.value.substring(0, 28) + '...' : ioc.value}</span>
                      </div>
                    </HoverContextMenu>
                  );
                })}
                {hasMoreIocs && (
                  <Button
                    variant="info"
                    size="xs"
                    onClick={(e) => { e.stopPropagation(); setShowAllIocs(!showAllIocs); }}
                    style={{ background: 'rgba(96, 165, 250, 0.1)', border: '1px solid rgba(96, 165, 250, 0.25)' }}
                  >
                    {showAllIocs ? 'Show less' : `+${iocs.length - initialIocCount} more`}
                  </Button>
                )}
              </div>
            </div>
          )}
        </div>

        {/* RIGHT COLUMN: Metadata */}
        <div style={{
          borderLeft: '1px solid rgba(255,255,255,0.08)',
          paddingLeft: '1.25rem'
        }}>
          {/* Metadata rows - simple key/value */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.6rem' }}>
            <div>
              <div style={{ color: mutedText, fontSize: '0.6rem', textTransform: 'uppercase', marginBottom: '0.15rem' }}>Owner</div>
              <div style={{ color: investigation.owner ? 'var(--text-primary)' : mutedText, fontSize: '0.75rem' }}>
                {investigation.owner || 'Unassigned'}
              </div>
            </div>
            <div>
              <div style={{ color: mutedText, fontSize: '0.6rem', textTransform: 'uppercase', marginBottom: '0.15rem' }}>Created</div>
              <div style={{ color: 'var(--text-primary)', fontSize: '0.75rem' }}>
                {formatDateTime(investigation.created_at, preferences?.dateFormat, preferences?.timezone)}
              </div>
            </div>
            <div>
              <div style={{ color: mutedText, fontSize: '0.6rem', textTransform: 'uppercase', marginBottom: '0.15rem' }}>Updated</div>
              <div style={{ color: 'var(--text-primary)', fontSize: '0.75rem' }}>
                {formatDateTime(investigation.updated_at, preferences?.dateFormat, preferences?.timezone)}
              </div>
            </div>
            <div>
              <div style={{ color: mutedText, fontSize: '0.6rem', textTransform: 'uppercase', marginBottom: '0.15rem' }}>Alert ID</div>
              <div style={{ color: '#93c5fd', fontSize: '0.7rem', fontFamily: 'monospace' }}>
                {investigation.alert_id || 'N/A'}
              </div>
            </div>
            <div>
              <div style={{ color: mutedText, fontSize: '0.6rem', textTransform: 'uppercase', marginBottom: '0.15rem' }}>Source</div>
              <div style={{ color: 'var(--text-primary)', fontSize: '0.75rem' }}>
                {investigation.source || investigation.alert_source || 'Unknown'}
              </div>
            </div>
            <div>
              <div style={{ color: mutedText, fontSize: '0.6rem', textTransform: 'uppercase', marginBottom: '0.15rem' }}>Severity</div>
              <div style={{ color: 'var(--text-primary)', fontSize: '0.75rem', textTransform: 'capitalize' }}>
                {investigation.severity || 'Unknown'}
              </div>
            </div>
            {threatType && (
              <div>
                <div style={{ color: mutedText, fontSize: '0.6rem', textTransform: 'uppercase', marginBottom: '0.15rem' }}>Threat Type</div>
                <div style={{
                  fontSize: '0.75rem',
                  textTransform: 'capitalize',
                  color: verdict === 'malicious' ? '#f87171' : verdict === 'suspicious' ? '#fbbf24' : 'var(--text-primary)'
                }}>
                  {threatType.replace(/_/g, ' ')}
                </div>
              </div>
            )}

            {/* MITRE ATT&CK - Clickable links */}
            {mitreAttacks.length > 0 && (
              <div>
                <div style={{ color: mutedText, fontSize: '0.6rem', textTransform: 'uppercase', marginBottom: '0.25rem' }}>MITRE ATT&CK</div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.25rem' }}>
                  {mitreAttacks.slice(0, 6).map((attack, idx) => {
                    const id = typeof attack === 'string' ? attack : attack.id || attack;
                    const name = typeof attack === 'object' ? attack.name : null;
                    const mitreUrl = id ? `https://attack.mitre.org/techniques/${id.replace('.', '/')}` : null;
                    return (
                      <a
                        key={idx}
                        href={mitreUrl}
                        target="_blank"
                        rel="noopener noreferrer"
                        onClick={(e) => e.stopPropagation()}
                        style={{
                          display: 'inline-block',
                          padding: '0.15rem 0.35rem',
                          background: 'rgba(139, 92, 246, 0.15)',
                          border: '1px solid rgba(139, 92, 246, 0.25)',
                          borderRadius: '3px',
                          fontSize: '0.6rem',
                          fontFamily: 'monospace',
                          color: '#a78bfa',
                          textDecoration: 'none',
                          cursor: 'pointer'
                        }}
                        title={name ? `${name} - View on MITRE ATT&CK` : 'View on MITRE ATT&CK'}
                      >
                        {id}
                      </a>
                    );
                  })}
                </div>
              </div>
            )}
          </div>

          {/* Action Buttons - Bottom of right column */}
          <div style={{ marginTop: '1rem', display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
            <Link
              to={`/investigation/${investigation.investigation_id}`}
              onClick={(e) => e.stopPropagation()}
              style={{
                display: 'block',
                padding: '0.5rem 0.75rem',
                background: 'rgba(96, 165, 250, 0.15)',
                color: '#60a5fa',
                border: '1px solid rgba(96, 165, 250, 0.25)',
                borderRadius: '4px',
                fontSize: '0.7rem',
                fontWeight: '500',
                textDecoration: 'none',
                textAlign: 'center'
              }}
            >
              Open Full Investigation
            </Link>
            {investigation.alert_id && (
              <Link
                to={`/queue?search=${investigation.alert_id}`}
                onClick={(e) => e.stopPropagation()}
                style={{
                  display: 'block',
                  padding: '0.5rem 0.75rem',
                  background: 'rgba(255, 255, 255, 0.03)',
                  color: secondaryText,
                  border: '1px solid rgba(255, 255, 255, 0.08)',
                  borderRadius: '4px',
                  fontSize: '0.7rem',
                  fontWeight: '500',
                  textDecoration: 'none',
                  textAlign: 'center'
                }}
              >
                View Source Alert
              </Link>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

function InvestigationsList() {
  const [searchParams] = useSearchParams();
  const initialFilter = searchParams.get('state') || 'all';
  const { preferences } = usePreferences();

  const [investigations, setInvestigations] = useState([]);
  const [loading, setLoading] = useState(true);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [stateFilter, setStateFilter] = useState(initialFilter);
  const [dispositionFilter, setDispositionFilter] = useState('all');
  const [priorityFilter, setPriorityFilter] = useState('all');
  const [slaFilter, setSlaFilter] = useState('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [showColumnCustomizer, setShowColumnCustomizer] = useState(false);
  const [timeRange, setTimeRangeState] = useState(() => {
    return localStorage.getItem('T1_Agentics_inv_timerange') || '7d';
  });
  const setTimeRange = (value) => {
    localStorage.setItem('T1_Agentics_inv_timerange', value);
    setTimeRangeState(value);
  };
  const [rowsPerPage, setRowsPerPage] = useState(() => {
    const saved = localStorage.getItem('T1_Agentics_inv_rows_per_page');
    return saved ? parseInt(saved, 10) : 20;
  });
  const [currentPage, setCurrentPage] = useState(1);

  // Expandable row state
  const [expandedRows, setExpandedRows] = useState(new Map()); // Map of id -> { data, loading }
  const [loadingRows, setLoadingRows] = useState(new Set());

  // Time range options
  const timeRangeOptions = [
    { value: '1h', label: '1 hour', minutes: 60 },
    { value: '6h', label: '6 hours', minutes: 360 },
    { value: '24h', label: '24 hours', minutes: 1440 },
    { value: '7d', label: '7 days', minutes: 10080 },
    { value: '30d', label: '30 days', minutes: 43200 },
    { value: 'all', label: 'All time', minutes: null }
  ];

  // Column configuration
  const availableColumns = [
    { key: 'investigation_id', label: 'ID' },
    { key: 'alert_title', label: 'Title' },
    { key: 'state', label: 'State' },
    { key: 'disposition', label: 'Disposition' },
    { key: 'priority', label: 'Priority' },
    { key: 'owner', label: 'Owner' },
    { key: 'created_at', label: 'Created' },
    { key: 'updated_at', label: 'Updated' },
    { key: 'sla_status', label: 'SLA Status' },
    { key: 'time_open', label: 'Time Open' },
    { key: 'severity', label: 'Severity' },
    { key: 'confidence', label: 'Confidence' },
    { key: 'alert_id', label: 'Alert ID' },
    { key: 'executive_summary', label: 'Summary' }
  ];

  const [selectedColumns, setSelectedColumns] = useState(() => {
    const saved = localStorage.getItem('T1_Agentics_investigation_columns');
    return saved ? JSON.parse(saved) : ['investigation_id', 'alert_title', 'state', 'disposition', 'priority', 'sla_status', 'owner', 'created_at'];
  });

  // SLA thresholds in minutes
  const SLA_THRESHOLDS = {
    P1: 30,   // 30 minutes
    P2: 120,  // 2 hours
    P3: 480,  // 8 hours
    P4: 1440  // 24 hours
  };

  const fetchInvestigations = useCallback(async (showFullLoading = false) => {
    if (showFullLoading) {
      setLoading(true);
    } else {
      setIsRefreshing(true);
    }

    try {
      let url = `${API_BASE_URL}/api/v1/investigations?limit=5000`;
      if (stateFilter !== 'all') {
        url += `&state=${stateFilter}`;
      }
      const response = await fetch(url, { headers: getAuthHeaders() });
      const data = await response.json();

      // Add computed SLA fields
      const enrichedData = (Array.isArray(data) ? data : []).map(inv => ({
        ...inv,
        ...calculateSLA(inv)
      }));

      setInvestigations(enrichedData);
    } catch (error) {
    } finally {
      setLoading(false);
      setIsRefreshing(false);
    }
  }, [stateFilter]);

  useEffect(() => {
    fetchInvestigations(true);

    let interval;
    if (autoRefresh) {
      interval = setInterval(() => fetchInvestigations(false), 10000);
    }

    return () => {
      if (interval) clearInterval(interval);
    };
  }, [stateFilter, autoRefresh, fetchInvestigations]);

  useEffect(() => {
    setCurrentPage(1);
  }, [stateFilter, dispositionFilter, priorityFilter, slaFilter, timeRange, searchQuery, rowsPerPage]);

  const calculateSLA = (inv) => {
    const created = new Date(inv.created_at);
    const now = new Date();
    const minutesOpen = Math.floor((now - created) / (1000 * 60));
    const threshold = SLA_THRESHOLDS[inv.priority] || SLA_THRESHOLDS.P3;
    const percentUsed = (minutesOpen / threshold) * 100;

    let slaStatus = 'ok';
    if (inv.state === 'CLOSED' || inv.state === 'RESOLVED') {
      slaStatus = 'met';
    } else if (percentUsed >= 100) {
      slaStatus = 'breached';
    } else if (percentUsed >= 75) {
      slaStatus = 'at_risk';
    }

    return {
      minutes_open: minutesOpen,
      sla_threshold: threshold,
      sla_percent: Math.min(percentUsed, 100),
      sla_status: slaStatus,
      time_remaining: Math.max(threshold - minutesOpen, 0)
    };
  };

  const formatTimeOpen = (minutes) => {
    if (minutes < 60) return `${minutes}m`;
    if (minutes < 1440) return `${Math.floor(minutes / 60)}h ${minutes % 60}m`;
    return `${Math.floor(minutes / 1440)}d ${Math.floor((minutes % 1440) / 60)}h`;
  };

  // Format date using user's timezone preference
  const formatDate = useCallback((dateStr) => {
    if (!dateStr) return '-';
    return formatDateTime(
      dateStr,
      preferences.dateFormat || 'relative',
      preferences.timezone || 'local'
    );
  }, [preferences.dateFormat, preferences.timezone]);

  // Get time range cutoff
  const getTimeCutoff = () => {
    const option = timeRangeOptions.find(o => o.value === timeRange);
    if (!option || option.minutes === null) return null;
    return new Date(Date.now() - option.minutes * 60 * 1000);
  };

  // Filter investigations
  const filteredInvestigations = investigations.filter(inv => {
    // Time range filter
    const cutoff = getTimeCutoff();
    if (cutoff) {
      const invDate = new Date(inv.created_at);
      if (invDate < cutoff) return false;
    }
    if (dispositionFilter !== 'all' && inv.disposition?.toLowerCase() !== dispositionFilter) return false;
    if (priorityFilter !== 'all' && inv.priority !== priorityFilter) return false;
    if (slaFilter !== 'all' && inv.sla_status !== slaFilter) return false;
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      const matchesId = inv.investigation_id?.toLowerCase().includes(q);
      const matchesTitle = inv.alert_title?.toLowerCase().includes(q);
      const matchesOwner = inv.owner?.toLowerCase().includes(q);
      const matchesSummary = inv.executive_summary?.toLowerCase().includes(q);
      if (!matchesId && !matchesTitle && !matchesOwner && !matchesSummary) return false;
    }
    return true;
  });

  // Pagination
  const totalPages = Math.ceil(filteredInvestigations.length / rowsPerPage);
  const startIndex = (currentPage - 1) * rowsPerPage;
  const paginatedInvestigations = filteredInvestigations.slice(startIndex, startIndex + rowsPerPage);

  const handleColumnsChange = (newColumns) => {
    setSelectedColumns(newColumns);
    localStorage.setItem('T1_Agentics_investigation_columns', JSON.stringify(newColumns));
  };

  // Handle row click - toggle expansion and fetch full investigation data
  const handleRowClick = async (inv) => {
    const itemId = inv.investigation_id;

    // If already expanded, collapse it
    if (expandedRows.has(itemId)) {
      setExpandedRows(prev => {
        const newMap = new Map(prev);
        newMap.delete(itemId);
        return newMap;
      });
      return;
    }

    // Mark as loading
    setLoadingRows(prev => new Set(prev).add(itemId));

    try {
      // Fetch full investigation data
      const response = await fetch(`${API_BASE_URL}/api/v1/investigations/${itemId}`, { headers: getAuthHeaders() });
      let data;
      if (response.ok) {
        data = await response.json();
      } else {
        data = inv; // Fall back to existing data
      }

      // Add to expanded rows
      setExpandedRows(prev => {
        const newMap = new Map(prev);
        newMap.set(itemId, { data });
        return newMap;
      });
    } catch (error) {
      // Still expand with original data on error
      setExpandedRows(prev => {
        const newMap = new Map(prev);
        newMap.set(itemId, { data: inv });
        return newMap;
      });
    } finally {
      setLoadingRows(prev => {
        const newSet = new Set(prev);
        newSet.delete(itemId);
        return newSet;
      });
    }
  };

  // Color functions removed - now using centralized colors from ../styles/colors.js

  const renderCell = (inv, columnKey) => {
    const value = inv[columnKey];

    switch (columnKey) {
      case 'investigation_id':
        // Use the actual investigation_id (INV-XXXXXXXX format) from backend
        // This is the unique identifier used for routing and lookups
        const actualId = value || inv.investigation_id || 'unknown';
        return (
          <span style={{ fontFamily: 'monospace', fontSize: '0.75rem', color: '#a0e9ff' }} title={actualId}>
            {actualId}
          </span>
        );

      case 'alert_title':
      case 'title':
        // Support both 'title' and 'alert_title' keys - alert_title is the actual field
        const titleValue = inv.alert_title || inv.title || value;
        return (
          <div
            style={{ maxWidth: '300px', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}
            title={titleValue || 'Untitled Investigation'}
          >
            {titleValue || 'Untitled Investigation'}
          </div>
        );

      case 'state':
        // Simplified 5-state workflow display names
        const stateDisplayMap = {
          'NEW': 'NEW',
          'ANALYZING': 'ANALYZING',
          'NEEDS_REVIEW': 'NEEDS REVIEW',
          'IN_PROGRESS': 'IN PROGRESS',
          'CLOSED': 'CLOSED',
          // Legacy state mappings
          'ENRICHING': 'ANALYZING',
          'AI_TRIAGE_L1': 'ANALYZING',
          'AI_TRIAGE_L2': 'ANALYZING',
          'RIGGS_REVIEW': 'NEEDS REVIEW',
          'RIGGS_ANALYZED': 'NEEDS REVIEW',
          'AWAITING_HUMAN': 'NEEDS REVIEW',
          'RESOLVED': 'CLOSED'
        };
        const displayState = stateDisplayMap[value] || value?.replace(/_/g, ' ') || 'NEW';
        const isAnalyzing = value === 'ANALYZING' || ['ENRICHING', 'AI_TRIAGE_L1', 'AI_TRIAGE_L2'].includes(value);
        return (
          <Badge
            variant={statusToBadgeVariant(value)}
            size="xs"
            solid
            style={isAnalyzing ? { animation: 'pulse 2s infinite' } : undefined}
          >
            {isAnalyzing && '◉ '}{displayState}
          </Badge>
        );

      case 'disposition':
        return (
          <Badge variant={verdictToBadgeVariant(value)} size="xs" solid>
            {value?.replace(/_/g, ' ') || 'UNKNOWN'}
          </Badge>
        );

      case 'priority':
        return (
          <Badge variant={priorityToBadgeVariant(value)} size="xs" solid>
            {value || 'P3'}
          </Badge>
        );

      case 'sla_status':
        const slaVariant = inv.sla_status === 'breached' ? 'danger' :
                          inv.sla_status === 'at_risk' ? 'warning' :
                          inv.sla_status === 'ok' ? 'success' : 'default';
        return (
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
            <Badge variant={slaVariant} size="xs" solid>
              {inv.sla_status === 'breached' ? 'BREACHED' :
               inv.sla_status === 'at_risk' ? 'AT RISK' :
               inv.sla_status === 'met' ? 'MET' : 'OK'}
            </Badge>
            {inv.sla_status !== 'met' && inv.sla_status !== 'breached' && (
              <span style={{ fontSize: '0.65rem', color: 'var(--text-muted)' }}>
                {formatTimeOpen(inv.time_remaining)} left
              </span>
            )}
          </div>
        );

      case 'time_open':
        return (
          <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
            {formatTimeOpen(inv.minutes_open)}
          </span>
        );

      case 'owner':
        return <span style={{ color: 'var(--text-secondary)', fontSize: '0.8rem' }}>{value || 'Unassigned'}</span>;

      case 'created_at':
      case 'updated_at':
        return <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>{formatDate(value)}</span>;

      case 'severity':
        return value ? (
          <Badge variant={severityToBadgeVariant(value)} size="xs" solid>
            {value.toUpperCase()}
          </Badge>
        ) : '-';

      case 'confidence':
        const confPct = value > 1 ? value : value * 100;
        return value ? `${Math.round(confPct)}%` : '-';

      case 'executive_summary':
        return (
          <div style={{ maxWidth: '180px', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
            {value || '-'}
          </div>
        );

      case 'alert_id':
        if (!value) return '-';
        const alertShortId = value?.substring(0, 8) || 'unknown';
        return <span style={{ fontFamily: 'monospace', fontSize: '0.75rem', color: '#94a3b8' }}>alert-{alertShortId}</span>;

      default:
        return value || '-';
    }
  };

  // Calculate metrics
  const metrics = {
    total: investigations.length,
    open: investigations.filter(i => !['CLOSED', 'RESOLVED'].includes(i.state)).length,
    breached: investigations.filter(i => i.sla_status === 'breached').length,
    atRisk: investigations.filter(i => i.sla_status === 'at_risk').length,
    p1Open: investigations.filter(i => i.priority === 'P1' && !['CLOSED', 'RESOLVED'].includes(i.state)).length,
    needsReview: investigations.filter(i => i.state === 'NEEDS_REVIEW' || i.state === 'RIGGS_REVIEW' || i.state === 'AWAITING_HUMAN' || i.state === 'RIGGS_ANALYZED').length,
    resolvedToday: investigations.filter(i => {
      if (!['CLOSED', 'RESOLVED'].includes(i.state)) return false;
      const updated = new Date(i.updated_at);
      const today = new Date();
      return updated.toDateString() === today.toDateString();
    }).length
  };

  // Inline styles object removed - now using CSS module classes from InvestigationsList.module.css

  return (
    <div className={`${styles.container} fade-in`}>
      {/* Header */}
      <div className={styles.header}>
        <div>
          <h2 className={styles.headerTitle}>Investigations</h2>
          <p className={styles.headerSubtitle}>
            {filteredInvestigations.length} of {metrics.total} investigations
            <span className={styles.timezoneBadge} title={`Showing times in ${preferences.timezone || 'local'} timezone`}>
              {getTimezoneAbbr(preferences.timezone || 'local')}
            </span>
          </p>
        </div>
        <div className={styles.headerActions}>
          {expandedRows.size > 0 && (
            <button
              onClick={() => setExpandedRows(new Map())}
              className={`${styles.btn} ${styles.btnSecondary} ${styles.btnCollapse}`}
            >
              ▲ Collapse All ({expandedRows.size})
            </button>
          )}
          <button
            onClick={() => fetchInvestigations(true)}
            disabled={loading || isRefreshing}
            className={`${styles.btn} ${styles.btnSecondary} ${(loading || isRefreshing) ? styles.btnDisabled : ''}`}
          >
            {loading ? '...' : isRefreshing ? '↻' : '↻'} Refresh
          </button>
          <label className={styles.autoRefreshLabel}>
            <input type="checkbox" checked={autoRefresh} onChange={(e) => setAutoRefresh(e.target.checked)} />
            Auto
            {autoRefresh && <span className={styles.autoRefreshStatus}>{isRefreshing ? '...' : 'ON'}</span>}
          </label>
          <Link to="/investigate" className={`${styles.btn} ${styles.btnPrimary}`} style={{ textDecoration: 'none' }}>
            + New
          </Link>
        </div>
      </div>

      {/* Dashboard Metrics - Clickable */}
      <div className={styles.metricsGrid}>
        <div
          className={styles.metricCard}
          onClick={() => { setStateFilter('all'); setDispositionFilter('all'); setPriorityFilter('all'); setSlaFilter('all'); }}
          title="Show all investigations"
        >
          <span className={styles.metricValue}>{metrics.total}</span>
          <span className={styles.metricLabel}>Total</span>
        </div>
        <div
          className={`${styles.metricCard} ${stateFilter !== 'all' && stateFilter !== 'RESOLVED' && stateFilter !== 'CLOSED' ? styles.activeBlue : ''}`}
          onClick={() => { setStateFilter('all'); setSlaFilter('all'); }}
          title="Filter by Open investigations"
        >
          <span className={`${styles.metricValue} ${styles.metricValueBlue}`}>{metrics.open}</span>
          <span className={styles.metricLabel}>Open</span>
        </div>
        <div
          className={`${styles.metricCard} ${slaFilter === 'breached' ? styles.activeRed : ''}`}
          onClick={() => { setSlaFilter('breached'); setStateFilter('all'); }}
          title="Filter by SLA Breached"
        >
          <span className={`${styles.metricValue} ${styles.metricValueRed}`}>{metrics.breached}</span>
          <span className={styles.metricLabel}>Breached</span>
        </div>
        <div
          className={`${styles.metricCard} ${slaFilter === 'at_risk' ? styles.activeYellow : ''}`}
          onClick={() => { setSlaFilter('at_risk'); setStateFilter('all'); }}
          title="Filter by At Risk SLA"
        >
          <span className={`${styles.metricValue} ${styles.metricValueYellow}`}>{metrics.atRisk}</span>
          <span className={styles.metricLabel}>At Risk</span>
        </div>
        <div
          className={`${styles.metricCard} ${priorityFilter === 'P1' ? styles.activeRed : ''}`}
          onClick={() => { setPriorityFilter('P1'); setStateFilter('all'); setSlaFilter('all'); }}
          title="Filter by P1 priority"
        >
          <span className={`${styles.metricValue} ${styles.metricValueRed}`}>{metrics.p1Open}</span>
          <span className={styles.metricLabel}>P1 Open</span>
        </div>
        <div
          className={`${styles.metricCard} ${stateFilter === 'NEEDS_REVIEW' ? styles.activeOrange : ''}`}
          onClick={() => { setStateFilter('NEEDS_REVIEW'); setSlaFilter('all'); }}
          title="Filter by Needs Review (awaiting human decision)"
        >
          <span className={`${styles.metricValue} ${styles.metricValueOrange}`}>{metrics.needsReview}</span>
          <span className={styles.metricLabel}>Needs Review</span>
        </div>
        <div
          className={`${styles.metricCard} ${stateFilter === 'CLOSED' ? styles.activeGreen : ''}`}
          onClick={() => { setStateFilter('CLOSED'); setSlaFilter('all'); }}
          title="Filter by Closed today"
        >
          <span className={`${styles.metricValue} ${styles.metricValueGreen}`}>{metrics.resolvedToday}</span>
          <span className={styles.metricLabel}>Closed Today</span>
        </div>
      </div>

      {/* Search Bar */}
      <div className={styles.searchBar}>
        <input
          type="text"
          placeholder="Search ID, title, owner, summary..."
          className={styles.searchInput}
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
        />
        <button className={`${styles.btn} ${styles.btnSecondary}`} onClick={() => setShowColumnCustomizer(true)}>
          Columns
        </button>
      </div>

      {/* Filter Bar */}
      <div className={styles.filterBar}>
        <div className={styles.filterGroup}>
          <span className={styles.filterLabel}>State:</span>
          <select className={styles.select} value={stateFilter} onChange={(e) => setStateFilter(e.target.value)}>
            <option value="all">All</option>
            <option value="NEW">New</option>
            <option value="ANALYZING">Analyzing (AI Working)</option>
            <option value="NEEDS_REVIEW">Needs Review</option>
            <option value="IN_PROGRESS">In Progress</option>
            <option value="CLOSED">Closed</option>
          </select>
        </div>

        <div className={styles.filterGroup}>
          <span className={styles.filterLabel}>Disposition:</span>
          <select className={styles.select} value={dispositionFilter} onChange={(e) => setDispositionFilter(e.target.value)}>
            <option value="all">All</option>
            <option value="malicious">Malicious</option>
            <option value="suspicious">Suspicious</option>
            <option value="benign">Benign</option>
            <option value="false_positive">False Positive</option>
            <option value="unknown">Unknown</option>
          </select>
        </div>

        <div className={styles.filterGroup}>
          <span className={styles.filterLabel}>Priority:</span>
          <select className={styles.select} value={priorityFilter} onChange={(e) => setPriorityFilter(e.target.value)}>
            <option value="all">All</option>
            <option value="P1">P1</option>
            <option value="P2">P2</option>
            <option value="P3">P3</option>
            <option value="P4">P4</option>
          </select>
        </div>

        <div className={styles.filterGroup}>
          <span className={styles.filterLabel}>SLA:</span>
          <select className={styles.select} value={slaFilter} onChange={(e) => setSlaFilter(e.target.value)}>
            <option value="all">All</option>
            <option value="breached">Breached</option>
            <option value="at_risk">At Risk</option>
            <option value="ok">OK</option>
            <option value="met">Met</option>
          </select>
        </div>

        <div className={styles.filterGroup}>
          <span className={styles.filterLabel}>Time:</span>
          <select className={styles.select} value={timeRange} onChange={(e) => setTimeRange(e.target.value)}>
            {timeRangeOptions.map(opt => (
              <option key={opt.value} value={opt.value}>{opt.label}</option>
            ))}
          </select>
        </div>

        <div style={{ flex: 1 }} />

        <div className={styles.filterGroup}>
          <span className={styles.filterLabel}>Rows:</span>
          <select className={styles.select} value={rowsPerPage} onChange={(e) => {
            const val = Number(e.target.value);
            setRowsPerPage(val);
            localStorage.setItem('T1_Agentics_inv_rows_per_page', val);
          }}>
            <option value={10}>10</option>
            <option value={15}>15</option>
            <option value={20}>20</option>
            <option value={30}>30</option>
            <option value={50}>50</option>
            <option value={100}>100</option>
          </select>
        </div>
      </div>

      {/* Table */}
      {loading ? (
        <div style={{ textAlign: 'center', padding: '2rem', color: 'var(--text-muted)' }}>Loading...</div>
      ) : paginatedInvestigations.length === 0 ? (
        <div style={{ textAlign: 'center', padding: '2rem', color: 'var(--text-muted)', background: 'var(--bg-tertiary)', borderRadius: '6px' }}>
          No investigations found
        </div>
      ) : (
        <div className={styles.tableContainer}>
          <table className={styles.table}>
            <thead>
              <tr>
                {selectedColumns.map(colKey => {
                  const col = availableColumns.find(c => c.key === colKey);
                  return <th key={colKey} className={styles.th}>{col?.label || colKey}</th>;
                })}
                <th className={styles.th} style={{ textAlign: 'right', width: '60px' }}>Action</th>
              </tr>
            </thead>
            <tbody>
              {paginatedInvestigations.map((inv, index) => {
                const isEvenRow = index % 2 === 0;
                const isBreached = inv.sla_status === 'breached';
                const isExpanded = expandedRows.has(inv.investigation_id);
                const isLoading = loadingRows.has(inv.investigation_id);
                const expandedInfo = expandedRows.get(inv.investigation_id);
                return (
                  <React.Fragment key={inv.investigation_id}>
                    <tr
                      className={`${styles.row} ${isExpanded ? styles.rowExpanded : ''} ${isBreached ? styles.rowBreached : inv.priority === 'P1' ? styles.rowP1 : ''}`}
                      style={{
                        background: !isExpanded && !isEvenRow ? 'rgba(255, 255, 255, 0.02)' : undefined
                      }}
                      onClick={() => handleRowClick(inv)}
                    >
                      {selectedColumns.map(colKey => (
                        <td key={colKey} className={styles.td}>
                          {renderCell(inv, colKey)}
                        </td>
                      ))}
                      <td className={styles.td} style={{ textAlign: 'right' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem', justifyContent: 'flex-end' }}>
                          <button
                            onClick={(e) => { e.stopPropagation(); handleRowClick(inv); }}
                            className={`${styles.btn} ${styles.btnSecondary}`}
                            style={{ fontSize: '0.65rem', padding: '0.25rem 0.5rem', minWidth: '50px' }}
                          >
                            {isLoading ? '...' : isExpanded ? '▲' : '▼'}
                          </button>
                          <Link
                            to={`/investigation/${inv.investigation_id}`}
                            className={`${styles.btn} ${styles.btnSecondary}`}
                            style={{ fontSize: '0.65rem', padding: '0.25rem 0.5rem', textDecoration: 'none' }}
                            onClick={(e) => e.stopPropagation()}
                          >
                            View
                          </Link>
                        </div>
                      </td>
                    </tr>
                    {/* Expanded content row */}
                    {isExpanded && !isLoading && expandedInfo?.data && (
                      <tr>
                        <td colSpan={selectedColumns.length + 1} style={{ padding: 0 }}>
                          <ExpandedInvestigationContent
                            investigation={expandedInfo.data}
                            preferences={preferences}
                          />
                        </td>
                      </tr>
                    )}
                    {/* Loading row */}
                    {isLoading && (
                      <tr>
                        <td colSpan={selectedColumns.length + 1} style={{ padding: '1rem', textAlign: 'center', color: 'var(--text-muted)' }}>
                          Loading investigation details...
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                );
              })}
            </tbody>
          </table>

          {/* Pagination */}
          <div className={styles.pagination}>
            <span className={styles.paginationInfo}>
              Showing {startIndex + 1}-{Math.min(startIndex + rowsPerPage, filteredInvestigations.length)} of {filteredInvestigations.length}
            </span>
            <div className={styles.paginationControls}>
              <button
                className={`${styles.btn} ${styles.btnSecondary} ${currentPage === 1 ? styles.btnDisabled : ''}`}
                onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
                disabled={currentPage === 1}
              >
                ← Prev
              </button>
              <span className={styles.paginationText}>
                Page {currentPage} of {totalPages || 1}
              </span>
              <button
                className={`${styles.btn} ${styles.btnSecondary} ${(currentPage === totalPages || totalPages === 0) ? styles.btnDisabled : ''}`}
                onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))}
                disabled={currentPage === totalPages || totalPages === 0}
              >
                Next →
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Column Customizer Modal */}
      {showColumnCustomizer && (
        <ColumnCustomizer
          availableColumns={availableColumns}
          selectedColumns={selectedColumns}
          onColumnsChange={handleColumnsChange}
          onClose={() => setShowColumnCustomizer(false)}
          defaultColumns={['investigation_id', 'alert_title', 'state', 'disposition', 'priority', 'sla_status', 'owner', 'created_at']}
        />
      )}
    </div>
  );
}

export default InvestigationsList;
