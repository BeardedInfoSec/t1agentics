/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

import React, { useState, useEffect, useCallback, useRef, useMemo } from 'react';
import { useParams, Link } from 'react-router-dom';
import InvestigationChat from './InvestigationChat';
import CampaignMembership from './CampaignMembership';
import RelatedActivity from './RelatedActivity';
import RecommendationsPanel from './RecommendationsPanel';
import ResponseActions from './ResponseActions';
import SOPRecommendations from './SOPRecommendations';
import RecommendedActions from './RecommendedActions';
import HoverContextMenu from './HoverContextMenu';
import InvestigationSidebar from './investigation/InvestigationSidebar';
import IOCActionButtons from './investigation/IOCActionButtons';
import ReportGenerator from './investigation/ReportGenerator';
import { getAuthHeaders, API_BASE_URL, getCsrfToken, authFetch } from '../utils/api';
import { telemetry } from '../utils/telemetry';
import { buildRiggsInsights } from './riggs/riggsWidgetAdapter';
import { getLicenseTier, refreshLicenseCache } from '../utils/licenseCache';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import './InvestigationWorkbench.css';
import styles from './InvestigationWorkbenchV2.module.css';

// Typewriter effect for AI chat messages — reveals text word-by-word
function SidePanelTypewriter({ text, speed = 35, onComplete, onTick, renderFn }) {
  const [count, setCount] = useState(0);
  const [done, setDone] = useState(false);
  const words = useMemo(() => text.split(/(\s+)/), [text]);
  const total = words.length;
  const ref = useRef(null);
  const tickRef = useRef(0);

  useEffect(() => {
    if (done) return;
    ref.current = setInterval(() => {
      setCount(prev => {
        const next = prev + 1;
        tickRef.current++;
        if (tickRef.current % 8 === 0) onTick?.();
        if (next >= total) {
          clearInterval(ref.current);
          setDone(true);
          onComplete?.();
          return total;
        }
        return next;
      });
    }, 1000 / speed);
    return () => clearInterval(ref.current);
  }, [total, speed, done, onComplete, onTick]);

  const skip = useCallback(() => {
    clearInterval(ref.current);
    setCount(total);
    setDone(true);
    onComplete?.();
  }, [total, onComplete]);

  const partial = words.slice(0, count).join('');
  return (
    <div onClick={skip} style={{ cursor: done ? 'default' : 'pointer' }}>
      {renderFn ? renderFn(partial) : partial}
      {!done && (
        <span className={styles.typewriterCursor} />
      )}
    </div>
  );
}

// Enhanced markdown renderer for chat messages - structures content for readability
function renderMarkdown(text) {
  if (!text) return null;

  // Process inline formatting (bold, code, etc.)
  const processInline = (str, keyPrefix = '') => {
    const parts = [];
    let remaining = str;
    let keyIdx = 0;

    while (remaining.length > 0) {
      const boldMatch = remaining.match(/\*\*(.+?)\*\*/);
      const codeMatch = remaining.match(/`([^`]+)`/);
      const boldIdx = boldMatch ? remaining.indexOf(boldMatch[0]) : Infinity;
      const codeIdx = codeMatch ? remaining.indexOf(codeMatch[0]) : Infinity;

      if (boldIdx === Infinity && codeIdx === Infinity) {
        if (remaining) parts.push(<span key={`${keyPrefix}${keyIdx++}`}>{remaining}</span>);
        break;
      }

      if (boldIdx < codeIdx) {
        if (boldIdx > 0) parts.push(<span key={`${keyPrefix}${keyIdx++}`}>{remaining.slice(0, boldIdx)}</span>);
        parts.push(<strong key={`${keyPrefix}${keyIdx++}`} className={styles.markdownBold}>{boldMatch[1]}</strong>);
        remaining = remaining.slice(boldIdx + boldMatch[0].length);
      } else {
        if (codeIdx > 0) parts.push(<span key={`${keyPrefix}${keyIdx++}`}>{remaining.slice(0, codeIdx)}</span>);
        parts.push(
          <code key={`${keyPrefix}${keyIdx++}`} className={styles.markdownCode}>
            {codeMatch[1]}
          </code>
        );
        remaining = remaining.slice(codeIdx + codeMatch[0].length);
      }
    }
    return parts;
  };

  // Split into sentences for better structure
  const structureText = (text) => {
    // Split by common patterns that indicate separate pieces of info
    const segments = [];

    // First split by newlines
    const lines = text.split('\n').filter(l => l.trim());

    for (const line of lines) {
      const trimmed = line.trim();

      // Check if it's a bullet point
      if (trimmed.startsWith('- ') || trimmed.startsWith('• ') || trimmed.startsWith('* ')) {
        segments.push({ type: 'bullet', content: trimmed.slice(2) });
        continue;
      }

      // Check if it's a header-like pattern (ends with colon followed by nothing or newline)
      if (trimmed.endsWith(':')) {
        segments.push({ type: 'header', content: trimmed });
        continue;
      }

      // Check for key-value patterns in the text
      // Split long text into logical segments at sentence boundaries
      const sentences = trimmed.split(/(?<=[.!?])\s+(?=[A-Z])/);

      for (const sentence of sentences) {
        if (sentence.trim()) {
          segments.push({ type: 'paragraph', content: sentence.trim() });
        }
      }
    }

    return segments;
  };

  const segments = structureText(text);

  // If we only have one segment and it's long, try to break it up more
  if (segments.length === 1 && segments[0].content.length > 100) {
    const content = segments[0].content;
    // Try to break at sentence boundaries
    const sentences = content.split(/(?<=[.!?])\s+/);
    if (sentences.length > 1) {
      return (
        <div className={styles.markdownSentences}>
          {sentences.map((sentence, idx) => (
            <div key={idx} className={styles.markdownSentence}>
              {processInline(sentence, `s${idx}-`)}
            </div>
          ))}
        </div>
      );
    }
  }

  return (
    <div className={styles.markdownSegments}>
      {segments.map((segment, idx) => {
        if (segment.type === 'bullet') {
          return (
            <div key={idx} className={styles.markdownBullet}>
              <span className={styles.markdownBulletDot}>•</span>
              <span>{processInline(segment.content, `b${idx}-`)}</span>
            </div>
          );
        }

        if (segment.type === 'header') {
          return (
            <div key={idx} className={styles.markdownHeader} style={{ marginTop: idx > 0 ? '0.3rem' : 0 }}>
              {processInline(segment.content, `h${idx}-`)}
            </div>
          );
        }

        // Regular paragraph
        return (
          <div key={idx} className={styles.markdownParagraph}>
            {processInline(segment.content, `p${idx}-`)}
          </div>
        );
      })}
    </div>
  );
}

/**
 * Investigation Workbench V2 - Summary-First Layout
 *
 * Design Philosophy:
 * - 10-second decision: Analyst sees verdict + key IOCs immediately
 * - Tabbed interface for progressive disclosure
 * - Chat is collapsible to maximize workspace
 */

// ============================================================================
// RIGGS INSIGHTS - Dynamic widgets based on AI analysis
// ============================================================================

function RiggsInsights({ investigation, alertData, deepDiveLoading }) {
  const [insights, setInsights] = useState([]);
  const [coreInfo, setCoreInfo] = useState({});
  const [loading, setLoading] = useState(true);
  const [showConfidenceDrawer, setShowConfidenceDrawer] = useState(false);
  const [hoveredTimelineEvent, setHoveredTimelineEvent] = useState(null);
  const [completedRecommendations, setCompletedRecommendations] = useState({});
  const [triageLoading, setTriageLoading] = useState(false);
  const [triageError, setTriageError] = useState(null);

  useEffect(() => {
    const { coreInfo: nextCore, widgets } = buildRiggsInsights(investigation, alertData);
    setCoreInfo(nextCore || {});
    setInsights(widgets || []);
    setLoading(false);
  }, [investigation, alertData]);

  const handleManualTriage = async () => {
    setTriageLoading(true);
    setTriageError(null);
    try {
      const response = await fetch(
        `${window.API_BASE_URL || '/api'}/api/v1/investigations/${investigation.investigation_id}/triage`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'include'
        }
      );
      if (!response.ok) {
        throw new Error('Failed to queue triage');
      }
      const data = await response.json();
      // Success - triage queued, can show a toast or update UI
      console.log('Triage queued:', data);
    } catch (err) {
      setTriageError(err.message);
      console.error('Triage error:', err);
    } finally {
      setTriageLoading(false);
    }
  };


  if (loading) {
    return null;
  }

  // Always show static header even if no dynamic insights
  // Get verdict color
  const getVerdictColor = (verdict) => {
    const v = (verdict || '').toUpperCase();
    const root = getComputedStyle(document.documentElement);
    if (['MALICIOUS', 'TRUE_POSITIVE', 'CONFIRMED'].includes(v))
      return root.getPropertyValue('--danger').trim() || '#ef4444';
    if (['SUSPICIOUS', 'NEEDS_INVESTIGATION'].includes(v))
      return root.getPropertyValue('--warning').trim() || '#f59e0b';
    if (['BENIGN', 'FALSE_POSITIVE', 'CLEAN'].includes(v))
      return root.getPropertyValue('--success').trim() || '#22c55e';
    return root.getPropertyValue('--text-muted').trim() || '#6b7280';
  };

  const verdictColor = getVerdictColor(coreInfo.verdict);

  // Extract impact summary for the banner
  const getImpactSummary = () => {
    const impactWidget = insights.find(w => (w.title || '').toLowerCase().includes('impact'));
    if (impactWidget?.items?.[0]) {
      const firstItem = impactWidget.items[0];
      return typeof firstItem === 'string' ? firstItem : firstItem.label;
    }
    // Try to extract from affected hosts
    const affectedWidget = insights.find(w => (w.title || '').toLowerCase().includes('affected'));
    if (affectedWidget?.items?.length > 0) {
      return `${affectedWidget.items.length} system${affectedWidget.items.length > 1 ? 's' : ''} affected`;
    }
    return null;
  };

  // Extract duration from timeline
  const getDurationInfo = () => {
    const timelineWidget = insights.find(w => w.type === 'timeline');
    if (timelineWidget?.timelineData?.length >= 2) {
      const events = timelineWidget.timelineData;
      const minTime = events[0].timestamp.getTime();
      const maxTime = events[events.length - 1].timestamp.getTime();
      const hours = Math.ceil((maxTime - minTime) / (1000 * 60 * 60));
      if (hours >= 24) {
        const days = Math.ceil(hours / 24);
        return `Active for ${days} day${days > 1 ? 's' : ''}`;
      }
      return `Active for ${hours} hour${hours > 1 ? 's' : ''}`;
    }
    return null;
  };

  const impactSummary = getImpactSummary();
  const durationInfo = getDurationInfo();

  return (
    <div className={styles.riggsInsightsWrap}>
      {/* VERDICT HEADER BANNER - Medium emotional anchor */}
      <div className={styles.verdictBanner} style={{
        background: `linear-gradient(135deg, ${verdictColor}1a 0%, ${verdictColor}06 100%)`,
        borderLeft: `3px solid ${verdictColor}`
      }}>
        {/* Verdict content */}
        <div>
          {/* Main verdict line */}
          <div className={styles.verdictMainRow}>
          <span className={styles.verdictLabel} style={{ color: verdictColor }}>
            {(coreInfo.verdict || 'Unknown').replace(/_/g, ' ')}
          </span>
          <span className={styles.verdictSeparator}>—</span>
          <span className={styles.verdictTitle}>
            {coreInfo.verdictTitle
              ? coreInfo.verdictTitle
              : coreInfo.threatCategory
                ? coreInfo.threatCategory
                : coreInfo.threatType && coreInfo.threatType !== 'unknown' && coreInfo.threatType !== 'none'
                  ? `${coreInfo.threatType.replace(/_/g, ' ')} Detected`
                  : 'Threat Detected'}
          </span>
        </div>

        {/* Context line - confidence, urgency, impact, duration */}
        <div className={styles.verdictContextRow}>
          {coreInfo.confidence > 0 && (() => {
            const confPct = Math.round(coreInfo.confidence > 1 ? coreInfo.confidence : coreInfo.confidence * 100);
            const confBarColor = confPct > 80 ? 'var(--success, #22c55e)' : confPct >= 50 ? 'var(--warning, #f59e0b)' : 'var(--danger, #ef4444)';
            return (
              <>
                <span className={styles.confidenceMeterInline}>
                  <span className={styles.confidenceMeterBar} style={{ '--conf-pct': `${confPct}%`, '--conf-color': confBarColor }} />
                  <span className={styles.confidenceMeterLabel}>{confPct}%</span>
                </span>
                <span className={styles.verdictDot}>•</span>
              </>
            );
          })()}
          {coreInfo.urgency && (
            <>
              <span className={styles.verdictUrgency} style={{ color: coreInfo.urgency.color }}>
                {coreInfo.urgency.label}
              </span>
              <span className={styles.verdictDot}>•</span>
            </>
          )}
          {impactSummary && (
            <>
              <span>{impactSummary}</span>
              <span className={styles.verdictDot}>•</span>
            </>
          )}
          {durationInfo && (
            <span>{durationInfo}</span>
          )}
          {!impactSummary && !durationInfo && !coreInfo.urgency && coreInfo.source && (
            <span>Source: {coreInfo.source}</span>
          )}
        </div>

        {/* Top IOCs - compact chips for key indicators */}
        {(() => {
          const rawEvent = alertData?.raw_event || alertData || {};
          const _sa = (v) => Array.isArray(v) ? v : [];
          const topIocs = [
            ..._sa(investigation?.extracted_iocs),
            ..._sa(rawEvent?.iocs),
            ..._sa(rawEvent?._extracted?.iocs)
          ].filter(ioc => ioc && (ioc.value || ioc.indicator))
           .slice(0, 3);
          if (topIocs.length === 0) return null;
          return (
            <div className={styles.verdictIOCChips}>
              {topIocs.map((ioc, i) => {
                const rep = (ioc.reputation || ioc.verdict || '').toLowerCase();
                const chipColor = rep === 'malicious' ? 'var(--danger, #ef4444)' : rep === 'suspicious' ? 'var(--warning, #f59e0b)' : rep === 'clean' || rep === 'benign' ? 'var(--success, #22c55e)' : 'var(--text-muted, #6b7280)';
                return (
                  <span key={i} className={styles.verdictIOCChip} style={{ color: chipColor, borderColor: chipColor }}>
                    <span className={styles.verdictIOCType}>[{(ioc.type || 'IOC').toUpperCase()}]</span>
                    <span className={styles.verdictIOCValue}>{(ioc.value || ioc.indicator || '').length > 40 ? (ioc.value || ioc.indicator).slice(0, 37) + '...' : ioc.value || ioc.indicator}</span>
                    {rep && <span className={styles.verdictIOCRep}>- {rep.toUpperCase()}</span>}
                  </span>
                );
              })}
            </div>
          );
        })()}

        {/* Summary - split OBSERVED / INFERRED into labeled sections */}
        {coreInfo.summary && (() => {
          const text = coreInfo.summary;
          const obsMatch = text.match(/OBSERVED:\s*([\s\S]*?)(?=\s*INFERRED:|$)/i);
          const infMatch = text.match(/INFERRED:\s*([\s\S]*?)$/i);
          if (obsMatch || infMatch) {
            return (
              <div className={styles.verdictSummary}>
                {obsMatch && obsMatch[1].trim() && (
                  <div style={{ marginBottom: infMatch ? '0.6rem' : 0 }}>
                    <span style={{ fontWeight: 700, fontSize: '0.75rem', textTransform: 'uppercase', letterSpacing: '0.5px', color: 'var(--text-muted)', display: 'block', marginBottom: '0.25rem' }}>Observed</span>
                    {obsMatch[1].trim()}
                  </div>
                )}
                {infMatch && infMatch[1].trim() && (
                  <div>
                    <span style={{ fontWeight: 700, fontSize: '0.75rem', textTransform: 'uppercase', letterSpacing: '0.5px', color: 'var(--text-muted)', display: 'block', marginBottom: '0.25rem' }}>Inferred</span>
                    {infMatch[1].trim()}
                  </div>
                )}
              </div>
            );
          }
          return <div className={styles.verdictSummary}>{text}</div>;
        })()}

        {/* Attack Narrative - detailed story of what happened */}
        {coreInfo.attackNarrative && (
          <div className={styles.attackNarrative}>
            <span className={styles.attackNarrativeLabel}>
              Attack Flow:
            </span>
            {coreInfo.attackNarrative}
          </div>
        )}

        {/* Business Impact */}
        {coreInfo.businessImpact && (
          <div className={styles.businessImpact}>
            <span className={styles.businessImpactLabel}>
              Business Impact:
            </span>
            {coreInfo.businessImpact}
          </div>
        )}

        {/* Why we're confident - Collapsible drawer */}
        {(coreInfo.confidenceSignals?.length > 0 || coreInfo.whatWouldChange?.length > 0) && (
          <div className={styles.confidenceToggle}>
            <button
              onClick={() => setShowConfidenceDrawer(!showConfidenceDrawer)}
              className={styles.confidenceToggleBtn}
            >
              <span className={styles.confidenceToggleArrow} style={{
                transform: showConfidenceDrawer ? 'rotate(90deg)' : 'rotate(0deg)'
              }}>
                {'>'}
              </span>
              Why we're confident
            </button>

            {showConfidenceDrawer && (
              <div className={styles.confidenceDrawer}>
                {/* Top signals - Enhanced with severity badges */}
                {coreInfo.confidenceSignals?.length > 0 && (
                  <div className={styles.evidenceGroup}>
                    <div className={styles.evidenceSectionTitle}>
                      <span className={styles.evidenceCheck}>&#10003;</span>
                      Key Evidence
                    </div>
                    <div className={styles.evidenceList}>
                      {coreInfo.confidenceSignals.map((s, i) => (
                        <div key={i} className={`${styles.evidenceItem} ${s.weight === 'high' ? styles.evidenceItemHigh : s.weight === 'medium' ? styles.evidenceItemMedium : styles.evidenceItemLow}`}>
                          <span className={`${styles.evidenceWeightBadge} ${s.weight === 'high' ? styles.evidenceWeightHigh : s.weight === 'medium' ? styles.evidenceWeightMedium : styles.evidenceWeightLow}`}>
                            {s.weight === 'high' ? 'HIGH' : s.weight === 'medium' ? 'MED' : 'LOW'}
                          </span>
                          <span className={styles.evidenceSignalText}>
                            {s.signal}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* What would change the verdict - Enhanced */}
                {coreInfo.whatWouldChange?.length > 0 && (
                  <div className={coreInfo.confidenceSignals?.length > 0 ? styles.counterEvidenceWithSeparator : undefined}>
                    <div className={styles.evidenceSectionTitle}>
                      <span className={styles.evidenceQuestion}>&#63;</span>
                      Counter-evidence Needed
                    </div>
                    <div className={styles.counterEvidenceList}>
                      {coreInfo.whatWouldChange.map((w, i) => (
                        <div key={i} className={styles.counterEvidenceItem}>
                          <span className={styles.counterEvidenceCheckbox} />
                          <span className={styles.counterEvidenceText}>
                            {w}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        )}
        </div>
      </div>

      {/* RECOMMENDATIONS STRIP - Horizontal action bar below verdict */}
      <RecommendationsPanel
        investigation={investigation}
        onUpdate={async (data) => {
          try {
            await fetch(
              `${API_BASE_URL}/api/v1/investigations/${investigation.investigation_id || investigation.id}`,
              {
                method: 'PATCH',
                headers: { ...getAuthHeaders(), 'Content-Type': 'application/json' },
                body: JSON.stringify(data)
              }
            );
          } catch (err) {
          }
        }}
      />

      {/* Suggested Playbooks and SOP recommendations are rendered in SummaryTab */}

      {/* NO ANALYSIS - Show manual triage button */}
      {insights.length === 0 && (
        <div style={{
          padding: '2rem',
          textAlign: 'center',
          background: 'var(--bg-secondary, #f9fafb)',
          borderRadius: '8px',
          margin: '1rem 0',
          border: '1px solid var(--border-light, #e5e7eb)'
        }}>
          <div style={{ marginBottom: '1rem', color: 'var(--text-muted, #6b7280)' }}>
            No analysis details yet. Click the button below to trigger triage analysis.
          </div>
          <button
            onClick={handleManualTriage}
            disabled={triageLoading}
            style={{
              padding: '0.5rem 1rem',
              background: 'var(--primary, #3b82f6)',
              color: 'white',
              border: 'none',
              borderRadius: '6px',
              cursor: triageLoading ? 'not-allowed' : 'pointer',
              opacity: triageLoading ? 0.6 : 1,
              fontWeight: 500,
              fontSize: '0.875rem'
            }}
          >
            {triageLoading ? 'Queuing Triage...' : 'Trigger Triage Analysis'}
          </button>
          {triageError && (
            <div style={{
              marginTop: '0.5rem',
              color: 'var(--danger, #ef4444)',
              fontSize: '0.875rem'
            }}>
              Error: {triageError}
            </div>
          )}
        </div>
      )}

      {/* DYNAMIC WIDGETS */}
      {insights.length > 0 && (
        <>
          <div className={styles.analysisDetailsSectionTitle}>
            Analysis Details
          </div>

          {/* ATTACK TIMELINE - Horizontal visual timeline with kill chain phases */}
          {insights.find(w => w.type === 'timeline') && (() => {
            const timelineWidget = insights.find(w => w.type === 'timeline');
            const events = timelineWidget.timelineData || [];
            if (events.length === 0) return null;

            const minTime = events[0].timestamp.getTime();
            const maxTime = events[events.length - 1].timestamp.getTime();
            const durationDays = Math.ceil((maxTime - minTime) / (1000 * 60 * 60 * 24));

            // Classify events into kill chain phases based on keywords
            // Default to orange/amber for most events to match screenshot style
            const classifyEvent = (label, type) => {
              const lower = (label || '').toLowerCase() + ' ' + (type || '').toLowerCase();
              // Initial Access - orange (most common for compromises)
              if (lower.includes('initial') || lower.includes('access') || lower.includes('entry') || lower.includes('exploit') || lower.includes('compromise') || lower.includes('compromised')) {
                return { phase: 'INITIAL ACCESS', color: '#f59e0b', icon: '>' };
              }
              // Lateral Movement - purple
              if (lower.includes('lateral') || lower.includes('spread') || lower.includes('pivot') || lower.includes('movement')) {
                return { phase: 'LATERAL MOVEMENT', color: '#8b5cf6', icon: '~' };
              }
              // Persistence - pink
              if (lower.includes('persist') || lower.includes('cron') || lower.includes('scheduled') || lower.includes('backdoor') || lower.includes('install')) {
                return { phase: 'PERSISTENCE', color: '#ec4899', icon: '+' };
              }
              // Impact - red
              if (lower.includes('impact') || lower.includes('mining') || lower.includes('encrypt') || lower.includes('exfil') || lower.includes('damage')) {
                return { phase: 'IMPACT', color: '#ef4444', icon: '!' };
              }
              // Detection - green (but less common to show)
              if (lower.includes('detect') || lower.includes('alert') || lower.includes('trigger')) {
                return { phase: 'DETECTION', color: '#22c55e', icon: '*' };
              }
              // Command & Control - indigo
              if (lower.includes('command') || lower.includes('c2') || lower.includes('beacon') || lower.includes('callback')) {
                return { phase: 'COMMAND & CONTROL', color: '#6366f1', icon: '@' };
              }
              // Default: Use orange for unclassified events (matches screenshot style)
              return { phase: 'INITIAL ACCESS', color: '#f59e0b', icon: '>' };
            };

            return (
              <div className={styles.attackTimeline}>
                {/* Header */}
                <div className={styles.attackTimelineHeader}>
                  <span className={styles.attackTimelineTitle}>
                    Attack Timeline
                  </span>
                  <span className={styles.attackTimelineDuration}>
                    Duration: {durationDays} day{durationDays !== 1 ? 's' : ''}
                  </span>
                </div>

                {/* Horizontal scrollable timeline */}
                <div className={styles.attackTimelineScroller}>
                  {events.map((evt, i) => {
                    const classification = classifyEvent(evt.label, evt.type);
                    const isRootCause = i === 0;
                    const isLastEvent = i === events.length - 1;
                    const isHovered = hoveredTimelineEvent === i;

                    // Generate detailed context for tooltip
                    const getEventContext = () => {
                      const phase = classification.phase;
                      const contexts = {
                        'Initial Access': 'This is where the attacker first gained entry to your environment. Focus remediation here to prevent similar future attacks.',
                        'Lateral Movement': 'The attacker spread from the initial foothold to other systems. Check for additional compromised hosts.',
                        'Persistence': 'The attacker established mechanisms to maintain access. Remove these to fully evict the threat.',
                        'Impact': 'This is where the attacker achieved their objective. Assess damage and prioritize recovery.',
                        'Detection': 'Security controls triggered on this activity. Review detection rules for tuning.',
                        'Command & Control': 'Communication channel between attacker and compromised systems. Block these connections.',
                        'Event': 'Activity observed during the incident timeline.'
                      };
                      return contexts[phase] || contexts['Event'];
                    };

                    // Calculate time delta from previous event
                    const getTimeDelta = () => {
                      if (i === 0) return null;
                      const prevTime = events[i - 1].timestamp.getTime();
                      const currTime = evt.timestamp.getTime();
                      const diffMs = currTime - prevTime;
                      const diffMins = Math.floor(diffMs / 60000);
                      const diffHours = Math.floor(diffMs / 3600000);
                      const diffDays = Math.floor(diffMs / 86400000);
                      if (diffDays > 0) return `+${diffDays}d ${diffHours % 24}h later`;
                      if (diffHours > 0) return `+${diffHours}h ${diffMins % 60}m later`;
                      if (diffMins > 0) return `+${diffMins}m later`;
                      return '+<1m later';
                    };

                    return (
                      <div
                        key={i}
                        className={styles.timelineEventWrap}
                      >
                        {/* Event card with phase styling - Root Cause gets subtle emphasis */}
                        <div
                          onMouseEnter={() => setHoveredTimelineEvent(i)}
                          onMouseLeave={() => setHoveredTimelineEvent(null)}
                          className={styles.timelineEventCard}
                          style={{
                            background: isHovered ? `${classification.color}20` : isRootCause ? `${classification.color}12` : `${classification.color}08`,
                            border: isRootCause ? `1px solid ${classification.color}60` : isHovered ? `1px solid ${classification.color}50` : `1px solid ${classification.color}25`,
                            boxShadow: isHovered ? `0 0 6px ${classification.color}15` : 'none'
                          }}
                        >
                          {/* Hover tooltip */}
                          {isHovered && (
                            <div className={styles.timelineTooltip} style={{ border: `1px solid ${classification.color}40` }}>
                              {/* Tooltip arrow */}
                              <div className={styles.timelineTooltipArrow} style={{ borderTop: `6px solid ${classification.color}40` }} />
                              {/* Time delta */}
                              {getTimeDelta() && (
                                <div className={styles.timelineTooltipDelta} style={{ color: classification.color }}>
                                  {getTimeDelta()}
                                </div>
                              )}
                              {/* Full timestamp */}
                              <div className={styles.timelineTooltipTimestamp}>
                                {evt.timestamp.toLocaleString('en-US', {
                                  weekday: 'short',
                                  month: 'short',
                                  day: 'numeric',
                                  year: 'numeric',
                                  hour: '2-digit',
                                  minute: '2-digit',
                                  second: '2-digit',
                                  hour12: false
                                })}
                              </div>
                              {/* Phase context */}
                              <div className={styles.timelineTooltipContext}>
                                {getEventContext()}
                              </div>
                              {/* Event type if available */}
                              {evt.type && evt.type !== 'event' && (
                                <div className={styles.timelineTooltipType}>
                                  Type: <span className={styles.timelineTooltipTypeValue}>{evt.type}</span>
                                </div>
                              )}
                            </div>
                          )}
                          {/* Root Cause badge for first event - subtle styling */}
                          {isRootCause && (
                            <div className={styles.rootCauseBadge} style={{ color: classification.color, border: `1px solid ${classification.color}50` }}>
                              Detection
                            </div>
                          )}
                          {/* Phase label */}
                          <div className={styles.timelinePhaseRow} style={{ marginTop: isRootCause ? '0.15rem' : 0 }}>
                            <span className={styles.timelinePhaseName} style={{ color: classification.color }}>
                              {classification.phase}
                            </span>
                          </div>
                          {/* Timestamp */}
                          <div className={styles.timelineTimestamp}>
                            {evt.timestamp.toLocaleDateString('en-US', { month: 'short', day: 'numeric' })}
                            {' '}
                            {evt.timestamp.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false })}
                          </div>
                          {/* Event description */}
                          <div className={isRootCause ? styles.timelineEventDescRoot : styles.timelineEventDesc}>
                            {evt.label}
                          </div>
                        </div>
                        {/* Arrow connector with propagation label */}
                        {!isLastEvent && (
                          <div className={styles.timelineArrowWrap}>
                            {isRootCause && events.length > 2 && (
                              <span className={styles.timelineSpreadLabel}>
                                spread
                              </span>
                            )}
                            <span className={styles.timelineArrowIcon} style={{ color: classification.color }}>
                              →
                            </span>
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>
            );
          })()}

          {/* ALL WIDGETS - Unified masonry layout */}
          {(() => {
            // Get all IOC-type widgets, but only keep ONE (prefer iocs_with_reputation)
            const allIocWidgets = insights.filter(w =>
              w.type !== 'timeline' && (
                w.type === 'iocs_with_reputation' ||
                w.type === 'malicious_iocs' ||
                w.title?.toLowerCase().includes('ioc') ||
                w.title?.toLowerCase().includes('indicator')
              )
            );
            // Dedupe: prefer iocs_with_reputation, then first available
            const bestIocWidget = allIocWidgets.find(w => w.type === 'iocs_with_reputation') ||
                                   allIocWidgets.find(w => w.type === 'malicious_iocs') ||
                                   allIocWidgets[0];

            // Get MITRE widgets
            const mitreWidgets = insights.filter(w =>
              w.type !== 'timeline' && (
                w.type === 'mitre' ||
                w.title?.toLowerCase().includes('mitre') ||
                w.title?.toLowerCase().includes('technique')
              )
            );
            // Prefer widget with type 'mitre' (our properly constructed one) over title-matched ones
            const bestMitreWidget = mitreWidgets.find(w => w.type === 'mitre') || mitreWidgets[0];

            // Get secondary widgets (everything else)
            const secondaryWidgets = insights.filter(w =>
              w.type !== 'timeline' &&
              w.type !== 'iocs_with_reputation' &&
              w.type !== 'malicious_iocs' &&
              w.type !== 'mitre' &&
              !w.title?.toLowerCase().includes('ioc') &&
              !w.title?.toLowerCase().includes('indicator') &&
              !w.title?.toLowerCase().includes('mitre') &&
              !w.title?.toLowerCase().includes('technique')
            );

            // Combine all widgets: IOCs first, then secondary, then MITRE (since it's tall)
            const allWidgets = [bestIocWidget, ...secondaryWidgets, bestMitreWidget].filter(Boolean);

            if (allWidgets.length === 0) return null;
            return (
              <div className="riggs-widget-grid">
                {allWidgets.map((widget, idx) => {
                  // Generate contextual interpretation based on widget type and content
                  const getInterpretation = () => {
                    const titleLower = (widget.title || '').toLowerCase();
                    const itemsText = widget.items?.map(i => (i.label || '').toLowerCase()).join(' ') || '';

                    if (titleLower.includes('ioc') || titleLower.includes('indicator')) {
                      if (widget.type === 'malicious_iocs') {
                        return 'Confirmed threat indicators';
                      }
                      return 'Artifacts for blocking and hunting';
                    }
                    if (titleLower.includes('mitre') || titleLower.includes('technique')) {
                      return 'Adversary behavior mapping';
                    }
                    if (titleLower.includes('affected') && titleLower.includes('host')) {
                      return widget.items?.length > 2 ? 'Multiple systems indicate lateral spread' : 'Systems requiring immediate attention';
                    }
                    if (titleLower.includes('finding') || titleLower.includes('key')) {
                      return 'Critical evidence for this verdict';
                    }
                    if (titleLower.includes('confidence')) {
                      return 'Analysis certainty factors';
                    }
                    if (titleLower.includes('entity') || titleLower.includes('entities')) {
                      return 'Involved assets and identities';
                    }
                    if (titleLower.includes('justification') || titleLower.includes('threat type')) {
                      return 'Classification reasoning';
                    }
                    if (titleLower.includes('change') || titleLower.includes('verdict')) {
                      return 'Counter-evidence considerations';
                    }
                    if (titleLower.includes('mode')) {
                      return 'Analysis depth setting';
                    }
                    return null;
                  };
                  const interpretation = getInterpretation();
                  // Determine if this is a "primary" widget (IOC or MITRE)
                  const isPrimary = widget.type === 'iocs_with_reputation' ||
                                    widget.type === 'malicious_iocs' ||
                                    widget.type === 'mitre' ||
                                    widget.title?.toLowerCase().includes('ioc') ||
                                    widget.title?.toLowerCase().includes('mitre');

                  return (
                    <div
                      key={`widget-${idx}`}
                      className={`riggs-widget${widget.fullWidth ? ' riggs-widget--full-width' : ''}`}
                    >
                      <div className="riggs-widget__header">
                        <span className="riggs-widget__title">
                          {widget.title}
                        </span>
                        <span className="riggs-widget__count">{widget.items?.length || 0}</span>
                      </div>
                      {interpretation && (
                        <div className="riggs-widget__interpretation">
                          {interpretation}
                        </div>
                      )}
                      {widget.type === 'iocs_with_reputation' || widget.type === 'malicious_iocs' ? (
                        <div className={styles.iocList}>
                          {(() => {
                            // Helper to derive reputation from item
                            const deriveReputation = (item) => {
                              const v = (item.verdict || item.reputation || '').toLowerCase();
                              if (v === 'malicious' || v === 'bad' || v === 'dangerous') return 'malicious';
                              if (v === 'suspicious' || v === 'medium' || v === 'risky') return 'suspicious';
                              if (v === 'clean' || v === 'safe' || v === 'benign' || v === 'good') return 'clean';

                              const enrichment = item.enrichment;
                              if (enrichment) {
                                let vtData, abuseData, otxData;
                                if (Array.isArray(enrichment)) {
                                  vtData = enrichment.find(e => e.provider === 'virustotal' || e.source === 'virustotal');
                                  abuseData = enrichment.find(e => e.provider === 'abuseipdb' || e.source === 'abuseipdb');
                                  otxData = enrichment.find(e => e.provider === 'otx' || e.source === 'otx');
                                } else if (enrichment.virustotal || enrichment.vt || enrichment.abuseipdb || enrichment.otx) {
                                  vtData = enrichment.virustotal || enrichment.vt;
                                  abuseData = enrichment.abuseipdb || enrichment.abuse;
                                  otxData = enrichment.otx || enrichment.alienvault;
                                } else {
                                  if (enrichment.malicious !== undefined || enrichment.positives !== undefined) vtData = enrichment;
                                  if (enrichment.confidence !== undefined || enrichment.abuseConfidenceScore !== undefined) abuseData = enrichment;
                                  if (enrichment.pulses !== undefined || enrichment.pulse_count !== undefined) otxData = enrichment;
                                }
                                const vtMalicious = vtData?.malicious || vtData?.positives || 0;
                                const vtTotal = vtData?.total || 0;
                                const abuseConfidence = abuseData?.confidence || abuseData?.abuseConfidenceScore || 0;
                                const otxPulses = otxData?.pulses || otxData?.pulse_count || 0;
                                if (vtMalicious >= 3) return 'malicious';
                                if (vtMalicious > 0 || abuseConfidence > 50 || otxPulses > 0) return 'suspicious';
                                if (vtTotal > 0) return 'clean';
                              }
                              return 'unknown';
                            };

                            // Sort items by verdict priority: malicious > suspicious > clean > unknown
                            const getVerdictPriority = (item) => {
                              const rep = deriveReputation(item);
                              if (rep === 'malicious') return 0;
                              if (rep === 'suspicious') return 1;
                              if (rep === 'clean') return 2;
                              return 3;
                            };
                            const sortedItems = [...widget.items].sort((a, b) => getVerdictPriority(a) - getVerdictPriority(b));

                            return sortedItems.map((item, i) => {
                              const reputation = deriveReputation(item);
                              const isMalicious = reputation === 'malicious';
                              const isSuspicious = reputation === 'suspicious';
                              const isClean = reputation === 'clean';

                              // Get enrichment summary for tooltip
                              const getEnrichmentSummary = () => {
                                const e = item.enrichment;
                                if (!e) return null;
                                const parts = [];
                                // Extract VT data
                                let vtMal = 0, vtTotal = 0;
                                if (Array.isArray(e)) {
                                  const vt = e.find(x => x.provider === 'virustotal' || x.source === 'virustotal');
                                  vtMal = vt?.malicious || vt?.positives || 0;
                                  vtTotal = vt?.total || 0;
                                } else {
                                  vtMal = e.malicious || e.positives || e.vt_malicious || 0;
                                  vtTotal = e.total || e.vt_total || 0;
                                }
                                if (vtTotal > 0) parts.push(`VT: ${vtMal}/${vtTotal}`);
                                // Abuse score
                                let abuseScore = 0;
                                if (Array.isArray(e)) {
                                  const abuse = e.find(x => x.provider === 'abuseipdb' || x.source === 'abuseipdb');
                                  abuseScore = abuse?.confidence || abuse?.abuseConfidenceScore || 0;
                                } else {
                                  abuseScore = e.confidence || e.abuseConfidenceScore || e.abuse_confidence || 0;
                                }
                                if (abuseScore > 0) parts.push(`Abuse: ${abuseScore}%`);
                                return parts.length > 0 ? parts.join(' | ') : null;
                              };
                              const enrichmentSummary = getEnrichmentSummary();

                              return (
                                <div key={i} className="riggs-ioc" data-verdict={reputation}>
                                  {/* Type badge */}
                                  <span className="riggs-ioc__type">
                                    {item.type}
                                  </span>
                                  {/* IOC value with hover context */}
                                  <HoverContextMenu
                                    type="ioc"
                                    data={{
                                      value: item.label,
                                      type: item.type,
                                      reputation: reputation,
                                      enrichment: item.enrichment || null
                                    }}
                                  >
                                    <span className="riggs-ioc__value">
                                      {item.label}
                                    </span>
                                  </HoverContextMenu>
                                  {/* Enrichment summary */}
                                  {enrichmentSummary && (
                                    <span className="riggs-ioc__enrichment">
                                      {enrichmentSummary}
                                    </span>
                                  )}
                                  {/* Verdict badge */}
                                  <span className="riggs-ioc__verdict" data-verdict={reputation}>
                                    {isMalicious ? 'MALICIOUS' :
                                     isSuspicious ? 'SUSPICIOUS' :
                                     isClean ? 'CLEAN' :
                                     'UNKNOWN'}
                                  </span>
                                </div>
                              );
                            });
                          })()}
                        </div>
                      ) : widget.type === 'mitre' ? (
                        <div className={styles.mitreList}>
                          {widget.items.map((item, i) => {
                            const techId = item.techId;
                            const techName = item.label;
                            const tactic = item.tactic;
                            const description = item.description || item.relevance || techName;

                            return (
                              <HoverContextMenu
                                key={i}
                                type="mitre"
                                data={{
                                  technique_id: techId,
                                  technique_name: techName,
                                  tactic: tactic,
                                  description: description
                                }}
                              >
                                <div className="riggs-mitre">
                                  <div className="riggs-mitre__header">
                                    <span className="riggs-mitre__id">
                                      {techId || 'TXXXX'}
                                    </span>
                                    {tactic && (
                                      <span className="riggs-mitre__tactic">
                                        {tactic}
                                      </span>
                                    )}
                                  </div>
                                  <div className="riggs-mitre__name">
                                    {description}
                                  </div>
                                </div>
                              </HoverContextMenu>
                            );
                          })}
                        </div>
                      ) : (widget.title || '').toLowerCase().includes('finding') || (widget.title || '').toLowerCase().includes('key') ? (
                        // Key Findings - Enhanced with severity badges
                        <div className={styles.findingsList}>
                          {(widget.items || []).slice(0, 8).map((item, i) => {
                            // Derive severity from finding text
                            const findingText = (item.label || '').toLowerCase();
                            let severity = 'info';
                            if (findingText.includes('malicious') || findingText.includes('critical') || findingText.includes('exploit') || findingText.includes('breach') || findingText.includes('compromised')) {
                              severity = 'critical';
                            } else if (findingText.includes('suspicious') || findingText.includes('detected') || findingText.includes('unauthorized') || findingText.includes('abnormal')) {
                              severity = 'high';
                            } else if (findingText.includes('potential') || findingText.includes('possible') || findingText.includes('may') || findingText.includes('warning')) {
                              severity = 'medium';
                            }

                            const severityColors = {
                              critical: { bg: 'rgba(239, 68, 68, 0.1)', border: 'rgba(239, 68, 68, 0.25)', badge: '#ef4444', label: 'CRIT' },
                              high: { bg: 'rgba(249, 115, 22, 0.1)', border: 'rgba(249, 115, 22, 0.25)', badge: '#f97316', label: 'HIGH' },
                              medium: { bg: 'rgba(234, 179, 8, 0.08)', border: 'rgba(234, 179, 8, 0.2)', badge: '#eab308', label: 'MED' },
                              info: { bg: 'rgba(100, 116, 139, 0.08)', border: 'rgba(100, 116, 139, 0.15)', badge: '#64748b', label: 'INFO' }
                            };
                            const colors = severityColors[severity];

                            return (
                              <div key={i} className={`riggs-finding riggs-finding--${severity}`}>
                                <span className="riggs-finding__badge" style={{
                                  background: `${colors.badge}25`,
                                  color: colors.badge
                                }}>
                                  {colors.label}
                                </span>
                                <span className="riggs-finding__text">
                                  {item.label}
                                </span>
                              </div>
                            );
                          })}
                        </div>
                      ) : (
                        // Default generic widget rendering
                        <div className={styles.genericItemList}>
                          {(widget.items || []).slice(0, 8).map((item, i) => (
                            <div key={i} className={styles.genericItem}>
                              <span className={styles.genericItemDot}>•</span>
                              <span className={styles.genericItemText}>{item.label}</span>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            );
          })()}
        </>
      )}
    </div>
  );
}

// ============================================================================
// ACTIONS PANEL - Disposition & State Controls
// ============================================================================

/**
 * Slim inline controls for analyst classification (disposition + assignee).
 * Sits in the top action bar between the state pill and the lifecycle buttons.
 * Same visual language as the right-side action buttons so the bar reads as
 * one row instead of two zones.
 */
function ClassificationControls({ investigation, onUpdate }) {
  const [saving, setSaving] = useState(false);
  const [openMenu, setOpenMenu] = useState(null); // 'disp' | 'priority' | 'severity' | 'assign' | null

  const dispositions = [
    { value: 'TRUE_POSITIVE',  label: 'True Positive',  color: '#ef4444' },
    { value: 'FALSE_POSITIVE', label: 'False Positive', color: '#22c55e' },
    { value: 'BENIGN',         label: 'Benign',         color: '#22c55e' },
    { value: 'SUSPICIOUS',     label: 'Suspicious',     color: '#f59e0b' },
    { value: 'UNKNOWN',        label: 'Unknown',        color: '#6b7280' },
  ];

  const priorities = [
    // Priority value (P1..P4) is self-evident; no dot needed.
    { value: 'P1', label: 'P1 — Critical' },
    { value: 'P2', label: 'P2 — High'     },
    { value: 'P3', label: 'P3 — Medium'   },
    { value: 'P4', label: 'P4 — Low'      },
  ];

  const severities = [
    { value: 'critical', label: 'Critical', color: '#ef4444' },
    { value: 'high',     label: 'High',     color: '#f97316' },
    { value: 'medium',   label: 'Medium',   color: '#fbbf24' },
    { value: 'low',      label: 'Low',      color: '#94a3b8' },
  ];

  // Real users + teams fetched from backend
  const [users, setUsers] = useState([]);
  const [teams, setTeams] = useState([]);
  const [assigneesLoading, setAssigneesLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const [uRes, tRes] = await Promise.all([
          authFetch(`${API_BASE_URL}/api/v1/users`),
          authFetch(`${API_BASE_URL}/api/v1/teams`),
        ]);
        if (cancelled) return;
        if (uRes.ok) {
          const u = await uRes.json();
          // /api/v1/users returns a flat array of {username, role, full_name, disabled}
          setUsers(Array.isArray(u) ? u : (u.users || []));
        }
        if (tRes.ok) {
          const t = await tRes.json();
          // /api/v1/teams returns { teams: [...] }
          setTeams(Array.isArray(t.teams) ? t.teams : (Array.isArray(t) ? t : []));
        }
      } catch {
        /* leave lists empty */
      } finally {
        if (!cancelled) setAssigneesLoading(false);
      }
    })();
    return () => { cancelled = true; };
  }, []);

  const assignees = [
    { value: null, label: 'Unassigned', group: 'none' },
    ...teams.map(t => ({
      value: t.team_id || t.id,
      label: t.name,
      group: 'team',
    })),
    ...users.map(u => ({
      value: u.username,
      label: u.full_name || u.username,
      sublabel: u.username,
      role: u.role,
      group: 'user',
    })),
  ];

  const currentDisp     = dispositions.find(d => d.value === investigation?.disposition) || dispositions[4];
  const currentPriority = priorities.find(p => p.value === investigation?.priority) || priorities[2];
  const currentSeverity = severities.find(s => s.value === investigation?.severity) || severities[2];

  // Backend stores this on `owner` (with `assigned_to` as a write-time alias);
  // GET responses can use either name depending on the route, so normalize.
  const assignedToRaw = investigation?.assigned_to ?? investigation?.owner ?? null;

  // Resolve current assignee with race-tolerance:
  //   1. null/undefined                 -> "Unassigned"
  //   2. matches a fetched user/team    -> show their full-name label
  //   3. set, but lists still loading   -> show raw id; upgrades when fetch lands
  //   4. set, lists loaded, no match    -> show raw id (orphaned ref to a
  //      deleted user/team); preserve the value so the chip doesn't flash
  //      "Unassigned" and silently lose the assignment on next save.
  const currentAssignee =
    assignees.find(a => a.value === assignedToRaw) ||
    (assignedToRaw
      ? {
          value: assignedToRaw,
          label: assignedToRaw,
          group: 'unknown',
          pending: assigneesLoading,
        }
      : assignees[0]);

  const patch = async (body) => {
    setSaving(true);
    setOpenMenu(null);
    try {
      const res = await fetch(
        `${API_BASE_URL}/api/v1/investigations/${investigation.investigation_id || investigation.id}`,
        {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
          body: JSON.stringify(body),
        }
      );
      if (res.ok && onUpdate) {
        onUpdate({ ...investigation, ...body });
      }
    } catch {} finally {
      setSaving(false);
    }
  };

  // Close menu on outside click
  useEffect(() => {
    if (!openMenu) return;
    const handler = (e) => {
      if (!e.target.closest('[data-classification-control]')) setOpenMenu(null);
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, [openMenu]);

  return (
    <>
      <Facet
        label="Disposition"
        value={currentDisp.label}
        color={currentDisp.color}
        active={openMenu === 'disp'}
        onToggle={() => setOpenMenu(openMenu === 'disp' ? null : 'disp')}
        disabled={saving}
        showDot
      >
        {dispositions.map(d => (
          <FacetMenuItem
            key={d.value}
            color={d.color}
            current={d.value === currentDisp.value}
            onPick={() => patch({ disposition: d.value })}
            label={d.label}
            showDot
          />
        ))}
      </Facet>

      <Facet
        label="Priority"
        value={currentPriority.value}
        active={openMenu === 'priority'}
        onToggle={() => setOpenMenu(openMenu === 'priority' ? null : 'priority')}
        disabled={saving}
      >
        {priorities.map(p => (
          <FacetMenuItem
            key={p.value}
            current={p.value === currentPriority.value}
            onPick={() => patch({ priority: p.value })}
            label={p.label}
          />
        ))}
      </Facet>

      <Facet
        label="Severity"
        value={currentSeverity.label}
        color={currentSeverity.color}
        active={openMenu === 'severity'}
        onToggle={() => setOpenMenu(openMenu === 'severity' ? null : 'severity')}
        disabled={saving}
      >
        {severities.map(s => (
          <FacetMenuItem
            key={s.value}
            color={s.color}
            current={s.value === currentSeverity.value}
            onPick={() => patch({ severity: s.value })}
            label={s.label}
          />
        ))}
      </Facet>

      <Facet
        label="Assignee"
        value={
          currentAssignee.pending ? (
            <span style={{ fontStyle: 'italic', opacity: 0.75 }}>{currentAssignee.label}</span>
          ) : currentAssignee.label
        }
        active={openMenu === 'assign'}
        onToggle={() => setOpenMenu(openMenu === 'assign' ? null : 'assign')}
        disabled={saving}
        icon={
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/>
            <circle cx="12" cy="7" r="4"/>
          </svg>
        }
        menuMinWidth={220}
      >
        {assigneesLoading ? (
          <div style={{ padding: '0.75rem 0.65rem', fontSize: '0.85rem', color: 'var(--text-muted)' }}>
            Loading…
          </div>
        ) : (
          <>
            {assignees.filter(a => a.group === 'none').map(a => (
              <FacetMenuItem
                key="unassigned"
                current={a.value === currentAssignee.value}
                onPick={() => patch({ assigned_to: a.value })}
                label={a.label}
                muted
              />
            ))}
            {teams.length > 0 && (
              <>
                <FacetMenuSection title="Teams" />
                {assignees.filter(a => a.group === 'team').map(a => (
                  <FacetMenuItem
                    key={`team-${a.value}`}
                    current={a.value === currentAssignee.value}
                    onPick={() => patch({ assigned_to: a.value })}
                    label={a.label}
                  />
                ))}
              </>
            )}
            {users.length > 0 && (
              <>
                <FacetMenuSection title="Users" />
                {assignees.filter(a => a.group === 'user').map(a => (
                  <FacetMenuItem
                    key={`user-${a.value}`}
                    current={a.value === currentAssignee.value}
                    onPick={() => patch({ assigned_to: a.value })}
                    label={a.label}
                    sublabel={a.sublabel}
                  />
                ))}
              </>
            )}
            {users.length === 0 && teams.length === 0 && (
              <div style={{ padding: '0.75rem 0.65rem', fontSize: '0.85rem', color: 'var(--text-muted)' }}>
                No users or teams found.
              </div>
            )}
          </>
        )}
      </Facet>

      <style>{`
        /* Restrained palette — neutral chips with semantic dots, like Linear/Tines.
           Color only carries meaning (severity, status), not decoration. */
        :root {
          --case-chip-h: 30px;
          --case-chip-pad-y: 0.35rem;
          --case-chip-pad-x: 0.7rem;
          --case-chip-radius: 6px;
          --case-chip-fs: 0.82rem;
          --case-chip-fw: 500;
          --case-chip-bg: rgba(255,255,255,0.03);
          --case-chip-border: rgba(148,163,184,0.18);
          --case-chip-bg-hover: rgba(255,255,255,0.07);
          --case-chip-border-hover: rgba(148,163,184,0.3);
        }
        .case-facet-row {
          display: flex;
          flex-wrap: wrap;
          gap: 0.5rem;
          align-items: flex-end;
          padding: 0.9rem 1.5rem;
          border-bottom: 1px solid rgba(148,163,184,0.1);
        }
        /* Whitespace-based group separators (replaces visible dividers).
           Bigger gap between zones, tighter within. */
        .case-facet-divider {
          width: 1.5rem;
          flex-shrink: 0;
          align-self: stretch;
        }
        .case-facet-row .case-facet-rest {
          display: inline-flex;
          align-items: flex-end;
          gap: 0.4rem;
          margin-left: auto;
          flex-wrap: wrap;
        }

        /* All chips share this base */
        .case-chip {
          display: inline-flex;
          align-items: center;
          gap: 0.4rem;
          height: var(--case-chip-h);
          padding: var(--case-chip-pad-y) var(--case-chip-pad-x);
          font-size: var(--case-chip-fs);
          font-weight: var(--case-chip-fw);
          border-radius: var(--case-chip-radius);
          background: var(--case-chip-bg);
          border: 1px solid var(--case-chip-border);
          color: var(--text-primary, #e2e8f0);
          line-height: 1;
          white-space: nowrap;
          box-sizing: border-box;
          transition: background 120ms, border-color 120ms;
        }

        /* State pill — the one quietly emphasized chip on the left */
        .case-facet-state-pill {
          font-size: 0.7rem;
          font-weight: 700;
          letter-spacing: 0.05em;
          text-transform: uppercase;
          color: #fbbf24;
          border-color: rgba(251,191,36,0.35);
          background: rgba(251,191,36,0.08);
        }
        .case-facet-id-chip {
          font-family: var(--font-mono, ui-monospace, monospace);
          font-weight: 500;
          font-size: 0.76rem;
          color: var(--text-muted);
        }

        /* Lifecycle action buttons — neutral by default. Run Analysis is the
           single accent on the right; the rest use subtle role-shaded hover. */
        .case-action-btn {
          display: inline-flex;
          align-items: center;
          justify-content: center;
          height: var(--case-chip-h);
          padding: var(--case-chip-pad-y) 0.85rem;
          font-size: var(--case-chip-fs);
          font-weight: 600;
          border-radius: var(--case-chip-radius);
          cursor: pointer;
          border: 1px solid var(--case-chip-border);
          background: var(--case-chip-bg);
          color: var(--text-primary, #e2e8f0);
          transition: all 120ms;
          white-space: nowrap;
          line-height: 1;
          box-sizing: border-box;
        }
        .case-action-btn:hover:not(:disabled) {
          background: var(--case-chip-bg-hover);
          border-color: var(--case-chip-border-hover);
        }
        .case-action-btn:disabled { cursor: not-allowed; opacity: 0.6; }
        .case-action-btn--primary {
          background: #3b82f6;
          color: #fff;
          border-color: #3b82f6;
        }
        .case-action-btn--primary:hover:not(:disabled) {
          background: #2563eb;
          border-color: #2563eb;
        }
        /* Subtle role tints on hover only — keeps row neutral until intent */
        .case-action-btn--danger:hover:not(:disabled) {
          color: #ef4444;
          border-color: rgba(239,68,68,0.5);
          background: rgba(239,68,68,0.08);
        }
        .case-action-btn--success:hover:not(:disabled) {
          color: #22c55e;
          border-color: rgba(34,197,94,0.5);
          background: rgba(34,197,94,0.08);
        }

        /* Faceted chip with a tiny label above */
        .case-facet {
          position: relative;
          display: inline-flex;
          flex-direction: column;
          gap: 0.3rem;
        }
        .case-facet-label {
          font-size: 0.62rem;
          font-weight: 700;
          color: var(--text-muted, #94a3b8);
          text-transform: uppercase;
          letter-spacing: 0.08em;
          padding-left: 0.15rem;
        }
        .case-facet-btn {
          display: inline-flex;
          align-items: center;
          gap: 0.45rem;
          height: var(--case-chip-h);
          padding: var(--case-chip-pad-y) var(--case-chip-pad-x);
          font-size: var(--case-chip-fs);
          font-weight: var(--case-chip-fw);
          border-radius: var(--case-chip-radius);
          background: var(--case-chip-bg);
          border: 1px solid var(--case-chip-border);
          color: var(--text-primary, #e2e8f0);
          cursor: pointer;
          white-space: nowrap;
          transition: background 120ms, border-color 120ms;
          line-height: 1;
          box-sizing: border-box;
        }
        .case-facet-btn:hover:not(:disabled) {
          background: var(--case-chip-bg-hover);
          border-color: var(--case-chip-border-hover);
        }
        .case-facet-btn:disabled {
          cursor: not-allowed;
          opacity: 0.6;
        }
        .case-facet-btn-arrow {
          font-size: 0.65rem;
          opacity: 0.5;
          margin-left: 0.05rem;
        }
        .case-facet-dot {
          width: 8px; height: 8px; border-radius: 50%;
          flex-shrink: 0;
        }
        .case-facet-menu {
          position: absolute;
          top: calc(100% + 4px);
          left: 0;
          background: var(--bg-secondary, #1a1f2e);
          border: 1px solid rgba(148,163,184,0.2);
          border-radius: 8px;
          box-shadow: 0 12px 32px rgba(0,0,0,0.5);
          padding: 0.35rem;
          z-index: 100;
          min-width: 200px;
        }
        .case-facet-menu-item {
          width: 100%;
          text-align: left;
          padding: 0.5rem 0.65rem;
          background: transparent;
          border: none;
          border-radius: 5px;
          cursor: pointer;
          font-size: 0.85rem;
          display: flex;
          align-items: center;
          gap: 0.5rem;
        }
        .case-facet-menu-item:hover {
          background: rgba(148,163,184,0.1);
        }
        .case-facet-menu-section {
          font-size: 0.65rem;
          color: var(--text-muted);
          text-transform: uppercase;
          letter-spacing: 0.06em;
          padding: 0.5rem 0.65rem 0.2rem;
          font-weight: 700;
        }
      `}</style>
    </>
  );
}

/* ── Facet primitives used by ClassificationControls ────────────────────────── */
function Facet({ label, value, color, active, onToggle, disabled, icon, menuMinWidth, children }) {
  // Neutral chip + colored status dot. The button stays one of two background
  // tones across the whole row, and color only signals semantic state via the
  // small dot (Linear / Tines pattern).
  return (
    <div className="case-facet" data-classification-control>
      <span className="case-facet-label">{label}</span>
      <button className="case-facet-btn" disabled={disabled} onClick={onToggle}>
        {color && <span className="case-facet-dot" style={{ background: color }} />}
        {icon}
        <span>{value}</span>
        <span className="case-facet-btn-arrow">▼</span>
      </button>
      {active && (
        <div className="case-facet-menu" style={menuMinWidth ? { minWidth: menuMinWidth } : undefined}>
          {children}
        </div>
      )}
    </div>
  );
}

function FacetMenuItem({ label, sublabel, color, current, onPick, muted }) {
  return (
    <button
      className="case-facet-menu-item"
      onClick={onPick}
      style={{
        color: muted ? 'var(--text-muted)' : 'var(--text-primary)',
        fontWeight: current ? 600 : 500,
      }}
    >
      {color
        ? <span className="case-facet-dot" style={{ background: color }} />
        : <span style={{ width: 8, height: 8 }} />
      }
      <span style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'flex-start', minWidth: 0 }}>
        <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: '100%' }}>
          {label}
        </span>
        {sublabel && sublabel !== label && (
          <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', fontWeight: 400, marginTop: 1 }}>
            {sublabel}
          </span>
        )}
      </span>
      {current && <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>✓</span>}
    </button>
  );
}

function FacetMenuSection({ title }) {
  return <div className="case-facet-menu-section">{title}</div>;
}

const STATE_COLORS = {
  NEW:             '#60a5fa',  // blue
  IN_PROGRESS:     '#fbbf24',  // amber
  AWAITING_HUMAN:  '#fbbf24',  // amber
  NEEDS_REVIEW:    '#fbbf24',  // amber
  ANALYZING:       '#a78bfa',  // violet (in-flight)
  ESCALATED:       '#ef4444',  // red
  CLOSED:          '#94a3b8',  // gray
  RESOLVED:        '#22c55e',  // green
};

function StatePill({ state }) {
  const value = (state || 'NEW').toUpperCase();
  const color = STATE_COLORS[value] || '#94a3b8';
  return (
    <span
      className="case-chip case-facet-state-pill"
      style={{
        color,
        borderColor: `${color}40`,
        background: `${color}10`,
      }}
    >
      {value.replace(/_/g, ' ')}
    </span>
  );
}

function ActionsPanel({ investigation, onUpdate }) {
  const [saving, setSaving] = useState(false);
  const [showDispositionMenu, setShowDispositionMenu] = useState(false);
  const [showStateMenu, setShowStateMenu] = useState(false);
  const [showAssignMenu, setShowAssignMenu] = useState(false);
  const [localInvestigation, setLocalInvestigation] = useState(investigation);

  // Update local state when prop changes
  useEffect(() => {
    setLocalInvestigation(investigation);
  }, [investigation]);

  const dispositions = [
    { value: 'TRUE_POSITIVE', label: 'True Positive', color: '#ef4444', description: 'Confirmed security incident' },
    { value: 'FALSE_POSITIVE', label: 'False Positive', color: '#22c55e', description: 'Not a real threat' },
    { value: 'BENIGN', label: 'Benign', color: '#22c55e', description: 'Expected/authorized activity' },
    { value: 'SUSPICIOUS', label: 'Suspicious', color: '#f59e0b', description: 'Needs further investigation' },
    { value: 'UNKNOWN', label: 'Unknown', color: '#6b7280', description: 'Cannot determine' },
  ];

  const states = [
    { value: 'NEW', label: 'New', color: '#3b82f6' },
    { value: 'IN_PROGRESS', label: 'In Progress', color: '#f59e0b' },
    { value: 'AWAITING_HUMAN', label: 'Awaiting Human', color: '#eab308' },
    { value: 'ESCALATED', label: 'Escalated', color: '#ef4444' },
    { value: 'CLOSED', label: 'Closed', color: '#6b7280' },
    { value: 'RESOLVED', label: 'Resolved', color: '#22c55e' },
  ];

  // Sample users/teams - in production this would come from an API
  const assignees = [
    { value: null, label: 'Unassigned', type: 'none' },
    { value: 'tier1-team', label: 'Tier 1 Team', type: 'team', color: '#3b82f6' },
    { value: 'tier2-team', label: 'Tier 2 Team', type: 'team', color: '#8b5cf6' },
    { value: 'incident-response', label: 'Incident Response', type: 'team', color: '#ef4444' },
    { value: 'admin', label: 'Admin', type: 'user', color: '#22c55e' },
    { value: 'analyst1', label: 'John Smith', type: 'user', color: '#06b6d4' },
    { value: 'analyst2', label: 'Jane Doe', type: 'user', color: '#f59e0b' },
  ];

  const handleDispositionChange = async (disposition) => {
    setSaving(true);
    setShowDispositionMenu(false);
    telemetry.track('investigation', 'investigation.verdict_set', { verdict: disposition, confidence: investigation?.confidence_score, time_to_decision_ms: Date.now() - (window._investigationOpenTime || Date.now()) });
    try {
      const response = await fetch(
        `${API_BASE_URL}/api/v1/investigations/${investigation.investigation_id || investigation.id}`,
        {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
          body: JSON.stringify({ disposition })
        }
      );
      if (response.ok) {
        setLocalInvestigation(prev => ({ ...prev, disposition }));
        if (onUpdate) onUpdate({ ...localInvestigation, disposition });
      }
    } catch (err) {
    }
    setSaving(false);
  };

  const handleStateChange = async (state) => {
    setSaving(true);
    setShowStateMenu(false);
    try {
      const response = await fetch(
        `${API_BASE_URL}/api/v1/investigations/${investigation.investigation_id || investigation.id}`,
        {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
          body: JSON.stringify({ state })
        }
      );
      if (response.ok) {
        setLocalInvestigation(prev => ({ ...prev, state }));
        if (onUpdate) onUpdate({ ...localInvestigation, state });
      }
    } catch (err) {
    }
    setSaving(false);
  };

  const handleAssignChange = async (assignee) => {
    setSaving(true);
    setShowAssignMenu(false);
    try {
      const response = await fetch(
        `${API_BASE_URL}/api/v1/investigations/${investigation.investigation_id || investigation.id}`,
        {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
          body: JSON.stringify({ assigned_to: assignee.value, assigned_type: assignee.type })
        }
      );
      if (response.ok) {
        setLocalInvestigation(prev => ({ ...prev, assigned_to: assignee.value, assigned_type: assignee.type }));
        if (onUpdate) onUpdate({ ...localInvestigation, assigned_to: assignee.value, assigned_type: assignee.type });
      }
    } catch (err) {
    }
    setSaving(false);
  };

  const currentDisposition = dispositions.find(d => d.value === localInvestigation.disposition) || dispositions[4];
  const currentState = states.find(s => s.value === localInvestigation.state) || states[0];
  const currentAssignee = assignees.find(a => a.value === localInvestigation.assigned_to) || assignees[0];

  return (
    <div className={styles.actionsPanel}>
      <span className={styles.actionsPanelLabel}>
        Actions
      </span>

      {/* Disposition Dropdown */}
      <div className={styles.dropdownRelative}>
        <button
          onClick={() => { setShowDispositionMenu(!showDispositionMenu); setShowStateMenu(false); }}
          disabled={saving}
          className={styles.dropdownBtn}
          style={{
            background: `${currentDisposition.color}20`,
            border: `1px solid ${currentDisposition.color}40`,
            color: currentDisposition.color
          }}
        >
          <span>Disposition: {currentDisposition.label}</span>
          <span className={styles.dropdownArrow}>▼</span>
        </button>
        {showDispositionMenu && (
          <div className={styles.dropdownMenuWide}>
            {dispositions.map(d => (
              <button
                key={d.value}
                onClick={() => handleDispositionChange(d.value)}
                className={d.value === investigation.disposition ? styles.dropdownItemActive : styles.dropdownItem}
              >
                <div className={styles.dropdownItemLabel} style={{ color: d.color }}>{d.label}</div>
                <div className={styles.dropdownItemDesc}>{d.description}</div>
              </button>
            ))}
          </div>
        )}
      </div>

      {/* State Dropdown */}
      <div className={styles.dropdownRelative}>
        <button
          onClick={() => { setShowStateMenu(!showStateMenu); setShowDispositionMenu(false); }}
          disabled={saving}
          className={styles.dropdownBtn}
          style={{
            background: `${currentState.color}20`,
            border: `1px solid ${currentState.color}40`,
            color: currentState.color
          }}
        >
          <span>State: {currentState.label}</span>
          <span className={styles.dropdownArrow}>▼</span>
        </button>
        {showStateMenu && (
          <div className={styles.dropdownMenuMedium}>
            {states.map(s => (
              <button
                key={s.value}
                onClick={() => handleStateChange(s.value)}
                className={`${s.value === investigation.state ? styles.dropdownItemActive : styles.dropdownItem} ${styles.stateDropdownItem}`}
                style={{ color: s.color }}
              >
                {s.label}
              </button>
            ))}
          </div>
        )}
      </div>

      {/* Assignment Dropdown */}
      <div className={styles.assignDropdownAutoRight}>
        <button
          onClick={() => { setShowAssignMenu(!showAssignMenu); setShowDispositionMenu(false); setShowStateMenu(false); }}
          disabled={saving}
          className={styles.dropdownBtn}
          style={{
            background: currentAssignee.color ? `${currentAssignee.color}20` : 'rgba(107, 114, 128, 0.2)',
            border: `1px solid ${currentAssignee.color || '#6b7280'}40`,
            color: currentAssignee.color || '#6b7280'
          }}
        >
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/>
            <circle cx="12" cy="7" r="4"/>
          </svg>
          <span>{currentAssignee.label}</span>
          <span className={styles.dropdownArrow}>▼</span>
        </button>
        {showAssignMenu && (
          <div className={styles.dropdownMenuRight}>
            <div className={styles.assignToHeader}>
              Assign To
            </div>
            {assignees.filter(a => a.type === 'none').map(a => (
              <button
                key={a.value || 'unassigned'}
                onClick={() => handleAssignChange(a)}
                className={`${localInvestigation.assigned_to === a.value ? styles.dropdownItemActive : styles.dropdownItemFlex} ${styles.dropdownItemMuted}`}
              >
                {a.label}
              </button>
            ))}
            <div className={styles.dropdownSectionHeader}>
              Teams
            </div>
            {assignees.filter(a => a.type === 'team').map(a => (
              <button
                key={a.value}
                onClick={() => handleAssignChange(a)}
                className={localInvestigation.assigned_to === a.value ? styles.dropdownItemActive : styles.dropdownItemFlex}
                style={{ color: a.color }}
              >
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/>
                  <circle cx="9" cy="7" r="4"/>
                  <path d="M23 21v-2a4 4 0 0 0-3-3.87"/>
                  <path d="M16 3.13a4 4 0 0 1 0 7.75"/>
                </svg>
                {a.label}
              </button>
            ))}
            <div className={styles.dropdownSectionHeader}>
              Users
            </div>
            {assignees.filter(a => a.type === 'user').map(a => (
              <button
                key={a.value}
                onClick={() => handleAssignChange(a)}
                className={localInvestigation.assigned_to === a.value ? styles.dropdownItemActive : styles.dropdownItemFlex}
                style={{ color: a.color }}
              >
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/>
                  <circle cx="12" cy="7" r="4"/>
                </svg>
                {a.label}
              </button>
            ))}
          </div>
        )}
      </div>

    </div>
  );
}

function InvestigationWorkbenchV2() {
  const { id } = useParams();

  // State
  const [investigation, setInvestigation] = useState(null);
  const [alertData, setAlertData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [chatOpen, setChatOpen] = useState(true); // Default open for quick analyst access
  const [copied, setCopied] = useState(false);
  const [activeTab, setActiveTab] = useState('summary');
  const [linkedAlerts, setLinkedAlerts] = useState([]); // Correlated alerts with full data
  const [investigationEntities, setInvestigationEntities] = useState({}); // Entity risk scores
  const [licenseData, setLicenseData] = useState(null);
  const [deepDiveLoading, setDeepDiveLoading] = useState(false);
  const hasLoadedSecondary = useRef(false);
  const [deepDiveError, setDeepDiveError] = useState(null);
  const [correlationHistory, setCorrelationHistory] = useState([]);
  const [investigationSummary, setInvestigationSummary] = useState(null);
  const [attachmentCount, setAttachmentCount] = useState(0);
  const [reportModalOpen, setReportModalOpen] = useState(false);
  const [triageLoading, setTriageLoading] = useState(false);
  const [triageStatus, setTriageStatus] = useState(null); // null | 'running' | 'success' | 'error'
  const [triageMessage, setTriageMessage] = useState('');
  const [triageElapsed, setTriageElapsed] = useState(0);
  const [buildPlaybookState, setBuildPlaybookState] = useState({ loading: false, error: null });

  const handleBuildPlaybookFromAlert = async () => {
    const alertId = investigation?.alert_id || alertData?.alert_id || alertData?.id;
    if (!alertId) {
      setBuildPlaybookState({ loading: false, error: 'No alert attached to this investigation.' });
      return;
    }
    setBuildPlaybookState({ loading: true, error: null });
    try {
      const response = await fetch(
        `${API_BASE_URL}/api/v1/riggs/playbooks/build-from-alert`,
        {
          method: 'POST',
          headers: { ...getAuthHeaders(), 'Content-Type': 'application/json', 'X-CSRF-Token': getCsrfToken() },
          credentials: 'include',
          body: JSON.stringify({ alert_id: String(alertId), persist: true, use_llm: true }),
        }
      );
      if (!response.ok) {
        const detail = await response.text();
        throw new Error(`Build failed: ${response.status} ${detail.slice(0, 200)}`);
      }
      const data = await response.json();
      const editorUrl = data.editor_url || (data.playbook_id ? `/playbooks/${data.playbook_id}` : null);
      if (editorUrl) {
        window.location.href = editorUrl;
      }
    } catch (err) {
      console.error('Build playbook error:', err);
      setBuildPlaybookState({ loading: false, error: err.message || 'Failed to build playbook' });
    }
  };

  const handleManualTriage = async () => {
    if (!investigation?.investigation_id) return;
    setTriageLoading(true);
    setTriageStatus('running');
    setTriageMessage('Queuing analysis job...');
    setTriageElapsed(0);

    const startTime = Date.now();
    const elapsedTimer = setInterval(() => {
      setTriageElapsed(Math.floor((Date.now() - startTime) / 1000));
    }, 1000);

    try {
      const response = await fetch(
        `${API_BASE_URL}/api/v1/investigation-details/${investigation.investigation_id}/triage`,
        {
          method: 'POST',
          headers: { ...getAuthHeaders(), 'Content-Type': 'application/json', 'X-CSRF-Token': getCsrfToken() },
          credentials: 'include'
        }
      );
      if (!response.ok) {
        const errText = await response.text();
        setTriageStatus('error');
        setTriageMessage(`Failed: ${errText.substring(0, 200)}`);
        clearInterval(elapsedTimer);
        setTriageLoading(false);
        return;
      }

      setTriageMessage('Analysis running on backend. Auto-refreshing...');

      // Poll investigation every 5s, up to 90s, for updated data
      let polls = 0;
      const maxPolls = 18;
      const poll = async () => {
        polls += 1;
        try {
          await fetchInvestigation();
        } catch (e) {}
        if (polls >= maxPolls) {
          clearInterval(elapsedTimer);
          setTriageStatus('success');
          setTriageMessage('Analysis complete. Review updated cards.');
          setTriageLoading(false);
          setTimeout(() => setTriageStatus(null), 6000);
        } else {
          setTimeout(poll, 5000);
        }
      };
      setTimeout(poll, 5000);
    } catch (err) {
      clearInterval(elapsedTimer);
      setTriageStatus('error');
      setTriageMessage(`Error: ${err.message}`);
      setTriageLoading(false);
    }
  };

  // Fetch investigation data
  const fetchInvestigation = useCallback(async () => {
    try {
      const response = await fetch(
        `${API_BASE_URL}/api/v1/investigations/${id}`,
        { headers: getAuthHeaders() }
      );

      if (!response.ok) throw new Error(`HTTP ${response.status}`);

      const data = await response.json();
      setInvestigation(data);
      telemetry.track('investigation', 'investigation.open', { investigation_id: id, severity: data.severity });
      window._investigationOpenTime = Date.now();

      if (data.alert_id) {
        try {
          const alertResponse = await fetch(
            `${API_BASE_URL}/api/v1/alerts/${data.alert_id}`,
            { headers: getAuthHeaders() }
          );
          if (alertResponse.ok) {
            const primaryAlert = await alertResponse.json();
            setAlertData(primaryAlert);
          }
        } catch (alertErr) {
        }
      }

      setLoading(false);
    } catch (err) {
      setError(err.message);
      setLoading(false);
    }
  }, [id]);

  useEffect(() => {
    hasLoadedSecondary.current = false; // Reset when id changes
    fetchInvestigation();
  }, [fetchInvestigation]);

  // Fetch license tier (cached in sessionStorage)
  useEffect(() => {
    getLicenseTier().then(setLicenseData).catch(e => console.error('License tier error:', e));
  }, []);

  // Deep Dive handler
  const handleDeepDive = useCallback(async () => {
    if (!investigation) return;
    const invId = investigation.investigation_id || investigation.id;
    setDeepDiveLoading(true);
    setDeepDiveError(null);
    try {
      const csrfToken = getCsrfToken();
      const headers = { ...getAuthHeaders(), 'Content-Type': 'application/json' };
      if (csrfToken) headers['X-CSRF-Token'] = csrfToken;
      const res = await fetch(
        `${API_BASE_URL}/api/v1/investigations/${invId}/deep-dive`,
        { method: 'POST', headers, credentials: 'include' }
      );
      if (res.status === 403) {
        const err = await res.json();
        setDeepDiveError(err.detail?.message || 'Deep Dive requires a Pro or Enterprise plan.');
        return;
      }
      if (res.status === 429) {
        const err = await res.json();
        const detail = err.detail || {};
        if (detail.error === 'deep_dive_limit_exceeded') {
          setDeepDiveError(`Monthly Deep Dive limit reached (${detail.used}/${detail.limit}). Upgrade to Pro for unlimited Deep Dives.`);
        } else {
          setDeepDiveError(detail.message || 'Monthly AI token quota exceeded.');
        }
        refreshLicenseCache(); // Update the counter in the UI
        return;
      }
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const result = await res.json();
      // Refresh investigation to pick up stored deep dive results
      setInvestigation(prev => ({
        ...prev,
        investigation_data: {
          ...(prev?.investigation_data || {}),
          riggs_deep_analysis: result
        }
      }));
      refreshLicenseCache(); // Refresh usage counts
    } catch (err) {
      setDeepDiveError(err.message || 'Deep Dive analysis failed.');
    } finally {
      setDeepDiveLoading(false);
    }
  }, [investigation]);

  // Fetch linked alerts with correlation data
  const fetchLinkedAlerts = useCallback(async () => {
    try {
      // Try new investigation-details endpoint first
      const response = await fetch(
        `${API_BASE_URL}/api/v1/investigation-details/${id}/alerts?limit=100`,
        { headers: getAuthHeaders() }
      );

      if (response.ok) {
        const data = await response.json();
        if (data.items && data.items.length > 0) {
          setLinkedAlerts(data.items);
        }
      } else {
        // Fallback to legacy endpoint
        const legacyResponse = await fetch(
          `${API_BASE_URL}/api/v1/investigations/${id}/linked-alerts`,
          { headers: getAuthHeaders() }
        );
        if (legacyResponse.ok) {
          const legacyData = await legacyResponse.json();
          if (legacyData.alerts && legacyData.alerts.length > 0) {
            const alertsWithCorrelation = legacyData.alerts.map(a => ({
              ...a,
              correlation: { decision_type: 'legacy', reasons: [], matched_entities: [] }
            }));
            setLinkedAlerts(alertsWithCorrelation);
          }
        }
      }
    } catch (err) {
    }
  }, [id]);

  // Fetch investigation entities with risk scores
  const fetchInvestigationEntities = useCallback(async () => {
    try {
      const response = await fetch(
        `${API_BASE_URL}/api/v1/investigation-details/${id}/entities`,
        { headers: getAuthHeaders() }
      );

      if (response.ok) {
        const data = await response.json();
        setInvestigationEntities(data);
      }
    } catch (err) {
    }
  }, [id]);

  // Fetch correlation history for linked alerts
  const fetchCorrelationHistory = useCallback(async () => {
    try {
      const res = await fetch(
        `${API_BASE_URL}/api/v1/investigation-details/${id}/correlation-history`,
        { headers: getAuthHeaders() }
      );
      if (res.ok) {
        const data = await res.json();
        setCorrelationHistory(data.decisions || data.history || []);
      }
    } catch (err) { /* graceful degradation */ }
  }, [id]);

  // Fetch investigation summary metrics
  const fetchInvestigationSummary = useCallback(async () => {
    try {
      const res = await fetch(
        `${API_BASE_URL}/api/v1/investigation-details/${id}/summary`,
        { headers: getAuthHeaders() }
      );
      if (res.ok) {
        setInvestigationSummary(await res.json());
      }
    } catch (err) { /* graceful degradation */ }
  }, [id]);

  // Fetch attachment count for tab badge
  const fetchAttachmentCount = useCallback(async (alertId) => {
    if (!alertId) return;
    try {
      const res = await fetch(
        `${API_BASE_URL}/api/v1/attachments/alert/${alertId}`,
        { headers: getAuthHeaders() }
      );
      if (res.ok) {
        const data = await res.json();
        setAttachmentCount(data.total_count || 0);
      }
    } catch (err) { /* graceful degradation */ }
  }, []);

  // Fetch linked alerts, entities, correlation, summary when investigation loads (once per id)
  useEffect(() => {
    if (investigation && !hasLoadedSecondary.current) {
      hasLoadedSecondary.current = true;
      fetchLinkedAlerts();
      fetchInvestigationEntities();
      fetchCorrelationHistory();
      fetchInvestigationSummary();
      fetchAttachmentCount(investigation.alert_id);
    }
  }, [investigation, fetchLinkedAlerts, fetchInvestigationEntities, fetchCorrelationHistory, fetchInvestigationSummary, fetchAttachmentCount]);

  const handleCopyId = () => {
    const idToCopy = investigation?.investigation_id || id;

    // Try modern clipboard API first, fall back to execCommand for HTTP contexts (Firefox)
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(idToCopy).then(() => {
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
      }).catch(() => {
        // Fallback for clipboard API failure
        fallbackCopy(idToCopy);
      });
    } else {
      fallbackCopy(idToCopy);
    }

    function fallbackCopy(text) {
      const textarea = document.createElement('textarea');
      textarea.value = text;
      textarea.style.position = 'fixed';
      textarea.style.opacity = '0';
      document.body.appendChild(textarea);
      textarea.select();
      try {
        document.execCommand('copy');
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
      } catch (e) {
      }
      document.body.removeChild(textarea);
    }
  };

  if (loading) {
    return (
      <div className={styles.loadingScreen}>
        <div className={styles.loadingInner}>
          <div className={`spinner ${styles.loadingSpinner}`} />
          <div className={styles.loadingText}>Loading investigation...</div>
        </div>
      </div>
    );
  }

  if (error || !investigation) {
    return (
      <div className={styles.errorScreen}>
        <h2 className={styles.errorTitle}>Investigation Not Found</h2>
        <p className={styles.errorMessage}>{error || 'This investigation does not exist'}</p>
        <Link
          to="/investigations"
          className={styles.errorBackLink}
        >
          Back to Investigations
        </Link>
      </div>
    );
  }

  const verdictData = extractVerdictData(investigation, alertData);

  const TAB_CONFIG = [
    { id: 'summary', label: 'Summary' },
    { id: 'all-iocs', label: 'IOCs' },
    { id: 'related-events', label: 'Related Events', badge: linkedAlerts.length || null },
    { id: 'attachments', label: 'Attachments', badge: attachmentCount || null },
    { id: 'evidence', label: 'Evidence' },
    { id: 'generate-report', label: 'Generate Report' },
  ];

  return (
    <div className={styles.workbenchRoot}>
      {/* CASE HEADER — single unified row: state + id + classification + lifecycle */}
      <div className={styles.stickyActionBar} style={{ padding: 0 }}>
        <div className="case-facet-row">
          {/* Status group */}
          <StatePill state={investigation?.state} />
          {investigation?.investigation_id && (
            <code className="case-chip case-facet-id-chip">
              {investigation.investigation_id}
            </code>
          )}

          <div className="case-facet-divider" />

          {/* Classification facets (Disposition / Priority / Severity / Assignee) */}
          <ClassificationControls investigation={investigation} onUpdate={setInvestigation} />

          <div className="case-facet-divider" />

          <div className="case-facet-rest">
          <button
            onClick={handleManualTriage}
            disabled={triageLoading}
            title="Run Riggs analysis for this investigation"
            className="case-action-btn case-action-btn--primary"
          >
            {triageLoading ? 'Queuing…' : 'Run Analysis'}
          </button>
          {(investigation?.alert_id || alertData?.alert_id || alertData?.id) && (
            <button
              onClick={handleBuildPlaybookFromAlert}
              disabled={buildPlaybookState.loading}
              title={buildPlaybookState.error || 'Have Riggs draft a SOAR playbook tailored to this alert'}
              className="case-action-btn"
            >
              {buildPlaybookState.loading ? 'Riggs is drafting…' : 'Build Playbook'}
            </button>
          )}
          <button
            className="case-action-btn"
            onClick={async () => {
              if (!window.confirm('Close this investigation as a false positive?')) return;
              try {
                const r = await fetch(
                  `${API_BASE_URL}/api/v1/investigations/${investigation?.investigation_id || investigation?.id}`,
                  {
                    method: 'PATCH',
                    headers: { ...getAuthHeaders(), 'Content-Type': 'application/json', 'X-CSRF-Token': getCsrfToken() },
                    credentials: 'include',
                    body: JSON.stringify({ state: 'CLOSED' })
                  }
                );
                if (!r.ok) {
                  const detail = await r.text();
                  alert(`Close failed (${r.status}): ${detail.slice(0, 300)}`);
                  return;
                }
                window.location.reload();
              } catch (err) {
                alert(`Close failed: ${err.message || 'network error'}`);
              }
            }}
          >
            Close
          </button>
          <button
            className="case-action-btn case-action-btn--success"
            onClick={async () => {
              if (!window.confirm('Mark this investigation as resolved?')) return;
              try {
                // RESOLVED is mapped to CLOSED server-side (DB has no RESOLVED state).
                const r = await fetch(
                  `${API_BASE_URL}/api/v1/investigations/${investigation?.investigation_id || investigation?.id}`,
                  {
                    method: 'PATCH',
                    headers: { ...getAuthHeaders(), 'Content-Type': 'application/json', 'X-CSRF-Token': getCsrfToken() },
                    credentials: 'include',
                    body: JSON.stringify({ state: 'RESOLVED' })
                  }
                );
                if (!r.ok) {
                  const detail = await r.text();
                  alert(`Resolve failed (${r.status}): ${detail.slice(0, 300)}`);
                  return;
                }
                window.location.reload();
              } catch (err) {
                alert(`Resolve failed: ${err.message || 'network error'}`);
              }
            }}
          >
            Resolve
          </button>
          <button
            className="case-action-btn case-action-btn--danger"
            onClick={() => {
              if (window.confirm('Escalate this investigation?')) {
                fetch(`${API_BASE_URL}/api/v1/chat/investigations/${investigation?.investigation_id}/state`, {
                  method: 'PUT',
                  headers: { ...getAuthHeaders(), 'Content-Type': 'application/json', 'X-CSRF-Token': getCsrfToken() },
                  credentials: 'include',
                  body: JSON.stringify({ state: 'ESCALATED', reason: 'Escalated by analyst' })
                }).then(() => window.location.reload());
              }
            }}
          >
            Escalate
          </button>
          </div>
        </div>
      </div>

      {/* TRIAGE STATUS BANNER */}
      {triageStatus && (
        <div style={{
          padding: '0.75rem 1rem',
          marginTop: '0.5rem',
          borderRadius: '6px',
          display: 'flex',
          alignItems: 'center',
          gap: '0.75rem',
          background:
            triageStatus === 'running' ? 'rgba(59, 130, 246, 0.12)' :
            triageStatus === 'success' ? 'rgba(34, 197, 94, 0.12)' :
            'rgba(239, 68, 68, 0.12)',
          border: '1px solid ' + (
            triageStatus === 'running' ? '#3b82f6' :
            triageStatus === 'success' ? '#22c55e' :
            '#ef4444'
          ),
          color:
            triageStatus === 'running' ? '#60a5fa' :
            triageStatus === 'success' ? '#4ade80' :
            '#f87171',
          fontSize: '0.875rem',
          fontWeight: 500
        }}>
          {triageStatus === 'running' && (
            <span style={{
              display: 'inline-block',
              width: '14px',
              height: '14px',
              border: '2px solid currentColor',
              borderTopColor: 'transparent',
              borderRadius: '50%',
              animation: 'spin 0.8s linear infinite'
            }} />
          )}
          {triageStatus === 'success' && <span>&#10003;</span>}
          {triageStatus === 'error' && <span>!</span>}
          <span style={{ flex: 1 }}>{triageMessage}</span>
          {triageStatus === 'running' && (
            <span style={{ opacity: 0.7, fontSize: '0.75rem' }}>
              {triageElapsed}s
            </span>
          )}
          {triageStatus !== 'running' && (
            <button
              onClick={() => setTriageStatus(null)}
              style={{
                background: 'transparent',
                border: 'none',
                color: 'inherit',
                cursor: 'pointer',
                fontSize: '1rem',
                padding: '0 0.25rem'
              }}
            >
              x
            </button>
          )}
          <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
        </div>
      )}

      {/* TAB BAR */}
      <div className="wb-tab-bar">
        {TAB_CONFIG.map(tab => (
          <button
            key={tab.id}
            onClick={() => {
              if (tab.id === 'generate-report') {
                setReportModalOpen(true);
              } else {
                setActiveTab(tab.id);
              }
            }}
            className={`wb-tab ${activeTab === tab.id ? 'wb-tab--active' : ''}`}
          >
            {tab.label}
            {tab.badge > 0 && <span className="wb-tab__badge">{tab.badge}</span>}
          </button>
        ))}
      </div>

      {/* MAIN CONTENT AREA + RIGGS CHAT SIDEBAR */}
      <div className={styles.mainContentRow}>
        {/* Content Area */}
        <div className={styles.contentArea}>
        <div className={styles.contentInner}>
          {/* Deep Dive Error Banner */}
          {deepDiveError && (
            <div className={styles.deepDiveErrorBanner}>
              <span>{deepDiveError}</span>
              <button
                onClick={() => setDeepDiveError(null)}
                className={styles.deepDiveErrorClose}
              >x</button>
            </div>
          )}
          {activeTab === 'summary' && (
            <SummaryTab
              investigation={investigation}
              alertData={alertData}
              verdictData={verdictData}
              onInvestigationUpdate={setInvestigation}
              linkedAlerts={linkedAlerts}
              investigationEntities={investigationEntities}
              investigationSummary={investigationSummary}
              onSwitchTab={setActiveTab}
              licenseData={licenseData}
              onDeepDive={handleDeepDive}
              deepDiveLoading={deepDiveLoading}
            />
          )}
          {activeTab === 'related-events' && (
            <LinkedAlertsTab
              linkedAlerts={linkedAlerts}
              investigationEntities={investigationEntities}
              investigationId={investigation?.investigation_id || id}
              correlationHistory={correlationHistory}
            />
          )}
          {activeTab === 'all-iocs' && (
            <AllIOCsTab
              investigation={investigation}
              alertData={alertData}
            />
          )}
          {activeTab === 'attachments' && (
            <AttachmentsTab
              investigation={investigation}
              alertData={alertData}
            />
          )}
          {activeTab === 'evidence' && (
            <>
              <ActivityTab investigation={investigation} />
              <div style={{ marginTop: '1rem' }}>
                <RawDataTab investigation={investigation} alertData={alertData} />
              </div>
            </>
          )}
        </div>
        </div>

        {/* RIGGS CHAT SIDEBAR */}
        <div className={`${styles.riggsSidebar} ${chatOpen ? styles.riggsSidebarOpen : ''}`}>
          <div className={styles.riggsSidebarHeader}>
            <span className={styles.riggsSidebarTitle}>Riggs Chat</span>
            <button
              className={styles.riggsSidebarToggle}
              onClick={() => setChatOpen(!chatOpen)}
            >
              {chatOpen ? 'X' : 'Chat'}
            </button>
          </div>
          {chatOpen && (
            <div className={styles.riggsSidebarBody}>
              <SidePanelChat
                investigation={investigation}
                chatOpen={true}
                setChatOpen={setChatOpen}
                licenseData={licenseData}
              />
            </div>
          )}
        </div>
      </div>

      {/* Report Generator Modal */}
      <ReportGenerator
        investigationId={investigation?.investigation_id || investigation?.id}
        investigationTitle={investigation?.title || investigation?.investigation_id}
        open={reportModalOpen}
        onClose={() => setReportModalOpen(false)}
      />
    </div>
  );
}

// ============================================================================
// VERDICT HEADER
// ============================================================================

function VerdictHeaderContent({ investigation, verdictData, onCopyId, copied, onUpdate, chatOpen, onToggleChat, licenseData, onDeepDive, deepDiveLoading, onGenerateReport }) {
  const [saving, setSaving] = useState(false);
  const hasDeepDive = licenseData?.features?.deep_dive;
  const deepDiveUsage = licenseData?.deep_dive_usage || {};
  const deepDiveUnlimited = deepDiveUsage.unlimited !== false;
  const deepDiveRemaining = deepDiveUsage.remaining ?? null;
  const deepDiveLimit = deepDiveUsage.limit || 0;
  const deepDiveUsed = deepDiveUsage.used || 0;
  const existingDeepDive = investigation?.investigation_data?.riggs_deep_analysis;

  const handleQuickClose = async (disposition) => {
    setSaving(true);
    try {
      await fetch(
        `${API_BASE_URL}/api/v1/investigations/${investigation.investigation_id || investigation.id}`,
        {
          method: 'PATCH',
          headers: { ...getAuthHeaders(), 'Content-Type': 'application/json' },
          body: JSON.stringify({ disposition, state: 'CLOSED' })
        }
      );
      onUpdate?.();
    } catch (err) {
    }
    setSaving(false);
  };

  const handleEscalate = async () => {
    setSaving(true);
    try {
      await fetch(
        `${API_BASE_URL}/api/v1/investigations/${investigation.investigation_id || investigation.id}`,
        {
          method: 'PATCH',
          headers: { ...getAuthHeaders(), 'Content-Type': 'application/json' },
          body: JSON.stringify({ state: 'ESCALATED' })
        }
      );
      onUpdate?.();
    } catch (err) {
    }
    setSaving(false);
  };

  const sevColor = getSeverityColor(investigation.severity);
  const isOpen = investigation.state !== 'CLOSED' && investigation.state !== 'RESOLVED';
  const atLimit = !deepDiveUnlimited && deepDiveRemaining !== null && deepDiveRemaining <= 0;
  const showCount = !deepDiveUnlimited && deepDiveLimit > 0;

  return (
    <div className="wb-header">
      {/* ROW 1: Navigation + Metadata + Actions */}
      <div className="wb-header__row1">
        <div className="wb-header__left">
          <Link to="/investigations" className="wb-header__back">
            <span className={styles.backArrow}>&#8592;</span> Investigations
          </Link>

          <button onClick={onCopyId} title="Click to copy full ID" className="wb-header__id-btn">
            <code className="wb-header__id-code" style={{ color: copied ? '#22c55e' : undefined }}>
              {copied ? 'Copied!' : (investigation.investigation_id || '').slice(0, 14)}
            </code>
          </button>

          <StateIndicator state={investigation.state} />

          {investigation.priority && (
            <span className="wb-header__badge">
              {(investigation.priority || '').toUpperCase()}
            </span>
          )}

          {investigation.severity && (
            <span className="wb-header__badge">
              {(investigation.severity || '').toUpperCase()}
            </span>
          )}

          <span className="wb-header__age">{formatDuration(investigation.created_at)}</span>
        </div>

        <div className="wb-header__actions">
          {/* Enrichment Progress - compact in row 1 */}
          {investigation.enrichment_progress !== undefined && investigation.enrichment_progress < 100 && (
            <div className="wb-header__enrichment">
              <div className="wb-header__enrichment-dot" />
              <span>{investigation.enrichment_completed_iocs || 0}/{investigation.enrichment_total_iocs || '?'} IOCs</span>
              <div className="wb-header__enrichment-bar">
                <div style={{ width: `${investigation.enrichment_progress}%` }} />
              </div>
            </div>
          )}

          {/* Deep Dive */}
          <button
            onClick={hasDeepDive ? onDeepDive : undefined}
            disabled={!hasDeepDive || deepDiveLoading || atLimit}
            title={!hasDeepDive ? 'Deep Dive requires Pro plan' : atLimit ? `Limit reached (${deepDiveUsed}/${deepDiveLimit})` : ''}
            className="wb-header__deep-dive"
          >
            {deepDiveLoading ? 'Analyzing...' : (existingDeepDive ? 'Re-run Deep Dive' : 'Deep Dive')}
            {!hasDeepDive && <span className="wb-header__pro-badge">PRO</span>}
            {hasDeepDive && showCount && !deepDiveLoading && (
              <span className="wb-header__deep-dive-count">
                {deepDiveRemaining}/{deepDiveLimit}
              </span>
            )}
          </button>

          {/* Quick Actions */}
          {isOpen && (
            <div className="wb-header__quick-actions">
              {verdictData.isBenign ? (
                <button onClick={() => handleQuickClose('false_positive')} disabled={saving} className="wb-header__action-btn wb-header__action-btn--green">Close FP</button>
              ) : verdictData.isMalicious ? (
                <button onClick={handleEscalate} disabled={saving} className="wb-header__action-btn wb-header__action-btn--red">Escalate</button>
              ) : (
                <button onClick={handleEscalate} disabled={saving} className="wb-header__action-btn wb-header__action-btn--amber">Review</button>
              )}
              <button onClick={() => handleQuickClose('benign')} disabled={saving} className="wb-header__action-btn wb-header__action-btn--ghost">Dismiss</button>
            </div>
          )}
          {!isOpen && (
            <span className="wb-header__closed-badge">
              {investigation.state === 'RESOLVED' ? 'Resolved' : 'Closed'}
              {investigation.disposition && <> &middot; {investigation.disposition.replace(/_/g, ' ')}</>}
            </span>
          )}

          {/* Generate Report */}
          <button
            onClick={onGenerateReport}
            className={styles.generateReportBtn}
          >
            Generate Report
          </button>

          {/* Sidebar Toggle */}
          <button onClick={onToggleChat} className={`wb-header__chat-toggle ${chatOpen ? 'wb-header__chat-toggle--active' : ''}`}>
            {chatOpen ? 'Hide Panel' : 'Notes & Riggs'}
          </button>
        </div>
      </div>

      {/* ROW 2: Verdict + Title (the hero area) */}
      <div className="wb-header__row2">
        <div className="wb-header__verdict">
          {(investigation.triage_status === 'provisional' || investigation.state === 'TRIAGE_PROVISIONAL') && (
            <span className="wb-header__provisional">PROVISIONAL</span>
          )}
          <span className="wb-header__verdict-label">
            {verdictData.label}
          </span>
          {verdictData.confidence > 0 && (
            <div className="wb-header__confidence">
              <div className="wb-header__confidence-track">
                <div className="wb-header__confidence-fill" style={{ width: `${verdictData.confidence}%` }} />
              </div>
              <span className="wb-header__confidence-pct">{verdictData.confidence}%</span>
            </div>
          )}
        </div>

        <h1 className="wb-header__title">
          {investigation.alert_title || investigation.title || 'Security Investigation'}
        </h1>
      </div>
    </div>
  );
}

// ============================================================================
// ============================================================================
// DEEP DIVE RESULTS COMPONENT
// ============================================================================

function DeepDiveResults({ investigation, licenseData, alertData }) {
  const isPaid = licenseData?.features?.deep_dive === true;
  const [expanded, setExpanded] = useState(isPaid);
  const deepDive = investigation?.investigation_data?.riggs_deep_analysis;
  if (!deepDive || deepDive.error || deepDive.parse_error) return null;

  // Determine verdict severity for color-coding
  const verdictLower = (deepDive.verdict_title || '').toLowerCase();
  const verdictSeverity = verdictLower.includes('malicious') || verdictLower.includes('critical')
    ? 'malicious'
    : verdictLower.includes('suspicious') || verdictLower.includes('warning')
      ? 'suspicious'
      : 'benign';

  const verdictClass = verdictSeverity === 'malicious'
    ? styles.ddVerdictMalicious
    : verdictSeverity === 'suspicious'
      ? styles.ddVerdictSuspicious
      : styles.ddVerdictBenign;

  // MITRE tactic color mapping
  const tacticColors = {
    'initial-access': '#ef4444', 'execution': '#f97316', 'persistence': '#eab308',
    'privilege-escalation': '#f59e0b', 'defense-evasion': '#a855f7',
    'credential-access': '#ec4899', 'discovery': '#3b82f6', 'lateral-movement': '#6366f1',
    'collection': '#14b8a6', 'command-and-control': '#dc2626', 'exfiltration': '#be123c',
    'impact': '#7f1d1d', 'resource-development': '#64748b', 'reconnaissance': '#0ea5e9',
  };

  const getTacticColor = (tactic) => {
    const key = (tactic || '').toLowerCase().replace(/[\s_]+/g, '-');
    return tacticColors[key] || '#8b5cf6';
  };

  const priorityClassMap = {
    critical: styles.ddRecCritical,
    high: styles.ddRecHigh,
    medium: styles.ddRecMedium,
    low: styles.ddRecLow,
  };

  // Format elapsed time
  const formatElapsed = (ms) => {
    if (!ms) return null;
    return ms >= 1000 ? `${(ms / 1000).toFixed(1)}s` : `${ms}ms`;
  };

  return (
    <div className={styles.ddWrap}>
      {/* Collapsible Header — verdict title + toggle */}
      <div
        className={styles.ddHeader}
        onClick={() => setExpanded(!expanded)}
        style={{ cursor: 'pointer', userSelect: 'none' }}
      >
        <h4 className={styles.ddHeaderTitle}>
          Deep Dive Analysis
          <span className={styles.deepDiveProBadge}>PRO</span>
          {deepDive.verdict_title && (
            <span style={{ fontWeight: 400, fontSize: '0.8rem', marginLeft: '0.75rem', color: 'var(--text-secondary)' }}>
              {deepDive.verdict_title}
            </span>
          )}
        </h4>
        <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginLeft: 'auto', flexShrink: 0 }}>
          {expanded ? 'Collapse' : 'Expand'}
        </span>
      </div>

      {/* Collapsed: show just executive summary */}
      {!expanded && deepDive.executive_summary && (
        <div style={{ padding: '0.5rem 0.75rem', fontSize: '0.8rem', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
          {deepDive.executive_summary.length > 200
            ? deepDive.executive_summary.slice(0, 200) + '...'
            : deepDive.executive_summary}
        </div>
      )}

      {/* Expanded: full deep dive content */}
      {expanded && (
        <>
      {/* Verdict Banner */}
      {deepDive.verdict_title && (
        <div className={`${styles.ddVerdictBanner} ${verdictClass}`} style={{ animationDelay: '0ms' }}>
          <div className={styles.ddVerdictLabel}>Verdict</div>
          <div className={styles.ddVerdictText}>{deepDive.verdict_title}</div>
        </div>
      )}

      {/* Executive Summary */}
      {deepDive.executive_summary && (
        <div className={styles.ddExecCard} style={{ animationDelay: '60ms' }}>
          <div className={styles.ddExecContent}>{deepDive.executive_summary}</div>
        </div>
      )}

      {/* Threat Narrative */}
      {deepDive.threat_narrative && (
        <div className={styles.ddSection} style={{ animationDelay: '120ms' }}>
          <h5 className={styles.ddSectionTitle}>Threat Narrative</h5>
          <div className={styles.ddNarrativeBody}>
            <ReactMarkdown remarkPlugins={[remarkGfm]}>
              {deepDive.threat_narrative}
            </ReactMarkdown>
          </div>
        </div>
      )}

      {/* MITRE ATT&CK Mapping */}
      {deepDive.mitre_attack?.length > 0 && (
        <div className={styles.ddSection} style={{ animationDelay: '180ms' }}>
          <h5 className={styles.ddSectionTitle}>MITRE ATT&CK</h5>
          <div className={styles.ddMitreGrid}>
            {deepDive.mitre_attack.map((tech, i) => (
                <div key={i} className={styles.ddMitreChip}>
                  <span className={styles.ddMitreChipId}>{tech.technique_id}</span>
                  <span className={styles.ddMitreChipName}>{tech.technique_name}</span>
                  <span className={styles.ddMitreChipTactic}>
                    {tech.tactic}
                  </span>
                </div>
            ))}
          </div>
        </div>
      )}

      {/* Root Cause Analysis */}
      {deepDive.root_cause_analysis && (
        <div className={styles.ddSection} style={{ animationDelay: '240ms' }}>
          <h5 className={styles.ddSectionTitle}>Root Cause Analysis</h5>
          <div className={styles.ddRootCauseCard}>
            <ReactMarkdown remarkPlugins={[remarkGfm]}>
              {deepDive.root_cause_analysis}
            </ReactMarkdown>
          </div>
        </div>
      )}

      {/* Response Recommendations + Connector Actions (merged) */}
      {(deepDive.response_recommendations?.length > 0 || true) && (
        <div className={styles.ddSection} style={{ animationDelay: '300ms' }}>
          <h5 className={styles.ddSectionTitle}>Response Recommendations</h5>
          <div className={styles.ddRecSplit}>
            {/* Left: Riggs text recommendations */}
            {deepDive.response_recommendations?.length > 0 && (
              <div className={styles.ddRecSplitLeft}>
                <div className={styles.ddRecList}>
                  {deepDive.response_recommendations.map((rec, i) => (
                    <div
                      key={i}
                      className={`${styles.ddRecCard} ${priorityClassMap[rec.priority] || ''}`}
                    >
                      <div className={styles.ddRecHeader}>
                        <span className={`${styles.ddRecBadge} ${priorityClassMap[rec.priority] || ''}`}>
                          {(rec.priority || 'info').toUpperCase()}
                        </span>
                        <span className={styles.ddRecAction}>{rec.action}</span>
                      </div>
                      {rec.rationale && (
                        <div className={styles.ddRecRationale}>{rec.rationale}</div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}
            {/* Connector actions moved to standalone section below */}
          </div>
        </div>
      )}

      {/* Threat Actor Assessment */}
      {deepDive.threat_actor_assessment && (
        <div className={styles.ddSection} style={{ animationDelay: '360ms' }}>
          <h5 className={styles.ddSectionTitle}>Threat Actor Assessment</h5>
          <div className={styles.ddActorCard}>
            <ReactMarkdown remarkPlugins={[remarkGfm]}>
              {deepDive.threat_actor_assessment}
            </ReactMarkdown>
          </div>
        </div>
      )}

      {/* Confidence Factors */}
      {deepDive.confidence_factors && (
        <div className={styles.ddSection} style={{ animationDelay: '420ms' }}>
          <h5 className={styles.ddSectionTitle}>Confidence Factors</h5>
          <div className={styles.ddConfGrid}>
            {deepDive.confidence_factors.supporting?.length > 0 && (
              <div className={styles.ddConfColumn}>
                <div className={`${styles.ddConfColHeader} ${styles.ddConfSupporting}`}>Supporting</div>
                {deepDive.confidence_factors.supporting.map((f, i) => (
                  <div key={i} className={styles.ddConfFactorItem}>
                    <span className={`${styles.ddConfDot} ${styles.ddConfDotGreen}`} />
                    <span>{f}</span>
                  </div>
                ))}
              </div>
            )}
            {deepDive.confidence_factors.contradicting?.length > 0 && (
              <div className={styles.ddConfColumn}>
                <div className={`${styles.ddConfColHeader} ${styles.ddConfContradicting}`}>Contradicting</div>
                {deepDive.confidence_factors.contradicting.map((f, i) => (
                  <div key={i} className={styles.ddConfFactorItem}>
                    <span className={`${styles.ddConfDot} ${styles.ddConfDotRed}`} />
                    <span>{f}</span>
                  </div>
                ))}
              </div>
            )}
            {deepDive.confidence_factors.gaps?.length > 0 && (
              <div className={styles.ddConfColumn}>
                <div className={`${styles.ddConfColHeader} ${styles.ddConfGaps}`}>Information Gaps</div>
                {deepDive.confidence_factors.gaps.map((f, i) => (
                  <div key={i} className={styles.ddConfFactorItem}>
                    <span className={`${styles.ddConfDot} ${styles.ddConfDotAmber}`} />
                    <span>{f}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Timeline */}
      {deepDive.timeline?.length > 0 && (
        <div className={styles.ddSection} style={{ animationDelay: '480ms' }}>
          <h5 className={styles.ddSectionTitle}>Timeline</h5>
          <div className={styles.ddTimeline}>
            {deepDive.timeline.map((evt, i) => (
              <div key={i} className={styles.ddTimelineItem}>
                <div className={styles.ddTimelineTrack}>
                  <div className={styles.ddTimelineDot} />
                  {i < deepDive.timeline.length - 1 && <div className={styles.ddTimelineLine} />}
                </div>
                <div className={styles.ddTimelineContent}>
                  {evt.time && <div className={styles.ddTimelineTime}>{evt.time}</div>}
                  <div className={styles.ddTimelineDesc}>
                    {evt.description || evt.event || (typeof evt === 'string' ? evt : JSON.stringify(evt))}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Analysis Metadata Footer */}
      <div className={styles.ddFooter} style={{ animationDelay: '540ms' }}>
        {[
          deepDive.analyzed_at && `Analyzed at ${new Date(deepDive.analyzed_at).toLocaleString()}`,
          deepDive.token_count && `${deepDive.token_count.toLocaleString()} tokens`,
          deepDive.elapsed_ms && formatElapsed(deepDive.elapsed_ms),
        ].filter(Boolean).join('  --  ')}
      </div>
        </>
      )}
    </div>
  );
}


// SUMMARY TAB - Quick decision view
// ============================================================================

function SummaryTab({ investigation, alertData, verdictData, onInvestigationUpdate, linkedAlerts, investigationEntities, investigationSummary, onSwitchTab, licenseData, onDeepDive, deepDiveLoading }) {
  const [expandedTimelineAlert, setExpandedTimelineAlert] = useState(null);
  let rawEvent = alertData?.raw_event || {};
  if (typeof rawEvent === 'string') {
    try { rawEvent = JSON.parse(rawEvent); } catch { rawEvent = {}; }
  }

  const contextFacts = extractContextFacts(rawEvent, alertData, investigation);

  const hasDeepDive = !!(investigation?.investigation_data?.riggs_deep_analysis && !investigation.investigation_data.riggs_deep_analysis.error && !investigation.investigation_data.riggs_deep_analysis.parse_error);

  // Merge IOCs from multiple sources:
  // 1. investigation.extracted_iocs - pre-extracted IOCs
  // 2. rawEvent.iocs - IOCs from raw event
  // 3. investigation.indicators - includes decoded/hidden IOCs from AI analysis
  // 4. rawEvent._extracted.decoded_iocs - hidden IOCs from encoded content
  const safeArr = (v) => Array.isArray(v) ? v : [];
  let iocs = [...safeArr(investigation?.extracted_iocs), ...safeArr(rawEvent.iocs)];

  // Add indicators (which include decoded/hidden IOCs)
  const indicators = investigation?.indicators || [];
  if (Array.isArray(indicators)) {
    indicators.forEach(ind => {
      iocs.push({
        type: ind.type || 'unknown',
        value: ind.value,
        reputation: ind.severity === 'high' ? 'suspicious' : (ind.is_hidden ? 'suspicious' : 'unknown'),
        source: ind.source || 'unknown',
        note: ind.note,
        is_hidden: ind.is_hidden
      });
    });
  }

  // Add decoded IOCs from multiple sources:
  // 1. rawEvent._extracted.decoded_iocs - from preprocessing
  // 2. rawEvent._extracted.ai_triage.decoded_iocs - from T1 AI triage
  // 3. investigation_data.tier1_analysis.decoded_iocs - from T1 agent
  // 4. investigation_data.tier2_analysis.decoded_iocs - from T2 agent (most common for encoded payloads)
  let invData = investigation?.investigation_data || {};
  if (typeof invData === 'string') {
    try { invData = JSON.parse(invData); } catch { invData = {}; }
  }

  // Merge decoded IOCs from all sources
  const allDecodedSources = [
    rawEvent._extracted?.decoded_iocs,
    rawEvent._extracted?.ai_triage?.decoded_iocs,
    invData?.tier1_analysis?.decoded_iocs,
    invData?.tier2_analysis?.decoded_iocs,
    invData?.tier3_analysis?.decoded_iocs,
  ].filter(Boolean);

  // Combine all decoded IOCs
  const mergedDecodedIOCs = { ips: [], urls: [], domains: [], emails: [] };
  allDecodedSources.forEach(src => {
    if (src.ips) mergedDecodedIOCs.ips.push(...src.ips);
    if (src.urls) mergedDecodedIOCs.urls.push(...src.urls);
    if (src.domains) mergedDecodedIOCs.domains.push(...src.domains);
    if (src.emails) mergedDecodedIOCs.emails.push(...src.emails);
  });

  // Dedupe each type
  mergedDecodedIOCs.ips = [...new Set(mergedDecodedIOCs.ips)];
  mergedDecodedIOCs.urls = [...new Set(mergedDecodedIOCs.urls)];
  mergedDecodedIOCs.domains = [...new Set(mergedDecodedIOCs.domains)].filter(d => !['System.Net', 'System', 'Net', 'localhost'].includes(d));
  mergedDecodedIOCs.emails = [...new Set(mergedDecodedIOCs.emails)];

  const decodedIOCs = mergedDecodedIOCs;

  if (decodedIOCs.ips && decodedIOCs.ips.length > 0) {
    decodedIOCs.ips.forEach(ip => {
      iocs.push({
        type: 'ip',
        value: ip,
        reputation: 'suspicious',
        source: 'ai_decoded',
        note: 'Hidden IP extracted from encoded content',
        is_hidden: true
      });
    });
  }
  if (decodedIOCs.urls && decodedIOCs.urls.length > 0) {
    decodedIOCs.urls.forEach(url => {
      iocs.push({
        type: 'url',
        value: url,
        reputation: 'suspicious',
        source: 'ai_decoded',
        note: 'Hidden URL extracted from encoded content',
        is_hidden: true
      });
    });
  }
  if (decodedIOCs.domains && decodedIOCs.domains.length > 0) {
    decodedIOCs.domains.forEach(domain => {
      iocs.push({
        type: 'domain',
        value: domain,
        reputation: 'suspicious',
        source: 'ai_decoded',
        note: 'Hidden domain extracted from encoded content',
        is_hidden: true
      });
    });
  }

  // Dedupe and sort IOCs - show only important ones (malicious/suspicious)
  const uniqueIOCs = iocs.reduce((acc, ioc) => {
    const key = `${ioc.type}-${ioc.value}`;
    if (!acc.has(key)) acc.set(key, ioc);
    return acc;
  }, new Map());
  const dedupedIOCs = Array.from(uniqueIOCs.values());

  const importantIOCs = dedupedIOCs.filter(ioc => {
    const rep = (ioc.reputation || '').toLowerCase();
    // Include hidden IOCs as important even if reputation not explicitly set
    return rep === 'malicious' || rep === 'suspicious' || ioc.is_hidden;
  });

  // Use previously parsed invData for tier analysis
  const tier3 = invData.tier3_analysis || {};
  const tier2 = invData.tier2_analysis || {};
  const tier1 = invData.tier1_analysis || {};
  const analysis = tier3.verdict ? tier3 : (tier2.verdict ? tier2 : tier1);

  // Timeline helpers
  const getSeverityColor = (severity) => {
    const colors = {
      critical: '#dc2626',
      high: '#ea580c',
      medium: '#d97706',
      low: '#0284c7',
      info: '#64748b'
    };
    return colors[(severity || '').toLowerCase()] || '#64748b';
  };

  const formatTimeOnly = (dateStr) => {
    if (!dateStr) return '-';
    const date = new Date(dateStr);
    return date.toLocaleTimeString('en-US', {
      hour: '2-digit', minute: '2-digit'
    });
  };

  const formatDateOnly = (dateStr) => {
    if (!dateStr) return '-';
    const date = new Date(dateStr);
    return date.toLocaleDateString('en-US', {
      weekday: 'short', month: 'short', day: 'numeric'
    });
  };

  // Group alerts by date for timeline
  const getAlertsByDate = () => {
    const chronoAlerts = [...(linkedAlerts || [])].sort((a, b) => {
      return new Date(a.created_at || 0) - new Date(b.created_at || 0);
    });

    const grouped = {};
    chronoAlerts.forEach(alert => {
      const dateKey = alert.created_at ? new Date(alert.created_at).toDateString() : 'Unknown';
      if (!grouped[dateKey]) {
        grouped[dateKey] = [];
      }
      grouped[dateKey].push(alert);
    });

    return grouped;
  };

  // Compact Timeline Event
  const renderCompactTimelineEvent = (alert, isLast) => {
    const severityColor = getSeverityColor(alert.severity);
    const isExpanded = expandedTimelineAlert === alert.id;

    return (
      <div key={alert.id} className={styles.compactEventRow}>
        {/* Timeline Line and Dot */}
        <div className={styles.timelineDotLine}>
          <div className={styles.timelineDot} style={{
            background: severityColor,
            boxShadow: `0 0 6px ${severityColor}40`
          }} />
          {!isLast && (
            <div className={styles.timelineLine} />
          )}
        </div>

        {/* Event Card - Compact */}
        <div className={styles.compactEventCard} style={{
          background: isExpanded ? 'var(--bg-secondary, #1e293b)' : 'transparent',
          border: isExpanded ? '1px solid rgba(255,255,255,0.1)' : 'none'
        }}>
          <div
            onClick={() => setExpandedTimelineAlert(isExpanded ? null : alert.id)}
            className={styles.compactEventClickable} style={{
              padding: isExpanded ? '10px 12px' : '4px 0'
            }}
          >
            {/* Time */}
            <span className={styles.compactEventTime}>
              {formatTimeOnly(alert.created_at)}
            </span>

            {/* Severity Badge */}
            <span className={styles.compactSeverityBadge} style={{
              background: `${severityColor}20`,
              color: severityColor
            }}>
              {alert.severity || 'unk'}
            </span>

            {/* Title */}
            <span className={styles.compactEventTitle}>
              {alert.title || 'Untitled Alert'}
            </span>

            {/* Quick Entities */}
            {alert.extracted_entities?.user?.length > 0 && (
              <span className={styles.compactEventEntity}>
                {alert.extracted_entities.user[0]}
              </span>
            )}
          </div>

          {/* Expanded Details */}
          {isExpanded && (
            <div className={styles.compactExpandedDetails}>
              <div className={styles.compactExpandedDesc}>
                {alert.description || 'No description available'}
              </div>
              <div className={styles.compactExpandedRow}>
                {alert.source && (
                  <span className={styles.compactMetaLabel}>
                    Source: <strong className={styles.compactMetaValue}>{alert.source}</strong>
                  </span>
                )}
                {alert.extracted_entities?.host?.length > 0 && (
                  <span className={styles.compactMetaLabel}>
                    Host: <strong className={styles.compactMetaValue}>{alert.extracted_entities.host[0]}</strong>
                  </span>
                )}
                {alert.mitre_techniques?.length > 0 && (
                  <span className={styles.compactMetaLabel}>
                    MITRE: <strong className={styles.compactMetaValueWarning}>{alert.mitre_techniques.join(', ')}</strong>
                  </span>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    );
  };

  // Render Compact Timeline
  const renderCompactTimeline = () => {
    if (!linkedAlerts || linkedAlerts.length === 0) {
      return (
        <div className={styles.emptyTimeline}>
          <div className={styles.emptyTimelineIcon}>📅</div>
          <p className={styles.emptyTimelineText}>No correlated alerts in this investigation</p>
        </div>
      );
    }

    const alertsByDate = getAlertsByDate();
    const dates = Object.keys(alertsByDate);

    return (
      <div>
        {dates.map((dateKey, dateIdx) => (
          <div key={dateKey} className={styles.dateGroup}>
            {/* Date Header */}
            <div className={styles.dateGroupHeader}>
              <div className={styles.dateBadge}>
                {formatDateOnly(alertsByDate[dateKey][0]?.created_at)}
              </div>
              <span className={styles.dateEventCount}>
                {alertsByDate[dateKey].length} event{alertsByDate[dateKey].length !== 1 ? 's' : ''}
              </span>
            </div>

            {/* Events for this date */}
            <div className={styles.dateGroupEvents}>
              {alertsByDate[dateKey].map((alert, idx) =>
                renderCompactTimelineEvent(
                  alert,
                  idx === alertsByDate[dateKey].length - 1 && dateIdx === dates.length - 1
                )
              )}
            </div>
          </div>
        ))}
      </div>
    );
  };

  // Build coreInfo from RiggsInsights for the dashboard
  const { coreInfo: riggsCore, widgets: riggsWidgets } = buildRiggsInsights(investigation, alertData);

  // Entity risk data
  const entityTypes = investigationEntities?.entity_types || investigationEntities?.entities || {};

  // Summary metrics
  const totalIOCs = dedupedIOCs.length;
  const maliciousIOCs = dedupedIOCs.filter(i => (i.reputation || '').toLowerCase() === 'malicious').length;
  const suspiciousIOCs = dedupedIOCs.filter(i => (i.reputation || '').toLowerCase() === 'suspicious' || i.is_hidden).length;
  const entityCount = Object.values(entityTypes).reduce((sum, arr) => sum + (Array.isArray(arr) ? arr.length : 0), 0);

  // MITRE techniques from analysis
  const mitreTechniques = analysis.mitre_techniques || tier2.mitre_techniques || tier1.mitre_techniques || [];

  // Actionable IOCs for integration actions
  const actionableIOCs = importantIOCs.filter(i => ['malicious', 'suspicious'].includes((i.reputation || '').toLowerCase()));

  return (
    <div>
      {/* RIGGS DEEP ANALYSIS THINKING INDICATOR */}
      {deepDiveLoading && (
        <div style={{
          position: 'relative',
          padding: '1.5rem',
          background: 'linear-gradient(135deg, rgba(59, 130, 246, 0.1) 0%, rgba(99, 102, 241, 0.1) 100%)',
          border: '1px solid rgba(59, 130, 246, 0.3)',
          borderRadius: '8px',
          marginBottom: '1rem',
          textAlign: 'center'
        }}>
          {/* Animated thinking dots */}
          <div style={{
            display: 'flex',
            justifyContent: 'center',
            alignItems: 'center',
            gap: '0.5rem',
            marginBottom: '0.75rem'
          }}>
            <div style={{
              width: '8px',
              height: '8px',
              borderRadius: '50%',
              background: 'var(--primary, #3b82f6)',
              animation: 'pulse 1.4s infinite',
              animationDelay: '0s'
            }} />
            <div style={{
              width: '8px',
              height: '8px',
              borderRadius: '50%',
              background: 'var(--primary, #3b82f6)',
              animation: 'pulse 1.4s infinite',
              animationDelay: '0.2s'
            }} />
            <div style={{
              width: '8px',
              height: '8px',
              borderRadius: '50%',
              background: 'var(--primary, #3b82f6)',
              animation: 'pulse 1.4s infinite',
              animationDelay: '0.4s'
            }} />
          </div>
          <div style={{
            fontSize: '0.875rem',
            fontWeight: 500,
            color: 'var(--text-secondary, #4b5563)'
          }}>
            Riggs is thinking... analyzing this investigation with deep dive analysis
          </div>
        </div>
      )}

      {/* SINGLE-COLUMN LAYOUT */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>

        {/* RIGGS SUMMARY + FINDINGS side by side -- hidden when Deep Dive
            is available, since Deep Dive supersedes the T1 summary and
            includes a richer verdict, threat narrative, and findings list. */}
        {!hasDeepDive && (
        <div className={styles.summaryGrid}>
        <div className={styles.summaryCard}>
          <div className={styles.summaryCardHeader}>Riggs Summary</div>
          <div className={styles.summaryCardBody}>
            {/* Verdict + Confidence */}
            {verdictData.label && (
              <div style={{ marginBottom: hasDeepDive ? '0.35rem' : '0.75rem' }}>
                <span style={{ fontWeight: 700, fontSize: hasDeepDive ? '0.82rem' : '0.9rem', textTransform: 'uppercase' }}>{verdictData.label}</span>
                {verdictData.confidence > 0 && (
                  <span style={{ marginLeft: '0.5rem', fontSize: '0.72rem', color: 'var(--text-muted)' }}>{verdictData.confidence}% confidence</span>
                )}
                {verdictData.threatCategory && (
                  <span style={{ marginLeft: '0.5rem', fontSize: '0.72rem', color: 'var(--text-muted)' }}>-- {verdictData.threatCategory}</span>
                )}
              </div>
            )}

            {/* When deep dive exists: compact summary only */}
            {hasDeepDive ? (
              <>
                {(riggsCore.summary || riggsCore.riggsStatement) && (
                  <div style={{ fontSize: '0.75rem', lineHeight: 1.45, color: 'var(--text-secondary)', marginBottom: '0.3rem' }}>
                    {(riggsCore.summary || riggsCore.riggsStatement || '').slice(0, 250)}{(riggsCore.summary || '').length > 250 ? '...' : ''}
                  </div>
                )}
                {riggsCore.confidenceSignals?.length > 0 && (
                  <div>
                    <div style={{ fontSize: '0.6rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '0.2rem' }}>Key Signals</div>
                    {riggsCore.confidenceSignals.slice(0, 3).map((s, i) => (
                      <div key={i} style={{ fontSize: '0.72rem', color: 'var(--text-secondary)', padding: '0.1rem 0', lineHeight: 1.35 }}>
                        - {(typeof s === 'string' ? s : s.signal || s.label || s.text || s.finding || '').slice(0, 120)}{(typeof s === 'string' ? s : '').length > 120 ? '...' : ''}
                      </div>
                    ))}
                  </div>
                )}
              </>
            ) : (
              <>
                {/* Full summary when no deep dive */}
                {(riggsCore.summary || riggsCore.riggsStatement) && (
                  <div style={{ fontSize: '0.8125rem', lineHeight: 1.7, color: 'var(--text-secondary)', marginBottom: '0.75rem' }}>
                    {riggsCore.summary || riggsCore.riggsStatement}
                  </div>
                )}

                {riggsCore.attackNarrative && (
                  <div style={{ fontSize: '0.8125rem', lineHeight: 1.7, color: 'var(--text-secondary)', marginBottom: '0.75rem' }}>
                    {riggsCore.attackNarrative}
                  </div>
                )}

                {riggsCore.confidenceSignals?.length > 0 && (
                  <div style={{ marginBottom: '0.75rem' }}>
                    <div style={{ fontSize: '0.6875rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '0.35rem' }}>Key Signals</div>
                    {riggsCore.confidenceSignals.map((s, i) => (
                      <div key={i} style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', padding: '0.15rem 0' }}>
                        - {typeof s === 'string' ? s : s.signal || s.label || s.text || s.finding}
                      </div>
                    ))}
                  </div>
                )}

                {riggsCore.whatWouldChange?.length > 0 && (
                  <div>
                    <div style={{ fontSize: '0.6875rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '0.35rem' }}>What would change this verdict</div>
                    {riggsCore.whatWouldChange.map((item, i) => (
                      <div key={i} style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', padding: '0.15rem 0' }}>
                        - {typeof item === 'string' ? item : item.label || item.text}
                      </div>
                    ))}
                  </div>
                )}

                {riggsCore.businessImpact && (
                  <div style={{ marginTop: '0.75rem' }}>
                    <div style={{ fontSize: '0.6875rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '0.35rem' }}>Business Impact</div>
                    <div style={{ fontSize: '0.8125rem', lineHeight: 1.6, color: 'var(--text-secondary)' }}>
                      {riggsCore.businessImpact}
                    </div>
                  </div>
                )}
              </>
            )}
          </div>
        </div>

        {/* FINDINGS / THREAT OBJECTS */}
        <div className={styles.summaryCard}>
          <div className={styles.summaryCardHeader}>
            Findings / Threat Objects
            <span style={{ fontWeight: 400, fontSize: '0.7rem', color: 'var(--text-muted)', marginLeft: '0.5rem' }}>
              {totalIOCs} IOCs -- {entityCount} entities
            </span>
          </div>
          <div className={styles.summaryCardBody}>
            {importantIOCs.length > 0 && (
              <div style={{ marginBottom: '0.75rem' }}>
                <div style={{ fontSize: '0.6875rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '0.35rem' }}>Top IOCs</div>
                {importantIOCs.slice(0, 8).map((ioc, i) => {
                  const rep = (ioc.reputation || 'unknown').toLowerCase();
                  const repColor = rep === 'malicious' ? '#ef4444' : rep === 'suspicious' ? '#f59e0b' : 'var(--text-muted)';
                  return (
                    <div key={i} style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', padding: '0.25rem 0', fontSize: '0.8125rem', cursor: 'pointer' }} onClick={() => onSwitchTab?.('all-iocs')}>
                      <span style={{ fontSize: '0.65rem', fontWeight: 600, textTransform: 'uppercase', color: 'var(--text-muted)', minWidth: '3.5rem', flexShrink: 0 }}>{ioc.type}</span>
                      <span style={{ fontFamily: "'SF Mono', 'Fira Code', monospace", color: 'var(--text-primary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{ioc.value}</span>
                      <span style={{ fontSize: '0.65rem', color: repColor, flexShrink: 0, fontWeight: rep !== 'unknown' ? 600 : 400 }}>{rep}</span>
                    </div>
                  );
                })}
                {totalIOCs > 8 && (
                  <button onClick={() => onSwitchTab?.('all-iocs')} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', fontSize: '0.75rem', cursor: 'pointer', padding: '0.25rem 0', marginTop: '0.25rem' }}>
                    View all {totalIOCs} IOCs
                  </button>
                )}
              </div>
            )}
            {entityCount > 0 && (
              <div>
                <div style={{ fontSize: '0.6875rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '0.35rem' }}>Entities</div>
                {Object.entries(entityTypes).map(([type, entities]) => {
                  if (!Array.isArray(entities) || entities.length === 0) return null;
                  return (
                    <div key={type} style={{ marginBottom: '0.5rem' }}>
                      <span style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-secondary)' }}>
                        {type === 'ip' ? 'IP Addresses' : type === 'user' ? 'Users' : type === 'host' ? 'Hosts' : type === 'domain' ? 'Domains' : type}
                        <span style={{ fontWeight: 400, color: 'var(--text-muted)', marginLeft: '0.3rem' }}>({entities.length})</span>
                      </span>
                      <div style={{ marginTop: '0.2rem' }}>
                        {entities.slice(0, 5).map((entity, i) => (
                          <div key={i} style={{ fontSize: '0.8125rem', color: 'var(--text-primary)', padding: '0.1rem 0', fontFamily: "'SF Mono', 'Fira Code', monospace" }}>
                            {entity.value || entity}
                          </div>
                        ))}
                        {entities.length > 5 && (
                          <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>+{entities.length - 5} more</span>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
            {mitreTechniques.length > 0 && (
              <div style={{ marginTop: '0.5rem' }}>
                <div style={{ fontSize: '0.6875rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '0.35rem' }}>MITRE ATT&CK</div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.35rem' }}>
                  {mitreTechniques.map((tech, i) => {
                    const techId = typeof tech === 'string' ? tech : tech.technique_id || tech.id || tech;
                    return (
                      <span key={i} style={{ fontSize: '0.7rem', padding: '0.15rem 0.4rem', borderRadius: '4px', background: 'rgba(255,255,255,0.06)', border: '1px solid rgba(255,255,255,0.08)', color: 'var(--text-secondary)' }}>
                        {techId}
                      </span>
                    );
                  })}
                </div>
              </div>
            )}
          </div>
        </div>

        </div>
        )}{/* close summaryGrid + hasDeepDive guard */}

        {/* Deep Dive (if available) — PRIMARY CONTENT, full width */}
        <DeepDiveResults investigation={investigation} licenseData={licenseData} alertData={alertData} />

        {/* RECOMMENDED ACTIONS — compact, below deep dive */}
        <div className={styles.summaryCard}>
          <div className={styles.summaryCardHeader}>Recommended Actions</div>
          <div className={styles.summaryCardBody}>
            <RecommendedActions investigation={investigation} alertData={alertData} />
          </div>
        </div>
      </div>

      {/* Supplemental sections below the grid */}
      <div style={{ marginTop: '1rem' }}>
        <CampaignMembership
          investigationId={investigation?.investigation_id || investigation?.id}
          investigationData={investigation}
        />
        <RelatedActivity
          investigationId={investigation?.investigation_id || investigation?.id}
        />
      </div>
    </div>
  );
}

// (Old SummaryTab return removed — replaced with two-column layout above)
// Keeping a marker so the next function boundary is clean

// ============================================================================
// LINKED ALERTS TAB - Shows all correlated alerts with full data
// ============================================================================

function LinkedAlertsTab({ linkedAlerts, investigationEntities, investigationId, correlationHistory }) {
  const [expandedAlert, setExpandedAlert] = useState(null);
  const [sortBy, setSortBy] = useState('created_at');
  const [sortOrder, setSortOrder] = useState('desc');
  const [viewMode, setViewMode] = useState('table'); // 'timeline' or 'table' - default to table since timeline is on Summary

  // Sort alerts - always chronological for timeline, user choice for table
  const sortedAlerts = [...(linkedAlerts || [])].sort((a, b) => {
    let aVal, bVal;
    if (sortBy === 'created_at') {
      aVal = new Date(a.created_at || 0);
      bVal = new Date(b.created_at || 0);
    } else if (sortBy === 'severity') {
      const sevOrder = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
      aVal = sevOrder[(a.severity || '').toLowerCase()] || 0;
      bVal = sevOrder[(b.severity || '').toLowerCase()] || 0;
    } else if (sortBy === 'score') {
      aVal = a.correlation?.score || 0;
      bVal = b.correlation?.score || 0;
    }
    return sortOrder === 'desc' ? bVal - aVal : aVal - bVal;
  });

  const getSeverityColor = (severity) => {
    const colors = {
      critical: '#dc2626',
      high: '#ea580c',
      medium: '#d97706',
      low: '#0284c7',
      info: '#64748b'
    };
    return colors[(severity || '').toLowerCase()] || '#64748b';
  };

  const getCorrelationBadge = (correlation) => {
    if (!correlation) return null;
    const type = correlation.decision_type || 'unknown';
    const colors = {
      auto_link: { bg: 'rgba(16, 185, 129, 0.15)', text: '#10b981', label: 'Auto-Linked' },
      soft_link: { bg: 'rgba(59, 130, 246, 0.15)', text: '#3b82f6', label: 'Soft-Linked' },
      legacy: { bg: 'rgba(100, 116, 139, 0.15)', text: '#94a3b8', label: 'Legacy' },
      create_new: { bg: 'rgba(139, 92, 246, 0.15)', text: '#8b5cf6', label: 'Created' }
    };
    const style = colors[type] || colors.legacy;
    return (
      <span style={{
        padding: '2px 8px',
        borderRadius: '4px',
        fontSize: '11px',
        fontWeight: '500',
        background: style.bg,
        color: style.text
      }}>
        {style.label}
      </span>
    );
  };

  const formatDate = (dateStr) => {
    if (!dateStr) return '-';
    const date = new Date(dateStr);
    return date.toLocaleString('en-US', {
      month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit'
    });
  };

  const formatTimeOnly = (dateStr) => {
    if (!dateStr) return '-';
    const date = new Date(dateStr);
    return date.toLocaleTimeString('en-US', {
      hour: '2-digit', minute: '2-digit', second: '2-digit'
    });
  };

  const formatDateOnly = (dateStr) => {
    if (!dateStr) return '-';
    const date = new Date(dateStr);
    return date.toLocaleDateString('en-US', {
      weekday: 'short', month: 'short', day: 'numeric', year: 'numeric'
    });
  };

  // Group alerts by date for timeline
  const getAlertsByDate = () => {
    const chronoAlerts = [...(linkedAlerts || [])].sort((a, b) => {
      return new Date(a.created_at || 0) - new Date(b.created_at || 0);
    });

    const grouped = {};
    chronoAlerts.forEach(alert => {
      const dateKey = alert.created_at ? new Date(alert.created_at).toDateString() : 'Unknown';
      if (!grouped[dateKey]) {
        grouped[dateKey] = [];
      }
      grouped[dateKey].push(alert);
    });

    return grouped;
  };

  // Timeline Event Component
  const renderTimelineEvent = (alert, isLast) => {
    const isExpanded = expandedAlert === alert.id;
    const correlation = alert.correlation || {};
    const severityColor = getSeverityColor(alert.severity);

    return (
      <div key={alert.id} className={styles.timelineEventRow}>
        {/* Timeline Line and Dot */}
        <div className={styles.linkedDotLine}>
          {/* Dot */}
          <div className={styles.linkedDot} style={{
            background: severityColor,
            border: `2px solid ${severityColor}`,
            boxShadow: `0 0 8px ${severityColor}40`
          }} />
          {/* Line */}
          {!isLast && (
            <div className={styles.linkedLine} />
          )}
        </div>

        {/* Event Card */}
        <div className={styles.linkedEventCard} style={{
          background: isExpanded ? 'var(--bg-secondary, #1e293b)' : 'var(--bg-tertiary, #0f172a)',
          border: isExpanded ? `1px solid ${severityColor}40` : '1px solid rgba(255,255,255,0.05)'
        }}>
          {/* Event Header */}
          <div
            onClick={() => setExpandedAlert(isExpanded ? null : alert.id)}
            className={styles.linkedEventHeaderRow}
          >
            {/* Time */}
            <div className={styles.linkedEventTime}>
              {formatTimeOnly(alert.created_at)}
            </div>

            {/* Main Content */}
            <div className={styles.linkedEventMainContent}>
              {/* Title Row */}
              <div className={styles.linkedEventTitleRow}>
                <span className={styles.severityBadge} style={{
                  background: `${severityColor}20`,
                  color: severityColor
                }}>
                  {alert.severity || 'unknown'}
                </span>
                {getCorrelationBadge(correlation)}
                <span className={styles.alertIdMono}>
                  {alert.alert_id || alert.id?.slice(0, 12)}
                </span>
              </div>

              {/* Title */}
              <div className={styles.linkedEventTitle}>
                {alert.title || 'Untitled Alert'}
              </div>

              {/* Quick Info */}
              <div className={styles.linkedEventQuickInfo}>
                {alert.source && (
                  <span>Source: <strong>{alert.source}</strong></span>
                )}
                {correlation.score !== undefined && (
                  <span>
                    Score: <strong style={{ color: correlation.score >= 100 ? '#10b981' : '#f59e0b' }}>
                      {correlation.score}
                    </strong>
                  </span>
                )}
                {alert.extracted_entities?.user?.length > 0 && (
                  <span>User: <strong>{alert.extracted_entities.user[0]}</strong></span>
                )}
                {alert.extracted_entities?.host?.length > 0 && (
                  <span>Host: <strong>{alert.extracted_entities.host[0]}</strong></span>
                )}
              </div>
            </div>

            {/* Expand Icon */}
            <div className={styles.expandIcon} style={{ transform: isExpanded ? 'rotate(180deg)' : 'rotate(0)' }}>
              ▼
            </div>
          </div>

          {/* Expanded Details */}
          {isExpanded && (
            <div className={styles.expandedDetails}>
              <div className={styles.expandedGrid}>
                {/* Left: Alert Details */}
                <div>
                  <h5 className={styles.expandedSectionTitle}>
                    Event Details
                  </h5>

                  {alert.description && (
                    <div className={styles.fieldGroup}>
                      <label className={styles.fieldLabel}>
                        Description
                      </label>
                      <p className={styles.fieldValue}>
                        {alert.description}
                      </p>
                    </div>
                  )}

                  {alert.ai_verdict && (
                    <div className={styles.fieldGroup}>
                      <label className={styles.fieldLabel}>
                        AI Verdict
                      </label>
                      <span className={`${styles.aiVerdictBadge} ${alert.ai_verdict === 'MALICIOUS' ? styles.aiVerdictMalicious : alert.ai_verdict === 'SUSPICIOUS' ? styles.aiVerdictSuspicious : styles.aiVerdictBenign}`}>
                        {alert.ai_verdict}
                      </span>
                    </div>
                  )}

                  {alert.ai_reasoning && (
                    <div className={styles.fieldGroup}>
                      <label className={styles.fieldLabel}>
                        AI Analysis
                      </label>
                      <p className={styles.fieldValueCompact}>
                        {alert.ai_reasoning}
                      </p>
                    </div>
                  )}

                  {alert.mitre_techniques && alert.mitre_techniques.length > 0 && (
                    <div className={styles.fieldGroup}>
                      <label className={styles.fieldLabel}>
                        MITRE ATT&CK
                      </label>
                      <div className={styles.mitreTechRow}>
                        {alert.mitre_techniques.map((tech, idx) => (
                          <span key={idx} className={styles.mitreTechChip}>
                            {tech}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  {alert.extracted_entities && Object.keys(alert.extracted_entities).length > 0 && (
                    <div>
                      <label className={styles.fieldLabel}>
                        Entities
                      </label>
                      <div className={styles.entityChipRow}>
                        {Object.entries(alert.extracted_entities).map(([type, values]) => (
                          Array.isArray(values) && values.length > 0 && (
                            <div key={type} className={styles.entityChip}>
                              <span className={styles.entityChipType}>
                                {type}:
                              </span>
                              <span className={styles.entityChipValue}>
                                {values.slice(0, 3).join(', ')}
                                {values.length > 3 && ` +${values.length - 3}`}
                              </span>
                            </div>
                          )
                        ))}
                      </div>
                    </div>
                  )}
                </div>

                {/* Right: Correlation Explanation */}
                <div>
                  <h5 className={styles.expandedSectionTitle}>
                    Correlation Explanation
                  </h5>

                  {correlation.reasons && correlation.reasons.length > 0 ? (
                    <div style={{
                      background: 'rgba(16, 185, 129, 0.05)',
                      border: '1px solid rgba(16, 185, 129, 0.2)',
                      borderRadius: '6px',
                      padding: '12px'
                    }}>
                      <ul style={{ margin: 0, padding: '0 0 0 16px', listStyle: 'disc' }}>
                        {correlation.reasons.map((reason, idx) => (
                          <li key={idx} className={styles.correlationListItem}>
                            {reason}
                          </li>
                        ))}
                      </ul>
                    </div>
                  ) : (
                    <p className={styles.correlationEmpty}>
                      No correlation details available
                    </p>
                  )}

                  {correlation.matched_entities && correlation.matched_entities.length > 0 && (
                    <div className={styles.fieldGroupSpaced}>
                      <label className={styles.fieldLabel}>
                        Matched Entities
                      </label>
                      <div className={styles.matchedEntityRow}>
                        {correlation.matched_entities.map((entity, idx) => (
                          <span key={idx} className={styles.matchedEntityChip}>
                            {entity}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  {correlation.score !== undefined && (
                    <div className={styles.fieldGroupSpaced}>
                      <label className={styles.fieldLabel}>
                        Correlation Score
                      </label>
                      <div className={styles.correlationScoreBar}>
                        <div className={styles.correlationScoreTrack}>
                          <div className={styles.correlationScoreFill} style={{
                            width: `${Math.min(100, (correlation.score / (correlation.threshold || 100)) * 100)}%`,
                            background: correlation.score >= (correlation.threshold || 100) ? 'var(--success)' : 'var(--warning)'
                          }} />
                        </div>
                        <span className={styles.correlationScoreLabel}>
                          {correlation.score}/{correlation.threshold || 100}
                        </span>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    );
  };

  // Render Timeline View
  const renderTimeline = () => {
    const alertsByDate = getAlertsByDate();
    const dates = Object.keys(alertsByDate);

    if (dates.length === 0) {
      return (
        <div className={styles.emptyLinkedAlerts}>
          <div className={styles.emptyLinkedIcon}>📅</div>
          <p className={styles.emptyLinkedText}>No events to display on timeline</p>
        </div>
      );
    }

    return (
      <div className={styles.linkedTimelineWrap}>
        {dates.map((dateKey, dateIdx) => (
          <div key={dateKey} className={styles.linkedDateGroup}>
            {/* Date Header */}
            <div className={styles.linkedDateHeader}>
              <div className={styles.linkedDateBadge}>
                {formatDateOnly(alertsByDate[dateKey][0]?.created_at)}
              </div>
              <span className={styles.linkedDateCount}>
                {alertsByDate[dateKey].length} event{alertsByDate[dateKey].length !== 1 ? 's' : ''}
              </span>
            </div>

            {/* Events for this date */}
            <div className={styles.linkedDateEvents}>
              {alertsByDate[dateKey].map((alert, idx) =>
                renderTimelineEvent(alert, idx === alertsByDate[dateKey].length - 1 && dateIdx === dates.length - 1)
              )}
            </div>
          </div>
        ))}
      </div>
    );
  };

  // Entity Summary Section
  const renderEntitySummary = () => {
    if (!investigationEntities || Object.keys(investigationEntities).length === 0) {
      return null;
    }

    const entityTypes = [
      { key: 'users', label: 'Users', icon: '', color: '#3b82f6' },
      { key: 'hosts', label: 'Hosts', icon: '', color: '#10b981' },
      { key: 'mitre_techniques', label: 'MITRE Techniques', icon: '', color: '#f59e0b' },
      { key: 'ips', label: 'IP Addresses', icon: '', color: '#8b5cf6' }
    ];

    return (
      <div className={styles.entityRiskSummaryWrap}>
        <h4 className={styles.entityRiskSummaryTitle}>
          Entity Risk Summary
        </h4>
        <div className={styles.entityRiskSummaryGrid}>
          {entityTypes.map(({ key, label, icon, color }) => {
            const entities = investigationEntities[key];
            if (!entities || entities.length === 0) return null;
            return (
              <div key={key} className={styles.entityRiskCard}>
                <div className={styles.entityRiskCardHeader}>
                  <span className={styles.entityRiskCardLabel}>{label}</span>
                  <span className={styles.entityRiskCardCount}>
                    {entities.length}
                  </span>
                </div>
                <div className={styles.entityRiskCardList}>
                  {entities.slice(0, 5).map((entity, idx) => (
                    <div key={idx} className={styles.entityRiskCardRow}>
                      <span className={styles.entityRiskCardValue}>
                        {entity.value || entity}
                      </span>
                      {entity.confidence && (
                        <span className={styles.entityRiskCardConfidence}>
                          {entity.confidence}%
                        </span>
                      )}
                    </div>
                  ))}
                  {entities.length > 5 && (
                    <span className={styles.entityRiskCardMore}>
                      +{entities.length - 5} more
                    </span>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>
    );
  };

  // Look up correlation history entry for a given alert
  const getCorrelationDecision = (alert) => {
    if (!correlationHistory || correlationHistory.length === 0) return null;
    return correlationHistory.find(d =>
      d.alert_id === alert.alert_id ||
      d.alert_id === alert.id ||
      d.alert_external_id === alert.alert_id ||
      d.alert_external_id === alert.id
    ) || null;
  };

  // Build entity overlap data — entities appearing in 2+ alerts
  const entityOverlap = useMemo(() => {
    if (!linkedAlerts || linkedAlerts.length < 2) return [];
    const entityMap = {}; // "type:value" -> { type, value, alertIds: Set }
    linkedAlerts.forEach(alert => {
      const entities = alert.extracted_entities || {};
      Object.entries(entities).forEach(([type, values]) => {
        if (!Array.isArray(values)) return;
        values.forEach(val => {
          const key = `${type}:${val}`;
          if (!entityMap[key]) {
            entityMap[key] = { type, value: val, alertIds: new Set() };
          }
          entityMap[key].alertIds.add(alert.alert_id || alert.id);
        });
      });
    });
    return Object.values(entityMap)
      .filter(e => e.alertIds.size >= 2)
      .sort((a, b) => b.alertIds.size - a.alertIds.size)
      .map(e => ({ ...e, count: e.alertIds.size }));
  }, [linkedAlerts]);

  // Alert Row Component
  const renderAlertRow = (alert, index) => {
    const isExpanded = expandedAlert === alert.id;
    const correlation = alert.correlation || {};
    const corrDecision = getCorrelationDecision(alert);
    const matchedEntities = corrDecision?.matched_entities || correlation.matched_entities || [];
    const corrScore = corrDecision?.correlation_score ?? corrDecision?.score ?? correlation.score;
    const corrReasons = corrDecision?.reasons || correlation.reasons || [];

    return (
      <div key={alert.id || index} className="wb-card" style={{
        background: isExpanded ? 'var(--bg-secondary, #1e293b)' : 'rgba(15, 23, 42, 0.4)',
        borderRadius: '8px',
        marginBottom: '6px',
        border: isExpanded ? '1px solid rgba(59, 130, 246, 0.3)' : '1px solid rgba(148, 163, 184, 0.08)',
        padding: 0
      }}>
        {/* Alert Header Row */}
        <div
          onClick={() => setExpandedAlert(isExpanded ? null : alert.id)}
          style={{
            display: 'grid',
            gridTemplateColumns: '100px 1fr 80px 100px',
            gap: '12px',
            padding: '12px 16px',
            alignItems: 'start',
            cursor: 'pointer',
            transition: 'background 0.15s ease'
          }}
          onMouseEnter={(e) => e.currentTarget.style.background = 'rgba(255,255,255,0.03)'}
          onMouseLeave={(e) => e.currentTarget.style.background = 'transparent'}
        >
          {/* Time + ID */}
          <div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', fontFamily: 'monospace' }}>
              {formatDate(alert.created_at)}
            </div>
            <div style={{ fontFamily: 'monospace', fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: '2px' }}>
              {(alert.alert_id || alert.id || '').slice(0, 12)}
            </div>
          </div>

          {/* Title + correlation chips */}
          <div>
            <div style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '4px' }}>
              {alert.title || 'Untitled Alert'}
            </div>

            {/* Inline correlation chips */}
            <div className="wb-corr-chips">
              {getCorrelationBadge(correlation)}
              {corrScore !== undefined && (
                <span className={`wb-corr-chip--score ${corrScore >= 80 ? 'high' : corrScore >= 50 ? 'mid' : 'low'}`}
                  style={{
                    padding: '1px 6px', borderRadius: '4px', fontSize: '0.65rem', fontWeight: 600,
                    background: corrScore >= 80 ? 'rgba(16,185,129,0.15)' : corrScore >= 50 ? 'rgba(245,158,11,0.15)' : 'rgba(100,116,139,0.15)',
                    color: corrScore >= 80 ? '#10b981' : corrScore >= 50 ? '#f59e0b' : '#94a3b8'
                  }}>
                  {corrScore}/100
                </span>
              )}
              {matchedEntities.slice(0, 4).map((entity, idx) => (
                <span key={idx} className="wb-corr-chip--entity" style={{
                  padding: '1px 6px', borderRadius: '4px', fontSize: '0.65rem',
                  background: 'rgba(59,130,246,0.12)', color: '#60a5fa', fontFamily: 'monospace'
                }}>
                  {typeof entity === 'string' ? entity : `${entity.type}: ${entity.value}`}
                </span>
              ))}
              {matchedEntities.length > 4 && (
                <span style={{ fontSize: '0.65rem', color: 'var(--text-muted)' }}>+{matchedEntities.length - 4}</span>
              )}
              {corrReasons.length > 0 && !isExpanded && (
                <span style={{ fontSize: '0.65rem', color: 'var(--text-secondary)', fontStyle: 'italic' }}
                  title={corrReasons.join('; ')}>
                  {corrReasons[0].length > 50 ? corrReasons[0].slice(0, 50) + '...' : corrReasons[0]}
                </span>
              )}
            </div>
          </div>

          {/* Severity */}
          <div>
            <span style={{
              padding: '2px 8px', borderRadius: '4px', fontSize: '0.65rem', fontWeight: 600,
              background: `${getSeverityColor(alert.severity)}20`, color: getSeverityColor(alert.severity),
              textTransform: 'uppercase'
            }}>
              {alert.severity || 'unknown'}
            </span>
          </div>

          {/* Expand icon */}
          <div style={{ textAlign: 'right', color: 'var(--text-muted)', fontSize: '14px',
            transform: isExpanded ? 'rotate(180deg)' : 'rotate(0)', transition: 'transform 0.2s ease' }}>
            ▼
          </div>
        </div>

        {/* Expanded Details */}
        {isExpanded && (
          <div className={styles.cardExpandedGrid}>
            {/* Left Column - Alert Details */}
            <div>
              <h5 className={styles.expandedSectionTitle}>
                Alert Details
              </h5>

              {alert.description && (
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>
                    Description
                  </label>
                  <p className={styles.fieldValue}>
                    {alert.description}
                  </p>
                </div>
              )}

              {alert.ai_verdict && (
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>
                    AI Verdict
                  </label>
                  <span className={`${styles.aiVerdictBadge} ${alert.ai_verdict === 'MALICIOUS' ? styles.aiVerdictMalicious : alert.ai_verdict === 'SUSPICIOUS' ? styles.aiVerdictSuspicious : styles.aiVerdictBenign}`}>
                    {alert.ai_verdict}
                  </span>
                </div>
              )}

              {alert.ai_reasoning && (
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>
                    AI Reasoning
                  </label>
                  <p className={styles.fieldValueCompact}>
                    {alert.ai_reasoning}
                  </p>
                </div>
              )}

              {alert.mitre_techniques && alert.mitre_techniques.length > 0 && (
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>
                    MITRE ATT&CK Techniques
                  </label>
                  <div className={styles.mitreTechRow}>
                    {alert.mitre_techniques.map((tech, idx) => (
                      <span key={idx} className={styles.mitreTechChip}>
                        {tech}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {alert.extracted_entities && Object.keys(alert.extracted_entities).length > 0 && (
                <div>
                  <label className={styles.fieldLabel}>
                    Extracted Entities
                  </label>
                  <div className={styles.entityChipRow}>
                    {Object.entries(alert.extracted_entities).map(([type, values]) => (
                      Array.isArray(values) && values.length > 0 && (
                        <div key={type} className={styles.entityChip}>
                          <span className={styles.entityChipType}>
                            {type}:
                          </span>
                          <span className={styles.entityChipValue}>
                            {values.slice(0, 3).join(', ')}
                            {values.length > 3 && ` +${values.length - 3}`}
                          </span>
                        </div>
                      )
                    ))}
                  </div>
                </div>
              )}
            </div>

            {/* Right Column - Correlation Explanation */}
            <div>
              <h5 className={styles.expandedSectionTitle}>
                Why This Alert Was Correlated
              </h5>

              {correlation.reasons && correlation.reasons.length > 0 ? (
                <div className={styles.correlationReasonsBox}>
                  <ul className={styles.correlationReasonsList}>
                    {correlation.reasons.map((reason, idx) => (
                      <li key={idx} className={styles.correlationListItem}>
                        {reason}
                      </li>
                    ))}
                  </ul>
                </div>
              ) : (
                <p className={styles.correlationEmpty}>
                  No correlation details available
                </p>
              )}

              {correlation.matched_entities && correlation.matched_entities.length > 0 && (
                <div className={styles.fieldGroupSpaced}>
                  <label className={styles.fieldLabel}>
                    Matched Entity Types
                  </label>
                  <div className={styles.matchedEntityRow}>
                    {correlation.matched_entities.map((entity, idx) => (
                      <span key={idx} className={styles.matchedEntityTag}>
                        {entity}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {correlation.linked_at && (
                <div className={styles.correlationLinkedAt}>
                  Linked at: {formatDate(correlation.linked_at)}
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    );
  };

  return (
    <div>
      {/* Entity Summary */}
      {renderEntitySummary()}

      {/* Header with View Toggle */}
      <div className={styles.linkedAlertsHeader}>
        <h4 className={styles.linkedAlertsTitle}>
          Event Timeline
          <span className={styles.linkedAlertsCount}>
            {(linkedAlerts || []).length} alerts
          </span>
        </h4>

        {/* View Toggle & Controls */}
        <div className={styles.linkedAlertsControls}>
          {/* View Mode Toggle */}
          <div className={styles.viewModeToggle}>
            <button
              onClick={() => setViewMode('timeline')}
              className={viewMode === 'timeline' ? styles.viewModeActive : styles.viewModeInactive}
            >
              <span className={styles.viewModeIcon}>⏱</span> Timeline
            </button>
            <button
              onClick={() => setViewMode('table')}
              className={viewMode === 'table' ? styles.viewModeActive : styles.viewModeInactive}
            >
              <span className={styles.viewModeIcon}>☰</span> Table
            </button>
          </div>

          {/* Sort Controls - only show for table view */}
          {viewMode === 'table' && (
            <div className={styles.sortControls}>
              <label className={styles.sortLabel}>Sort:</label>
              <select
                value={sortBy}
                onChange={(e) => setSortBy(e.target.value)}
                className={styles.sortSelect}
              >
                <option value="created_at">Time</option>
                <option value="severity">Severity</option>
                <option value="score">Score</option>
              </select>
              <button
                onClick={() => setSortOrder(sortOrder === 'desc' ? 'asc' : 'desc')}
                className={styles.sortOrderBtn}
              >
                {sortOrder === 'desc' ? '↓' : '↑'}
              </button>
            </div>
          )}
        </div>
      </div>

      {/* Content based on view mode */}
      {viewMode === 'timeline' ? (
        renderTimeline()
      ) : (
        <>
          {/* Column Headers */}
          <div className={styles.tableColumnHeaders}>
            <div>Time</div>
            <div>Alert</div>
            <div>Severity</div>
            <div></div>
          </div>

          {/* Alert Rows */}
          {sortedAlerts.length > 0 ? (
            sortedAlerts.map((alert, idx) => renderAlertRow(alert, idx))
          ) : (
            <div className={styles.emptyLinkedAlerts}>
              <div className={styles.emptyLinkedIcon}>📋</div>
              <p className={styles.emptyLinkedText}>No linked alerts found for this investigation</p>
              <p className={styles.emptyLinkedSubtext}>
                Alerts will appear here when they are correlated to this investigation
              </p>
            </div>
          )}
        </>
      )}

      {/* Entity Overlap Summary */}
      {entityOverlap.length > 0 && (
        <div className={`wb-entity-overlap ${styles.entityOverlapSpaced}`}>
          <div className="wb-entity-overlap__header">
            <h4 className={styles.entityOverlapTitle}>
              Shared Entities
            </h4>
            <span className={styles.entityOverlapSubtitle}>
              Entities appearing in 2+ alerts
            </span>
          </div>
          <div className={`wb-entity-overlap__grid ${styles.entityOverlapGrid}`}>
            {entityOverlap.slice(0, 12).map((entity, idx) => {
              const typeColors = {
                user: '#3b82f6', host: '#10b981', ip: '#8b5cf6', domain: '#f59e0b',
                email: '#ec4899', hostname: '#06b6d4', url: '#f97316'
              };
              const color = typeColors[entity.type.toLowerCase()] || '#94a3b8';
              return (
                <div key={idx} className={`wb-entity-overlap__item wb-card ${styles.entityOverlapItem}`}>
                  <span className={styles.entityOverlapTypeBadge} style={{
                    background: `${color}20`, color: color
                  }}>
                    {entity.type}
                  </span>
                  <span className={styles.entityOverlapValue}>
                    {entity.value}
                  </span>
                  <span className={entity.count >= 3 ? styles.entityOverlapCountHigh : styles.entityOverlapCountNormal}>
                    {entity.count} alerts
                  </span>
                </div>
              );
            })}
          </div>
          {entityOverlap.length > 12 && (
            <div className={styles.entityOverlapMore}>
              +{entityOverlap.length - 12} more shared entities
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ============================================================================
// ALL IOCs TAB - Full IOC list with inline enrichment
// ============================================================================

function AllIOCsTab({ investigation, alertData }) {
  const [selectedIOC, setSelectedIOC] = useState(null);
  const [enrichmentData, setEnrichmentData] = useState(null);
  const [enrichmentLoading, setEnrichmentLoading] = useState(false);
  const [initialLoadDone, setInitialLoadDone] = useState(false);
  const [isEnriching, setIsEnriching] = useState(false);
  const [copiedIOC, setCopiedIOC] = useState(null);
  const [filterType, setFilterType] = useState('all');
  const [filterVerdict, setFilterVerdict] = useState('all');
  const [batchEnrichProgress, setBatchEnrichProgress] = useState(null); // { current, total }
  const [enrichedReputations, setEnrichedReputations] = useState(new Map()); // ioc.value -> verdict after live enrichment
  const autoEnrichRef = useRef(false); // prevents re-running auto-enrich on re-renders

  let rawEvent = alertData?.raw_event || {};
  if (typeof rawEvent === 'string') {
    try { rawEvent = JSON.parse(rawEvent); } catch { rawEvent = {}; }
  }

  // Collect IOCs from multiple sources
  let iocs = [];

  // Source 1: investigation.extracted_iocs
  if (Array.isArray(investigation?.extracted_iocs)) {
    iocs.push(...investigation.extracted_iocs);
  }

  // Valid IOC types - exclude contextual fields like cron_job, wallet, file_path
  const validIOCTypes = new Set(['ip', 'domain', 'url', 'hash', 'hash_md5', 'hash_sha1', 'hash_sha256', 'email', 'hostname']);
  const isValidIOC = (ioc) => {
    const iocType = (ioc.type || '').toLowerCase();
    return validIOCTypes.has(iocType);
  };

  // Source 2: rawEvent.iocs (from raw_event)
  if (Array.isArray(rawEvent.iocs)) {
    rawEvent.iocs.filter(isValidIOC).forEach(ioc => iocs.push(ioc));
  }

  // Source 3: alertData.iocs (direct on alert for webhook alerts)
  if (Array.isArray(alertData?.iocs)) {
    alertData.iocs.filter(isValidIOC).forEach(ioc => iocs.push(ioc));
  }

  // Source 4: alertData._extracted.iocs (auto-extracted by pipeline)
  const extractedIOCs = alertData?._extracted?.iocs || {};
  if (extractedIOCs) {
    // Handle structured format: {ips: [...], domains: [...], hashes: [...], etc}
    if (Array.isArray(extractedIOCs.ips)) {
      iocs.push(...extractedIOCs.ips.map(v => ({ type: 'ip', value: v })));
    }
    if (Array.isArray(extractedIOCs.domains)) {
      iocs.push(...extractedIOCs.domains.map(v => ({ type: 'domain', value: v })));
    }
    if (Array.isArray(extractedIOCs.hashes)) {
      iocs.push(...extractedIOCs.hashes.map(v => ({ type: 'hash', value: v })));
    }
    if (Array.isArray(extractedIOCs.urls)) {
      iocs.push(...extractedIOCs.urls.map(v => ({ type: 'url', value: v })));
    }
    if (Array.isArray(extractedIOCs.emails)) {
      iocs.push(...extractedIOCs.emails.map(v => ({ type: 'email', value: v })));
    }
  }

  // Source 5: alertData._extracted.enrichment.results (enriched IOCs)
  const enrichmentResults = alertData?._extracted?.enrichment?.results || {};
  ['ips', 'domains', 'hashes', 'urls'].forEach(key => {
    if (Array.isArray(enrichmentResults[key])) {
      enrichmentResults[key].forEach(item => {
        if (item.value) {
          iocs.push({
            type: item.type || key.replace(/s$/, ''),
            value: item.value,
            reputation: item.verdict,
            confidence: item.confidence
          });
        }
      });
    }
  });

  // Source 6: investigation.investigation_data.indicators (RIGGS extracted IOCs)
  const investigationIndicators = investigation?.investigation_data?.indicators || [];
  if (Array.isArray(investigationIndicators)) {
    investigationIndicators.forEach(ind => {
      // Normalize type names (e.g., 'hashe' -> 'hash', 'private_ip' -> 'ip')
      let normalizedType = (ind.type || 'ip').toLowerCase();
      if (normalizedType === 'hashe') normalizedType = 'hash';
      if (normalizedType === 'private_ip') normalizedType = 'ip';
      if (normalizedType === 'file_name') normalizedType = 'hostname'; // Map file_name to hostname for display

      // Skip if not a valid IOC type
      if (!validIOCTypes.has(normalizedType)) return;

      iocs.push({
        type: normalizedType,
        value: ind.value,
        source: ind.source || 'riggs',
        discovered_by: ind.discovered_by
      });
    });
  }

  // Source 7: investigation.investigation_data.riggs_analysis.riggs_extracted_iocs
  const riggsExtracted = investigation?.investigation_data?.riggs_analysis?.riggs_extracted_iocs || {};
  if (riggsExtracted && typeof riggsExtracted === 'object') {
    if (Array.isArray(riggsExtracted.ips)) {
      iocs.push(...riggsExtracted.ips.map(v => ({ type: 'ip', value: v, source: 'riggs' })));
    }
    if (Array.isArray(riggsExtracted.domains)) {
      iocs.push(...riggsExtracted.domains.map(v => ({ type: 'domain', value: v, source: 'riggs' })));
    }
    if (Array.isArray(riggsExtracted.hashes)) {
      iocs.push(...riggsExtracted.hashes.map(v => ({ type: 'hash', value: v, source: 'riggs' })));
    }
    if (Array.isArray(riggsExtracted.urls)) {
      iocs.push(...riggsExtracted.urls.map(v => ({ type: 'url', value: v, source: 'riggs' })));
    }
    if (Array.isArray(riggsExtracted.emails)) {
      iocs.push(...riggsExtracted.emails.map(v => ({ type: 'email', value: v, source: 'riggs' })));
    }
  }

  // Handle case where iocs is an object (e.g., {ip: [...], domain: [...]})
  if (!Array.isArray(iocs) && typeof iocs === 'object' && iocs !== null) {
    iocs = Object.entries(iocs).flatMap(([type, values]) =>
      Array.isArray(values) ? values.map(v => typeof v === 'string' ? { type, value: v } : v) : []
    );
  }
  const uniqueIOCs = iocs.reduce((acc, ioc) => {
    const key = `${ioc.type}-${ioc.value}`;
    if (!acc.has(key)) acc.set(key, ioc);
    return acc;
  }, new Map());
  const dedupedIOCs = Array.from(uniqueIOCs.values());

  // Sort: malicious first, then suspicious, then others
  const sortedIOCs = [...dedupedIOCs].sort((a, b) => {
    const repOrder = { malicious: 0, suspicious: 1, unknown: 2, clean: 3, benign: 3 };
    const aRep = repOrder[(a.reputation || 'unknown').toLowerCase()] ?? 2;
    const bRep = repOrder[(b.reputation || 'unknown').toLowerCase()] ?? 2;
    return aRep - bRep;
  });

  // Apply filters
  const filteredIOCs = sortedIOCs.filter(ioc => {
    if (filterType !== 'all') {
      const t = (ioc.type || '').toLowerCase();
      if (filterType === 'hash' && !t.startsWith('hash')) return false;
      if (filterType !== 'hash' && t !== filterType) return false;
    }
    if (filterVerdict !== 'all') {
      const v = (ioc.reputation || 'unknown').toLowerCase();
      if (filterVerdict === 'clean' && v !== 'clean' && v !== 'benign' && v !== 'safe') return false;
      if (filterVerdict !== 'clean' && v !== filterVerdict) return false;
    }
    return true;
  });

  // Unique IOC types for filter dropdown
  const iocTypes = useMemo(() => {
    const types = new Set(dedupedIOCs.map(i => {
      const t = (i.type || '').toLowerCase();
      return t.startsWith('hash') ? 'hash' : t;
    }));
    return Array.from(types).sort();
  }, [dedupedIOCs]);

  // Copy all visible IOC values
  const copyAllIOCs = () => {
    const values = filteredIOCs.map(i => i.value).join('\n');
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(values);
    } else {
      const ta = document.createElement('textarea');
      ta.value = values;
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
    }
    setCopiedIOC('__all__');
    setTimeout(() => setCopiedIOC(null), 1500);
  };

  // Export CSV
  const exportCSV = () => {
    const header = 'Type,Value,Verdict,Source\n';
    const rows = filteredIOCs.map(i =>
      `"${i.type || ''}","${(i.value || '').replace(/"/g, '""')}","${i.reputation || 'unknown'}","${i.source || ''}"`
    ).join('\n');
    const blob = new Blob([header + rows], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `iocs-${investigation?.investigation_id || 'export'}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  // Batch enrich all IOCs
  const batchEnrich = async () => {
    const toEnrich = filteredIOCs.filter(i => i.value);
    if (toEnrich.length === 0) return;
    setBatchEnrichProgress({ current: 0, total: toEnrich.length });
    for (let i = 0; i < toEnrich.length; i++) {
      try {
        const ioc = toEnrich[i];
        const rawType = ioc.type || 'ip';
        const type = normalizeIOCType(rawType, ioc.value);
        const batchHeaders = { ...getAuthHeaders(), 'Content-Type': 'application/json' };
        const batchCsrf = getCsrfToken();
        if (batchCsrf) batchHeaders['X-CSRF-Token'] = batchCsrf;
        await fetch(`${API_BASE_URL}/api/v1/threat-intel/enrich/stream`, {
          method: 'POST',
          headers: batchHeaders,
          credentials: 'include',
          body: JSON.stringify({ value: ioc.value, type, force_refresh: false })
        });
      } catch {}
      setBatchEnrichProgress({ current: i + 1, total: toEnrich.length });
    }
    setTimeout(() => setBatchEnrichProgress(null), 2000);
  };

  // Detect IOC type
  const detectType = (value) => {
    if (!value) return 'ip';
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(value)) return 'ip';
    if (/^[a-fA-F0-9]{32}$/.test(value)) return 'hash_md5';
    if (/^[a-fA-F0-9]{40}$/.test(value)) return 'hash_sha1';
    if (/^[a-fA-F0-9]{64}$/.test(value)) return 'hash_sha256';
    if (value.startsWith('http://') || value.startsWith('https://')) return 'url';
    if (value.includes('@')) return 'email';
    if (value.includes('.')) return 'domain';
    return 'ip';
  };

  // Map generic 'hash' type to specific hash type based on length
  const normalizeIOCType = (type, value) => {
    if (type === 'hash' && value) {
      if (value.length === 32) return 'hash_md5';
      if (value.length === 40) return 'hash_sha1';
      if (value.length === 64) return 'hash_sha256';
    }
    return type;
  };

  // Fetch enrichment for selected IOC - only gets cached data, doesn't auto-enrich
  const fetchEnrichment = async (iocValue, iocType) => {
    setEnrichmentLoading(true);
    setEnrichmentData(null);
    try {
      const rawType = iocType || detectType(iocValue);
      const type = normalizeIOCType(rawType, iocValue);

      // Try to get cached data from DB - use query param endpoint for URLs with special chars
      const url = `${API_BASE_URL}/api/v1/threat-intel/ioc/lookup?value=${encodeURIComponent(iocValue)}&type=${type}&with_enrichments=true`;

      const response = await fetch(url, {
        headers: getAuthHeaders(),
        credentials: 'include'
      });

      if (response.ok) {
        const data = await response.json();
        // Set data even if enrichments are empty - the panel will show "no data" state
        setEnrichmentData(data);
      } else {
        // IOC not in DB - set empty data so panel shows "no enrichment" message
        setEnrichmentData({ enrichments: [], value: iocValue, type: type });
      }
    } catch (error) {
      // On error, set empty data to stop spinner
      setEnrichmentData({ enrichments: [], value: iocValue, type: iocType });
    }
    setEnrichmentLoading(false);
  };

  // Force enrich IOC - triggers fresh enrichment from all providers with streaming
  const forceEnrichIOC = async (iocValue, iocType) => {
    setIsEnriching(true);

    // Initialize with empty data to show the panel immediately
    setEnrichmentData({
      enrichments: [],
      value: iocValue,
      type: iocType,
      sources_checked: 0,
      sources_flagged: 0,
      provider_status: [],
      _streaming: true
    });

    try {
      const rawType = iocType || detectType(iocValue);
      const type = normalizeIOCType(rawType, iocValue);

      // Create AbortController for timeout
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 90000); // 90 second timeout for streaming

      const enrichHeaders = { ...getAuthHeaders(), 'Content-Type': 'application/json' };
      const csrfToken = getCsrfToken();
      if (csrfToken) enrichHeaders['X-CSRF-Token'] = csrfToken;
      const response = await fetch(`${API_BASE_URL}/api/v1/threat-intel/enrich/stream`, {
        method: 'POST',
        headers: enrichHeaders,
        credentials: 'include',
        body: JSON.stringify({ value: iocValue, type: type, force_refresh: true }),
        signal: controller.signal
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        setEnrichmentData({ enrichments: [], error: 'Enrichment failed', value: iocValue, type: type });
        setIsEnriching(false);
        return;
      }

      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';

      // Accumulate enrichments as they arrive
      const enrichments = [];
      const providerStatuses = [];

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\n');
        buffer = lines.pop() || ''; // Keep incomplete line in buffer

        for (const line of lines) {
          if (line.startsWith('data: ')) {
            try {
              const data = JSON.parse(line.slice(6));

              if (data.event === 'start') {
                // Streaming started
              } else if (data.event === 'result') {
                // Add enrichment result
                if (data.enrichment) {
                  enrichments.push(data.enrichment);
                }
                providerStatuses.push({
                  provider_id: data.provider_id,
                  provider_name: data.provider_name,
                  status: data.status,
                  cached: data.cached,
                  has_data: data.has_data
                });

                // Update state incrementally so widgets appear as data arrives
                setEnrichmentData(prev => ({
                  ...prev,
                  enrichments: [...enrichments],
                  provider_status: [...providerStatuses],
                  sources_checked: data.completed || providerStatuses.length,
                  _streaming: true
                }));
              } else if (data.event === 'complete') {
                // Update local reputation badge for the enriched IOC
                if (data.consensus_verdict) {
                  setEnrichedReputations(prev => {
                    const next = new Map(prev);
                    next.set(iocValue, data.consensus_verdict);
                    return next;
                  });
                }
                setEnrichmentData(prev => ({
                  ...prev,
                  enrichments: [...enrichments],
                  provider_status: data.provider_status || providerStatuses,
                  sources_checked: data.sources_checked,
                  sources_flagged: data.sources_flagged,
                  consensus_verdict: data.consensus_verdict,
                  consensus_score: data.consensus_score,
                  _streaming: false
                }));
              } else if (data.event === 'error') {
                setEnrichmentData(prev => ({
                  ...prev,
                  error: data.error,
                  _streaming: false
                }));
              }
            } catch (e) {
              // Ignore parse errors for incomplete SSE data
            }
          }
        }
      }
    } catch (error) {
      if (error.name === 'AbortError') {
        setEnrichmentData(prev => ({
          ...prev,
          error: 'Request timed out - some providers may be slow or unavailable',
          _streaming: false
        }));
      } else {
        setEnrichmentData(prev => ({
          ...prev,
          error: error.message,
          _streaming: false
        }));
      }
    }
    setIsEnriching(false);
  };

  // Auto-select the first IOC on initial load to show enrichment panel by default
  useEffect(() => {
    if (!initialLoadDone && filteredIOCs.length > 0 && !selectedIOC) {
      setInitialLoadDone(true);
      const firstIOC = filteredIOCs[0];
      setSelectedIOC(firstIOC);
      fetchEnrichment(firstIOC.value, firstIOC.type);
    }
  }, [filteredIOCs, initialLoadDone, selectedIOC]);

  // Auto-enrich all unenriched IOCs silently in the background when the tab first loads
  useEffect(() => {
    if (autoEnrichRef.current || dedupedIOCs.length === 0) return;
    autoEnrichRef.current = true;

    const unenriched = dedupedIOCs.filter(ioc =>
      ioc.value && (!ioc.reputation || ioc.reputation.toLowerCase() === 'unknown')
    );
    if (unenriched.length === 0) return;

    const autoEnrich = async () => {
      for (const ioc of unenriched) {
        try {
          const type = normalizeIOCType(ioc.type || 'ip', ioc.value);
          const headers = { ...getAuthHeaders(), 'Content-Type': 'application/json' };
          const csrf = getCsrfToken();
          if (csrf) headers['X-CSRF-Token'] = csrf;

          const resp = await fetch(`${API_BASE_URL}/api/v1/threat-intel/enrich/stream`, {
            method: 'POST',
            headers,
            credentials: 'include',
            body: JSON.stringify({ value: ioc.value, type, force_refresh: false })
          });
          if (!resp.ok) continue;

          const reader = resp.body.getReader();
          const decoder = new TextDecoder();
          let buf = '';
          while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            buf += decoder.decode(value, { stream: true });
            const lines = buf.split('\n');
            buf = lines.pop() || '';
            for (const line of lines) {
              if (line.startsWith('data: ')) {
                try {
                  const evt = JSON.parse(line.slice(6));
                  if (evt.event === 'complete' && evt.consensus_verdict) {
                    setEnrichedReputations(prev => {
                      const next = new Map(prev);
                      next.set(ioc.value, evt.consensus_verdict);
                      return next;
                    });
                  }
                } catch {}
              }
            }
          }
        } catch {}
      }
    };

    autoEnrich();
  }, [investigation?.investigation_id]);

  // Copy IOC value to clipboard (with fallback for non-HTTPS contexts like Firefox)
  const copyToClipboard = (value) => {
    const onSuccess = () => {
      setCopiedIOC(value);
      setTimeout(() => setCopiedIOC(null), 1500);
    };

    const fallbackCopy = () => {
      const textarea = document.createElement('textarea');
      textarea.value = value;
      textarea.style.position = 'fixed';
      textarea.style.opacity = '0';
      document.body.appendChild(textarea);
      textarea.select();
      try {
        document.execCommand('copy');
        onSuccess();
      } catch (e) {
      }
      document.body.removeChild(textarea);
    };

    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(value).then(onSuccess).catch(fallbackCopy);
    } else {
      fallbackCopy();
    }
  };

  const handleIOCClick = (ioc) => {
    if (selectedIOC?.value === ioc.value) {
      // Already selected - copy to clipboard on second click
      copyToClipboard(ioc.value);
      return;
    } else {
      // First click - just select, don't copy
      setSelectedIOC(ioc);
      fetchEnrichment(ioc.value, ioc.type);
    }
  };

  // Get enrichment age text for an IOC
  const getEnrichmentAge = (ioc) => {
    // Check enrichment results for this specific IOC
    const results = alertData?._extracted?.enrichment?.results || {};
    let lastEnriched = null;
    ['ips', 'domains', 'hashes', 'urls'].forEach(key => {
      if (Array.isArray(results[key])) {
        const match = results[key].find(r => r.value === ioc.value);
        if (match?.enriched_at || match?.last_enriched || match?.timestamp) {
          const ts = new Date(match.enriched_at || match.last_enriched || match.timestamp);
          if (!lastEnriched || ts > lastEnriched) lastEnriched = ts;
        }
      }
    });
    if (!lastEnriched) return null;
    const ageMs = Date.now() - lastEnriched.getTime();
    const ageHours = ageMs / (1000 * 60 * 60);
    if (ageHours < 1) return { text: `${Math.round(ageMs / 60000)}m ago`, color: '#22c55e' };
    if (ageHours < 24) return { text: `${Math.round(ageHours)}h ago`, color: '#f59e0b' };
    const ageDays = Math.round(ageHours / 24);
    return { text: `${ageDays}d ago`, color: '#ef4444' };
  };

  return (
    <div className="all-iocs-tab">
      {/* IOC Toolbar */}
      <div className={`wb-ioc-toolbar ${styles.iocToolbar}`}>
        <select value={filterType} onChange={e => setFilterType(e.target.value)}
          className={`wb-ioc-toolbar__select ${styles.iocToolbarSelect}`}>
          <option value="all">All Types</option>
          {iocTypes.map(t => <option key={t} value={t}>{t.toUpperCase()}</option>)}
        </select>

        <select value={filterVerdict} onChange={e => setFilterVerdict(e.target.value)}
          className={`wb-ioc-toolbar__select ${styles.iocToolbarSelect}`}>
          <option value="all">All Verdicts</option>
          <option value="malicious">Malicious</option>
          <option value="suspicious">Suspicious</option>
          <option value="clean">Clean</option>
          <option value="unknown">Unknown</option>
        </select>

        <span className={styles.iocToolbarCount}>
          {filteredIOCs.length}/{dedupedIOCs.length} IOCs
        </span>

        <div className={styles.iocToolbarActions}>
          {batchEnrichProgress && (
            <span className={styles.batchEnrichProgress}>
              Enriching {batchEnrichProgress.current}/{batchEnrichProgress.total}
            </span>
          )}
          {copiedIOC === '__all__' && (
            <span className={styles.copyAllConfirm}>Copied all!</span>
          )}
          <button onClick={copyAllIOCs} title="Copy all IOC values" className={styles.iocToolbarBtnCopy}>
            Copy All
          </button>
          <button onClick={exportCSV} title="Export as CSV" className={styles.iocToolbarBtnExport}>
            Export CSV
          </button>
          <button onClick={batchEnrich} disabled={!!batchEnrichProgress} title="Enrich all visible IOCs" className={styles.iocToolbarBtn} style={{
            background: batchEnrichProgress ? 'rgba(100,116,139,0.1)' : 'rgba(139,92,246,0.1)',
            border: `1px solid ${batchEnrichProgress ? 'rgba(100,116,139,0.2)' : 'rgba(139,92,246,0.2)'}`,
            color: batchEnrichProgress ? '#94a3b8' : '#a78bfa',
            cursor: batchEnrichProgress ? 'not-allowed' : 'pointer'
          }}>
            Enrich All
          </button>
        </div>
      </div>

      {/* IOC List */}
      <div className="all-iocs-list">
        <div className="all-iocs-list__header">
          <span>Indicators ({filteredIOCs.length})</span>
          <span className={styles.iocListSubtitle}>
            Click to view enrichment
          </span>
        </div>

        <div className="all-iocs-list__items">
          {filteredIOCs.map((ioc, idx) => {
            const displayReputation = enrichedReputations.get(ioc.value) || ioc.reputation;
            const rep = (displayReputation || 'unknown').toLowerCase();
            const isMalicious = rep === 'malicious';
            const isSuspicious = rep === 'suspicious';
            const isClean = rep === 'clean' || rep === 'benign' || rep === 'safe';
            const isSelected = selectedIOC?.value === ioc.value;
            const enrichAge = getEnrichmentAge(ioc);

            const itemClasses = [
              'all-iocs-item',
              isSelected && 'all-iocs-item--selected',
              isMalicious && 'all-iocs-item--malicious',
              isSuspicious && 'all-iocs-item--suspicious',
              isClean && !isMalicious && !isSuspicious && 'all-iocs-item--clean',
            ].filter(Boolean).join(' ');

            return (
              <div
                key={idx}
                className={itemClasses}
                onClick={() => handleIOCClick(ioc)}
                onDoubleClick={(e) => {
                  e.preventDefault();
                  e.stopPropagation();
                  copyToClipboard(ioc.value);
                }}
              >
                <span
                  className="all-iocs-item__type"
                  style={{
                    color: getIOCTypeColor(ioc.type),
                    background: `${getIOCTypeColor(ioc.type)}15`,
                  }}
                >
                  {ioc.type || 'IOC'}
                </span>

                <div className={styles.iocItemMeta}>
                  <div className="all-iocs-item__value">
                    {ioc.value}
                  </div>
                  <div className={styles.iocItemMetaRow}>
                    {displayReputation && (
                      <span
                        className="all-iocs-item__reputation"
                        style={{
                          background: `${getReputationColor(displayReputation)}20`,
                          color: getReputationColor(displayReputation),
                        }}
                      >
                        {displayReputation}
                      </span>
                    )}
                    {enrichAge && (
                      <span className={styles.enrichAgeText} style={{ color: enrichAge.color }}>
                        {enrichAge.text}
                      </span>
                    )}
                    {!enrichAge && !enrichedReputations.has(ioc.value) && (
                      <span className={styles.notEnrichedText}>
                        Not enriched
                      </span>
                    )}
                    {!enrichAge && enrichedReputations.has(ioc.value) && (
                      <span className={styles.justNowText}>
                        just now
                      </span>
                    )}
                  </div>
                </div>

                {/* One-touch action buttons for malicious/suspicious IOCs */}
                {(isMalicious || isSuspicious) && (
                  <IOCActionButtons
                    iocType={ioc.type}
                    iocValue={ioc.value}
                    investigationId={investigation?.investigation_id || investigation?.id}
                    compact
                  />
                )}

                {copiedIOC === ioc.value && (
                  <span className="all-iocs-item__copied">Copied!</span>
                )}
                {isSelected && (
                  <span className={styles.selectedArrow}>→</span>
                )}
              </div>
            );
          })}
        </div>
      </div>

      {/* Enrichment Detail Panel - Always visible */}
      <div className="all-iocs-enrichment-panel">
        {selectedIOC ? (
          <div className={styles.iocItemMeta} style={{ overflowY: 'auto', overflowX: 'hidden' }}>
            <IOCEnrichmentPanel
              ioc={selectedIOC}
              enrichmentData={enrichmentData}
              loading={enrichmentLoading}
              isEnriching={isEnriching}
              onEnrich={() => forceEnrichIOC(selectedIOC.value, selectedIOC.type)}
              onClose={() => { setSelectedIOC(null); setEnrichmentData(null); }}
            />
          </div>
        ) : (
          <div className="all-iocs-enrichment-panel__empty">
            <div>
              <div className={styles.enrichPanelEmptyLabel}>IOC Enrichment</div>
              <div className={styles.enrichPanelEmptyHint}>Select an indicator from the list to view enrichment details</div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

// ============================================================================
// IOC ENRICHMENT PANEL - Rich threat intel display (matching IOCDetail)
// ============================================================================

function IOCEnrichmentPanel({ ioc, enrichmentData, loading, isEnriching, onEnrich, onClose }) {
  const enrichments = enrichmentData?.enrichments || [];

  // Helper to find enrichment by provider - more flexible matching
  const findEnrichment = (providers) => {
    const names = Array.isArray(providers) ? providers : [providers];
    return enrichments.find(e => {
      const providerName = (e.provider || '').toLowerCase().replace(/[_-]/g, '');
      return names.some(n => {
        const searchName = n.toLowerCase().replace(/[_-]/g, '');
        return providerName === searchName || providerName.includes(searchName) || searchName.includes(providerName);
      });
    });
  };

  const vtEnrichment = findEnrichment(['virustotal', 'vt', 'virus_total']);
  const otxEnrichment = findEnrichment(['otx', 'alienvault_otx', 'alienvault', 'alien_vault']);
  const abuseipdbEnrichment = findEnrichment(['abuseipdb', 'abuse_ipdb', 'abuse']);
  const urlscanEnrichment = findEnrichment(['urlscan', 'urlscanio', 'urlscan_io']);
  const ipinfoEnrichment = findEnrichment(['ipinfo', 'ip_info']);
  const rdapEnrichment = findEnrichment(['rdap', 'rdap_arin', 'rdap_verisign', 'rdap_ripe', 'rdap_apnic', 'whois']);
  const shodanEnrichment = findEnrichment(['shodan']);
  const greynoiseEnrichment = findEnrichment(['greynoise', 'grey_noise']);

  // Get VT data
  const getVtAttrs = (rawData) => {
    if (!rawData) return null;
    if (rawData.data?.attributes) return rawData.data.attributes;
    if (rawData.attributes) return rawData.attributes;
    if (rawData.last_analysis_stats) return rawData;
    return null;
  };

  const vtAttrs = getVtAttrs(vtEnrichment?.raw_data) || {};
  const vtStats = vtAttrs.last_analysis_stats || {};
  const vtTotal = (vtStats.malicious || 0) + (vtStats.harmless || 0) + (vtStats.undetected || 0) + (vtStats.suspicious || 0);

  // Calculate threat level
  let threatLevel = 'unknown';
  let reasons = [];

  if (vtStats.malicious > 0) {
    threatLevel = vtStats.malicious >= 5 ? 'malicious' : 'suspicious';
    reasons.push(`${vtStats.malicious}/${vtTotal} vendors flagged as malicious`);
  } else if (vtTotal > 0) {
    threatLevel = 'clean';
    reasons.push(`0/${vtTotal} vendors flagged`);
  }

  const pulseCount = otxEnrichment?.raw_data?.pulse_info?.count || 0;
  if (pulseCount > 0) {
    reasons.push(`Found in ${pulseCount} OTX pulse${pulseCount !== 1 ? 's' : ''}`);
  }

  const abuseScore = abuseipdbEnrichment?.raw_data?.data?.abuseConfidenceScore || 0;
  if (abuseScore > 0) {
    reasons.push(`${abuseScore}% AbuseIPDB confidence`);
  }

  const getThemeColor = () => {
    const root = getComputedStyle(document.documentElement);
    switch (threatLevel) {
      case 'malicious': return root.getPropertyValue('--danger').trim() || '#dc2626';
      case 'suspicious': return root.getPropertyValue('--warning').trim() || '#f59e0b';
      case 'clean': return root.getPropertyValue('--success').trim() || '#22c55e';
      default: return root.getPropertyValue('--text-muted').trim() || '#6b7280';
    }
  };

  const themeColor = getThemeColor();

  // Provider status for enriching indicator - this is an array from ThreatIntelReport
  const providerStatusArray = enrichmentData?.provider_status || [];
  const sourcesChecked = enrichmentData?.sources_checked || 0;
  const sourcesFlagged = enrichmentData?.sources_flagged || 0;
  const consensusVerdict = enrichmentData?.consensus_verdict || enrichmentData?.overall_verdict;
  const consensusScore = enrichmentData?.consensus_score;
  const allProviders = ['VirusTotal', 'AlienVault OTX', 'AbuseIPDB', 'URLScan', 'IPInfo', 'RDAP', 'Shodan', 'GreyNoise'];

  if (loading) {
    return (
      <div className={styles.enrichmentLoadingWrap}>
        <div className="spinner" style={{ margin: '0 auto 0.5rem', width: '24px', height: '24px' }} />
        <div className={styles.enrichmentLoadingText}>Loading cached data...</div>
      </div>
    );
  }

  return (
    <div>
      {/* Enriching in Progress Indicator */}
      {isEnriching && (
        <div className="enrichment-streaming">
          <div className={styles.enrichmentStreamingRow}>
            <div className="spinner" style={{ width: '14px', height: '14px', borderWidth: '2px' }} />
            <span className={styles.enrichmentStreamingLabel}>Enriching from threat intel providers...</span>
          </div>
          <div className="enrichment-streaming__chips">
            {allProviders.map((provider) => {
              const isLoaded = enrichments.some(e =>
                e.provider?.toLowerCase().includes(provider.toLowerCase().replace(/\s+/g, '').substring(0, 6))
              );
              return (
                <span key={provider} className="enrichment-streaming__chip" style={{
                  background: isLoaded ? 'rgba(34, 197, 94, 0.15)' : 'rgba(107, 114, 128, 0.2)',
                  color: isLoaded ? '#22c55e' : 'var(--text-muted)',
                }}>
                  {isLoaded ? '✓' : <span className="spinner" style={{ width: '8px', height: '8px', borderWidth: '1px' }} />}
                  {provider}
                </span>
              );
            })}
          </div>
        </div>
      )}

      {/* Provider Status Summary - shows what was checked after enrichment */}
      {!isEnriching && providerStatusArray.length > 0 && (
        <div className="enrichment-providers">
          <div className={styles.enrichmentProviderSummaryRow}>
            <span className={styles.enrichmentProviderSummaryText}>
              {sourcesChecked} provider{sourcesChecked !== 1 ? 's' : ''} checked, {sourcesFlagged} flagged as malicious
            </span>
            {consensusVerdict && (
              <span className={styles.consensusBadge} style={{
                background: consensusVerdict === 'malicious' ? 'rgba(220, 38, 38, 0.15)' :
                  consensusVerdict === 'suspicious' ? 'rgba(245, 158, 11, 0.15)' :
                    consensusVerdict === 'clean' ? 'rgba(34, 197, 94, 0.15)' : 'rgba(107, 114, 128, 0.15)',
                color: consensusVerdict === 'malicious' ? '#dc2626' :
                  consensusVerdict === 'suspicious' ? '#f59e0b' :
                    consensusVerdict === 'clean' ? '#22c55e' : 'var(--text-muted)'
              }}>
                {consensusVerdict}
              </span>
            )}
          </div>
          <div className="enrichment-providers__chips">
            {providerStatusArray.map((ps, idx) => {
              const statusColor = ps.status === 'success' || ps.status === 'cached' ? '#22c55e' :
                ps.status === 'failed' || ps.status === 'error' ? '#ef4444' :
                  ps.status === 'rate_limited' ? '#f59e0b' : '#6b7280';
              return (
                <span key={idx} title={ps.message || ps.status} className="enrichment-providers__chip" style={{
                  background: `${statusColor}15`,
                  color: statusColor,
                }}>
                  {ps.status === 'success' || ps.status === 'cached' ? '✓' :
                    ps.status === 'failed' || ps.status === 'error' ? '✗' :
                      ps.status === 'rate_limited' ? '⏳' : '○'}
                  {ps.provider_name || ps.provider_id}
                </span>
              );
            })}
          </div>
        </div>
      )}

      {/* Header */}
      <div className="enrichment-header">
        <div>
          <div className="enrichment-header__badges">
            <span className="enrichment-header__badge" style={{
              background: `${themeColor}20`,
              color: themeColor,
            }}>
              {threatLevel}
            </span>
            <span className="enrichment-header__badge" style={{
              background: '#3CB37120',
              color: '#3CB371',
            }}>
              {ioc.type}
            </span>
          </div>
          <div className="enrichment-header__value">
            {ioc.value}
          </div>
        </div>
        <div className={styles.enrichmentActions}>
          <button
            onClick={() => onEnrich()}
            disabled={isEnriching}
            className="enrichment-enrich-btn"
          >
            {isEnriching ? (
              <>
                <span className="spinner" style={{ width: '12px', height: '12px', borderWidth: '2px' }} />
                Enriching...
              </>
            ) : (
              <>Enrich IOC</>
            )}
          </button>
          <button
            onClick={onClose}
            className={styles.enrichmentCloseBtn}
          >
            ×
          </button>
        </div>
      </div>

      {/* Quick Stats Row — only show cells for providers that returned data */}
      {enrichments.length > 0 && (() => {
        const cells = [];
        if (vtTotal > 0) {
          cells.push(
            <div key="vt" className="enrichment-stats__cell">
              <div className="enrichment-stats__value" style={{ color: vtStats.malicious > 0 ? 'var(--danger, #ef4444)' : 'var(--text-primary)' }}>
                {vtStats.malicious || 0}/{vtTotal}
              </div>
              <div className="enrichment-stats__label">VT</div>
            </div>
          );
        }
        if (otxEnrichment) {
          cells.push(
            <div key="otx" className="enrichment-stats__cell">
              <div className="enrichment-stats__value" style={{ color: pulseCount > 0 ? 'var(--warning, #f59e0b)' : 'var(--text-primary)' }}>
                {pulseCount}
              </div>
              <div className="enrichment-stats__label">OTX</div>
            </div>
          );
        }
        if (abuseipdbEnrichment?.raw_data?.data) {
          cells.push(
            <div key="abuse" className="enrichment-stats__cell">
              <div className="enrichment-stats__value" style={{ color: abuseScore > 50 ? 'var(--danger, #ef4444)' : abuseScore > 20 ? 'var(--warning, #f59e0b)' : 'var(--text-primary)' }}>
                {abuseScore}%
              </div>
              <div className="enrichment-stats__label">Abuse</div>
            </div>
          );
        }
        if (urlscanEnrichment) {
          cells.push(
            <div key="scan" className="enrichment-stats__cell">
              <div className="enrichment-stats__value" style={{ color: 'var(--text-primary)' }}>
                {urlscanEnrichment?.raw_data?.page ? 1 : (urlscanEnrichment?.raw_data?.results?.length || 0)}
              </div>
              <div className="enrichment-stats__label">Scan</div>
            </div>
          );
        }
        if (cells.length === 0) return null;
        return (
          <div className="enrichment-stats" style={{ gridTemplateColumns: `repeat(${cells.length}, 1fr)` }}>
            {cells}
          </div>
        );
      })()}

      {/* Empty state — enriched but no threat signals found */}
      {enrichments.length > 0 && threatLevel !== 'malicious' && threatLevel !== 'suspicious' && reasons.length === 0 && (
        <div style={{
          padding: '0.75rem',
          background: 'rgba(34, 197, 94, 0.06)',
          border: '1px solid rgba(34, 197, 94, 0.15)',
          borderRadius: '5px',
          marginBottom: '0.5rem',
          fontSize: '0.75rem',
          color: 'var(--text-secondary)',
          textAlign: 'center'
        }}>
          <div style={{ fontWeight: 600, color: 'var(--success, #22c55e)', marginBottom: '0.15rem' }}>No threat intel matches</div>
          <div style={{ color: 'var(--text-muted)', fontSize: '0.7rem' }}>
            Checked {enrichments.length} source{enrichments.length !== 1 ? 's' : ''} — IOC does not appear in any threat feeds
          </div>
        </div>
      )}

      {/* Not yet enriched empty state */}
      {enrichments.length === 0 && !isEnriching && (
        <div style={{
          padding: '1rem',
          background: 'rgba(107, 114, 128, 0.08)',
          border: '1px dashed rgba(107, 114, 128, 0.25)',
          borderRadius: '5px',
          marginBottom: '0.5rem',
          fontSize: '0.75rem',
          color: 'var(--text-muted)',
          textAlign: 'center'
        }}>
          This IOC has not been enriched yet. Click "Enrich IOC" above to query threat intel sources.
        </div>
      )}

      {/* Vendor Flags Summary */}
      {reasons.length > 0 && (
        <div className="enrichment-reasons" style={{
          background: `${themeColor}10`,
          borderLeft: `2px solid ${themeColor}`
        }}>
          {reasons.map((reason, i) => (
            <div key={i} className={styles.enrichmentReasonRow} style={{
              marginBottom: i < reasons.length - 1 ? '0.2rem' : 0
            }}>
              <span style={{ color: themeColor }}>•</span>
              {reason}
            </div>
          ))}
        </div>
      )}

      {/* Vendor Consensus / Conflict Badge */}
      {enrichments.length >= 2 && (() => {
        const vendorVerdicts = enrichments.map(e => {
          let verdict = 'unknown';
          if (e.provider?.toLowerCase().includes('virustotal')) {
            const stats = e.raw_data?.data?.attributes?.last_analysis_stats || e.raw_data?.attributes?.last_analysis_stats || e.raw_data?.last_analysis_stats || {};
            verdict = (stats.malicious || 0) >= 5 ? 'malicious' : (stats.malicious || 0) > 0 ? 'suspicious' : 'clean';
          } else if (e.provider?.toLowerCase().includes('abuse')) {
            const score = e.raw_data?.data?.abuseConfidenceScore || 0;
            verdict = score > 50 ? 'malicious' : score > 20 ? 'suspicious' : 'clean';
          } else if (e.provider?.toLowerCase().includes('otx')) {
            const pulses = e.raw_data?.pulse_info?.count || 0;
            verdict = pulses > 5 ? 'malicious' : pulses > 0 ? 'suspicious' : 'clean';
          } else if (e.provider?.toLowerCase().includes('greynoise')) {
            const classification = e.raw_data?.classification || '';
            verdict = classification === 'malicious' ? 'malicious' : classification === 'benign' ? 'clean' : 'unknown';
          } else if (e.provider?.toLowerCase().includes('shodan')) {
            const vulns = e.raw_data?.vulns?.length || 0;
            verdict = vulns > 3 ? 'suspicious' : 'clean';
          }
          return { provider: e.provider, verdict };
        }).filter(v => v.verdict !== 'unknown');

        if (vendorVerdicts.length < 2) return null;

        const verdictCounts = {};
        vendorVerdicts.forEach(v => { verdictCounts[v.verdict] = (verdictCounts[v.verdict] || 0) + 1; });
        const majorityVerdict = Object.entries(verdictCounts).sort((a, b) => b[1] - a[1])[0];
        const isConsensus = majorityVerdict[1] === vendorVerdicts.length;
        const consensusColor = majorityVerdict[0] === 'malicious' ? '#dc2626' : majorityVerdict[0] === 'suspicious' ? '#f59e0b' : '#22c55e';

        return (
          <div className={styles.vendorConsensusWrap} style={{
            background: isConsensus ? `${consensusColor}08` : 'rgba(245,158,11,0.08)',
            border: `1px solid ${isConsensus ? `${consensusColor}25` : 'rgba(245,158,11,0.25)'}`,
          }}>
            <div className={styles.enrichmentStreamingRow} style={{ marginBottom: '6px' }}>
              <span className={styles.vendorConsensusBadge} style={{
                background: isConsensus ? `${consensusColor}20` : 'rgba(245,158,11,0.2)',
                color: isConsensus ? consensusColor : '#f59e0b'
              }}>
                {isConsensus ? 'Consensus' : 'Split Verdict'}
              </span>
              <span className={styles.vendorConsensusText}>
                {isConsensus
                  ? `${majorityVerdict[0]} (${vendorVerdicts.length}/${vendorVerdicts.length})`
                  : `${majorityVerdict[1]}/${vendorVerdicts.length} ${majorityVerdict[0]}`}
              </span>
            </div>
            {!isConsensus && (
              <div className={styles.vendorConsensusChips}>
                {vendorVerdicts.map((v, i) => {
                  const vc = v.verdict === 'malicious' ? '#dc2626' : v.verdict === 'suspicious' ? '#f59e0b' : '#22c55e';
                  return (
                    <span key={i} className={styles.vendorConsensusChip} style={{
                      background: `${vc}15`, color: vc
                    }}>
                      {(v.provider || '').split('_')[0]}: {v.verdict}
                    </span>
                  );
                })}
              </div>
            )}
          </div>
        );
      })()}

      {/* VirusTotal Section */}
      {vtEnrichment && (
        <div className="enrichment-vendor">
          <div className="enrichment-vendor__title" style={{ color: 'var(--text-secondary)' }}>
            <span style={{ color: 'var(--text-muted)', opacity: 0.6 }}>•</span> VirusTotal
          </div>
          <div className="enrichment-vendor__grid">
            <div className="enrichment-vendor__stat">
              <div className="enrichment-vendor__stat-value" style={{ color: vtStats.malicious > 0 ? 'var(--danger, #ef4444)' : 'var(--text-primary)' }}>{vtStats.malicious || 0}</div>
              <div className="enrichment-vendor__stat-label">Malicious</div>
            </div>
            <div className="enrichment-vendor__stat">
              <div className="enrichment-vendor__stat-value" style={{ color: vtStats.suspicious > 0 ? 'var(--warning, #f59e0b)' : 'var(--text-primary)' }}>{vtStats.suspicious || 0}</div>
              <div className="enrichment-vendor__stat-label">Suspicious</div>
            </div>
            <div className="enrichment-vendor__stat">
              <div className="enrichment-vendor__stat-value" style={{ color: 'var(--text-primary)' }}>{vtStats.harmless || 0}</div>
              <div className="enrichment-vendor__stat-label">Clean</div>
            </div>
          </div>
          {/* Detection bar */}
          {vtTotal > 0 && (
            <div>
              <div className="enrichment-detection-bar">
                <div className="enrichment-detection-bar__segment" style={{ width: `${(vtStats.malicious / vtTotal) * 100}%`, background: '#dc2626' }} />
                <div className="enrichment-detection-bar__segment" style={{ width: `${(vtStats.suspicious / vtTotal) * 100}%`, background: '#f59e0b' }} />
                <div className="enrichment-detection-bar__segment" style={{ width: `${(vtStats.harmless / vtTotal) * 100}%`, background: '#22c55e' }} />
              </div>
              <div className={styles.vtVendorsLabel}>
                {vtTotal} vendors {vtAttrs.reputation !== undefined && <span>• Rep: <strong style={{ color: vtAttrs.reputation < 0 ? '#dc2626' : '#22c55e' }}>{vtAttrs.reputation}</strong></span>}
              </div>
            </div>
          )}
        </div>
      )}

      {/* AlienVault OTX Section — hide when no pulses AND no validation AND no malware family */}
      {otxEnrichment && (() => {
        const hasValidation = otxEnrichment.raw_data?.validation?.length > 0;
        const hasMalware = (otxEnrichment.raw_data?.pulse_info?.related?.alienvault?.malware_families?.length || 0) +
                           (otxEnrichment.raw_data?.pulse_info?.related?.other?.malware_families?.length || 0) > 0;
        const showSection = pulseCount > 0 || hasValidation || hasMalware;
        if (!showSection) return null;
        return (
        <div className="enrichment-vendor">
          <div className="enrichment-vendor__title" style={{ color: 'var(--text-secondary)' }}>
            <span style={{ color: 'var(--text-muted)', opacity: 0.6 }}>•</span> AlienVault OTX
          </div>
          <div className={styles.otxFlexRow}>
            <div className={styles.otxPulseBox}>
              <span className={styles.otxPulseCount} style={{ color: pulseCount > 0 ? 'var(--warning, #f59e0b)' : 'var(--text-primary)' }}>{pulseCount}</span>
              <span className={styles.otxPulseLabel}>pulses</span>
            </div>
            {/* Malware family tags */}
            {pulseCount > 0 && otxEnrichment.raw_data?.pulse_info?.related && (
              <>
                {[...(otxEnrichment.raw_data.pulse_info.related.alienvault?.malware_families || []),
                  ...(otxEnrichment.raw_data.pulse_info.related.other?.malware_families || [])].slice(0, 4).map((fam, i) => (
                  <span key={i} className={styles.malwareFamilyTag}>{fam}</span>
                ))}
              </>
            )}
            {/* Validation info when no pulses (whitelisted, popular domain, etc.) */}
            {pulseCount === 0 && otxEnrichment.raw_data?.validation && otxEnrichment.raw_data.validation.length > 0 && (
              <>
                {otxEnrichment.raw_data.validation.slice(0, 3).map((v, i) => (
                  <span key={i} className={styles.validationTag}>{v.name || v.message}</span>
                ))}
              </>
            )}
            {/* Domain info when available */}
            {otxEnrichment.raw_data?.domain && !otxEnrichment.raw_data?.validation?.length && pulseCount === 0 && (
              <span className={styles.noThreatsTag}>No threats found</span>
            )}
          </div>
        </div>
        );
      })()}

      {/* AbuseIPDB Section — hide when 0% confidence AND 0 reports AND no usage type */}
      {abuseipdbEnrichment?.raw_data?.data && (abuseScore > 0 || abuseipdbEnrichment.raw_data.data.totalReports > 0 || abuseipdbEnrichment.raw_data.data.usageType) && (
        <div className="enrichment-vendor">
          <div className="enrichment-vendor__title" style={{ color: 'var(--text-secondary)' }}>
            <span style={{ color: 'var(--text-muted)', opacity: 0.6 }}>•</span> AbuseIPDB
          </div>
          <div className={styles.abuseFlexRow}>
            <div className={styles.abuseStatBox}>
              <span className={styles.abuseStatValue} style={{ color: abuseScore > 50 ? 'var(--danger, #ef4444)' : abuseScore > 20 ? 'var(--warning, #f59e0b)' : 'var(--text-primary)' }}>{abuseScore}%</span>
              <span className={styles.abuseStatLabel}>conf</span>
            </div>
            <div className={styles.abuseStatBox}>
              <span className={styles.abuseStatValue} style={{ color: 'var(--text-primary)' }}>{abuseipdbEnrichment.raw_data.data.totalReports || 0}</span>
              <span className={styles.abuseStatLabel}>reports</span>
            </div>
            {abuseipdbEnrichment.raw_data.data.usageType && (
              <span className={styles.abuseUsageType}>{abuseipdbEnrichment.raw_data.data.usageType}</span>
            )}
          </div>
        </div>
      )}

      {/* WHOIS / Network Section */}
      {(vtAttrs.whois || rdapEnrichment?.raw_data) && (
        <div className="enrichment-vendor">
          <div className="enrichment-vendor__title" style={{ color: 'var(--text-secondary)' }}>
            <span style={{ color: 'var(--text-muted)', opacity: 0.6 }}>•</span> WHOIS / Network
            {rdapEnrichment && <span className={styles.whoisEmpty} style={{ fontSize: '0.65rem' }}>(RDAP)</span>}
          </div>
          {(() => {
            const whoisData = {};
            const rdap = rdapEnrichment?.raw_data || {};

            // Extract RDAP data
            if (rdap.startAddress && rdap.endAddress) whoisData['NetRange'] = `${rdap.startAddress} - ${rdap.endAddress}`;
            if (rdap.cidr0_cidrs?.[0]) {
              const cidr = rdap.cidr0_cidrs[0];
              whoisData['CIDR'] = `${cidr.v4prefix || cidr.v6prefix || ''}/${cidr.length || ''}`;
            }
            if (rdap.name) whoisData['NetName'] = rdap.name;
            if (rdap.type) whoisData['NetType'] = rdap.type;

            // Extract org name from RDAP entities
            if (rdap.entities) {
              for (const entity of rdap.entities) {
                const vcard = entity.vcardArray?.[1] || [];
                for (const item of vcard) {
                  if (item[0] === 'fn' && item[3] && !whoisData['OrgName']) {
                    whoisData['OrgName'] = item[3];
                    break;
                  }
                }
              }
            }

            // Extract dates from RDAP events
            if (rdap.events) {
              for (const event of rdap.events) {
                if (event.eventAction === 'registration' && event.eventDate) {
                  whoisData['RegDate'] = event.eventDate.split('T')[0];
                }
                if (event.eventAction === 'last changed' && event.eventDate) {
                  whoisData['Updated'] = event.eventDate.split('T')[0];
                }
              }
            }

            if (rdap.handle) whoisData['Handle'] = rdap.handle;

            const entries = Object.entries(whoisData);
            if (entries.length > 0) {
              return (
                <div className={styles.whoisGrid}>
                  {entries.slice(0, 8).map(([key, value], i) => (
                    <div key={i} className={styles.whoisRow}>
                      <span className={styles.whoisKey}>{key}</span>
                      <span className={styles.whoisValue}>{value}</span>
                    </div>
                  ))}
                </div>
              );
            }
            return <div className={styles.whoisEmpty}>No WHOIS data</div>;
          })()}
        </div>
      )}

      {/* IPInfo Section */}
      {ipinfoEnrichment?.raw_data && (
        <div className="enrichment-vendor">
          <div className="enrichment-vendor__title" style={{ color: 'var(--text-secondary)' }}>
            <span style={{ color: 'var(--text-muted)', opacity: 0.6 }}>•</span> IPInfo
          </div>
          {(() => {
            const ip = ipinfoEnrichment.raw_data;
            return (
              <div className={styles.ipinfoGrid}>
                {/* Location */}
                {(ip.city || ip.region || ip.country) && (
                  <div className={styles.ipinfoRow}>
                    <span className={styles.ipinfoLabel}>Location </span>
                    <span className={styles.ipinfoValue}>{[ip.city, ip.region, ip.country].filter(Boolean).join(', ')}</span>
                  </div>
                )}
                {/* Organization */}
                {(ip.org || ip.company?.name) && (
                  <div className={styles.ipinfoRow}>
                    <span className={styles.ipinfoLabel}>Org </span>
                    <span className={styles.ipinfoValue}>{ip.company?.name || ip.org}</span>
                  </div>
                )}
                {/* Hostname */}
                {ip.hostname && (
                  <div className={styles.ipinfoRowSmall}>
                    <span className={styles.ipinfoLabel}>Hostname: </span>
                    <span className={styles.ipinfoHostname}>{ip.hostname}</span>
                  </div>
                )}
                {/* Privacy Flags */}
                {ip.privacy && (ip.privacy.vpn || ip.privacy.proxy || ip.privacy.tor || ip.privacy.hosting) && (
                  <div className={styles.privacyFlags}>
                    {ip.privacy.vpn && <span className={styles.privacyFlag} style={{ background: 'rgba(245, 158, 11, 0.15)', color: '#f59e0b' }}>VPN</span>}
                    {ip.privacy.proxy && <span className={styles.privacyFlag} style={{ background: 'rgba(245, 158, 11, 0.15)', color: '#f59e0b' }}>PROXY</span>}
                    {ip.privacy.tor && <span className={styles.privacyFlag} style={{ background: 'rgba(220, 38, 38, 0.15)', color: '#dc2626' }}>TOR</span>}
                    {ip.privacy.hosting && <span className={styles.privacyFlag} style={{ background: 'rgba(59, 130, 246, 0.15)', color: '#3b82f6' }}>HOSTING</span>}
                  </div>
                )}
              </div>
            );
          })()}
        </div>
      )}

      {/* URLScan.io Section - handles both search results and fresh scan results */}
      {urlscanEnrichment && (urlscanEnrichment.raw_data?.results?.length > 0 || urlscanEnrichment.raw_data?.page || urlscanEnrichment.raw_data?.result_url) && (
        <div className="enrichment-vendor">
          <div className="enrichment-vendor__title" style={{ color: 'var(--text-secondary)' }}>
            <span style={{ color: 'var(--text-muted)', opacity: 0.6 }}>•</span> URLScan.io
            {(urlscanEnrichment.raw_data?.results?.length > 0 || urlscanEnrichment.raw_data?.page) && (
              <span className={styles.whoisEmpty} style={{ fontSize: '0.7rem' }}>
                ({urlscanEnrichment.raw_data?.results?.length || 1})
              </span>
            )}
            {urlscanEnrichment.raw_data?.status === 'scan_pending' && (
              <span className={styles.urlscanPendingText} style={{ marginLeft: '0.25rem' }}>Pending...</span>
            )}
          </div>
          <div className={styles.urlscanGrid}>
            {/* Fresh scan result (has page/verdicts directly in raw_data) */}
            {urlscanEnrichment.raw_data?.page && (
              <div className={styles.urlscanResultRow}>
                {urlscanEnrichment.raw_data.task?.screenshotURL && (
                  <a href={urlscanEnrichment.raw_data.task.screenshotURL} target="_blank" rel="noopener noreferrer">
                    <img
                      src={urlscanEnrichment.raw_data.task.screenshotURL}
                      alt="Screenshot"
                      className={styles.urlscanScreenshot}
                      onError={(e) => { e.target.style.display = 'none'; }}
                    />
                  </a>
                )}
                <div className={styles.urlscanInfo}>
                  <div className={styles.urlscanTitle}>
                    {urlscanEnrichment.raw_data.page?.title || urlscanEnrichment.raw_data.page?.domain || 'Scan Complete'}
                  </div>
                  <div className={styles.urlscanMetaRow}>
                    {urlscanEnrichment.raw_data.verdicts?.overall?.malicious && (
                      <span className={styles.malwareFamilyTag} style={{ fontSize: '0.65rem' }}>MALICIOUS</span>
                    )}
                    {urlscanEnrichment.raw_data.verdicts?.overall?.score > 0 && !urlscanEnrichment.raw_data.verdicts?.overall?.malicious && (
                      <span className={styles.validationTag} style={{ background: 'rgba(245, 158, 11, 0.15)', color: '#f59e0b', fontSize: '0.65rem' }}>Score: {urlscanEnrichment.raw_data.verdicts.overall.score}</span>
                    )}
                    {urlscanEnrichment.raw_data.page?.server && (
                      <span className={styles.whoisEmpty} style={{ fontSize: '0.65rem' }}>
                        {urlscanEnrichment.raw_data.page.server}
                      </span>
                    )}
                    {urlscanEnrichment.tags?.includes('fresh_scan') && (
                      <span className={styles.noThreatsTag} style={{ fontSize: '0.6rem' }}>Fresh Scan</span>
                    )}
                  </div>
                </div>
                {urlscanEnrichment.raw_data.task?.reportURL && (
                  <a href={urlscanEnrichment.raw_data.task.reportURL} target="_blank" rel="noopener noreferrer" className={styles.urlscanReportLink}>
                    Report
                  </a>
                )}
              </div>
            )}

            {/* Search results (array in raw_data.results) */}
            {!urlscanEnrichment.raw_data?.page && urlscanEnrichment.raw_data?.results?.length > 0 && (
              urlscanEnrichment.raw_data.results.slice(0, 3).map((scan, idx) => (
                <div key={idx} className={styles.urlscanResultRowSmall}>
                  {scan.screenshot && (
                    <a href={scan.screenshot} target="_blank" rel="noopener noreferrer">
                      <img
                        src={scan.screenshot}
                        alt="Screenshot"
                        className={styles.urlscanScreenshotSmall}
                        onError={(e) => { e.target.style.display = 'none'; }}
                      />
                    </a>
                  )}
                  <div className={styles.urlscanInfo}>
                    <div className={styles.urlscanTitle}>
                      {scan.page?.title || scan.task?.domain || 'Unknown'}
                    </div>
                    <div className={styles.urlscanMetaRow}>
                      <span className={styles.whoisEmpty} style={{ fontSize: '0.7rem' }}>
                        {scan.task?.time && new Date(scan.task.time).toLocaleDateString()}
                      </span>
                      {scan.task?.tags?.slice(0, 2).map((tag, i) => (
                        <span key={i} className={styles.vendorConsensusChip} style={{
                          background: tag.includes('phishing') || tag.includes('malicious') ? 'rgba(220, 38, 38, 0.15)' : 'var(--bg-secondary)',
                          color: tag.includes('phishing') || tag.includes('malicious') ? '#dc2626' : 'var(--text-muted)'
                        }}>{tag}</span>
                      ))}
                    </div>
                  </div>
                  {scan.result && (
                    <a href={scan.result} target="_blank" rel="noopener noreferrer" className={styles.urlscanPendingLink}>
                      View
                    </a>
                  )}
                </div>
              ))
            )}

            {/* Scan pending/submitted state */}
            {!urlscanEnrichment.raw_data?.page && !urlscanEnrichment.raw_data?.results?.length && urlscanEnrichment.raw_data?.result_url && (
              <div className={styles.urlscanPendingBox}>
                <div className={styles.urlscanPendingText}>
                  Scan in progress...
                </div>
                <a href={urlscanEnrichment.raw_data.result_url} target="_blank" rel="noopener noreferrer" className={styles.urlscanPendingLink}>
                  View Result (when ready)
                </a>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Error message */}
      {enrichmentData?.error && (
        <div className={styles.enrichmentError}>
          <div className={styles.enrichmentErrorTitle}>
            Enrichment Error
          </div>
          <div className={styles.enrichmentErrorBody}>
            {enrichmentData.error}
          </div>
        </div>
      )}

      {/* No enrichment message */}
      {enrichments.length === 0 && !loading && !isEnriching && !enrichmentData?.error && (
        <div className={styles.enrichmentEmpty}>
          <div className={styles.enrichmentEmptyLabel}>No enrichment data available</div>
          {sourcesChecked === 0 && providerStatusArray.length === 0 ? (
            <div className={styles.enrichmentEmptyHint}>
              <div>Click "Enrich IOC" to fetch threat intelligence</div>
              <div className={styles.enrichmentEmptySubHint}>
                If enrichment returns empty, check that threat intel<br />
                integrations are configured in Settings → Integrations
              </div>
            </div>
          ) : (
            <div className={styles.enrichmentEmptyProviders}>
              {sourcesChecked} provider{sourcesChecked !== 1 ? 's' : ''} were checked but returned no data
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ============================================================================
// ATTACHMENTS TAB - File Uploads, Downloads, Analysis
// ============================================================================

function AttachmentsTab({ investigation, alertData }) {
  const [attachments, setAttachments] = useState([]);
  const [loading, setLoading] = useState(true);
  const [uploading, setUploading] = useState(false);
  const [uploadError, setUploadError] = useState(null);
  const [analyzingId, setAnalyzingId] = useState(null);
  const [expandedId, setExpandedId] = useState(null);
  const [dragOver, setDragOver] = useState(false);
  const fileInputRef = useRef(null);

  const alertId = alertData?.alert_id || alertData?.id || investigation?.alert_id;

  const fetchAttachments = useCallback(async () => {
    if (!alertId) { setLoading(false); return; }
    try {
      const res = await fetch(
        `${API_BASE_URL}/api/v1/attachments/alert/${alertId}`,
        { headers: getAuthHeaders() }
      );
      if (res.ok) {
        const data = await res.json();
        setAttachments(data.attachments || []);
      }
    } catch (err) {
      console.error('Failed to load attachments:', err);
    } finally {
      setLoading(false);
    }
  }, [alertId]);

  useEffect(() => { fetchAttachments(); }, [fetchAttachments]);

  const handleUpload = async (files) => {
    if (!alertId || !files?.length) return;
    setUploading(true);
    setUploadError(null);

    for (const file of files) {
      try {
        const formData = new FormData();
        formData.append('file', file);

        const headers = getAuthHeaders();
        delete headers['Content-Type']; // Let browser set multipart boundary
        const csrfToken = getCsrfToken();
        if (csrfToken) headers['X-CSRF-Token'] = csrfToken;

        const res = await fetch(
          `${API_BASE_URL}/api/v1/attachments/upload/${alertId}`,
          { method: 'POST', headers, body: formData, credentials: 'include' }
        );
        if (!res.ok) {
          const err = await res.json().catch(() => ({}));
          throw new Error(err.detail || err.message || `Upload failed (${res.status})`);
        }
      } catch (err) {
        setUploadError(err.message);
      }
    }

    setUploading(false);
    fetchAttachments();
  };

  const handleDrop = (e) => {
    e.preventDefault();
    setDragOver(false);
    handleUpload(e.dataTransfer.files);
  };

  const handleAnalyze = async (attachmentId) => {
    setAnalyzingId(attachmentId);
    try {
      const res = await fetch(
        `${API_BASE_URL}/api/v1/attachments/${attachmentId}/analyze`,
        { method: 'POST', headers: { ...getAuthHeaders(), 'X-CSRF-Token': getCsrfToken() }, credentials: 'include' }
      );
      if (res.ok) {
        fetchAttachments();
      }
    } catch (err) {
      console.error('Analysis failed:', err);
    } finally {
      setAnalyzingId(null);
    }
  };

  const handleDelete = async (attachmentId) => {
    if (!window.confirm('Delete this attachment?')) return;
    try {
      const res = await fetch(
        `${API_BASE_URL}/api/v1/attachments/${attachmentId}`,
        {
          method: 'DELETE',
          headers: { ...getAuthHeaders(), 'X-CSRF-Token': getCsrfToken() },
          credentials: 'include'
        }
      );
      if (res.ok) fetchAttachments();
    } catch (err) {
      console.error('Delete failed:', err);
    }
  };

  const handleDownload = async (attachment) => {
    try {
      const res = await fetch(
        `${API_BASE_URL}/api/v1/attachments/${attachment.attachment_id}/download`,
        { headers: getAuthHeaders() }
      );
      if (!res.ok) throw new Error('Download failed');
      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = attachment.original_filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      window.URL.revokeObjectURL(url);
    } catch (err) {
      console.error('Download failed:', err);
    }
  };

  const formatFileSize = (bytes) => {
    if (!bytes) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
  };

  const getFileIcon = (mime, filename) => {
    const ext = (filename || '').split('.').pop()?.toLowerCase();
    if (mime?.startsWith('image/')) return '\u{1F5BC}';
    if (mime?.includes('pdf')) return '\u{1F4C4}';
    if (['exe', 'dll', 'msi', 'scr'].includes(ext)) return '\u26A0\uFE0F';
    if (['zip', 'rar', '7z', 'tar', 'gz'].includes(ext)) return '\u{1F4E6}';
    if (['eml', 'msg'].includes(ext)) return '\u2709\uFE0F';
    if (['pcap', 'pcapng'].includes(ext)) return '\u{1F310}';
    if (['log', 'txt', 'csv'].includes(ext)) return '\u{1F4DD}';
    if (['doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx'].includes(ext)) return '\u{1F4C3}';
    return '\u{1F4CE}';
  };

  const getThreatBadge = (attachment) => {
    if (attachment.is_malicious === true) {
      return { label: 'Malicious', color: '#ef4444', bg: 'rgba(239,68,68,0.15)' };
    }
    if (attachment.threat_score != null && attachment.threat_score > 50) {
      return { label: 'Suspicious', color: '#f59e0b', bg: 'rgba(245,158,11,0.15)' };
    }
    if (attachment.analysis_status === 'analyzed' && !attachment.is_malicious) {
      return { label: 'Clean', color: '#22c55e', bg: 'rgba(34,197,94,0.15)' };
    }
    if (attachment.analysis_status === 'analyzing') {
      return { label: 'Analyzing...', color: '#3b82f6', bg: 'rgba(59,130,246,0.15)' };
    }
    return { label: 'Pending', color: 'var(--text-muted)', bg: 'rgba(255,255,255,0.05)' };
  };

  if (loading) {
    return (
      <div className={styles.attachmentsLoading}>
        Loading attachments...
      </div>
    );
  }

  return (
    <div className="attachments-tab">
      {/* Upload Zone */}
      <div
        className={`attachments-upload-zone ${dragOver ? 'drag-over' : ''}`}
        onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
        onDragLeave={() => setDragOver(false)}
        onDrop={handleDrop}
        onClick={() => fileInputRef.current?.click()}
      >
        <input
          ref={fileInputRef}
          type="file"
          multiple
          style={{ display: 'none' }}
          onChange={(e) => handleUpload(e.target.files)}
        />
        <div className={styles.uploadZoneContent}>
          {uploading ? '\u23F3' : '\u{1F4E4}'}
        </div>
        <div className={styles.uploadZoneText}>
          {uploading ? 'Uploading...' : 'Drop files here or click to upload'}
        </div>
        <div className={styles.uploadZoneHint}>
          Documents, images, logs, PCAPs, executables (max 50MB)
        </div>
      </div>

      {uploadError && (
        <div className="attachments-error">
          {uploadError}
          <button onClick={() => setUploadError(null)} className={styles.uploadErrorCloseBtn}>x</button>
        </div>
      )}

      {/* Attachment List */}
      {attachments.length === 0 ? (
        <div className={styles.attachmentsEmpty}>
          No attachments yet. Upload files to associate evidence with this investigation.
        </div>
      ) : (
        <div className="attachments-list">
          <div className={styles.attachmentsListHeader}>
            <span>{attachments.length} file{attachments.length !== 1 ? 's' : ''}</span>
            <span>{formatFileSize(attachments.reduce((sum, a) => sum + (a.file_size || 0), 0))} total</span>
          </div>

          {attachments.map(att => {
            const badge = getThreatBadge(att);
            const isExpanded = expandedId === att.attachment_id;

            return (
              <div key={att.attachment_id} className="attachment-row">
                <div
                  className="attachment-row-main"
                  onClick={() => setExpandedId(isExpanded ? null : att.attachment_id)}
                >
                  <span className="attachment-icon">{getFileIcon(att.mime_type, att.original_filename)}</span>

                  <div className="attachment-info">
                    <div className="attachment-filename">{att.original_filename}</div>
                    <div className="attachment-meta">
                      {formatFileSize(att.file_size)}
                      {att.uploaded_by && <> &middot; {att.uploaded_by}</>}
                      {att.uploaded_at && <> &middot; {new Date(att.uploaded_at).toLocaleDateString()}</>}
                    </div>
                  </div>

                  <span className="attachment-badge" style={{ color: badge.color, background: badge.bg }}>
                    {badge.label}
                  </span>
                </div>

                {isExpanded && (
                  <div className="attachment-expanded">
                    {/* Hashes */}
                    <div className="attachment-hashes">
                      {att.sha256_hash && (
                        <div className="hash-row">
                          <span className="hash-label">SHA-256</span>
                          <code className="hash-value">{att.sha256_hash}</code>
                        </div>
                      )}
                      {att.md5_hash && (
                        <div className="hash-row">
                          <span className="hash-label">MD5</span>
                          <code className="hash-value">{att.md5_hash}</code>
                        </div>
                      )}
                      {att.mime_type && (
                        <div className="hash-row">
                          <span className="hash-label">Type</span>
                          <code className="hash-value">{att.mime_type}</code>
                        </div>
                      )}
                      {att.description && (
                        <div className="hash-row">
                          <span className="hash-label">Note</span>
                          <span className="hash-value" style={{ fontFamily: 'inherit' }}>{att.description}</span>
                        </div>
                      )}
                      {att.threat_score != null && (
                        <div className="hash-row">
                          <span className="hash-label">Threat Score</span>
                          <span className="hash-value" style={{
                            fontFamily: 'inherit',
                            color: att.threat_score > 70 ? '#ef4444' : att.threat_score > 40 ? '#f59e0b' : '#22c55e'
                          }}>
                            {att.threat_score}/100
                          </span>
                        </div>
                      )}
                    </div>

                    {/* Actions */}
                    <div className="attachment-actions">
                      <button className="att-action-btn" onClick={(e) => { e.stopPropagation(); handleDownload(att); }}>
                        Download
                      </button>
                      {att.analysis_status === 'pending' && (
                        <button
                          className="att-action-btn att-action-analyze"
                          disabled={analyzingId === att.attachment_id}
                          onClick={(e) => { e.stopPropagation(); handleAnalyze(att.attachment_id); }}
                        >
                          {analyzingId === att.attachment_id ? 'Analyzing...' : 'Analyze'}
                        </button>
                      )}
                      <button
                        className="att-action-btn att-action-delete"
                        onClick={(e) => { e.stopPropagation(); handleDelete(att.attachment_id); }}
                      >
                        Delete
                      </button>
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

// ============================================================================
// ACTIVITY TAB - Immutable Audit Trail
// ============================================================================

function ActivityTab({ investigation }) {
  const [activities, setActivities] = useState([]);
  const [chatHistory, setChatHistory] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState('all'); // all, ai, human, system, chat
  const [viewMode, setViewMode] = useState('timeline'); // 'list' or 'timeline'
  const scrollRef = useRef(null);

  const investigationId = investigation?.investigation_id || investigation?.id;

  useEffect(() => {
    if (!investigationId) return;

    const fetchAllActivity = async () => {
      setLoading(true);
      const allActivities = [];

      try {
        // Parse investigation data
        let invData = investigation?.investigation_data || {};
        if (typeof invData === 'string') {
          try { invData = JSON.parse(invData); } catch { invData = {}; }
        }

        // 1. ALERT INGESTION EVENT - When the alert came in
        const createdAt = investigation?.created_at;
        if (createdAt) {
          const alertData = invData.alert || investigation?.alert_data || {};
          allActivities.push({
            type: 'ingestion',
            actor_type: 'system',
            actor_name: 'Ingestion',
            summary: `Alert received: ${investigation?.title || alertData?.title || 'Security Alert'}`,
            details: `Source: ${alertData?.source || investigation?.source || 'Unknown'} | Severity: ${investigation?.severity || alertData?.severity || 'Unknown'}`,
            timestamp: createdAt,
            icon: '📥',
            category: 'system'
          });
        }

        // 2. IOC EXTRACTION EVENT
        const extractedData = invData.extracted_data || invData._extracted || {};
        const iocs = extractedData.iocs || invData.iocs || {};
        const totalIOCs = Object.values(iocs).reduce((sum, arr) => sum + (Array.isArray(arr) ? arr.length : 0), 0);
        if (totalIOCs > 0) {
          const iocTypes = Object.entries(iocs)
            .filter(([_, v]) => Array.isArray(v) && v.length > 0)
            .map(([k, v]) => `${v.length} ${k}`)
            .join(', ');
          allActivities.push({
            type: 'extraction',
            actor_type: 'system',
            actor_name: 'Extractor',
            summary: `Extracted ${totalIOCs} IOCs: ${iocTypes}`,
            details: Object.entries(iocs)
              .filter(([_, v]) => Array.isArray(v) && v.length > 0)
              .map(([k, v]) => `${k}: ${v.slice(0, 3).join(', ')}${v.length > 3 ? '...' : ''}`)
              .join(' | '),
            timestamp: new Date(new Date(createdAt).getTime() + 500).toISOString(), // 0.5s after ingestion
            icon: '🔍',
            category: 'system'
          });
        }

        // 3. ENRICHMENT EVENTS
        const enrichment = invData.enrichment || invData.enrichment_data || {};
        const enrichmentResults = enrichment.results || enrichment;
        if (Object.keys(enrichmentResults).length > 0) {
          const enrichedCount = Object.keys(enrichmentResults).length;
          const providers = [...new Set(Object.values(enrichmentResults).flatMap(r =>
            r?.sources?.map(s => s.provider) || [r?.provider]).filter(Boolean))];
          allActivities.push({
            type: 'enrichment',
            actor_type: 'system',
            actor_name: 'Enrichment',
            summary: `Enriched ${enrichedCount} IOC${enrichedCount > 1 ? 's' : ''} via ${providers.length > 0 ? providers.join(', ') : 'threat intel'}`,
            details: Object.entries(enrichmentResults).slice(0, 3)
              .map(([ioc, data]) => `${ioc}: ${data?.verdict || data?.reputation || 'checked'}`)
              .join(' | '),
            timestamp: enrichment.timestamp || new Date(new Date(createdAt).getTime() + 2000).toISOString(),
            icon: '🌐',
            category: 'system'
          });
        }

        // 4. RIGGS TRIAGE EVENT
        if (invData.tier1_analysis) {
          const t1 = invData.tier1_analysis;
          allActivities.push({
            type: 'ai_analysis',
            tier: 'T1',
            actor_type: 'ai_agent',
            actor_name: 'Riggs',
            summary: `Riggs Triage: ${t1.verdict || 'Analyzed'} (${Math.round((t1.confidence || 0) > 1 ? (t1.confidence || 0) : (t1.confidence || 0) * 100)}% confidence)`,
            details: t1.reasoning || t1.summary || 'Automated AI triage completed',
            timestamp: t1.timestamp || new Date(new Date(createdAt).getTime() + 5000).toISOString(),
            icon: '🤖',
            category: 'ai'
          });

          // Riggs Recommended Actions
          if (t1.recommended_actions?.length > 0) {
            allActivities.push({
              type: 'recommendation',
              actor_type: 'ai_agent',
              actor_name: 'Riggs',
              summary: `Recommended: ${t1.recommended_actions.join(', ')}`,
              timestamp: new Date(new Date(t1.timestamp || createdAt).getTime() + 100).toISOString(),
              icon: '💡',
              category: 'ai'
            });
          }
        }

        // 5. T2 ANALYSIS EVENT
        if (invData.tier2_analysis) {
          const t2 = invData.tier2_analysis;
          allActivities.push({
            type: 'ai_analysis',
            tier: 'T2',
            actor_type: 'ai_agent',
            actor_name: 'T2 Agent',
            summary: `T2 Deep Analysis: ${t2.verdict || 'Analyzed'} (${Math.round((t2.confidence || 0) > 1 ? (t2.confidence || 0) : (t2.confidence || 0) * 100)}% confidence)`,
            details: t2.reasoning || t2.summary || 'Deep analysis completed',
            timestamp: t2.timestamp || investigation?.updated_at,
            icon: '🧠',
            category: 'ai'
          });

          // MITRE ATT&CK techniques
          if (t2.mitre_techniques?.length > 0) {
            allActivities.push({
              type: 'mitre',
              actor_type: 'ai_agent',
              actor_name: 'T2 Agent',
              summary: `MITRE ATT&CK: ${t2.mitre_techniques.map(t => t.technique_id || t).join(', ')}`,
              timestamp: new Date(new Date(t2.timestamp || investigation?.updated_at).getTime() + 100).toISOString(),
              icon: '🎯',
              category: 'ai'
            });
          }
        }

        // 6. STATE CHANGE EVENT (if escalated to RIGGS_REVIEW)
        if (investigation?.state === 'RIGGS_REVIEW' || investigation?.state === 'AWAITING_HUMAN') {
          allActivities.push({
            type: 'state_change',
            actor_type: 'system',
            actor_name: 'Workflow',
            summary: `State changed to ${investigation.state.replace('_', ' ')}`,
            details: investigation.state === 'RIGGS_REVIEW' ? 'Awaiting AI-assisted review' : 'Escalated for human review',
            timestamp: investigation?.updated_at || new Date().toISOString(),
            icon: '📋',
            category: 'system'
          });
        }

        // 7. FETCH AUDIT TRAIL (state changes, assignments, etc.)
        const auditResponse = await fetch(
          `${API_BASE_URL}/api/v1/chat/investigations/${investigationId}/audit?limit=100`,
          { headers: getAuthHeaders() }
        );
        if (auditResponse.ok) {
          const auditData = await auditResponse.json();
          (auditData.audit_trail || []).forEach(entry => {
            allActivities.push({
              ...entry,
              type: 'audit',
              actor_type: entry.actor_type || 'system',
              actor_name: entry.actor_name || entry.user || 'System',
              summary: entry.action || entry.summary,
              timestamp: entry.created_at || entry.timestamp,
              icon: '📝',
              category: 'audit'
            });
          });
        }

        // 8. FETCH CHAT HISTORY
        const chatResponse = await fetch(
          `${API_BASE_URL}/api/v1/chat/investigations/${investigationId}/messages?limit=100`,
          { headers: getAuthHeaders() }
        );
        if (chatResponse.ok) {
          const chatData = await chatResponse.json();
          const messages = chatData.messages || chatData || [];
          setChatHistory(messages);
          messages.forEach(msg => {
            // Determine if this is an AI message - check sender_type (the actual field used in backend)
            // Backend uses: sender_type='agent_riggs' or 'agent_t1', 'agent_t2' for AI
            // Backend uses: sender_type='human' for human messages
            const senderType = (msg.sender_type || '').toLowerCase();
            const senderName = msg.sender_name || '';
            const isAI = senderType.startsWith('agent') ||  // agent_riggs, agent_t1, agent_t2
                         senderType === 'ai' ||
                         msg.role === 'assistant' ||
                         senderName.toLowerCase() === 'riggs';

            // Get proper display name from sender_name (the actual field from backend)
            let displayName;
            if (isAI) {
              displayName = senderName || 'Riggs';
            } else {
              // For human messages, sender_name contains the actual username
              displayName = senderName || msg.sender_id || msg.username || 'Analyst';
            }

            allActivities.push({
              ...msg,
              type: 'chat',
              timestamp: msg.timestamp || msg.created_at,
              actor_type: isAI ? 'ai_agent' : 'human',
              actor_name: displayName,
              summary: msg.content || msg.message,
              icon: isAI ? '🤖' : '👤',
              category: 'chat'
            });
          });
        }

        // 9. RESPONSE ACTIONS (if any taken)
        const actions = invData.response_actions || invData.actions_taken || [];
        actions.forEach((action, idx) => {
          allActivities.push({
            type: 'action',
            actor_type: action.actor_type || 'system',
            actor_name: action.actor || 'System',
            summary: `Action: ${action.action || action.name || action.type}`,
            details: action.result || action.status || '',
            timestamp: action.timestamp || new Date(new Date(investigation?.updated_at).getTime() + (idx * 1000)).toISOString(),
            icon: '⚡',
            category: 'action'
          });
        });

        // Sort by timestamp ascending (oldest first for timeline view)
        allActivities.sort((a, b) => {
          const timeA = new Date(a.timestamp || 0).getTime();
          const timeB = new Date(b.timestamp || 0).getTime();
          return timeA - timeB;
        });

        setActivities(allActivities);
      } catch (err) {
      }
      setLoading(false);
    };

    fetchAllActivity();
  }, [investigationId, investigation]);

  // Format timestamp - show actual time, not relative
  const formatTime = (timestamp) => {
    if (!timestamp) return '';
    const date = new Date(timestamp);

    // Always show actual timestamp: "Jan 8, 2:34:15 PM"
    return date.toLocaleString('en-US', {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit'
    });
  };

  // Get color for actor type or event type
  const getActorColor = (actorType, eventType) => {
    // Event-specific colors first
    const eventColors = {
      ingestion: '#f59e0b',    // amber - alert came in
      extraction: '#8b5cf6',   // purple - IOC extraction
      enrichment: '#06b6d4',   // cyan - enrichment
      ai_analysis: '#3b82f6',  // blue - AI analysis
      recommendation: '#22c55e', // green - recommendations
      mitre: '#ef4444',        // red - MITRE ATT&CK
      state_change: '#f97316', // orange - workflow
      action: '#ec4899',       // pink - response actions
      chat: '#3CB371',         // teal - chat
      audit: '#6b7280'         // gray - audit
    };
    if (eventType && eventColors[eventType]) {
      return eventColors[eventType];
    }
    // Actor-based colors
    const colors = {
      human: '#3CB371',
      ai_agent: '#3b82f6',
      system: '#6b7280'
    };
    return colors[actorType] || '#6b7280';
  };

  // Filter activities
  const filteredActivities = activities.filter(a => {
    if (filter === 'all') return true;
    if (filter === 'ai') return a.actor_type === 'ai_agent' || a.type === 'ai_analysis';
    if (filter === 'human') return a.actor_type === 'human';
    if (filter === 'system') return a.actor_type === 'system';
    if (filter === 'chat') return a.type === 'chat';
    return true;
  });

  if (loading) {
    return (
      <div className={styles.activityLoadingText}>
        Loading activity...
      </div>
    );
  }

  return (
    <div className={styles.activityTabWrap}>
      {/* Header with filters */}
      <div className={styles.activityHeader}>
        <div className={styles.activityControlsRow} style={{ justifyContent: 'flex-start' }}>
          <span className={styles.activityTitle}>
            Activity Timeline
          </span>
          <span className={styles.activityEventCount}>
            {filteredActivities.length} events
          </span>
        </div>

        {/* View toggle + Filter buttons */}
        <div className={styles.activityControlsRow}>
          {/* View mode toggle */}
          <div className={styles.activityViewToggle}>
            <button
              onClick={() => setViewMode('timeline')}
              title="Timeline View"
              className={viewMode === 'timeline' ? styles.activityViewBtnActive : styles.activityViewBtnInactive}
            >
              Timeline
            </button>
            <button
              onClick={() => setViewMode('list')}
              title="List View"
              className={viewMode === 'list' ? styles.activityViewBtnActive : styles.activityViewBtnInactive}
            >
              List
            </button>
          </div>

          {/* Filter buttons */}
          <div className={styles.activityFilterRow}>
            {[
              { key: 'all', label: 'All' },
              { key: 'ai', label: 'AI' },
              { key: 'chat', label: 'Chat' },
              { key: 'human', label: 'Human' },
              { key: 'system', label: 'System' }
            ].map(f => (
              <button
                key={f.key}
                onClick={() => setFilter(f.key)}
                className={filter === f.key ? styles.activityFilterBtnActive : styles.activityFilterBtnInactive}
              >
                {f.label}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Content area - Timeline or List view */}
      <div
        ref={scrollRef}
        className={styles.activityScrollArea} style={{
          padding: viewMode === 'timeline' ? '0.5rem' : '0.5rem 1rem'
        }}
      >
        {filteredActivities.length === 0 ? (
          <div className={styles.activityEmptyText}>
            No activity recorded yet
          </div>
        ) : viewMode === 'timeline' ? (
          /* Visual Timeline Graph View */
          <div className={styles.activityTimelineGraph}>
            {/* Timeline vertical line */}
            <div className={styles.activityTimelineLine} />

            {/* Timeline events - oldest first (already sorted ascending) */}
            {filteredActivities.map((entry, index) => {
              const isAI = entry.actor_type === 'ai_agent';
              const isChat = entry.type === 'chat';
              const isAnalysis = entry.type === 'ai_analysis';
              const isImportant = ['ai_analysis', 'ingestion', 'state_change', 'mitre'].includes(entry.type);
              const color = getActorColor(entry.actor_type, entry.type);

              return (
                <div
                  key={entry.id || index}
                  className={styles.activityTimelineEvent}
                >
                  {/* Timeline node with icon */}
                  <div className={styles.activityNodeCol}>
                    <div className={styles.activityNode} style={{
                      width: isImportant ? '24px' : '20px',
                      height: isImportant ? '24px' : '20px',
                      background: `${color}20`,
                      border: `2px solid ${color}`,
                      boxShadow: `0 0 ${isImportant ? '8px' : '4px'} ${color}40`,
                      fontSize: isImportant ? '0.7rem' : '0.6rem'
                    }}>
                      {entry.icon || '•'}
                    </div>
                  </div>

                  {/* Event card */}
                  <div className={styles.activityCardBody} style={{
                    background: `${color}10`,
                    borderLeft: `3px solid ${color}`
                  }}>
                    {/* Header row */}
                    <div className={styles.activityCardHeaderRow}>
                      <span className={styles.activityActorName} style={{ color: color }}>
                        {entry.actor_name || (isAI ? 'AI' : 'User')}
                      </span>
                      {entry.tier && (
                        <span className={styles.activityTierBadge} style={{
                          background: entry.tier === 'T1' ? 'rgba(34, 197, 94, 0.25)' : 'rgba(59, 130, 246, 0.25)',
                          color: entry.tier === 'T1' ? '#22c55e' : '#3b82f6'
                        }}>
                          {entry.tier}
                        </span>
                      )}
                      <span className={styles.activityTimestamp}>
                        {formatTime(entry.timestamp)}
                      </span>
                    </div>

                    {/* Content */}
                    <div className={styles.activityContent} style={{
                      maxHeight: isChat ? '120px' : '60px'
                    }}>
                      {isChat ? (entry.content || entry.message) : (entry.summary || entry.action)}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        ) : (
          /* Compact List View - newest first */
          <div className={styles.activityListView}>
            {filteredActivities.slice().reverse().map((entry, index) => {
              const isAI = entry.actor_type === 'ai_agent';
              const isChat = entry.type === 'chat';
              const color = getActorColor(entry.actor_type, entry.type);

              return (
                <div
                  key={entry.id || index}
                  className={styles.activityListEvent}
                  style={{
                    background: `${color}10`,
                    borderLeft: `3px solid ${color}`
                  }}
                >
                  {/* Icon + Actor badge */}
                  <div className={styles.activityListActorCol}>
                    <span className={styles.activityListIcon}>{entry.icon || '•'}</span>
                    <span className={styles.activityActorName} style={{ color: color }}>
                      {entry.actor_name || (isAI ? 'AI' : 'User')}
                    </span>
                    {entry.tier && (
                      <span className={styles.activityTierBadge} style={{
                        background: entry.tier === 'T1' ? 'rgba(34, 197, 94, 0.25)' : 'rgba(59, 130, 246, 0.25)',
                        color: entry.tier === 'T1' ? '#22c55e' : '#3b82f6',
                        fontSize: '0.6rem', padding: '0.1rem 0.25rem'
                      }}>
                        {entry.tier}
                      </span>
                    )}
                  </div>

                  {/* Content */}
                  <div className={styles.activityListContent}>
                    <div className={styles.activityListText}>
                      {isChat ? (entry.content || entry.message) : (entry.summary || entry.action)}
                    </div>
                  </div>

                  {/* Timestamp */}
                  <span className={styles.activityListTimestamp}>
                    {formatTime(entry.timestamp)}
                  </span>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Footer info */}
      <div className={styles.activityFooter}>
        <span>Immutable audit log - all events are permanently recorded</span>
        <span>{chatHistory.length} chat messages</span>
      </div>
    </div>
  );
}

// ============================================================================
// RAW DATA TAB
// ============================================================================

function RawDataTab({ investigation, alertData }) {
  const [searchTerm, setSearchTerm] = useState('');
  const [activeSection, setActiveSection] = useState('raw_event');

  let rawEvent = alertData?.raw_event || {};
  if (typeof rawEvent === 'string') {
    try { rawEvent = JSON.parse(rawEvent); } catch { rawEvent = {}; }
  }

  let invData = investigation?.investigation_data || {};
  if (typeof invData === 'string') {
    try { invData = JSON.parse(invData); } catch { invData = {}; }
  }

  const sections = [
    { key: 'raw_event', label: 'Raw Event', data: rawEvent },
    { key: 'investigation_data', label: 'Investigation Data', data: invData },
  ];

  // Add investigation-level metadata
  if (investigation) {
    const meta = {};
    ['investigation_id', 'alert_id', 'state', 'priority', 'severity', 'ai_verdict',
     'ai_confidence', 'created_at', 'updated_at', 'triage_status', 'assigned_to'].forEach(k => {
      if (investigation[k] !== undefined) meta[k] = investigation[k];
    });
    if (Object.keys(meta).length > 0) {
      sections.unshift({ key: 'metadata', label: 'Metadata', data: meta });
    }
  }

  const activeData = sections.find(s => s.key === activeSection)?.data || {};

  // Copy a section's data
  const copySection = () => {
    const text = JSON.stringify(activeData, null, 2);
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text);
    } else {
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
    }
  };

  return (
    <div className="wb-json-viewer">
      {/* Toolbar */}
      <div className={styles.rawDataToolbar}>
        {/* Section tabs */}
        <div className={styles.rawDataSectionTabs}>
          {sections.map(s => (
            <button key={s.key} onClick={() => setActiveSection(s.key)}
              className={activeSection === s.key ? styles.rawDataSectionBtnActive : styles.rawDataSectionBtnInactive}>
              {s.label}
              <span className={styles.rawDataSectionCount}>
                {Object.keys(s.data).length}
              </span>
            </button>
          ))}
        </div>

        {/* Search */}
        <input
          type="text"
          placeholder="Search keys/values..."
          value={searchTerm}
          onChange={e => setSearchTerm(e.target.value)}
          className={styles.rawDataSearchInput}
        />

        {/* Copy button */}
        <button onClick={copySection} className={styles.rawDataCopyBtn}>
          Copy
        </button>
      </div>

      {/* JSON Tree */}
      <div className={styles.rawDataJsonTree}>
        <JsonNode data={activeData} depth={0} searchTerm={searchTerm} defaultExpanded={true} />
      </div>
    </div>
  );
}

// Recursive JSON tree node with syntax coloring + collapse
function JsonNode({ data, depth, searchTerm, name, defaultExpanded }) {
  const [expanded, setExpanded] = useState(depth < 2 || defaultExpanded);

  const isArray = Array.isArray(data);
  const isObject = data !== null && typeof data === 'object' && !isArray;
  const isExpandable = isObject || isArray;
  const entries = isObject ? Object.entries(data) : isArray ? data.map((v, i) => [i, v]) : [];

  // Search filter: if search is active, check if this branch contains matching key/value
  const matchesSearch = (val, key) => {
    if (!searchTerm) return true;
    const term = searchTerm.toLowerCase();
    if (key !== undefined && String(key).toLowerCase().includes(term)) return true;
    if (val === null || val === undefined) return false;
    if (typeof val === 'object') {
      return JSON.stringify(val).toLowerCase().includes(term);
    }
    return String(val).toLowerCase().includes(term);
  };

  const filteredEntries = searchTerm
    ? entries.filter(([k, v]) => matchesSearch(v, k))
    : entries;

  if (searchTerm && !isExpandable && !matchesSearch(data, name)) return null;
  if (searchTerm && isExpandable && filteredEntries.length === 0) return null;

  // Render a primitive value with syntax coloring
  const renderValue = (val) => {
    if (val === null) return <span className="wb-json-null">null</span>;
    if (val === undefined) return <span className="wb-json-null">undefined</span>;
    if (typeof val === 'boolean') return <span className="wb-json-boolean">{String(val)}</span>;
    if (typeof val === 'number') return <span className="wb-json-number">{val}</span>;
    if (typeof val === 'string') {
      const isHighlighted = searchTerm && val.toLowerCase().includes(searchTerm.toLowerCase());
      const truncated = val.length > 200 ? val.slice(0, 200) + '...' : val;
      return (
        <span className={`wb-json-string ${isHighlighted ? 'wb-json-highlight' : ''}`}>
          "{truncated}"
        </span>
      );
    }
    return <span>{String(val)}</span>;
  };

  // Leaf value
  if (!isExpandable) {
    return (
      <span>
        {name !== undefined && (
          <>
            <span className={`wb-json-key ${searchTerm && String(name).toLowerCase().includes(searchTerm.toLowerCase()) ? 'wb-json-highlight' : ''}`}>
              {isNaN(name) ? `"${name}"` : name}
            </span>
            <span className={styles.jsonColon}>: </span>
          </>
        )}
        {renderValue(data)}
      </span>
    );
  }

  // Expandable (object/array)
  const bracketOpen = isArray ? '[' : '{';
  const bracketClose = isArray ? ']' : '}';
  const count = filteredEntries.length;

  return (
    <div style={{ paddingLeft: depth > 0 ? '16px' : 0 }}>
      <span
        className={`wb-json-toggle ${styles.jsonToggle}`}
        onClick={() => setExpanded(!expanded)}
      >
        <span className={styles.jsonToggleArrowCol}>
          {expanded ? '▾' : '▸'}
        </span>
        {name !== undefined && (
          <>
            <span className={`wb-json-key ${searchTerm && String(name).toLowerCase().includes(searchTerm.toLowerCase()) ? 'wb-json-highlight' : ''}`}>
              {isNaN(name) ? `"${name}"` : name}
            </span>
            <span className={styles.jsonColon}>: </span>
          </>
        )}
        <span className={styles.jsonBracket}>{bracketOpen}</span>
        {!expanded && (
          <span className={styles.jsonCollapsedCount}>
            {' '}{count} {isArray ? 'items' : 'keys'}{' '}{bracketClose}
          </span>
        )}
      </span>
      {expanded && (
        <div>
          {filteredEntries.map(([key, value], idx) => (
            <div key={key} className={styles.jsonNodeEntry}>
              <JsonNode
                data={value}
                depth={depth + 1}
                searchTerm={searchTerm}
                name={key}
                defaultExpanded={false}
              />
              {idx < filteredEntries.length - 1 && (
                <span className={styles.jsonBracket}>,</span>
              )}
            </div>
          ))}
          <span className={styles.jsonBracket}>{bracketClose}</span>
        </div>
      )}
    </div>
  );
}

// ============================================================================
// SIDE PANEL CHAT - Pushes content instead of overlaying
// ============================================================================

function SidePanelChat({ investigation, chatOpen, setChatOpen, licenseData }) {
  const [messages, setMessages] = useState([]);
  const [newMessage, setNewMessage] = useState('');
  const [connected, setConnected] = useState(false);
  const [sending, setSending] = useState(false);
  const [waitingForRiggs, setWaitingForRiggs] = useState(false);
  const [chatMode, setChatMode] = useState(() => localStorage.getItem('t1_chat_mode') || 'typewriter');
  const wsRef = useRef(null);
  const messagesEndRef = useRef(null);
  const newMessageIdsRef = useRef(new Set());
  const historyLoadedRef = useRef(false);

  const investigationId = investigation?.investigation_id || investigation?.id;
  const username = localStorage.getItem('username') || 'analyst';

  const toggleChatMode = useCallback(() => {
    setChatMode(prev => {
      const next = prev === 'typewriter' ? 'instant' : 'typewriter';
      localStorage.setItem('t1_chat_mode', next);
      return next;
    });
  }, []);

  // License-based chat gating
  const chatUsage = licenseData?.riggs_usage?.chat;
  const chatLimit = licenseData?.riggs_limits?.chat_messages_per_month || 0;
  const isUnlimited = chatUsage?.unlimited !== false;
  const chatUsed = chatUsage?.used || 0;
  const chatRemaining = chatUsage?.remaining;
  const isChatLimited = !isUnlimited && chatLimit > 0 && chatUsed >= chatLimit;

  // WebSocket connection
  useEffect(() => {
    if (!investigationId || !chatOpen) return;

    let isMounted = true;
    let ws = null;
    let reconnectTimeout = null;

    const connect = () => {
      if (!isMounted) return;

      const wsProtocol = window.location.protocol === 'https:' ? 'wss' : 'ws';
      const wsUrl = `${wsProtocol}://${window.location.host}/ws/chat/${investigationId}`;

      try {
        ws = new WebSocket(wsUrl);
        wsRef.current = ws;

        ws.onopen = () => {
          if (!isMounted) {
            ws.close(1000, 'Component unmounted');
            return;
          }
          setConnected(true);
          ws.send(JSON.stringify({ type: 'get_history', limit: 50 }));
        };

        ws.onmessage = (event) => {
          if (!isMounted) return;
          try {
            const data = JSON.parse(event.data);
            if (data.type === 'chat_history') {
              setMessages(data.messages || []);
              historyLoadedRef.current = true;
              // Scroll to bottom after history loads
              setTimeout(() => messagesEndRef.current?.scrollIntoView({ behavior: 'auto' }), 150);
            } else if (data.type === 'new_message') {
              if (historyLoadedRef.current && data.message?.id) {
                newMessageIdsRef.current.add(data.message.id);
              }
              setMessages(prev => {
                const exists = prev.some(m => m.id === data.message.id);
                if (exists) return prev;
                return [...prev, data.message];
              });
              // Clear "Riggs is thinking" when agent responds
              if (data.message.sender_type?.startsWith('agent')) {
                setWaitingForRiggs(false);
              }
              setTimeout(() => messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' }), 100);
            }
          } catch (e) {
          }
        };

        ws.onclose = (event) => {
          if (!isMounted) return;
          setConnected(false);
          if (event.code !== 1000 && isMounted) {
            reconnectTimeout = setTimeout(connect, 2000);
          }
        };

        ws.onerror = () => {
          if (!isMounted) return;
          setConnected(false);
        };
      } catch (e) {
        if (isMounted) {
          reconnectTimeout = setTimeout(connect, 2000);
        }
      }
    };

    const connectTimeout = setTimeout(connect, 100);

    return () => {
      isMounted = false;
      clearTimeout(connectTimeout);
      clearTimeout(reconnectTimeout);
      if (ws && ws.readyState === WebSocket.OPEN) {
        ws.close(1000, 'Component unmounting');
      }
    };
  }, [investigationId, chatOpen]);

  const sendMessage = async (e) => {
    e?.preventDefault();
    if (!newMessage.trim() || !connected) return;

    telemetry.track('investigation', 'investigation.chat_message', { mode: chatMode || 'chat' });
    setSending(true);
    try {
      if (wsRef.current?.readyState === WebSocket.OPEN) {
        wsRef.current.send(JSON.stringify({
          type: 'chat_message',
          message: newMessage.trim()
        }));
        setNewMessage('');
        setWaitingForRiggs(true);
      }
    } catch (err) {
    } finally {
      setSending(false);
    }
  };

  const formatTime = (ts) => {
    if (!ts) return '';
    const d = new Date(ts);
    return d.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
  };

  // Side panel - slides in from right
  return (
    <div className={chatOpen ? styles.sidePanelChatOpen : styles.sidePanelChatClosed}>
      {chatOpen && (
        <>
          {/* Header */}
          <div className={styles.chatHeader}>
            <div className={styles.chatHeaderLeft}>
              <div className={styles.chatAvatar}>
                R
              </div>
              <div>
                <div className={styles.chatHeaderName}>Riggs</div>
                <div className={connected ? styles.chatHeaderStatusOnline : styles.chatHeaderStatusOffline}>
                  {connected ? 'Online' : 'Connecting...'}
                </div>
              </div>
            </div>
            <div className={styles.chatHeaderActions}>
              <button
                onClick={toggleChatMode}
                title={chatMode === 'typewriter' ? 'Typewriter mode (click for instant)' : 'Instant mode (click for typewriter)'}
                className={chatMode === 'typewriter' ? `${styles.chatModeBtn} ${styles.chatModeBtnActive}` : styles.chatModeBtn}
              >
                {chatMode === 'typewriter' ? (
                  <><span className={styles.chatModeBtnIcon}>&#9998;</span> Live</>
                ) : (
                  <><span className={styles.chatModeBtnIcon}>&#9889;</span> Instant</>
                )}
              </button>
              <button
                onClick={() => setChatOpen(false)}
                className={styles.chatHideBtn}
              >
                <span>→</span>
                <span>Hide</span>
              </button>
            </div>
          </div>

          {/* Messages */}
          <div className={styles.chatMessages}>
            {messages.length === 0 && (
              <div className={styles.chatEmptyHint}>
                Ask Riggs anything about this investigation
                {/* Tour suggestion chip — gives Riggs an in-product way to
                    surface the guided tour. Clicking dispatches the same
                    custom event the user-pill replay button fires. */}
                <div style={{ marginTop: '0.75rem', display: 'flex', flexDirection: 'column', gap: '0.4rem' }}>
                  <button
                    type="button"
                    onClick={() => {
                      try { localStorage.removeItem('t1-app-tour-seen-v1'); } catch { /* ignore */ }
                      window.dispatchEvent(new CustomEvent('t1-tour-start', { detail: { tour: 'platform', step: 0 } }));
                    }}
                    style={{
                      background: 'rgba(60,179,113,0.1)',
                      border: '1px solid rgba(60,179,113,0.35)',
                      color: 'var(--primary, #3CB371)',
                      borderRadius: '999px',
                      padding: '0.35rem 0.85rem',
                      fontSize: '0.78rem',
                      fontWeight: 600,
                      cursor: 'pointer',
                      alignSelf: 'flex-start',
                    }}
                    title="Walks you through the platform with green spotlights"
                  >
                    Take the platform tour →
                  </button>
                </div>
              </div>
            )}
            {messages.map((msg, idx) => {
              const isOwnMessage = msg.sender_id === username;
              const isAgent = msg.sender_type?.startsWith('agent_');

              return (
                <div
                  key={msg.id || idx}
                  className={isOwnMessage ? styles.chatMsgWrapOwn : styles.chatMsgWrapOther}
                >
                  <div className={isOwnMessage ? styles.chatMsgMetaRight : styles.chatMsgMeta}>
                    <span className={isAgent ? styles.chatMsgSenderAgent : styles.chatMsgSenderHuman}>
                      {isAgent ? 'Riggs' : (isOwnMessage ? 'You' : msg.sender_name)}
                    </span>
                    {' · '}
                    {formatTime(msg.created_at)}
                  </div>
                  <div className={isOwnMessage ? styles.chatMsgBubbleOwn : (isAgent ? styles.chatMsgBubbleAgent : styles.chatMsgBubbleOther)}>
                    {isAgent ? (
                      chatMode === 'typewriter' && newMessageIdsRef.current.has(msg.id) ? (
                        <SidePanelTypewriter
                          text={msg.message}
                          speed={35}
                          renderFn={renderMarkdown}
                          onTick={() => messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })}
                          onComplete={() => {
                            newMessageIdsRef.current.delete(msg.id);
                            messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
                          }}
                        />
                      ) : renderMarkdown(msg.message)
                    ) : msg.message}
                  </div>
                </div>
              );
            })}

            {/* Riggs thinking indicator */}
            {waitingForRiggs && (
              <div className={styles.chatThinkingWrap}>
                <div className={styles.chatThinkingMeta}>
                  <span className={styles.chatThinkingName}>Riggs</span>
                </div>
                <div className={styles.chatThinkingBubble}>
                  <div className={styles.chatThinkingDots}>
                    <span className={styles.chatThinkingDot} style={{ animationDelay: '0s' }} />
                    <span className={styles.chatThinkingDot} style={{ animationDelay: '0.2s' }} />
                    <span className={styles.chatThinkingDot} style={{ animationDelay: '0.4s' }} />
                  </div>
                </div>
              </div>
            )}

            <div ref={messagesEndRef} />
          </div>

          {/* Chat usage indicator for limited tiers */}
          {!isUnlimited && chatLimit > 0 && !isChatLimited && (
            <div className={styles.chatUsageBar}>
              {chatUsed}/{chatLimit} messages this month
            </div>
          )}

          {/* Input */}
          {isChatLimited ? (
            <div className={styles.chatLimitedWrap}>
              <div className={styles.chatLimitedTitle}>
                Monthly chat limit reached ({chatUsed}/{chatLimit})
              </div>
              <div className={styles.chatLimitedHint}>
                Upgrade to Pro for unlimited Riggs access
              </div>
            </div>
          ) : (
          <form onSubmit={sendMessage} className={styles.chatInputForm}>
            <input
              type="text"
              value={newMessage}
              onChange={(e) => setNewMessage(e.target.value)}
              placeholder={connected ? "Ask about this investigation..." : "Connecting..."}
              disabled={!connected || sending}
              className={styles.chatInput}
            />
            <button
              type="submit"
              disabled={!newMessage.trim() || !connected || sending}
              className={newMessage.trim() && connected ? styles.chatSendBtnActive : styles.chatSendBtnDisabled}
            >
              {sending ? '...' : 'Send'}
            </button>
          </form>
          )}
        </>
      )}
    </div>
  );
}

// ============================================================================
// HELPER COMPONENTS
// ============================================================================

function StateIndicator({ state }) {
  const colors = {
    'NEW': { bg: 'rgba(59, 130, 246, 0.15)', color: '#3b82f6' },
    'IN_PROGRESS': { bg: 'rgba(245, 158, 11, 0.15)', color: '#f59e0b' },
    'RIGGS_REVIEW': { bg: 'rgba(249, 115, 22, 0.15)', color: '#f97316' },
    'RIGGS_ANALYZED': { bg: 'rgba(139, 92, 246, 0.15)', color: '#8b5cf6' },
    'AWAITING_HUMAN': { bg: 'rgba(234, 179, 8, 0.15)', color: '#eab308' },
    'NEEDS_REVIEW': { bg: 'rgba(234, 179, 8, 0.15)', color: '#eab308' },
    'PENDING': { bg: 'rgba(60, 179, 113, 0.15)', color: '#3CB371' },
    'ESCALATED': { bg: 'rgba(239, 68, 68, 0.15)', color: '#ef4444' },
    'CLOSED': { bg: 'rgba(107, 114, 128, 0.15)', color: '#6b7280' },
    'RESOLVED': { bg: 'rgba(34, 197, 94, 0.15)', color: '#22c55e' },
    // Two-track triage states
    'TRIAGE_RUNNING': { bg: 'rgba(59, 130, 246, 0.15)', color: '#3b82f6' },
    'TRIAGE_PROVISIONAL': { bg: 'rgba(245, 158, 11, 0.15)', color: '#f59e0b' },
    'ENRICHMENT_RUNNING': { bg: 'rgba(59, 130, 246, 0.15)', color: '#3b82f6' },
    'MERGE_PENDING': { bg: 'rgba(139, 92, 246, 0.15)', color: '#8b5cf6' },
    'CONFIRMED': { bg: 'rgba(34, 197, 94, 0.15)', color: '#22c55e' },
    'ANALYZING': { bg: 'rgba(139, 92, 246, 0.15)', color: '#8b5cf6' }
  };

  const style = colors[state] || colors['NEW'];

  // Display friendly name
  const displayNames = {
    'RIGGS_REVIEW': 'RIGGS REVIEW',
    'AWAITING_HUMAN': 'AWAITING HUMAN',
    'TRIAGE_RUNNING': 'TRIAGE',
    'TRIAGE_PROVISIONAL': 'PROVISIONAL',
    'ENRICHMENT_RUNNING': 'ENRICHING',
    'MERGE_PENDING': 'MERGING',
    'CONFIRMED': 'CONFIRMED'
  };

  return (
    <span className={styles.stateIndicator} style={{
      background: style.bg,
      color: style.color
    }}>
      {displayNames[state] || state?.replace(/_/g, ' ') || 'New'}
    </span>
  );
}

function getIOCTypeColor(type) {
  const root = getComputedStyle(document.documentElement);
  switch (type?.toLowerCase()) {
    case 'url': return root.getPropertyValue('--info').trim() || '#3b82f6';
    case 'domain': return root.getPropertyValue('--accent-purple').trim() || '#8b5cf6';
    case 'ip': return root.getPropertyValue('--accent-cyan').trim() || '#06b6d4';
    case 'hash': return root.getPropertyValue('--warning').trim() || '#f59e0b';
    case 'email': return root.getPropertyValue('--accent-pink').trim() || '#ec4899';
    case 'file': return '#84cc16';
    default: return root.getPropertyValue('--text-muted').trim() || '#6b7280';
  }
}

function getReputationColor(reputation) {
  const root = getComputedStyle(document.documentElement);
  switch (reputation?.toLowerCase()) {
    case 'malicious': return root.getPropertyValue('--danger').trim() || '#ef4444';
    case 'suspicious': return root.getPropertyValue('--warning').trim() || '#f59e0b';
    case 'clean': return root.getPropertyValue('--success').trim() || '#22c55e';
    case 'benign': return root.getPropertyValue('--success').trim() || '#22c55e';
    default: return root.getPropertyValue('--text-muted').trim() || '#6b7280';
  }
}

function getSeverityColor(severity) {
  const root = getComputedStyle(document.documentElement);
  switch (severity?.toLowerCase()) {
    case 'critical': return root.getPropertyValue('--danger').trim() || '#ef4444';
    case 'high': return root.getPropertyValue('--warning').trim() || '#f97316';
    case 'medium': return root.getPropertyValue('--warning').trim() || '#eab308';
    case 'low': return root.getPropertyValue('--success').trim() || '#22c55e';
    default: return 'var(--text-muted)';
  }
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

function extractVerdictData(investigation, alertData) {
  let invData = investigation?.investigation_data || {};
  if (typeof invData === 'string') {
    try { invData = JSON.parse(invData); } catch { invData = {}; }
  }

  const riggsAnalysis = invData.riggs_analysis || {};
  const tier3 = invData.tier3_analysis || {};
  const tier2 = invData.tier2_analysis || {};
  const tier1 = invData.tier1_analysis || {};

  let verdict = '';
  let confidence = 0;
  let tier = '';
  let summary = '';

  // Normalize confidence: if > 1, it's already a percentage; otherwise multiply by 100
  const normalizeConfidence = (c) => Math.round((c || 0) > 1 ? (c || 0) : (c || 0) * 100);

  // Priority: riggs_analysis (deep analysis) > tier3 > tier2 > tier1 > ai_verdict (T1 triage) > alertData
  // Riggs deep analysis is always more accurate than the initial T1 triage ai_verdict
  if (riggsAnalysis.verdict) {
    verdict = riggsAnalysis.verdict;
    confidence = normalizeConfidence(riggsAnalysis.confidence);
    tier = 'Riggs AI';
    summary = riggsAnalysis.summary || riggsAnalysis.reasoning;
  } else if (tier3.verdict) {
    verdict = tier3.verdict;
    confidence = normalizeConfidence(tier3.confidence);
    tier = 'Riggs AI';
    summary = tier3.summary || tier3.reasoning;
  } else if (tier2.verdict) {
    verdict = tier2.verdict;
    confidence = normalizeConfidence(tier2.confidence);
    tier = 'Riggs AI';
    summary = tier2.summary || tier2.reasoning;
  } else if (tier1.verdict) {
    verdict = tier1.verdict;
    confidence = normalizeConfidence(tier1.confidence);
    tier = 'Riggs AI';
    summary = tier1.summary || tier1.reasoning;
  } else if (investigation?.ai_verdict) {
    verdict = investigation.ai_verdict;
    confidence = normalizeConfidence(investigation.ai_confidence);
    tier = 'Riggs AI';
    summary = investigation.ai_summary;
  } else if (alertData?.ai_verdict) {
    verdict = alertData.ai_verdict;
    confidence = normalizeConfidence(alertData.ai_confidence);
    tier = 'Riggs AI';
    summary = alertData.ai_summary;
  }

  // TRUE_POSITIVE from Riggs means a confirmed real alert (e.g. spam, social engineering)
  // but does NOT automatically mean malicious -- depends on threat_type
  const isMalicious = ['malicious', 'needs_escalation'].includes(verdict?.toLowerCase());
  const isBenign = ['benign', 'clean', 'false_positive'].includes(verdict?.toLowerCase());
  const isSuspicious = ['suspicious', 'needs_investigation'].includes(verdict?.toLowerCase());

  let color, label, headerBg;
  if (isMalicious) {
    color = '#ef4444';
    label = 'Malicious';
    headerBg = 'rgba(239, 68, 68, 0.08)';
  } else if (isBenign) {
    color = '#22c55e';
    label = 'Benign';
    headerBg = 'rgba(34, 197, 94, 0.08)';
  } else if (isSuspicious) {
    color = '#f59e0b';
    label = 'Suspicious';
    headerBg = 'rgba(245, 158, 11, 0.08)';
  } else {
    color = '#6b7280';
    label = 'Pending';
    headerBg = 'rgba(107, 114, 128, 0.05)';
  }

  let whyItMatters = summary || 'Awaiting analysis...';
  if (whyItMatters.length > 150) {
    whyItMatters = whyItMatters.substring(0, 147) + '...';
  }

  let riggsStatement;
  if (isMalicious) {
    riggsStatement = `This looks like a real threat. ${confidence}% confident. I'd escalate this one.`;
  } else if (isBenign) {
    riggsStatement = `This appears to be a false positive. Safe to close unless you see something I missed.`;
  } else if (isSuspicious) {
    riggsStatement = `I'm not 100% on this one - needs a closer look before we decide.`;
  } else {
    riggsStatement = `Still analyzing this alert. Give me a moment to gather more context.`;
  }

  return {
    verdict,
    label,
    color,
    headerBg,
    confidence,
    tier,
    summary,
    whyItMatters,
    riggsStatement,
    isMalicious,
    isBenign,
    isSuspicious
  };
}

function extractContextFacts(rawEvent, alertData, investigation) {
  const facts = [];
  const seen = new Set();

  const addFact = (label, value, mono = false) => {
    if (!value || seen.has(label)) return;
    let displayValue = value;
    if (typeof value === 'object' && value !== null) {
      displayValue = value.userName || value.name || value.value || value.id || JSON.stringify(value);
    }
    seen.add(label);
    facts.push({ label, value: String(displayValue), mono });
  };

  const hostname = rawEvent.computerDnsName || rawEvent.hostname || rawEvent.host || rawEvent.computer_name;
  const user = (typeof rawEvent.relatedUser === 'object' ? rawEvent.relatedUser?.userName : rawEvent.relatedUser)
    || rawEvent.user || rawEvent.username || rawEvent.account;

  addFact('Hostname', hostname);
  addFact('User', user);
  addFact('IP Address', rawEvent.source_ip || rawEvent.src_ip || rawEvent.dest_ip, true);
  addFact('Source', alertData?.source || rawEvent.detectionSource);
  addFact('Category', alertData?.category || rawEvent.category);

  if (rawEvent.evidence && Array.isArray(rawEvent.evidence)) {
    rawEvent.evidence.forEach((item) => {
      if (item.entityType === 'Process' && item.fileName) {
        addFact('Process', item.fileName);
        if (item.processCommandLine) {
          addFact('Command', item.processCommandLine.substring(0, 100) + (item.processCommandLine.length > 100 ? '...' : ''));
        }
      }
      if (item.entityType === 'File' && item.sha256) {
        addFact('File Hash', item.sha256, true);
      }
    });
  }

  addFact('Sender', rawEvent.sender || rawEvent.from);
  addFact('Subject', rawEvent.subject);
  addFact('Reporter', rawEvent.reporter);
  addFact('Domain', rawEvent.domain, true);
  addFact('URL', rawEvent.url, true);

  return facts;
}

function formatDuration(startTime) {
  if (!startTime) return 'Unknown';
  const start = new Date(startTime);
  const now = new Date();
  const diffMs = now - start;
  const hours = Math.floor(diffMs / 3600000);
  const mins = Math.floor((diffMs % 3600000) / 60000);

  if (hours > 0) return `${hours}h ${mins}m`;
  return `${mins}m`;
}

export default InvestigationWorkbenchV2;


