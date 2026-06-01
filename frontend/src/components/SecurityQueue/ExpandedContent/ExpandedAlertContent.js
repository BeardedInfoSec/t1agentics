/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

/**
 * ExpandedAlertContent Component
 *
 * Expanded view for alert items showing analysis, enrichment, IOCs, and actions.
 * Layout matches the investigation expanded view for visual consistency.
 */

import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import GroupedIocDisplay from './GroupedIocDisplay';
import InlineOwnerSelect from './InlineOwnerSelect';
import InlineDropdown from './InlineDropdown';
import Badge from '../../ui/Badge';
import Button from '../../ui/Button';
import RecommendedActions from '../../RecommendedActions';
import { authFetch, API_BASE_URL } from '../../../utils/api';
import {
  severityToBadgeVariant,
  verdictToBadgeVariant,
} from '../../../styles/colors';
import styles from '../SecurityQueue.module.css';

const SEVERITY_OPTIONS = ['critical', 'high', 'medium', 'low'];
const ALERT_STATUS_OPTIONS = ['open', 'investigating', 'in_progress', 'needs_review', 'resolved', 'closed'];

/**
 * Simple JSON viewer for the raw data panel
 * Top level is always expanded, nested items collapse based on size
 */
function JsonViewer({ data, depth = 0 }) {
  const getDefaultCollapsed = () => {
    if (depth === 0) return false;
    if (Array.isArray(data) && data.length > 5) return true;
    if (typeof data === 'object' && data !== null && Object.keys(data).length > 5) return true;
    if (depth > 2) return true;
    return false;
  };

  const [collapsed, setCollapsed] = useState(getDefaultCollapsed);
  const [copied, setCopied] = useState(false);

  const copyValue = (value) => {
    navigator.clipboard.writeText(String(value));
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  if (data === null) return <span style={{ color: '#f87171' }}>null</span>;
  if (data === undefined) return <span style={{ color: '#f87171' }}>undefined</span>;
  if (typeof data === 'boolean') return (
    <span style={{ color: '#f472b6', cursor: 'pointer', position: 'relative' }} onClick={() => copyValue(data)} title="Click to copy">
      {String(data)}
      {copied && <span style={{ marginLeft: '0.5rem', color: '#22c55e', fontSize: '0.7rem' }}>Copied!</span>}
    </span>
  );
  if (typeof data === 'number') return (
    <span style={{ color: '#a78bfa', cursor: 'pointer', position: 'relative' }} onClick={() => copyValue(data)} title="Click to copy">
      {data}
      {copied && <span style={{ marginLeft: '0.5rem', color: '#22c55e', fontSize: '0.7rem' }}>Copied!</span>}
    </span>
  );
  if (typeof data === 'string') return (
    <span style={{ color: '#4ade80', cursor: 'pointer', position: 'relative' }} onClick={() => copyValue(data)} title="Click to copy">
      "{data}"
      {copied && <span style={{ marginLeft: '0.5rem', color: '#22c55e', fontSize: '0.7rem' }}>Copied!</span>}
    </span>
  );

  if (Array.isArray(data)) {
    if (data.length === 0) return <span>[]</span>;
    if (collapsed) {
      return (
        <span onClick={() => setCollapsed(false)} style={{ cursor: 'pointer', color: '#94a3b8' }}>
          [{data.length} items] &#9656;
        </span>
      );
    }
    return (
      <span>
        <span onClick={() => setCollapsed(true)} style={{ cursor: 'pointer', color: '#94a3b8' }}>&#9662; [</span>
        <div style={{ paddingLeft: '1rem' }}>
          {data.map((item, i) => (
            <div key={i}>
              <JsonViewer data={item} depth={depth + 1} />
              {i < data.length - 1 && ','}
            </div>
          ))}
        </div>
        ]
      </span>
    );
  }

  if (typeof data === 'object') {
    const keys = Object.keys(data);
    if (keys.length === 0) return <span>{'{}'}</span>;
    if (collapsed) {
      return (
        <span onClick={() => setCollapsed(false)} style={{ cursor: 'pointer', color: '#94a3b8' }}>
          {'{' + keys.length + ' keys}'} &#9656;
        </span>
      );
    }
    return (
      <span>
        <span onClick={() => setCollapsed(true)} style={{ cursor: 'pointer', color: '#94a3b8' }}>&#9662; {'{'}</span>
        <div style={{ paddingLeft: '1rem' }}>
          {keys.map((key, i) => (
            <div key={key}>
              <span style={{ color: '#60a5fa' }}>"{key}"</span>: <JsonViewer data={data[key]} depth={depth + 1} />
              {i < keys.length - 1 && ','}
            </div>
          ))}
        </div>
        {'}'}
      </span>
    );
  }

  return <span>{String(data)}</span>;
}

// IOC type icons and colors (text symbols only, no emojis)
const IOC_TYPE_CONFIG = {
  hash: { icon: '#', color: '#f59e0b' },
  domain: { icon: '@', color: '#3b82f6' },
  ip: { icon: '\u25CF', color: '#8b5cf6' },
  url: { icon: '\u2197', color: '#06b6d4' },
  file: { icon: '\u2261', color: '#22c55e' },
  email: { icon: '\u2709', color: '#ec4899' },
  unknown: { icon: '?', color: '#6b7280' },
};

/**
 * Format date for display
 */
function formatDateTime(dateStr) {
  if (!dateStr) return '-';
  const date = new Date(dateStr);
  return date.toLocaleDateString('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

/**
 * ExpandedAlertContent Component
 * @param {Object} props
 * @param {import('../types').SecurityQueueItem} props.item - Alert queue item
 * @param {Function} props.onRefresh - Refresh data handler
 * @param {Object} props.systemConfig - System configuration
 */
function ExpandedAlertContent({ item, onRefresh, onFieldUpdate, systemConfig }) {
  const navigate = useNavigate();
  const [creating, setCreating] = useState(false);
  const [error, setError] = useState(null);
  const [showRawDataPanel, setShowRawDataPanel] = useState(false);

  // Editable field state
  const [localSeverity, setLocalSeverity] = useState(item.severity || 'medium');
  const [localStatus, setLocalStatus] = useState(item.status || 'open');
  const [localOwner, setLocalOwner] = useState(item.owner || '');
  const [localSensitivity, setLocalSensitivity] = useState(item.sensitivity || 'internal');
  const [copiedField, setCopiedField] = useState(null);
  const copyToClipboard = (text, field) => { navigator.clipboard.writeText(text); setCopiedField(field); setTimeout(() => setCopiedField(null), 1500); };

  const handleSeverityChange = async (newSeverity) => {
    const prev = localSeverity;
    setLocalSeverity(newSeverity);
    onFieldUpdate?.({ severity: newSeverity });
    try {
      if (item.investigation_id) {
        await authFetch(`${API_BASE_URL}/api/v1/investigations/${item.investigation_id}`, {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ severity: newSeverity }),
        });
      } else {
        await authFetch(`${API_BASE_URL}/api/v1/alerts/${item.alert_id}/severity`, {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ severity: newSeverity }),
        });
      }
    } catch (e) { setError('Failed to update severity'); setLocalSeverity(prev); onFieldUpdate?.({ severity: prev }); }
  };

  const handleStatusChange = async (newStatus) => {
    const prev = localStatus;
    setLocalStatus(newStatus);
    onFieldUpdate?.({ status: newStatus });
    try {
      if (item.investigation_id) {
        await authFetch(`${API_BASE_URL}/api/v1/investigations/${item.investigation_id}/state`, {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ state: newStatus }),
        });
      } else {
        await authFetch(`${API_BASE_URL}/api/v1/alerts/${item.alert_id}/status`, {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ status: newStatus }),
        });
      }
    } catch (e) { setError('Failed to update status'); setLocalStatus(prev); onFieldUpdate?.({ status: prev }); }
  };

  const handleOwnerChange = async (newOwner) => {
    const prev = localOwner;
    setLocalOwner(newOwner);
    onFieldUpdate?.({ owner: newOwner });
    if (item.investigation_id) {
      try {
        await authFetch(`${API_BASE_URL}/api/v1/investigations/${item.investigation_id}`, {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ owner: newOwner }),
        });
      } catch (e) { setError('Failed to update owner'); setLocalOwner(prev); onFieldUpdate?.({ owner: prev }); }
    }
  };

  // ─── Quick-action handlers used by the header buttons ─────────────────
  // These exist so common triage actions are one click from the drawer
  // instead of buried behind dropdowns + multi-step changes.

  const [busyAction, setBusyAction] = useState(null);
  const [noteOpen, setNoteOpen] = useState(false);
  const [noteText, setNoteText] = useState('');
  const [savingNote, setSavingNote] = useState(false);
  const [meUser, setMeUser] = useState(null);

  // Fetch the current user once when the drawer mounts so "Assign to me"
  // knows who "me" is without forcing the user to open the owner dropdown.
  useEffect(() => {
    let cancelled = false;
    authFetch(`${API_BASE_URL}/api/v1/users/me`)
      .then((r) => (r.ok ? r.json() : null))
      .then((u) => { if (!cancelled && u) setMeUser(u); })
      .catch(() => {});
    return () => { cancelled = true; };
  }, []);

  const handleAssignToMe = async () => {
    if (!meUser?.username || busyAction) return;
    setBusyAction('assign');
    try {
      await handleOwnerChange(meUser.username);
    } finally {
      setBusyAction(null);
    }
  };

  // Drives the three "Close as ..." buttons. Sends status + disposition in
  // one PATCH; backend cascade lifts the investigation state in the same
  // request so the dashboard and drawer stay in sync.
  const closeAsDisposition = async (label, status, disposition) => {
    if (busyAction) return;
    setBusyAction(label);
    const prevStatus = localStatus;
    setLocalStatus(status);
    onFieldUpdate?.({ status, disposition });
    try {
      const res = await authFetch(`${API_BASE_URL}/api/v1/alerts/${item.alert_id}/status`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status, disposition }),
      });
      if (!res.ok) throw new Error('Status update failed');
    } catch (e) {
      setError(`Failed to close as ${label.toLowerCase()}`);
      setLocalStatus(prevStatus);
      onFieldUpdate?.({ status: prevStatus });
    } finally {
      setBusyAction(null);
    }
  };

  const handleAddNote = async () => {
    if (!noteText.trim() || savingNote) return;
    if (!item.investigation_id) {
      setError('Notes attach to investigations — promote this alert first.');
      return;
    }
    setSavingNote(true);
    try {
      const res = await authFetch(
        `${API_BASE_URL}/api/v1/investigations/${item.investigation_id}/notes`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            content: noteText.trim(),
            author: meUser?.username || 'analyst',
            author_type: 'HUMAN',
            note_type: 'HUMAN_NOTE',
          }),
        },
      );
      if (!res.ok) throw new Error('Note save failed');
      setNoteText('');
      setNoteOpen(false);
    } catch (e) {
      setError('Failed to add note');
    } finally {
      setSavingNote(false);
    }
  };

  const handleEscalate = async () => {
    if (busyAction) return;
    setBusyAction('escalate');
    try {
      const res = await authFetch(`${API_BASE_URL}/api/v1/alerts/${item.alert_id}/escalate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      });
      if (!res.ok) throw new Error('Escalation failed');
      const data = await res.json().catch(() => ({}));
      if (data?.severity && data.severity !== localSeverity) {
        setLocalSeverity(data.severity);
        onFieldUpdate?.({ severity: data.severity });
      }
    } catch (e) {
      setError('Failed to escalate');
    } finally {
      setBusyAction(null);
    }
  };

  const SENSITIVITY_OPTIONS = ['public', 'internal', 'confidential', 'restricted'];

  const handleSensitivityChange = async (newSensitivity) => {
    const prev = localSensitivity;
    setLocalSensitivity(newSensitivity);
    onFieldUpdate?.({ sensitivity: newSensitivity });
    try {
      const res = await authFetch(`${API_BASE_URL}/api/v1/alerts/${item.alert_id}/sensitivity`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ sensitivity: newSensitivity }),
      });
      if (!res.ok) throw new Error();
    } catch (e) { setError('Failed to update sensitivity'); setLocalSensitivity(prev); onFieldUpdate?.({ sensitivity: prev }); }
  };

  const alert = item.alert_context || {};
  const rawEvent = alert.raw_event || {};
  const extracted = rawEvent._extracted || {};
  const enrichment = extracted.enrichment || {};
  const iocs = extracted.iocs || {};

  // AI Verdict / Triage info
  const aiVerdict = alert.ai_verdict || item.ai_verdict;
  const aiConfidence = alert.ai_confidence || item.ai_confidence;
  const confValue = aiConfidence ? Math.round(aiConfidence > 1 ? aiConfidence : aiConfidence * 100) : null;

  // AI triage results (stored after enrichment + triage pipeline)
  const triageResult = alert.triage_result || alert.ai_triage_result || rawEvent.triage_result || extracted.ai_triage || {};
  // enrichment.summary is an object {clean, unknown, malicious, ...} — NOT a text string
  const triageSummary = triageResult.summary || triageResult.analysis || alert.ai_summary || '';

  // Key findings from triage or enrichment
  const normalizeFindings = (findings) => {
    if (!findings || !Array.isArray(findings)) return [];
    return findings.map(f => {
      if (typeof f === 'string') return f;
      if (typeof f === 'object') return f.finding || f.description || f.text || f.summary || JSON.stringify(f);
      return String(f);
    }).filter(Boolean);
  };

  const keyFindings = normalizeFindings(
    triageResult.key_findings || triageResult.findings || enrichment.key_findings || alert.key_findings || []
  );

  // Recommended actions
  const normalizeRecommendations = (recs) => {
    if (!recs || !Array.isArray(recs)) return [];
    return recs.map(r => {
      if (typeof r === 'string') return r;
      if (typeof r === 'object') return r.action || r.description || r.recommendation || r.text || JSON.stringify(r);
      return String(r);
    }).filter(Boolean);
  };

  const serverRecommendations = normalizeRecommendations(
    triageResult.recommended_actions || triageResult.recommendations || alert.recommended_actions || []
  );

  // When the server hasn't generated recommendations for this alert yet
  // (Riggs hasn't run, or no IOC-actionable connectors), surface verdict-
  // intent fallbacks so analysts always have an actionable next step in
  // the drawer instead of staring at "Key Findings" with no follow-up.
  // Mirrors the demo's intent-aware pattern.
  const fallbackRecommendations = (() => {
    if (serverRecommendations.length > 0) return [];
    const verdict = (alert.ai_verdict || alert.disposition || '').toUpperCase();
    if (!verdict) return [];

    // Try to find a sender domain for the whitelist suggestion
    const senderDomain = (() => {
      const fromEmail = rawEvent.from_email || rawEvent.from || rawEvent.sender || '';
      const m = String(fromEmail).match(/@([^>\s]+)/);
      if (m) return m[1].toLowerCase();
      // Fall back to the first non-infra domain among IOCs
      const iocList = Array.isArray(alert.iocs) ? alert.iocs : [];
      const domHit = iocList.find(i => (i?.type || '').toLowerCase() === 'domain' && i.value);
      return domHit?.value?.toLowerCase() || '';
    })();

    if (['BENIGN', 'FALSE_POSITIVE', 'BENIGN_POSITIVE'].includes(verdict)) {
      const out = ['Auto-close as false positive'];
      if (senderDomain) out.push(`Whitelist sender ${senderDomain}`);
      out.push('Tune the detection rule that flagged this alert');
      return out;
    }
    if (verdict === 'MALICIOUS') {
      return [
        'Open incident ticket and notify on-call',
        'Approve block actions on the IOCs below',
        'Contain affected hosts / disable affected accounts',
      ];
    }
    if (['SUSPICIOUS', 'NEEDS_INVESTIGATION', 'NEEDS_REVIEW'].includes(verdict)) {
      return [
        'Escalate to senior analyst for manual review',
        'Run deeper analysis before any containment action',
      ];
    }
    return [];
  })();

  const recommendations = serverRecommendations.length > 0
    ? serverRecommendations
    : fallbackRecommendations;

  // Description / summary text — strip HTML tags and limit length
  // (email bodies contain raw HTML that would render as ugly markup)
  const rawDescription = triageSummary || alert.description || rawEvent.description || '';
  const description = (() => {
    if (typeof rawDescription !== 'string') return '';
    const stripped = rawDescription.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
    return stripped.length > 800 ? stripped.slice(0, 800) + '…' : stripped;
  })();

  // Enrichment summary stats
  const enrichmentSummary = (typeof enrichment.summary === 'object' && enrichment.summary) ? enrichment.summary : null;

  // Threat type
  const threatType = triageResult.threat_type || alert.threat_type || enrichment.threat_type || '';

  // Disposition and false positive likelihood
  const disposition = triageResult.disposition || alert.disposition || '';
  const fpLikelihood = triageResult.false_positive_likelihood;

  // Email auth status (for email alerts)
  const emailAuth = triageResult.email_auth_status || extracted.email_auth || null;

  // Source info
  const source = item.source || alert.source || rawEvent.source || 'Unknown';

  // Analysis source label
  const hasTriageText = typeof triageSummary === 'string' && triageSummary.length > 0;
  const analysisSource = hasTriageText ? 'AI TRIAGE' :
                         enrichment.status === 'enriched' ? 'ENRICHMENT ANALYSIS' : 'ALERT DETAILS';

  // Collect IOCs from various sources
  const allIocs = [];
  if (iocs.ips) {
    iocs.ips.forEach(ip => allIocs.push({ type: 'ip', value: ip, verdict: 'unknown' }));
  }
  if (iocs.domains) {
    iocs.domains.forEach(d => allIocs.push({ type: 'domain', value: d, verdict: 'unknown' }));
  }
  if (iocs.hashes) {
    iocs.hashes.forEach(h => allIocs.push({ type: 'hash', value: h, verdict: 'unknown' }));
  }
  if (iocs.urls) {
    iocs.urls.forEach(u => allIocs.push({ type: 'url', value: u, verdict: 'unknown' }));
  }

  // Enriched IOCs with verdicts — results are in enrichment.results.{ips,domains,hashes,urls}
  const enrichmentResults = enrichment.results || {};
  const enrichedIocLists = [
    ...(enrichmentResults.ips || []),
    ...(enrichmentResults.domains || []),
    ...(enrichmentResults.hashes || []),
    ...(enrichmentResults.urls || []),
  ];
  enrichedIocLists.forEach(ind => {
    const existing = allIocs.find(i => i.value === ind.value);
    if (existing) {
      existing.verdict = ind.verdict || 'unknown';
      existing.sources = ind.sources;
      existing.score = ind.score;
      existing.country = ind.country;
      existing.asn = ind.asn;
      existing.sources_checked = ind.sources_checked;
      existing.sources_flagged = ind.sources_flagged;
    } else {
      allIocs.push({
        type: ind.type || 'unknown',
        value: ind.value,
        verdict: ind.verdict || 'unknown',
        sources: ind.sources,
        score: ind.score,
        country: ind.country,
        asn: ind.asn,
      });
    }
  });

  // Sort IOCs: malicious first, then suspicious, then benign, then unknown
  const getVerdictPriority = (ioc) => {
    const v = (ioc.verdict || '').toLowerCase();
    if (v === 'malicious') return 0;
    if (v === 'suspicious') return 1;
    if (v === 'benign' || v === 'clean') return 2;
    return 3;
  };
  allIocs.sort((a, b) => getVerdictPriority(a) - getVerdictPriority(b));

  const maliciousCount = allIocs.filter(i => (i.verdict || '').toLowerCase() === 'malicious').length;
  const suspiciousCount = allIocs.filter(i => (i.verdict || '').toLowerCase() === 'suspicious').length;

  // Create investigation from alert
  const handleCreateInvestigation = async () => {
    setCreating(true);
    setError(null);

    try {
      const response = await authFetch(`${API_BASE_URL}/api/v1/investigations`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          alert_id: item.alert_id,
          priority: item.severity === 'critical' ? 'P1' : item.severity === 'high' ? 'P2' : 'P3',
        }),
      });

      if (!response.ok) {
        throw new Error('Failed to create investigation');
      }

      const data = await response.json();
      onRefresh?.();
      navigate(`/investigation/${data.investigation_id}`);
    } catch (err) {
      setError(err.message);
    } finally {
      setCreating(false);
    }
  };

  // Terminal alert statuses — if already in one of these, hide the
  // "Close as ..." buttons. Reopening is a different gesture.
  const isClosed = ['closed', 'resolved', 'false_positive', 'confirmed'].includes(
    String(localStatus).toLowerCase(),
  );

  return (
    <div className={styles.expandedContent}>
      {/* Action Buttons - top row */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.75rem', flexWrap: 'wrap' }}>
        {error && <p className={styles.errorText} style={{ margin: 0, marginRight: '0.5rem' }}>{error}</p>}
        {item.investigation_id ? (
          <Button
            variant="primary"
            size="sm"
            onClick={() => navigate(`/investigation/${item.investigation_id}`)}
          >
            Open Full Investigation
          </Button>
        ) : (
          <Button
            variant="primary"
            size="sm"
            onClick={handleCreateInvestigation}
            disabled={creating}
          >
            {creating ? 'Creating...' : 'Create Investigation'}
          </Button>
        )}
        <Button
          variant="secondary"
          size="sm"
          onClick={() => setShowRawDataPanel(!showRawDataPanel)}
        >
          {showRawDataPanel ? 'Back to Analysis' : 'View Raw Log'}
        </Button>

        {/* Separator */}
        <span style={{ width: 1, height: 22, background: 'rgba(255,255,255,0.12)', margin: '0 0.25rem' }} />

        {/* Assign to me — disabled until we know who "me" is. */}
        <Button
          variant="secondary"
          size="sm"
          onClick={handleAssignToMe}
          disabled={!meUser || busyAction === 'assign' || localOwner === meUser?.username}
          title={meUser ? `Assign owner to ${meUser.username}` : 'Loading user...'}
        >
          {localOwner === meUser?.username ? 'Assigned to me' : (busyAction === 'assign' ? 'Assigning...' : 'Assign to me')}
        </Button>

        {/* Close-as buttons — hidden once the alert is terminal */}
        {!isClosed && (
          <>
            <Button
              variant="secondary"
              size="sm"
              onClick={() => closeAsDisposition('Benign', 'resolved', 'BENIGN')}
              disabled={!!busyAction}
              title="Mark resolved and dispose as benign"
            >
              {busyAction === 'Benign' ? 'Closing...' : 'Close as Benign'}
            </Button>
            <Button
              variant="secondary"
              size="sm"
              onClick={() => closeAsDisposition('FP', 'false_positive', 'FALSE_POSITIVE')}
              disabled={!!busyAction}
              title="Close as a false positive"
            >
              {busyAction === 'FP' ? 'Closing...' : 'Close as FP'}
            </Button>
            <Button
              variant="secondary"
              size="sm"
              onClick={() => closeAsDisposition('TP', 'confirmed', 'TRUE_POSITIVE')}
              disabled={!!busyAction}
              title="Confirm as a true positive"
            >
              {busyAction === 'TP' ? 'Closing...' : 'Close as TP'}
            </Button>
          </>
        )}

        <Button
          variant="secondary"
          size="sm"
          onClick={() => setNoteOpen((v) => !v)}
          title={item.investigation_id ? 'Add a timeline note' : 'Promote to investigation first'}
          disabled={!item.investigation_id}
        >
          {noteOpen ? 'Cancel note' : 'Add note'}
        </Button>

        <Button
          variant="danger"
          size="sm"
          onClick={handleEscalate}
          disabled={busyAction === 'escalate' || localSeverity === 'critical'}
          title={localSeverity === 'critical' ? 'Already at critical severity' : 'Bump to critical and notify the team'}
        >
          {busyAction === 'escalate' ? 'Escalating...' : 'Escalate'}
        </Button>
      </div>

      {noteOpen && (
        <div style={{ marginBottom: '0.75rem', padding: '0.6rem', background: 'rgba(255,255,255,0.03)', borderRadius: 6, border: '1px solid rgba(255,255,255,0.08)' }}>
          <textarea
            value={noteText}
            onChange={(e) => setNoteText(e.target.value)}
            placeholder="Add a quick note pinned to the investigation timeline..."
            rows={3}
            style={{
              width: '100%', padding: '0.5rem',
              background: 'var(--bg-tertiary)', color: 'var(--text-primary)',
              border: '1px solid var(--border-color)', borderRadius: 4,
              fontSize: '0.85rem', resize: 'vertical', fontFamily: 'inherit',
            }}
          />
          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.5rem', marginTop: '0.4rem' }}>
            <Button variant="secondary" size="sm" onClick={() => { setNoteOpen(false); setNoteText(''); }}>Cancel</Button>
            <Button variant="primary" size="sm" onClick={handleAddNote} disabled={!noteText.trim() || savingNote}>
              {savingNote ? 'Saving...' : 'Save note'}
            </Button>
          </div>
        </div>
      )}

      {/* Metadata Grid */}
      {(() => {
        const labelStyle = { display: 'block', fontSize: '0.7rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '0.2rem' };
        const valueStyle = { display: 'block', fontSize: '0.85rem', color: 'var(--text-primary)', fontWeight: 500 };
        const codeStyle = { display: 'block', fontSize: '0.8rem', color: 'var(--info)', fontFamily: "'SF Mono', Monaco, Consolas, monospace", fontWeight: 500, cursor: 'pointer' };
        return (
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fill, minmax(180px, 1fr))',
        gap: '0.6rem 2rem',
        marginBottom: '0.75rem',
      }}>
        <div>
          <span style={labelStyle}>Alert ID</span>
          <code style={codeStyle} onClick={() => copyToClipboard(item.alert_id, 'alertId')} title="Click to copy">
            {item.alert_id}
            {copiedField === 'alertId' && <span style={{ marginLeft: '0.4rem', color: '#22c55e', fontSize: '0.6rem' }}>Copied!</span>}
          </code>
        </div>
        <div>
          <span style={labelStyle}>Severity</span>
          <InlineDropdown
            value={localSeverity}
            options={SEVERITY_OPTIONS}
            onChange={handleSeverityChange}
            renderValue={(val) => (
              <span style={{ fontSize: '0.85rem', fontWeight: 500, color: 'var(--text-primary)' }}>
                {(val || 'unknown').toUpperCase()}
              </span>
            )}
            renderOption={(opt) => (
              <span>{opt.toUpperCase()}</span>
            )}
          />
        </div>
        <div>
          <span style={labelStyle}>Status</span>
          <InlineDropdown
            value={localStatus}
            options={item.item_type === 'investigation'
              ? ['NEW', 'ANALYZING', 'NEEDS_REVIEW', 'IN_PROGRESS', 'CLOSED']
              : ALERT_STATUS_OPTIONS}
            onChange={handleStatusChange}
            renderValue={(val) => (
              <span style={{ fontSize: '0.85rem', fontWeight: 500, color: 'var(--text-primary)' }}>
                {(val || '').replace(/_/g, ' ').toUpperCase()}
              </span>
            )}
            renderOption={(opt) => (
              <span>{opt.replace(/_/g, ' ').toUpperCase()}</span>
            )}
          />
        </div>
        <div>
          <span style={labelStyle}>Source</span>
          <span style={valueStyle}>{source}</span>
        </div>
        <div>
          <span style={labelStyle}>Owner</span>
          <InlineOwnerSelect
            value={localOwner}
            onChange={handleOwnerChange}
          />
        </div>
        <div>
          <span style={labelStyle}>Sensitivity</span>
          <InlineDropdown
            value={localSensitivity}
            options={SENSITIVITY_OPTIONS}
            onChange={handleSensitivityChange}
            renderValue={(val) => (
              <span style={{ fontSize: '0.85rem', fontWeight: 500, color: 'var(--text-primary)' }}>
                {(val || 'internal').toUpperCase()}
              </span>
            )}
            renderOption={(opt) => (
              <span>{opt.toUpperCase()}</span>
            )}
          />
        </div>
        <div>
          <span style={labelStyle}>Created</span>
          <span style={valueStyle}>{formatDateTime(item.created_at)}</span>
        </div>
        <div>
          <span style={labelStyle}>Updated</span>
          <span style={valueStyle}>{formatDateTime(item.updated_at)}</span>
        </div>
        {threatType && (
          <div>
            <span style={labelStyle}>Threat Type</span>
            <span style={valueStyle}>{threatType}</span>
          </div>
        )}
        {rawEvent.source_ip && (
          <div>
            <span style={labelStyle}>Source IP</span>
            <code style={codeStyle} onClick={() => copyToClipboard(rawEvent.source_ip, 'srcIp')} title="Click to copy">
              {rawEvent.source_ip}
              {copiedField === 'srcIp' && <span style={{ marginLeft: '0.4rem', color: '#22c55e', fontSize: '0.6rem' }}>Copied!</span>}
            </code>
          </div>
        )}
        {rawEvent.dest_ip && (
          <div>
            <span style={labelStyle}>Dest IP</span>
            <code style={codeStyle} onClick={() => copyToClipboard(rawEvent.dest_ip, 'dstIp')} title="Click to copy">
              {rawEvent.dest_ip}
              {copiedField === 'dstIp' && <span style={{ marginLeft: '0.4rem', color: '#22c55e', fontSize: '0.6rem' }}>Copied!</span>}
            </code>
          </div>
        )}
      </div>
        );
      })()}

      {/* Divider */}
      <div style={{ borderTop: '1px solid var(--border-color)', marginBottom: '0.75rem' }} />

      {/* Content below the line */}
      {/* Raw Data View (replaces analysis when toggled) */}
      {showRawDataPanel && (
        <div>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem' }}>
            <h4 className={styles.expandedSectionTitle} style={{ margin: 0 }}>RAW EVENT DATA</h4>
            <button
              onClick={() => {
                const eventData = rawEvent || alert || {};
                let toCopy = eventData;
                if (typeof eventData === 'string') {
                  try { toCopy = JSON.parse(eventData); } catch (e) { toCopy = eventData; }
                }
                navigator.clipboard.writeText(JSON.stringify(toCopy, null, 2));
              }}
              className={styles.rawDataCopyBtn}
            >
              Copy JSON
            </button>
          </div>
          <div style={{
            padding: '1rem',
            background: 'var(--bg-tertiary)',
            borderRadius: '6px',
            overflowX: 'auto',
            maxHeight: 'calc(100vh - 320px)',
            overflowY: 'auto',
            border: '1px solid var(--border-color)',
            fontFamily: 'monospace',
            fontSize: '0.7rem',
            lineHeight: 1.5,
            wordBreak: 'break-all',
            whiteSpace: 'pre-wrap',
          }}>
            <JsonViewer data={(() => {
              const eventData = rawEvent || alert || {};
              if (typeof eventData === 'string') {
                try { return JSON.parse(eventData); } catch (e) { return { raw: eventData }; }
              }
              return eventData;
            })()} />
          </div>
        </div>
      )}

      {!showRawDataPanel && (
      <>
        {/* AI Triage Section */}
        <div style={{ background: 'var(--bg-tertiary)', border: '1px solid var(--border-color)', borderRadius: '8px', padding: '0.75rem 1rem', marginBottom: '0.75rem', overflow: 'hidden' }}>
          <h4 className={styles.expandedSectionTitle} style={{ marginTop: 0 }}>AI TRIAGE</h4>
          <div className={styles.analysisHeader}>
            <span className={styles.analysisSource}>{analysisSource}</span>
            {confValue && (
              <span className={styles.analysisConfidence}>{'\u2022'} {confValue}% CONFIDENCE</span>
            )}
            {aiVerdict && (
              <>
                <span className={styles.analysisDot}>{'\u2022'}</span>
                <Badge variant={verdictToBadgeVariant(aiVerdict)} size="xs" solid>
                  {aiVerdict.replace(/_/g, ' ').toUpperCase()}
                </Badge>
              </>
            )}
          </div>

          {/* Description / Summary */}
          {description && (
            <p className={styles.analysisSummary} style={{ marginBottom: '0.5rem' }}>{description}</p>
          )}

          {/* Triage Detail Grid */}
          {(threatType || disposition || emailAuth || enrichmentSummary || fpLikelihood != null) && (
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(180px, 1fr))', gap: '0.5rem 1rem', marginTop: description ? 0 : '0.5rem', padding: '0.5rem 0', borderTop: description ? '1px solid var(--border-color)' : 'none' }}>
              {disposition && (
                <div>
                  <span style={{ fontSize: '0.65rem', textTransform: 'uppercase', color: 'var(--text-tertiary)', letterSpacing: '0.5px' }}>Disposition</span>
                  <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginTop: '2px' }}>{disposition.replace(/_/g, ' ')}</div>
                </div>
              )}
              {threatType && threatType !== 'none' && (
                <div>
                  <span style={{ fontSize: '0.65rem', textTransform: 'uppercase', color: 'var(--text-tertiary)', letterSpacing: '0.5px' }}>Threat Type</span>
                  <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginTop: '2px' }}>{threatType.replace(/_/g, ' ')}</div>
                </div>
              )}
              {fpLikelihood != null && (
                <div>
                  <span style={{ fontSize: '0.65rem', textTransform: 'uppercase', color: 'var(--text-tertiary)', letterSpacing: '0.5px' }}>False Positive Likelihood</span>
                  <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginTop: '2px' }}>{Math.round(fpLikelihood * 100)}%</div>
                </div>
              )}
              {emailAuth && (
                <div>
                  <span style={{ fontSize: '0.65rem', textTransform: 'uppercase', color: 'var(--text-tertiary)', letterSpacing: '0.5px' }}>Email Authentication</span>
                  <div style={{ fontSize: '0.8rem', marginTop: '2px', display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
                    {emailAuth.spf_pass != null && (
                      <Badge variant={emailAuth.spf_pass ? 'success' : 'danger'} size="xs">SPF {emailAuth.spf_pass ? 'PASS' : 'FAIL'}</Badge>
                    )}
                    {emailAuth.dkim_pass != null && (
                      <Badge variant={emailAuth.dkim_pass ? 'success' : 'danger'} size="xs">DKIM {emailAuth.dkim_pass ? 'PASS' : 'FAIL'}</Badge>
                    )}
                    {emailAuth.dmarc_pass != null && (
                      <Badge variant={emailAuth.dmarc_pass ? 'success' : 'danger'} size="xs">DMARC {emailAuth.dmarc_pass ? 'PASS' : 'FAIL'}</Badge>
                    )}
                  </div>
                </div>
              )}
              {enrichmentSummary && (
                <div>
                  <span style={{ fontSize: '0.65rem', textTransform: 'uppercase', color: 'var(--text-tertiary)', letterSpacing: '0.5px' }}>IOC Enrichment</span>
                  <div style={{ fontSize: '0.8rem', marginTop: '2px', display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
                    {enrichmentSummary.total_enriched != null && (
                      <span style={{ color: 'var(--text-secondary)' }}>{enrichmentSummary.total_enriched} checked</span>
                    )}
                    {enrichmentSummary.clean > 0 && (
                      <Badge variant="success" size="xs">{enrichmentSummary.clean} clean</Badge>
                    )}
                    {enrichmentSummary.malicious > 0 && (
                      <Badge variant="danger" size="xs">{enrichmentSummary.malicious} malicious</Badge>
                    )}
                    {enrichmentSummary.suspicious > 0 && (
                      <Badge variant="warning" size="xs">{enrichmentSummary.suspicious} suspicious</Badge>
                    )}
                    {enrichmentSummary.unknown > 0 && (
                      <Badge variant="default" size="xs">{enrichmentSummary.unknown} unknown</Badge>
                    )}
                  </div>
                </div>
              )}
            </div>
          )}

        </div>

        {/* Key Findings Section */}
        {keyFindings.length > 0 && (
          <div style={{ background: 'var(--bg-tertiary)', border: '1px solid var(--border-color)', borderRadius: '8px', padding: '0.75rem 1rem', marginBottom: '0.75rem', overflow: 'hidden' }}>
            <h4 className={styles.expandedSectionTitle} style={{ marginTop: 0 }}>KEY FINDINGS</h4>
            <ul className={styles.findingsList}>
              {keyFindings.map((finding, idx) => (
                <li key={idx} className={styles.findingItem}>{'\u2022'} {finding}</li>
              ))}
            </ul>
          </div>
        )}

        {/* Recommended Actions Section */}
        {(recommendations.length > 0 || item.investigation_id) && (
          <div style={{ background: 'var(--bg-tertiary)', border: '1px solid var(--border-color)', borderRadius: '8px', padding: '0.75rem 1rem', marginBottom: '0.75rem', overflow: 'hidden' }}>
            <h4 className={styles.expandedSectionTitle} style={{ marginTop: 0 }}>RECOMMENDED ACTIONS</h4>
            {recommendations.length > 0 && (
              <ol className={styles.recommendationsList}>
                {recommendations.map((rec, idx) => (
                  <li key={idx} className={styles.recommendationItem}>{rec}</li>
                ))}
              </ol>
            )}
            {item.investigation_id && (
              <RecommendedActions investigation={item} embedded={true} />
            )}
          </div>
        )}

        {/* Raw Event Key Fields (shown when no AI triage data) */}
        {!triageSummary && !description && (
          <div style={{ background: 'var(--bg-tertiary)', border: '1px solid var(--border-color)', borderRadius: '8px', padding: '0.75rem 1rem', marginBottom: '0.75rem', overflow: 'hidden' }}>
            {rawEvent.source_ip && (
              <div className={styles.detailRow}>
                <span className={styles.detailLabel}>Source IP:</span>
                <code className={styles.codeValue}>{rawEvent.source_ip}</code>
              </div>
            )}
            {rawEvent.dest_ip && (
              <div className={styles.detailRow}>
                <span className={styles.detailLabel}>Dest IP:</span>
                <code className={styles.codeValue}>{rawEvent.dest_ip}</code>
              </div>
            )}
            {rawEvent.user && (
              <div className={styles.detailRow}>
                <span className={styles.detailLabel}>User:</span>
                <span className={styles.detailValue}>{rawEvent.user}</span>
              </div>
            )}
          </div>
        )}

        {allIocs.length === 0 && !description && !triageSummary && (
          <p className={styles.emptyText}>No analysis data available yet. Alert is awaiting enrichment.</p>
        )}

        {/* Indicators of Compromise Section */}
        {allIocs.length > 0 && (
          <div style={{ background: 'var(--bg-tertiary)', border: '1px solid var(--border-color)', borderRadius: '8px', padding: '0.75rem 1rem', marginBottom: '0.75rem', overflow: 'hidden' }}>
            <h4 className={styles.expandedSectionTitle} style={{ marginTop: 0 }}>
              INDICATORS OF COMPROMISE
              {maliciousCount > 0 && (
                <Badge variant="danger" size="xs">{maliciousCount} malicious</Badge>
              )}
              {suspiciousCount > 0 && (
                <Badge variant="warning" size="xs">{suspiciousCount} suspicious</Badge>
              )}
            </h4>
            <GroupedIocDisplay iocs={allIocs} />
          </div>
        )}
      </>
      )}
    </div>
  );
}



export default ExpandedAlertContent;
