/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

/**
 * ExpandedInvestigationContent Component
 *
 * Expanded view for investigation items showing analysis, findings, timeline, and actions.
 * Matches the rich layout of the original InvestigationsList expanded view.
 */

import React, { useState, useEffect, useCallback } from 'react';
import { Link } from 'react-router-dom';
import GroupedIocDisplay from './GroupedIocDisplay';
import InlineOwnerSelect from './InlineOwnerSelect';
import InlineDropdown from './InlineDropdown';
import Badge from '../../ui/Badge';
import Button from '../../ui/Button';
import ChildAlertDrawer from '../components/ChildAlertDrawer';
import { getAuthHeaders, authFetch, API_BASE_URL } from '../../../utils/api';
import {
  severityToBadgeVariant,
} from '../../../styles/colors';
import styles from '../SecurityQueue.module.css';

const SEVERITY_OPTIONS = ['critical', 'high', 'medium', 'low'];
const INVESTIGATION_STATUS_OPTIONS = ['open', 'investigating', 'in_progress', 'needs_review', 'resolved', 'closed'];

/**
 * Simple JSON viewer for the raw data panel
 * Top level is always expanded, nested items collapse based on size
 */
function JsonViewer({ data, depth = 0 }) {
  // Determine default collapsed state based on depth and size
  const getDefaultCollapsed = () => {
    // Top level always expanded
    if (depth === 0) return false;
    // Nested arrays with >5 items collapse
    if (Array.isArray(data) && data.length > 5) return true;
    // Nested objects with >5 keys collapse
    if (typeof data === 'object' && data !== null && Object.keys(data).length > 5) return true;
    // Deep nesting collapses
    if (depth > 2) return true;
    return false;
  };

  const [collapsed, setCollapsed] = useState(getDefaultCollapsed);
  const [copied, setCopied] = useState(false);

  // Click to copy for primitive values
  const copyValue = (value) => {
    navigator.clipboard.writeText(String(value));
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  if (data === null) return <span style={{ color: '#f87171' }}>null</span>;
  if (data === undefined) return <span style={{ color: '#f87171' }}>undefined</span>;
  if (typeof data === 'boolean') return (
    <span
      style={{ color: '#f472b6', cursor: 'pointer', position: 'relative' }}
      onClick={() => copyValue(data)}
      title="Click to copy"
    >
      {String(data)}
      {copied && <span style={{ marginLeft: '0.5rem', color: '#22c55e', fontSize: '0.7rem' }}>Copied!</span>}
    </span>
  );
  if (typeof data === 'number') return (
    <span
      style={{ color: '#a78bfa', cursor: 'pointer', position: 'relative' }}
      onClick={() => copyValue(data)}
      title="Click to copy"
    >
      {data}
      {copied && <span style={{ marginLeft: '0.5rem', color: '#22c55e', fontSize: '0.7rem' }}>Copied!</span>}
    </span>
  );
  if (typeof data === 'string') return (
    <span
      style={{ color: '#4ade80', cursor: 'pointer', position: 'relative' }}
      onClick={() => copyValue(data)}
      title="Click to copy"
    >
      "{data}"
      {copied && <span style={{ marginLeft: '0.5rem', color: '#22c55e', fontSize: '0.7rem' }}>Copied!</span>}
    </span>
  );

  if (Array.isArray(data)) {
    if (data.length === 0) return <span>[]</span>;
    if (collapsed) {
      return (
        <span onClick={() => setCollapsed(false)} style={{ cursor: 'pointer', color: '#94a3b8' }}>
          [{data.length} items] ▸
        </span>
      );
    }
    return (
      <span>
        <span onClick={() => setCollapsed(true)} style={{ cursor: 'pointer', color: '#94a3b8' }}>▾ [</span>
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
          {'{' + keys.length + ' keys}'} ▸
        </span>
      );
    }
    return (
      <span>
        <span onClick={() => setCollapsed(true)} style={{ cursor: 'pointer', color: '#94a3b8' }}>▾ {'{'}</span>
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

// IOC type icons and colors


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
 * ExpandedInvestigationContent Component
 */
function ExpandedInvestigationContent({ item, onRefresh, onFieldUpdate, systemConfig }) {
  const [showRawDataPanel, setShowRawDataPanel] = useState(false);
  const [selectedChildAlert, setSelectedChildAlert] = useState(null);
  const [iocEnrichments, setIocEnrichments] = useState({});
  const [enrichmentLoading, setEnrichmentLoading] = useState(false);
  const [updateError, setUpdateError] = useState(null);

  // Editable field state
  const [localSeverity, setLocalSeverity] = useState(item.severity || 'medium');
  const [localStatus, setLocalStatus] = useState(item.status || 'NEW');
  const [localOwner, setLocalOwner] = useState(item.owner || '');
  const [localSensitivity, setLocalSensitivity] = useState(item.sensitivity || 'internal');
  const [copiedField, setCopiedField] = useState(null);
  const copyToClipboard = (text, field) => { navigator.clipboard.writeText(text); setCopiedField(field); setTimeout(() => setCopiedField(null), 1500); };

  const updateField = async (field, value) => {
    try {
      await authFetch(`${API_BASE_URL}/api/v1/investigations/${item.investigation_id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ [field]: value }),
      });
    } catch (e) { setUpdateError(`Failed to update ${field}`); throw e; }
  };

  const handleSeverityChange = async (newSeverity) => {
    const prev = localSeverity;
    setLocalSeverity(newSeverity);
    onFieldUpdate?.({ severity: newSeverity });
    try {
      await updateField('severity', newSeverity);
    } catch (e) { setLocalSeverity(prev); onFieldUpdate?.({ severity: prev }); }
  };

  const handleStatusChange = async (newStatus) => {
    const prev = localStatus;
    setLocalStatus(newStatus);
    onFieldUpdate?.({ status: newStatus });
    try {
      await authFetch(`${API_BASE_URL}/api/v1/investigations/${item.investigation_id}/state`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ state: newStatus }),
      });
    } catch (e) { setUpdateError('Failed to update status'); setLocalStatus(prev); onFieldUpdate?.({ status: prev }); }
  };

  const handleOwnerChange = async (newOwner) => {
    const prev = localOwner;
    setLocalOwner(newOwner);
    onFieldUpdate?.({ owner: newOwner });
    try {
      await updateField('owner', newOwner);
    } catch (e) { setLocalOwner(prev); onFieldUpdate?.({ owner: prev }); }
  };

  const SENSITIVITY_OPTIONS = ['public', 'internal', 'confidential', 'restricted'];

  const handleSensitivityChange = async (newSensitivity) => {
    const prev = localSensitivity;
    setLocalSensitivity(newSensitivity);
    onFieldUpdate?.({ sensitivity: newSensitivity });
    try {
      const res = await authFetch(`${API_BASE_URL}/api/v1/investigations/${item.investigation_id}/sensitivity`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ sensitivity: newSensitivity }),
      });
      if (!res.ok) throw new Error();
    } catch (e) { setUpdateError('Failed to update sensitivity'); setLocalSensitivity(prev); onFieldUpdate?.({ sensitivity: prev }); }
  };

  const investigation = item.investigation_context || {};
  const investigationData = investigation.investigation_data || {};
  const tier1Analysis = investigationData.tier1_analysis || investigationData.tier1_findings || {};
  const riggsAnalysis = investigationData.riggs_analysis || investigationData.tier2_analysis || {};
  const aiTriage = investigation.ai_triage || investigation.triage_result || tier1Analysis || {};

  // Get the main analysis summary text
  const analysisSummary = riggsAnalysis.summary || riggsAnalysis.analysis ||
                          tier1Analysis.summary || tier1Analysis.analysis ||
                          aiTriage.summary || aiTriage.analysis ||
                          item.executive_summary || investigation.executive_summary || '';

  // Normalize findings to strings
  const normalizeFindings = (findings) => {
    if (!findings || !Array.isArray(findings)) return [];
    return findings.map(f => {
      if (typeof f === 'string') return f;
      if (typeof f === 'object') return f.finding || f.description || f.text || f.summary || JSON.stringify(f);
      return String(f);
    }).filter(Boolean);
  };

  // Consolidated findings - deduplicated
  const allFindings = [
    ...normalizeFindings(riggsAnalysis.key_findings),
    ...normalizeFindings(tier1Analysis.key_findings),
    ...normalizeFindings(aiTriage.key_findings || investigation.key_findings)
  ].filter((v, i, a) => a.indexOf(v) === i);

  // Normalize recommendations
  const normalizeRecommendations = (recs) => {
    if (!recs || !Array.isArray(recs)) return [];
    return recs.map(r => {
      if (typeof r === 'string') return r;
      if (typeof r === 'object') return r.action || r.description || r.recommendation || r.text || JSON.stringify(r);
      return String(r);
    }).filter(Boolean);
  };

  const recommendations = normalizeRecommendations(
    riggsAnalysis.recommendations || aiTriage.recommended_actions || investigation.recommended_actions || []
  );

  // Confidence value
  const confidence = riggsAnalysis.confidence || tier1Analysis.confidence || investigation.ai_confidence;
  const confValue = confidence ? Math.round(confidence > 1 ? confidence : confidence * 100) : null;

  // Extract IOCs from multiple sources
  let iocs = riggsAnalysis.iocs || tier1Analysis.iocs || aiTriage.iocs || [];

  // Fallback to investigation_data.indicators
  if (iocs.length === 0 && investigationData.indicators && Array.isArray(investigationData.indicators)) {
    iocs = investigationData.indicators.map(ind => ({
      type: ind.type || 'unknown',
      value: ind.value,
      verdict: ind.verdict || 'unknown',
      source: ind.source || 'investigation'
    }));
  }

  // Fallback to source alert's extracted IOCs (raw_event._extracted.iocs)
  if (iocs.length === 0 && item.alert_context) {
    const alertRaw = item.alert_context.raw_event || {};
    const alertExtracted = alertRaw._extracted || {};
    const alertIocs = alertExtracted.iocs || {};
    const alertEnrichment = alertExtracted.enrichment || {};
    const enrichResults = alertEnrichment.results || {};
    const collectedIocs = [];

    // Collect raw IOCs
    (alertIocs.ips || []).forEach(v => collectedIocs.push({ type: 'ip', value: v, verdict: 'unknown' }));
    (alertIocs.domains || []).forEach(v => collectedIocs.push({ type: 'domain', value: v, verdict: 'unknown' }));
    (alertIocs.hashes || []).forEach(v => collectedIocs.push({ type: 'hash', value: v, verdict: 'unknown' }));
    (alertIocs.urls || []).forEach(v => collectedIocs.push({ type: 'url', value: v, verdict: 'unknown' }));
    (alertIocs.emails || []).forEach(v => collectedIocs.push({ type: 'email', value: v, verdict: 'unknown' }));

    // Overlay enrichment verdicts
    const enrichedList = [
      ...(enrichResults.ips || []),
      ...(enrichResults.domains || []),
      ...(enrichResults.hashes || []),
      ...(enrichResults.urls || []),
    ];
    enrichedList.forEach(ind => {
      const existing = collectedIocs.find(i => i.value === ind.value);
      if (existing) {
        existing.verdict = ind.verdict || 'unknown';
        existing.score = ind.score;
        existing.country = ind.country;
        existing.asn = ind.asn;
      } else {
        collectedIocs.push({ type: ind.type || 'unknown', value: ind.value, verdict: ind.verdict || 'unknown', score: ind.score, country: ind.country, asn: ind.asn });
      }
    });

    if (collectedIocs.length > 0) iocs = collectedIocs;
  }

  // Fetch enrichment data from threat intel API
  const fetchEnrichmentData = useCallback(async (iocsToEnrich) => {
    if (!iocsToEnrich || iocsToEnrich.length === 0) return;

    setEnrichmentLoading(true);
    const enrichments = {};

    // Limit to first 10 IOCs to avoid excessive requests
    const iocsToFetch = iocsToEnrich.slice(0, 10);

    try {
      await Promise.all(iocsToFetch.map(async (ioc) => {
        if (!ioc.value) return;

        try {
          // Determine the lookup endpoint based on IOC type
          const iocType = (ioc.type || '').toLowerCase();
          let endpoint;

          if (iocType === 'ip' || iocType === 'ipv4' || iocType === 'ipv6') {
            endpoint = `${API_BASE_URL}/api/v1/threat-intel/lookup/ip/${encodeURIComponent(ioc.value)}`;
          } else if (iocType === 'domain' || iocType === 'hostname') {
            endpoint = `${API_BASE_URL}/api/v1/threat-intel/lookup/domain/${encodeURIComponent(ioc.value)}`;
          } else if (iocType === 'hash' || iocType === 'md5' || iocType === 'sha1' || iocType === 'sha256') {
            endpoint = `${API_BASE_URL}/api/v1/threat-intel/lookup/hash/${encodeURIComponent(ioc.value)}`;
          } else {
            // Use generic lookup for other types
            endpoint = `${API_BASE_URL}/api/v1/threat-intel/ioc/lookup?value=${encodeURIComponent(ioc.value)}&with_enrichments=true`;
          }

          const response = await fetch(endpoint, {
            headers: getAuthHeaders(),
          });

          if (response.ok) {
            const data = await response.json();
            if (data) {
              const enrichmentsList = data.enrichments || [];

              // Extract provider-specific data
              const vtData = enrichmentsList.find(e => e.provider === 'virustotal');
              const abuseData = enrichmentsList.find(e => e.provider === 'abuseipdb');
              const ipApiData = enrichmentsList.find(e => e.provider === 'ipapi' || e.provider === 'ip-api');

              // Extract VirusTotal detection counts
              const vtMalicious = vtData?.raw_data?.malicious || vtData?.raw_data?.positives || 0;
              const vtSuspicious = vtData?.raw_data?.suspicious || 0;
              const vtTotal = vtData?.raw_data?.total ||
                (vtData?.raw_data?.malicious !== undefined ?
                  (vtData.raw_data.malicious + (vtData.raw_data.suspicious || 0) +
                   (vtData.raw_data.harmless || 0) + (vtData.raw_data.undetected || 0)) : 0);

              // Extract AbuseIPDB score
              const abuseScore = abuseData?.raw_data?.abuseConfidenceScore ||
                                 abuseData?.raw_data?.abuse_confidence_score ||
                                 abuseData?.threat_score || 0;

              // Calculate verdict based on enrichment data
              let calculatedVerdict = data.verdict || data.ioc?.verdict || data.consensus_verdict;

              // If no verdict from API, calculate from enrichment data
              if (!calculatedVerdict || calculatedVerdict === 'unknown') {
                const hasMaliciousFlag = enrichmentsList.some(e => e.is_malicious);
                if (vtMalicious > 3 || abuseScore > 50 || hasMaliciousFlag || (data.sources_flagged && data.sources_flagged > 1)) {
                  calculatedVerdict = 'malicious';
                } else if (vtMalicious > 0 || vtSuspicious > 0 || abuseScore > 20 || data.sources_flagged > 0) {
                  calculatedVerdict = 'suspicious';
                } else if (vtTotal > 0 && vtMalicious === 0) {
                  calculatedVerdict = 'clean';
                } else {
                  calculatedVerdict = 'unknown';
                }
              }

              enrichments[ioc.value] = {
                verdict: calculatedVerdict,
                confidence: data.ioc?.confidence || data.consensus_score || data.score,
                severity: data.ioc?.severity,
                first_seen: data.ioc?.first_seen,
                last_seen: data.ioc?.last_seen,
                country: ipApiData?.raw_data?.country || ipApiData?.raw_data?.countryCode ||
                         enrichmentsList.find(e => e.raw_data?.country)?.raw_data?.country,
                asn: ipApiData?.raw_data?.as || ipApiData?.raw_data?.asn ||
                     enrichmentsList.find(e => e.raw_data?.asn)?.raw_data?.asn,
                isp: ipApiData?.raw_data?.isp,
                abuse_score: abuseScore,
                total_reports: abuseData?.raw_data?.totalReports,
                vt_positives: vtMalicious,
                vt_suspicious: vtSuspicious,
                vt_total: vtTotal,
                categories: [...new Set(enrichmentsList.flatMap(e => e.categories || []))],
                tags: data.ioc?.tags || [...new Set(enrichmentsList.flatMap(e => e.tags || []))],
                sources: enrichmentsList.map(e => e.provider).filter(Boolean),
                sources_flagged: data.sources_flagged || 0,
                sources_checked: data.sources_checked || enrichmentsList.length,
              };
            }
          }
        } catch (err) {
        }
      }));

      setIocEnrichments(enrichments);
    } catch (err) {
    } finally {
      setEnrichmentLoading(false);
    }
  }, []);

  // Fetch enrichment when IOCs are available
  useEffect(() => {
    if (iocs.length > 0 && Object.keys(iocEnrichments).length === 0 && !enrichmentLoading) {
      fetchEnrichmentData(iocs);
    }
  }, [iocs, iocEnrichments, enrichmentLoading, fetchEnrichmentData]);

  // Threat context
  const threatType = riggsAnalysis.threat_type || aiTriage.threat_type || investigation.threat_type;
  const verdict = item.disposition || riggsAnalysis.verdict || aiTriage.verdict || investigation.ai_verdict;
  const source = item.source || investigation.source || item.alert_context?.source || item.alert_context?.alert_source || investigation.alert_source || 'Unknown';

  // IOC display settings

  // Sort IOCs by verdict: malicious first, then suspicious, then benign/clean, then unknown
  const getVerdictPriority = (ioc) => {
    const enrichment = iocEnrichments[ioc.value] || {};
    const verdict = (enrichment.verdict || ioc.verdict || '').toLowerCase();
    if (verdict === 'malicious' || ioc.malicious) return 0;
    if (verdict === 'suspicious') return 1;
    if (verdict === 'benign' || verdict === 'clean') return 2;
    return 3; // unknown or no verdict
  };

  const sortedIocs = [...iocs].sort((a, b) => getVerdictPriority(a) - getVerdictPriority(b));
  const flatIocs = sortedIocs;

  // Analysis source label
  const analysisSource = riggsAnalysis.summary ? 'RIGGS ANALYSIS' :
                         tier1Analysis.summary ? 'TIER 1 ANALYSIS' : 'AI ANALYSIS';

  return (
    <div className={styles.expandedContent}>
      {/* Action Buttons - top row */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.75rem' }}>
        {updateError && <p className={styles.errorText} style={{ margin: 0, marginRight: '0.5rem' }}>{updateError}</p>}
        <Link to={`/investigation/${item.investigation_id}`} style={{ textDecoration: 'none' }}>
          <Button variant="primary" size="sm">
            Open Full Investigation
          </Button>
        </Link>
        <Button
          variant="secondary"
          size="sm"
          onClick={() => setShowRawDataPanel(!showRawDataPanel)}
        >
          {showRawDataPanel ? 'Back to Analysis' : 'View Raw Log'}
        </Button>
      </div>

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
        {item.alert_id && (
          <div>
            <span style={labelStyle}>Alert ID</span>
            <code style={codeStyle} onClick={() => copyToClipboard(item.alert_id, 'alertId')} title="Click to copy">{item.alert_id}</code>
            {copiedField === 'alertId' && <span style={{ fontSize: '0.6rem', color: 'var(--success)', marginLeft: '0.3rem' }}>Copied!</span>}
          </div>
        )}
        <div>
          <span style={labelStyle}>Severity</span>
          <InlineDropdown
            value={localSeverity}
            options={SEVERITY_OPTIONS}
            onChange={handleSeverityChange}
            renderValue={(val) => (
              <span style={{ fontSize: '0.85rem', fontWeight: 500, color: 'var(--text-primary)' }}>
                {(val || 'medium').toUpperCase()}
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
            options={INVESTIGATION_STATUS_OPTIONS}
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
                const rawEvent = item.alert_context?.raw_event ||
                                 item.investigation_context?.raw_alert ||
                                 item.investigation_context?.raw_event ||
                                 item.alert_context ||
                                 item.investigation_context ||
                                 {};
                let toCopy = rawEvent;
                if (typeof rawEvent === 'string') {
                  try { toCopy = JSON.parse(rawEvent); } catch (e) { toCopy = rawEvent; }
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
              const rawEvent = item.alert_context?.raw_event ||
                               item.investigation_context?.raw_alert ||
                               item.investigation_context?.raw_event ||
                               item.alert_context ||
                               item.investigation_context ||
                               {};
              if (typeof rawEvent === 'string') {
                try { return JSON.parse(rawEvent); } catch (e) { return { raw: rawEvent }; }
              }
              return rawEvent;
            })()} />
          </div>
        </div>
      )}

      {!showRawDataPanel && (
      <>
        {/* AI Triage Section */}
        {(analysisSummary || confValue) && (
          <div style={{ background: 'var(--bg-tertiary)', border: '1px solid var(--border-color)', borderRadius: '8px', padding: '0.75rem 1rem', marginBottom: '0.75rem', overflow: 'hidden' }}>
            <h4 className={styles.expandedSectionTitle} style={{ marginTop: 0 }}>AI TRIAGE</h4>
            <div className={styles.analysisHeader}>
              <span className={styles.analysisSource}>{analysisSource}</span>
              {confValue && (
                <span className={styles.analysisConfidence}>{'\u2022'} {confValue}% CONFIDENCE</span>
              )}
            </div>

            {/* Analysis Summary */}
            {analysisSummary && (
              <p className={styles.analysisSummary} style={{ marginBottom: 0 }}>{analysisSummary}</p>
            )}
          </div>
        )}

        {/* Key Findings Section */}
        {allFindings.length > 0 && (
          <div style={{ background: 'var(--bg-tertiary)', border: '1px solid var(--border-color)', borderRadius: '8px', padding: '0.75rem 1rem', marginBottom: '0.75rem', overflow: 'hidden' }}>
            <h4 className={styles.expandedSectionTitle} style={{ marginTop: 0 }}>KEY FINDINGS</h4>
            <ul className={styles.findingsList}>
              {allFindings.map((finding, idx) => (
                <li key={idx} className={styles.findingItem}>{'\u2022'} {finding}</li>
              ))}
            </ul>
          </div>
        )}

        {/* Recommended Actions Section */}
        {recommendations.length > 0 && (
          <div style={{ background: 'var(--bg-tertiary)', border: '1px solid var(--border-color)', borderRadius: '8px', padding: '0.75rem 1rem', marginBottom: '0.75rem', overflow: 'hidden' }}>
            <h4 className={styles.expandedSectionTitle} style={{ marginTop: 0 }}>RECOMMENDED ACTIONS</h4>
            <ol className={styles.recommendationsList}>
              {recommendations.map((rec, idx) => (
                <li key={idx} className={styles.recommendationItem}>{rec}</li>
              ))}
            </ol>
          </div>
        )}

        {/* Correlated Alerts Section - shows all child alerts attached to this
            investigation. Replaces the queue clutter of N peer rows with a
            single drillable list. Outlier (non-benign) rows are highlighted. */}
        {Array.isArray(item.correlated_alerts) && item.correlated_alerts.length > 1 && (() => {
          const children = item.correlated_alerts;
          const sorted = children.slice().sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
          const benignSet = new Set(['BENIGN', 'FALSE_POSITIVE', 'BENIGN_POSITIVE']);
          const terminalStatuses = new Set(['closed', 'resolved', 'false_positive', 'confirmed']);
          // An alert is a flagged outlier only if it's BOTH non-benign by
          // verdict AND not already in a terminal status. Otherwise the
          // analyst already handled it — don't keep pinging it red.
          const isNonBenign = (a) => {
            const status = (a.status || '').toLowerCase();
            if (terminalStatuses.has(status)) return false;
            const v = (a.ai_verdict || a.disposition || '').toUpperCase();
            return v && !benignSet.has(v) && ['MALICIOUS', 'SUSPICIOUS', 'TRUE_POSITIVE', 'NEEDS_INVESTIGATION', 'NEEDS_REVIEW'].includes(v);
          };
          const outliers = sorted.filter(isNonBenign).length;
          return (
            <div style={{ background: 'var(--bg-tertiary)', border: '1px solid var(--border-color)', borderRadius: '8px', padding: '0.75rem 1rem', marginBottom: '0.75rem', overflow: 'hidden' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', marginBottom: '0.5rem' }}>
                <h4 className={styles.expandedSectionTitle} style={{ marginTop: 0, marginBottom: 0 }}>
                  CORRELATED ALERTS ({children.length})
                </h4>
                <span style={{ fontSize: '0.7rem', color: outliers > 0 ? 'var(--danger, #ef4444)' : 'var(--text-muted)' }}>
                  {outliers > 0
                    ? `${outliers} non-benign — review`
                    : 'All benign'}
                </span>
              </div>
              <div style={{ maxHeight: '260px', overflowY: 'auto', borderRadius: '4px' }}>
                <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.78rem' }}>
                  <thead>
                    <tr style={{ textAlign: 'left', color: 'var(--text-muted)', borderBottom: '1px solid var(--border-color)' }}>
                      <th style={{ padding: '0.35rem 0.5rem', fontWeight: 600 }}>Alert ID</th>
                      <th style={{ padding: '0.35rem 0.5rem', fontWeight: 600 }}>Received</th>
                      <th style={{ padding: '0.35rem 0.5rem', fontWeight: 600 }}>Verdict</th>
                      <th style={{ padding: '0.35rem 0.5rem', fontWeight: 600 }}>Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {sorted.slice(0, 50).map((child) => {
                      const verdict = (child.ai_verdict || child.disposition || '').toUpperCase();
                      const outlier = isNonBenign(child);
                      return (
                        <tr
                          key={child.alert_id || child.id}
                          onClick={() => setSelectedChildAlert(child)}
                          style={{
                            borderBottom: '1px solid var(--border-color)',
                            background: outlier ? 'rgba(239, 68, 68, 0.06)' : 'transparent',
                            cursor: 'pointer',
                          }}
                          onMouseEnter={(e) => { e.currentTarget.style.background = outlier ? 'rgba(239, 68, 68, 0.12)' : 'rgba(255, 255, 255, 0.04)'; }}
                          onMouseLeave={(e) => { e.currentTarget.style.background = outlier ? 'rgba(239, 68, 68, 0.06)' : 'transparent'; }}
                          title="Click to open alert detail"
                        >
                          <td style={{ padding: '0.35rem 0.5rem', fontFamily: "'SF Mono', Monaco, Consolas, monospace", color: 'var(--info)' }}>
                            {child.alert_id || child.id}
                          </td>
                          <td style={{ padding: '0.35rem 0.5rem', color: 'var(--text-secondary)' }}>
                            {child.created_at ? new Date(child.created_at).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }) : '—'}
                          </td>
                          <td style={{ padding: '0.35rem 0.5rem', color: outlier ? 'var(--danger, #ef4444)' : 'var(--text-secondary)', fontWeight: outlier ? 600 : 400 }}>
                            {verdict || '—'}
                          </td>
                          <td style={{ padding: '0.35rem 0.5rem', color: 'var(--text-secondary)', textTransform: 'uppercase', fontSize: '0.7rem' }}>
                            {child.status || '—'}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
                {sorted.length > 50 && (
                  <div style={{ padding: '0.4rem 0.5rem', fontSize: '0.7rem', color: 'var(--text-muted)', textAlign: 'center' }}>
                    Showing 50 of {sorted.length}. Open the full investigation to see all.
                  </div>
                )}
              </div>
            </div>
          );
        })()}

        {/* Indicators of Compromise Section */}
        {iocs.length > 0 && (
          <div style={{ background: 'var(--bg-tertiary)', border: '1px solid var(--border-color)', borderRadius: '8px', padding: '0.75rem 1rem', marginBottom: '0.75rem', overflow: 'hidden' }}>
            <h4 className={styles.expandedSectionTitle} style={{ marginTop: 0 }}>
              INDICATORS OF COMPROMISE
              {enrichmentLoading && (
                <span style={{ marginLeft: '0.5rem', fontSize: '0.6rem', color: 'var(--text-muted)' }}>
                  (fetching enrichment...)
                </span>
              )}
            </h4>
            <GroupedIocDisplay
              iocs={flatIocs}
              iocEnrichments={iocEnrichments}
              enrichmentLoading={enrichmentLoading}
              buildEnrichmentDetails={(ioc, enrichment) => {
                const details = [];
                const effectiveVerdict = enrichment.verdict || ioc.verdict || '';
                if (effectiveVerdict && effectiveVerdict !== 'unknown') {
                  details.push({ label: 'Verdict', value: effectiveVerdict.toUpperCase() });
                }
                if (enrichment.sources?.length > 0) {
                  details.push({ label: 'Sources', value: enrichment.sources.join(', ') });
                } else if (ioc.source) {
                  details.push({ label: 'Source', value: ioc.source });
                }
                if (enrichment.sources_flagged != null && enrichment.sources_checked != null) {
                  details.push({ label: 'Flagged', value: `${enrichment.sources_flagged}/${enrichment.sources_checked} sources` });
                }
                if (enrichment.confidence != null) {
                  details.push({ label: 'Confidence', value: `${Math.round(enrichment.confidence)}%` });
                } else if (ioc.score != null) {
                  details.push({ label: 'Score', value: `${ioc.score}/100` });
                }
                if (enrichment.abuse_score != null && enrichment.abuse_score > 0) {
                  details.push({ label: 'Abuse Score', value: `${enrichment.abuse_score}%` });
                }
                if (enrichment.vt_total > 0) {
                  const vtLabel = enrichment.vt_positives > 0 ? 'VT Detections' : 'VirusTotal';
                  let vtValue = `${enrichment.vt_positives}/${enrichment.vt_total}`;
                  if (enrichment.vt_suspicious > 0) vtValue += ` (${enrichment.vt_suspicious} suspicious)`;
                  details.push({ label: vtLabel, value: vtValue });
                }
                if (enrichment.country || ioc.country) details.push({ label: 'Country', value: enrichment.country || ioc.country });
                if (enrichment.asn || ioc.asn) details.push({ label: 'ASN', value: enrichment.asn || ioc.asn });
                if (enrichment.first_seen || ioc.first_seen) details.push({ label: 'First Seen', value: new Date(enrichment.first_seen || ioc.first_seen).toLocaleDateString() });
                if (enrichment.last_seen || ioc.last_seen) details.push({ label: 'Last Seen', value: new Date(enrichment.last_seen || ioc.last_seen).toLocaleDateString() });
                if (enrichment.categories?.length > 0) {
                  details.push({ label: 'Tags', value: enrichment.categories.slice(0, 3).join(', ') });
                } else if (ioc.category) {
                  details.push({ label: 'Category', value: ioc.category });
                }
                return details;
              }}
            />
          </div>
        )}
      </>
      )}

      <ChildAlertDrawer
        alert={selectedChildAlert}
        onClose={() => setSelectedChildAlert(null)}
        onFieldUpdate={() => onRefresh?.()}
      />
    </div>
  );
}

export default ExpandedInvestigationContent;
