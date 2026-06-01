/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

import React, { useState, useEffect, useCallback } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import ColumnCustomizer from './ColumnCustomizer';
import BulkUpdateModal from './BulkUpdateModal';
import Badge from './ui/Badge';
import Button from './ui/Button';
import { usePreferences, formatDateTime, getTimezoneAbbr, formatInTimezone } from '../hooks/usePreferences';
import { getAuthHeaders, API_BASE_URL } from '../utils/api';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import {
  severityToBadgeVariant,
  statusToBadgeVariant,
  verdictToBadgeVariant
} from '../styles/colors';
import styles from './AlertViewer.module.css';

// Expanded Alert Content Component - Decision-focused layout
// Shows what analysts need to make a quick triage decision
function ExpandedAlertContent({ alert, investigation, onCreateInvestigation, onRefresh, preferences }) {
  const [showRawEvent, setShowRawEvent] = useState(false);
  const [showBody, setShowBody] = useState(false);
  const [showCleanIOCs, setShowCleanIOCs] = useState(true);
  const [showAllFields, setShowAllFields] = useState(true);
  const [showEmailHeaders, setShowEmailHeaders] = useState(false);
  const [copiedValue, setCopiedValue] = useState(null);
  const [attachments, setAttachments] = useState([]);
  const [loadingAttachments, setLoadingAttachments] = useState(false);
  const [downloadingId, setDownloadingId] = useState(null);

  // Fetch attachments for this alert
  useEffect(() => {
    const fetchAttachments = async () => {
      if (!alert?.alert_id) return;
      setLoadingAttachments(true);
      try {
        const response = await fetch(`${API_BASE_URL}/api/v1/attachments/alert/${alert.alert_id}`, {
          headers: getAuthHeaders()
        });
        if (response.ok) {
          const data = await response.json();
          setAttachments(data.attachments || []);
        }
      } catch (error) {
      } finally {
        setLoadingAttachments(false);
      }
    };
    fetchAttachments();
  }, [alert?.alert_id]);

  // Download attachment
  const downloadAttachment = async (attachment) => {
    setDownloadingId(attachment.attachment_id);
    try {
      const response = await fetch(`${API_BASE_URL}/api/v1/attachments/${attachment.attachment_id}/download`, {
        headers: getAuthHeaders()
      });
      if (response.ok) {
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = attachment.original_filename;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
      }
    } catch (error) {
    } finally {
      setDownloadingId(null);
    }
  };

  // Format file size
  const formatFileSize = (bytes) => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  };

  // Copy to clipboard helper
  const copyToClipboard = async (value) => {
    try {
      await navigator.clipboard.writeText(value);
      setCopiedValue(value);
      setTimeout(() => setCopiedValue(null), 1500);
    } catch (err) {
    }
  };

  // Extract enrichment data
  const enrichment = alert.raw_event?._extracted?.enrichment;
  const enrichmentResults = enrichment?.results || {};
  const enrichmentSummary = enrichment?.summary || {};

  // Extract AI analysis
  const aiTriage = alert.raw_event?._extracted?.ai_triage;

  // Extract ALL event fields for display
  const rawEvent = alert.raw_event || {};

  // Extract email headers for phishing alerts
  const emailHeaders = rawEvent.email_headers || {};
  const receivedChain = rawEvent.received_chain || [];
  const allHeaders = rawEvent.all_headers || {};
  const hasEmailHeaders = Object.keys(emailHeaders).length > 0 || receivedChain.length > 0;

  // Helper to flatten nested objects into key-value pairs
  const flattenObject = (obj, prefix = '', result = []) => {
    if (!obj || typeof obj !== 'object') return result;

    Object.entries(obj).forEach(([key, value]) => {
      // Skip internal/extracted fields and very large arrays
      if (key.startsWith('_') || key === 'raw_event') return;

      const fullKey = prefix ? `${prefix}.${key}` : key;

      if (value === null || value === undefined) return;

      if (Array.isArray(value)) {
        if (value.length === 0) return;
        // For arrays, show count and first few items
        if (value.length <= 3 && value.every(v => typeof v === 'string' || typeof v === 'number')) {
          result.push({ key: fullKey, value: value.join(', '), type: 'array' });
        } else {
          result.push({ key: fullKey, value: `[${value.length} items]`, type: 'array' });
        }
      } else if (typeof value === 'object') {
        // Recurse into nested objects (but limit depth)
        if (prefix.split('.').length < 2) {
          flattenObject(value, fullKey, result);
        } else {
          result.push({ key: fullKey, value: '{...}', type: 'object' });
        }
      } else if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
        result.push({ key: fullKey, value: String(value), type: typeof value });
      }
    });

    return result;
  };

  // Get all flattened fields from raw event
  const allEventFields = flattenObject(rawEvent);


  // Helper to get risk color
  const getRiskInfo = () => {
    const hasMalicious = enrichmentSummary.malicious > 0;
    const hasSuspicious = enrichmentSummary.suspicious > 0;
    const isClean = enrichment?.status === 'enriched' && enrichmentSummary.total_enriched > 0 &&
                    enrichmentSummary.malicious === 0 && enrichmentSummary.suspicious === 0;

    if (hasMalicious) return { level: 'High Risk', color: '#dc2626', bg: 'rgba(220, 38, 38, 0.12)', icon: '!' };
    if (hasSuspicious) return { level: 'Medium Risk', color: '#ea580c', bg: 'rgba(234, 88, 12, 0.12)', icon: '?' };
    if (isClean) return { level: 'Low Risk', color: '#22c55e', bg: 'rgba(34, 197, 94, 0.12)', icon: '✓' };
    if (alert.ai_verdict === 'malicious') return { level: 'High Risk', color: '#dc2626', bg: 'rgba(220, 38, 38, 0.12)', icon: '!' };
    if (alert.ai_verdict === 'suspicious') return { level: 'Medium Risk', color: '#ea580c', bg: 'rgba(234, 88, 12, 0.12)', icon: '?' };
    if (alert.ai_verdict === 'benign') return { level: 'Low Risk', color: '#22c55e', bg: 'rgba(34, 197, 94, 0.12)', icon: '✓' };
    return { level: 'Unknown', color: '#64748b', bg: 'rgba(100, 116, 139, 0.12)', icon: '-' };
  };

  const risk = getRiskInfo();

  // Collect all IOCs with their verdicts
  // Check multiple possible field names for verdict (verdict, status, result, classification)
  const allIOCs = [];
  ['ips', 'domains', 'hashes', 'urls', 'emails'].forEach(type => {
    const items = enrichmentResults[type] || [];
    items.forEach(item => {
      // Normalize verdict field - check multiple possible field names
      const verdict = item.verdict || item.status || item.result || item.classification || 'unknown';
      allIOCs.push({
        ...item,
        verdict: verdict,  // Ensure verdict is always set
        iocType: type === 'ips' ? 'IP' : type === 'domains' ? 'Domain' : type === 'hashes' ? 'Hash' : type === 'urls' ? 'URL' : 'Email'
      });
    });
  });

  const styles = {
    section: {
      background: 'var(--bg-tertiary)',
      borderRadius: '6px',
      marginBottom: '0.5rem',
      overflow: 'hidden'
    },
    sectionHeader: {
      display: 'flex',
      alignItems: 'center',
      gap: '0.5rem',
      padding: '0.5rem 0.75rem',
      background: 'rgba(255,255,255,0.03)',
      borderBottom: '1px solid rgba(255,255,255,0.06)'
    },
    sectionIcon: {
      width: '18px',
      height: '18px',
      borderRadius: '4px',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      fontSize: '0.65rem',
      fontWeight: '700'
    },
    sectionTitle: {
      fontSize: '0.7rem',
      fontWeight: '600',
      color: 'var(--text-primary)',
      textTransform: 'uppercase',
      letterSpacing: '0.5px'
    },
    sectionContent: {
      padding: '0.5rem 0.75rem'
    },
    badge: (color) => ({
      display: 'inline-flex',
      alignItems: 'center',
      gap: '0.2rem',
      padding: '0.15rem 0.4rem',
      borderRadius: '4px',
      fontSize: '0.6rem',
      fontWeight: '600',
      textTransform: 'uppercase',
      background: `${color}20`,
      color: color,
      border: `1px solid ${color}40`
    }),
    fieldGrid: {
      display: 'grid',
      gridTemplateColumns: 'repeat(auto-fill, minmax(220px, 1fr))',
      gap: '0.25rem 1rem'
    },
    fieldRow: {
      display: 'flex',
      gap: '0.5rem',
      fontSize: '0.7rem',
      padding: '0.15rem 0',
      borderBottom: '1px solid rgba(255,255,255,0.03)'
    },
    fieldLabel: {
      color: 'var(--text-muted)',
      minWidth: '90px',
      maxWidth: '120px',
      flexShrink: 0,
      fontSize: '0.65rem',
      overflow: 'hidden',
      textOverflow: 'ellipsis',
      whiteSpace: 'nowrap'
    },
    fieldValue: {
      color: 'var(--text-secondary)',
      wordBreak: 'break-word',
      fontFamily: 'monospace',
      fontSize: '0.65rem',
      flex: 1
    },
    categoryLabel: {
      fontSize: '0.6rem',
      fontWeight: '600',
      color: 'var(--text-muted)',
      textTransform: 'uppercase',
      marginBottom: '0.25rem',
      marginTop: '0.5rem',
      display: 'flex',
      alignItems: 'center',
      gap: '0.35rem'
    },
    iocRow: {
      display: 'flex',
      alignItems: 'center',
      gap: '0.5rem',
      padding: '0.3rem 0.5rem',
      background: 'rgba(255,255,255,0.02)',
      borderRadius: '4px',
      marginBottom: '0.25rem'
    },
    markdown: {
      fontSize: '0.75rem',
      lineHeight: 1.5,
      color: 'var(--text-secondary)'
    }
  };

  // Extract key fields for display
  const subjectField = allEventFields.find(f => f.key.toLowerCase().includes('subject'));
  const bodyField = allEventFields.find(f => f.key.toLowerCase() === 'body' || f.key.toLowerCase().includes('message'));
  const senderField = allEventFields.find(f => f.key.toLowerCase().includes('sender') || f.key.toLowerCase() === 'from');
  const reporterField = allEventFields.find(f => f.key.toLowerCase().includes('reporter'));
  const tagsField = allEventFields.find(f => f.key.toLowerCase() === 'tags');
  const otherFields = allEventFields.filter(f =>
    f !== subjectField && f !== bodyField && f !== senderField && f !== reporterField && f !== tagsField
  );

  // Parse tags (could be array or comma-separated string)
  let tags = [];
  if (tagsField?.value) {
    if (Array.isArray(tagsField.value)) {
      tags = tagsField.value;
    } else if (typeof tagsField.value === 'string') {
      tags = tagsField.value.split(',').map(t => t.trim()).filter(Boolean);
    }
  }

  // Split IOCs into threats and clean
  const normalizeVerdict = (v) => (v || '').toLowerCase().trim();
  const threatIOCs = allIOCs.filter(ioc => ['malicious', 'suspicious'].includes(normalizeVerdict(ioc.verdict)));
  const cleanIOCs = allIOCs.filter(ioc => !['malicious', 'suspicious'].includes(normalizeVerdict(ioc.verdict)));

  // Toggle button style
  const toggleBtnStyle = (isActive) => ({
    padding: '0.2rem 0.5rem',
    background: isActive ? 'rgba(100, 116, 139, 0.3)' : 'transparent',
    color: isActive ? 'var(--text-primary)' : 'var(--text-muted)',
    border: '1px solid rgba(100, 116, 139, 0.3)',
    borderRadius: '3px',
    fontSize: '0.6rem',
    cursor: 'pointer',
    fontWeight: '500'
  });

  return (
    <div style={{ padding: '0.5rem' }}>
      {/* ══════════ ROW 1: Subject Line ══════════ */}
      {subjectField && (
        <div style={{ marginBottom: '0.5rem' }}>
          <span style={{ fontSize: '0.55rem', color: 'var(--text-muted)', marginRight: '0.4rem' }}>SUBJECT:</span>
          <span style={{ fontSize: '0.85rem', color: 'var(--text-primary)', fontWeight: '600' }}>
            {subjectField.value}
          </span>
        </div>
      )}

      {/* ══════════ ROW 2: Key Metadata + Tags (inline) ══════════ */}
      <div style={{
        display: 'flex',
        flexWrap: 'wrap',
        gap: '0.4rem 1.5rem',
        marginBottom: '0.5rem',
        fontSize: '0.68rem',
        color: 'var(--text-secondary)',
        alignItems: 'center'
      }}>
        {senderField && (
          <span><span style={{ color: 'var(--text-muted)' }}>sender:</span> <span style={{ fontFamily: 'monospace', color: '#a0e9ff' }}>{senderField.value}</span></span>
        )}
        {reporterField && (
          <span><span style={{ color: 'var(--text-muted)' }}>reporter:</span> <span style={{ fontFamily: 'monospace', color: '#a0e9ff' }}>{reporterField.value}</span></span>
        )}
        <span><span style={{ color: 'var(--text-muted)' }}>source:</span> <span style={{ color: 'var(--text-secondary)' }}>{alert.source || 'Unknown'}</span></span>
        <span><span style={{ color: 'var(--text-muted)' }}>time:</span> {formatInTimezone(alert.created_at, preferences?.timezone || 'local', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })}</span>
        {tags.length > 0 && tags.map((tag, idx) => (
          <span key={idx} style={{
            padding: '0.1rem 0.4rem',
            background: tag.toLowerCase() === 'malicious' ? 'rgba(220, 38, 38, 0.2)' :
                       tag.toLowerCase() === 'suspicious' ? 'rgba(234, 88, 12, 0.2)' :
                       'rgba(96, 165, 250, 0.15)',
            color: tag.toLowerCase() === 'malicious' ? '#f87171' :
                   tag.toLowerCase() === 'suspicious' ? '#fb923c' :
                   '#a0e9ff',
            border: `1px solid ${
              tag.toLowerCase() === 'malicious' ? 'rgba(220, 38, 38, 0.4)' :
              tag.toLowerCase() === 'suspicious' ? 'rgba(234, 88, 12, 0.4)' :
              'rgba(96, 165, 250, 0.3)'
            }`,
            borderRadius: '10px',
            fontSize: '0.58rem',
            fontWeight: '500'
          }}>
            {tag}
          </span>
        ))}
      </div>

      {/* ══════════ ROW 3: AI Analysis (compact) ══════════ */}
      <div style={{
        marginBottom: '0.5rem',
        padding: '0.4rem 0.6rem',
        background: 'var(--bg-tertiary)',
        borderRadius: '4px',
        borderLeft: `3px solid ${
          aiTriage?.verdict === 'malicious' ? '#dc2626' :
          aiTriage?.verdict === 'suspicious' ? '#ea580c' :
          aiTriage?.verdict === 'benign' ? '#22c55e' : '#60a5fa'
        }`
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.3rem' }}>
          <span style={{ fontSize: '0.55rem', color: 'var(--text-muted)', fontWeight: '700', textTransform: 'uppercase' }}>AI Analysis</span>
          {aiTriage?.verdict && (
            <span style={{
              ...styles.badge(
                aiTriage.verdict === 'malicious' ? '#dc2626' :
                aiTriage.verdict === 'suspicious' ? '#ea580c' :
                aiTriage.verdict === 'benign' ? '#22c55e' : '#60a5fa'
              )
            }}>
              {aiTriage.verdict}
            </span>
          )}
          {alert.ai_confidence && (
            <span style={{ fontSize: '0.6rem', color: 'var(--text-muted)' }}>
              {Math.round(alert.ai_confidence > 1 ? alert.ai_confidence : alert.ai_confidence * 100)}% confidence
            </span>
          )}
        </div>
        <div style={{ fontSize: '0.7rem', color: 'var(--text-secondary)', lineHeight: 1.4 }}>
          {aiTriage?.summary || alert.ai_summary || alert.executive_summary ||
           (alert.ai_confidence || aiTriage?.verdict ? 'Analysis complete - see details below' : 'AI analysis pending...')}
        </div>
      </div>

      {/* ══════════ ROW 4: Threats (if any) ══════════ */}
      {threatIOCs.length > 0 && (
        <div style={{
          marginBottom: '0.5rem',
          padding: '0.3rem 0.5rem',
          background: 'rgba(220, 38, 38, 0.1)',
          border: '1px solid rgba(220, 38, 38, 0.25)',
          borderRadius: '4px',
          display: 'flex',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: '0.3rem'
        }}>
          <span style={{ fontSize: '0.6rem', fontWeight: '700', color: '#f87171', marginRight: '0.3rem' }}>
            ⚠ {threatIOCs.length} THREAT{threatIOCs.length > 1 ? 'S' : ''}:
          </span>
          {threatIOCs.map((ioc, idx) => {
            const verdict = normalizeVerdict(ioc.verdict);
            return (
              <span key={idx} style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '0.25rem',
                padding: '0.15rem 0.4rem',
                background: verdict === 'malicious' ? 'rgba(220, 38, 38, 0.25)' : 'rgba(234, 88, 12, 0.25)',
                border: `1px solid ${verdict === 'malicious' ? 'rgba(220, 38, 38, 0.4)' : 'rgba(234, 88, 12, 0.4)'}`,
                borderRadius: '3px',
                fontSize: '0.62rem',
                fontFamily: 'monospace'
              }}>
                <span style={{ fontWeight: '700', color: 'var(--text-muted)', fontSize: '0.5rem' }}>{ioc.iocType}</span>
                <span
                  onClick={() => copyToClipboard(ioc.value)}
                  style={{
                    color: copiedValue === ioc.value ? '#22c55e' : (verdict === 'malicious' ? '#fca5a5' : '#fdba74'),
                    maxWidth: '200px',
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                    whiteSpace: 'nowrap',
                    cursor: 'pointer'
                  }}
                  title={`Click to copy: ${ioc.value}`}
                >{copiedValue === ioc.value ? '✓ Copied' : ioc.value}</span>
                <span style={{ fontSize: '0.5rem', fontWeight: '700', color: verdict === 'malicious' ? '#ef4444' : '#f97316', textTransform: 'uppercase' }}>{verdict}</span>
              </span>
            );
          })}
        </div>
      )}

      {/* ══════════ ROW 5: Expandable Sections ══════════ */}
      <div style={{ display: 'flex', gap: '0.4rem', flexWrap: 'wrap', marginBottom: '0.5rem' }}>
        {bodyField && (
          <button onClick={() => setShowBody(!showBody)} style={toggleBtnStyle(showBody)}>
            {showBody ? '− Hide' : '+'} Email Body
          </button>
        )}
        {cleanIOCs.length > 0 && (
          <button onClick={() => setShowCleanIOCs(!showCleanIOCs)} style={toggleBtnStyle(showCleanIOCs)}>
            {showCleanIOCs ? '− Hide' : '+'} {cleanIOCs.length} Clean IOCs
          </button>
        )}
        {otherFields.length > 0 && (
          <button onClick={() => setShowAllFields(!showAllFields)} style={toggleBtnStyle(showAllFields)}>
            {showAllFields ? '− Hide' : '+'} {otherFields.length} Fields
          </button>
        )}
        <button onClick={() => setShowRawEvent(!showRawEvent)} style={toggleBtnStyle(showRawEvent)}>
          {showRawEvent ? '− Hide' : '+'} JSON
        </button>
        {hasEmailHeaders && (
          <button onClick={() => setShowEmailHeaders(!showEmailHeaders)} style={toggleBtnStyle(showEmailHeaders)}>
            {showEmailHeaders ? '− Hide' : '+'} Email Headers
          </button>
        )}

        {/* Actions on right */}
        <div style={{ marginLeft: 'auto', display: 'flex', gap: '0.3rem' }}>
          {!investigation && (
            <button onClick={onCreateInvestigation} style={{
              padding: '0.2rem 0.5rem',
              background: 'rgba(60, 179, 113, 0.2)',
              color: '#5eead4',
              border: '1px solid rgba(60, 179, 113, 0.4)',
              borderRadius: '3px',
              fontSize: '0.6rem',
              fontWeight: '600',
              cursor: 'pointer'
            }}>
              + Create Investigation
            </button>
          )}
          {investigation && (
            <Link to={`/investigation/${investigation.investigation_id}`} style={{
              padding: '0.2rem 0.5rem',
              background: 'rgba(59, 130, 246, 0.2)',
              color: '#60a5fa',
              border: '1px solid rgba(59, 130, 246, 0.4)',
              borderRadius: '3px',
              fontSize: '0.6rem',
              fontWeight: '600',
              textDecoration: 'none'
            }}>
              View Investigation →
            </Link>
          )}
        </div>
      </div>

      {/* ══════════ EXPANDABLE: Email Body ══════════ */}
      {showBody && bodyField && (
        <div style={{
          marginBottom: '0.5rem',
          padding: '0.5rem',
          background: 'var(--bg-tertiary)',
          borderRadius: '4px',
          maxHeight: '150px',
          overflow: 'auto'
        }}>
          <div style={{ fontSize: '0.5rem', color: 'var(--text-muted)', marginBottom: '0.3rem', textTransform: 'uppercase' }}>
            {bodyField.key}
          </div>
          <div style={{ fontSize: '0.7rem', color: 'var(--text-secondary)', lineHeight: 1.5, whiteSpace: 'pre-wrap' }}>
            {bodyField.value}
          </div>
        </div>
      )}

      {/* ══════════ EXPANDABLE: Other Fields ══════════ */}
      {showAllFields && otherFields.length > 0 && (
        <div style={{
          marginBottom: '0.5rem',
          padding: '0.5rem',
          background: 'var(--bg-tertiary)',
          borderRadius: '4px',
          maxHeight: '160px',
          overflow: 'auto'
        }}>
          <div style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))',
            gap: '0.35rem 1.5rem'
          }}>
            {otherFields.map((field, idx) => (
              <div key={idx} style={{
                display: 'flex',
                alignItems: 'baseline',
                gap: '0.5rem',
                fontSize: '0.7rem',
                padding: '0.2rem 0.4rem',
                background: 'rgba(255,255,255,0.02)',
                borderRadius: '3px',
                borderLeft: '2px solid rgba(100, 116, 139, 0.2)'
              }}>
                <span style={{
                  color: 'var(--text-muted)',
                  minWidth: '110px',
                  flexShrink: 0,
                  fontSize: '0.65rem',
                  fontWeight: '500'
                }}>{field.key}</span>
                <span style={{
                  color: '#a0e9ff',
                  fontFamily: 'monospace',
                  fontSize: '0.68rem',
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                  whiteSpace: 'nowrap',
                  flex: 1
                }} title={field.value}>{field.value}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ══════════ EXPANDABLE: Clean IOCs ══════════ */}
      {showCleanIOCs && cleanIOCs.length > 0 && (
        <div style={{
          marginBottom: '0.5rem',
          padding: '0.4rem',
          background: 'var(--bg-tertiary)',
          borderRadius: '4px',
          maxHeight: '120px',
          overflow: 'auto'
        }}>
          <div style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))',
            gap: '0.2rem'
          }}>
            {cleanIOCs.map((ioc, idx) => (
              <div key={idx} style={{
                display: 'flex',
                alignItems: 'center',
                gap: '0.3rem',
                fontSize: '0.58rem',
                padding: '0.1rem 0.3rem',
                background: 'rgba(255,255,255,0.02)',
                borderRadius: '2px'
              }}>
                <span style={{ fontWeight: '700', color: 'var(--text-muted)', fontSize: '0.5rem', minWidth: '40px' }}>{ioc.iocType}</span>
                <span
                  onClick={() => copyToClipboard(ioc.value)}
                  style={{
                    fontFamily: 'monospace',
                    color: copiedValue === ioc.value ? '#22c55e' : '#a0e9ff',
                    flex: 1,
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                    whiteSpace: 'nowrap',
                    cursor: 'pointer'
                  }}
                  title={`Click to copy: ${ioc.value}`}
                >{copiedValue === ioc.value ? '✓ Copied' : ioc.value}</span>
                <span style={{ fontSize: '0.5rem', color: '#22c55e', fontWeight: '600' }}>CLEAN</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ══════════ EXPANDABLE: Email Headers ══════════ */}
      {showEmailHeaders && hasEmailHeaders && (
        <div style={{
          marginBottom: '0.5rem',
          padding: '0.5rem',
          background: 'var(--bg-tertiary)',
          borderRadius: '4px',
          maxHeight: '300px',
          overflow: 'auto'
        }}>
          {/* Security Headers */}
          {Object.keys(emailHeaders).length > 0 && (
            <div style={{ marginBottom: '0.5rem' }}>
              <div style={{
                fontSize: '0.6rem',
                fontWeight: '600',
                color: '#f97316',
                marginBottom: '0.3rem',
                textTransform: 'uppercase',
                borderBottom: '1px solid rgba(249, 115, 22, 0.2)',
                paddingBottom: '0.2rem'
              }}>
                Security Headers
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.2rem' }}>
                {Object.entries(emailHeaders).map(([key, value]) => {
                  // Determine if this header indicates a pass/fail status
                  const valueStr = String(value);
                  const isPassing = valueStr.toLowerCase().includes('pass') || valueStr.toLowerCase().includes('spf=pass') || valueStr.toLowerCase().includes('dkim=pass');
                  const isFailing = valueStr.toLowerCase().includes('fail') || valueStr.toLowerCase().includes('none') || valueStr.toLowerCase().includes('softfail');

                  return (
                    <div key={key} style={{
                      display: 'flex',
                      alignItems: 'flex-start',
                      gap: '0.5rem',
                      fontSize: '0.62rem',
                      padding: '0.2rem 0.4rem',
                      background: isFailing ? 'rgba(220, 38, 38, 0.08)' : isPassing ? 'rgba(34, 197, 94, 0.08)' : 'rgba(255,255,255,0.02)',
                      borderRadius: '3px',
                      borderLeft: `2px solid ${isFailing ? '#dc2626' : isPassing ? '#22c55e' : 'rgba(100, 116, 139, 0.3)'}`
                    }}>
                      <span style={{
                        color: 'var(--text-muted)',
                        minWidth: '160px',
                        flexShrink: 0,
                        fontWeight: '500',
                        fontSize: '0.58rem'
                      }}>{key}</span>
                      <span
                        onClick={() => copyToClipboard(valueStr)}
                        style={{
                          color: copiedValue === valueStr ? '#22c55e' : (isFailing ? '#f87171' : isPassing ? '#4ade80' : '#a0e9ff'),
                          fontFamily: 'monospace',
                          fontSize: '0.58rem',
                          wordBreak: 'break-all',
                          cursor: 'pointer'
                        }}
                        title="Click to copy"
                      >{copiedValue === valueStr ? '✓ Copied' : valueStr}</span>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* Received Chain - Email Path */}
          {receivedChain.length > 0 && (
            <div style={{ marginBottom: '0.5rem' }}>
              <div style={{
                fontSize: '0.6rem',
                fontWeight: '600',
                color: '#60a5fa',
                marginBottom: '0.3rem',
                textTransform: 'uppercase',
                borderBottom: '1px solid rgba(96, 165, 250, 0.2)',
                paddingBottom: '0.2rem'
              }}>
                Email Path (Received Chain) - {receivedChain.length} hops
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.15rem' }}>
                {receivedChain.map((hop, idx) => (
                  <div key={idx} style={{
                    display: 'flex',
                    alignItems: 'flex-start',
                    gap: '0.3rem',
                    fontSize: '0.58rem',
                    padding: '0.2rem 0.4rem',
                    background: 'rgba(255,255,255,0.02)',
                    borderRadius: '3px',
                    borderLeft: '2px solid rgba(96, 165, 250, 0.3)'
                  }}>
                    <span style={{
                      color: '#60a5fa',
                      fontWeight: '600',
                      minWidth: '20px'
                    }}>#{idx + 1}</span>
                    <span
                      style={{
                        color: '#94a3b8',
                        fontFamily: 'monospace',
                        fontSize: '0.55rem',
                        wordBreak: 'break-all',
                        lineHeight: 1.4
                      }}
                    >{hop}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* All Headers (expandable) */}
          {Object.keys(allHeaders).length > 0 && (
            <details style={{ marginTop: '0.3rem' }}>
              <summary style={{
                fontSize: '0.58rem',
                color: 'var(--text-muted)',
                cursor: 'pointer',
                padding: '0.2rem 0'
              }}>
                All Headers ({Object.keys(allHeaders).length})
              </summary>
              <div style={{
                marginTop: '0.3rem',
                maxHeight: '150px',
                overflow: 'auto',
                display: 'flex',
                flexDirection: 'column',
                gap: '0.1rem'
              }}>
                {Object.entries(allHeaders).map(([key, value]) => (
                  <div key={key} style={{
                    display: 'flex',
                    alignItems: 'flex-start',
                    gap: '0.5rem',
                    fontSize: '0.55rem',
                    padding: '0.1rem 0.3rem',
                    background: 'rgba(255,255,255,0.01)',
                    borderRadius: '2px'
                  }}>
                    <span style={{
                      color: 'var(--text-muted)',
                      minWidth: '120px',
                      flexShrink: 0,
                      fontSize: '0.52rem'
                    }}>{key}</span>
                    <span style={{
                      color: '#94a3b8',
                      fontFamily: 'monospace',
                      fontSize: '0.52rem',
                      wordBreak: 'break-all'
                    }}>{String(value).substring(0, 200)}{String(value).length > 200 ? '...' : ''}</span>
                  </div>
                ))}
              </div>
            </details>
          )}
        </div>
      )}

      {/* ══════════ EXPANDABLE: Raw JSON ══════════ */}
      {showRawEvent && (
        <div style={{
          marginBottom: '0.5rem',
          padding: '0.4rem',
          background: 'var(--bg-tertiary)',
          borderRadius: '4px',
          maxHeight: '200px',
          overflow: 'auto'
        }}>
          <pre style={{
            fontSize: '0.55rem',
            color: '#94a3b8',
            margin: 0,
            whiteSpace: 'pre-wrap',
            wordBreak: 'break-all',
            fontFamily: 'monospace'
          }}>
            {JSON.stringify(rawEvent, null, 2)}
          </pre>
        </div>
      )}

      {/* ══════════ ATTACHMENTS ══════════ */}
      {(attachments.length > 0 || loadingAttachments) && (
        <div style={{
          marginBottom: '0.5rem',
          padding: '0.5rem',
          background: 'var(--bg-tertiary)',
          borderRadius: '4px',
          border: '1px solid rgba(96, 165, 250, 0.2)'
        }}>
          <div style={{
            display: 'flex',
            alignItems: 'center',
            gap: '0.5rem',
            marginBottom: '0.4rem'
          }}>
            <span style={{ fontSize: '0.6rem', fontWeight: '600', color: '#60a5fa' }}>
              📎 ATTACHMENTS ({attachments.length})
            </span>
          </div>
          {loadingAttachments ? (
            <div style={{ fontSize: '0.6rem', color: 'var(--text-muted)' }}>Loading attachments...</div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.3rem' }}>
              {attachments.map((att) => (
                <div
                  key={att.attachment_id}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.5rem',
                    padding: '0.3rem 0.5rem',
                    background: att.is_malicious ? 'rgba(220, 38, 38, 0.1)' : 'rgba(255,255,255,0.03)',
                    borderRadius: '3px',
                    border: att.is_malicious ? '1px solid rgba(220, 38, 38, 0.3)' : '1px solid rgba(255,255,255,0.05)'
                  }}
                >
                  {/* File icon based on type */}
                  <span style={{ fontSize: '0.7rem' }}>
                    {att.mime_type?.startsWith('image/') ? '🖼️' :
                     att.mime_type?.includes('pdf') ? '📄' :
                     att.mime_type?.includes('zip') || att.mime_type?.includes('rar') ? '📦' :
                     att.original_filename?.match(/\.(exe|dll|msi)$/i) ? '⚠️' :
                     att.original_filename?.match(/\.(eml|msg)$/i) ? '✉️' :
                     '📎'}
                  </span>

                  {/* Filename */}
                  <span
                    style={{
                      flex: 1,
                      fontSize: '0.65rem',
                      fontFamily: 'monospace',
                      color: att.is_malicious ? '#f87171' : '#a0e9ff',
                      overflow: 'hidden',
                      textOverflow: 'ellipsis',
                      whiteSpace: 'nowrap'
                    }}
                    title={att.original_filename}
                  >
                    {att.original_filename}
                  </span>

                  {/* File size */}
                  <span style={{ fontSize: '0.55rem', color: 'var(--text-muted)' }}>
                    {formatFileSize(att.file_size)}
                  </span>

                  {/* Analysis status badge */}
                  {att.is_malicious && (
                    <span style={{
                      padding: '0.1rem 0.3rem',
                      borderRadius: '3px',
                      fontSize: '0.5rem',
                      fontWeight: '600',
                      background: 'rgba(220, 38, 38, 0.2)',
                      color: '#f87171',
                      border: '1px solid rgba(220, 38, 38, 0.3)'
                    }}>
                      MALICIOUS
                    </span>
                  )}
                  {att.analysis_status === 'analyzed' && !att.is_malicious && (
                    <span style={{
                      padding: '0.1rem 0.3rem',
                      borderRadius: '3px',
                      fontSize: '0.5rem',
                      fontWeight: '600',
                      background: 'rgba(34, 197, 94, 0.15)',
                      color: '#4ade80',
                      border: '1px solid rgba(34, 197, 94, 0.25)'
                    }}>
                      CLEAN
                    </span>
                  )}
                  {att.analysis_status === 'pending' && (
                    <span style={{
                      padding: '0.1rem 0.3rem',
                      borderRadius: '3px',
                      fontSize: '0.5rem',
                      fontWeight: '600',
                      background: 'rgba(96, 165, 250, 0.15)',
                      color: '#60a5fa',
                      border: '1px solid rgba(96, 165, 250, 0.25)'
                    }}>
                      PENDING
                    </span>
                  )}

                  {/* Hash (click to copy) */}
                  <span
                    onClick={() => copyToClipboard(att.sha256_hash)}
                    style={{
                      fontSize: '0.5rem',
                      fontFamily: 'monospace',
                      color: copiedValue === att.sha256_hash ? '#22c55e' : 'var(--text-muted)',
                      cursor: 'pointer'
                    }}
                    title={`SHA256: ${att.sha256_hash} (click to copy)`}
                  >
                    {copiedValue === att.sha256_hash ? '✓' : att.sha256_hash?.substring(0, 8)}
                  </span>

                  {/* Download button */}
                  <button
                    onClick={() => downloadAttachment(att)}
                    disabled={downloadingId === att.attachment_id}
                    style={{
                      padding: '0.15rem 0.4rem',
                      borderRadius: '3px',
                      border: 'none',
                      background: 'rgba(96, 165, 250, 0.2)',
                      color: '#60a5fa',
                      fontSize: '0.55rem',
                      fontWeight: '600',
                      cursor: downloadingId === att.attachment_id ? 'wait' : 'pointer',
                      opacity: downloadingId === att.attachment_id ? 0.6 : 1
                    }}
                  >
                    {downloadingId === att.attachment_id ? '...' : '↓ Download'}
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

    </div>
  );
}

function AlertViewer() {
  const [searchParams] = useSearchParams();
  const initialFilter = searchParams.get('status') || 'all';
  const initialSearch = searchParams.get('search') || '';
  const { preferences } = usePreferences();

  const [alerts, setAlerts] = useState([]);
  const [investigations, setInvestigations] = useState([]); // For linking alerts to investigations
  const [loading, setLoading] = useState(true);
  const [systemConfig, setSystemConfig] = useState(null); // For confidence display settings
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [statusFilter, setStatusFilter] = useState(initialFilter);
  const [severityFilter, setSeverityFilter] = useState('all');
  const [sourceFilter, setSourceFilter] = useState('all');
  const [timeRange, setTimeRangeState] = useState(() => {
    // If searching by ID, show all time to find the alert
    if (initialSearch) return 'all';
    return localStorage.getItem('T1 Agentics_alert_timerange') || '24h';
  });
  const setTimeRange = (value) => {
    localStorage.setItem('T1 Agentics_alert_timerange', value);
    setTimeRangeState(value);
  };
  const [searchQuery, setSearchQuery] = useState(initialSearch);
  const [autoRefresh, setAutoRefresh] = useState(true);

  // Time range options in minutes
  const timeRangeOptions = [
    { value: '5m', label: '5 min', minutes: 5 },
    { value: '15m', label: '15 min', minutes: 15 },
    { value: '30m', label: '30 min', minutes: 30 },
    { value: '1h', label: '1 hour', minutes: 60 },
    { value: '3h', label: '3 hours', minutes: 180 },
    { value: '6h', label: '6 hours', minutes: 360 },
    { value: '12h', label: '12 hours', minutes: 720 },
    { value: '24h', label: '24 hours', minutes: 1440 },
    { value: '7d', label: '7 days', minutes: 10080 },
    { value: '30d', label: '30 days', minutes: 43200 },
    { value: 'all', label: 'All time', minutes: null }
  ];
  const [expandedAlertId, setExpandedAlertId] = useState(null);
  const [expandedAlertData, setExpandedAlertData] = useState(null);
  const [loadingExpanded, setLoadingExpanded] = useState(false);
  const [showColumnCustomizer, setShowColumnCustomizer] = useState(false);
  const [showBulkUpdateModal, setShowBulkUpdateModal] = useState(false);
  const [rowsPerPage, setRowsPerPage] = useState(() => {
    const saved = localStorage.getItem('T1_Agentics_alert_rows_per_page');
    return saved ? parseInt(saved, 10) : 10;
  });
  const [currentPage, setCurrentPage] = useState(1);

  // Column configuration
  const availableColumns = [
    { key: 'alert_id', label: 'ID' },
    { key: 'title', label: 'Title' },
    { key: 'source', label: 'Source' },
    { key: 'severity', label: 'Severity' },
    { key: 'status', label: 'Status' },
    { key: 'enrichment', label: 'Enrichment' },
    { key: 'created_at', label: 'Created' },
    { key: 'updated_at', label: 'Updated' },
    { key: 'description', label: 'Description' },
    { key: 'category', label: 'Category' },
    { key: 'subcategory', label: 'Subcategory' },
    { key: 'confidence', label: 'Confidence' },
    { key: 'source_type', label: 'Source Type' },
    { key: 'external_id', label: 'External ID' }
  ];

  const defaultColumns = ['alert_id', 'title', 'severity', 'status', 'enrichment', 'source', 'created_at'];

  const [selectedColumns, setSelectedColumns] = useState(() => {
    const saved = localStorage.getItem('T1 Agentics_alert_columns');
    if (saved) {
      const parsed = JSON.parse(saved);
      // Ensure new columns like 'enrichment' are added if missing
      const hasEnrichment = parsed.includes('enrichment');
      if (!hasEnrichment) {
        // Insert 'enrichment' after 'status' if status exists, otherwise add at end
        const statusIdx = parsed.indexOf('status');
        if (statusIdx !== -1) {
          parsed.splice(statusIdx + 1, 0, 'enrichment');
        } else {
          parsed.push('enrichment');
        }
        localStorage.setItem('T1 Agentics_alert_columns', JSON.stringify(parsed));
      }
      return parsed;
    }
    return defaultColumns;
  });

  // Persist selected alerts to sessionStorage (survives page navigation but not tab close)
  const [selectedAlerts, setSelectedAlerts] = useState(() => {
    const saved = sessionStorage.getItem('T1 Agentics_selected_alerts');
    return saved ? new Set(JSON.parse(saved)) : new Set();
  });

  // Persist selected alerts whenever they change
  useEffect(() => {
    sessionStorage.setItem('T1 Agentics_selected_alerts', JSON.stringify([...selectedAlerts]));
  }, [selectedAlerts]);

  // Fetch both alerts and investigations
  const fetchData = useCallback(async (showFullLoading = false) => {
    // showFullLoading: true = show loading spinner (initial load, manual refresh)
    // showFullLoading: false = background refresh (auto-refresh)
    if (showFullLoading) {
      setLoading(true);
    } else {
      setIsRefreshing(true);
    }

    try {
      // Fetch alerts
      let alertUrl = `${API_BASE_URL}/api/v1/alerts?limit=10000`;
      if (statusFilter !== 'all') {
        alertUrl += `&status=${statusFilter}`;
      }

      // Fetch investigations
      let invUrl = `${API_BASE_URL}/api/v1/investigations?limit=5000`;

      // Also fetch system config for confidence display settings
      const configUrl = `${API_BASE_URL}/api/v1/config/`;

      const [alertsRes, investigationsRes, configRes] = await Promise.all([
        fetch(alertUrl, { headers: getAuthHeaders() }),
        fetch(invUrl, { headers: getAuthHeaders() }),
        fetch(configUrl, { headers: getAuthHeaders() })
      ]);

      // Check for auth errors on main data endpoints only - redirect to login if session expired
      // Note: Don't check configRes - it's optional and shouldn't trigger logout
      if (alertsRes.status === 401 || investigationsRes.status === 401) {
        localStorage.removeItem('token');
        localStorage.removeItem('username');
        localStorage.removeItem('role');
        window.location.href = '/login';
        return;
      }

      const alertsData = alertsRes.ok ? await alertsRes.json() : [];
      const investigationsData = investigationsRes.ok ? await investigationsRes.json() : [];
      const configData = configRes.ok ? await configRes.json() : {};

      setAlerts(Array.isArray(alertsData) ? alertsData : []);
      setInvestigations(Array.isArray(investigationsData) ? investigationsData : []);
      setSystemConfig(configData);
    } catch (error) {
    } finally {
      setLoading(false);
      setIsRefreshing(false);
    }
  }, [statusFilter]);

  useEffect(() => {
    // Initial load with full loading state
    fetchData(true);

    let interval;
    if (autoRefresh) {
      // Auto-refresh every 5 seconds without showing loading spinner
      interval = setInterval(() => fetchData(false), 5000);
    }

    return () => {
      if (interval) clearInterval(interval);
    };
  }, [statusFilter, autoRefresh, fetchData]);

  // Sync search query from URL when it changes (e.g., from navigation)
  useEffect(() => {
    const urlSearch = searchParams.get('search') || '';
    if (urlSearch !== searchQuery) {
      setSearchQuery(urlSearch);
      // If searching by ID, expand time range to find it
      if (urlSearch && timeRange !== 'all') {
        setTimeRangeState('all');
      }
    }
  }, [searchParams]);

  useEffect(() => {
    setCurrentPage(1);
  }, [statusFilter, severityFilter, sourceFilter, timeRange, searchQuery, rowsPerPage]);

  // Get unique sources for filter
  const uniqueSources = [...new Set(alerts.map(a => a.source).filter(Boolean))].sort();

  // Get time range cutoff
  const getTimeCutoff = () => {
    const option = timeRangeOptions.find(o => o.value === timeRange);
    if (!option || option.minutes === null) return null;
    return new Date(Date.now() - option.minutes * 60 * 1000);
  };

  // Filter alerts only (investigations are used for linking, not display)
  const filteredAlerts = alerts.filter(alert => {
    // Time range filter
    const cutoff = getTimeCutoff();
    if (cutoff) {
      const alertDate = new Date(alert.created_at);
      if (alertDate < cutoff) return false;
    }
    if (severityFilter !== 'all' && alert.severity?.toLowerCase() !== severityFilter) return false;
    if (sourceFilter !== 'all' && alert.source !== sourceFilter) return false;
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      const matchesId = alert.alert_id?.toLowerCase().includes(q);
      const matchesTitle = alert.title?.toLowerCase().includes(q);
      const matchesDesc = alert.description?.toLowerCase().includes(q);
      const matchesSource = alert.source?.toLowerCase().includes(q);
      if (!matchesId && !matchesTitle && !matchesDesc && !matchesSource) return false;
    }
    return true;
  });

  // Pagination
  const totalPages = Math.ceil(filteredAlerts.length / rowsPerPage);
  const startIndex = (currentPage - 1) * rowsPerPage;
  const paginatedAlerts = filteredAlerts.slice(startIndex, startIndex + rowsPerPage);

  const handleColumnsChange = (newColumns) => {
    setSelectedColumns(newColumns);
    localStorage.setItem('T1 Agentics_alert_columns', JSON.stringify(newColumns));
  };

  // Color functions removed - now using CSS module classes

  // Format date using user's timezone preference
  const formatDate = useCallback((dateStr) => {
    if (!dateStr) return '-';
    return formatDateTime(
      dateStr,
      preferences.dateFormat || 'relative',
      preferences.timezone || 'local'
    );
  }, [preferences.dateFormat, preferences.timezone]);

  const toggleSelectAlert = (alertId) => {
    const newSelected = new Set(selectedAlerts);
    if (newSelected.has(alertId)) {
      newSelected.delete(alertId);
    } else {
      newSelected.add(alertId);
    }
    setSelectedAlerts(newSelected);
  };

  const toggleSelectAll = () => {
    if (selectedAlerts.size === paginatedAlerts.length) {
      setSelectedAlerts(new Set());
    } else {
      setSelectedAlerts(new Set(paginatedAlerts.map(a => a.alert_id)));
    }
  };

  const handleBulkUpdate = async (updates) => {
    if (selectedAlerts.size === 0) return;
    try {
      const response = await fetch(`${API_BASE_URL}/api/v1/alerts/bulk-update`, {
        method: 'PATCH',
        headers: getAuthHeaders(),
        body: JSON.stringify({
          alert_ids: Array.from(selectedAlerts),
          updates: updates
        })
      });
      if (response.ok) {
        setSelectedAlerts(new Set());
        setShowBulkUpdateModal(false);
        await fetchData();
      }
    } catch (error) {
    }
  };

  const handleRowClick = async (alert) => {
    // Toggle off if clicking same row
    if (expandedAlertId === alert.alert_id) {
      setExpandedAlertId(null);
      setExpandedAlertData(null);
      return;
    }

    setExpandedAlertId(alert.alert_id);
    setLoadingExpanded(true);

    try {
      // Fetch full alert data including enrichment
      const response = await fetch(`${API_BASE_URL}/api/v1/alerts/${alert.alert_id}`, {
        headers: getAuthHeaders()
      });
      if (response.ok) {
        const fullAlertData = await response.json();

        // Also fetch investigation if linked
        let investigationData = null;
        if (fullAlertData.investigation_id) {
          try {
            const invResponse = await fetch(`${API_BASE_URL}/api/v1/investigations/${fullAlertData.investigation_id}`, {
              headers: getAuthHeaders()
            });
            if (invResponse.ok) {
              investigationData = await invResponse.json();
            }
          } catch (err) {
          }
        }

        setExpandedAlertData({ ...fullAlertData, investigation: investigationData });
      } else {
        // Fallback to basic alert data
        setExpandedAlertData(alert);
      }
    } catch (error) {
      setExpandedAlertData(alert);
    } finally {
      setLoadingExpanded(false);
    }
  };

  // Create investigation from alert
  const handleCreateInvestigation = async (alert) => {
    try {
      const response = await fetch(`${API_BASE_URL}/api/v1/investigations`, {
        method: 'POST',
        headers: getAuthHeaders(),
        body: JSON.stringify({
          alert_id: alert.id || alert.alert_id,
          title: alert.title,
          priority: alert.severity === 'critical' ? 'P1' : alert.severity === 'high' ? 'P2' : 'P3'
        })
      });
      if (response.ok) {
        // Refresh data to show updated alert with investigation link
        await fetchData(false);
        // Re-expand the row to show updated investigation link
        handleRowClick(alert);
      }
    } catch (error) {
    }
  };

  // Get investigation for an alert (if it has one)
  const getAlertInvestigation = (alert) => {
    if (!alert.investigation_id) return null;
    return investigations.find(inv => inv.investigation_id === alert.investigation_id);
  };

  const renderCell = (alert, columnKey) => {
    const value = alert[columnKey];

    switch (columnKey) {
      case 'alert_id':
        // Show alert-{first 8 chars of UUID} format for consistent identification
        const shortId = value?.substring(0, 8) || 'unknown';
        const displayLabel = `alert-${shortId}`;
        return <span className={styles.cellId}>{displayLabel}</span>;

      case 'title':
        return <div className={styles.cellTitle}>{value || 'Untitled Event'}</div>;
      
      case 'severity':
        // Severity badges using Badge component
        return (
          <Badge variant={severityToBadgeVariant(value)} size="xs" solid>
            {value?.toUpperCase() || 'UNKNOWN'}
          </Badge>
        );
      
      case 'status':
        // Status badges using Badge component
        const statusLower = value?.toLowerCase();
        const hasInvestigation = alert.investigation_id;

        // Confirmed threat - danger
        if (statusLower === 'confirmed' || statusLower === 'true_positive') {
          return <Badge variant="danger" size="xs" solid>CONFIRMED</Badge>;
        }

        // Needs review - warning
        if (statusLower === 'needs_review' || statusLower === 'awaiting_human') {
          return <Badge variant="warning" size="xs" solid>NEEDS REVIEW</Badge>;
        }

        // Closed - default (muted)
        if (statusLower === 'closed') {
          return <Badge variant="default" size="xs" solid>CLOSED</Badge>;
        }

        // Resolved/False Positive - success
        if (['resolved', 'false_positive'].includes(statusLower)) {
          const displayText = statusLower === 'false_positive' ? 'FALSE POS' : 'RESOLVED';
          return <Badge variant="success" size="xs" solid>{displayText}</Badge>;
        }

        // Investigating - info (active work)
        if (hasInvestigation || statusLower === 'investigating') {
          return <Badge variant="info" size="xs" solid>INVESTIGATING</Badge>;
        }

        // Open/New - info (needs attention)
        return <Badge variant="info" size="xs" solid>{value?.toUpperCase() || 'OPEN'}</Badge>;

      case 'enrichment':
        // Show enrichment verdict using Badge component
        const enrichmentData = alert.raw_event?._extracted?.enrichment;
        if (enrichmentData && enrichmentData.status === 'enriched') {
          const summary = enrichmentData.summary || {};
          const hasMalicious = summary.malicious > 0;
          const hasSuspicious = summary.suspicious > 0;
          const totalEnriched = summary.total_enriched || 0;

          // Malicious - danger
          if (hasMalicious) {
            return <Badge variant="danger" size="xs" solid>{summary.malicious} MAL ({totalEnriched})</Badge>;
          }

          // Suspicious - warning
          if (hasSuspicious) {
            return <Badge variant="warning" size="xs" solid>{summary.suspicious} SUS ({totalEnriched})</Badge>;
          }

          // Clean - success
          return <Badge variant="success" size="xs" solid>CLEAN ({totalEnriched})</Badge>;
        }

        // Check for other states
        const enrichmentStatus = alert.enrichment_status;
        const enrichmentSummary = alert.enrichment_summary;
        const rawEvent = alert.raw_event || {};
        const hasIOCs = rawEvent.source_ip || rawEvent.domain || rawEvent.file?.hashes ||
                       rawEvent._extracted?.iocs?.ips?.length > 0 ||
                       rawEvent._extracted?.iocs?.domains?.length > 0 ||
                       rawEvent._extracted?.iocs?.hashes?.length > 0;

        // Pending - info
        if (hasIOCs && !enrichmentData) {
          return <Badge variant="info" size="xs" solid>PENDING</Badge>;
        }

        // Internal - default
        if (enrichmentSummary?.internal_only) {
          const privateIps = enrichmentSummary?.private_ips || [];
          const title = privateIps.length > 0
            ? `${privateIps.length} internal IP(s)`
            : 'Internal indicators';
          return <Badge variant="default" size="xs" solid title={title}>INTERNAL</Badge>;
        }

        // N/A - default
        return <Badge variant="default" size="xs" solid title={enrichmentSummary?.reason || 'No IOCs in alert'}>N/A</Badge>;

      case 'source':
        return <span className={styles.cellSource}>{value || '-'}</span>;

      case 'created_at':
      case 'updated_at':
        return <span className={styles.cellDate}>{formatDate(value)}</span>;

      case 'description':
        return <div className={styles.cellDescription}>{value || '-'}</div>;

      case 'confidence':
        // Check ai_confidence first (actual AI verdict confidence), then fallback to other fields
        const directConfidence = alert.ai_confidence || value;
        const aiTriageConfidence = alert.raw_event?._extracted?.ai_triage?.confidence;
        const confidenceValue = directConfidence || aiTriageConfidence;

        if (confidenceValue) {
          // Convert to percentage if it's a decimal (0-1)
          const pct = confidenceValue > 1 ? confidenceValue : confidenceValue * 100;

          // Check system config for display mode (label vs numeric)
          const displayMode = systemConfig?.confidence?.display_mode || 'label';
          const labels = systemConfig?.confidence?.labels || { high: 'High', medium: 'Medium', low: 'Low' };

          // Determine label based on thresholds (≥75% = high, 40-74% = medium, <40% = low)
          let displayText;
          if (displayMode === 'numeric') {
            displayText = `${Math.round(pct)}%`;
          } else {
            // Label mode
            if (pct >= 75) {
              displayText = labels.high || 'High';
            } else if (pct >= 40) {
              displayText = labels.medium || 'Medium';
            } else {
              displayText = labels.low || 'Low';
            }
          }

          const confVariant = pct >= 75 ? 'success' : pct >= 40 ? 'warning' : 'danger';
          return <Badge variant={confVariant} size="xs" solid>{displayText}</Badge>;
        }
        return <span className={styles.cellMuted}>-</span>;

      case 'category':
      case 'subcategory':
      case 'source_type':
        return value ? (
          <Badge variant="info" size="xs">{value}</Badge>
        ) : <span className={styles.cellMuted}>-</span>;

      case 'external_id':
        return value ? (
          <span className={styles.cellExternalId}>
            {value.length > 20 ? `${value.substring(0, 20)}...` : value}
          </span>
        ) : <span className={styles.cellMuted}>-</span>;

      default:
        return value || '-';
    }
  };

  // Calculate metrics - alerts only
  const metrics = {
    total: alerts.length,
    open: alerts.filter(a => a.status?.toLowerCase() === 'open').length,
    investigating: alerts.filter(a => a.status?.toLowerCase() === 'investigating' || a.investigation_id).length,
    critical: alerts.filter(a => a.severity?.toLowerCase() === 'critical').length,
    high: alerts.filter(a => a.severity?.toLowerCase() === 'high').length,
    todayCount: alerts.filter(a => {
      const created = new Date(a.created_at);
      const today = new Date();
      return created.toDateString() === today.toDateString();
    }).length,
    resolvedToday: alerts.filter(a => {
      if (a.status?.toLowerCase() !== 'resolved' && a.status?.toLowerCase() !== 'closed') return false;
      const updated = new Date(a.updated_at);
      const today = new Date();
      return updated.toDateString() === today.toDateString();
    }).length
  };

  // Local styles object has been moved to AlertViewer.module.css
  // Now using imported 'styles' from the CSS module

  return (
    <div className={`${styles.container} fade-in`}>
      {/* Header */}
      <div className={styles.header}>
        <div>
          <h2 className={styles.headerTitle}>Queue</h2>
          <p className={styles.headerSubtitle}>
            {filteredAlerts.length} of {metrics.total} alerts
            <span className={styles.timezoneBadge} title={`Showing times in ${preferences.timezone || 'local'} timezone`}>
              {getTimezoneAbbr(preferences.timezone || 'local')}
            </span>
          </p>
        </div>
        <div className={styles.headerActions}>
          <button
            onClick={() => fetchData(true)}
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
        </div>
      </div>

      {/* Dashboard Metrics - Clickable */}
      <div className={styles.metricsGrid}>
        <div
          className={styles.metricCard}
          onClick={() => { setStatusFilter('all'); setSeverityFilter('all'); }}
          title="Show all events"
        >
          <span className={styles.metricValue}>{metrics.total}</span>
          <span className={styles.metricLabel}>Total</span>
        </div>
        <div
          className={`${styles.metricCard} ${statusFilter === 'open' ? styles.activeBlue : ''}`}
          onClick={() => { setStatusFilter('open'); setSeverityFilter('all'); }}
          title="Filter by Open status"
        >
          <span className={`${styles.metricValue} ${styles.metricValueBlue}`}>{metrics.open}</span>
          <span className={styles.metricLabel}>Open</span>
        </div>
        <div
          className={`${styles.metricCard} ${statusFilter === 'investigating' ? styles.activeYellow : ''}`}
          onClick={() => { setStatusFilter('investigating'); setSeverityFilter('all'); }}
          title="Filter by Investigating status"
        >
          <span className={`${styles.metricValue} ${styles.metricValueYellow}`}>{metrics.investigating}</span>
          <span className={styles.metricLabel}>Investigating</span>
        </div>
        <div
          className={`${styles.metricCard} ${severityFilter === 'critical' ? styles.activeRed : ''}`}
          onClick={() => { setSeverityFilter('critical'); setStatusFilter('all'); }}
          title="Filter by Critical severity"
        >
          <span className={`${styles.metricValue} ${styles.metricValueRed}`}>{metrics.critical}</span>
          <span className={styles.metricLabel}>Critical</span>
        </div>
        <div
          className={`${styles.metricCard} ${severityFilter === 'high' ? styles.activeOrange : ''}`}
          onClick={() => { setSeverityFilter('high'); setStatusFilter('all'); }}
          title="Filter by High severity"
        >
          <span className={`${styles.metricValue} ${styles.metricValueOrange}`}>{metrics.high}</span>
          <span className={styles.metricLabel}>High</span>
        </div>
        <div
          className={`${styles.metricCard} ${(timeRange === '24h' && statusFilter === 'all') ? styles.active : ''}`}
          onClick={() => { setTimeRange('24h'); setStatusFilter('all'); setSeverityFilter('all'); }}
          title="Show events from last 24 hours"
        >
          <span className={styles.metricValue}>{metrics.todayCount}</span>
          <span className={styles.metricLabel}>Today</span>
        </div>
        <div
          className={`${styles.metricCard} ${statusFilter === 'resolved' ? styles.activeGreen : ''}`}
          onClick={() => { setStatusFilter('resolved'); setSeverityFilter('all'); }}
          title="Filter by Resolved status"
        >
          <span className={`${styles.metricValue} ${styles.metricValueGreen}`}>{metrics.resolvedToday}</span>
          <span className={styles.metricLabel}>Resolved Today</span>
        </div>
      </div>

      {/* Search Bar */}
      <div className={styles.searchBar}>
        <input
          type="text"
          placeholder="Search ID, title, description, source..."
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
          <span className={styles.filterLabel}>Status:</span>
          <select className={styles.select} value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)}>
            <option value="all">All</option>
            <option value="open">Open</option>
            <option value="investigating">Investigating</option>
            <option value="resolved">Resolved</option>
            <option value="closed">Closed</option>
          </select>
        </div>

        <div className={styles.filterGroup}>
          <span className={styles.filterLabel}>Severity:</span>
          <select className={styles.select} value={severityFilter} onChange={(e) => setSeverityFilter(e.target.value)}>
            <option value="all">All</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </div>

        <div className={styles.filterGroup}>
          <span className={styles.filterLabel}>Source:</span>
          <select className={styles.select} value={sourceFilter} onChange={(e) => setSourceFilter(e.target.value)}>
            <option value="all">All</option>
            {uniqueSources.map(src => (
              <option key={src} value={src}>{src}</option>
            ))}
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
                localStorage.setItem('T1_Agentics_alert_rows_per_page', val);
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

      {/* Bulk Actions Bar */}
      {selectedAlerts.size > 0 && (
        <div className={styles.bulkBar}>
          <span className={styles.bulkBarText}>
            {selectedAlerts.size} event{selectedAlerts.size > 1 ? 's' : ''} selected
          </span>
          <div className={styles.bulkBarActions}>
            <button
              onClick={() => setShowBulkUpdateModal(true)}
              className={`${styles.btn} ${styles.btnPrimary}`}
              style={{ background: 'white', color: '#3CB371' }}
            >
              Update
            </button>
            <Link
              to={`/investigate?alert_ids=${Array.from(selectedAlerts).join(',')}`}
              className={styles.btn}
              style={{ background: 'rgba(255,255,255,0.2)', color: 'white', textDecoration: 'none' }}
            >
              Investigate
            </Link>
            <button
              onClick={() => setSelectedAlerts(new Set())}
              className={styles.btn}
              style={{ background: 'rgba(255,255,255,0.1)', color: 'white' }}
            >
              Clear
            </button>
          </div>
        </div>
      )}

      {/* Table */}
      {loading ? (
        <div style={{ textAlign: 'center', padding: '2rem', color: 'var(--text-muted)' }}>Loading...</div>
      ) : paginatedAlerts.length === 0 ? (
        <div style={{ textAlign: 'center', padding: '2rem', color: 'var(--text-muted)', background: 'var(--bg-tertiary)', borderRadius: '6px' }}>
          No events found
        </div>
      ) : (
        <div className={styles.tableContainer}>
          <table className={styles.table}>
            <thead>
              <tr>
                <th className={styles.th} style={{ width: '40px', textAlign: 'center' }}>
                  <input
                    type="checkbox"
                    checked={selectedAlerts.size === paginatedAlerts.length && paginatedAlerts.length > 0}
                    onChange={toggleSelectAll}
                    className={styles.checkbox}
                  />
                </th>
                {selectedColumns.map(colKey => {
                  const col = availableColumns.find(c => c.key === colKey);
                  return <th key={colKey} className={styles.th}>{col?.label || colKey}</th>;
                })}
                <th className={styles.th} style={{ textAlign: 'right', width: '60px' }}>Action</th>
              </tr>
            </thead>
            <tbody>
              {paginatedAlerts.map((alert, index) => {
                const isExpanded = expandedAlertId === alert.alert_id;
                const linkedInvestigation = getAlertInvestigation(alert);
                const hasInvestigation = !!linkedInvestigation || !!alert.investigation_id;
                const isEvenRow = index % 2 === 0;
                const colSpan = selectedColumns.length + 2; // +2 for checkbox and action columns

                return (
                <React.Fragment key={alert.alert_id}>
                  <tr
                    className={`${styles.row} ${isExpanded ? styles.rowExpanded : ''}`}
                    style={{
                      background: isExpanded ? 'rgba(60, 179, 113, 0.1)' : (isEvenRow ? 'transparent' : 'rgba(255, 255, 255, 0.02)'),
                      borderLeft: hasInvestigation ? '3px solid #3CB371' : '3px solid transparent'
                    }}
                  >
                    <td className={styles.td} style={{ textAlign: 'center' }} onClick={(e) => e.stopPropagation()}>
                      <input
                        type="checkbox"
                        checked={selectedAlerts.has(alert.alert_id)}
                        onChange={() => toggleSelectAlert(alert.alert_id)}
                        className={styles.checkbox}
                      />
                    </td>
                    {selectedColumns.map(colKey => (
                      <td key={colKey} className={styles.td} onClick={() => handleRowClick(alert)}>
                        {/* Show investigation badge in status column if linked */}
                        {colKey === 'status' && hasInvestigation ? (
                          <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                            {renderCell(alert, colKey)}
                            <Link
                              to={`/investigation/${alert.investigation_id || linkedInvestigation?.investigation_id}`}
                              onClick={(e) => e.stopPropagation()}
                              className={styles.actionBtnView}
                              style={{ padding: '0.15rem 0.35rem', fontSize: '0.55rem' }}
                              title={`Investigation: ${linkedInvestigation?.state || 'View'}`}
                            >
                              INV
                            </Link>
                          </div>
                        ) : (
                          renderCell(alert, colKey)
                        )}
                      </td>
                    ))}
                    <td className={styles.td} style={{ textAlign: 'right', whiteSpace: 'nowrap' }}>
                      <div style={{ display: 'flex', gap: '0.25rem', justifyContent: 'flex-end', alignItems: 'center' }}>
                        {!hasInvestigation && (
                          <button
                            onClick={(e) => { e.stopPropagation(); handleCreateInvestigation(alert); }}
                            className={styles.actionBtnCreate}
                            style={{ fontSize: '0.65rem', padding: '0.2rem 0.5rem' }}
                            title="Create investigation from this alert"
                          >
                            Investigate
                          </button>
                        )}
                        {hasInvestigation && (
                          <Link
                            to={`/investigation/${alert.investigation_id || linkedInvestigation?.investigation_id}`}
                            onClick={(e) => e.stopPropagation()}
                            className={styles.actionBtnCreate}
                            style={{ fontSize: '0.65rem', padding: '0.2rem 0.5rem', textDecoration: 'none' }}
                          >
                            Open Inv
                          </Link>
                        )}
                        <button
                          onClick={() => handleRowClick(alert)}
                          className={`${styles.btn} ${styles.btnSecondary}`}
                          style={{
                            fontSize: '0.65rem',
                            padding: '0.2rem 0.4rem',
                            background: isExpanded ? 'rgba(60, 179, 113, 0.3)' : undefined
                          }}
                        >
                          {isExpanded ? '▲' : '▼'}
                        </button>
                      </div>
                    </td>
                  </tr>

                  {/* Expanded Details Row */}
                  {isExpanded && (
                    <tr>
                      <td colSpan={colSpan} style={{ padding: 0, background: 'var(--bg-secondary)', position: 'relative' }}>
                        <div style={{
                          padding: '1rem',
                          borderLeft: '3px solid #3CB371',
                          animation: 'fadeIn 0.2s ease',
                          width: '100%',
                          boxSizing: 'border-box',
                          overflow: 'hidden'
                        }}>
                          {loadingExpanded ? (
                            <div style={{ textAlign: 'center', padding: '1rem', color: 'var(--text-muted)' }}>
                              Loading details...
                            </div>
                          ) : expandedAlertData ? (
                            <ExpandedAlertContent
                              alert={expandedAlertData}
                              investigation={expandedAlertData.investigation}
                              onCreateInvestigation={() => handleCreateInvestigation(alert)}
                              onRefresh={() => fetchData(false)}
                              preferences={preferences}
                            />
                          ) : (
                            <div style={{ textAlign: 'center', padding: '1rem', color: 'var(--text-muted)' }}>
                              Unable to load details
                            </div>
                          )}
                        </div>
                      </td>
                    </tr>
                  )}
                </React.Fragment>
              );})}
            </tbody>
          </table>

          {/* Pagination */}
          {filteredAlerts.length > rowsPerPage && (
            <div className={styles.pagination}>
              <span className={styles.paginationInfo}>
                Showing {startIndex + 1}-{Math.min(startIndex + rowsPerPage, filteredAlerts.length)} of {filteredAlerts.length}
              </span>
              <div className={styles.paginationControls}>
                <button
                  className={`${styles.btn} ${styles.btnSecondary} ${currentPage === 1 ? styles.btnDisabled : ''}`}
                  onClick={() => setCurrentPage(1)}
                  disabled={currentPage === 1}
                >First</button>
                <button
                  className={`${styles.btn} ${styles.btnSecondary} ${currentPage === 1 ? styles.btnDisabled : ''}`}
                  onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
                  disabled={currentPage === 1}
                >Prev</button>
                <span style={{ padding: '0 0.5rem', color: 'var(--text-primary)' }}>
                  Page {currentPage} of {totalPages}
                </span>
                <button
                  className={`${styles.btn} ${styles.btnSecondary} ${currentPage === totalPages ? styles.btnDisabled : ''}`}
                  onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))}
                  disabled={currentPage === totalPages}
                >Next</button>
                <button
                  className={`${styles.btn} ${styles.btnSecondary} ${currentPage === totalPages ? styles.btnDisabled : ''}`}
                  onClick={() => setCurrentPage(totalPages)}
                  disabled={currentPage === totalPages}
                >Last</button>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Column Customizer Modal */}
      {showColumnCustomizer && (
        <ColumnCustomizer
          availableColumns={availableColumns}
          selectedColumns={selectedColumns}
          onColumnsChange={handleColumnsChange}
          onClose={() => setShowColumnCustomizer(false)}
          defaultColumns={['alert_id', 'title', 'severity', 'status', 'enrichment', 'source', 'created_at']}
        />
      )}

      {/* Bulk Update Modal */}
      {showBulkUpdateModal && (
        <BulkUpdateModal
          selectedCount={selectedAlerts.size}
          onUpdate={handleBulkUpdate}
          onClose={() => setShowBulkUpdateModal(false)}
        />
      )}
    </div>
  );
}

export default AlertViewer;
