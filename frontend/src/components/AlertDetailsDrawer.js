/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { usePermissions } from '../hooks/usePermissions';
import { usePreferences, formatInTimezone } from '../hooks/usePreferences';
import { getAuthHeaders, API_BASE_URL, authFetch } from '../utils/api';
import { useToast } from './ui/Toast';
import JsonViewer from './JsonViewer';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';

/**
 * Alert Details Drawer - Slides in from right
 * Replaces inline "View" and "Investigate" buttons
 * Entire alert row is now clickable
 */
function AlertDetailsDrawer({ alert: initialAlert, onClose, onStatusChange, onRefresh }) {
  const { can } = usePermissions();
  const { preferences } = usePreferences();
  const toast = useToast();
  const [alert, setAlert] = useState(initialAlert);
  const [investigation, setInvestigation] = useState(null);
  const [newSeverity, setNewSeverity] = useState(initialAlert?.severity || 'medium');
  const [showRawDataPanel, setShowRawDataPanel] = useState(false);
  const [saving, setSaving] = useState(false);
  const [threatData, setThreatData] = useState(null);
  const [loadingThreatData, setLoadingThreatData] = useState(false);
  const [updatingInvestigation, setUpdatingInvestigation] = useState(false);
  const [confidenceConfig, setConfidenceConfig] = useState({
    display_mode: 'label',
    labels: { high: 'High Confidence', medium: 'Medium Confidence', low: 'Low Confidence' }
  });
  const [isCreatingInvestigation, setIsCreatingInvestigation] = useState(false);

  // Function to update investigation state/disposition
  const updateInvestigation = async (updates) => {
    if (!investigation?.investigation_id) return;

    setUpdatingInvestigation(true);
    try {
      const response = await authFetch(`${API_BASE_URL}/api/v1/investigations/${investigation.investigation_id}`, {
        method: 'PATCH',
        body: JSON.stringify(updates)
      });

      if (response.ok) {
        const updatedInv = await response.json();
        setInvestigation(prev => ({ ...prev, ...updatedInv }));
        if (onRefresh) onRefresh();
        // Show success feedback
        const el = document.createElement('div');
        el.textContent = 'Updated!';
        el.style.cssText = 'position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);background:#22c55e;color:white;padding:0.5rem 1rem;border-radius:4px;z-index:9999;font-size:0.8rem;';
        document.body.appendChild(el);
        setTimeout(() => el.remove(), 1500);
      } else {
        const err = await response.text();
        toast.error('Failed to update investigation');
      }
    } catch (error) {
      toast.error('Error updating investigation: ' + error.message);
    } finally {
      setUpdatingInvestigation(false);
    }
  };

  // Fetch confidence display config
  useEffect(() => {
    const fetchConfig = async () => {
      try {
      const response = await fetch(`${API_BASE_URL}/api/v1/config`, {
        });
        if (response.ok) {
          const data = await response.json();
          if (data.confidence) {
            setConfidenceConfig(data.confidence);
          }
        }
      } catch (error) {
        console.error('Config fetch error:', error);
      }
    };
    fetchConfig();
  }, []);

  // Helper to format confidence based on config
  const formatConfidence = (value) => {
    if (value === null || value === undefined) return null;

    // Normalize to 0-100 range
    const numValue = value > 1 ? value : value * 100;

    if (confidenceConfig.display_mode === 'numeric') {
      return `${Math.round(numValue)}%`;
    }

    // Label mode
    if (numValue >= 75) return confidenceConfig.labels?.high || 'High';
    if (numValue >= 40) return confidenceConfig.labels?.medium || 'Medium';
    return confidenceConfig.labels?.low || 'Low';
  };

  useEffect(() => {
    if (initialAlert) {
      setAlert(initialAlert);
      setNewSeverity(initialAlert.severity || 'medium');
      fetchInvestigation();

      // Always fetch fresh alert data to get latest enrichment status
      if (initialAlert.alert_id) {
        fetchFullAlertAndEnrichment(initialAlert.alert_id);
      } else {
        // No alert_id, just use what we have
        fetchThreatData(initialAlert);
      }
    }
  }, [initialAlert]);

  // Fetch fresh alert data and then process enrichment
  const fetchFullAlertAndEnrichment = async (alertId) => {
    try {
      const response = await fetch(`${API_BASE_URL}/api/v1/alerts/${alertId}`, {
      });
      if (response.ok) {
        const fullAlertData = await response.json();
        setAlert(fullAlertData);
        setNewSeverity(fullAlertData.severity || 'medium');
        // Now fetch threat data with the fresh data
        fetchThreatData(fullAlertData);
      } else {
        // Fallback to initial data
        fetchThreatData(initialAlert);
      }
    } catch (error) {
      fetchThreatData(initialAlert);
    }
  };

  // Fetch threat intelligence data for IOCs in the alert
  const fetchThreatData = async (alertData) => {
    if (!alertData) return;

    const rawEvent = alertData.raw_event || {};

    // First check if auto-enrichment already happened (stored in _extracted.enrichment)
    const preEnriched = rawEvent._extracted?.enrichment;
    if (preEnriched && preEnriched.status === 'enriched' && preEnriched.results) {
      // Use pre-enriched data - convert to our display format
      const results = [];
      for (const iocType of ['ips', 'domains', 'hashes']) {
        const iocResults = preEnriched.results[iocType] || [];
        for (const item of iocResults) {
          results.push({
            value: item.value,
            type: item.type,
            found: !item.error,
            verdict: item.verdict,
            confidence: item.confidence,
            sources: item.sources || [],
            enrichment: {
              country: item.country,
              asn: item.asn,
              abuse_score: item.abuse_score,
              vt_positives: item.vt_positives,
              vt_total: item.vt_total
            },
            first_seen: item.first_seen,
            last_seen: item.last_seen
          });
        }
      }
      if (results.length > 0) {
        setThreatData(results);
        setLoadingThreatData(false);
        return;
      }
    }

    // No pre-enriched data, extract IOCs and fetch from API
    const iocs = [];
    const extracted = rawEvent._extracted?.iocs || {};

    // Helper to add unique IOCs
    const addedValues = new Set();
    const addIOC = (value, type) => {
      if (value && !addedValues.has(value)) {
        addedValues.add(value);
        iocs.push({ value, type });
      }
    };

    // 1. Check _extracted.iocs (from ingestion pipeline)
    if (extracted.ips?.length > 0) {
      extracted.ips.forEach(ip => addIOC(ip, 'ip'));
    }
    if (extracted.domains?.length > 0) {
      extracted.domains.forEach(domain => addIOC(domain, 'domain'));
    }
    if (extracted.hashes?.length > 0) {
      extracted.hashes.forEach(hash => addIOC(hash, 'hash'));
    }
    if (extracted.urls?.length > 0) {
      extracted.urls.forEach(url => addIOC(url, 'url'));
    }

    // 1b. Check decoded_iocs from AI analysis (hidden IOCs from base64/encoded content)
    const decodedIOCs = rawEvent._extracted?.decoded_iocs || rawEvent._extracted?.ai_triage?.decoded_iocs || {};
    if (decodedIOCs.ips?.length > 0) {
      decodedIOCs.ips.forEach(ip => addIOC(ip, 'ip'));
    }
    if (decodedIOCs.domains?.length > 0) {
      decodedIOCs.domains.forEach(domain => addIOC(domain, 'domain'));
    }
    if (decodedIOCs.urls?.length > 0) {
      decodedIOCs.urls.forEach(url => addIOC(url, 'url'));
    }
    if (decodedIOCs.emails?.length > 0) {
      decodedIOCs.emails.forEach(email => {
        // Extract domain from email for enrichment
        const match = email.match(/@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/);
        if (match) addIOC(match[1], 'domain');
      });
    }

    // 2. Check structured fields in raw_event (file.hashes, network.*, etc.)
    // File hashes
    if (rawEvent.file?.hashes) {
      const hashes = rawEvent.file.hashes;
      if (hashes.md5) addIOC(hashes.md5, 'hash');
      if (hashes.sha1) addIOC(hashes.sha1, 'hash');
      if (hashes.sha256) addIOC(hashes.sha256, 'hash');
    }
    // Direct hash fields
    if (rawEvent.md5) addIOC(rawEvent.md5, 'hash');
    if (rawEvent.sha1) addIOC(rawEvent.sha1, 'hash');
    if (rawEvent.sha256) addIOC(rawEvent.sha256, 'hash');
    if (rawEvent.hash) addIOC(rawEvent.hash, 'hash');

    // Network IPs (exclude private ranges)
    const isPublicIP = (ip) => {
      if (!ip) return false;
      const parts = ip.split('.');
      if (parts.length !== 4) return false;
      const first = parseInt(parts[0]);
      const second = parseInt(parts[1]);
      // Exclude private ranges
      if (first === 10) return false;
      if (first === 172 && second >= 16 && second <= 31) return false;
      if (first === 192 && second === 168) return false;
      if (first === 127) return false;
      return true;
    };

    if (rawEvent.network?.remote_ip && isPublicIP(rawEvent.network.remote_ip)) {
      addIOC(rawEvent.network.remote_ip, 'ip');
    }
    if (rawEvent.src_ip && isPublicIP(rawEvent.src_ip)) addIOC(rawEvent.src_ip, 'ip');
    if (rawEvent.dst_ip && isPublicIP(rawEvent.dst_ip)) addIOC(rawEvent.dst_ip, 'ip');
    if (rawEvent.source_ip && isPublicIP(rawEvent.source_ip)) addIOC(rawEvent.source_ip, 'ip');
    if (rawEvent.dest_ip && isPublicIP(rawEvent.dest_ip)) addIOC(rawEvent.dest_ip, 'ip');

    // Domains
    if (rawEvent.domain) addIOC(rawEvent.domain, 'domain');
    if (rawEvent.network?.domain) addIOC(rawEvent.network.domain, 'domain');
    if (rawEvent.dns?.query) addIOC(rawEvent.dns.query, 'domain');

    // Email-specific fields (phishing reports)
    if (rawEvent.sender_domain) addIOC(rawEvent.sender_domain, 'domain');
    if (rawEvent.original_sender) {
      // Extract domain from email address
      const emailMatch = rawEvent.original_sender.match(/@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/);
      if (emailMatch) addIOC(emailMatch[1], 'domain');
    }
    if (rawEvent.reporter) {
      const reporterMatch = rawEvent.reporter.match(/@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/);
      if (reporterMatch) addIOC(reporterMatch[1], 'domain');
    }

    // Extract URLs and domains from email body
    if (rawEvent.body && typeof rawEvent.body === 'string') {
      // Extract URLs
      const urlRegex = /https?:\/\/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})[^\s<>)}\]"']*/gi;
      const urlMatches = rawEvent.body.match(urlRegex);
      if (urlMatches) {
        // Extract unique domains from URLs
        const seenDomains = new Set();
        urlMatches.forEach(url => {
          try {
            const urlObj = new URL(url);
            const domain = urlObj.hostname;
            if (!seenDomains.has(domain) && domain.includes('.')) {
              seenDomains.add(domain);
              addIOC(domain, 'domain');
            }
          } catch (e) {
            // Try to extract domain with regex if URL parsing fails
            const domainMatch = url.match(/https?:\/\/([a-zA-Z0-9.-]+)/);
            if (domainMatch && !seenDomains.has(domainMatch[1])) {
              seenDomains.add(domainMatch[1]);
              addIOC(domainMatch[1], 'domain');
            }
          }
        });
      }
    }

    // Also check subject for URLs (sometimes phishing URLs are in subject)
    if (rawEvent.subject && typeof rawEvent.subject === 'string') {
      const subjectUrlMatch = rawEvent.subject.match(/https?:\/\/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/gi);
      if (subjectUrlMatch) {
        subjectUrlMatch.forEach(url => {
          try {
            const urlObj = new URL(url);
            addIOC(urlObj.hostname, 'domain');
          } catch (e) { /* URL parse error, skip */ }
        });
      }
    }

    if (iocs.length === 0) {
      setThreatData(null);
      return;
    }

    setLoadingThreatData(true);
    try {
      // Fetch IOC data from Threat Intel APIconst results = [];

      // Query each IOC (limit to first 5 to avoid too many requests)
      for (const ioc of iocs.slice(0, 5)) {
        try {
          // Use the correct threat-intel lookup endpoint based on IOC type
          let endpoint;
          if (ioc.type === 'ip') {
            endpoint = `${API_BASE_URL}/api/v1/threat-intel/lookup/ip/${encodeURIComponent(ioc.value)}`;
          } else if (ioc.type === 'domain') {
            endpoint = `${API_BASE_URL}/api/v1/threat-intel/lookup/domain/${encodeURIComponent(ioc.value)}`;
          } else if (ioc.type === 'hash') {
            endpoint = `${API_BASE_URL}/api/v1/threat-intel/lookup/hash/${encodeURIComponent(ioc.value)}`;
          } else {
            // For URLs and other types, skip for now
            continue;
          }

          const response = await fetch(endpoint, {
          });
          if (response.ok) {
            const data = await response.json();
            // Handle the threat intel API response format
            if (data) {
              // Extract enrichment details from the enrichments array
              const enrichments = data.enrichments || [];

              // Find specific provider data
              const vtData = enrichments.find(e => e.provider === 'virustotal');
              const abuseData = enrichments.find(e => e.provider === 'abuseipdb');
              const ipApiData = enrichments.find(e => e.provider === 'ipapi' || e.provider === 'ip-api');

              // Build enrichment object from provider data
              const enrichment = {
                // From IP geolocation
                country: ipApiData?.raw_data?.country || ipApiData?.raw_data?.countryCode || data.ioc?.tags?.find(t => t.length === 2),
                asn: ipApiData?.raw_data?.as || ipApiData?.raw_data?.asn,
                isp: ipApiData?.raw_data?.isp,
                org: ipApiData?.raw_data?.org,
                // From AbuseIPDB
                abuse_score: abuseData?.raw_data?.abuseConfidenceScore || abuseData?.threat_score,
                total_reports: abuseData?.raw_data?.totalReports,
                // From VirusTotal
                vt_positives: vtData?.raw_data?.malicious || vtData?.raw_data?.positives,
                vt_total: vtData?.raw_data?.total || (vtData?.raw_data?.malicious !== undefined ?
                  (vtData.raw_data.malicious + (vtData.raw_data.suspicious || 0) + (vtData.raw_data.harmless || 0) + (vtData.raw_data.undetected || 0)) : undefined),
                // Categories and tags from all sources
                categories: [...new Set(enrichments.flatMap(e => e.categories || []))],
                tags: [...new Set(enrichments.flatMap(e => e.tags || []))]
              };

              results.push({
                ...ioc,
                found: true,
                verdict: data.verdict || data.ioc?.verdict || null,
                confidence: data.ioc?.confidence || data.score || null,
                score: data.score,
                sources_checked: data.sources_checked || 0,
                sources_flagged: data.sources_flagged || 0,
                enrichment: enrichment,
                first_seen: data.ioc?.first_seen,
                last_seen: data.ioc?.last_seen,
                raw_enrichments: enrichments
              });
            }
          }
        } catch (err) {
        }
      }

      setThreatData(results.length > 0 ? results : null);
    } catch (error) {
      setThreatData(null);
    } finally {
      setLoadingThreatData(false);
    }
  };

  const fetchInvestigation = async () => {
    if (!initialAlert) return;

    try {
      // If investigation_id was passed directly, fetch full investigation details
      if (initialAlert.investigation_id) {const response = await fetch(`${API_BASE_URL}/api/v1/investigations/${initialAlert.investigation_id}`, {
        });
        if (response.ok) {
          const data = await response.json();
          setInvestigation(data);
        } else {
          // Fallback to basic info
          setInvestigation({
            id: initialAlert.investigation_id,
            investigation_id: initialAlert.investigation_id,
            title: initialAlert.title
          });
        }
        return;
      }

      // Try to fetch investigation by alert_id
      const response = await fetch(`${API_BASE_URL}/api/v1/alerts/${initialAlert.alert_id}/investigation`, { headers: getAuthHeaders() });
      if (response.ok) {
        const data = await response.json();
        setInvestigation(data);
      }
    } catch (error) {
    }
  };

  const getSeverityColor = (severity) => {
    const colors = {
      'critical': '#dc2626',
      'high': '#ea580c',
      'medium': '#eab308',
      'low': '#22c55e'
    };
    return colors[severity?.toLowerCase()] || '#6b7280';
  };

  if (!alert) return null;

  return (
    <>
      {/* Overlay */}
      <div 
        style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          background: 'rgba(0, 0, 0, 0.5)',
          zIndex: 999,
          backdropFilter: 'blur(2px)',
          animation: 'fadeIn 0.2s ease'
        }}
        onClick={onClose}
      />

      {/* Drawer */}
      <div style={{
        position: 'fixed',
        top: 0,
        right: 0,
        bottom: 0,
        width: '700px',
        maxWidth: '95vw',
        background: 'var(--bg-primary)',
        boxShadow: '-4px 0 20px rgba(0, 0, 0, 0.5)',
        zIndex: 1000,
        overflow: 'hidden',
        animation: 'slideInRight 0.25s ease',
        display: 'flex',
        flexDirection: 'column'
      }}>
        {/* Header */}
        <div style={{
          padding: '0.75rem 1rem',
          borderBottom: '1px solid var(--bg-tertiary)',
          position: 'sticky',
          top: 0,
          background: 'var(--bg-primary)',
          zIndex: 10,
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <h2 style={{ fontSize: '0.95rem', fontWeight: '600', margin: 0 }}>Event Details</h2>
            <code
              onClick={() => {
                navigator.clipboard.writeText(alert.alert_id);
                // Show brief feedback
                const el = document.createElement('div');
                el.textContent = 'Copied!';
                el.style.cssText = 'position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);background:#22c55e;color:white;padding:0.5rem 1rem;border-radius:4px;z-index:9999;font-size:0.8rem;';
                document.body.appendChild(el);
                setTimeout(() => el.remove(), 1000);
              }}
              style={{
                background: 'rgba(60, 179, 113, 0.1)',
                padding: '0.2rem 0.5rem',
                borderRadius: '4px',
                fontSize: '0.7rem',
                color: '#a0e9ff',
                cursor: 'pointer',
                transition: 'background 0.2s'
              }}
              title={`Click to copy full ID: ${alert.alert_id}`}
            >
              {alert.display_id || alert.alert_id?.substring(0, 8)}
            </code>
          </div>
          <button
            onClick={onClose}
            style={{
              background: 'none',
              border: 'none',
              color: 'var(--text-secondary)',
              fontSize: '1.1rem',
              cursor: 'pointer',
              padding: '0.25rem',
              lineHeight: 1
            }}
          >
            ✕
          </button>
        </div>

        {/* Content - Scrollable area */}
        <div style={{ flex: 1, padding: '0.75rem 1rem', paddingBottom: '0.75rem', overflowY: 'auto' }}>
          {/* At-a-Glance Verdict Bar */}
          {(() => {
            // Determine overall verdict from AI analysis, threat data, AND enrichment results
            const aiVerdict = alert.ai_verdict;
            const aiConfidence = alert.ai_confidence;
            const hasMalicious = threatData?.some(t => t.verdict === 'malicious');
            const hasSuspicious = threatData?.some(t => t.verdict === 'suspicious');
            const allBenign = threatData?.length > 0 && threatData.every(t => t.verdict === 'benign' || t.verdict === 'clean');

            // Check enrichment results - this takes precedence for risk calculation
            const enrichment = alert.raw_event?._extracted?.enrichment;
            const enrichmentSummary = enrichment?.summary || {};
            const enrichedMalicious = enrichmentSummary.malicious > 0;
            const enrichedSuspicious = enrichmentSummary.suspicious > 0;
            const enrichedAllClean = enrichment?.status === 'enriched' &&
                                     enrichmentSummary.total_enriched > 0 &&
                                     enrichmentSummary.malicious === 0 &&
                                     enrichmentSummary.suspicious === 0;

            let risk = 'Unknown';
            let riskColor = '#64748b';
            let riskBg = 'rgba(100, 116, 139, 0.15)';

            // Priority: Enrichment results > AI verdict > Threat data
            // If enrichment found malicious IOCs, it's definitely high risk
            if (enrichedMalicious || hasMalicious) {
              risk = 'High';
              riskColor = '#dc2626';
              riskBg = 'rgba(220, 38, 38, 0.12)';
            } else if (enrichedSuspicious || hasSuspicious) {
              risk = 'Medium';
              riskColor = '#ea580c';
              riskBg = 'rgba(234, 88, 12, 0.12)';
            } else if (enrichedAllClean) {
              // Enrichment shows all IOCs are clean - this overrides AI's behavioral concerns
              risk = 'Low';
              riskColor = '#22c55e';
              riskBg = 'rgba(34, 197, 94, 0.12)';
            } else if (aiVerdict === 'malicious' || aiVerdict === 'true_positive') {
              // Fall back to AI verdict if no clear enrichment signal
              risk = 'High';
              riskColor = '#dc2626';
              riskBg = 'rgba(220, 38, 38, 0.12)';
            } else if (aiVerdict === 'suspicious') {
              risk = 'Medium';
              riskColor = '#ea580c';
              riskBg = 'rgba(234, 88, 12, 0.12)';
            } else if (aiVerdict === 'benign' || aiVerdict === 'false_positive' || allBenign) {
              risk = 'Low';
              riskColor = '#22c55e';
              riskBg = 'rgba(34, 197, 94, 0.12)';
            }

            const confidence = aiConfidence || (threatData?.length > 0 ? Math.round(threatData.reduce((acc, t) => acc + (t.confidence || 50), 0) / threatData.length) : null);

            return (
              <div style={{
                display: 'flex',
                alignItems: 'center',
                gap: '0.75rem',
                padding: '0.5rem 0.75rem',
                background: riskBg,
                borderRadius: '6px',
                marginBottom: '0.75rem',
                border: `1px solid ${riskColor}30`
              }}>
                {/* Risk Level */}
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                  <span style={{ fontSize: '0.65rem', color: 'var(--text-muted)', fontWeight: '600' }}>RISK:</span>
                  <span style={{
                    color: riskColor,
                    fontWeight: '700',
                    fontSize: '0.8rem',
                    textTransform: 'uppercase'
                  }}>{risk}</span>
                </div>

                {/* Confidence */}
                {confidence && (
                  <>
                    <div style={{ width: '1px', height: '16px', background: 'var(--bg-tertiary)' }} />
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                      <span style={{ fontSize: '0.65rem', color: 'var(--text-muted)', fontWeight: '600' }}>CONF:</span>
                      <span style={{ color: 'var(--text-secondary)', fontWeight: '600', fontSize: '0.8rem' }}>{formatConfidence(confidence)}</span>
                    </div>
                  </>
                )}

              </div>
            );
          })()}

          {/* Title + Why This Alert */}
          <div style={{ marginBottom: '0.75rem' }}>
            <div style={{ fontSize: '0.95rem', fontWeight: '600', color: 'var(--text-primary)', lineHeight: 1.4 }}>
              {alert.title}
            </div>
            {/* Why this alert exists - one liner */}
            <div style={{
              fontSize: '0.75rem',
              color: 'var(--text-muted)',
              marginTop: '0.35rem',
              fontStyle: 'italic'
            }}>
              {(() => {
                const source = alert.source || 'Unknown source';
                const rawEvent = alert.raw_event || {};

                // Try to build a meaningful "why" from context
                if (source.includes('phishing') || alert.title?.toLowerCase().includes('phishing')) {
                  const sender = rawEvent.original_sender || rawEvent.sender_domain || 'unknown sender';
                  return `Triggered because: Phishing report received from ${sender}`;
                } else if (alert.title?.toLowerCase().includes('failed login')) {
                  return `Triggered because: Multiple authentication failures detected`;
                } else if (alert.title?.toLowerCase().includes('malware')) {
                  return `Triggered because: Malicious file or behavior detected`;
                } else if (alert.title?.toLowerCase().includes('network')) {
                  return `Triggered because: Suspicious network activity observed`;
                } else if (rawEvent.reporter) {
                  return `Triggered because: User report from ${rawEvent.reporter}`;
                } else {
                  return `Triggered by: ${source}`;
                }
              })()}
            </div>
          </div>

          {/* Metadata Row */}
          <div style={{
            display: 'flex',
            gap: '1rem',
            marginBottom: '0.75rem',
            padding: '0.5rem 0.75rem',
            background: 'var(--bg-secondary)',
            borderRadius: '6px',
            fontSize: '0.75rem'
          }}>
            <div>
              <span style={{ color: 'var(--text-muted)' }}>Created: </span>
              <span style={{ color: 'var(--text-secondary)' }}>
                {formatInTimezone(alert.created_at, preferences.timezone || 'local', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })}
              </span>
            </div>
            <div>
              <span style={{ color: 'var(--text-muted)' }}>Updated: </span>
              <span style={{ color: 'var(--text-secondary)' }}>
                {formatInTimezone(alert.updated_at || alert.created_at, preferences.timezone || 'local', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })}
              </span>
            </div>
            {investigation && (
              <div>
                <span style={{ color: 'var(--text-muted)' }}>Investigation: </span>
                <Link to={`/investigation/${investigation.investigation_id}`} style={{ color: '#3b82f6', textDecoration: 'none' }}>
                  View
                </Link>
              </div>
            )}
          </div>

          {/* Investigation Status Controls - Only show if investigation exists */}
          {investigation && (
            <div style={{
              display: 'grid',
              gridTemplateColumns: '1fr 1fr',
              gap: '0.75rem',
              marginBottom: '0.75rem',
              padding: '0.5rem 0.75rem',
              background: 'linear-gradient(135deg, rgba(60, 179, 113, 0.08), rgba(118, 75, 162, 0.08))',
              borderRadius: '6px',
              border: '1px solid rgba(60, 179, 113, 0.2)'
            }}>
              {/* State Dropdown */}
              <div>
                <label style={{ display: 'block', fontSize: '0.65rem', color: 'var(--text-muted)', marginBottom: '0.25rem', fontWeight: '600', textTransform: 'uppercase' }}>
                  Status
                </label>
                <select
                  value={investigation.state || 'NEW'}
                  onChange={(e) => updateInvestigation({ state: e.target.value })}
                  disabled={updatingInvestigation}
                  style={{
                    width: '100%',
                    padding: '0.35rem 0.5rem',
                    background: 'var(--bg-secondary)',
                    border: '1px solid var(--bg-tertiary)',
                    borderRadius: '4px',
                    color: 'var(--text-primary)',
                    fontSize: '0.75rem',
                    fontWeight: '600',
                    cursor: updatingInvestigation ? 'wait' : 'pointer'
                  }}
                >
                  <option value="NEW">New</option>
                  <option value="IN_PROGRESS">In Progress</option>
                  <option value="ESCALATED">Escalated</option>
                  <option value="PENDING">Pending</option>
                  <option value="RESOLVED">Resolved</option>
                  <option value="CLOSED">Closed</option>
                </select>
              </div>

              {/* Disposition Dropdown */}
              <div>
                <label style={{ display: 'block', fontSize: '0.65rem', color: 'var(--text-muted)', marginBottom: '0.25rem', fontWeight: '600', textTransform: 'uppercase' }}>
                  Disposition
                </label>
                <select
                  value={investigation.disposition || ''}
                  onChange={(e) => updateInvestigation({ disposition: e.target.value })}
                  disabled={updatingInvestigation}
                  style={{
                    width: '100%',
                    padding: '0.35rem 0.5rem',
                    background: 'var(--bg-secondary)',
                    border: '1px solid var(--bg-tertiary)',
                    borderRadius: '4px',
                    color: investigation.disposition ? (
                      ['TRUE_POSITIVE', 'MALICIOUS', 'CONFIRMED'].includes(investigation.disposition) ? '#dc2626' :
                      ['FALSE_POSITIVE', 'BENIGN'].includes(investigation.disposition) ? '#22c55e' :
                      'var(--text-primary)'
                    ) : 'var(--text-muted)',
                    fontSize: '0.75rem',
                    fontWeight: '600',
                    cursor: updatingInvestigation ? 'wait' : 'pointer'
                  }}
                >
                  <option value="">-- Select --</option>
                  <option value="TRUE_POSITIVE">True Positive</option>
                  <option value="FALSE_POSITIVE">False Positive</option>
                  <option value="BENIGN">Benign</option>
                  <option value="MALICIOUS">Malicious</option>
                  <option value="SUSPICIOUS">Suspicious</option>
                  <option value="INCONCLUSIVE">Inconclusive</option>
                </select>
              </div>
            </div>
          )}

          {/* Tags & Severity Row */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem', marginBottom: '0.75rem' }}>
            {/* Tags - Based on enrichment verdicts */}
            <div>
              <label style={{ display: 'block', fontSize: '0.7rem', color: 'var(--text-muted)', marginBottom: '0.25rem', fontWeight: '600' }}>
                TAGS
              </label>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.35rem' }}>
                {/* Show verdict tags based on threat data */}
                {threatData && threatData.some(t => t.verdict === 'malicious') && (
                  <span style={{
                    display: 'inline-block',
                    background: 'rgba(220, 38, 38, 0.15)',
                    border: '1px solid rgba(220, 38, 38, 0.4)',
                    color: '#dc2626',
                    fontSize: '0.7rem',
                    padding: '0.2rem 0.5rem',
                    textTransform: 'uppercase',
                    fontWeight: '600',
                    borderRadius: '4px'
                  }}>
                    Malicious
                  </span>
                )}
                {threatData && threatData.some(t => t.verdict === 'suspicious') && !threatData.some(t => t.verdict === 'malicious') && (
                  <span style={{
                    display: 'inline-block',
                    background: 'rgba(234, 88, 12, 0.15)',
                    border: '1px solid rgba(234, 88, 12, 0.4)',
                    color: '#ea580c',
                    fontSize: '0.7rem',
                    padding: '0.2rem 0.5rem',
                    textTransform: 'uppercase',
                    fontWeight: '600',
                    borderRadius: '4px'
                  }}>
                    Suspicious
                  </span>
                )}
                {threatData && threatData.length > 0 && threatData.every(t => t.verdict === 'benign' || t.verdict === 'clean') && (
                  <span style={{
                    display: 'inline-block',
                    background: 'rgba(34, 197, 94, 0.15)',
                    border: '1px solid rgba(34, 197, 94, 0.4)',
                    color: '#22c55e',
                    fontSize: '0.7rem',
                    padding: '0.2rem 0.5rem',
                    textTransform: 'uppercase',
                    fontWeight: '600',
                    borderRadius: '4px'
                  }}>
                    Benign
                  </span>
                )}
                {/* Show loading state */}
                {loadingThreatData && (
                  <span style={{
                    display: 'inline-block',
                    background: 'rgba(100, 116, 139, 0.15)',
                    border: '1px solid rgba(100, 116, 139, 0.4)',
                    color: '#64748b',
                    fontSize: '0.7rem',
                    padding: '0.2rem 0.5rem',
                    fontWeight: '600',
                    borderRadius: '4px'
                  }}>
                    Checking...
                  </span>
                )}
                {/* Show appropriate badge based on IOC status */}
                {!loadingThreatData && threatData === null && (() => {
                  const rawEvent = alert.raw_event || {};
                  const extracted = rawEvent._extracted?.iocs || {};
                  const decodedIOCs = rawEvent._extracted?.decoded_iocs || rawEvent._extracted?.ai_triage?.decoded_iocs || {};
                  // Check for private/internal IPs
                  const hasPrivateIPs = extracted.private_ips?.length > 0;
                  // Check for decoded/hidden IOCs from AI analysis
                  const hasDecodedIOCs =
                    decodedIOCs.ips?.length > 0 ||
                    decodedIOCs.domains?.length > 0 ||
                    decodedIOCs.urls?.length > 0;
                  // Check all public IOC sources
                  const hasPublicIOCs =
                    extracted.ips?.length > 0 ||
                    extracted.domains?.length > 0 ||
                    extracted.hashes?.length > 0 ||
                    extracted.urls?.length > 0 ||
                    hasDecodedIOCs ||
                    rawEvent.file?.hashes?.md5 ||
                    rawEvent.file?.hashes?.sha256 ||
                    rawEvent.md5 || rawEvent.sha256 || rawEvent.hash ||
                    rawEvent.network?.remote_ip ||
                    rawEvent.domain;

                  // If only private IPs, show "Internal" badge
                  if (hasPrivateIPs && !hasPublicIOCs) {
                    return (
                      <span style={{
                        display: 'inline-block',
                        background: 'rgba(59, 130, 246, 0.15)',
                        border: '1px solid rgba(59, 130, 246, 0.4)',
                        color: '#3b82f6',
                        fontSize: '0.7rem',
                        padding: '0.2rem 0.5rem',
                        textTransform: 'uppercase',
                        fontWeight: '600',
                        borderRadius: '4px'
                      }} title={`${extracted.private_ips.length} internal IP(s) detected`}>
                        Internal
                      </span>
                    );
                  }

                  // No IOCs at all
                  if (!hasPublicIOCs && !hasPrivateIPs) {
                    return (
                      <span style={{
                        display: 'inline-block',
                        background: 'rgba(100, 116, 139, 0.15)',
                        border: '1px solid rgba(100, 116, 139, 0.4)',
                        color: '#64748b',
                        fontSize: '0.7rem',
                        padding: '0.2rem 0.5rem',
                        textTransform: 'uppercase',
                        fontWeight: '600',
                        borderRadius: '4px'
                      }}>
                        No IOCs
                      </span>
                    );
                  }

                  return null; // Has public IOCs - will show pending or threat data
                })()}
                {/* Show "Pending Enrichment" if public IOCs exist but no threat data yet */}
                {!loadingThreatData && threatData === null && (() => {
                  const rawEvent = alert.raw_event || {};
                  const extracted = rawEvent._extracted?.iocs || {};
                  // Check for PUBLIC IOCs only (not private IPs)
                  const hasPublicIOCs =
                    extracted.ips?.length > 0 ||
                    extracted.domains?.length > 0 ||
                    extracted.hashes?.length > 0 ||
                    extracted.urls?.length > 0 ||
                    rawEvent.file?.hashes?.md5 ||
                    rawEvent.file?.hashes?.sha256 ||
                    rawEvent.md5 || rawEvent.sha256 || rawEvent.hash ||
                    rawEvent.network?.remote_ip ||
                    rawEvent.domain;
                  return hasPublicIOCs;
                })() && (
                  <span style={{
                    display: 'inline-block',
                    background: 'rgba(234, 179, 8, 0.15)',
                    border: '1px solid rgba(234, 179, 8, 0.4)',
                    color: '#eab308',
                    fontSize: '0.7rem',
                    padding: '0.2rem 0.5rem',
                    textTransform: 'uppercase',
                    fontWeight: '600',
                    borderRadius: '4px'
                  }}>
                    Pending Enrichment
                  </span>
                )}
                {/* Show alert source as a tag with label */}
                {alert.source && (
                  <span style={{
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '0.25rem',
                    background: 'rgba(60, 179, 113, 0.15)',
                    border: '1px solid rgba(60, 179, 113, 0.4)',
                    color: '#3CB371',
                    fontSize: '0.7rem',
                    padding: '0.2rem 0.5rem',
                    fontWeight: '600',
                    borderRadius: '4px'
                  }}>
                    <span style={{ opacity: 0.7, fontSize: '0.65rem' }}>SRC:</span>
                    {alert.source}
                  </span>
                )}
              </div>
            </div>

            {/* Severity */}
            <div>
              <label style={{ display: 'block', fontSize: '0.7rem', color: 'var(--text-muted)', marginBottom: '0.25rem', fontWeight: '600' }}>
                SEVERITY
              </label>
              {can('update_alert_status') ? (
                <select
                  value={newSeverity}
                  onChange={async (e) => {
                    const value = e.target.value;
                    setNewSeverity(value);
                    setSaving(true);
                    try {
                      const response = await fetch(`${API_BASE_URL}/api/v1/alerts/${alert.alert_id}/severity`, {
                        method: 'PATCH',
                        headers: getAuthHeaders(),
                        body: JSON.stringify({ severity: value })
                      });
                      if (response.ok && onRefresh) onRefresh();
                    } catch (error) {
                      setNewSeverity(alert.severity);
                    } finally {
                      setSaving(false);
                    }
                  }}
                  disabled={saving}
                  style={{
                    width: '100%',
                    padding: '0.4rem 0.5rem',
                    background: `${getSeverityColor(newSeverity)}15`,
                    border: `1px solid ${getSeverityColor(newSeverity)}`,
                    borderRadius: '4px',
                    color: getSeverityColor(newSeverity),
                    fontSize: '0.8rem',
                    fontWeight: '600',
                    textTransform: 'uppercase',
                    cursor: 'pointer'
                  }}
                >
                  <option value="low">Low</option>
                  <option value="medium">Medium</option>
                  <option value="high">High</option>
                  <option value="critical">Critical</option>
                </select>
              ) : (
                <span style={{
                  display: 'inline-block',
                  background: getSeverityColor(alert.severity),
                  color: 'white',
                  fontSize: '0.75rem',
                  padding: '0.3rem 0.5rem',
                  textTransform: 'uppercase',
                  fontWeight: '600',
                  borderRadius: '4px'
                }}>
                  {alert.severity || 'medium'}
                </span>
              )}
            </div>
          </div>

          {/* Description */}
          {alert.description && (
            <div style={{ marginBottom: '0.75rem' }}>
              <label style={{ display: 'block', fontSize: '0.7rem', color: 'var(--text-muted)', marginBottom: '0.25rem', fontWeight: '600' }}>
                DESCRIPTION
              </label>
              <div style={{
                padding: '0.5rem 0.75rem',
                background: 'var(--bg-secondary)',
                borderRadius: '6px',
                fontSize: '0.8rem',
                lineHeight: 1.5,
                color: 'var(--text-secondary)'
              }}>
                {alert.description}
              </div>
            </div>
          )}

          {/* AI Analysis - Always show section, with verdict/summary or placeholder */}
          <div style={{ marginBottom: '0.75rem' }}>
            <label style={{ display: 'block', fontSize: '0.7rem', color: 'var(--text-muted)', marginBottom: '0.25rem', fontWeight: '600' }}>
              AI ANALYSIS
            </label>
            <div style={{
              padding: '0.75rem',
              background: alert.ai_summary || alert.ai_verdict
                ? 'linear-gradient(135deg, rgba(60, 179, 113, 0.1), rgba(118, 75, 162, 0.1))'
                : 'var(--bg-secondary)',
              borderRadius: '8px',
              border: alert.ai_summary || alert.ai_verdict
                ? '1px solid rgba(60, 179, 113, 0.2)'
                : '1px solid var(--bg-tertiary)',
              fontSize: '0.8rem',
              lineHeight: 1.6,
              color: 'var(--text-secondary)'
            }}>
              {alert.ai_summary ? (
                <div className="markdown-content">
                  {/* Format threaded AI analysis comments with visual distinction */}
                  {/* Support both "--- Tier X Agent [timestamp] ---" format AND "Tier X Agent timestamp content" format */}
                  {(alert.ai_summary.includes('---') && alert.ai_summary.includes('Tier')) ||
                   /^Tier\s*\d\s*Agent\s+\d{4}-\d{2}-\d{2}/i.test(alert.ai_summary.trim()) ? (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                      {/* Split on --- Tier X patterns, OR parse standalone Tier X Agent timestamp format */}
                      {(() => {
                        const text = alert.ai_summary;
                        // Check if it's the simple format without --- separators
                        // e.g., "Tier 1 Agent 2026-01-05 01:32 UTC Malicious file hashes..."
                        const simpleFormatMatch = text.match(/^(Tier\s*\d\s*Agent)\s+(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}\s*UTC?)\s+([\s\S]*)$/i);
                        if (simpleFormatMatch && !text.includes('---')) {
                          // Simple format - wrap it in a styled box
                          return [{
                            source: simpleFormatMatch[1].trim(),
                            timestamp: simpleFormatMatch[2].trim(),
                            content: simpleFormatMatch[3].trim()
                          }];
                        }
                        // Standard format with --- separators
                        return text.split(/\s*---\s*(?=Tier\s*\d|T[123]\s*Agent)/i).filter(s => s.trim()).map(section => {
                          const headerMatch = section.match(/^(Tier\s*\d\s*Agent|T[123]\s*Agent)\s*(?:\[([^\]]+)\])?\s*-*\s*([\s\S]*)/i);
                          if (!headerMatch) {
                            return { raw: section.trim() };
                          }
                          return {
                            source: headerMatch[1].trim(),
                            timestamp: headerMatch[2] || '',
                            content: headerMatch[3] || ''
                          };
                        });
                      })().map((item, idx) => {
                        // Handle raw text without header
                        if (item.raw) {
                          return item.raw ? (
                            <div key={idx} style={{
                              background: 'rgba(100, 116, 139, 0.08)',
                              borderLeft: '3px solid #64748b',
                              padding: '0.5rem 0.75rem',
                              borderRadius: '4px'
                            }}>
                              <ReactMarkdown remarkPlugins={[remarkGfm]}>{item.raw}</ReactMarkdown>
                            </div>
                          ) : null;
                        }
                        const { source, timestamp, content } = item;

                        // Determine colors based on source
                        let colors = { bg: 'rgba(100, 116, 139, 0.1)', border: '#64748b' };
                        const sourceLower = source.toLowerCase();
                        if (sourceLower.includes('riggs') || sourceLower.includes('tier 1') || sourceLower.includes('tier1') || sourceLower.includes('t1')) {
                          colors = { bg: 'rgba(96, 165, 250, 0.1)', border: '#60a5fa' };
                        } else if (sourceLower.includes('tier 2') || sourceLower.includes('tier2') || sourceLower.includes('t2')) {
                          colors = { bg: 'rgba(167, 139, 250, 0.1)', border: '#a78bfa' };
                        } else if (sourceLower.includes('tier 3') || sourceLower.includes('tier3') || sourceLower.includes('t3')) {
                          colors = { bg: 'rgba(244, 114, 182, 0.1)', border: '#f472b6' };
                        } else if (sourceLower.includes('mock') || sourceLower.includes('initial')) {
                          colors = { bg: 'rgba(156, 163, 175, 0.1)', border: '#9ca3af' };
                        }

                        return (
                          <div key={idx} style={{
                            background: colors.bg,
                            borderLeft: `3px solid ${colors.border}`,
                            padding: '0.5rem 0.75rem',
                            borderRadius: '4px'
                          }}>
                            <div style={{
                              display: 'flex',
                              justifyContent: 'space-between',
                              alignItems: 'center',
                              marginBottom: '0.25rem'
                            }}>
                              <span style={{
                                fontSize: '0.65rem',
                                color: colors.border,
                                fontWeight: 600,
                                textTransform: 'uppercase'
                              }}>
                                {source}
                              </span>
                              {timestamp && (
                                <span style={{
                                  fontSize: '0.6rem',
                                  color: 'var(--text-muted)',
                                  fontStyle: 'italic'
                                }}>
                                  {timestamp}
                                </span>
                              )}
                            </div>
                            <ReactMarkdown remarkPlugins={[remarkGfm]}>
                              {content.trim()}
                            </ReactMarkdown>
                          </div>
                        );
                      })}
                    </div>
                  ) : alert.ai_summary.includes('[T1]') || alert.ai_summary.includes('[T2]') || alert.ai_summary.includes('[T3]') ? (
                    /* Legacy format support */
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                      {alert.ai_summary.split(/\n\n(?=\[T[123]\])/).map((section, idx) => {
                        const tierMatch = section.match(/^\[T([123])\]\s*/);
                        const tier = tierMatch ? parseInt(tierMatch[1]) : null;
                        const content = tierMatch ? section.replace(/^\[T[123]\]\s*/, '') : section;
                        const tierColors = {
                          1: { bg: 'rgba(96, 165, 250, 0.1)', border: '#60a5fa', label: 'Riggs Triage' },
                          2: { bg: 'rgba(167, 139, 250, 0.1)', border: '#a78bfa', label: 'Riggs Analysis' },
                          3: { bg: 'rgba(244, 114, 182, 0.1)', border: '#f472b6', label: 'Riggs Deep Analysis' }
                        };
                        const colors = tier ? tierColors[tier] : null;

                        return (
                          <div key={idx} style={{
                            background: colors ? colors.bg : 'transparent',
                            borderLeft: colors ? `3px solid ${colors.border}` : 'none',
                            padding: colors ? '0.5rem 0.75rem' : '0',
                            borderRadius: '4px'
                          }}>
                            {colors && (
                              <div style={{
                                fontSize: '0.65rem',
                                color: colors.border,
                                fontWeight: 600,
                                marginBottom: '0.25rem',
                                textTransform: 'uppercase'
                              }}>
                                {colors.label}
                              </div>
                            )}
                            <ReactMarkdown remarkPlugins={[remarkGfm]}>
                              {content}
                            </ReactMarkdown>
                          </div>
                        );
                      })}
                    </div>
                  ) : (
                    /* Format plain text AI summary with better structure */
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                      {(() => {
                        // Try to parse common AI response patterns and format them nicely
                        let text = alert.ai_summary;

                        // Check if it looks like structured output (has bullet points, numbered lists, or sections)
                        const hasStructure = /^[\s]*[-•*\d+.]/m.test(text) || /\*\*[^*]+\*\*/m.test(text);

                        if (hasStructure) {
                          // Already has some structure, use markdown directly
                          return (
                            <ReactMarkdown remarkPlugins={[remarkGfm]}>
                              {text}
                            </ReactMarkdown>
                          );
                        }

                        // For long unformatted text, try to break it into sections
                        // Split on common section indicators
                        const sectionPatterns = [
                          /(?:^|\n)(Summary|Analysis|Conclusion|Recommendation|Verdict|Risk|Finding|Assessment|Overview|Details|Observations?):?\s*/gi,
                          /(?:^|\n)(Key Points?|Key Findings?|Next Steps?|Action Items?):?\s*/gi
                        ];

                        let foundSections = false;

                        for (const pattern of sectionPatterns) {
                          if (pattern.test(text)) {
                            foundSections = true;
                            break;
                          }
                        }

                        if (foundSections) {
                          // Has section headers, format them
                          const parts = text.split(/\n*(?=(?:Summary|Analysis|Conclusion|Recommendation|Verdict|Risk|Finding|Assessment|Overview|Details|Observations?|Key Points?|Key Findings?|Next Steps?|Action Items?):?\s*)/i);
                          return parts.map((part, idx) => {
                            const headerMatch = part.match(/^(Summary|Analysis|Conclusion|Recommendation|Verdict|Risk|Finding|Assessment|Overview|Details|Observations?|Key Points?|Key Findings?|Next Steps?|Action Items?):?\s*/i);
                            if (headerMatch) {
                              const header = headerMatch[1];
                              const content = part.slice(headerMatch[0].length).trim();
                              return (
                                <div key={idx} style={{
                                  background: 'rgba(100, 116, 139, 0.08)',
                                  borderLeft: '3px solid #3CB371',
                                  padding: '0.5rem 0.75rem',
                                  borderRadius: '4px'
                                }}>
                                  <div style={{
                                    fontSize: '0.65rem',
                                    color: '#3CB371',
                                    fontWeight: 600,
                                    marginBottom: '0.25rem',
                                    textTransform: 'uppercase'
                                  }}>
                                    {header}
                                  </div>
                                  <div style={{ fontSize: '0.8rem', lineHeight: 1.5 }}>
                                    {content}
                                  </div>
                                </div>
                              );
                            }
                            return part.trim() ? (
                              <div key={idx} style={{ fontSize: '0.8rem', lineHeight: 1.5 }}>
                                {part.trim()}
                              </div>
                            ) : null;
                          });
                        }

                        // No section headers found - split by double newlines or long sentences
                        const paragraphs = text.split(/\n\n+/).filter(p => p.trim());

                        if (paragraphs.length > 1) {
                          // Multiple paragraphs
                          return paragraphs.map((para, idx) => (
                            <div key={idx} style={{
                              fontSize: '0.8rem',
                              lineHeight: 1.6,
                              paddingBottom: idx < paragraphs.length - 1 ? '0.5rem' : 0,
                              borderBottom: idx < paragraphs.length - 1 ? '1px solid rgba(100, 116, 139, 0.15)' : 'none'
                            }}>
                              {para.trim()}
                            </div>
                          ));
                        }

                        // Single block of text - try to break on sentence boundaries for readability
                        const sentences = text.match(/[^.!?]+[.!?]+/g) || [text];
                        if (sentences.length > 3) {
                          // Group sentences into logical chunks (2-3 sentences each)
                          const chunks = [];
                          for (let i = 0; i < sentences.length; i += 2) {
                            chunks.push(sentences.slice(i, i + 2).join(' ').trim());
                          }
                          return chunks.map((chunk, idx) => (
                            <div key={idx} style={{
                              fontSize: '0.8rem',
                              lineHeight: 1.6,
                              paddingBottom: idx < chunks.length - 1 ? '0.5rem' : 0
                            }}>
                              {chunk}
                            </div>
                          ));
                        }

                        // Fallback - just render as-is with proper styling
                        return (
                          <div style={{ fontSize: '0.8rem', lineHeight: 1.6 }}>
                            {text}
                          </div>
                        );
                      })()}
                    </div>
                  )}
                </div>
              ) : alert.ai_verdict ? (
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <span style={{
                    padding: '0.2rem 0.5rem',
                    borderRadius: '4px',
                    fontSize: '0.7rem',
                    fontWeight: '600',
                    textTransform: 'uppercase',
                    background: alert.ai_verdict === 'malicious' ? 'rgba(220, 38, 38, 0.15)' :
                               alert.ai_verdict === 'suspicious' ? 'rgba(234, 88, 12, 0.15)' :
                               alert.ai_verdict === 'benign' ? 'rgba(34, 197, 94, 0.15)' :
                               'rgba(100, 116, 139, 0.15)',
                    color: alert.ai_verdict === 'malicious' ? '#dc2626' :
                          alert.ai_verdict === 'suspicious' ? '#ea580c' :
                          alert.ai_verdict === 'benign' ? '#22c55e' :
                          '#64748b'
                  }}>
                    {alert.ai_verdict}
                  </span>
                  {alert.ai_confidence && (
                    <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>
                      ({Math.round(alert.ai_confidence * 100)}% confidence)
                    </span>
                  )}
                </div>
              ) : (
                <div style={{ color: 'var(--text-muted)', fontStyle: 'italic', fontSize: '0.75rem' }}>
                  Not yet analyzed by AI agent
                </div>
              )}
            </div>
          </div>

          {/* Indicators of Compromise - Extracted IOCs */}
          {alert.raw_event?._extracted?.iocs && Object.values(alert.raw_event._extracted.iocs).some(arr => arr && arr.length > 0) && (
            <div style={{ marginBottom: '1rem' }}>
              <label style={{ display: 'block', fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '0.75rem', fontWeight: '600' }}>
                INDICATORS OF COMPROMISE
              </label>
              <div style={{ display: 'grid', gap: '0.75rem' }}>
                {alert.raw_event._extracted.iocs.ips?.length > 0 && (
                  <div style={{
                    padding: '0.75rem',
                    background: 'rgba(59, 130, 246, 0.1)',
                    borderRadius: '6px',
                    border: '1px solid rgba(59, 130, 246, 0.2)'
                  }}>
                    <div style={{ fontSize: '0.688rem', color: '#3b82f6', fontWeight: '700', marginBottom: '0.5rem', textTransform: 'uppercase' }}>
                      IP Addresses ({alert.raw_event._extracted.iocs.ips.length})
                    </div>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
                      {alert.raw_event._extracted.iocs.ips.slice(0, 10).map((ip, i) => (
                        <code key={i} style={{
                          padding: '0.25rem 0.5rem',
                          background: 'rgba(59, 130, 246, 0.15)',
                          border: '1px solid rgba(59, 130, 246, 0.3)',
                          borderRadius: '4px',
                          fontSize: '0.75rem',
                          color: '#60a5fa'
                        }}>
                          {ip}
                        </code>
                      ))}
                      {alert.raw_event._extracted.iocs.ips.length > 10 && (
                        <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', alignSelf: 'center' }}>
                          +{alert.raw_event._extracted.iocs.ips.length - 10} more
                        </span>
                      )}
                    </div>
                  </div>
                )}
                {alert.raw_event._extracted.iocs.domains?.length > 0 && (
                  <div style={{
                    padding: '0.75rem',
                    background: 'rgba(168, 85, 247, 0.1)',
                    borderRadius: '6px',
                    border: '1px solid rgba(168, 85, 247, 0.2)'
                  }}>
                    <div style={{ fontSize: '0.688rem', color: '#a855f7', fontWeight: '700', marginBottom: '0.5rem', textTransform: 'uppercase' }}>
                      Domains ({alert.raw_event._extracted.iocs.domains.length})
                    </div>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
                      {alert.raw_event._extracted.iocs.domains.slice(0, 5).map((domain, i) => (
                        <code key={i} style={{
                          padding: '0.25rem 0.5rem',
                          background: 'rgba(168, 85, 247, 0.15)',
                          border: '1px solid rgba(168, 85, 247, 0.3)',
                          borderRadius: '4px',
                          fontSize: '0.75rem',
                          color: '#c084fc'
                        }}>
                          {domain}
                        </code>
                      ))}
                      {alert.raw_event._extracted.iocs.domains.length > 5 && (
                        <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', alignSelf: 'center' }}>
                          +{alert.raw_event._extracted.iocs.domains.length - 5} more
                        </span>
                      )}
                    </div>
                  </div>
                )}
                {alert.raw_event._extracted.iocs.urls?.length > 0 && (
                  <div style={{
                    padding: '0.75rem',
                    background: 'rgba(236, 72, 153, 0.1)',
                    borderRadius: '6px',
                    border: '1px solid rgba(236, 72, 153, 0.2)'
                  }}>
                    <div style={{ fontSize: '0.688rem', color: '#ec4899', fontWeight: '700', marginBottom: '0.5rem', textTransform: 'uppercase' }}>
                      URLs ({alert.raw_event._extracted.iocs.urls.length})
                    </div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                      {alert.raw_event._extracted.iocs.urls.slice(0, 3).map((url, i) => (
                        <code key={i} style={{
                          padding: '0.25rem 0.5rem',
                          background: 'rgba(236, 72, 153, 0.15)',
                          border: '1px solid rgba(236, 72, 153, 0.3)',
                          borderRadius: '4px',
                          fontSize: '0.7rem',
                          color: '#f472b6',
                          wordBreak: 'break-all'
                        }}>
                          {url}
                        </code>
                      ))}
                      {alert.raw_event._extracted.iocs.urls.length > 3 && (
                        <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                          +{alert.raw_event._extracted.iocs.urls.length - 3} more
                        </span>
                      )}
                    </div>
                  </div>
                )}
                {alert.raw_event._extracted.iocs.hashes?.length > 0 && (
                  <div style={{
                    padding: '0.75rem',
                    background: 'rgba(234, 88, 12, 0.1)',
                    borderRadius: '6px',
                    border: '1px solid rgba(234, 88, 12, 0.2)'
                  }}>
                    <div style={{ fontSize: '0.688rem', color: '#ea580c', fontWeight: '700', marginBottom: '0.5rem', textTransform: 'uppercase' }}>
                      File Hashes ({alert.raw_event._extracted.iocs.hashes.length})
                    </div>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
                      {alert.raw_event._extracted.iocs.hashes.slice(0, 3).map((hash, i) => (
                        <code key={i} style={{
                          padding: '0.25rem 0.5rem',
                          background: 'rgba(234, 88, 12, 0.15)',
                          border: '1px solid rgba(234, 88, 12, 0.3)',
                          borderRadius: '4px',
                          fontSize: '0.688rem',
                          color: '#fb923c',
                          maxWidth: '200px',
                          overflow: 'hidden',
                          textOverflow: 'ellipsis',
                          whiteSpace: 'nowrap'
                        }}>
                          {hash}
                        </code>
                      ))}
                      {alert.raw_event._extracted.iocs.hashes.length > 3 && (
                        <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', alignSelf: 'center' }}>
                          +{alert.raw_event._extracted.iocs.hashes.length - 3} more
                        </span>
                      )}
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Threat Intelligence Section - Always show */}
          <div style={{ marginBottom: '1rem' }}>
            <label style={{ display: 'block', fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '0.75rem', fontWeight: '600' }}>
              THREAT INTELLIGENCE
            </label>
            {loadingThreatData ? (
              <div style={{
                padding: '1rem',
                background: 'var(--bg-secondary)',
                borderRadius: '8px',
                textAlign: 'center',
                fontSize: '0.8rem',
                color: 'var(--text-muted)'
              }}>
                Checking threat intelligence sources...
              </div>
            ) : threatData && threatData.length > 0 ? (
              <div style={{
                background: 'var(--bg-secondary)',
                borderRadius: '8px',
                border: '1px solid var(--bg-tertiary)',
                overflow: 'hidden'
              }}>
                {threatData.map((item, idx) => (
                  <div
                    key={idx}
                    style={{
                      padding: '0.75rem',
                      borderBottom: idx < threatData.length - 1 ? '1px solid var(--bg-tertiary)' : 'none',
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                      gap: '0.75rem'
                    }}
                  >
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.25rem' }}>
                        <span style={{
                          fontSize: '0.65rem',
                          padding: '0.15rem 0.4rem',
                          borderRadius: '3px',
                          background: item.type === 'ip' ? 'rgba(59, 130, 246, 0.2)' :
                                     item.type === 'domain' ? 'rgba(168, 85, 247, 0.2)' :
                                     item.type === 'hash' ? 'rgba(234, 88, 12, 0.2)' :
                                     'rgba(100, 116, 139, 0.2)',
                          color: item.type === 'ip' ? '#3b82f6' :
                                item.type === 'domain' ? '#a855f7' :
                                item.type === 'hash' ? '#ea580c' :
                                '#64748b',
                          fontWeight: '600',
                          textTransform: 'uppercase'
                        }}>
                          {item.type}
                        </span>
                        <code style={{
                          fontSize: '0.75rem',
                          color: 'var(--text-primary)',
                          overflow: 'hidden',
                          textOverflow: 'ellipsis',
                          whiteSpace: 'nowrap',
                          maxWidth: '180px'
                        }}>
                          {item.value}
                        </code>
                      </div>
                      {/* Show enrichment details - Line 1: Geo/Network */}
                      {item.enrichment && (item.enrichment.country || item.enrichment.asn || item.enrichment.isp || item.enrichment.org) && (
                        <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: '0.25rem' }}>
                          {item.enrichment.country && <span style={{ marginRight: '0.5rem' }}>{item.enrichment.country}</span>}
                          {item.enrichment.asn && <span style={{ marginRight: '0.5rem' }}>ASN: {item.enrichment.asn}</span>}
                          {item.enrichment.isp && <span style={{ marginRight: '0.5rem' }}>ISP: {item.enrichment.isp}</span>}
                          {item.enrichment.org && !item.enrichment.isp && <span style={{ marginRight: '0.5rem' }}>Org: {item.enrichment.org}</span>}
                        </div>
                      )}
                      {/* Show enrichment details - Line 2: Threat Scores */}
                      {item.enrichment && (item.enrichment.abuse_score !== undefined || item.enrichment.vt_positives !== undefined) && (
                        <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: '0.25rem' }}>
                          {item.enrichment.abuse_score !== undefined && (
                            <span style={{
                              marginRight: '0.5rem',
                              color: item.enrichment.abuse_score >= 75 ? '#dc2626' :
                                     item.enrichment.abuse_score >= 25 ? '#ea580c' : 'var(--text-muted)'
                            }}>
                              AbuseIPDB: {item.enrichment.abuse_score}%
                              {item.enrichment.total_reports && ` (${item.enrichment.total_reports} reports)`}
                            </span>
                          )}
                          {item.enrichment.vt_positives !== undefined && (
                            <span style={{
                              color: item.enrichment.vt_positives >= 5 ? '#dc2626' :
                                     item.enrichment.vt_positives >= 1 ? '#ea580c' : '#22c55e'
                            }}>
                              VirusTotal: {item.enrichment.vt_positives}/{item.enrichment.vt_total || '?'}
                            </span>
                          )}
                        </div>
                      )}
                      {/* Show sources checked */}
                      {item.sources_checked > 0 && (
                        <div style={{ fontSize: '0.65rem', color: 'var(--text-muted)', marginTop: '0.25rem' }}>
                          Sources: {item.sources_flagged}/{item.sources_checked} flagged
                        </div>
                      )}
                      {/* Show categories/tags */}
                      {item.enrichment?.categories?.length > 0 && (
                        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.25rem', marginTop: '0.35rem' }}>
                          {item.enrichment.categories.slice(0, 4).map((cat, i) => (
                            <span key={i} style={{
                              fontSize: '0.6rem',
                              padding: '0.1rem 0.35rem',
                              background: 'rgba(234, 88, 12, 0.15)',
                              border: '1px solid rgba(234, 88, 12, 0.3)',
                              borderRadius: '3px',
                              color: '#ea580c'
                            }}>
                              {cat}
                            </span>
                          ))}
                          {item.enrichment.categories.length > 4 && (
                            <span style={{ fontSize: '0.6rem', color: 'var(--text-muted)' }}>
                              +{item.enrichment.categories.length - 4} more
                            </span>
                          )}
                        </div>
                      )}
                      {/* Show confidence score if available */}
                      {item.confidence !== undefined && item.confidence !== null && (
                        <div style={{ fontSize: '0.65rem', color: 'var(--text-muted)', marginTop: '0.25rem' }}>
                          Confidence: {formatConfidence(item.confidence)}
                        </div>
                      )}
                      {/* Show first/last seen if available */}
                      {(item.first_seen || item.last_seen) && (
                        <div style={{ fontSize: '0.65rem', color: 'var(--text-muted)', marginTop: '0.25rem' }}>
                          {item.first_seen && <span style={{ marginRight: '0.5rem' }}>First: {new Date(item.first_seen).toLocaleDateString()}</span>}
                          {item.last_seen && <span>Last: {new Date(item.last_seen).toLocaleDateString()}</span>}
                        </div>
                      )}
                      {/* Show sources */}
                      {item.sources && item.sources.length > 0 && (
                        <div style={{ fontSize: '0.65rem', color: 'var(--text-muted)', marginTop: '0.25rem' }}>
                          Sources: {item.sources.join(', ')}
                        </div>
                      )}
                    </div>
                    {/* Verdict badge - with smart labeling for known vendors */}
                    <div>
                      {(() => {
                        // Determine display verdict and styling
                        let displayVerdict = item.verdict || 'unknown';
                        let bgColor = 'rgba(100, 116, 139, 0.15)';
                        let textColor = '#64748b';
                        let borderColor = 'rgba(100, 116, 139, 0.3)';

                        // Known vendor domains that are expected/benign
                        const knownVendors = ['virustotal.com', 'microsoft.com', 'google.com', 'amazon.com',
                          'cloudflare.com', 'akamai.com', 'fastly.com', 'github.com', 'gitlab.com',
                          'slack.com', 'zoom.us', 'salesforce.com', 'okta.com', 'w3.org'];

                        const isKnownVendor = item.type === 'domain' &&
                          knownVendors.some(v => item.value.includes(v));

                        if (item.verdict === 'malicious') {
                          displayVerdict = 'MALICIOUS';
                          bgColor = 'rgba(220, 38, 38, 0.15)';
                          textColor = '#dc2626';
                          borderColor = 'rgba(220, 38, 38, 0.3)';
                        } else if (item.verdict === 'suspicious') {
                          displayVerdict = 'SUSPICIOUS';
                          bgColor = 'rgba(234, 88, 12, 0.15)';
                          textColor = '#ea580c';
                          borderColor = 'rgba(234, 88, 12, 0.3)';
                        } else if (item.verdict === 'benign' || item.verdict === 'clean') {
                          displayVerdict = 'CLEAN';
                          bgColor = 'rgba(34, 197, 94, 0.15)';
                          textColor = '#22c55e';
                          borderColor = 'rgba(34, 197, 94, 0.3)';
                        } else if (isKnownVendor) {
                          displayVerdict = 'KNOWN VENDOR';
                          bgColor = 'rgba(59, 130, 246, 0.15)';
                          textColor = '#3b82f6';
                          borderColor = 'rgba(59, 130, 246, 0.3)';
                        } else if (!item.verdict || item.verdict === 'unknown') {
                          displayVerdict = 'NO DATA';
                          bgColor = 'rgba(100, 116, 139, 0.1)';
                          textColor = '#64748b';
                          borderColor = 'rgba(100, 116, 139, 0.2)';
                        }

                        return (
                          <span style={{
                            display: 'inline-block',
                            padding: '0.25rem 0.5rem',
                            borderRadius: '4px',
                            fontSize: '0.65rem',
                            fontWeight: '700',
                            textTransform: 'uppercase',
                            background: bgColor,
                            color: textColor,
                            border: `1px solid ${borderColor}`
                          }}>
                            {displayVerdict}
                          </span>
                        );
                      })()}
                    </div>
                  </div>
                ))}
                {/* Link to Threat Center for full view */}
                <div style={{
                  padding: '0.5rem 0.75rem',
                  background: 'rgba(60, 179, 113, 0.05)',
                  borderTop: '1px solid var(--bg-tertiary)',
                  textAlign: 'center'
                }}>
                  <Link
                    to={`/threat-intel?iocs=${encodeURIComponent(threatData.map(t => t.value).join(','))}`}
                    style={{
                      fontSize: '0.75rem',
                      color: '#3CB371',
                      textDecoration: 'none',
                      fontWeight: '600'
                    }}
                  >
                    View Full Threat Intelligence →
                  </Link>
                </div>
              </div>
            ) : (
              <div style={{
                padding: '0.75rem 1rem',
                background: 'var(--bg-secondary)',
                borderRadius: '8px',
                border: '1px solid var(--bg-tertiary)',
                fontSize: '0.8rem',
                color: 'var(--text-muted)',
                fontStyle: 'italic'
              }}>
                No IOCs detected in this alert for threat intelligence lookup
              </div>
            )}
          </div>

          {/* Event Fields - Analyst-Friendly Semantic View */}
          {(() => {
            let rawEvent = alert.raw_event;
            if (typeof rawEvent === 'string') {
              try { rawEvent = JSON.parse(rawEvent); } catch (e) { rawEvent = null; }
            }

            const nestedAlert = rawEvent?.raw_alert || rawEvent?.alert_data || rawEvent?.data;
            const hasStructuredData = rawEvent && typeof rawEvent === 'object' && (
              rawEvent.host || rawEvent.user || rawEvent.network || rawEvent.file ||
              rawEvent.email || rawEvent.process || rawEvent.mitre || rawEvent.source ||
              rawEvent.detection || rawEvent.iocs || rawEvent.tags
            );
            const hasNestedStructuredData = nestedAlert && typeof nestedAlert === 'object' && (
              nestedAlert.host || nestedAlert.user || nestedAlert.network || nestedAlert.file ||
              nestedAlert.email || nestedAlert.process || nestedAlert.mitre || nestedAlert.source
            );

            let eventData = null;
            if (hasNestedStructuredData) eventData = nestedAlert;
            else if (hasStructuredData) eventData = rawEvent;
            else if (rawEvent && typeof rawEvent === 'object' && Object.keys(rawEvent).length > 0) eventData = rawEvent;

            if (!eventData) return null;

            return (
              <div style={{ marginBottom: '0.75rem' }}>
                <label style={{ display: 'block', fontSize: '0.7rem', color: 'var(--text-muted)', marginBottom: '0.4rem', fontWeight: '600' }}>
                  EVENT DATA
                </label>
                <div style={{ overflowY: 'auto', maxHeight: '300px' }}>
                  <JsonViewer data={eventData} />
                </div>
              </div>
            );
          })()}

          {/* Extracted Entities */}
          {alert.raw_event?._extracted?.entities && Object.values(alert.raw_event._extracted.entities).some(arr => arr && arr.length > 0) && (
            <div style={{ marginBottom: '1.5rem' }}>
              <label style={{ display: 'block', fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '0.75rem', fontWeight: '600' }}>
                EXTRACTED ENTITIES
              </label>
              <div style={{
                display: 'grid',
                gridTemplateColumns: '1fr 1fr',
                gap: '0.75rem'
              }}>
                {alert.raw_event._extracted.entities.hostnames?.length > 0 && (
                  <div style={{
                    padding: '0.75rem',
                    background: 'rgba(34, 197, 94, 0.1)',
                    borderRadius: '6px',
                    border: '1px solid rgba(34, 197, 94, 0.2)'
                  }}>
                    <div style={{ fontSize: '0.688rem', color: '#22c55e', fontWeight: '700', marginBottom: '0.5rem', textTransform: 'uppercase' }}>
                      Hosts ({alert.raw_event._extracted.entities.hostnames.length})
                    </div>
                    {alert.raw_event._extracted.entities.hostnames.slice(0, 3).map((host, i) => (
                      <div key={i} style={{ fontSize: '0.75rem', color: '#4ade80', marginBottom: '0.25rem' }}>
                        {host}
                      </div>
                    ))}
                    {alert.raw_event._extracted.entities.hostnames.length > 3 && (
                      <div style={{ fontSize: '0.688rem', color: 'var(--text-muted)', marginTop: '0.25rem' }}>
                        +{alert.raw_event._extracted.entities.hostnames.length - 3} more
                      </div>
                    )}
                  </div>
                )}
                {alert.raw_event._extracted.entities.users?.length > 0 && (
                  <div style={{
                    padding: '0.75rem',
                    background: 'rgba(234, 179, 8, 0.1)',
                    borderRadius: '6px',
                    border: '1px solid rgba(234, 179, 8, 0.2)'
                  }}>
                    <div style={{ fontSize: '0.688rem', color: '#eab308', fontWeight: '700', marginBottom: '0.5rem', textTransform: 'uppercase' }}>
                      Users ({alert.raw_event._extracted.entities.users.length})
                    </div>
                    {alert.raw_event._extracted.entities.users.slice(0, 3).map((user, i) => (
                      <div key={i} style={{ fontSize: '0.75rem', color: '#facc15', marginBottom: '0.25rem' }}>
                        {user}
                      </div>
                    ))}
                    {alert.raw_event._extracted.entities.users.length > 3 && (
                      <div style={{ fontSize: '0.688rem', color: 'var(--text-muted)', marginTop: '0.25rem' }}>
                        +{alert.raw_event._extracted.entities.users.length - 3} more
                      </div>
                    )}
                  </div>
                )}
              </div>
            </div>
          )}

        </div>

        {/* Actions Footer - Fixed at bottom */}
        <div style={{
          padding: '0.5rem 1rem',
          borderTop: '1px solid var(--bg-tertiary)',
          background: 'var(--bg-secondary)',
          flexShrink: 0,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'flex-end',
          gap: '0.5rem'
        }}>
          <button
            onClick={() => setShowRawDataPanel(true)}
            style={{
              padding: '0.4rem 0.75rem',
              fontSize: '0.7rem',
              fontWeight: '600',
              background: 'transparent',
              border: '1px solid rgba(100, 116, 139, 0.4)',
              borderRadius: '4px',
              color: '#94a3b8',
              cursor: 'pointer'
            }}
          >
            Raw JSON
          </button>

          {!investigation && can('create_investigation') && (
            <button
              disabled={isCreatingInvestigation}
              onClick={async () => {
                try {
                  setIsCreatingInvestigation(true);

                  // Create investigation directly
                  const response = await fetch(`${API_BASE_URL}/api/v1/investigate`, {
                    method: 'POST',
                    headers: getAuthHeaders(),
                    body: JSON.stringify({
                      title: alert.title,
                      description: alert.description || '',
                      source: alert.source || '',
                      metadata: (() => {
                        // Parse raw_event if it's a string
                        let rawEvent = alert.raw_event || {};
                        if (typeof rawEvent === 'string') {
                          try {
                            rawEvent = JSON.parse(rawEvent);
                          } catch (e) {
                            rawEvent = {};
                          }
                        }

                        // Only spread if it's a valid object
                        return {
                          alert_id: alert.alert_id,
                          external_id: alert.external_id,
                          source_type: alert.source_type,
                          severity: alert.severity,
                          ...(typeof rawEvent === 'object' && rawEvent !== null && !Array.isArray(rawEvent) ? rawEvent : {})
                        };
                      })()
                    })
                  });

                  if (!response.ok) {
                    throw new Error(`Failed to create investigation: ${response.status}`);
                  }

                  const result = await response.json();

                  // Navigate to investigation detail page
                  window.location.href = `/investigation/${result.investigation_id}`;
                } catch (error) {
                  toast.error('Failed to create investigation: ' + error.message);
                  setIsCreatingInvestigation(false);
                }
              }}
              style={{
                padding: '0.5rem 1rem',
                fontSize: '0.75rem',
                fontWeight: '600',
                background: 'linear-gradient(135deg, #3CB371 0%, #2e8b57 100%)',
                border: 'none',
                borderRadius: '4px',
                color: 'white',
                cursor: isCreatingInvestigation ? 'not-allowed' : 'pointer',
                opacity: isCreatingInvestigation ? 0.7 : 1,
                transition: 'all 0.2s ease'
              }}
              onMouseEnter={(e) => {
                if (!isCreatingInvestigation) e.target.style.opacity = '0.9';
              }}
              onMouseLeave={(e) => {
                if (!isCreatingInvestigation) e.target.style.opacity = '1';
              }}
            >
              {isCreatingInvestigation ? 'Creating...' : 'Investigate'}
            </button>
          )}
        </div>
      </div>

      {/* Raw Data Slide-out Panel */}
      {showRawDataPanel && (
        <>
          {/* Overlay for raw data panel - covers everything behind both panels */}
          <div 
            style={{
              position: 'fixed',
              top: 0,
              left: 0,
              right: 0,
              bottom: 0,
              background: 'rgba(0, 0, 0, 0.7)',
              zIndex: 998,  // Below alert drawer but above main content
              backdropFilter: 'blur(2px)',
              animation: 'fadeIn 0.2s ease'
            }}
            onClick={() => setShowRawDataPanel(false)}
          />

          {/* Raw Data Panel - Positioned to the left of the main drawer */}
          <div style={{
            position: 'fixed',
            top: 0,
            right: '700px',  // Match the width of the main drawer
            bottom: 0,
            width: 'min(600px, calc(100vw - 450px))',  // Responsive width
            background: '#0a0a0a',
            boxShadow: '-4px 0 20px rgba(0, 0, 0, 0.5)',  // Shadow on left side
            zIndex: 1001,  // Above alert drawer (1000)
            overflowY: 'auto',
            animation: 'slideInFromRight 0.3s ease',
            display: 'flex',
            flexDirection: 'column',
            borderLeft: '2px solid rgba(100, 116, 139, 0.3)'  // Border on left side
          }}>
            {/* Header */}
            <div style={{
              padding: '1.5rem',
              borderBottom: '2px solid rgba(100, 116, 139, 0.2)',
              position: 'sticky',
              top: 0,
              background: '#0a0a0a',
              zIndex: 10
            }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <h3 style={{ fontSize: '1.25rem', fontWeight: '700', margin: 0, color: '#a0e9ff' }}>
                  Raw Event Data
                </h3>
                <button
                  onClick={() => setShowRawDataPanel(false)}
                  style={{
                    background: 'none',
                    border: 'none',
                    color: 'var(--text-secondary)',
                    fontSize: '1.5rem',
                    cursor: 'pointer',
                    padding: '0.25rem',
                    lineHeight: 1
                  }}
                >
                  ✕
                </button>
              </div>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.5rem' }}>
                Complete event payload as received by T1 Agentics
              </div>
            </div>

            {/* JSON Viewer with Syntax Highlighting */}
            <div style={{ 
              flex: 1, 
              padding: '1.5rem', 
              overflow: 'auto',
              display: 'flex'  // Make it flex to fill height
            }}>
              <div style={{
                flex: 1,  // Fill available space
                padding: '1.5rem',
                background: '#1a1a1a',
                borderRadius: '8px',
                overflowX: 'auto',
                overflowY: 'auto',
                border: '1px solid rgba(100, 116, 139, 0.2)',
                height: '100%'  // Fill parent height
              }}>
                <JsonViewer data={(() => {
                  // Parse raw_event if it's a JSON string
                  let rawEventObj = alert.raw_event;
                  if (typeof rawEventObj === 'string') {
                    try {
                      rawEventObj = JSON.parse(rawEventObj);
                    } catch (e) {
                      return { error: 'Failed to parse raw_event', raw: alert.raw_event };
                    }
                  }
                  return rawEventObj || alert;
                })()} />
              </div>
            </div>

            {/* Footer Actions */}
            <div style={{
              padding: '1rem 1.5rem',
              borderTop: '2px solid rgba(100, 116, 139, 0.2)',
              background: '#0a0a0a',
              position: 'sticky',
              bottom: 0,
              display: 'flex',
              gap: '1rem'
            }}>
              <button
                onClick={() => {
                  // Parse raw_event if it's a JSON string
                  let rawEventObj = alert.raw_event;
                  if (typeof rawEventObj === 'string') {
                    try {
                      rawEventObj = JSON.parse(rawEventObj);
                    } catch (e) {
                      // If parsing fails, copy the raw string
                      navigator.clipboard.writeText(alert.raw_event);
                      return;
                    }
                  }
                  navigator.clipboard.writeText(JSON.stringify(rawEventObj || alert, null, 2));
                  // TODO: Add toast notification
                }}
                style={{
                  flex: 1,
                  padding: '0.75rem 1rem',
                  background: 'rgba(59, 130, 246, 0.1)',
                  border: '2px solid rgba(59, 130, 246, 0.3)',
                  borderRadius: '6px',
                  color: '#3b82f6',
                  fontSize: '0.875rem',
                  fontWeight: '600',
                  cursor: 'pointer',
                  transition: 'all 0.2s ease'
                }}
                onMouseEnter={(e) => {
                  e.target.style.background = 'rgba(59, 130, 246, 0.2)';
                  e.target.style.borderColor = 'rgba(59, 130, 246, 0.5)';
                }}
                onMouseLeave={(e) => {
                  e.target.style.background = 'rgba(59, 130, 246, 0.1)';
                  e.target.style.borderColor = 'rgba(59, 130, 246, 0.3)';
                }}
              >
                Copy to Clipboard
              </button>
              <button
                onClick={() => setShowRawDataPanel(false)}
                style={{
                  padding: '0.75rem 1.5rem',
                  background: 'rgba(100, 116, 139, 0.1)',
                  border: '2px solid rgba(100, 116, 139, 0.3)',
                  borderRadius: '6px',
                  color: 'var(--text-secondary)',
                  fontSize: '0.875rem',
                  fontWeight: '600',
                  cursor: 'pointer',
                  transition: 'all 0.2s ease'
                }}
              >
                Close
              </button>
            </div>
          </div>
        </>
      )}

      <style>{`
        @keyframes slideInRight {
          from {
            transform: translateX(100%);
          }
          to {
            transform: translateX(0);
          }
        }

        @keyframes slideInFromRight {
          from {
            transform: translateX(50%);
            opacity: 0;
          }
          to {
            transform: translateX(0);
            opacity: 1;
          }
        }

        @keyframes fadeIn {
          from {
            opacity: 0;
          }
          to {
            opacity: 1;
          }
        }
      `}</style>
    </>
  );
}

export default AlertDetailsDrawer;


