/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

import React, { useState, useRef, useEffect, useCallback } from 'react';
import { createPortal } from 'react-dom';

// Reputation colors
const reputationColors = {
  malicious: { bg: 'rgba(239, 68, 68, 0.15)', text: '#ef4444', label: 'Malicious' },
  suspicious: { bg: 'rgba(249, 115, 22, 0.15)', text: '#f97316', label: 'Suspicious' },
  clean: { bg: 'rgba(34, 197, 94, 0.15)', text: '#22c55e', label: 'Clean' },
  unknown: { bg: 'rgba(107, 114, 128, 0.15)', text: '#9ca3af', label: 'Unknown' }
};

// IOC type labels
const iocTypeLabels = {
  ip: 'IP Address',
  domain: 'Domain',
  url: 'URL',
  hash: 'File Hash',
  md5: 'MD5 Hash',
  sha1: 'SHA1 Hash',
  sha256: 'SHA256 Hash',
  email: 'Email Address',
  file: 'File Path',
  registry: 'Registry Key',
  cve: 'CVE',
  default: 'Indicator'
};

// MITRE tactic colors (muted)
const tacticColors = {
  'reconnaissance': '#64748b',
  'resource-development': '#64748b',
  'initial-access': '#ef4444',
  'execution': '#f97316',
  'persistence': '#eab308',
  'privilege-escalation': '#f59e0b',
  'defense-evasion': '#84cc16',
  'credential-access': '#22c55e',
  'discovery': '#14b8a6',
  'lateral-movement': '#06b6d4',
  'collection': '#3b82f6',
  'command-and-control': '#6366f1',
  'exfiltration': '#8b5cf6',
  'impact': '#ec4899',
  'default': '#64748b'
};

// HoverContextMenu component
// NOTE: This component displays enrichment data that was already fetched during investigation analysis.
// It does NOT make API calls on hover - all data comes from the investigation_data passed via props.
const HoverContextMenu = ({ children, type, data, disabled = false }) => {
  const [isVisible, setIsVisible] = useState(false);
  const [position, setPosition] = useState({ x: 0, y: 0 });
  const triggerRef = useRef(null);
  const menuRef = useRef(null);
  const timeoutRef = useRef(null);

  const showMenu = useCallback((e) => {
    if (disabled) return;

    // Clear any pending hide timeout
    if (timeoutRef.current) {
      clearTimeout(timeoutRef.current);
    }

    // Calculate position based on mouse event
    const rect = triggerRef.current?.getBoundingClientRect();
    if (!rect) return;

    // Position below the element, centered
    let x = rect.left + rect.width / 2;
    let y = rect.bottom + 8;

    // Adjust if too close to right edge
    const menuWidth = 280;
    if (x + menuWidth / 2 > window.innerWidth - 20) {
      x = window.innerWidth - menuWidth / 2 - 20;
    }
    if (x - menuWidth / 2 < 20) {
      x = menuWidth / 2 + 20;
    }

    // Adjust if too close to bottom
    const menuHeight = 200;
    if (y + menuHeight > window.innerHeight - 20) {
      y = rect.top - menuHeight - 8;
    }

    setPosition({ x, y });

    // Small delay to prevent flicker on quick mouse movements
    timeoutRef.current = setTimeout(() => {
      setIsVisible(true);
    }, 200);
  }, [disabled]);

  const hideMenu = useCallback(() => {
    if (timeoutRef.current) {
      clearTimeout(timeoutRef.current);
    }
    timeoutRef.current = setTimeout(() => {
      setIsVisible(false);
    }, 150);
  }, []);

  const keepMenuOpen = useCallback(() => {
    if (timeoutRef.current) {
      clearTimeout(timeoutRef.current);
    }
  }, []);

  useEffect(() => {
    return () => {
      if (timeoutRef.current) {
        clearTimeout(timeoutRef.current);
      }
    };
  }, []);

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
    // Could add a toast notification here
  };

  // Render IOC content - uses only enrichment data passed via props (no API calls)
  const renderIOCContent = () => {
    const { value, type: iocType, reputation, enrichment } = data;
    const typeLabel = iocTypeLabels[iocType?.toLowerCase()] || iocTypeLabels.default;

    // Use enrichment data from the investigation (already fetched during analysis)
    const activeEnrichment = enrichment;

    // Check if enrichment has any actual data
    const hasEnrichmentData = activeEnrichment && (
      activeEnrichment.virustotal || activeEnrichment.abuseipdb || activeEnrichment.otx ||
      activeEnrichment.malicious_count !== undefined || activeEnrichment.enriched ||
      (Array.isArray(activeEnrichment) && activeEnrichment.length > 0)
    );

    // Handle enrichment as array (from API) or object
    let vtData = null, abuseData = null, otxData = null;
    if (activeEnrichment) {
      if (Array.isArray(activeEnrichment)) {
        // Enrichment from API is an array of provider results
        activeEnrichment.forEach(e => {
          const provider = (e.provider || e.source || '').toLowerCase();
          if (provider.includes('virustotal') || provider.includes('vt')) {
            vtData = e.data || e.result || e;
          } else if (provider.includes('abuseipdb') || provider.includes('abuse')) {
            abuseData = e.data || e.result || e;
          } else if (provider.includes('otx') || provider.includes('alienvault')) {
            otxData = e.data || e.result || e;
          }
        });
      } else {
        // Enrichment as object with provider keys
        vtData = activeEnrichment.virustotal || activeEnrichment.vt;
        abuseData = activeEnrichment.abuseipdb || activeEnrichment.abuse;
        otxData = activeEnrichment.otx || activeEnrichment.alienvault;

        // Also check for flat enrichment data (from ioc_enrichment)
        if (!vtData && (activeEnrichment.malicious_count !== undefined || activeEnrichment.vt_detections !== undefined)) {
          vtData = {
            malicious: activeEnrichment.malicious_count || activeEnrichment.vt_detections || 0,
            total: activeEnrichment.total_engines || 0
          };
        }
        if (!abuseData && activeEnrichment.abuse_confidence !== undefined) {
          abuseData = { confidence: activeEnrichment.abuse_confidence };
        }
        if (!otxData && activeEnrichment.otx_pulses !== undefined) {
          otxData = { pulses: activeEnrichment.otx_pulses };
        }
      }
    }

    // Derive reputation from actual enrichment data, not just the passed-in reputation
    // This ensures the badge matches the actual threat intel findings
    const deriveReputation = () => {
      // Get VT malicious count
      const vtMalicious = vtData?.malicious || vtData?.positives || 0;
      const vtTotal = vtData?.total || 0;

      // Get AbuseIPDB confidence
      const abuseConfidence = abuseData?.confidence || abuseData?.abuseConfidenceScore || 0;

      // Get OTX pulse count
      const otxPulses = otxData?.pulses || otxData?.pulse_count || 0;

      // If VT has 3+ malicious detections, it's malicious
      if (vtMalicious >= 3) return 'malicious';

      // If VT has 1-2 malicious or AbuseIPDB >50% or OTX has pulses, suspicious
      if (vtMalicious > 0 || abuseConfidence > 50 || otxPulses > 0) return 'suspicious';

      // If we have enrichment data and nothing flagged it, it's clean
      if (hasEnrichmentData && vtTotal > 0) return 'clean';

      // Fall back to the passed reputation or unknown
      return reputation || 'unknown';
    };

    const activeReputation = deriveReputation();
    const repColor = reputationColors[activeReputation] || reputationColors.unknown;

    return (
      <>
        <div style={styles.header}>
          <span style={styles.headerLabel}>IOC</span>
          <span style={styles.headerValue}>{value}</span>
        </div>
        <div style={styles.divider} />
        <div style={styles.row}>
          <span style={styles.label}>Type:</span>
          <span style={styles.value}>{typeLabel}</span>
        </div>
        <div style={styles.row}>
          <span style={styles.label}>Reputation:</span>
          <span style={{
            ...styles.badge,
            backgroundColor: repColor.bg,
            color: repColor.text
          }}>
            {repColor.label}
          </span>
        </div>

        {hasEnrichmentData ? (
          <>
            <div style={styles.divider} />
            {vtData && (
              <div style={styles.row}>
                <span style={styles.label}>VirusTotal:</span>
                <span style={{
                  ...styles.value,
                  color: vtData.malicious > 0 ? '#ef4444' : '#22c55e'
                }}>
                  {vtData.malicious || vtData.positives || 0}/{vtData.total || '?'} malicious
                </span>
              </div>
            )}
            {abuseData && (
              <div style={styles.row}>
                <span style={styles.label}>AbuseIPDB:</span>
                <span style={{
                  ...styles.value,
                  color: (abuseData.confidence || abuseData.abuseConfidenceScore || 0) > 50 ? '#ef4444' : '#22c55e'
                }}>
                  {abuseData.confidence || abuseData.abuseConfidenceScore || 0}% confidence
                </span>
              </div>
            )}
            {otxData && (
              <div style={styles.row}>
                <span style={styles.label}>OTX:</span>
                <span style={{
                  ...styles.value,
                  color: (otxData.pulses || otxData.pulse_count || 0) > 0 ? '#f97316' : '#9ca3af'
                }}>
                  {otxData.pulses || otxData.pulse_count || 0} pulses
                </span>
              </div>
            )}
          </>
        ) : (
          <>
            <div style={styles.divider} />
            <div style={styles.hint}>
              No threat intel cached
            </div>
          </>
        )}

        <div style={styles.divider} />
        <div style={styles.actions}>
          <button style={styles.actionButton} onClick={() => copyToClipboard(value)}>
            Copy
          </button>
        </div>
      </>
    );
  };

  // Render MITRE content
  const renderMITREContent = () => {
    const { technique_id, technique_name, tactic, description, phase } = data;
    const tacticColor = tacticColors[tactic?.toLowerCase()?.replace(/\s+/g, '-')] || tacticColors.default;

    return (
      <>
        <div style={styles.header}>
          <span style={styles.headerLabel}>{technique_id}</span>
          <span style={styles.headerValue}>{technique_name}</span>
        </div>
        <div style={styles.divider} />
        {tactic && (
          <div style={styles.row}>
            <span style={styles.label}>Tactic:</span>
            <span style={{
              ...styles.badge,
              backgroundColor: `${tacticColor}20`,
              color: tacticColor
            }}>
              {tactic}
            </span>
          </div>
        )}
        {phase && (
          <div style={styles.row}>
            <span style={styles.label}>Phase:</span>
            <span style={styles.value}>{phase}</span>
          </div>
        )}
        {description && (
          <>
            <div style={styles.divider} />
            <div style={styles.description}>
              {description.length > 150 ? description.substring(0, 150) + '...' : description}
            </div>
          </>
        )}
        <div style={styles.divider} />
        <div style={styles.actions}>
          {technique_id && (
            <a
              href={`https://attack.mitre.org/techniques/${technique_id.replace(/\./g, '/')}/`}
              target="_blank"
              rel="noopener noreferrer"
              style={styles.actionLink}
            >
              View on MITRE ATT&CK
            </a>
          )}
        </div>
      </>
    );
  };

  // Render Entity content
  const renderEntityContent = () => {
    const { type: entityType, value, hostname, ip, user, activity_count, last_seen } = data;
    const displayValue = value || hostname || ip || user || 'Unknown';

    return (
      <>
        <div style={styles.header}>
          <span style={styles.headerLabel}>{entityType || 'Entity'}</span>
          <span style={styles.headerValue}>{displayValue}</span>
        </div>
        <div style={styles.divider} />
        <div style={styles.row}>
          <span style={styles.label}>Type:</span>
          <span style={styles.value}>{entityType || 'Unknown'}</span>
        </div>
        {activity_count !== undefined && (
          <div style={styles.row}>
            <span style={styles.label}>Activity:</span>
            <span style={styles.value}>{activity_count} events</span>
          </div>
        )}
        {last_seen && (
          <div style={styles.row}>
            <span style={styles.label}>Last Seen:</span>
            <span style={styles.value}>{new Date(last_seen).toLocaleString()}</span>
          </div>
        )}
        <div style={styles.divider} />
        <div style={styles.actions}>
          <button style={styles.actionButton} onClick={() => copyToClipboard(displayValue)}>
            Copy
          </button>
        </div>
      </>
    );
  };

  // Render Artifact content
  const renderArtifactContent = () => {
    const { encoding, decoded_value, original_value, extraction_method, associated_iocs } = data;

    return (
      <>
        <div style={styles.header}>
          <span style={styles.headerLabel}>Decoded Artifact</span>
        </div>
        <div style={styles.divider} />
        {encoding && (
          <div style={styles.row}>
            <span style={styles.label}>Encoding:</span>
            <span style={styles.value}>{encoding}</span>
          </div>
        )}
        {extraction_method && (
          <div style={styles.row}>
            <span style={styles.label}>Method:</span>
            <span style={styles.value}>{extraction_method}</span>
          </div>
        )}
        {decoded_value && (
          <>
            <div style={styles.divider} />
            <div style={styles.codeBlock}>
              {decoded_value.length > 200 ? decoded_value.substring(0, 200) + '...' : decoded_value}
            </div>
          </>
        )}
        {associated_iocs && associated_iocs.length > 0 && (
          <>
            <div style={styles.divider} />
            <div style={styles.row}>
              <span style={styles.label}>IOCs Found:</span>
              <span style={styles.value}>{associated_iocs.length}</span>
            </div>
          </>
        )}
        <div style={styles.divider} />
        <div style={styles.actions}>
          <button style={styles.actionButton} onClick={() => copyToClipboard(decoded_value || original_value)}>
            Copy
          </button>
        </div>
      </>
    );
  };

  // Render content based on type
  const renderContent = () => {
    switch (type) {
      case 'ioc':
        return renderIOCContent();
      case 'mitre':
        return renderMITREContent();
      case 'entity':
        return renderEntityContent();
      case 'artifact':
        return renderArtifactContent();
      default:
        return <div style={styles.description}>No details available</div>;
    }
  };

  const menu = isVisible && createPortal(
    <div
      ref={menuRef}
      style={{
        position: 'fixed',
        left: position.x,
        top: position.y,
        transform: 'translateX(-50%)',
        zIndex: 10000,
        backgroundColor: 'rgba(17, 24, 39, 0.98)',
        border: '1px solid rgba(75, 85, 99, 0.5)',
        borderRadius: '8px',
        boxShadow: '0 20px 40px rgba(0, 0, 0, 0.5)',
        backdropFilter: 'blur(8px)',
        minWidth: '260px',
        maxWidth: '320px',
        padding: '12px',
        animation: 'fadeIn 0.15s ease-out',
        pointerEvents: 'auto'
      }}
      onMouseEnter={keepMenuOpen}
      onMouseLeave={hideMenu}
    >
      <style>
        {`
          @keyframes fadeIn {
            from { opacity: 0; transform: translateX(-50%) translateY(-4px); }
            to { opacity: 1; transform: translateX(-50%) translateY(0); }
          }
        `}
      </style>
      {renderContent()}
    </div>,
    document.body
  );

  return (
    <span
      ref={triggerRef}
      onMouseEnter={showMenu}
      onMouseLeave={hideMenu}
      style={{ cursor: disabled ? 'default' : 'help' }}
    >
      {children}
      {menu}
    </span>
  );
};

// Styles
const styles = {
  header: {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
    marginBottom: '8px'
  },
  headerLabel: {
    fontSize: '10px',
    fontWeight: '600',
    letterSpacing: '0.05em',
    padding: '2px 6px',
    borderRadius: '3px',
    backgroundColor: 'rgba(59, 130, 246, 0.2)',
    color: '#60a5fa',
    textTransform: 'uppercase'
  },
  headerValue: {
    fontSize: '13px',
    fontWeight: '500',
    color: '#f3f4f6',
    wordBreak: 'break-all'
  },
  divider: {
    height: '1px',
    backgroundColor: 'rgba(75, 85, 99, 0.3)',
    margin: '8px 0'
  },
  row: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    padding: '4px 0'
  },
  label: {
    fontSize: '12px',
    color: '#9ca3af'
  },
  value: {
    fontSize: '12px',
    color: '#e5e7eb',
    textAlign: 'right'
  },
  badge: {
    fontSize: '11px',
    fontWeight: '500',
    padding: '2px 8px',
    borderRadius: '4px'
  },
  description: {
    fontSize: '12px',
    color: '#9ca3af',
    lineHeight: '1.5'
  },
  hint: {
    fontSize: '11px',
    color: '#6b7280',
    fontStyle: 'italic',
    textAlign: 'center',
    padding: '4px 0'
  },
  codeBlock: {
    fontSize: '11px',
    fontFamily: 'monospace',
    backgroundColor: 'rgba(0, 0, 0, 0.3)',
    padding: '8px',
    borderRadius: '4px',
    color: '#e5e7eb',
    wordBreak: 'break-all',
    maxHeight: '100px',
    overflow: 'auto'
  },
  actions: {
    display: 'flex',
    gap: '8px',
    marginTop: '4px'
  },
  actionButton: {
    fontSize: '11px',
    fontWeight: '500',
    padding: '4px 10px',
    borderRadius: '4px',
    border: '1px solid rgba(75, 85, 99, 0.5)',
    backgroundColor: 'rgba(75, 85, 99, 0.2)',
    color: '#e5e7eb',
    cursor: 'pointer',
    transition: 'all 0.15s'
  },
  actionLink: {
    fontSize: '11px',
    fontWeight: '500',
    color: '#60a5fa',
    textDecoration: 'none'
  }
};

export default HoverContextMenu;
