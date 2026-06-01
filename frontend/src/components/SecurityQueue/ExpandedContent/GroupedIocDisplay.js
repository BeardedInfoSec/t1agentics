/**
 * Copyright (c) 2025-2026 T1 Agentics LLC. SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useMemo } from 'react';
import styles from '../SecurityQueue.module.css';
import IocChipWithTooltip from './IocChipWithTooltip';

const IOC_TYPE_CONFIG = {
  hash: { icon: '#', color: '#f59e0b', label: 'HASHES', order: 0 },
  ip: { icon: '\u25CF', color: '#8b5cf6', label: 'IPs', order: 1 },
  email: { icon: '\u2709', color: '#ec4899', label: 'EMAILS', order: 2 },
  domain: { icon: '@', color: '#3b82f6', label: 'DOMAINS', order: 3 },
  url: { icon: '\u2197', color: '#06b6d4', label: 'URLs', order: 4 },
  file: { icon: '\u2261', color: '#22c55e', label: 'FILES', order: 5 },
  unknown: { icon: '?', color: '#6b7280', label: 'OTHER', order: 6 },
};

const VERDICT_ORDER = { malicious: 0, suspicious: 1, unknown: 2, '': 2, clean: 3, benign: 3 };

/**
 * Get the base domain from a URL for deduplication grouping.
 * e.g. "https://links.promo.promarketinsights.com/foo/bar" -> "links.promo.promarketinsights.com"
 */
function getUrlHost(value) {
  try {
    return new URL(value).hostname;
  } catch {
    return null;
  }
}

/**
 * Deduplicate URLs from the same hostname.
 * Returns { unique: IOC[], collapsed: { hostname: string, count: number, iocs: IOC[] }[] }
 */
function deduplicateUrls(iocs) {
  const hostGroups = {};
  const nonUrl = [];

  iocs.forEach(ioc => {
    const host = getUrlHost(ioc.value);
    if (!host) {
      nonUrl.push(ioc);
      return;
    }
    if (!hostGroups[host]) hostGroups[host] = [];
    hostGroups[host].push(ioc);
  });

  const unique = [...nonUrl];
  const collapsed = [];

  Object.entries(hostGroups).forEach(([host, group]) => {
    // Sort by verdict within group (malicious first)
    group.sort((a, b) => {
      const va = (a.verdict || '').toLowerCase();
      const vb = (b.verdict || '').toLowerCase();
      return (VERDICT_ORDER[va] ?? 2) - (VERDICT_ORDER[vb] ?? 2);
    });

    // Check if any in this group have a notable verdict
    const hasNotable = group.some(ioc => {
      const v = (ioc.verdict || '').toLowerCase();
      return v === 'malicious' || v === 'suspicious';
    });

    if (group.length === 1) {
      unique.push(group[0]);
    } else if (hasNotable) {
      // Show notable ones individually, collapse the rest
      const notable = group.filter(ioc => {
        const v = (ioc.verdict || '').toLowerCase();
        return v === 'malicious' || v === 'suspicious';
      });
      const rest = group.filter(ioc => {
        const v = (ioc.verdict || '').toLowerCase();
        return v !== 'malicious' && v !== 'suspicious';
      });
      unique.push(...notable);
      if (rest.length > 0) {
        collapsed.push({ hostname: host, count: rest.length, iocs: rest });
      }
    } else {
      // All benign/unknown -- show first, collapse rest
      unique.push(group[0]);
      collapsed.push({ hostname: host, count: group.length - 1, iocs: group.slice(1) });
    }
  });

  return { unique, collapsed };
}

/**
 * GroupedIocDisplay - renders IOCs grouped by type with deduplication
 *
 * @param {Object[]} iocs - Array of IOC objects with { type, value, verdict, ... }
 * @param {Object} [iocEnrichments] - Optional enrichment map (value -> enrichment data)
 * @param {Function} [buildEnrichmentDetails] - Optional function(ioc, enrichment) -> detail[]
 * @param {boolean} [enrichmentLoading] - Whether enrichment is still loading
 */
export default function GroupedIocDisplay({ iocs, iocEnrichments = {}, buildEnrichmentDetails, enrichmentLoading = false }) {
  const [expandedGroups, setExpandedGroups] = useState({});

  const toggleGroup = (key) => {
    setExpandedGroups(prev => ({ ...prev, [key]: !prev[key] }));
  };

  // Group IOCs by type
  const grouped = useMemo(() => {
    const groups = {};

    iocs.forEach(ioc => {
      const type = (ioc.type || 'unknown').toLowerCase();
      if (!groups[type]) groups[type] = [];
      groups[type].push(ioc);
    });

    // Sort within each group by verdict (malicious first)
    Object.values(groups).forEach(group => {
      group.sort((a, b) => {
        const va = (a.verdict || '').toLowerCase();
        const vb = (b.verdict || '').toLowerCase();
        return (VERDICT_ORDER[va] ?? 2) - (VERDICT_ORDER[vb] ?? 2);
      });
    });

    // Sort groups by type order (hashes first, URLs last)
    return Object.entries(groups)
      .sort(([a], [b]) => (IOC_TYPE_CONFIG[a]?.order ?? 6) - (IOC_TYPE_CONFIG[b]?.order ?? 6));
  }, [iocs]);

  const renderIocChip = (ioc, idx) => {
    const typeConfig = IOC_TYPE_CONFIG[ioc.type?.toLowerCase()] || IOC_TYPE_CONFIG.unknown;
    const enrichment = iocEnrichments[ioc.value] || {};
    const effectiveVerdict = enrichment.verdict || ioc.verdict || '';
    const verdictLower = effectiveVerdict.toLowerCase();
    const isMalicious = ioc.malicious || verdictLower === 'malicious';
    const isSuspicious = verdictLower === 'suspicious';
    const isBenign = verdictLower === 'benign' || verdictLower === 'clean';

    let chipClass = styles.iocChip;
    if (isMalicious) chipClass += ` ${styles.iocMalicious}`;
    else if (isSuspicious) chipClass += ` ${styles.iocSuspicious}`;
    else if (isBenign) chipClass += ` ${styles.iocBenign}`;

    let enrichmentDetails = [];
    if (buildEnrichmentDetails) {
      enrichmentDetails = buildEnrichmentDetails(ioc, enrichment);
    } else {
      // Default enrichment details
      if (effectiveVerdict && effectiveVerdict !== 'unknown') {
        enrichmentDetails.push({ label: 'Verdict', value: effectiveVerdict.toUpperCase() });
      }
      if (enrichment.sources?.length > 0) {
        enrichmentDetails.push({ label: 'Sources', value: enrichment.sources.join(', ') });
      } else if (ioc.sources?.length > 0) {
        enrichmentDetails.push({ label: 'Sources', value: ioc.sources.join(', ') });
      }
      if (ioc.score != null) enrichmentDetails.push({ label: 'Score', value: `${ioc.score}/100` });
      if (enrichment.country || ioc.country) enrichmentDetails.push({ label: 'Country', value: enrichment.country || ioc.country });
      if (enrichment.asn || ioc.asn) enrichmentDetails.push({ label: 'ASN', value: enrichment.asn || ioc.asn });
    }

    return (
      <IocChipWithTooltip
        key={idx}
        ioc={ioc}
        chipClass={chipClass}
        typeConfig={typeConfig}
        enrichmentDetails={enrichmentDetails}
        loading={enrichmentLoading}
      />
    );
  };

  return (
    <div>
      {grouped.map(([type, typeIocs]) => {
        const config = IOC_TYPE_CONFIG[type] || IOC_TYPE_CONFIG.unknown;
        const isUrlType = type === 'url';
        const { unique, collapsed } = isUrlType ? deduplicateUrls(typeIocs) : { unique: typeIocs, collapsed: [] };
        const totalCollapsed = collapsed.reduce((sum, c) => sum + c.count, 0);

        return (
          <div key={type} style={{ marginBottom: '0.6rem' }}>
            <div style={{
              display: 'flex',
              alignItems: 'center',
              gap: '0.5rem',
              marginBottom: '0.35rem',
            }}>
              <span style={{ color: config.color, fontSize: '0.7rem', fontWeight: 600 }}>
                {config.icon}
              </span>
              <span style={{
                fontSize: '0.7rem',
                fontWeight: 600,
                color: 'var(--text-muted)',
                letterSpacing: '0.05em',
              }}>
                {config.label} ({typeIocs.length})
              </span>
            </div>
            <div className={styles.iocGrid}>
              {unique.map((ioc, idx) => renderIocChip(ioc, `${type}-${idx}`))}
            </div>
            {collapsed.length > 0 && !expandedGroups[`${type}-collapsed`] && (
              <button
                onClick={() => toggleGroup(`${type}-collapsed`)}
                style={{
                  marginTop: '0.3rem',
                  background: 'none',
                  border: 'none',
                  color: 'var(--text-muted)',
                  fontSize: '0.75rem',
                  cursor: 'pointer',
                  padding: '0.2rem 0',
                }}
              >
                +{totalCollapsed} duplicate URLs from {collapsed.length} host{collapsed.length > 1 ? 's' : ''} ({collapsed.map(c => c.hostname).join(', ')})
              </button>
            )}
            {collapsed.length > 0 && expandedGroups[`${type}-collapsed`] && (
              <>
                <div className={styles.iocGrid} style={{ marginTop: '0.3rem' }}>
                  {collapsed.flatMap((c) => c.iocs).map((ioc, idx) => renderIocChip(ioc, `${type}-dup-${idx}`))}
                </div>
                <button
                  onClick={() => toggleGroup(`${type}-collapsed`)}
                  style={{
                    marginTop: '0.3rem',
                    background: 'none',
                    border: 'none',
                    color: 'var(--text-muted)',
                    fontSize: '0.75rem',
                    cursor: 'pointer',
                    padding: '0.2rem 0',
                  }}
                >
                  Collapse duplicates
                </button>
              </>
            )}
          </div>
        );
      })}
    </div>
  );
}
