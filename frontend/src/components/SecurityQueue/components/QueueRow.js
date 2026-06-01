/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

/**
 * QueueRow Component
 *
 * Renders a single row in the security queue table.
 * Works with the unified SecurityQueueItem type - no branching on raw backend objects.
 */

import React from 'react';
import Badge from '../../ui/Badge';
import {
  severityToBadgeVariant,
  verdictToBadgeVariant,
  priorityToBadgeVariant,
} from '../../../styles/colors';
import { columnAppliesTo } from '../constants';
import { formatDate, formatTimeRemaining, getStatusBadge } from '../utils';
import styles from '../SecurityQueue.module.css';

/**
 * Render cell content based on column key
 * @param {string} columnKey - Column key from COLUMN_CONFIG
 * @param {import('../types').SecurityQueueItem} item - Queue item
 * @returns {React.ReactNode}
 */
function renderCell(columnKey, item) {
  // Check if column applies to this item type
  if (!columnAppliesTo(columnKey, item.item_type)) {
    return <span className={styles.cellEmpty}>-</span>;
  }

  switch (columnKey) {
    case 'id': {
      // Display the *unique* tail of the ID, not the first 8 chars.
      // Alert IDs follow PHI-YYMMDD-XXXXXXXX where the leading "PHI-YYMMDD"
      // is a date prefix shared by every alert from that day, so taking
      // the first 8 chars collides for every alert on the same date. The
      // unique part is the segment after the LAST hyphen.
      const uniqueSuffix = (raw) => {
        const s = (raw || '').toString();
        const lastDash = s.lastIndexOf('-');
        const tail = lastDash >= 0 ? s.slice(lastDash + 1) : s;
        return tail.substring(0, 8).toUpperCase();
      };
      const rawInvId = (item.investigation_id || '').replace(/^INV-/i, '');
      const rawAlertId = (item.alert_id || '').replace(/^(alert-|ALT-)/i, '');
      const displayId = item.item_type === 'investigation'
        ? `INV-${uniqueSuffix(rawInvId) || rawInvId.substring(0, 8).toUpperCase()}`
        : `ALT-${uniqueSuffix(rawAlertId) || rawAlertId.substring(0, 8).toUpperCase()}`;
      return <span className={styles.cellId}>{displayId}</span>;
    }

    case 'title': {
      // Type badge:
      //   A          - standalone alert
      //   I          - investigation with 0 or 1 child alert
      //   M (red)    - investigation with >1 children AND >=1 non-benign child
      //   M (gray)   - investigation with >1 children, all benign
      const childCount = item.correlation_count || 0;
      const isMulti = item.item_type === 'investigation' && childCount > 1;
      let badgeLabel;
      let badgeData;
      if (item.item_type !== 'investigation') {
        badgeLabel = 'A';
        badgeData = 'alert';
      } else if (!isMulti) {
        badgeLabel = 'I';
        badgeData = 'investigation';
      } else if (item.has_non_benign_child) {
        badgeLabel = `M ${childCount}`;
        badgeData = 'multi-warn';
      } else {
        badgeLabel = `M ${childCount}`;
        badgeData = 'multi';
      }
      return (
        <div className={styles.cellTitle}>
          <span
            className={styles.itemTypeIndicator}
            data-type={badgeData}
            title={isMulti
              ? `${childCount} correlated alerts${item.has_non_benign_child ? ' — at least one non-benign verdict' : ' — all benign'}`
              : undefined}
          >
            {badgeLabel}
          </span>
          {item.title || 'Untitled'}
        </div>
      );
    }

    case 'status': {
      const { variant, text, pulse } = getStatusBadge(item);
      return (
        <Badge
          variant={variant}
          size="xs"
          solid
          style={pulse ? { animation: 'pulse 2s infinite' } : undefined}
        >
          {pulse && <span className={styles.pulseIndicator}>&#9679; </span>}
          {text}
        </Badge>
      );
    }

    case 'severity':
      return (
        <Badge variant={severityToBadgeVariant(item.severity)} size="xs" solid>
          {(item.severity || 'unknown').toUpperCase()}
        </Badge>
      );

    case 'disposition':
      return item.disposition ? (
        <Badge variant={verdictToBadgeVariant(item.disposition)} size="xs" solid>
          {item.disposition.replace(/_/g, ' ').toUpperCase()}
        </Badge>
      ) : <span className={styles.cellEmpty}>-</span>;

    case 'priority':
      return item.priority ? (
        <Badge variant={priorityToBadgeVariant(item.priority)} size="xs" solid>
          {item.priority}
        </Badge>
      ) : <span className={styles.cellEmpty}>-</span>;

    case 'sla': {
      if (!item.sla) return <span className={styles.cellEmpty}>-</span>;

      const { status: slaStatus, remaining: slaRemaining } = item.sla;

      // Closed states
      if (slaStatus === 'met') {
        return <Badge variant="success" size="xs" solid>MET</Badge>;
      }
      if (slaStatus === 'exceeded' && ['closed', 'resolved', 'CLOSED', 'RESOLVED'].includes(item.status)) {
        return <Badge variant="danger" size="xs" solid>EXCEEDED</Badge>;
      }
      if (slaStatus === 'exceeded') {
        return <Badge variant="danger" size="xs" solid>EXCEEDED</Badge>;
      }

      // Open states — show time remaining
      const isUrgent = slaStatus === 'at_risk'; // < 1 hour left
      return (
        <span style={{ color: isUrgent ? 'var(--danger)' : 'var(--text-secondary)', fontWeight: isUrgent ? 600 : 400, fontSize: '0.8rem' }}>
          {formatTimeRemaining(slaRemaining)}
        </span>
      );
    }

    case 'owner':
      return (
        <span className={styles.cellOwner}>
          {item.owner || 'Unassigned'}
        </span>
      );

    case 'enrichment': {
      const alertContext = item.alert_context;
      if (!alertContext) return <span className={styles.cellEmpty}>-</span>;

      const enrichmentData = alertContext.raw_event?._extracted?.enrichment;
      if (enrichmentData && enrichmentData.status === 'enriched') {
        const summary = enrichmentData.summary || {};
        const totalEnriched = summary.total_enriched || 0;

        if (summary.malicious > 0) {
          return (
            <Badge variant="danger" size="xs" solid>
              {summary.malicious} MAL ({totalEnriched})
            </Badge>
          );
        }
        if (summary.suspicious > 0) {
          return (
            <Badge variant="warning" size="xs" solid>
              {summary.suspicious} SUS ({totalEnriched})
            </Badge>
          );
        }
        return (
          <Badge variant="success" size="xs" solid>
            CLEAN ({totalEnriched})
          </Badge>
        );
      }

      const rawEvent = alertContext.raw_event || {};
      const hasIOCs = rawEvent.source_ip || rawEvent.domain ||
                      rawEvent._extracted?.iocs?.ips?.length > 0 ||
                      rawEvent._extracted?.iocs?.domains?.length > 0;

      if (hasIOCs && !enrichmentData) {
        return <Badge variant="info" size="xs" solid>PENDING</Badge>;
      }

      const enrichmentSummary = alertContext.enrichment_summary;
      if (enrichmentSummary?.internal_only) {
        return <Badge variant="default" size="xs" solid title="Internal indicators">INTERNAL</Badge>;
      }

      return <Badge variant="default" size="xs" solid title="No IOCs">N/A</Badge>;
    }

    case 'correlation': {
      const corrCount = item.correlation_count;
      const corrGroup = item.correlation_group;

      if (!corrCount && !corrGroup) return <span className={styles.cellEmpty}>-</span>;

      if (corrCount > 0) {
        return (
          <Badge variant="info" size="xs" solid title={corrGroup || `${corrCount} correlated`}>
            {corrCount} linked
          </Badge>
        );
      }

      if (corrGroup) {
        return (
          <Badge variant="default" size="xs" solid title={corrGroup}>
            grouped
          </Badge>
        );
      }

      return <span className={styles.cellEmpty}>-</span>;
    }

    case 'confidence': {
      const confidence = item.ai_confidence;
      if (confidence == null) return <span className={styles.cellEmpty}>-</span>;
      const pct = confidence > 1 ? confidence : confidence * 100;
      return <span className={styles.cellConfidence}>{Math.round(pct)}%</span>;
    }

    case 'source':
      return <span className={styles.cellSource}>{item.source || '-'}</span>;

    case 'created_at':
      return <span className={styles.cellDate}>{formatDate(item.created_at)}</span>;

    case 'updated_at':
      return <span className={styles.cellDate}>{formatDate(item.updated_at)}</span>;

    default:
      return <span className={styles.cellEmpty}>-</span>;
  }
}

/**
 * QueueRow Component
 * @param {Object} props
 * @param {import('../types').SecurityQueueItem} props.item - Queue item to render
 * @param {string[]} props.columns - Column keys to render
 * @param {boolean} props.isSelected - Whether row is selected
 * @param {boolean} props.isActive - Whether row is active (drawer open)
 * @param {Function} props.onSelect - Selection handler
 * @param {Function} props.onClick - Row click handler
 */
function QueueRow({
  item,
  columns,
  isSelected,
  isActive,
  isFocused,
  onSelect,
  onClick,
}) {
  const handleCheckboxClick = (e) => {
    e.stopPropagation();
    onSelect?.(item.queue_id);
  };

  const handleRowClick = () => {
    onClick?.();
  };

  return (
    <tr
      className={`${styles.queueRow} ${isSelected ? styles.rowSelected : ''} ${isActive ? styles.rowActive : ''} ${isFocused ? styles.rowFocused : ''}`}
      data-type={item.item_type}
      data-severity={item.severity || 'unknown'}
      data-queue-id={item.queue_id}
      onClick={handleRowClick}
      tabIndex={isFocused ? 0 : -1}
      role="row"
    >
      {/* Selection checkbox */}
      <td className={styles.cellCheckbox}>
        <input
          type="checkbox"
          checked={isSelected}
          onChange={handleCheckboxClick}
          onClick={(e) => e.stopPropagation()}
          className={styles.checkbox}
        />
      </td>

      {/* Data columns */}
      {columns.map((colKey) => (
        <td key={colKey} className={styles[`col-${colKey}`]}>
          {renderCell(colKey, item)}
        </td>
      ))}
    </tr>
  );
}

export default React.memo(QueueRow);
