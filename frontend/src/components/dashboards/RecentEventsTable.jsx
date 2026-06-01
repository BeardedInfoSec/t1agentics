/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

/**
 * RecentEventsTable
 *
 * Shared "Recent Critical Events" table used by every SOC dashboard
 * (Overview / Operations / Management). Provides:
 *   - Column customizer (persisted per-dashboard via storageKey)
 *   - Inline preview drawer on row click (no full-page navigation)
 *   - Sensible defaults that surface the workflow status of each event
 */

import React, { useState, useMemo, useCallback } from 'react';
import Badge from '../ui/Badge';
import { severityToBadgeVariant } from '../../styles/colors';
import { ItemPreviewDrawer } from '../SecurityQueue';
import styles from '../Dashboard.module.css';
import { EmptyState } from './DashboardStates';
import { ARIA_LABELS } from './DashboardConfig';

// Column registry — each entry maps to a cell renderer. Keep keys lowercase;
// they're persisted to localStorage as part of user preferences.
const COLUMNS = [
  {
    key: 'severity',
    label: 'Severity',
    render: (a) => (
      <Badge variant={severityToBadgeVariant(a.severity)} size="xs" solid>
        {a.severity}
      </Badge>
    ),
  },
  {
    key: 'title',
    label: 'Title',
    className: 'tableTitle',
    render: (a) => a.title,
  },
  {
    key: 'state',
    label: 'State',
    className: 'tableMuted',
    render: (a) => (a.state ? prettify(a.state) : '-'),
  },
  {
    key: 'assignee',
    label: 'Assigned To',
    className: 'tableMuted',
    render: (a) => a.assignee || 'Unassigned',
  },
  {
    key: 'disposition',
    label: 'Disposition',
    className: 'tableMuted',
    render: (a) => (a.disposition ? prettify(a.disposition) : '-'),
  },
  {
    key: 'ai_confidence',
    label: 'AI Confidence',
    className: 'tableMuted',
    render: (a) => {
      if (a.ai_confidence == null) return '-';
      const pct = a.ai_confidence;
      // Tier the color so analysts can scan at a glance. Thresholds match
      // the Riggs auto-close convention (>=80 high confidence).
      const tier = pct >= 80 ? 'aiConfHigh' : pct >= 50 ? 'aiConfMed' : 'aiConfLow';
      return <span className={styles[tier]}>{pct}%</span>;
    },
  },
  {
    key: 'source',
    label: 'Source',
    className: 'tableMuted',
    render: (a) => a.source || '-',
  },
  {
    key: 'time',
    label: 'Time',
    className: 'tableMuted',
    render: (a) => a.time,
  },
];

const DEFAULT_VISIBLE = [
  'severity', 'title', 'state', 'assignee', 'disposition', 'ai_confidence', 'source', 'time',
];

function prettify(value) {
  if (!value) return '';
  return String(value)
    .replace(/_/g, ' ')
    .toLowerCase()
    .replace(/\b\w/g, (c) => c.toUpperCase());
}

function loadColumnPrefs(storageKey) {
  if (!storageKey) return DEFAULT_VISIBLE;
  try {
    const raw = localStorage.getItem(storageKey);
    if (!raw) return DEFAULT_VISIBLE;
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed) && parsed.length > 0) {
      // Filter to known columns only — drops stale keys after a redeploy
      // that renamed something.
      const known = new Set(COLUMNS.map((c) => c.key));
      const filtered = parsed.filter((k) => known.has(k));
      return filtered.length > 0 ? filtered : DEFAULT_VISIBLE;
    }
  } catch {
    /* fall through to defaults */
  }
  return DEFAULT_VISIBLE;
}

// Map an ExpandedContent field patch into the row shape used by this table.
// ExpandedContent emits queue-item-level keys (status, severity, owner,
// disposition, sensitivity); the dashboard row uses (state, severity,
// assignee, disposition). Translate so optimistic updates land in the right
// columns — otherwise edits in the drawer never visibly affect the table.
function patchToRowFields(patch) {
  const next = {};
  if (patch.status !== undefined) {
    // "status" here is the unified queue status — for closed-side states it
    // maps directly to our `state` column; otherwise also stash to alert
    // status for completeness.
    next.state = String(patch.status).toUpperCase();
    next.status = patch.status;
  }
  if (patch.severity !== undefined) {
    next.severity = String(patch.severity).charAt(0).toUpperCase() + String(patch.severity).slice(1);
  }
  if (patch.owner !== undefined) {
    next.assignee = patch.owner || null;
  }
  if (patch.disposition !== undefined) {
    next.disposition = patch.disposition;
  }
  if (patch.ai_confidence !== undefined) {
    const n = Number(patch.ai_confidence);
    if (!Number.isNaN(n)) next.ai_confidence = n <= 1 ? Math.round(n * 100) : Math.round(n);
  }
  return next;
}

function RecentEventsTable({
  alerts,
  emptyMessage = 'No critical events in this range',
  storageKey = 'dashboardRecentEventsColumns',
}) {
  const [visibleKeys, setVisibleKeys] = useState(() => loadColumnPrefs(storageKey));
  const [pickerOpen, setPickerOpen] = useState(false);
  const [preview, setPreview] = useState({ alertId: null, investigationId: null });
  // Optimistic patch store, keyed by alert_id. Applied on render so the
  // drawer's inline edits show up in the table immediately.
  const [overrides, setOverrides] = useState({});

  const visibleColumns = useMemo(
    () => COLUMNS.filter((c) => visibleKeys.includes(c.key)),
    [visibleKeys],
  );

  const toggleColumn = useCallback(
    (key) => {
      setVisibleKeys((prev) => {
        // Always keep at least one column visible — without this the table
        // collapses to a confusing empty grid.
        const isOn = prev.includes(key);
        let next;
        if (isOn) {
          if (prev.length === 1) return prev;
          next = prev.filter((k) => k !== key);
        } else {
          // Preserve canonical column order rather than append order.
          const canonical = COLUMNS.map((c) => c.key);
          next = canonical.filter((k) => prev.includes(k) || k === key);
        }
        try {
          localStorage.setItem(storageKey, JSON.stringify(next));
        } catch {
          /* localStorage may be disabled */
        }
        return next;
      });
    },
    [storageKey],
  );

  const openPreview = useCallback((alert) => {
    if (!alert?.alert_id && !alert?.investigation_id) return;
    setPreview({
      alertId: alert.alert_id || null,
      investigationId: alert.investigation_id || null,
    });
  }, []);

  const closePreview = useCallback(() => {
    setPreview({ alertId: null, investigationId: null });
  }, []);

  // Receive patches from the drawer. Merge into the alert_id-keyed override
  // map so subsequent renders show the analyst's edits without forcing a
  // backend refetch.
  const handleItemChange = useCallback(({ alertId: targetId, patch }) => {
    if (!targetId || !patch) return;
    const fields = patchToRowFields(patch);
    if (Object.keys(fields).length === 0) return;
    setOverrides((prev) => ({
      ...prev,
      [targetId]: { ...(prev[targetId] || {}), ...fields },
    }));
  }, []);

  // Apply any drawer-level overrides on top of the rows coming in via props.
  const visibleRows = useMemo(() => {
    if (!alerts) return [];
    if (Object.keys(overrides).length === 0) return alerts;
    return alerts.map((a) =>
      a.alert_id && overrides[a.alert_id]
        ? { ...a, ...overrides[a.alert_id] }
        : a,
    );
  }, [alerts, overrides]);

  if (!visibleRows || visibleRows.length === 0) {
    return <EmptyState type="alerts" message={emptyMessage} />;
  }

  return (
    <>
      <div className={styles.tableToolbar}>
        <div className={styles.tableToolbarSpacer} />
        <div className={styles.columnsPickerWrap}>
          <button
            type="button"
            className={styles.columnsPickerToggle}
            onClick={() => setPickerOpen((v) => !v)}
            aria-expanded={pickerOpen}
            aria-haspopup="true"
          >
            Columns ({visibleKeys.length})
          </button>
          {pickerOpen && (
            <>
              <div
                className={styles.columnsPickerBackdrop}
                onClick={() => setPickerOpen(false)}
                aria-hidden="true"
              />
              <div className={styles.columnsPickerMenu} role="menu">
                {COLUMNS.map((col) => (
                  <label key={col.key} className={styles.columnsPickerItem}>
                    <input
                      type="checkbox"
                      checked={visibleKeys.includes(col.key)}
                      onChange={() => toggleColumn(col.key)}
                    />
                    <span>{col.label}</span>
                  </label>
                ))}
              </div>
            </>
          )}
        </div>
      </div>

      <table className={styles.table} aria-label={ARIA_LABELS.dataTable}>
        <thead>
          <tr>
            {visibleColumns.map((col) => (
              <th scope="col" key={col.key}>
                {col.label}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {visibleRows.map((alert, idx) => (
            <tr
              key={alert.id || idx}
              className={`${styles.tableRow} ${styles.tableRowClickable}`}
              onClick={() => openPreview(alert)}
              onKeyDown={(e) => (e.key === 'Enter' || e.key === ' ') && openPreview(alert)}
              tabIndex={0}
              role="button"
              title="Preview details"
            >
              {visibleColumns.map((col) => (
                <td
                  key={col.key}
                  className={col.className ? styles[col.className] : undefined}
                >
                  {col.render(alert)}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>

      <ItemPreviewDrawer
        alertId={preview.alertId}
        investigationId={preview.investigationId}
        onClose={closePreview}
        onItemChange={handleItemChange}
      />
    </>
  );
}

export default RecentEventsTable;
