/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

/**
 * ItemPreviewDrawer
 *
 * Self-contained side drawer that fetches an alert (and its linked
 * investigation, if any), normalizes into a SecurityQueueItem, and renders
 * the same ExpandedContent used inside the triage queue. Lets dashboards
 * pop a preview without sending the user to /queue.
 *
 * Props:
 *   alertId         — alert_id to preview (required if investigationId absent)
 *   investigationId — investigation_id to preview (optional)
 *   onClose         — called when the user dismisses the drawer
 */

import React, { useEffect, useState, useCallback } from 'react';
import Drawer from '../../ui/Drawer';
import ExpandedContent from '../ExpandedContent/ExpandedContent';
import { normalizeAlert, normalizeInvestigation } from '../transforms';
import { getAuthHeaders, API_BASE_URL } from '../../../utils/api';
import styles from '../SecurityQueue.module.css';

function ItemPreviewDrawer({ alertId, investigationId, onClose, onItemChange }) {
  const isOpen = Boolean(alertId || investigationId);
  const [item, setItem] = useState(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!isOpen) {
      setItem(null);
      return undefined;
    }

    let cancelled = false;
    const run = async () => {
      setLoading(true);
      try {
        let alert = null;
        let inv = null;

        if (alertId) {
          const r = await fetch(`${API_BASE_URL}/api/v1/alerts/${alertId}`, {
            headers: getAuthHeaders(),
          });
          if (r.ok) alert = await r.json();
        }

        const invIdToFetch = investigationId || alert?.investigation_id;
        if (invIdToFetch) {
          const r = await fetch(`${API_BASE_URL}/api/v1/investigations/${invIdToFetch}`, {
            headers: getAuthHeaders(),
          });
          if (r.ok) inv = await r.json();
        }

        if (cancelled) return;

        let built = null;
        if (inv) {
          built = normalizeInvestigation(inv, alert);
          // Inject the freshly-fetched contexts so ExpandedContent has the
          // full raw_event / enrichment payload to render against.
          built.investigation_context = { ...(built.investigation_context || {}), ...inv };
          if (alert) built.alert_context = { ...(built.alert_context || {}), ...alert };
        } else if (alert) {
          built = normalizeAlert(alert);
          built.alert_context = { ...(built.alert_context || {}), ...alert };
        }

        setItem(built);
      } catch (err) {
        if (!cancelled) setItem(null);
      } finally {
        if (!cancelled) setLoading(false);
      }
    };

    run();
    return () => {
      cancelled = true;
    };
  }, [alertId, investigationId, isOpen]);

  // Edits made via the inline dropdowns in ExpandedContent fire onFieldUpdate
  // with the patched fields. We mirror the patch onto our local `item` so the
  // drawer stays consistent, and propagate it up so the host (dashboard table)
  // can repaint without waiting for a full refetch.
  const handleFieldUpdate = useCallback((patch) => {
    if (!patch) return;
    setItem((prev) => (prev ? { ...prev, ...patch } : prev));
    if (onItemChange && (alertId || investigationId)) {
      onItemChange({
        alertId: alertId || null,
        investigationId: investigationId || null,
        patch,
      });
    }
  }, [alertId, investigationId, onItemChange]);

  return (
    <Drawer
      isOpen={isOpen}
      onClose={onClose}
      title={item ? item.title || 'Details' : loading ? 'Loading...' : 'Details'}
      size={item?.item_type === 'investigation' ? 'xl' : 'lg'}
      position="right"
    >
      <Drawer.Body>
        {loading ? (
          <div className={styles.expandedLoading}>
            <div className={styles.loadingSpinner} />
            <span>Loading details...</span>
          </div>
        ) : item ? (
          <ExpandedContent
            item={item}
            onRefresh={() => {}}
            onFieldUpdate={handleFieldUpdate}
          />
        ) : (
          <div className={styles.expandedLoading}>
            <span>Could not load this item.</span>
          </div>
        )}
      </Drawer.Body>
    </Drawer>
  );
}

export default ItemPreviewDrawer;
