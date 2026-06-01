/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

import React, { useState, useEffect, useCallback } from 'react';
import { apiClient } from '../../utils/api';
import styles from './IOCActionButtons.module.css';

const ACTION_LABELS = {
  block_ip: 'Block IP',
  block_domain: 'Block Domain',
  block_url: 'Block URL',
  block_hash: 'Block Hash',
  isolate_host: 'Isolate Host',
  enrich_ip: 'Enrich',
  enrich_domain: 'Enrich',
  enrich_hash: 'Enrich',
  enrich_url: 'Enrich',
  disable_user: 'Disable User',
};

const ACTION_ICONS = {
  block: 'Block',
  enrich: 'Enrich',
  isolate: 'Isolate',
  disable: 'Disable',
};

function getActionLabel(actionType) {
  if (ACTION_LABELS[actionType]) return ACTION_LABELS[actionType];
  for (const [prefix, label] of Object.entries(ACTION_ICONS)) {
    if (actionType?.startsWith(prefix)) return label;
  }
  return actionType?.replace(/_/g, ' ') || 'Action';
}

function getActionCategory(actionType) {
  if (actionType?.startsWith('block')) return 'block';
  if (actionType?.startsWith('enrich')) return 'enrich';
  if (actionType?.startsWith('isolate')) return 'isolate';
  if (actionType?.startsWith('disable')) return 'disable';
  return 'default';
}

/**
 * IOCActionButtons -- compact inline action buttons for a single IOC.
 * Fetches available actions from the tenant's connected integrations
 * and allows one-touch execution.
 *
 * @param {string} iocType         - IOC type (ip, domain, hash, url, email)
 * @param {string} iocValue        - The IOC value
 * @param {string} investigationId - UUID of the current investigation
 * @param {string} [compact]       - If true, render smaller buttons
 */
export default function IOCActionButtons({ iocType, iocValue, investigationId, compact = false }) {
  const [actions, setActions] = useState([]);
  const [loading, setLoading] = useState(true);
  const [executingIds, setExecutingIds] = useState(new Set());
  const [results, setResults] = useState({}); // actionKey -> 'success' | 'failed'

  const fetchAvailable = useCallback(async () => {
    if (!iocType || !iocValue || !investigationId) {
      setLoading(false);
      return;
    }
    try {
      const res = await apiClient.get('/api/v1/recommended-actions/available', {
        params: { ioc_type: iocType, ioc_value: iocValue, investigation_id: investigationId },
      });
      setActions(res.data?.actions || []);
    } catch (err) {
      // No actions available is fine
      setActions([]);
    } finally {
      setLoading(false);
    }
  }, [iocType, iocValue, investigationId]);

  useEffect(() => {
    fetchAvailable();
  }, [fetchAvailable]);

  const handleExecute = async (action) => {
    const actionKey = `${action.action_type}-${action.instance_id}`;
    setExecutingIds(prev => new Set([...prev, actionKey]));

    try {
      await apiClient.post('/api/v1/recommended-actions/execute-instant', {
        investigation_id: investigationId,
        ioc_type: iocType,
        ioc_value: iocValue,
        action_type: action.action_type,
        instance_id: action.instance_id,
      });
      setResults(prev => ({ ...prev, [actionKey]: 'success' }));
    } catch (err) {
      setResults(prev => ({ ...prev, [actionKey]: 'failed' }));
    } finally {
      setExecutingIds(prev => {
        const next = new Set(prev);
        next.delete(actionKey);
        return next;
      });
    }
  };

  if (loading) return null;
  if (actions.length === 0) return null;

  return (
    <div className={`${styles.actionButtons} ${compact ? styles.compact : ''}`}>
      {actions.map((action) => {
        const actionKey = `${action.action_type}-${action.instance_id}`;
        const isExecuting = executingIds.has(actionKey);
        const result = results[actionKey];
        const category = getActionCategory(action.action_type);

        if (result === 'success') {
          return (
            <span key={actionKey} className={`${styles.actionResult} ${styles.actionResultSuccess}`}>
              Done
            </span>
          );
        }

        if (result === 'failed') {
          return (
            <button
              key={actionKey}
              className={`${styles.actionBtn} ${styles.actionBtnFailed}`}
              onClick={() => {
                setResults(prev => { const n = { ...prev }; delete n[actionKey]; return n; });
              }}
              title="Click to retry"
            >
              Failed - Retry
            </button>
          );
        }

        return (
          <button
            key={actionKey}
            className={`${styles.actionBtn} ${styles[`actionBtn_${category}`] || ''}`}
            onClick={() => handleExecute(action)}
            disabled={isExecuting}
            title={`${getActionLabel(action.action_type)} via ${action.connector_name || action.instance_name || 'integration'}`}
          >
            {isExecuting ? (
              <span className={styles.actionSpinner} />
            ) : (
              <>
                {getActionLabel(action.action_type)}
                {action.connector_name && (
                  <span className={styles.actionVia}> via {action.connector_name}</span>
                )}
              </>
            )}
          </button>
        );
      })}
    </div>
  );
}
