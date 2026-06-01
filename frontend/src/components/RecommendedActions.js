/**
 * Copyright (c) 2025-2026 T1 Agentics LLC. SPDX-License-Identifier: Apache-2.0
 *
 * RecommendedActions - Displays Riggs-generated action recommendations within investigations.
 * Analysts can approve (execute) or dismiss each recommendation with one click.
 */

import React, { useState, useEffect, useCallback } from 'react';
import * as recApi from '../services/recommended-actions-api';
import './RecommendedActions.css';

const PRIORITY_ORDER = { high: 0, medium: 1, low: 2 };

const STATUS_CONFIG = {
  pending:   { label: 'Pending',   className: 'ra-status--pending' },
  approved:  { label: 'Approved',  className: 'ra-status--approved' },
  executing: { label: 'Running',   className: 'ra-status--executing' },
  completed: { label: 'Done',      className: 'ra-status--completed' },
  failed:    { label: 'Failed',    className: 'ra-status--failed' },
  dismissed: { label: 'Dismissed', className: 'ra-status--dismissed' },
};

const ACTION_ICONS = {
  enrich: 'search',
  block:  'shield',
  isolate: 'lock',
  disable: 'user-x',
};

function getActionIcon(actionType) {
  for (const [key, icon] of Object.entries(ACTION_ICONS)) {
    if (actionType?.startsWith(key)) return icon;
  }
  return 'zap';
}

function RecommendedActions({ investigation, embedded = false }) {
  const [actions, setActions] = useState([]);
  const [loading, setLoading] = useState(true);
  const [generating, setGenerating] = useState(false);
  const [error, setError] = useState(null);
  const [processingIds, setProcessingIds] = useState(new Set());

  const investigationId = investigation?.investigation_id || investigation?.id;

  const fetchActions = useCallback(async () => {
    if (!investigationId) return;
    try {
      const data = await recApi.getActions(investigationId);
      setActions(data.actions || []);
      setError(null);
    } catch (err) {
      // 404 or no table yet is fine -- just show empty
      if (err?.response?.status !== 404) {
        setError('Failed to load recommendations');
      }
      setActions([]);
    } finally {
      setLoading(false);
    }
  }, [investigationId]);

  useEffect(() => {
    fetchActions();
  }, [fetchActions]);

  // Poll for status updates when there are executing actions
  useEffect(() => {
    const hasActive = actions.some(a => a.status === 'executing' || a.status === 'approved');
    if (!hasActive) return;
    const interval = setInterval(fetchActions, 3000);
    return () => clearInterval(interval);
  }, [actions, fetchActions]);

  const handleGenerate = useCallback(async () => {
    if (!investigationId) return;
    setGenerating(true);
    try {
      const result = await recApi.generateActions(investigationId);
      if (result?.actions) {
        setActions(result.actions);
      } else {
        await fetchActions();
      }
      setError(null);
    } catch (err) {
      setError(err?.response?.data?.detail || 'Failed to generate recommendations');
    } finally {
      setGenerating(false);
    }
  }, [investigationId, fetchActions]);

  // Auto-generate recommendations when analysis exists but no actions loaded yet
  const [autoGenAttempted, setAutoGenAttempted] = useState(false);
  useEffect(() => {
    if (autoGenAttempted || loading || generating || actions.length > 0) return;
    const invData = investigation?.investigation_data || {};
    const hasAnalysis = invData.riggs_analysis
      || invData.tier1_analysis || invData.tier2_analysis
      || invData.tier3_analysis || invData.riggs_deep_analysis
      || investigation?.riggs_analysis;
    if (hasAnalysis && investigationId) {
      setAutoGenAttempted(true);
      handleGenerate();
    }
  }, [loading, actions, investigation, investigationId, autoGenAttempted, generating, handleGenerate]);

  const handleApprove = async (actionId) => {
    setProcessingIds(prev => new Set(prev).add(actionId));
    try {
      await recApi.approveAction(actionId);
      await fetchActions();
    } catch (err) {
      setError(err?.response?.data?.detail || 'Failed to approve action');
    } finally {
      setProcessingIds(prev => {
        const next = new Set(prev);
        next.delete(actionId);
        return next;
      });
    }
  };

  const handleDismiss = async (actionId) => {
    setProcessingIds(prev => new Set(prev).add(actionId));
    try {
      await recApi.dismissAction(actionId);
      await fetchActions();
    } catch (err) {
      setError(err?.response?.data?.detail || 'Failed to dismiss action');
    } finally {
      setProcessingIds(prev => {
        const next = new Set(prev);
        next.delete(actionId);
        return next;
      });
    }
  };

  // Don't render if no investigation
  if (!investigationId) return null;

  const pendingActions = actions.filter(a => a.status === 'pending');
  const processedActions = actions.filter(a => a.status !== 'pending');
  const invData = investigation?.investigation_data || {};
  const hasRiggsAnalysis = invData.riggs_analysis
    || invData.tier1_analysis
    || invData.tier2_analysis
    || invData.tier3_analysis
    || invData.riggs_deep_analysis
    || investigation?.riggs_analysis;

  // Embedded mode: hide completely when no actions
  if (embedded && !loading && !generating && actions.length === 0) {
    return null;
  }

  return (
    <div className={`ra-container ${embedded ? 'ra-container--embedded' : ''}`}>
      {!embedded && (
      <div className="ra-header">
        <div className="ra-header__left">
          <h3 className="ra-title">Recommended Actions</h3>
          {pendingActions.length > 0 && (
            <span className="ra-badge">{pendingActions.length}</span>
          )}
        </div>
        {generating && (
          <span className="ra-generating-text" style={{ fontSize: '12px', opacity: 0.7 }}>Analyzing connectors...</span>
        )}
      </div>
      )}

      {embedded && actions.length > 0 && (
        <div style={{ fontSize: '0.6875rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '0.5rem' }}>
          Connector Actions
          {pendingActions.length > 0 && (
            <span className="ra-badge" style={{ marginLeft: '0.5rem' }}>{pendingActions.length}</span>
          )}
        </div>
      )}

      {error && <div className="ra-error">{error}</div>}

      {loading && (
        <div className="ra-loading">
          <div className="ra-loading__bar" />
          <div className="ra-loading__bar" />
        </div>
      )}

      {!embedded && !loading && !generating && actions.length === 0 && (
        <div className="ra-empty">
          {autoGenAttempted
            ? 'No actionable recommendations for this investigation. No matching IOCs or connectors found.'
            : hasRiggsAnalysis
              ? 'Generating recommendations...'
              : 'Recommendations will appear after Riggs analysis completes.'
          }
        </div>
      )}

      {/* Pending actions -- show first 5, collapse rest */}
      {pendingActions.length > 0 && (() => {
        const sorted = pendingActions.sort((a, b) => (PRIORITY_ORDER[a.priority] ?? 2) - (PRIORITY_ORDER[b.priority] ?? 2));
        const visible = sorted.slice(0, 5);
        const hidden = sorted.slice(5);
        return (
          <>
            <div className="ra-list">
              {visible.map(action => (
                <ActionCard
                  key={action.id}
                  action={action}
                  processing={processingIds.has(action.id)}
                  onApprove={handleApprove}
                  onDismiss={handleDismiss}
                />
              ))}
            </div>
            {hidden.length > 0 && (
              <details className="ra-processed" style={{ marginTop: '0.25rem' }}>
                <summary className="ra-processed__summary">
                  {hidden.length} more pending action{hidden.length !== 1 ? 's' : ''}
                </summary>
                <div className="ra-list">
                  {hidden.map(action => (
                    <ActionCard
                      key={action.id}
                      action={action}
                      processing={processingIds.has(action.id)}
                      onApprove={handleApprove}
                      onDismiss={handleDismiss}
                    />
                  ))}
                </div>
              </details>
            )}
          </>
        );
      })()}

      {/* Processed actions -- collapsed */}
      {processedActions.length > 0 && (
        <details className="ra-processed">
          <summary className="ra-processed__summary">
            {processedActions.length} processed action{processedActions.length !== 1 ? 's' : ''}
          </summary>
          <div className="ra-list ra-list--processed">
            {processedActions.map(action => (
              <ActionCard
                key={action.id}
                action={action}
                processing={false}
                onApprove={null}
                onDismiss={null}
              />
            ))}
          </div>
        </details>
      )}
    </div>
  );
}


function ActionCard({ action, processing, onApprove, onDismiss }) {
  const statusCfg = STATUS_CONFIG[action.status] || STATUS_CONFIG.pending;
  const isPending = action.status === 'pending';
  const isDestructive = action.action_type && !action.action_type.startsWith('enrich');
  const icon = getActionIcon(action.action_type);

  return (
    <div className={`ra-card ${statusCfg.className} ${isDestructive ? 'ra-card--destructive' : ''}`}>
      <div className="ra-card__icon">
        <ActionIcon name={icon} />
      </div>
      <div className="ra-card__body">
        <div className="ra-card__title">{action.title}</div>
        <div className="ra-card__meta">
          <span className={`ra-priority ra-priority--${action.priority}`}>
            {action.priority}
          </span>
          {action.connector_name && (
            <span className="ra-card__connector">{action.connector_name}</span>
          )}
          {action.ioc_value && (
            <code className="ra-card__ioc">{action.ioc_value}</code>
          )}
        </div>
        {action.status === 'failed' && action.execution_result?.error && (
          <div className="ra-card__error">{action.execution_result.error}</div>
        )}
      </div>
      <div className="ra-card__actions">
        {isPending && onApprove && (
          <>
            <button
              className={`ra-btn ra-btn--approve ${isDestructive ? 'ra-btn--confirm' : ''}`}
              onClick={() => onApprove(action.id)}
              disabled={processing}
              title={isDestructive ? 'This action modifies external systems' : 'Approve and execute'}
            >
              {processing ? '...' : isDestructive ? 'Approve' : 'Run'}
            </button>
            <button
              className="ra-btn ra-btn--dismiss"
              onClick={() => onDismiss(action.id)}
              disabled={processing}
              title="Dismiss this recommendation"
            >
              Dismiss
            </button>
          </>
        )}
        {action.status === 'executing' && (
          <span className="ra-executing-indicator" />
        )}
        {!isPending && (
          <span className={`ra-status-badge ${statusCfg.className}`}>
            {statusCfg.label}
          </span>
        )}
      </div>
    </div>
  );
}


function ActionIcon({ name }) {
  const icons = {
    search: (
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <circle cx="11" cy="11" r="8" /><path d="M21 21l-4.35-4.35" />
      </svg>
    ),
    shield: (
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
      </svg>
    ),
    lock: (
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <rect x="3" y="11" width="18" height="11" rx="2" ry="2" /><path d="M7 11V7a5 5 0 0 1 10 0v4" />
      </svg>
    ),
    'user-x': (
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M16 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2" /><circle cx="8.5" cy="7" r="4" /><line x1="18" y1="8" x2="23" y2="13" /><line x1="23" y1="8" x2="18" y2="13" />
      </svg>
    ),
    zap: (
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2" />
      </svg>
    ),
  };
  return icons[name] || icons.zap;
}


export default RecommendedActions;
