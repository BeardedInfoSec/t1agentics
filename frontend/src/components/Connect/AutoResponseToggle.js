/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

import React, { useState, useEffect, useCallback } from 'react';
import { apiClient } from '../../utils/api';
import styles from './AutoResponseToggle.module.css';

/**
 * All known action types that can be individually toggled.
 * Destructive actions (block, isolate, disable) show a warning modal.
 * Enrichment actions toggle without a warning.
 */
const ACTION_TYPES = [
  { id: 'block_ip',       label: 'Block IP',        destructive: true },
  { id: 'block_domain',   label: 'Block Domain',    destructive: true },
  { id: 'block_url',      label: 'Block URL',       destructive: true },
  { id: 'block_hash',     label: 'Block Hash',      destructive: true },
  { id: 'isolate_host',   label: 'Isolate Host',    destructive: true },
  { id: 'disable_user',   label: 'Disable User',    destructive: true },
  { id: 'enrich_ip',      label: 'Enrich IP',       destructive: false },
  { id: 'enrich_domain',  label: 'Enrich Domain',   destructive: false },
  { id: 'enrich_hash',    label: 'Enrich Hash',     destructive: false },
];

/**
 * AutoResponseToggle -- per-integration auto-response controls with
 * granular per-action-type toggles underneath a master toggle.
 *
 * @param {string}   instanceId           - Connect instance UUID
 * @param {boolean}  initialEnabled       - Current global auto-response state
 * @param {string}   connectorName        - Display name of the connector
 * @param {function} [onToggle]           - Callback after successful global toggle (receives new state)
 * @param {boolean}  [isAdmin]            - Whether current user is admin (toggle hidden if not)
 */
export default function AutoResponseToggle({
  instanceId,
  initialEnabled = false,
  connectorName,
  onToggle,
  isAdmin = false,
}) {
  const [globalEnabled, setGlobalEnabled] = useState(initialEnabled);
  const [actionSettings, setActionSettings] = useState({});
  const [saving, setSaving] = useState(false);
  const [savingAction, setSavingAction] = useState(null);
  const [showWarning, setShowWarning] = useState(false);
  const [pendingAction, setPendingAction] = useState(null);
  const [expanded, setExpanded] = useState(false);

  // Fetch per-action settings on mount
  const fetchSettings = useCallback(async () => {
    try {
      const res = await apiClient.get(
        `/api/v1/connect/instances/${instanceId}/auto-response`
      );
      const data = res.data || res;
      if (data.action_settings) {
        setActionSettings(data.action_settings);
      }
      if (typeof data.auto_response_enabled === 'boolean') {
        setGlobalEnabled(data.auto_response_enabled);
      }
    } catch (err) {
      console.error('[AutoResponseToggle] fetch settings error:', err);
    }
  }, [instanceId]);

  useEffect(() => {
    if (isAdmin && instanceId) {
      fetchSettings();
    }
  }, [isAdmin, instanceId, fetchSettings]);

  if (!isAdmin) return null;

  // -- Global toggle --------------------------------------------------------

  const handleGlobalToggle = () => {
    if (!globalEnabled) {
      // Enabling global: show warning
      setPendingAction(null);
      setShowWarning(true);
    } else {
      doGlobalToggle(false);
    }
  };

  const doGlobalToggle = async (newState) => {
    setSaving(true);
    try {
      await apiClient.patch(
        `/api/v1/connect/instances/${instanceId}/auto-response`,
        { enabled: newState }
      );
      setGlobalEnabled(newState);
      setShowWarning(false);
      onToggle?.(newState);
    } catch (err) {
      console.error('[AutoResponseToggle] global toggle error:', err);
    } finally {
      setSaving(false);
    }
  };

  // -- Per-action toggle ----------------------------------------------------

  const handleActionToggle = (actionType, isDestructive) => {
    const currentlyEnabled = !!actionSettings[actionType];
    if (!currentlyEnabled && isDestructive) {
      // Enabling a destructive action: show warning
      setPendingAction(actionType);
      setShowWarning(true);
    } else {
      doActionToggle(actionType, !currentlyEnabled);
    }
  };

  const doActionToggle = async (actionType, newState) => {
    setSavingAction(actionType);
    try {
      await apiClient.patch(
        `/api/v1/connect/instances/${instanceId}/auto-response`,
        { enabled: newState, action_type: actionType }
      );
      setActionSettings((prev) => ({ ...prev, [actionType]: newState }));
      setShowWarning(false);
      setPendingAction(null);
    } catch (err) {
      console.error('[AutoResponseToggle] action toggle error:', err);
    } finally {
      setSavingAction(null);
    }
  };

  // -- Warning modal confirm ------------------------------------------------

  const handleWarningConfirm = () => {
    if (pendingAction) {
      doActionToggle(pendingAction, true);
    } else {
      doGlobalToggle(true);
    }
  };

  const warningActionLabel = pendingAction
    ? ACTION_TYPES.find((a) => a.id === pendingAction)?.label || pendingAction
    : null;

  return (
    <>
      <div className={styles.container}>
        {/* Master toggle */}
        <div className={styles.toggleRow}>
          <div className={styles.toggleInfo}>
            <div className={styles.toggleLabel}>Auto-Response</div>
            <div className={styles.toggleDesc}>
              Allow Riggs to execute actions automatically
            </div>
          </div>
          <button
            className={`${styles.toggle} ${globalEnabled ? styles.toggleOn : styles.toggleOff}`}
            onClick={handleGlobalToggle}
            disabled={saving}
            role="switch"
            aria-checked={globalEnabled}
            aria-label={`Auto-response ${globalEnabled ? 'enabled' : 'disabled'} for ${connectorName}`}
          >
            <span className={styles.toggleKnob} />
          </button>
        </div>

        {/* Per-action toggles (collapsible) */}
        {globalEnabled && (
          <>
            <button
              className={styles.expandBtn}
              onClick={() => setExpanded(!expanded)}
              type="button"
            >
              {expanded ? 'Hide' : 'Show'} per-action settings
              <span className={`${styles.expandArrow} ${expanded ? styles.expandArrowOpen : ''}`}>
                &#9662;
              </span>
            </button>

            {expanded && (
              <div className={styles.actionList}>
                {ACTION_TYPES.map((action) => {
                  const isOn = !!actionSettings[action.id];
                  const isSaving = savingAction === action.id;
                  return (
                    <div key={action.id} className={styles.actionRow}>
                      <div className={styles.actionInfo}>
                        <span className={styles.actionLabel}>{action.label}</span>
                        {action.destructive && (
                          <span className={styles.destructiveBadge}>response</span>
                        )}
                      </div>
                      <button
                        className={`${styles.actionToggle} ${isOn ? styles.actionToggleOn : styles.actionToggleOff}`}
                        onClick={() => handleActionToggle(action.id, action.destructive)}
                        disabled={isSaving}
                        role="switch"
                        aria-checked={isOn}
                        aria-label={`${action.label} auto-response ${isOn ? 'enabled' : 'disabled'}`}
                      >
                        <span className={styles.actionToggleKnob} />
                      </button>
                    </div>
                  );
                })}
                <div className={styles.actionNote}>
                  Per-action settings override the master toggle for that specific action type.
                  Actions without a per-action setting use the master toggle.
                </div>
              </div>
            )}
          </>
        )}
      </div>

      {/* Warning Modal */}
      {showWarning && (
        <div className={styles.warningOverlay} onClick={() => { setShowWarning(false); setPendingAction(null); }}>
          <div className={styles.warningModal} onClick={(e) => e.stopPropagation()}>
            <div className={styles.warningHeader}>
              <span className={styles.warningIcon}>!</span>
              {pendingAction
                ? `Enable Auto-Response: ${warningActionLabel}`
                : 'Enable Auto-Response'
              }
            </div>
            <div className={styles.warningBody}>
              {pendingAction ? (
                <>
                  <p>
                    Enabling auto-response for <strong>{warningActionLabel}</strong> on
                    <strong> {connectorName}</strong> allows Riggs to execute this action
                    automatically when threats are detected.
                  </p>
                  <p>
                    This action will <strong>NOT</strong> require analyst approval
                    before execution.
                  </p>
                </>
              ) : (
                <>
                  <p>
                    Enabling auto-response allows Riggs to execute actions through
                    <strong> {connectorName}</strong> automatically when threats are
                    detected.
                  </p>
                  <p>
                    Actions are logged but will <strong>NOT</strong> require analyst
                    approval before execution.
                  </p>
                </>
              )}
              <p className={styles.warningNote}>
                Only enable this for integrations you trust to take automated
                response actions in your environment.
              </p>
            </div>
            <div className={styles.warningActions}>
              <button
                className={styles.warningCancel}
                onClick={() => { setShowWarning(false); setPendingAction(null); }}
                disabled={saving || savingAction}
              >
                Cancel
              </button>
              <button
                className={styles.warningConfirm}
                onClick={handleWarningConfirm}
                disabled={saving || savingAction}
              >
                {(saving || savingAction) ? 'Enabling...' : 'Enable'}
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
