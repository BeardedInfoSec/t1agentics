/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

/**
 * BulkActionsBar Component
 *
 * Displays when items are selected and provides bulk action options.
 * Supports: Close, Assign, Change Status, Change Severity, Delete (admin only, password required)
 */

import React, { useState } from 'react';
import { authFetch, API_BASE_URL } from '../../../utils/api';
import { telemetry } from '../../../utils/telemetry';
import { usePermissions } from '../../../hooks/usePermissions';
import styles from '../SecurityQueue.module.css';

const STATUS_OPTIONS = [
  { value: 'open', label: 'Open' },
  { value: 'investigating', label: 'Investigating' },
  { value: 'in_progress', label: 'In Progress' },
  { value: 'needs_review', label: 'Needs Review' },
  { value: 'resolved', label: 'Resolved' },
  { value: 'closed', label: 'Closed' },
];

const SEVERITY_OPTIONS = [
  { value: 'critical', label: 'Critical' },
  { value: 'high', label: 'High' },
  { value: 'medium', label: 'Medium' },
  { value: 'low', label: 'Low' },
  { value: 'informational', label: 'Informational' },
];

/**
 * BulkActionsBar Component
 */
function BulkActionsBar({
  selectedIds,
  items,
  onClearSelection,
  onActionComplete,
}) {
  const [isProcessing, setIsProcessing] = useState(false);
  const [showStatusDropdown, setShowStatusDropdown] = useState(false);
  const [showSeverityDropdown, setShowSeverityDropdown] = useState(false);
  const [showConfirmDelete, setShowConfirmDelete] = useState(false);
  const [deletePassword, setDeletePassword] = useState('');
  const [deletePasswordError, setDeletePasswordError] = useState('');
  const [verifyingPassword, setVerifyingPassword] = useState(false);
  const [actionResult, setActionResult] = useState(null);
  const [errorsExpanded, setErrorsExpanded] = useState(false);

  const { isAdmin } = usePermissions();

  // Get selected items with their types
  const selectedItems = items.filter(item => selectedIds.includes(item.queue_id));
  const alertCount = selectedItems.filter(i => i.item_type === 'alert').length;
  const investigationCount = selectedItems.filter(i => i.item_type === 'investigation').length;

  // Debug: log selected items structure
  console.log('[DEBUG] Selected items:', selectedItems.map(i => ({
    queue_id: i.queue_id,
    item_type: i.item_type,
    alert_id: i.alert_id,
    investigation_id: i.investigation_id,
  })));

  // Execute bulk action on all selected items
  const executeBulkAction = async (action, value = null) => {
    setIsProcessing(true);
    setActionResult(null);
    setErrorsExpanded(false);

    const results = { success: 0, failed: 0, errors: [] };

    // Split selected items by type
    const alerts = selectedItems.filter(i => i.item_type === 'alert');
    const investigations = selectedItems.filter(i => i.item_type === 'investigation');

    // Build updates object based on action
    let alertUpdates = {};
    let invUpdates = {};
    let isDelete = false;

    switch (action) {
      case 'close':
        alertUpdates = { status: 'closed' };
        invUpdates = { state: 'CLOSED' };
        break;
      case 'resolve':
        alertUpdates = { status: 'resolved' };
        invUpdates = { state: 'RESOLVED' };
        break;
      case 'status':
        // Map to correct field names per type
        // Alert statuses are lowercase; investigation states are uppercase
        alertUpdates = { status: value.toLowerCase() };
        invUpdates = { state: value.toUpperCase() };
        break;
      case 'severity':
        alertUpdates = { severity: value.toLowerCase() };
        invUpdates = { severity: value.toLowerCase() };
        break;
      case 'assign':
        invUpdates = { owner: value || 'current_user' };
        break;
      case 'delete':
        isDelete = true;
        break;
      default:
        break;
    }

    // Bulk update alerts
    if (alerts.length > 0 && !isDelete) {
      try {
        const alertIds = alerts.map(a => a.alert_id);
        const requestBody = { alert_ids: alertIds, updates: alertUpdates };
        console.log('[BULK-UPDATE] Alerts request:', requestBody);
        const res = await authFetch(`${API_BASE_URL}/api/v1/alerts/bulk-update`, {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(requestBody),
        });
        if (res.ok) {
          const data = await res.json().catch(() => ({}));
          const updated = data.updated_count ?? 0;
          results.success += updated;
        } else {
          const errorData = await res.json().catch(() => ({}));
          results.failed += alerts.length;
          results.errors.push(`Alerts: ${errorData.detail || res.statusText}`);
        }
      } catch (error) {
        results.failed += alerts.length;
        results.errors.push(`Alerts: ${error.message}`);
      }
    }

    // Bulk update investigations
    if (investigations.length > 0 && !isDelete) {
      try {
        const invIds = investigations.map(i => i.investigation_id);
        const requestBody = { investigation_ids: invIds, updates: invUpdates };
        console.log('[BULK-UPDATE] Investigations request:', requestBody);
        const res = await authFetch(`${API_BASE_URL}/api/v1/investigations/bulk-update`, {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(requestBody),
        });
        if (res.ok) {
          const data = await res.json().catch(() => ({}));
          const updated = data.updated_count ?? 0;
          results.success += updated;
        } else {
          const errorData = await res.json().catch(() => ({}));
          results.failed += investigations.length;
          results.errors.push(`Investigations: ${errorData.detail || res.statusText}`);
        }
      } catch (error) {
        results.failed += investigations.length;
        results.errors.push(`Investigations: ${error.message}`);
      }
    }

    // Handle deletes individually (no bulk delete endpoint)
    if (isDelete) {
      for (const item of selectedItems) {
        try {
          const endpoint = item.item_type === 'alert'
            ? `${API_BASE_URL}/api/v1/alerts/${item.alert_id}`
            : `${API_BASE_URL}/api/v1/investigations/${item.investigation_id}`;
          const res = await authFetch(endpoint, { method: 'DELETE' });
          if (res.ok) {
            results.success++;
          } else {
            results.failed++;
            const errorData = await res.json().catch(() => ({}));
            results.errors.push(`${item.title || item.queue_id}: ${errorData.detail || res.statusText}`);
          }
        } catch (error) {
          results.failed++;
          results.errors.push(`${item.title || item.queue_id}: ${error.message}`);
        }
      }
    }

    setIsProcessing(false);
    setActionResult(results);
    telemetry.track('queue', 'queue.bulk_action', { action, count: selectedItems.length, success: results.success, failed: results.failed });

    // Always refetch when there are successful updates
    if (results.success > 0) {
      onActionComplete?.();
    }

    // Auto-clear only when no failures; when failures exist, keep message for user review
    if (results.failed === 0 && results.success > 0) {
      setTimeout(() => {
        setActionResult(null);
        onClearSelection();
      }, 2000);
    }
  };

  const handleClose = () => executeBulkAction('close');
  const handleResolve = () => executeBulkAction('resolve');
  const handleStatusChange = (status) => {
    setShowStatusDropdown(false);
    executeBulkAction('status', status);
  };
  const handleSeverityChange = (severity) => {
    setShowSeverityDropdown(false);
    executeBulkAction('severity', severity);
  };

  // Delete requires password verification
  const handleDeleteWithPassword = async () => {
    if (!deletePassword.trim()) {
      setDeletePasswordError('Password is required');
      return;
    }

    setVerifyingPassword(true);
    setDeletePasswordError('');

    try {
      const res = await authFetch(`${API_BASE_URL}/api/v1/admin/verify-password`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password: deletePassword }),
      });

      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        setDeletePasswordError(data.detail || 'Incorrect password');
        setVerifyingPassword(false);
        return;
      }

      // Password verified - proceed with delete
      setVerifyingPassword(false);
      setShowConfirmDelete(false);
      setDeletePassword('');
      setDeletePasswordError('');
      executeBulkAction('delete');
    } catch (error) {
      setDeletePasswordError('Failed to verify password');
      setVerifyingPassword(false);
    }
  };

  const closeDeleteConfirm = () => {
    setShowConfirmDelete(false);
    setDeletePassword('');
    setDeletePasswordError('');
  };

  if (selectedIds.length === 0) return null;

  return (
    <div className={styles.bulkActionsBar}>
      <div className={styles.selectionInfo}>
        <span className={styles.selectionCount}>
          {selectedIds.length} item{selectedIds.length > 1 ? 's' : ''} selected
        </span>
        {(alertCount > 0 || investigationCount > 0) && (
          <span className={styles.selectionBreakdown}>
            ({alertCount > 0 && `${alertCount} alert${alertCount > 1 ? 's' : ''}`}
            {alertCount > 0 && investigationCount > 0 && ', '}
            {investigationCount > 0 && `${investigationCount} investigation${investigationCount > 1 ? 's' : ''}`})
          </span>
        )}
      </div>

      {/* Action Result Message */}
      {actionResult && (
        <div className={`${styles.actionResult} ${actionResult.failed > 0 ? styles.actionResultError : styles.actionResultSuccess}`}>
          <div className={styles.actionResultSummary}>
            <span>
              {actionResult.success > 0 && `${actionResult.success} updated`}
              {actionResult.success > 0 && actionResult.failed > 0 && ', '}
              {actionResult.failed > 0 && `${actionResult.failed} failed`}
            </span>
            {actionResult.failed > 0 && actionResult.errors.length > 0 && (
              <button
                className={styles.errorToggle}
                onClick={() => setErrorsExpanded(!errorsExpanded)}
              >
                {errorsExpanded ? 'Hide details' : 'Show details'}
              </button>
            )}
            {actionResult.failed > 0 && (
              <button
                className={styles.dismissButton}
                onClick={() => setActionResult(null)}
                title="Dismiss"
              >
                x
              </button>
            )}
          </div>
          {errorsExpanded && actionResult.errors.length > 0 && (
            <ul className={styles.errorList}>
              {actionResult.errors.map((err, i) => (
                <li key={i} className={styles.errorListItem}>{err}</li>
              ))}
            </ul>
          )}
        </div>
      )}

      <div className={styles.bulkButtons}>
        {/* Close Button */}
        <button
          className={styles.bulkButton}
          onClick={handleClose}
          disabled={isProcessing}
          title="Close selected items"
        >
          {isProcessing ? 'Processing...' : 'Close'}
        </button>

        {/* Resolve Button */}
        <button
          className={styles.bulkButton}
          onClick={handleResolve}
          disabled={isProcessing}
          title="Mark as resolved"
        >
          Resolve
        </button>

        {/* Status Dropdown */}
        <div className={styles.bulkDropdownContainer}>
          <button
            className={styles.bulkButton}
            onClick={() => setShowStatusDropdown(!showStatusDropdown)}
            disabled={isProcessing}
          >
            Status <span className={styles.dropdownArrow}>&#x25BC;</span>
          </button>
          {showStatusDropdown && (
            <>
              <div className={styles.dropdownBackdrop} onClick={() => setShowStatusDropdown(false)} />
              <div className={styles.bulkDropdown}>
                {STATUS_OPTIONS.map(opt => (
                  <button
                    key={opt.value}
                    className={styles.dropdownItem}
                    onClick={() => handleStatusChange(opt.value)}
                  >
                    {opt.label}
                  </button>
                ))}
              </div>
            </>
          )}
        </div>

        {/* Severity Dropdown */}
        <div className={styles.bulkDropdownContainer}>
          <button
            className={styles.bulkButton}
            onClick={() => setShowSeverityDropdown(!showSeverityDropdown)}
            disabled={isProcessing}
          >
            Severity <span className={styles.dropdownArrow}>&#x25BC;</span>
          </button>
          {showSeverityDropdown && (
            <>
              <div className={styles.dropdownBackdrop} onClick={() => setShowSeverityDropdown(false)} />
              <div className={styles.bulkDropdown}>
                {SEVERITY_OPTIONS.map(opt => (
                  <button
                    key={opt.value}
                    className={styles.dropdownItem}
                    onClick={() => handleSeverityChange(opt.value)}
                  >
                    {opt.label}
                  </button>
                ))}
              </div>
            </>
          )}
        </div>

        {/* Delete Button - Admin Only */}
        {isAdmin() && (
          <div className={styles.bulkDropdownContainer}>
            <button
              className={`${styles.bulkButton} ${styles.bulkButtonDanger}`}
              onClick={() => setShowConfirmDelete(true)}
              disabled={isProcessing}
              title="Delete selected items (admin only)"
            >
              Delete
            </button>
            {showConfirmDelete && (
              <>
                <div className={styles.dropdownBackdrop} onClick={closeDeleteConfirm} />
                <div className={`${styles.bulkDropdown} ${styles.confirmDropdown}`}>
                  <div className={styles.confirmMessage}>
                    Delete {selectedIds.length} item{selectedIds.length > 1 ? 's' : ''}?
                    <br />
                    <span className={styles.confirmWarning}>This cannot be undone. Enter your password to confirm.</span>
                  </div>
                  <input
                    type="password"
                    className={styles.deletePasswordInput}
                    placeholder="Enter your password"
                    value={deletePassword}
                    onChange={(e) => { setDeletePassword(e.target.value); setDeletePasswordError(''); }}
                    onKeyDown={(e) => { if (e.key === 'Enter') handleDeleteWithPassword(); }}
                    autoFocus
                  />
                  {deletePasswordError && (
                    <div className={styles.deletePasswordError}>{deletePasswordError}</div>
                  )}
                  <div className={styles.confirmButtons}>
                    <button
                      className={styles.confirmCancel}
                      onClick={closeDeleteConfirm}
                    >
                      Cancel
                    </button>
                    <button
                      className={styles.confirmDelete}
                      onClick={handleDeleteWithPassword}
                      disabled={verifyingPassword}
                    >
                      {verifyingPassword ? 'Verifying...' : 'Delete'}
                    </button>
                  </div>
                </div>
              </>
            )}
          </div>
        )}

        {/* Divider */}
        <span className={styles.bulkDivider} />

        {/* Clear Selection */}
        <button
          className={`${styles.bulkButton} ${styles.bulkButtonGhost}`}
          onClick={onClearSelection}
        >
          Clear
        </button>
      </div>
    </div>
  );
}

export default BulkActionsBar;
