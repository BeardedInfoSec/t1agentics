/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { usePermissions } from '../hooks/usePermissions';
import { API_BASE_URL, authFetch } from '../utils/api';
import { useToast } from './ui/Toast';
import SuggestedPlaybooks from './SuggestedPlaybooks';

/**
 * Investigation Details Drawer - Slides in from right
 * Quick view of investigation without leaving InvestigationList
 * Can update state, disposition, priority, owner
 * Phase 3.4: Added workflow actions (claim, release, assign, escalate, block, resolve, close)
 */
function InvestigationDetailsDrawer({ investigation: initialInvestigation, onClose, onRefresh }) {
  const { can } = usePermissions();
  const toast = useToast();
  const [investigation, setInvestigation] = useState(initialInvestigation);
  const [notes, setNotes] = useState([]);
  const [linkedAlert, setLinkedAlert] = useState(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [newNote, setNewNote] = useState('');
  const [addingNote, setAddingNote] = useState(false);
  const [users, setUsers] = useState([]);

  // Phase 3.4: Workflow state
  const [teams, setTeams] = useState([]);
  const [ownershipHistory, setOwnershipHistory] = useState([]);
  const [showHistoryModal, setShowHistoryModal] = useState(false);
  const [showAssignModal, setShowAssignModal] = useState(false);
  const [showBlockModal, setShowBlockModal] = useState(false);
  const [showResolveModal, setShowResolveModal] = useState(false);
  const [assignTarget, setAssignTarget] = useState('');
  const [blockReason, setBlockReason] = useState('');
  const [resolveData, setResolveData] = useState({ resolution_type: 'resolved', resolution_notes: '' });
  const [actionLoading, setActionLoading] = useState(false);

  // Get current user
  const currentUser = localStorage.getItem('username') || 'admin';

  useEffect(() => {
    if (initialInvestigation?.investigation_id) {
      fetchFullInvestigation(initialInvestigation.investigation_id);
      fetchNotes(initialInvestigation.investigation_id);
      fetchUsers();
      fetchTeams();
    }
  }, [initialInvestigation?.investigation_id]);

  const fetchFullInvestigation = async (id) => {
    setLoading(true);
    try {
      const response = await fetch(`${API_BASE_URL}/api/v1/investigations/${id}`);
      if (response.ok) {
        const data = await response.json();
        setInvestigation(data);

        // Fetch linked alert if available
        if (data.alert_id) {
          fetchLinkedAlert(data.alert_id);
        }
      }
    } catch (error) {
    } finally {
      setLoading(false);
    }
  };

  const fetchLinkedAlert = async (alertId) => {
    try {
      const response = await fetch(`${API_BASE_URL}/api/v1/alerts/${alertId}`);
      if (response.ok) {
        const data = await response.json();
        setLinkedAlert(data);
      }
    } catch (error) {
    }
  };

  const fetchNotes = async (id) => {
    try {
      const response = await fetch(`${API_BASE_URL}/api/v1/investigations/${id}/notes`);
      if (response.ok) {
        const data = await response.json();
        setNotes(data || []);
      }
    } catch (error) {
    }
  };

  const fetchUsers = async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/api/v1/users`);
      if (response.ok) {
        const data = await response.json();
        setUsers(data || []);
      }
    } catch (error) {
    }
  };

  // Phase 3.4: Fetch teams
  const fetchTeams = async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/api/v1/teams`);
      if (response.ok) {
        const data = await response.json();
        setTeams(data || []);
      }
    } catch (error) {
    }
  };

  // Phase 3.4: Fetch ownership history
  const fetchOwnershipHistory = async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/api/v1/investigations/${investigation.investigation_id}/ownership-history`);
      if (response.ok) {
        const data = await response.json();
        setOwnershipHistory(data || []);
        setShowHistoryModal(true);
      }
    } catch (error) {
    }
  };

  // Phase 3.4: Generic workflow action
  const performWorkflowAction = async (action, body = {}) => {
    setActionLoading(true);
    try {
      const response = await fetch(`${API_BASE_URL}/api/v1/investigations/${investigation.investigation_id}/${action}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(body)
      });
      if (response.ok) {
        const data = await response.json();
        setInvestigation(prev => ({ ...prev, ...data }));
        if (onRefresh) onRefresh();
        return true;
      } else {
        const err = await response.json();
        toast.error(err.detail || 'Action failed');
        return false;
      }
    } catch (error) {
      toast.error('Action failed');
      return false;
    } finally {
      setActionLoading(false);
    }
  };

  // Phase 3.4: Workflow action handlers
  const handleClaim = () => performWorkflowAction('claim');
  const handleRelease = () => performWorkflowAction('release');

  const handleAssign = async () => {
    if (!assignTarget) return;
    const success = await performWorkflowAction('assign', { new_owner: assignTarget });
    if (success) {
      setShowAssignModal(false);
      setAssignTarget('');
    }
  };

  const handleEscalate = () => performWorkflowAction('escalate', { level: 1, reason: 'Escalated by analyst' });

  const handleBlock = async () => {
    if (!blockReason.trim()) return;
    const success = await performWorkflowAction('block', { reason: blockReason });
    if (success) {
      setShowBlockModal(false);
      setBlockReason('');
    }
  };

  const handleUnblock = () => performWorkflowAction('unblock');

  const handleResolve = async () => {
    const success = await performWorkflowAction('resolve', {
      resolution_type: resolveData.resolution_type,
      notes: resolveData.resolution_notes
    });
    if (success) {
      setShowResolveModal(false);
      setResolveData({ resolution_type: 'resolved', resolution_notes: '' });
    }
  };

  const handleClose = () => performWorkflowAction('close');

  // Phase 3.4: Check ownership
  const isOwner = investigation?.owner === currentUser;
  const isBlocked = investigation?.is_blocked;
  const isClosed = investigation?.state === 'CLOSED';
  const isResolved = investigation?.state === 'RESOLVED';

  const updateField = async (field, value) => {
    setSaving(true);
    try {
      // Only `state` and `sensitivity` have dedicated sub-paths; every other
      // field (disposition, priority, owner, severity) goes to the parent
      // route with the field name in the body. Previously this always
      // appended /${field} which silently 404'd for disposition.
      const path = (field === 'state' || field === 'sensitivity')
        ? `${API_BASE_URL}/api/v1/investigations/${investigation.investigation_id}/${field}`
        : `${API_BASE_URL}/api/v1/investigations/${investigation.investigation_id}`;
      const response = await authFetch(path, {
        method: 'PATCH',
        body: JSON.stringify({ [field]: value }),
      });
      if (response.ok) {
        setInvestigation(prev => ({ ...prev, [field]: value, updated_at: new Date().toISOString() }));
        if (onRefresh) onRefresh();
      } else {
        const detail = await response.json().catch(() => ({}));
        console.error(`Failed to update ${field}:`, response.status, detail);
      }
    } catch (error) {
      console.error(`Network error updating ${field}:`, error);
    } finally {
      setSaving(false);
    }
  };

  const addNote = async () => {
    if (!newNote.trim()) return;
    setAddingNote(true);
    try {
      const response = await fetch(`${API_BASE_URL}/api/v1/investigations/${investigation.investigation_id}/notes`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ content: newNote, author: 'analyst' })
      });
      if (response.ok) {
        setNewNote('');
        fetchNotes(investigation.investigation_id);
      }
    } catch (error) {
    } finally {
      setAddingNote(false);
    }
  };

  const getStateColor = (state) => {
    // Simplified 5-state workflow colors
    const colors = {
      'NEW': '#3b82f6',           // Blue - just arrived
      'ANALYZING': '#3CB371',     // Teal - AI working
      'NEEDS_REVIEW': '#f97316',  // Orange - needs human attention!
      'IN_PROGRESS': '#f59e0b',   // Amber - analyst working
      'CLOSED': '#6b7280',        // Gray - terminal
      // Legacy state mappings (for any old data)
      'ENRICHING': '#3CB371',
      'AI_TRIAGE_L1': '#3CB371',
      'AI_TRIAGE_L2': '#3CB371',
      'RIGGS_REVIEW': '#f97316',
      'RIGGS_ANALYZED': '#f97316',
      'AWAITING_HUMAN': '#f97316',
      'RESOLVED': '#6b7280'
    };
    return colors[state] || '#6b7280';
  };

  const getDispositionColor = (disposition) => {
    const colors = {
      'MALICIOUS': '#dc2626',
      'TRUE_POSITIVE': '#dc2626',
      'SUSPICIOUS': '#ea580c',
      'BENIGN': '#22c55e',
      'FALSE_POSITIVE': '#6b7280',
      'INCONCLUSIVE': '#eab308',
      'UNKNOWN': '#64748b'
    };
    return colors[disposition] || '#64748b';
  };

  const getPriorityColor = (priority) => {
    const colors = { 'P1': '#dc2626', 'P2': '#ea580c', 'P3': '#eab308', 'P4': '#22c55e' };
    return colors[priority] || '#6b7280';
  };

  const formatDate = (dateStr) => {
    if (!dateStr) return '-';
    return new Date(dateStr).toLocaleString('en-US', {
      month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit'
    });
  };

  const formatTimeAgo = (dateStr) => {
    if (!dateStr) return '';
    const now = new Date();
    const date = new Date(dateStr);
    const minutes = Math.floor((now - date) / (1000 * 60));
    if (minutes < 60) return `${minutes}m ago`;
    if (minutes < 1440) return `${Math.floor(minutes / 60)}h ago`;
    return `${Math.floor(minutes / 1440)}d ago`;
  };

  if (!investigation) return null;

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
        width: '480px',
        maxWidth: '90vw',
        background: 'var(--bg-primary)',
        boxShadow: '-4px 0 20px rgba(0, 0, 0, 0.5)',
        zIndex: 1000,
        overflowY: 'auto',
        animation: 'slideInRight 0.25s ease',
        display: 'flex',
        flexDirection: 'column'
      }}>
        {/* Header */}
        <div style={{
          padding: '1rem',
          borderBottom: '1px solid var(--bg-tertiary)',
          position: 'sticky',
          top: 0,
          background: 'var(--bg-primary)',
          zIndex: 10
        }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.25rem' }}>
                <h2 style={{ fontSize: '0.9rem', fontWeight: '600', margin: 0 }}>Investigation</h2>
                <code style={{
                  background: 'rgba(60, 179, 113, 0.1)',
                  padding: '0.15rem 0.4rem',
                  borderRadius: '4px',
                  fontSize: '0.65rem',
                  color: '#a0e9ff'
                }}>
                  {investigation.investigation_id?.substring(0, 12)}...
                </code>
              </div>
              <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>
                Created {formatTimeAgo(investigation.created_at)}
              </div>
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
        </div>

        {/* Content */}
        <div style={{ flex: 1, padding: '1rem', overflowY: 'auto' }}>
          {loading ? (
            <div style={{ textAlign: 'center', padding: '2rem', color: 'var(--text-muted)' }}>
              Loading investigation details...
            </div>
          ) : (
            <>
              {/* Title */}
              <div style={{ marginBottom: '1rem' }}>
                <div style={{ fontSize: '1rem', fontWeight: '600', color: 'var(--text-primary)', lineHeight: 1.4 }}>
                  {investigation.alert_title || investigation.title || 'Untitled Investigation'}
                </div>
              </div>

              {/* Phase 3.4: Blocked Banner */}
              {isBlocked && (
                <div style={{
                  padding: '0.75rem',
                  background: 'rgba(220, 38, 38, 0.15)',
                  border: '1px solid rgba(220, 38, 38, 0.5)',
                  borderRadius: '6px',
                  marginBottom: '1rem',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between'
                }}>
                  <div>
                    <div style={{ fontSize: '0.8rem', fontWeight: '600', color: '#dc2626', marginBottom: '0.25rem' }}>
                      Investigation Blocked
                    </div>
                    <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>
                      {investigation.blocked_reason || 'No reason provided'}
                    </div>
                  </div>
                  {isOwner && (
                    <button
                      onClick={handleUnblock}
                      disabled={actionLoading}
                      style={{
                        padding: '0.4rem 0.75rem',
                        background: '#dc2626',
                        border: 'none',
                        borderRadius: '4px',
                        color: 'white',
                        fontSize: '0.7rem',
                        fontWeight: '600',
                        cursor: 'pointer'
                      }}
                    >
                      Unblock
                    </button>
                  )}
                </div>
              )}

              {/* Phase 3.4: Workflow Actions Bar */}
              {!isClosed && (
                <div style={{
                  display: 'flex',
                  flexWrap: 'wrap',
                  gap: '0.5rem',
                  marginBottom: '1rem',
                  padding: '0.75rem',
                  background: 'var(--bg-secondary)',
                  borderRadius: '6px',
                  borderLeft: '3px solid #3CB371'
                }}>
                  {/* Claim / Release */}
                  {!investigation.owner ? (
                    <button
                      onClick={handleClaim}
                      disabled={actionLoading}
                      style={{
                        padding: '0.4rem 0.75rem',
                        background: 'linear-gradient(135deg, #22c55e 0%, #16a34a 100%)',
                        border: 'none',
                        borderRadius: '4px',
                        color: 'white',
                        fontSize: '0.7rem',
                        fontWeight: '600',
                        cursor: 'pointer'
                      }}
                    >
                      Claim
                    </button>
                  ) : isOwner ? (
                    <button
                      onClick={handleRelease}
                      disabled={actionLoading || isBlocked}
                      style={{
                        padding: '0.4rem 0.75rem',
                        background: 'var(--bg-tertiary)',
                        border: 'none',
                        borderRadius: '4px',
                        color: 'var(--text-secondary)',
                        fontSize: '0.7rem',
                        fontWeight: '600',
                        cursor: isBlocked ? 'not-allowed' : 'pointer',
                        opacity: isBlocked ? 0.5 : 1
                      }}
                    >
                      Release
                    </button>
                  ) : null}

                  {/* Reassign */}
                  <button
                    onClick={() => setShowAssignModal(true)}
                    disabled={actionLoading}
                    style={{
                      padding: '0.4rem 0.75rem',
                      background: 'var(--bg-tertiary)',
                      border: 'none',
                      borderRadius: '4px',
                      color: 'var(--text-secondary)',
                      fontSize: '0.7rem',
                      fontWeight: '600',
                      cursor: 'pointer'
                    }}
                  >
                    Reassign
                  </button>

                  {/* Escalate */}
                  {isOwner && !isResolved && (
                    <button
                      onClick={handleEscalate}
                      disabled={actionLoading}
                      style={{
                        padding: '0.4rem 0.75rem',
                        background: 'linear-gradient(135deg, #f59e0b 0%, #d97706 100%)',
                        border: 'none',
                        borderRadius: '4px',
                        color: 'white',
                        fontSize: '0.7rem',
                        fontWeight: '600',
                        cursor: 'pointer'
                      }}
                    >
                      Escalate
                    </button>
                  )}

                  {/* Block */}
                  {isOwner && !isBlocked && !isResolved && (
                    <button
                      onClick={() => setShowBlockModal(true)}
                      disabled={actionLoading}
                      style={{
                        padding: '0.4rem 0.75rem',
                        background: 'rgba(220, 38, 38, 0.15)',
                        border: '1px solid rgba(220, 38, 38, 0.5)',
                        borderRadius: '4px',
                        color: '#dc2626',
                        fontSize: '0.7rem',
                        fontWeight: '600',
                        cursor: 'pointer'
                      }}
                    >
                      Block
                    </button>
                  )}

                  {/* Resolve */}
                  {isOwner && !isResolved && !isBlocked && (
                    <button
                      onClick={() => setShowResolveModal(true)}
                      disabled={actionLoading}
                      style={{
                        padding: '0.4rem 0.75rem',
                        background: 'linear-gradient(135deg, #3CB371 0%, #2e8b57 100%)',
                        border: 'none',
                        borderRadius: '4px',
                        color: 'white',
                        fontSize: '0.7rem',
                        fontWeight: '600',
                        cursor: 'pointer'
                      }}
                    >
                      Resolve
                    </button>
                  )}

                  {/* Close (after resolved) */}
                  {isOwner && isResolved && (
                    <button
                      onClick={handleClose}
                      disabled={actionLoading}
                      style={{
                        padding: '0.4rem 0.75rem',
                        background: 'var(--bg-tertiary)',
                        border: '1px solid var(--text-muted)',
                        borderRadius: '4px',
                        color: 'var(--text-primary)',
                        fontSize: '0.7rem',
                        fontWeight: '600',
                        cursor: 'pointer'
                      }}
                    >
                      Close
                    </button>
                  )}

                  {/* View History */}
                  <button
                    onClick={fetchOwnershipHistory}
                    style={{
                      padding: '0.4rem 0.75rem',
                      background: 'transparent',
                      border: '1px solid var(--bg-tertiary)',
                      borderRadius: '4px',
                      color: 'var(--text-muted)',
                      fontSize: '0.7rem',
                      fontWeight: '600',
                      cursor: 'pointer',
                      marginLeft: 'auto'
                    }}
                  >
                    History
                  </button>
                </div>
              )}

              {/* Phase 3.4: Resolution Info */}
              {investigation.resolution_type && (
                <div style={{
                  padding: '0.75rem',
                  background: 'rgba(34, 197, 94, 0.1)',
                  border: '1px solid rgba(34, 197, 94, 0.3)',
                  borderRadius: '6px',
                  marginBottom: '1rem'
                }}>
                  <div style={{ fontSize: '0.7rem', fontWeight: '600', color: '#22c55e', marginBottom: '0.25rem' }}>
                    Resolution: {investigation.resolution_type?.replace(/_/g, ' ').toUpperCase()}
                  </div>
                  {investigation.resolution_notes && (
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                      {investigation.resolution_notes}
                    </div>
                  )}
                  {investigation.resolved_at && (
                    <div style={{ fontSize: '0.65rem', color: 'var(--text-muted)', marginTop: '0.25rem' }}>
                      Resolved: {formatDate(investigation.resolved_at)}
                    </div>
                  )}
                </div>
              )}

              {/* Status Grid */}
              <div style={{
                display: 'grid',
                gridTemplateColumns: '1fr 1fr',
                gap: '0.75rem',
                marginBottom: '1rem'
              }}>
                {/* State */}
                <div>
                  <label style={{ display: 'block', fontSize: '0.65rem', color: 'var(--text-muted)', marginBottom: '0.25rem', fontWeight: '600', textTransform: 'uppercase' }}>
                    State
                  </label>
                  {can('update_investigation') ? (
                    <select
                      value={investigation.state || 'NEW'}
                      onChange={(e) => updateField('state', e.target.value)}
                      disabled={saving}
                      style={{
                        width: '100%',
                        padding: '0.4rem 0.5rem',
                        background: `${getStateColor(investigation.state)}15`,
                        border: `1px solid ${getStateColor(investigation.state)}`,
                        borderRadius: '4px',
                        color: getStateColor(investigation.state),
                        fontSize: '0.75rem',
                        fontWeight: '600',
                        cursor: 'pointer'
                      }}
                    >
                      <option value="NEW">NEW</option>
                      <option value="ANALYZING">ANALYZING</option>
                      <option value="NEEDS_REVIEW">NEEDS REVIEW</option>
                      <option value="IN_PROGRESS">IN PROGRESS</option>
                      <option value="CLOSED">CLOSED</option>
                    </select>
                  ) : (
                    <span style={{
                      display: 'inline-block',
                      padding: '0.3rem 0.5rem',
                      background: `${getStateColor(investigation.state)}15`,
                      border: `1px solid ${getStateColor(investigation.state)}`,
                      borderRadius: '4px',
                      color: getStateColor(investigation.state),
                      fontSize: '0.75rem',
                      fontWeight: '600'
                    }}>
                      {investigation.state || 'NEW'}
                    </span>
                  )}
                </div>

                {/* Priority */}
                <div>
                  <label style={{ display: 'block', fontSize: '0.65rem', color: 'var(--text-muted)', marginBottom: '0.25rem', fontWeight: '600', textTransform: 'uppercase' }}>
                    Priority
                  </label>
                  {can('update_investigation') ? (
                    <select
                      value={investigation.priority || 'P3'}
                      onChange={(e) => updateField('priority', e.target.value)}
                      disabled={saving}
                      style={{
                        width: '100%',
                        padding: '0.4rem 0.5rem',
                        background: `${getPriorityColor(investigation.priority)}15`,
                        border: `1px solid ${getPriorityColor(investigation.priority)}`,
                        borderRadius: '4px',
                        color: getPriorityColor(investigation.priority),
                        fontSize: '0.75rem',
                        fontWeight: '600',
                        cursor: 'pointer'
                      }}
                    >
                      <option value="P1">P1 - Critical</option>
                      <option value="P2">P2 - High</option>
                      <option value="P3">P3 - Medium</option>
                      <option value="P4">P4 - Low</option>
                    </select>
                  ) : (
                    <span style={{
                      display: 'inline-block',
                      padding: '0.3rem 0.5rem',
                      background: `${getPriorityColor(investigation.priority)}15`,
                      border: `1px solid ${getPriorityColor(investigation.priority)}`,
                      borderRadius: '4px',
                      color: getPriorityColor(investigation.priority),
                      fontSize: '0.75rem',
                      fontWeight: '600'
                    }}>
                      {investigation.priority || 'P3'}
                    </span>
                  )}
                </div>

                {/* Disposition */}
                <div>
                  <label style={{ display: 'block', fontSize: '0.65rem', color: 'var(--text-muted)', marginBottom: '0.25rem', fontWeight: '600', textTransform: 'uppercase' }}>
                    Disposition
                  </label>
                  {can('update_investigation') ? (
                    <select
                      value={investigation.disposition || 'UNKNOWN'}
                      onChange={(e) => updateField('disposition', e.target.value)}
                      disabled={saving}
                      style={{
                        width: '100%',
                        padding: '0.4rem 0.5rem',
                        background: `${getDispositionColor(investigation.disposition)}15`,
                        border: `1px solid ${getDispositionColor(investigation.disposition)}`,
                        borderRadius: '4px',
                        color: getDispositionColor(investigation.disposition),
                        fontSize: '0.75rem',
                        fontWeight: '600',
                        cursor: 'pointer'
                      }}
                    >
                      <option value="UNKNOWN">Unknown</option>
                      <option value="TRUE_POSITIVE">True Positive</option>
                      <option value="FALSE_POSITIVE">False Positive</option>
                      <option value="BENIGN">Benign</option>
                      <option value="MALICIOUS">Malicious</option>
                      <option value="SUSPICIOUS">Suspicious</option>
                      <option value="INCONCLUSIVE">Inconclusive</option>
                    </select>
                  ) : (
                    <span style={{
                      display: 'inline-block',
                      padding: '0.3rem 0.5rem',
                      background: `${getDispositionColor(investigation.disposition)}15`,
                      border: `1px solid ${getDispositionColor(investigation.disposition)}`,
                      borderRadius: '4px',
                      color: getDispositionColor(investigation.disposition),
                      fontSize: '0.75rem',
                      fontWeight: '600'
                    }}>
                      {investigation.disposition || 'UNKNOWN'}
                    </span>
                  )}
                </div>

                {/* Owner */}
                <div>
                  <label style={{ display: 'block', fontSize: '0.65rem', color: 'var(--text-muted)', marginBottom: '0.25rem', fontWeight: '600', textTransform: 'uppercase' }}>
                    Owner
                  </label>
                  {can('update_investigation') ? (
                    <select
                      value={investigation.owner || ''}
                      onChange={(e) => updateField('owner', e.target.value)}
                      disabled={saving}
                      style={{
                        width: '100%',
                        padding: '0.4rem 0.5rem',
                        background: 'var(--bg-secondary)',
                        border: '1px solid var(--bg-tertiary)',
                        borderRadius: '4px',
                        color: 'var(--text-primary)',
                        fontSize: '0.75rem',
                        cursor: 'pointer'
                      }}
                    >
                      <option value="">Unassigned</option>
                      {users.map(user => (
                        <option key={user.username} value={user.username}>
                          {user.full_name || user.username}
                        </option>
                      ))}
                    </select>
                  ) : (
                    <span style={{
                      display: 'inline-block',
                      padding: '0.3rem 0.5rem',
                      background: 'var(--bg-secondary)',
                      border: '1px solid var(--bg-tertiary)',
                      borderRadius: '4px',
                      color: 'var(--text-primary)',
                      fontSize: '0.75rem'
                    }}>
                      {investigation.owner || 'Unassigned'}
                    </span>
                  )}
                </div>
              </div>

              {/* Timestamps */}
              <div style={{
                display: 'flex',
                gap: '1rem',
                marginBottom: '1rem',
                padding: '0.5rem 0.75rem',
                background: 'var(--bg-secondary)',
                borderRadius: '6px',
                fontSize: '0.7rem'
              }}>
                <div>
                  <span style={{ color: 'var(--text-muted)' }}>Created: </span>
                  <span style={{ color: 'var(--text-secondary)' }}>{formatDate(investigation.created_at)}</span>
                </div>
                <div>
                  <span style={{ color: 'var(--text-muted)' }}>Updated: </span>
                  <span style={{ color: 'var(--text-secondary)' }}>{formatDate(investigation.updated_at)}</span>
                </div>
              </div>

              {/* Executive Summary */}
              {investigation.executive_summary && (
                <div style={{ marginBottom: '1rem' }}>
                  <label style={{ display: 'block', fontSize: '0.65rem', color: 'var(--text-muted)', marginBottom: '0.25rem', fontWeight: '600', textTransform: 'uppercase' }}>
                    Executive Summary
                  </label>
                  <div style={{
                    padding: '0.75rem',
                    background: 'var(--bg-secondary)',
                    borderRadius: '6px',
                    fontSize: '0.8rem',
                    lineHeight: 1.5,
                    color: 'var(--text-secondary)'
                  }}>
                    {investigation.executive_summary}
                  </div>
                </div>
              )}

              {/* Suggested Playbooks */}
              <SuggestedPlaybooks
                investigationId={investigation.investigation_id}
                investigation={investigation}
                compact={true}
              />

              {/* Linked Alert */}
              {linkedAlert && (
                <div style={{ marginBottom: '1rem' }}>
                  <label style={{ display: 'block', fontSize: '0.65rem', color: 'var(--text-muted)', marginBottom: '0.25rem', fontWeight: '600', textTransform: 'uppercase' }}>
                    Linked Alert
                  </label>
                  <div style={{
                    padding: '0.75rem',
                    background: 'rgba(60, 179, 113, 0.05)',
                    border: '1px solid rgba(60, 179, 113, 0.2)',
                    borderRadius: '6px'
                  }}>
                    <div style={{ fontSize: '0.8rem', fontWeight: '500', color: 'var(--text-primary)', marginBottom: '0.25rem' }}>
                      {linkedAlert.title}
                    </div>
                    <div style={{ display: 'flex', gap: '0.75rem', fontSize: '0.7rem', color: 'var(--text-muted)' }}>
                      <span style={{
                        padding: '0.15rem 0.4rem',
                        borderRadius: '3px',
                        background: linkedAlert.severity === 'critical' ? 'rgba(220, 38, 38, 0.15)' :
                                   linkedAlert.severity === 'high' ? 'rgba(234, 88, 12, 0.15)' :
                                   linkedAlert.severity === 'medium' ? 'rgba(234, 179, 8, 0.15)' :
                                   'rgba(34, 197, 94, 0.15)',
                        color: linkedAlert.severity === 'critical' ? '#dc2626' :
                              linkedAlert.severity === 'high' ? '#ea580c' :
                              linkedAlert.severity === 'medium' ? '#eab308' :
                              '#22c55e',
                        fontWeight: '600',
                        textTransform: 'uppercase'
                      }}>
                        {linkedAlert.severity}
                      </span>
                      <span>Source: {linkedAlert.source}</span>
                    </div>
                  </div>
                </div>
              )}

              {/* Notes Section */}
              <div style={{ marginBottom: '1rem' }}>
                <label style={{ display: 'block', fontSize: '0.65rem', color: 'var(--text-muted)', marginBottom: '0.5rem', fontWeight: '600', textTransform: 'uppercase' }}>
                  Notes ({notes.length})
                </label>

                {/* Add Note */}
                {can('add_notes') && (
                  <div style={{ marginBottom: '0.75rem' }}>
                    <textarea
                      value={newNote}
                      onChange={(e) => setNewNote(e.target.value)}
                      placeholder="Add a note..."
                      style={{
                        width: '100%',
                        padding: '0.5rem',
                        background: 'var(--bg-secondary)',
                        border: '1px solid var(--bg-tertiary)',
                        borderRadius: '6px',
                        color: 'var(--text-primary)',
                        fontSize: '0.8rem',
                        resize: 'vertical',
                        minHeight: '60px'
                      }}
                    />
                    <button
                      onClick={addNote}
                      disabled={addingNote || !newNote.trim()}
                      style={{
                        marginTop: '0.5rem',
                        padding: '0.4rem 0.75rem',
                        background: newNote.trim() ? 'linear-gradient(135deg, #3CB371 0%, #2e8b57 100%)' : 'var(--bg-tertiary)',
                        border: 'none',
                        borderRadius: '4px',
                        color: newNote.trim() ? 'white' : 'var(--text-muted)',
                        fontSize: '0.75rem',
                        fontWeight: '600',
                        cursor: newNote.trim() ? 'pointer' : 'not-allowed'
                      }}
                    >
                      {addingNote ? 'Adding...' : 'Add Note'}
                    </button>
                  </div>
                )}

                {/* Notes List */}
                <div style={{ maxHeight: '200px', overflowY: 'auto' }}>
                  {notes.length === 0 ? (
                    <div style={{
                      padding: '1rem',
                      background: 'var(--bg-secondary)',
                      borderRadius: '6px',
                      textAlign: 'center',
                      color: 'var(--text-muted)',
                      fontSize: '0.75rem'
                    }}>
                      No notes yet
                    </div>
                  ) : (
                    notes.map((note, idx) => (
                      <div key={note.id || idx} style={{
                        padding: '0.5rem 0.75rem',
                        background: 'var(--bg-secondary)',
                        borderRadius: '6px',
                        marginBottom: '0.5rem',
                        borderLeft: '3px solid #3CB371'
                      }}>
                        <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: '0.25rem' }}>
                          {note.content}
                        </div>
                        <div style={{ fontSize: '0.65rem', color: 'var(--text-muted)' }}>
                          {note.author} - {formatDate(note.created_at)}
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </div>
            </>
          )}
        </div>

        {/* Footer Actions */}
        <div style={{
          padding: '1rem',
          borderTop: '1px solid var(--bg-tertiary)',
          background: 'var(--bg-secondary)',
          display: 'flex',
          gap: '0.75rem'
        }}>
          <Link
            to={`/investigation/${investigation.investigation_id}`}
            style={{
              flex: 1,
              padding: '0.75rem 1rem',
              background: 'linear-gradient(135deg, #3CB371 0%, #2e8b57 100%)',
              border: 'none',
              borderRadius: '6px',
              color: 'white',
              fontSize: '0.85rem',
              fontWeight: '600',
              textAlign: 'center',
              textDecoration: 'none',
              cursor: 'pointer'
            }}
          >
            Open Full View
          </Link>
          <button
            onClick={onClose}
            style={{
              padding: '0.75rem 1rem',
              background: 'var(--bg-tertiary)',
              border: 'none',
              borderRadius: '6px',
              color: 'var(--text-secondary)',
              fontSize: '0.85rem',
              fontWeight: '600',
              cursor: 'pointer'
            }}
          >
            Close
          </button>
        </div>
      </div>

      {/* Phase 3.4: Assign Modal */}
      {showAssignModal && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          background: 'rgba(0, 0, 0, 0.7)',
          zIndex: 1100,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center'
        }}>
          <div style={{
            background: 'var(--bg-primary)',
            borderRadius: '8px',
            padding: '1.5rem',
            width: '350px',
            maxWidth: '90vw'
          }}>
            <h3 style={{ margin: '0 0 1rem 0', fontSize: '1rem', color: 'var(--text-primary)' }}>
              Reassign Investigation
            </h3>
            <select
              value={assignTarget}
              onChange={(e) => setAssignTarget(e.target.value)}
              style={{
                width: '100%',
                padding: '0.5rem',
                background: 'var(--bg-secondary)',
                border: '1px solid var(--bg-tertiary)',
                borderRadius: '6px',
                color: 'var(--text-primary)',
                fontSize: '0.85rem',
                marginBottom: '1rem'
              }}
            >
              <option value="">Select assignee...</option>
              {users.map(user => (
                <option key={user.username} value={user.username}>
                  {user.full_name || user.username}
                </option>
              ))}
            </select>
            <div style={{ display: 'flex', gap: '0.75rem', justifyContent: 'flex-end' }}>
              <button
                onClick={() => { setShowAssignModal(false); setAssignTarget(''); }}
                style={{
                  padding: '0.5rem 1rem',
                  background: 'var(--bg-tertiary)',
                  border: 'none',
                  borderRadius: '4px',
                  color: 'var(--text-secondary)',
                  fontSize: '0.8rem',
                  cursor: 'pointer'
                }}
              >
                Cancel
              </button>
              <button
                onClick={handleAssign}
                disabled={!assignTarget || actionLoading}
                style={{
                  padding: '0.5rem 1rem',
                  background: assignTarget ? 'linear-gradient(135deg, #3CB371 0%, #2e8b57 100%)' : 'var(--bg-tertiary)',
                  border: 'none',
                  borderRadius: '4px',
                  color: assignTarget ? 'white' : 'var(--text-muted)',
                  fontSize: '0.8rem',
                  fontWeight: '600',
                  cursor: assignTarget ? 'pointer' : 'not-allowed'
                }}
              >
                {actionLoading ? 'Assigning...' : 'Assign'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Phase 3.4: Block Modal */}
      {showBlockModal && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          background: 'rgba(0, 0, 0, 0.7)',
          zIndex: 1100,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center'
        }}>
          <div style={{
            background: 'var(--bg-primary)',
            borderRadius: '8px',
            padding: '1.5rem',
            width: '400px',
            maxWidth: '90vw'
          }}>
            <h3 style={{ margin: '0 0 1rem 0', fontSize: '1rem', color: '#dc2626' }}>
              Block Investigation
            </h3>
            <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '1rem' }}>
              Blocking indicates this investigation is waiting on external input or resources.
            </p>
            <textarea
              value={blockReason}
              onChange={(e) => setBlockReason(e.target.value)}
              placeholder="Enter reason for blocking..."
              style={{
                width: '100%',
                padding: '0.5rem',
                background: 'var(--bg-secondary)',
                border: '1px solid var(--bg-tertiary)',
                borderRadius: '6px',
                color: 'var(--text-primary)',
                fontSize: '0.85rem',
                minHeight: '80px',
                marginBottom: '1rem',
                resize: 'vertical'
              }}
            />
            <div style={{ display: 'flex', gap: '0.75rem', justifyContent: 'flex-end' }}>
              <button
                onClick={() => { setShowBlockModal(false); setBlockReason(''); }}
                style={{
                  padding: '0.5rem 1rem',
                  background: 'var(--bg-tertiary)',
                  border: 'none',
                  borderRadius: '4px',
                  color: 'var(--text-secondary)',
                  fontSize: '0.8rem',
                  cursor: 'pointer'
                }}
              >
                Cancel
              </button>
              <button
                onClick={handleBlock}
                disabled={!blockReason.trim() || actionLoading}
                style={{
                  padding: '0.5rem 1rem',
                  background: blockReason.trim() ? '#dc2626' : 'var(--bg-tertiary)',
                  border: 'none',
                  borderRadius: '4px',
                  color: blockReason.trim() ? 'white' : 'var(--text-muted)',
                  fontSize: '0.8rem',
                  fontWeight: '600',
                  cursor: blockReason.trim() ? 'pointer' : 'not-allowed'
                }}
              >
                {actionLoading ? 'Blocking...' : 'Block'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Phase 3.4: Resolve Modal */}
      {showResolveModal && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          background: 'rgba(0, 0, 0, 0.7)',
          zIndex: 1100,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center'
        }}>
          <div style={{
            background: 'var(--bg-primary)',
            borderRadius: '8px',
            padding: '1.5rem',
            width: '400px',
            maxWidth: '90vw'
          }}>
            <h3 style={{ margin: '0 0 1rem 0', fontSize: '1rem', color: '#22c55e' }}>
              Resolve Investigation
            </h3>
            <div style={{ marginBottom: '1rem' }}>
              <label style={{ display: 'block', fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '0.25rem' }}>
                Resolution Type
              </label>
              <select
                value={resolveData.resolution_type}
                onChange={(e) => setResolveData(prev => ({ ...prev, resolution_type: e.target.value }))}
                style={{
                  width: '100%',
                  padding: '0.5rem',
                  background: 'var(--bg-secondary)',
                  border: '1px solid var(--bg-tertiary)',
                  borderRadius: '6px',
                  color: 'var(--text-primary)',
                  fontSize: '0.85rem'
                }}
              >
                <option value="resolved">Resolved</option>
                <option value="false_positive">False Positive</option>
                <option value="true_positive">True Positive - Contained</option>
                <option value="benign">Benign</option>
                <option value="duplicate">Duplicate</option>
                <option value="no_action_needed">No Action Needed</option>
              </select>
            </div>
            <div style={{ marginBottom: '1rem' }}>
              <label style={{ display: 'block', fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '0.25rem' }}>
                Resolution Notes
              </label>
              <textarea
                value={resolveData.resolution_notes}
                onChange={(e) => setResolveData(prev => ({ ...prev, resolution_notes: e.target.value }))}
                placeholder="Add resolution notes..."
                style={{
                  width: '100%',
                  padding: '0.5rem',
                  background: 'var(--bg-secondary)',
                  border: '1px solid var(--bg-tertiary)',
                  borderRadius: '6px',
                  color: 'var(--text-primary)',
                  fontSize: '0.85rem',
                  minHeight: '80px',
                  resize: 'vertical'
                }}
              />
            </div>
            <div style={{ display: 'flex', gap: '0.75rem', justifyContent: 'flex-end' }}>
              <button
                onClick={() => { setShowResolveModal(false); setResolveData({ resolution_type: 'resolved', resolution_notes: '' }); }}
                style={{
                  padding: '0.5rem 1rem',
                  background: 'var(--bg-tertiary)',
                  border: 'none',
                  borderRadius: '4px',
                  color: 'var(--text-secondary)',
                  fontSize: '0.8rem',
                  cursor: 'pointer'
                }}
              >
                Cancel
              </button>
              <button
                onClick={handleResolve}
                disabled={actionLoading}
                style={{
                  padding: '0.5rem 1rem',
                  background: 'linear-gradient(135deg, #22c55e 0%, #16a34a 100%)',
                  border: 'none',
                  borderRadius: '4px',
                  color: 'white',
                  fontSize: '0.8rem',
                  fontWeight: '600',
                  cursor: 'pointer'
                }}
              >
                {actionLoading ? 'Resolving...' : 'Resolve'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Phase 3.4: Ownership History Modal */}
      {showHistoryModal && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          background: 'rgba(0, 0, 0, 0.7)',
          zIndex: 1100,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center'
        }}>
          <div style={{
            background: 'var(--bg-primary)',
            borderRadius: '8px',
            padding: '1.5rem',
            width: '500px',
            maxWidth: '90vw',
            maxHeight: '80vh',
            display: 'flex',
            flexDirection: 'column'
          }}>
            <h3 style={{ margin: '0 0 1rem 0', fontSize: '1rem', color: 'var(--text-primary)' }}>
              Ownership History
            </h3>
            <div style={{ flex: 1, overflowY: 'auto' }}>
              {ownershipHistory.length === 0 ? (
                <div style={{ textAlign: 'center', color: 'var(--text-muted)', padding: '2rem' }}>
                  No ownership history available
                </div>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                  {ownershipHistory.map((entry, idx) => (
                    <div key={idx} style={{
                      padding: '0.75rem',
                      background: 'var(--bg-secondary)',
                      borderRadius: '6px',
                      borderLeft: '3px solid #3CB371'
                    }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.25rem' }}>
                        <span style={{
                          fontSize: '0.75rem',
                          fontWeight: '600',
                          color: 'var(--text-primary)',
                          textTransform: 'uppercase'
                        }}>
                          {entry.action?.replace(/_/g, ' ')}
                        </span>
                        <span style={{ fontSize: '0.65rem', color: 'var(--text-muted)' }}>
                          {formatDate(entry.timestamp)}
                        </span>
                      </div>
                      <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                        {entry.from_user && <span>From: {entry.from_user} </span>}
                        {entry.to_user && <span>To: {entry.to_user}</span>}
                        {!entry.from_user && !entry.to_user && entry.user && (
                          <span>By: {entry.user}</span>
                        )}
                      </div>
                      {entry.notes && (
                        <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: '0.25rem', fontStyle: 'italic' }}>
                          {entry.notes}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
            <div style={{ marginTop: '1rem', display: 'flex', justifyContent: 'flex-end' }}>
              <button
                onClick={() => setShowHistoryModal(false)}
                style={{
                  padding: '0.5rem 1rem',
                  background: 'var(--bg-tertiary)',
                  border: 'none',
                  borderRadius: '4px',
                  color: 'var(--text-secondary)',
                  fontSize: '0.8rem',
                  cursor: 'pointer'
                }}
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      <style>{`
        @keyframes slideInRight {
          from { transform: translateX(100%); }
          to { transform: translateX(0); }
        }
        @keyframes fadeIn {
          from { opacity: 0; }
          to { opacity: 1; }
        }
      `}</style>
    </>
  );
}

export default InvestigationDetailsDrawer;


