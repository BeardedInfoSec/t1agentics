/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

/**
 * Execution View Component
 *
 * Displays the status and progress of a playbook execution.
 */

import React, { useState, useEffect } from 'react';
import {
  X, RefreshCw, CheckCircle, XCircle, Clock, AlertTriangle,
  Pause, Play, ChevronDown, ChevronRight
} from 'lucide-react';

const API_BASE = process.env.REACT_APP_API_URL || '';

function ExecutionView({ execution, onClose, onRefresh }) {
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [expandedNodes, setExpandedNodes] = useState({});
  const [autoRefresh, setAutoRefresh] = useState(true);

  // Auto-refresh while running
  useEffect(() => {
    if (autoRefresh && isRunningStatus(execution?.status)) {
      const interval = setInterval(() => {
        onRefresh();
      }, 3000);
      return () => clearInterval(interval);
    }
  }, [autoRefresh, execution?.status, onRefresh]);

  const handleRefresh = async () => {
    setIsRefreshing(true);
    await onRefresh();
    setIsRefreshing(false);
  };

  const toggleNode = (nodeId) => {
    setExpandedNodes((prev) => ({
      ...prev,
      [nodeId]: !prev[nodeId],
    }));
  };

  const nodeResults = execution?.node_results || {};

  return (
    <div style={styles.overlay} onClick={onClose}>
      <div style={styles.modal} onClick={(e) => e.stopPropagation()}>
        <div style={styles.header}>
          <div style={styles.headerInfo}>
            <h3 style={styles.title}>Execution: {execution?.execution_id}</h3>
            <StatusBadge status={execution?.status} />
          </div>
          <div style={styles.headerActions}>
            <button
              onClick={handleRefresh}
              style={styles.refreshButton}
              disabled={isRefreshing}
            >
              <RefreshCw size={16} className={isRefreshing ? 'spin' : ''} />
            </button>
            <button onClick={onClose} style={styles.closeButton}>
              <X size={18} />
            </button>
          </div>
        </div>

        <div style={styles.info}>
          <div style={styles.infoItem}>
            <span style={styles.infoLabel}>Started:</span>
            <span style={styles.infoValue}>
              {execution?.started_at
                ? new Date(execution.started_at).toLocaleString()
                : 'N/A'}
            </span>
          </div>
          {execution?.completed_at && (
            <div style={styles.infoItem}>
              <span style={styles.infoLabel}>Completed:</span>
              <span style={styles.infoValue}>
                {new Date(execution.completed_at).toLocaleString()}
              </span>
            </div>
          )}
          <div style={styles.infoItem}>
            <span style={styles.infoLabel}>Triggered by:</span>
            <span style={styles.infoValue}>{execution?.triggered_by || 'manual'}</span>
          </div>
          {execution?.current_node_id && (
            <div style={styles.infoItem}>
              <span style={styles.infoLabel}>Current Node:</span>
              <span style={styles.infoValue}>{execution.current_node_id}</span>
            </div>
          )}
        </div>

        {execution?.error_message && (
          <div style={styles.errorBanner}>
            <AlertTriangle size={16} />
            <span>{execution.error_message}</span>
          </div>
        )}

        <div style={styles.nodeResults}>
          <h4 style={styles.sectionTitle}>Node Results</h4>
          {Object.entries(nodeResults).length === 0 ? (
            <div style={styles.noResults}>No node results yet</div>
          ) : (
            Object.entries(nodeResults).map(([nodeId, result]) => (
              <div key={nodeId} style={styles.nodeResult}>
                <div
                  style={styles.nodeHeader}
                  onClick={() => toggleNode(nodeId)}
                >
                  <div style={styles.nodeInfo}>
                    <NodeStatusIcon status={result.status} />
                    <span style={styles.nodeId}>{nodeId}</span>
                    <span style={styles.nodeType}>({result.kind || result.node_type})</span>
                  </div>
                  <div style={styles.nodeHeaderRight}>
                    {(result.duration_ms ?? result.execution_time_ms) && (
                      <span style={styles.executionTime}>
                        {(result.duration_ms ?? result.execution_time_ms).toFixed(0)}ms
                      </span>
                    )}
                    {expandedNodes[nodeId] ? (
                      <ChevronDown size={16} />
                    ) : (
                      <ChevronRight size={16} />
                    )}
                  </div>
                </div>

                {expandedNodes[nodeId] && (
                  <div style={styles.nodeDetails}>
                    {result.error && (
                      <div style={styles.nodeError}>
                        <strong>Error:</strong> {result.error}
                      </div>
                    )}
                    {(result.outputs || result.output) && (
                      <div style={styles.nodeOutput}>
                        <strong>Output:</strong>
                        <pre style={styles.outputJson}>
                          {JSON.stringify(result.outputs || result.output, null, 2)}
                        </pre>
                      </div>
                    )}
                  </div>
                )}
              </div>
            ))
          )}
        </div>

        {isRunningStatus(execution?.status) && (
          <div style={styles.footer}>
            <label style={styles.autoRefreshLabel}>
              <input
                type="checkbox"
                checked={autoRefresh}
                onChange={(e) => setAutoRefresh(e.target.checked)}
              />
              Auto-refresh
            </label>
          </div>
        )}

        {execution?.status === 'waiting_approval' && (
          <WaitingApprovalActions execution={execution} onRefresh={onRefresh} />
        )}
        {execution?.status === 'waiting_input' && (
          <WaitingInputForm execution={execution} onRefresh={onRefresh} />
        )}
      </div>
    </div>
  );
}

function StatusBadge({ status }) {
  const config = getStatusConfig(status);

  return (
    <div style={{ ...styles.statusBadge, background: config.bg, color: config.color }}>
      {config.icon}
      <span>{status}</span>
    </div>
  );
}

function NodeStatusIcon({ status }) {
  switch (status) {
    case 'success':
      return <CheckCircle size={16} style={{ color: '#01B574' }} />;
    case 'failed':
      return <XCircle size={16} style={{ color: '#ef4444' }} />;
    case 'waiting':
      return <Pause size={16} style={{ color: '#f59e0b' }} />;
    case 'running':
      return <RefreshCw size={16} style={{ color: '#3b82f6' }} className="spin" />;
    case 'skipped':
      return <Clock size={16} style={{ color: '#64748b' }} />;
    default:
      return <Clock size={16} style={{ color: '#64748b' }} />;
  }
}

function WaitingApprovalActions({ execution, onRefresh }) {
  const [isApproving, setIsApproving] = useState(false);
  const [notes, setNotes] = useState('');

  const handleApprove = async () => {
    setIsApproving(true);
    try {
      const response = await fetch(
        `${API_BASE}/api/v1/playbooks/executions/${execution.execution_id}/approve/${execution.current_node_id}`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ notes }),
        }
      );
      if (response.ok) {
        onRefresh();
      }
    } catch (err) {
    } finally {
      setIsApproving(false);
    }
  };

  const handleReject = async () => {
    setIsApproving(true);
    try {
      const response = await fetch(
        `${API_BASE}/api/v1/playbooks/executions/${execution.execution_id}/reject/${execution.current_node_id}`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ notes }),
        }
      );
      if (response.ok) {
        onRefresh();
      }
    } catch (err) {
    } finally {
      setIsApproving(false);
    }
  };

  return (
    <div style={styles.approvalSection}>
      <h4 style={styles.approvalTitle}>Action Required</h4>
      <p style={styles.approvalText}>
        This execution is waiting for approval at node: {execution.current_node_id}
      </p>
      <textarea
        value={notes}
        onChange={(e) => setNotes(e.target.value)}
        placeholder="Add notes (optional)"
        style={styles.notesInput}
        rows={2}
      />
      <div style={styles.approvalButtons}>
        <button
          onClick={handleReject}
          style={styles.rejectButton}
          disabled={isApproving}
        >
          <XCircle size={16} />
          Reject
        </button>
        <button
          onClick={handleApprove}
          style={styles.approveButton}
          disabled={isApproving}
        >
          <CheckCircle size={16} />
          Approve
        </button>
      </div>
    </div>
  );
}

function WaitingInputForm({ execution, onRefresh }) {
  const nodeId = execution.current_node_id;
  const nodeOutputs = execution?.node_results?.[nodeId]?.outputs || {};
  const fields = Array.isArray(nodeOutputs.fields) ? nodeOutputs.fields : [];
  const [formData, setFormData] = useState({});
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState('');

  const handleSubmit = async () => {
    setIsSubmitting(true);
    setSubmitError('');
    try {
      const response = await fetch(
        `${API_BASE}/api/v1/playbooks/executions/${execution.execution_id}/submit-form/${nodeId}`,
        {
          method: 'POST',
          credentials: 'include',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ form_data: formData }),
        }
      );
      if (!response.ok) {
        const err = await response.json().catch(() => ({}));
        setSubmitError(err.detail || 'Submission failed');
      } else {
        await onRefresh();
      }
    } catch (e) {
      setSubmitError('Network error. Please try again.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const renderField = (field, index) => {
    const key = field.name || `field_${index}`;
    const val = formData[key] || '';
    const update = (v) => setFormData((prev) => ({ ...prev, [key]: v }));

    if (field.type === 'select' && Array.isArray(field.options)) {
      return (
        <div key={key} style={{ marginBottom: 10 }}>
          <label style={styles.formLabel}>{field.label || key}{field.required ? ' *' : ''}</label>
          <select value={val} onChange={(e) => update(e.target.value)} style={styles.formInput}>
            <option value="">Select...</option>
            {field.options.map((opt) => (
              <option key={opt.value || opt} value={opt.value || opt}>{opt.label || opt}</option>
            ))}
          </select>
        </div>
      );
    }
    if (field.type === 'textarea') {
      return (
        <div key={key} style={{ marginBottom: 10 }}>
          <label style={styles.formLabel}>{field.label || key}{field.required ? ' *' : ''}</label>
          <textarea value={val} onChange={(e) => update(e.target.value)} rows={3} style={styles.notesInput} placeholder={field.placeholder || ''} />
        </div>
      );
    }
    return (
      <div key={key} style={{ marginBottom: 10 }}>
        <label style={styles.formLabel}>{field.label || key}{field.required ? ' *' : ''}</label>
        <input type={field.type === 'number' ? 'number' : 'text'} value={val} onChange={(e) => update(e.target.value)} style={styles.formInput} placeholder={field.placeholder || ''} />
      </div>
    );
  };

  return (
    <div style={styles.approvalSection}>
      <h4 style={styles.approvalTitle}>Form Input Required</h4>
      <p style={styles.approvalText}>
        Node <strong>{nodeId}</strong> is waiting for form submission.
      </p>
      {fields.length > 0 ? (
        fields.map((field, i) => renderField(field, i))
      ) : (
        <div style={{ marginBottom: 10 }}>
          <label style={styles.formLabel}>Response</label>
          <textarea
            value={formData._response || ''}
            onChange={(e) => setFormData({ _response: e.target.value })}
            rows={3}
            style={styles.notesInput}
            placeholder="Enter your response..."
          />
        </div>
      )}
      {submitError && <div style={{ color: '#ef4444', fontSize: 12, marginBottom: 8 }}>{submitError}</div>}
      <button onClick={handleSubmit} disabled={isSubmitting} style={styles.approveButton}>
        <CheckCircle size={16} />
        {isSubmitting ? 'Submitting...' : 'Submit'}
      </button>
    </div>
  );
}

const isRunningStatus = (status) => {
  return ['pending', 'running'].includes(status);
};

const getStatusConfig = (status) => {
  const configs = {
    pending: {
      bg: 'rgba(100, 116, 139, 0.2)',
      color: '#94a3b8',
      icon: <Clock size={14} />,
    },
    running: {
      bg: 'rgba(59, 130, 246, 0.2)',
      color: '#3b82f6',
      icon: <RefreshCw size={14} className="spin" />,
    },
    waiting_approval: {
      bg: 'rgba(245, 158, 11, 0.2)',
      color: '#f59e0b',
      icon: <Pause size={14} />,
    },
    waiting_input: {
      bg: 'rgba(236, 72, 153, 0.2)',
      color: '#ec4899',
      icon: <Pause size={14} />,
    },
    waiting_file: {
      bg: 'rgba(236, 72, 153, 0.2)',
      color: '#ec4899',
      icon: <Pause size={14} />,
    },
    completed: {
      bg: 'rgba(1, 181, 116, 0.2)',
      color: '#01B574',
      icon: <CheckCircle size={14} />,
    },
    failed: {
      bg: 'rgba(239, 68, 68, 0.2)',
      color: '#ef4444',
      icon: <XCircle size={14} />,
    },
    cancelled: {
      bg: 'rgba(100, 116, 139, 0.2)',
      color: '#94a3b8',
      icon: <XCircle size={14} />,
    },
    timeout: {
      bg: 'rgba(239, 68, 68, 0.2)',
      color: '#ef4444',
      icon: <AlertTriangle size={14} />,
    },
  };
  return configs[status] || configs.pending;
};

const styles = {
  overlay: {
    position: 'fixed',
    top: 0,
    left: 0,
    right: 0,
    bottom: 0,
    background: 'rgba(0, 0, 0, 0.7)',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    zIndex: 1000,
  },
  modal: {
    width: '600px',
    maxHeight: '80vh',
    background: 'var(--bg-secondary, #1e293b)',
    borderRadius: '12px',
    border: '1px solid var(--border-color, #334155)',
    display: 'flex',
    flexDirection: 'column',
    overflow: 'hidden',
  },
  header: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    padding: '16px 20px',
    borderBottom: '1px solid var(--border-color, #334155)',
  },
  headerInfo: {
    display: 'flex',
    alignItems: 'center',
    gap: '12px',
  },
  title: {
    margin: 0,
    fontSize: '16px',
    fontWeight: '600',
    color: 'var(--text-primary, #f0f6fc)',
  },
  headerActions: {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
  },
  refreshButton: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    width: '32px',
    height: '32px',
    border: '1px solid var(--border-color, #334155)',
    borderRadius: '6px',
    background: 'transparent',
    color: 'var(--text-secondary, #94a3b8)',
    cursor: 'pointer',
  },
  closeButton: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    width: '32px',
    height: '32px',
    border: 'none',
    borderRadius: '6px',
    background: 'transparent',
    color: 'var(--text-secondary, #94a3b8)',
    cursor: 'pointer',
  },
  statusBadge: {
    display: 'flex',
    alignItems: 'center',
    gap: '6px',
    padding: '4px 10px',
    borderRadius: '12px',
    fontSize: '12px',
    fontWeight: '500',
  },
  info: {
    padding: '16px 20px',
    borderBottom: '1px solid var(--border-color, #334155)',
    display: 'grid',
    gridTemplateColumns: 'repeat(2, 1fr)',
    gap: '12px',
  },
  infoItem: {
    display: 'flex',
    flexDirection: 'column',
    gap: '4px',
  },
  infoLabel: {
    fontSize: '11px',
    color: 'var(--text-secondary, #94a3b8)',
    textTransform: 'uppercase',
  },
  infoValue: {
    fontSize: '13px',
    color: 'var(--text-primary, #f0f6fc)',
  },
  errorBanner: {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
    padding: '12px 20px',
    background: 'rgba(239, 68, 68, 0.1)',
    borderBottom: '1px solid rgba(239, 68, 68, 0.2)',
    color: '#ef4444',
    fontSize: '13px',
  },
  nodeResults: {
    flex: 1,
    overflow: 'auto',
    padding: '16px 20px',
  },
  sectionTitle: {
    margin: '0 0 12px 0',
    fontSize: '12px',
    fontWeight: '600',
    color: 'var(--text-secondary, #94a3b8)',
    textTransform: 'uppercase',
  },
  noResults: {
    textAlign: 'center',
    padding: '24px',
    color: 'var(--text-secondary, #94a3b8)',
    fontSize: '13px',
  },
  nodeResult: {
    marginBottom: '8px',
    borderRadius: '8px',
    background: 'rgba(255,255,255,0.03)',
    overflow: 'hidden',
  },
  nodeHeader: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    padding: '12px 16px',
    cursor: 'pointer',
  },
  nodeInfo: {
    display: 'flex',
    alignItems: 'center',
    gap: '10px',
  },
  nodeId: {
    fontSize: '13px',
    fontWeight: '500',
    color: 'var(--text-primary, #f0f6fc)',
  },
  nodeType: {
    fontSize: '12px',
    color: 'var(--text-secondary, #94a3b8)',
  },
  nodeHeaderRight: {
    display: 'flex',
    alignItems: 'center',
    gap: '12px',
    color: 'var(--text-secondary, #94a3b8)',
  },
  executionTime: {
    fontSize: '11px',
    color: 'var(--text-secondary, #94a3b8)',
  },
  nodeDetails: {
    padding: '12px 16px',
    borderTop: '1px solid var(--border-color, #334155)',
    background: 'rgba(0,0,0,0.2)',
  },
  nodeError: {
    color: '#ef4444',
    fontSize: '12px',
    marginBottom: '8px',
  },
  nodeOutput: {
    fontSize: '12px',
    color: 'var(--text-primary, #f0f6fc)',
  },
  outputJson: {
    margin: '8px 0 0 0',
    padding: '12px',
    background: 'rgba(0,0,0,0.3)',
    borderRadius: '6px',
    fontSize: '11px',
    overflow: 'auto',
    maxHeight: '200px',
  },
  footer: {
    padding: '12px 20px',
    borderTop: '1px solid var(--border-color, #334155)',
  },
  autoRefreshLabel: {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
    fontSize: '13px',
    color: 'var(--text-secondary, #94a3b8)',
    cursor: 'pointer',
  },
  approvalSection: {
    padding: '16px 20px',
    borderTop: '1px solid var(--border-color, #334155)',
    background: 'rgba(245, 158, 11, 0.05)',
  },
  approvalTitle: {
    margin: '0 0 8px 0',
    fontSize: '14px',
    fontWeight: '600',
    color: '#f59e0b',
  },
  approvalText: {
    margin: '0 0 12px 0',
    fontSize: '13px',
    color: 'var(--text-secondary, #94a3b8)',
  },
  notesInput: {
    width: '100%',
    padding: '10px 12px',
    border: '1px solid var(--border-color, #334155)',
    borderRadius: '6px',
    background: 'rgba(255,255,255,0.05)',
    color: 'var(--text-primary, #f0f6fc)',
    fontSize: '13px',
    resize: 'none',
    marginBottom: '12px',
  },
  approvalButtons: {
    display: 'flex',
    gap: '8px',
    justifyContent: 'flex-end',
  },
  rejectButton: {
    display: 'flex',
    alignItems: 'center',
    gap: '6px',
    padding: '10px 16px',
    border: '1px solid rgba(239, 68, 68, 0.3)',
    borderRadius: '6px',
    background: 'transparent',
    color: '#ef4444',
    fontSize: '13px',
    cursor: 'pointer',
  },
  approveButton: {
    display: 'flex',
    alignItems: 'center',
    gap: '6px',
    padding: '10px 16px',
    border: 'none',
    borderRadius: '6px',
    background: 'linear-gradient(135deg, #3CB371, #2e8b57)',
    color: 'white',
    fontSize: '13px',
    fontWeight: '500',
    cursor: 'pointer',
  },
  formLabel: {
    display: 'block',
    fontSize: '12px',
    fontWeight: '500',
    color: 'var(--text-secondary, #94a3b8)',
    marginBottom: 4,
  },
  formInput: {
    width: '100%',
    padding: '8px 10px',
    border: '1px solid var(--border-color, #334155)',
    borderRadius: 6,
    background: 'var(--bg-tertiary, #0f172a)',
    color: 'var(--text-primary, #f0f6fc)',
    fontSize: '13px',
  },
};

export default ExecutionView;
