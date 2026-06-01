/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { getAuthHeaders, API_BASE_URL } from '../utils/api';
import './PostResolution.css';

// PostResolution component - Updated 2025-12-25 to fix JSON parsing
const API_BASE = API_BASE_URL;

function PostResolution() {
  const [rules, setRules] = useState([]);
  const [recentTasks, setRecentTasks] = useState([]);
  const [emailLogs, setEmailLogs] = useState([]);
  const [smtpStatus, setSmtpStatus] = useState(null);
  const [notificationRules, setNotificationRules] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [showNewRuleModal, setShowNewRuleModal] = useState(false);
  const [activeTab, setActiveTab] = useState('rules');
  const [newRule, setNewRule] = useState({
    name: '',
    description: '',
    conditions: { severity: [], disposition: [], state: ['CLOSED', 'RESOLVED'] },
    actions: [],
    enabled: true,
    priority: 10
  });

  useEffect(() => {
    fetchRules();
    fetchRecentTasks();
    fetchEmailLogs();
    fetchSmtpStatus();
    fetchNotificationRules();
  }, []);

  const fetchRules = async () => {
    try {
      const response = await fetch(`${API_BASE}/api/v1/post-resolution/rules`, {
        headers: getAuthHeaders()
      });
      if (response.ok) {
        const data = await response.json();
        // Parse JSON strings for conditions and actions if needed
        const parsedRules = (data.rules || []).map(rule => ({
          ...rule,
          conditions: typeof rule.conditions === 'string' ? JSON.parse(rule.conditions) : (rule.conditions || {}),
          actions: typeof rule.actions === 'string' ? JSON.parse(rule.actions) : (rule.actions || [])
        }));
        setRules(parsedRules);
      }
    } catch (err) {
    } finally {
      setLoading(false);
    }
  };

  const fetchRecentTasks = async () => {
    try {
      const invResponse = await fetch(`${API_BASE}/api/v1/admin/investigations?limit=5&state=CLOSED`, {
        headers: getAuthHeaders()
      });
      if (invResponse.ok) {
        const invData = await invResponse.json();
        const investigations = invData.investigations || [];

        const allTasks = [];
        for (const inv of investigations.slice(0, 5)) {
          try {
            const taskResponse = await fetch(
              `${API_BASE}/api/v1/post-resolution/investigations/${inv.investigation_id}/tasks`,
              { headers: getAuthHeaders() }
            );
            if (taskResponse.ok) {
              const taskData = await taskResponse.json();
              if (taskData.tasks) {
                allTasks.push(...taskData.tasks.map(t => ({
                  ...t,
                  investigation_id: inv.investigation_id
                })));
              }
            }
          } catch (e) {
            // Ignore individual failures
          }
        }
        setRecentTasks(allTasks.slice(0, 10));
      }
    } catch (err) {
    }
  };

  const fetchEmailLogs = async () => {
    try {
      const response = await fetch(`${API_BASE}/api/v1/notifications/logs?limit=20`, {
        headers: getAuthHeaders()
      });
      if (response.ok) {
        const data = await response.json();
        setEmailLogs(data.logs || []);
      }
    } catch (err) {
    }
  };

  const fetchSmtpStatus = async () => {
    try {
      const response = await fetch(`${API_BASE}/api/v1/notifications/smtp`, {
        headers: getAuthHeaders()
      });
      if (response.ok) {
        const data = await response.json();
        setSmtpStatus(data);
      }
    } catch (err) {
    }
  };

  const fetchNotificationRules = async () => {
    try {
      const response = await fetch(`${API_BASE}/api/v1/notifications/rules`, {
        headers: getAuthHeaders()
      });
      if (response.ok) {
        const data = await response.json();
        // Filter for investigation-related rules
        const invRules = (data.rules || []).filter(r =>
          r.event_types?.includes('investigation_closed') ||
          r.event_types?.includes('ai_verdict_true_positive')
        );
        setNotificationRules(invRules);
      }
    } catch (err) {
    }
  };

  const createRule = async () => {
    try {
      const response = await fetch(`${API_BASE}/api/v1/post-resolution/rules`, {
        method: 'POST',
        headers: { ...getAuthHeaders(), 'Content-Type': 'application/json' },
        body: JSON.stringify(newRule)
      });

      if (response.ok) {
        setShowNewRuleModal(false);
        setNewRule({
          name: '',
          description: '',
          conditions: { severity: [], disposition: [], state: ['CLOSED', 'RESOLVED'] },
          actions: [],
          enabled: true,
          priority: 10
        });
        fetchRules();
      } else {
        const data = await response.json();
        setError(data.detail || 'Failed to create rule');
      }
    } catch (err) {
      setError(err.message);
    }
  };

  const toggleRule = async (ruleId, enabled) => {
    try {
      await fetch(`${API_BASE}/api/v1/post-resolution/rules/${ruleId}`, {
        method: 'PUT',
        headers: { ...getAuthHeaders(), 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled: !enabled })
      });
      fetchRules();
    } catch (err) {
    }
  };

  const deleteRule = async (ruleId) => {
    if (!window.confirm('Are you sure you want to delete this rule?')) return;

    try {
      await fetch(`${API_BASE}/api/v1/post-resolution/rules/${ruleId}`, {
        method: 'DELETE',
        headers: getAuthHeaders()
      });
      fetchRules();
    } catch (err) {
    }
  };

  const addAction = (actionType) => {
    const actionConfigs = {
      email_summary: { type: 'email_summary', config: { recipients: [], template: 'standard', attach_pdf: false } },
      itsm_export: { type: 'itsm_export', config: { system: 'servicenow', ticket_type: 'problem' } },
      cmdb_update: { type: 'cmdb_update', config: { action: 'mark_remediated' } },
      create_blocklist: { type: 'create_blocklist', config: {} }
    };

    setNewRule({
      ...newRule,
      actions: [...newRule.actions, actionConfigs[actionType]]
    });
  };

  const removeAction = (index) => {
    const newActions = [...newRule.actions];
    newActions.splice(index, 1);
    setNewRule({ ...newRule, actions: newActions });
  };

  if (loading) {
    return (
      <div className="post-resolution-container">
        <div className="loading-spinner">Loading post-resolution settings...</div>
      </div>
    );
  }

  return (
    <div className="post-resolution-container">
      <div className="post-resolution-header">
        <div className="header-content">
          <h1>Post-Resolution Workflow</h1>
          <p className="header-subtitle">
            Configure automated tasks and notifications when investigations are closed
          </p>
        </div>
        <button
          className="btn-primary"
          onClick={() => setShowNewRuleModal(true)}
        >
          + Create Rule
        </button>
      </div>

      {error && (
        <div className="error-banner">
          {error}
          <button onClick={() => setError(null)}>×</button>
        </div>
      )}

      {/* Tab Navigation */}
      <div className="tab-nav">
        <button
          className={`tab-btn ${activeTab === 'rules' ? 'active' : ''}`}
          onClick={() => setActiveTab('rules')}
        >
          Automation Rules
        </button>
        <button
          className={`tab-btn ${activeTab === 'tasks' ? 'active' : ''}`}
          onClick={() => setActiveTab('tasks')}
        >
          Recent Tasks
        </button>
        <button
          className={`tab-btn ${activeTab === 'notifications' ? 'active' : ''}`}
          onClick={() => setActiveTab('notifications')}
        >
          Email Notifications
        </button>
      </div>

      {/* Rules Tab */}
      {activeTab === 'rules' && (
        <>
          <div className="section">
            <h2>Automation Rules</h2>
            <p className="section-description">
              Rules automatically create tasks when investigations match the specified conditions.
            </p>

            {rules.length === 0 ? (
              <div className="empty-state">
                <div className="empty-icon">📋</div>
                <h3>No Rules Configured</h3>
                <p>Create your first rule to automate post-resolution tasks.</p>
                <button
                  className="btn-primary"
                  onClick={() => setShowNewRuleModal(true)}
                >
                  Create First Rule
                </button>
              </div>
            ) : (
              <div className="rules-grid">
                {rules.map(rule => (
                  <div key={rule.id} className={`rule-card ${!rule.enabled ? 'disabled' : ''}`}>
                    <div className="rule-header">
                      <h3>{rule.name}</h3>
                      <div className="rule-controls">
                        <label className="toggle-switch">
                          <input
                            type="checkbox"
                            checked={rule.enabled}
                            onChange={() => toggleRule(rule.id, rule.enabled)}
                          />
                          <span className="toggle-slider"></span>
                        </label>
                        <button
                          className="btn-icon btn-danger"
                          onClick={() => deleteRule(rule.id)}
                          title="Delete rule"
                        >
                          🗑️
                        </button>
                      </div>
                    </div>

                    {rule.description && (
                      <p className="rule-description">{rule.description}</p>
                    )}

                    <div className="rule-details">
                      <div className="detail-section">
                        <span className="detail-label">Conditions:</span>
                        <div className="condition-tags">
                          {rule.conditions?.severity?.map(s => (
                            <span key={s} className={`tag severity-${s}`}>{s}</span>
                          ))}
                          {rule.conditions?.disposition?.map(d => (
                            <span key={d} className="tag disposition">{d}</span>
                          ))}
                          {rule.conditions?.state?.map(s => (
                            <span key={s} className="tag state">{s}</span>
                          ))}
                        </div>
                      </div>

                      <div className="detail-section">
                        <span className="detail-label">Actions:</span>
                        <div className="action-tags">
                          {rule.actions?.map((action, i) => (
                            <span key={i} className="tag action">{action.type}</span>
                          ))}
                        </div>
                      </div>

                      <div className="detail-section">
                        <span className="detail-label">Priority:</span>
                        <span className="priority-badge">{rule.priority}</span>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Task Types Reference */}
          <div className="section">
            <h2>Available Task Types</h2>
            <div className="task-types-grid">
              <div className="task-type-card">
                <div className="task-icon">📧</div>
                <h3>Email Summary</h3>
                <p>Send case summary email to configured recipients</p>
              </div>
              <div className="task-type-card">
                <div className="task-icon">🎫</div>
                <h3>ITSM Export</h3>
                <p>Create ticket in ServiceNow, Jira, or other ITSM</p>
              </div>
              <div className="task-type-card">
                <div className="task-icon">🖥️</div>
                <h3>CMDB Update</h3>
                <p>Mark affected assets as remediated in CMDB</p>
              </div>
              <div className="task-type-card">
                <div className="task-icon">🚫</div>
                <h3>Create Blocklist</h3>
                <p>Add malicious IOCs to blocklist automatically</p>
              </div>
            </div>
          </div>
        </>
      )}

      {/* Tasks Tab */}
      {activeTab === 'tasks' && (
        <div className="section">
          <h2>Recent Tasks</h2>
          <p className="section-description">
            Post-resolution tasks from recently closed investigations.
          </p>

          {recentTasks.length === 0 ? (
            <div className="empty-state small">
              <p>No recent tasks</p>
            </div>
          ) : (
            <div className="tasks-table">
              <table>
                <thead>
                  <tr>
                    <th>Investigation</th>
                    <th>Task Type</th>
                    <th>Status</th>
                    <th>Created</th>
                    <th>Completed</th>
                  </tr>
                </thead>
                <tbody>
                  {recentTasks.map(task => (
                    <tr key={task.id}>
                      <td>
                        <Link to={`/investigations/${task.investigation_id}`}>
                          {task.investigation_id?.substring(0, 8)}...
                        </Link>
                      </td>
                      <td>
                        <span className={`task-type ${task.task_type}`}>
                          {task.task_type?.replace(/_/g, ' ')}
                        </span>
                      </td>
                      <td>
                        <span className={`status-badge ${task.status}`}>
                          {task.status}
                        </span>
                      </td>
                      <td>{new Date(task.created_at).toLocaleString()}</td>
                      <td>
                        {task.completed_at
                          ? new Date(task.completed_at).toLocaleString()
                          : '-'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* Email Notifications Tab */}
      {activeTab === 'notifications' && (
        <>
          {/* SMTP Status Card */}
          <div className="section">
            <div className="smtp-status-header">
              <h2>Email Configuration</h2>
              <Link to="/settings" className="btn-secondary">
                Configure SMTP Settings
              </Link>
            </div>

            <div className="smtp-status-card">
              <div className="status-indicator">
                <span className={`status-dot ${smtpStatus?.enabled ? 'active' : 'inactive'}`}></span>
                <span className="status-text">
                  {smtpStatus?.enabled ? 'Email Enabled' : 'Email Disabled'}
                </span>
              </div>
              {smtpStatus?.host && (
                <div className="smtp-details">
                  <span>Server: {smtpStatus.host}:{smtpStatus.port}</span>
                  <span>From: {smtpStatus.from_email}</span>
                </div>
              )}
              {!smtpStatus?.host && (
                <p className="smtp-warning">
                  SMTP not configured. Email notifications will not be sent.
                </p>
              )}
            </div>
          </div>

          {/* Investigation Notification Rules */}
          <div className="section">
            <div className="smtp-status-header">
              <h2>Notification Rules</h2>
              <Link to="/settings" className="btn-secondary">
                Manage All Rules
              </Link>
            </div>
            <p className="section-description">
              Email notification rules for investigation events (investigation_closed, ai_verdict_true_positive)
            </p>

            {notificationRules.length === 0 ? (
              <div className="empty-state small">
                <div className="empty-icon">🔔</div>
                <h3>No Investigation Notification Rules</h3>
                <p>Create notification rules in Settings to receive emails when investigations close.</p>
                <Link to="/settings" className="btn-primary">
                  Go to Notification Settings
                </Link>
              </div>
            ) : (
              <div className="notification-rules-list">
                {notificationRules.map(rule => (
                  <div key={rule.id} className={`notification-rule-card ${!rule.enabled ? 'disabled' : ''}`}>
                    <div className="rule-header">
                      <h3>{rule.name}</h3>
                      <span className={`status-badge ${rule.enabled ? 'active' : 'inactive'}`}>
                        {rule.enabled ? 'Active' : 'Disabled'}
                      </span>
                    </div>
                    <div className="rule-meta">
                      <span>Events: {rule.event_types?.join(', ')}</span>
                      <span>Recipients: {rule.recipients?.length || 0}</span>
                      {rule.severity_filter?.length > 0 && (
                        <span>Severity: {rule.severity_filter.join(', ')}</span>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Email Delivery Log */}
          <div className="section">
            <h2>Recent Email Deliveries</h2>
            <p className="section-description">
              Log of emails sent for investigation events.
            </p>

            {emailLogs.length === 0 ? (
              <div className="empty-state small">
                <p>No email deliveries yet</p>
              </div>
            ) : (
              <div className="tasks-table">
                <table>
                  <thead>
                    <tr>
                      <th>Sent At</th>
                      <th>Subject</th>
                      <th>Recipients</th>
                      <th>Event Type</th>
                      <th>Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {emailLogs.map(log => (
                      <tr key={log.id}>
                        <td>{new Date(log.sent_at || log.created_at).toLocaleString()}</td>
                        <td className="email-subject">{log.subject?.substring(0, 50)}{log.subject?.length > 50 ? '...' : ''}</td>
                        <td>{log.recipients?.join(', ') || log.to_email}</td>
                        <td>
                          <span className="tag action">{log.event_type || 'email'}</span>
                        </td>
                        <td>
                          <span className={`status-badge ${log.status}`}>
                            {log.status}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            <div className="mailhog-link">
              <p>
                View all emails in the development mail server:{' '}
                <a href="http://localhost:8025" target="_blank" rel="noopener noreferrer">
                  Mailhog (localhost:8025)
                </a>
              </p>
            </div>
          </div>
        </>
      )}

      {/* New Rule Modal */}
      {showNewRuleModal && (
        <div className="modal-overlay" onClick={() => setShowNewRuleModal(false)}>
          <div className="modal-content" onClick={e => e.stopPropagation()}>
            <div className="modal-header">
              <h2>Create Post-Resolution Rule</h2>
              <button
                className="modal-close"
                onClick={() => setShowNewRuleModal(false)}
              >
                ×
              </button>
            </div>

            <div className="modal-body">
              <div className="form-group">
                <label>Rule Name *</label>
                <input
                  type="text"
                  value={newRule.name}
                  onChange={e => setNewRule({ ...newRule, name: e.target.value })}
                  placeholder="e.g., Send Summary for Critical Incidents"
                />
              </div>

              <div className="form-group">
                <label>Description</label>
                <textarea
                  value={newRule.description}
                  onChange={e => setNewRule({ ...newRule, description: e.target.value })}
                  placeholder="What does this rule do?"
                  rows={2}
                />
              </div>

              <div className="form-group">
                <label>Priority</label>
                <input
                  type="number"
                  value={newRule.priority}
                  onChange={e => setNewRule({ ...newRule, priority: parseInt(e.target.value) || 10 })}
                  min={1}
                  max={100}
                />
                <small>Lower numbers run first</small>
              </div>

              <div className="form-section">
                <h3>Conditions</h3>
                <p className="form-help">Investigation must match these conditions to trigger the rule</p>

                <div className="form-group">
                  <label>Severity Filter</label>
                  <div className="checkbox-group">
                    {['critical', 'high', 'medium', 'low'].map(sev => (
                      <label key={sev} className="checkbox-label">
                        <input
                          type="checkbox"
                          checked={newRule.conditions.severity?.includes(sev)}
                          onChange={e => {
                            const severity = e.target.checked
                              ? [...(newRule.conditions.severity || []), sev]
                              : (newRule.conditions.severity || []).filter(s => s !== sev);
                            setNewRule({
                              ...newRule,
                              conditions: { ...newRule.conditions, severity }
                            });
                          }}
                        />
                        {sev}
                      </label>
                    ))}
                  </div>
                  <small>Leave empty to match any severity</small>
                </div>

                <div className="form-group">
                  <label>Disposition Filter</label>
                  <div className="checkbox-group">
                    {['TRUE_POSITIVE', 'FALSE_POSITIVE', 'BENIGN', 'MALICIOUS', 'SUSPICIOUS'].map(disp => (
                      <label key={disp} className="checkbox-label">
                        <input
                          type="checkbox"
                          checked={newRule.conditions.disposition?.includes(disp)}
                          onChange={e => {
                            const disposition = e.target.checked
                              ? [...(newRule.conditions.disposition || []), disp]
                              : (newRule.conditions.disposition || []).filter(d => d !== disp);
                            setNewRule({
                              ...newRule,
                              conditions: { ...newRule.conditions, disposition }
                            });
                          }}
                        />
                        {disp}
                      </label>
                    ))}
                  </div>
                </div>
              </div>

              <div className="form-section">
                <h3>Actions</h3>
                <p className="form-help">Tasks to create when the rule matches</p>

                <div className="action-buttons">
                  <button
                    className="btn-secondary"
                    onClick={() => addAction('email_summary')}
                  >
                    + Email Summary
                  </button>
                  <button
                    className="btn-secondary"
                    onClick={() => addAction('itsm_export')}
                  >
                    + ITSM Export
                  </button>
                  <button
                    className="btn-secondary"
                    onClick={() => addAction('cmdb_update')}
                  >
                    + CMDB Update
                  </button>
                  <button
                    className="btn-secondary"
                    onClick={() => addAction('create_blocklist')}
                  >
                    + Create Blocklist
                  </button>
                </div>

                {newRule.actions.length > 0 && (
                  <div className="actions-list">
                    {newRule.actions.map((action, index) => (
                      <div key={index} className="action-item">
                        <span className="action-name">{action.type.replace(/_/g, ' ')}</span>
                        <button
                          className="btn-icon"
                          onClick={() => removeAction(index)}
                        >
                          ×
                        </button>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              <div className="form-group">
                <label className="checkbox-label">
                  <input
                    type="checkbox"
                    checked={newRule.enabled}
                    onChange={e => setNewRule({ ...newRule, enabled: e.target.checked })}
                  />
                  Enable rule immediately
                </label>
              </div>
            </div>

            <div className="modal-footer">
              <button
                className="btn-secondary"
                onClick={() => setShowNewRuleModal(false)}
              >
                Cancel
              </button>
              <button
                className="btn-primary"
                onClick={createRule}
                disabled={!newRule.name || newRule.actions.length === 0}
              >
                Create Rule
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default PostResolution;
