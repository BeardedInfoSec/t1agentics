/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

import React, { useState, useEffect } from 'react';
import { authFetch, API_BASE_URL } from '../utils/api';
import { useToast } from './ui/Toast';

function WebhookManager() {
  const toast = useToast();
  const [webhooks, setWebhooks] = useState([]);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [showDisplayModal, setShowDisplayModal] = useState(false);
  const [newWebhook, setNewWebhook] = useState(null);
  const [copied, setCopied] = useState(null);
  const [editingWebhook, setEditingWebhook] = useState(null);
  const [editForm, setEditForm] = useState({
    name: '', description: '', rate_limit: 100, enabled: true,
  });
  const [formData, setFormData] = useState({
    name: '',
    description: '',
    rate_limit: 100
  });

  useEffect(() => {
    loadWebhooks();
  }, []);

  const loadWebhooks = async () => {
    try {
      const response = await authFetch(`${API_BASE_URL}/api/v1/admin/webhooks`);
      if (response.ok) {
        const data = await response.json();
        setWebhooks(data);
      }
    } catch (error) {
    }
  };

  const handleCreateWebhook = async (e) => {
    e.preventDefault();
    try {
      const response = await authFetch(`${API_BASE_URL}/api/v1/admin/webhooks`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(formData)
      });

      if (response.ok) {
        const data = await response.json();
        setNewWebhook(data);
        setShowCreateModal(false);
        setShowDisplayModal(true);
        setFormData({ name: '', description: '', rate_limit: 100 });
        loadWebhooks();
      } else {
        toast.error('Failed to create webhook');
      }
    } catch (error) {
      toast.error('Error creating webhook');
    }
  };

  const openEditWebhook = (webhook) => {
    setEditingWebhook(webhook);
    setEditForm({
      name: webhook.name || '',
      description: webhook.description || '',
      rate_limit: webhook.rate_limit ?? 100,
      enabled: webhook.enabled !== false,
    });
  };

  const handleUpdateWebhook = async (e) => {
    e.preventDefault();
    if (!editingWebhook) return;
    try {
      const response = await authFetch(
        `${API_BASE_URL}/api/v1/admin/webhooks/${editingWebhook.name}`,
        {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(editForm),
        },
      );
      if (response.ok) {
        toast.success('Webhook updated');
        setEditingWebhook(null);
        loadWebhooks();
      } else {
        toast.error('Failed to update webhook');
      }
    } catch (error) {
      toast.error('Error updating webhook');
    }
  };

  const handleDeleteWebhook = async (webhookName) => {
    if (!window.confirm('Delete this webhook?')) return;
    try {
      const response = await authFetch(`${API_BASE_URL}/api/v1/admin/webhooks/${webhookName}`, {
        method: 'DELETE',
      });
      if (response.ok) {
        loadWebhooks();
      }
    } catch (error) {
      toast.error('Failed to delete webhook');
    }
  };

  const copyToClipboard = (text, field) => {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(field);
      setTimeout(() => setCopied(null), 2000);
    });
  };

  const styles = {
    container: { padding: '0' },
    header: {
      display: 'flex',
      justifyContent: 'space-between',
      alignItems: 'center',
      marginBottom: '1rem'
    },
    title: { fontSize: '1.25rem', fontWeight: '600', margin: 0, color: 'var(--text-primary)' },
    btn: {
      padding: '0.5rem 1rem',
      borderRadius: 'var(--radius-md)',
      border: 'none',
      cursor: 'pointer',
      fontWeight: '500',
      fontSize: '0.875rem'
    },
    btnPrimary: {
      background: 'linear-gradient(135deg, var(--primary), #2e8b57)',
      color: 'white'
    },
    btnSecondary: {
      background: 'var(--bg-tertiary)',
      color: 'var(--text-primary)',
      border: '1px solid var(--border-color)'
    },
    btnDanger: {
      background: 'rgba(239, 68, 68, 0.15)',
      color: '#ef4444',
      padding: '0.375rem 0.75rem',
      fontSize: '0.75rem'
    },
    table: {
      width: '100%',
      borderCollapse: 'collapse',
      background: 'var(--bg-secondary)',
      borderRadius: 'var(--radius-md)',
      overflow: 'hidden'
    },
    th: {
      textAlign: 'left',
      padding: '0.75rem 1rem',
      fontSize: '0.7rem',
      fontWeight: '600',
      color: 'var(--text-muted)',
      textTransform: 'uppercase',
      letterSpacing: '0.05em',
      borderBottom: '1px solid var(--border-color)',
      background: 'var(--bg-tertiary)'
    },
    td: {
      padding: '0.75rem 1rem',
      borderBottom: '1px solid var(--border-color)',
      fontSize: '0.875rem',
      color: 'var(--text-primary)'
    },
    badge: {
      display: 'inline-block',
      padding: '0.2rem 0.5rem',
      borderRadius: 'var(--radius-sm)',
      fontSize: '0.7rem',
      fontWeight: '500'
    },
    badgeActive: { background: 'var(--primary-light)', color: 'var(--primary)' },
    badgeInactive: { background: 'rgba(107, 114, 128, 0.15)', color: 'var(--text-muted)' },
    endpoint: {
      fontFamily: 'monospace',
      fontSize: '0.75rem',
      color: 'var(--primary)',
      background: 'var(--bg-primary)',
      padding: '0.25rem 0.5rem',
      borderRadius: 'var(--radius-sm)'
    },
    modal: {
      position: 'fixed',
      top: 0, left: 0, right: 0, bottom: 0,
      background: 'rgba(0,0,0,0.8)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      zIndex: 1000,
      padding: '1rem'
    },
    modalContent: {
      background: 'var(--bg-secondary)',
      borderRadius: 'var(--radius-lg)',
      width: '100%',
      maxWidth: '480px',
      border: '1px solid var(--border-color)',
      maxHeight: '90vh',
      overflow: 'auto'
    },
    modalHeader: {
      display: 'flex',
      justifyContent: 'space-between',
      alignItems: 'center',
      padding: '1rem 1.25rem',
      borderBottom: '1px solid var(--border-color)'
    },
    modalTitle: { margin: 0, fontSize: '1rem', fontWeight: '600', color: 'var(--text-primary)' },
    modalClose: {
      background: 'none',
      border: 'none',
      color: 'var(--text-muted)',
      fontSize: '1.25rem',
      cursor: 'pointer',
      padding: 0
    },
    modalBody: { padding: '1.25rem' },
    formGroup: { marginBottom: '1rem' },
    label: {
      display: 'block',
      marginBottom: '0.375rem',
      fontSize: '0.8rem',
      color: 'var(--text-muted)'
    },
    input: {
      width: '100%',
      padding: '0.625rem',
      background: 'var(--bg-tertiary)',
      border: '1px solid var(--border-color)',
      borderRadius: 'var(--radius-md)',
      color: 'var(--text-primary)',
      fontSize: '0.875rem',
      boxSizing: 'border-box'
    },
    credentialBox: {
      background: 'var(--bg-primary)',
      borderRadius: 'var(--radius-md)',
      padding: '0.75rem',
      marginBottom: '0.75rem'
    },
    credentialLabel: {
      fontSize: '0.7rem',
      color: 'var(--text-muted)',
      textTransform: 'uppercase',
      marginBottom: '0.375rem'
    },
    credentialValue: {
      display: 'flex',
      alignItems: 'center',
      gap: '0.5rem'
    },
    credentialCode: {
      flex: 1,
      fontFamily: 'monospace',
      fontSize: '0.75rem',
      color: 'var(--primary)',
      wordBreak: 'break-all',
      lineHeight: 1.4
    },
    copyBtn: {
      background: 'var(--primary-light)',
      border: '1px solid var(--border-color)',
      color: 'var(--primary)',
      padding: '0.25rem 0.5rem',
      borderRadius: 'var(--radius-sm)',
      fontSize: '0.7rem',
      cursor: 'pointer',
      whiteSpace: 'nowrap'
    },
    warning: {
      display: 'flex',
      alignItems: 'flex-start',
      gap: '0.5rem',
      padding: '0.75rem',
      background: 'rgba(245, 158, 11, 0.1)',
      border: '1px solid rgba(245, 158, 11, 0.2)',
      borderRadius: 'var(--radius-md)',
      marginBottom: '1rem',
      fontSize: '0.8rem'
    },
    codeBlock: {
      background: 'var(--bg-primary)',
      padding: '0.75rem',
      borderRadius: 'var(--radius-md)',
      fontSize: '0.7rem',
      fontFamily: 'monospace',
      color: 'var(--text-muted)',
      overflow: 'auto',
      marginTop: '0.75rem',
      lineHeight: 1.5
    },
    emptyState: {
      textAlign: 'center',
      padding: '3rem 1rem',
      color: 'var(--text-muted)'
    },
    actions: { display: 'flex', gap: '0.5rem', marginTop: '1rem' }
  };

  return (
    <div style={styles.container}>
      {/* Header */}
      <div style={styles.header}>
        <h3 style={styles.title}>Webhooks</h3>
        <button
          style={{ ...styles.btn, ...styles.btnPrimary }}
          onClick={() => setShowCreateModal(true)}
        >
          + Create Webhook
        </button>
      </div>

      {/* Webhooks Table */}
      {webhooks.length > 0 ? (
        <div style={{ borderRadius: 'var(--radius-md)', overflow: 'hidden', border: '1px solid var(--border-color)' }}>
          <table style={styles.table}>
            <thead>
              <tr>
                <th style={styles.th}>Name</th>
                <th style={styles.th}>Endpoint</th>
                <th style={styles.th}>Status</th>
                <th style={styles.th}>Requests</th>
                <th style={styles.th}>Rate Limit</th>
                <th style={{ ...styles.th, textAlign: 'right' }}></th>
              </tr>
            </thead>
            <tbody>
              {webhooks.map(webhook => (
                <tr key={webhook.id || webhook.name}>
                  <td style={styles.td}>
                    <div style={{ fontWeight: '500' }}>{webhook.name}</div>
                    {webhook.description && (
                      <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.125rem' }}>
                        {webhook.description}
                      </div>
                    )}
                  </td>
                  <td style={styles.td}>
                    <code style={styles.endpoint}>{webhook.endpoint_path}</code>
                  </td>
                  <td style={styles.td}>
                    <span style={{
                      ...styles.badge,
                      ...(webhook.enabled ? styles.badgeActive : styles.badgeInactive)
                    }}>
                      {webhook.enabled ? 'Active' : 'Inactive'}
                    </span>
                  </td>
                  <td style={styles.td}>{webhook.trigger_count || 0}</td>
                  <td style={styles.td}>{webhook.rate_limit || 100}/hr</td>
                  <td style={{ ...styles.td, textAlign: 'right' }}>
                    <button
                      style={{ ...styles.btn, ...styles.btnSecondary, marginRight: '0.5rem', padding: '0.375rem 0.75rem', fontSize: '0.75rem' }}
                      onClick={() => openEditWebhook(webhook)}
                    >
                      Edit
                    </button>
                    <button
                      style={{ ...styles.btn, ...styles.btnDanger }}
                      onClick={() => handleDeleteWebhook(webhook.name)}
                    >
                      Delete
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div style={styles.emptyState}>
          <p style={{ margin: '0.25rem 0' }}>No webhooks configured</p>
          <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
            Create a webhook to receive alerts from external systems
          </p>
        </div>
      )}

      {/* Create Modal */}
      {showCreateModal && (
        <div style={styles.modal}>
          <div style={styles.modalContent}>
            <div style={styles.modalHeader}>
              <h4 style={styles.modalTitle}>Create Webhook</h4>
              <button
                style={styles.modalClose}
                onClick={() => { setShowCreateModal(false); setFormData({ name: '', description: '', rate_limit: 100 }); }}
              >
                ×
              </button>
            </div>
            <form onSubmit={handleCreateWebhook} style={styles.modalBody}>
              <div style={styles.formGroup}>
                <label style={styles.label}>Name *</label>
                <input
                  style={styles.input}
                  type="text"
                  value={formData.name}
                  onChange={(e) => setFormData({...formData, name: e.target.value})}
                  placeholder="e.g., splunk-alerts"
                  required
                  autoFocus
                />
              </div>
              <div style={styles.formGroup}>
                <label style={styles.label}>Description</label>
                <input
                  style={styles.input}
                  type="text"
                  value={formData.description}
                  onChange={(e) => setFormData({...formData, description: e.target.value})}
                  placeholder="Optional description"
                />
              </div>
              <div style={styles.formGroup}>
                <label style={styles.label}>Rate Limit (per hour)</label>
                <input
                  style={{ ...styles.input, width: '120px' }}
                  type="number"
                  value={formData.rate_limit}
                  onChange={(e) => setFormData({...formData, rate_limit: parseInt(e.target.value)})}
                  min="1"
                  max="10000"
                />
              </div>
              <div style={styles.actions}>
                <button type="submit" style={{ ...styles.btn, ...styles.btnPrimary }}>
                  Create
                </button>
                <button
                  type="button"
                  style={{ ...styles.btn, ...styles.btnSecondary }}
                  onClick={() => { setShowCreateModal(false); setFormData({ name: '', description: '', rate_limit: 100 }); }}
                >
                  Cancel
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Edit Modal */}
      {editingWebhook && (
        <div style={styles.modal}>
          <div style={styles.modalContent}>
            <div style={styles.modalHeader}>
              <h4 style={styles.modalTitle}>Edit Webhook</h4>
              <button
                style={styles.modalClose}
                onClick={() => setEditingWebhook(null)}
              >
                ×
              </button>
            </div>
            <form onSubmit={handleUpdateWebhook} style={styles.modalBody}>
              <div style={styles.formGroup}>
                <label style={styles.label}>Name</label>
                <input
                  style={styles.input}
                  type="text"
                  value={editForm.name}
                  onChange={(e) => setEditForm({ ...editForm, name: e.target.value })}
                />
                <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: '0.25rem' }}>
                  Changing the name changes the ingest URL path.
                </div>
              </div>
              <div style={styles.formGroup}>
                <label style={styles.label}>Description</label>
                <input
                  style={styles.input}
                  type="text"
                  value={editForm.description}
                  onChange={(e) => setEditForm({ ...editForm, description: e.target.value })}
                />
              </div>
              <div style={styles.formGroup}>
                <label style={styles.label}>Rate Limit (per hour)</label>
                <input
                  style={{ ...styles.input, width: '120px' }}
                  type="number"
                  value={editForm.rate_limit}
                  onChange={(e) => setEditForm({ ...editForm, rate_limit: parseInt(e.target.value) })}
                  min="1"
                  max="10000"
                />
              </div>
              <div style={styles.formGroup}>
                <label style={{ ...styles.label, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <input
                    type="checkbox"
                    checked={editForm.enabled}
                    onChange={(e) => setEditForm({ ...editForm, enabled: e.target.checked })}
                  />
                  Enabled
                </label>
              </div>
              <div style={styles.actions}>
                <button type="submit" style={{ ...styles.btn, ...styles.btnPrimary }}>
                  Save changes
                </button>
                <button
                  type="button"
                  style={{ ...styles.btn, ...styles.btnSecondary }}
                  onClick={() => setEditingWebhook(null)}
                >
                  Cancel
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Credentials Modal */}
      {showDisplayModal && newWebhook && (
        <div style={styles.modal}>
          <div style={{ ...styles.modalContent, maxWidth: '520px' }}>
            <div style={styles.modalHeader}>
              <h4 style={styles.modalTitle}>Webhook Created</h4>
              <button
                style={styles.modalClose}
                onClick={() => { setShowDisplayModal(false); setNewWebhook(null); }}
              >
                ×
              </button>
            </div>
            <div style={styles.modalBody}>
              <div style={styles.warning}>
                <div>
                  <strong style={{ color: '#f59e0b' }}>Save these credentials!</strong>
                  <span style={{ color: 'var(--text-muted)' }}> They won't be shown again.</span>
                </div>
              </div>

              <div style={styles.credentialBox}>
                <div style={styles.credentialLabel}>Webhook URL</div>
                <div style={styles.credentialValue}>
                  <code style={styles.credentialCode}>
                    {`${API_BASE_URL}${newWebhook.endpoint_path}`}
                  </code>
                  <button
                    style={{ ...styles.copyBtn, background: copied === 'url' ? 'var(--primary-light)' : styles.copyBtn.background }}
                    onClick={() => copyToClipboard(`${API_BASE_URL}${newWebhook.endpoint_path}`, 'url')}
                  >
                    {copied === 'url' ? 'Copied' : 'Copy'}
                  </button>
                </div>
              </div>

              <div style={styles.credentialBox}>
                <div style={styles.credentialLabel}>HEC Token</div>
                <div style={styles.credentialValue}>
                  <code style={styles.credentialCode}>{newWebhook.hec_token}</code>
                  <button
                    style={{ ...styles.copyBtn, background: copied === 'token' ? 'var(--primary-light)' : styles.copyBtn.background }}
                    onClick={() => copyToClipboard(newWebhook.hec_token, 'token')}
                  >
                    {copied === 'token' ? 'Copied' : 'Copy'}
                  </button>
                </div>
              </div>

              <details style={{ marginTop: '1rem' }}>
                <summary style={{ cursor: 'pointer', fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                  Example usage (Python)
                </summary>
                <pre style={styles.codeBlock}>
{`requests.post(
    "${API_BASE_URL}${newWebhook.endpoint_path}",
    headers={"Authorization": "HEC ${newWebhook.hec_token?.substring(0, 16)}..."},
    json={"title": "Alert", "severity": "high"}
)`}
                </pre>
              </details>

              <div style={{ ...styles.actions, marginTop: '1.25rem' }}>
                <button
                  style={{ ...styles.btn, ...styles.btnPrimary, flex: 1 }}
                  onClick={() => { setShowDisplayModal(false); setNewWebhook(null); }}
                >
                  Done
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default WebhookManager;
