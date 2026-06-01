/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

import React, { useState, useEffect, useCallback, useRef } from 'react';
import { API_BASE_URL, getAuthHeaders, authFetch } from '../utils/api';
import { LoadingState, ErrorState, EmptyState } from './dashboards/DashboardStates';
import { getRoleConfig, ARIA_LABELS } from './dashboards/DashboardConfig';
import styles from './AdminDashboard.module.css';

function AdminDashboard() {
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const mountedRef = useRef(true);

  // Tab state
  const [activeTab, setActiveTab] = useState('users');

  // Audit log state
  const [auditEntries, setAuditEntries] = useState([]);
  const [auditTotal, setAuditTotal] = useState(0);
  const [auditLoading, setAuditLoading] = useState(false);
  const [auditError, setAuditError] = useState(null);
  const [auditFilters, setAuditFilters] = useState({ action: '', username: '', resource_type: '' });

  // User management state
  const [showUserForm, setShowUserForm] = useState(false);
  const [editingUser, setEditingUser] = useState(null);
  const [userFormData, setUserFormData] = useState({
    username: '',
    email: '',
    full_name: '',
    password: '',
    confirmPassword: '',
    role: 'analyst',
    force_password_reset: false
  });
  const [formError, setFormError] = useState('');

  // Cleanup on unmount
  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

  const loadUsers = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await authFetch(`${API_BASE_URL}/api/v1/admin/users`);

      if (!mountedRef.current) return;

      if (response.ok) {
        const data = await response.json();
        setUsers(data);
      } else {
        const errorData = await response.json().catch(() => ({}));
        setError(errorData.detail || 'Failed to load users');
      }
    } catch (err) {
      if (mountedRef.current) {
        setError(err.message || 'Network error loading users');
      }
    } finally {
      if (mountedRef.current) {
        setLoading(false);
      }
    }
  }, []);

  useEffect(() => {
    loadUsers();
  }, [loadUsers]);

  // Password complexity checks (must match backend validate_password_complexity)
  const pw = userFormData.password;
  const passwordChecks = {
    length: pw.length >= 12,
    upper: /[A-Z]/.test(pw),
    lower: /[a-z]/.test(pw),
    digit: /\d/.test(pw),
    special: /[!@#$%^&*()_+\-=[\]{}|;:,.<>?]/.test(pw),
  };
  const allChecksPassed = Object.values(passwordChecks).every(Boolean);
  const passwordsMatch = pw && userFormData.confirmPassword && pw === userFormData.confirmPassword;

  const parseErrorDetail = (errorData) => {
    const detail = errorData?.detail;
    if (!detail) return 'Failed to save user';
    if (typeof detail === 'string') return detail;
    // Pydantic 422 validation errors return [{msg, loc, type}]
    if (Array.isArray(detail)) {
      return detail.map(e => {
        const field = e.loc?.slice(-1)[0] || '';
        return field ? `${field}: ${e.msg}` : e.msg;
      }).join('. ');
    }
    return 'Failed to save user';
  };

  const handleUserSubmit = async (e) => {
    e.preventDefault();
    setFormError('');

    const needsPassword = !editingUser || pw.length > 0;

    if (needsPassword) {
      if (!allChecksPassed) {
        setFormError('Please meet all password requirements below');
        return;
      }
      if (!passwordsMatch) {
        setFormError('New passwords do not match');
        return;
      }
    }

    const url = editingUser
      ? `${API_BASE_URL}/api/v1/admin/users/${editingUser.username}`
      : `${API_BASE_URL}/api/v1/admin/users`;
    const method = editingUser ? 'PUT' : 'POST';

    // Prepare data
    const submitData = { ...userFormData };
    delete submitData.confirmPassword;
    if (editingUser && !submitData.password) {
      delete submitData.password;
    }

    try {
      const response = await authFetch(url, {
        method,
        body: JSON.stringify(submitData)
      });

      if (response.ok) {
        setShowUserForm(false);
        setEditingUser(null);
        resetUserForm();
        loadUsers();
      } else {
        const errorData = await response.json().catch(() => ({}));
        setFormError(parseErrorDetail(errorData));
      }
    } catch (err) {
      setFormError(err.message || 'Error saving user');
    }
  };

  const resetUserForm = () => {
    setUserFormData({
      username: '',
      email: '',
      full_name: '',
      password: '',
      confirmPassword: '',
      role: 'analyst',
      force_password_reset: false
    });
    setFormError('');
  };

  const handleDeleteUser = async (username) => {
    if (!window.confirm(`Are you sure you want to delete user "${username}"?`)) return;

    try {
      const response = await authFetch(`${API_BASE_URL}/api/v1/admin/users/${username}`, {
        method: 'DELETE'
      });

      if (response.ok) {
        loadUsers();
      } else {
        const errorData = await response.json().catch(() => ({}));
        setError(errorData.detail || 'Failed to delete user');
      }
    } catch (err) {
      setError(err.message || 'Failed to delete user');
    }
  };

  const auditLoadedRef = useRef(false);

  const loadAuditLog = useCallback(async (filters = auditFilters) => {
    setAuditLoading(true);
    setAuditError(null);
    try {
      const params = new URLSearchParams({ limit: 100 });
      if (filters.action) params.set('action', filters.action);
      if (filters.username) params.set('username', filters.username);
      if (filters.resource_type) params.set('resource_type', filters.resource_type);
      const response = await authFetch(`${API_BASE_URL}/api/v1/admin/audit-log?${params}`);
      if (!mountedRef.current) return;
      if (response.ok) {
        const data = await response.json();
        setAuditEntries(data.entries || []);
        setAuditTotal(data.total || 0);
        auditLoadedRef.current = true;
      } else {
        const errData = await response.json().catch(() => ({}));
        setAuditError(errData.detail || `Failed to load audit log (${response.status})`);
      }
    } catch (err) {
      if (mountedRef.current) setAuditError(err.message || 'Network error loading audit log');
    } finally {
      if (mountedRef.current) setAuditLoading(false);
    }
  }, [auditFilters]);

  // Auto-load audit log when tab is switched to 'audit'
  useEffect(() => {
    if (activeTab === 'audit' && !auditLoadedRef.current) {
      loadAuditLog(auditFilters);
    }
  }, [activeTab, loadAuditLog, auditFilters]);

  // Use getRoleConfig from DashboardConfig for consistent role styling

  const formatDate = (dateStr) => {
    if (!dateStr) return '-';
    return new Date(dateStr).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric'
    });
  };

  return (
    <div className={styles.container}>
      {/* Header */}
      <header className={styles.header}>
        <h1 className={styles.title}>
          {activeTab === 'users' ? 'User Management' : 'Audit Log'}
        </h1>
        {activeTab === 'users' && (
          <button
            className={`${styles.button} ${styles.buttonPrimary}`}
            onClick={() => {
              resetUserForm();
              setEditingUser(null);
              setShowUserForm(true);
            }}
            aria-label="Create new user"
          >
            + Create User
          </button>
        )}
      </header>

      {/* Tab bar */}
      <div className={styles.tabBar}>
        {[
          { key: 'users', label: 'Users' },
          { key: 'audit', label: 'Audit Log' },
        ].map(tab => (
          <button
            key={tab.key}
            onClick={() => {
              setActiveTab(tab.key);
              if (tab.key === 'audit') loadAuditLog(auditFilters);
            }}
            className={`${styles.tabButton} ${activeTab === tab.key ? styles.tabButtonActive : styles.tabButtonInactive}`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* Error Banner (users tab) */}
      {activeTab === 'users' && error && (
        <div className={styles.errorBanner} role="alert">
          <span>{error}</span>
          <button onClick={loadUsers} className={styles.retryButton}>Retry</button>
        </div>
      )}

      {/* Users Table */}
      {activeTab === 'users' && <div className={styles.card}>
        {loading ? (
          <LoadingState message="Loading users..." />
        ) : error && users.length === 0 ? (
          <ErrorState
            error={error}
            title="Unable to Load Users"
            onRetry={loadUsers}
            retryLabel="Retry"
          />
        ) : users.length === 0 ? (
          <EmptyState
            type="users"
            message="No users found. Create your first user to get started."
          />
        ) : (
          <table className={styles.table} aria-label="User management table">
            <thead>
              <tr>
                <th className={styles.th} scope="col">User</th>
                <th className={styles.th} scope="col">Role</th>
                <th className={styles.th} scope="col">Created</th>
                <th className={styles.th} scope="col">Last Login</th>
                <th className={styles.th} scope="col">Actions</th>
              </tr>
            </thead>
            <tbody>
              {users.map(user => {
                const roleConfig = getRoleConfig(user.role);
                return (
                  <tr key={user.username}>
                    <td className={styles.td}>
                      <div className={styles.userCell}>
                        <div className={styles.userAvatar}>
                          {user.username.charAt(0).toUpperCase()}
                        </div>
                        <div>
                          <div className={styles.userName}>{user.username}</div>
                          <div className={styles.userEmail}>
                            {user.email}
                          </div>
                          {user.full_name && (
                            <div className={styles.userFullName}>
                              {user.full_name}
                            </div>
                          )}
                        </div>
                      </div>
                    </td>
                    <td className={styles.td}>
                      <span className={styles.roleBadge} style={{
                        background: roleConfig.bg,
                        color: roleConfig.color,
                        border: `1px solid ${roleConfig.border}`
                      }}>
                        {roleConfig.label}
                      </span>
                    </td>
                    <td className={styles.td}>
                      <span className={styles.dateText}>
                        {formatDate(user.created_at)}
                      </span>
                    </td>
                    <td className={styles.td}>
                      <span className={styles.lastLoginText}>
                        {user.last_login ? formatDate(user.last_login) : 'Never'}
                      </span>
                    </td>
                    <td className={styles.td}>
                      <div className={styles.actionButtons}>
                        <button
                          className={`${styles.button} ${styles.buttonSecondary} ${styles.buttonSmall}`}
                          onClick={() => {
                            setEditingUser(user);
                            setUserFormData({
                              username: user.username,
                              email: user.email,
                              full_name: user.full_name || '',
                              password: '',
                              confirmPassword: '',
                              role: user.role,
                              force_password_reset: user.force_password_reset || false
                            });
                            setShowUserForm(true);
                          }}
                          aria-label={`Edit user ${user.username}`}
                        >
                          Edit
                        </button>
                        {user.username !== 'admin' && (
                          <button
                            className={`${styles.button} ${styles.buttonDanger} ${styles.buttonSmall}`}
                            onClick={() => handleDeleteUser(user.username)}
                            aria-label={`Delete user ${user.username}`}
                          >
                            Delete
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>}

      {/* Audit Log Panel */}
      {activeTab === 'audit' && (
        <div>
          {/* Filters */}
          <div className={styles.auditFilters}>
            {[
              { key: 'username', placeholder: 'Filter by user...' },
              { key: 'action', placeholder: 'Filter by action...' },
              { key: 'resource_type', placeholder: 'Filter by resource type...' },
            ].map(f => (
              <input
                key={f.key}
                className={`${styles.input} ${styles.auditFilterInput}`}
                placeholder={f.placeholder}
                value={auditFilters[f.key]}
                onChange={e => setAuditFilters(prev => ({ ...prev, [f.key]: e.target.value }))}
                onKeyDown={e => { if (e.key === 'Enter') loadAuditLog({ ...auditFilters, [f.key]: e.target.value }); }}
              />
            ))}
            <button
              className={`${styles.button} ${styles.buttonSecondary}`}
              onClick={() => loadAuditLog(auditFilters)}
            >
              Search
            </button>
            <button
              className={`${styles.button} ${styles.buttonClear}`}
              onClick={() => {
                const cleared = { action: '', username: '', resource_type: '' };
                setAuditFilters(cleared);
                loadAuditLog(cleared);
              }}
            >
              Clear
            </button>
          </div>

          {auditError && (
            <div className={styles.errorBanner} role="alert">
              <span>{auditError}</span>
              <button onClick={() => loadAuditLog(auditFilters)} className={styles.retryButton}>Retry</button>
            </div>
          )}

          <div className={styles.card}>
            {auditLoading ? (
              <LoadingState message="Loading audit log..." />
            ) : auditEntries.length === 0 ? (
              <div className={styles.auditEmpty}>
                <div style={{ fontWeight: 600, marginBottom: '0.5rem' }}>No audit entries found</div>
                <div style={{ fontSize: '0.82rem', color: 'var(--text-muted)' }}>
                  Audit entries are created when users perform actions like managing users, credentials, playbooks, and system settings.
                  Actions will appear here as they occur.
                </div>
              </div>
            ) : (
              <>
                <div className={styles.auditSummary}>
                  {auditTotal} total entries
                </div>
                <table className={styles.table} aria-label="Audit log">
                  <thead>
                    <tr>
                      <th className={styles.th}>Timestamp</th>
                      <th className={styles.th}>User</th>
                      <th className={styles.th}>Action</th>
                      <th className={styles.th}>Resource Type</th>
                      <th className={styles.th}>Resource ID</th>
                      <th className={styles.th}>Details</th>
                    </tr>
                  </thead>
                  <tbody>
                    {auditEntries.map((entry, i) => (
                      <tr key={entry.id || i}>
                        <td className={`${styles.td} ${styles.auditTimestamp}`}>
                          {entry.created_at ? new Date(entry.created_at).toLocaleString() : '-'}
                        </td>
                        <td className={styles.td}>
                          <span className={styles.auditUser}>{entry.username || '-'}</span>
                        </td>
                        <td className={styles.td}>
                          <span className={styles.auditActionBadge}>
                            {entry.action || '-'}
                          </span>
                        </td>
                        <td className={`${styles.td} ${styles.auditResourceType}`}>{entry.resource_type || '-'}</td>
                        <td className={`${styles.td} ${styles.auditResourceId}`}>
                          {entry.resource_id ? entry.resource_id.substring(0, 24) + (entry.resource_id.length > 24 ? '...' : '') : '-'}
                        </td>
                        <td className={`${styles.td} ${styles.auditDetails}`}>
                          {entry.details && Object.keys(entry.details).length > 0
                            ? Object.entries(entry.details).slice(0, 2).map(([k, v]) => `${k}: ${String(v).substring(0, 40)}`).join(' | ')
                            : '-'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </>
            )}
          </div>
        </div>
      )}

      {/* USER FORM MODAL */}
      {showUserForm && (
        <div
          className={styles.modal}
          onClick={() => setShowUserForm(false)}
          role="dialog"
          aria-modal="true"
          aria-labelledby="user-form-title"
        >
          <div className={styles.modalContent} onClick={e => e.stopPropagation()}>
            <div className={styles.modalHeader}>
              <h3 id="user-form-title" className={styles.modalTitle}>
                {editingUser ? `Edit User: ${editingUser.username}` : 'Create New User'}
              </h3>
              <button
                onClick={() => setShowUserForm(false)}
                className={styles.modalClose}
                aria-label="Close modal"
              >
                x
              </button>
            </div>

            <form onSubmit={handleUserSubmit} className={styles.formBody}>
              {formError && (
                <div className={styles.error} role="alert" aria-live="polite">
                  {formError}
                </div>
              )}

              <div className={styles.formGroup}>
                <label className={styles.label} htmlFor="username">Username *</label>
                <input
                  type="text"
                  id="username"
                  className={styles.input}
                  style={editingUser ? { opacity: 0.6 } : undefined}
                  value={userFormData.username}
                  onChange={(e) => setUserFormData({...userFormData, username: e.target.value})}
                  required
                  disabled={editingUser}
                  aria-describedby={editingUser ? 'username-readonly' : undefined}
                />
                {editingUser && (
                  <span id="username-readonly" className={styles.usernameReadonly}>
                    Username cannot be changed
                  </span>
                )}
              </div>

              <div className={styles.formGroup}>
                <label className={styles.label} htmlFor="fullName">Full Name</label>
                <input
                  type="text"
                  id="fullName"
                  className={styles.input}
                  value={userFormData.full_name}
                  onChange={(e) => setUserFormData({...userFormData, full_name: e.target.value})}
                  placeholder="John Doe"
                />
              </div>

              <div className={styles.formGroup}>
                <label className={styles.label} htmlFor="email">Email *</label>
                <input
                  type="email"
                  id="email"
                  className={styles.input}
                  value={userFormData.email}
                  onChange={(e) => setUserFormData({...userFormData, email: e.target.value})}
                  required
                />
              </div>

              <div className={styles.formGroup}>
                <label className={styles.label} htmlFor="password">
                  {editingUser ? 'New Password (leave blank to keep current)' : 'Password *'}
                </label>
                <input
                  type="password"
                  id="password"
                  className={styles.input}
                  value={userFormData.password}
                  onChange={(e) => setUserFormData({...userFormData, password: e.target.value})}
                  required={!editingUser}
                  placeholder={editingUser ? 'Leave blank to keep current' : 'Min 12 chars, upper, lower, digit, special'}
                />
                {pw && (
                  <div className={styles.passwordChecks}>
                    {[
                      [passwordChecks.length, '12+ characters'],
                      [passwordChecks.upper, 'Uppercase letter'],
                      [passwordChecks.lower, 'Lowercase letter'],
                      [passwordChecks.digit, 'Digit'],
                      [passwordChecks.special, 'Special character (!@#$%...)'],
                    ].map(([met, label]) => (
                      <span key={label} className={`${styles.passwordCheckItem} ${met ? styles.passwordCheckMet : styles.passwordCheckUnmet}`}>
                        {met ? '\u2713' : '\u2022'} {label}
                      </span>
                    ))}
                  </div>
                )}
              </div>

              <div className={styles.formGroup}>
                <label className={styles.label} htmlFor="confirmPassword">
                  Confirm Password {(!editingUser || pw) ? '*' : ''}
                </label>
                <input
                  type="password"
                  id="confirmPassword"
                  className={styles.input}
                  value={userFormData.confirmPassword}
                  onChange={(e) => setUserFormData({...userFormData, confirmPassword: e.target.value})}
                  required={!editingUser || pw.length > 0}
                  placeholder="Re-enter password"
                />
                {userFormData.confirmPassword && !passwordsMatch && (
                  <span className={`${styles.passwordMatchHint} ${styles.passwordMatchFail}`}>Passwords do not match</span>
                )}
                {passwordsMatch && (
                  <span className={`${styles.passwordMatchHint} ${styles.passwordMatchOk}`}>{'\u2713'} Passwords match</span>
                )}
              </div>

              <div className={styles.formGroup}>
                <label className={styles.label} htmlFor="role">Role *</label>
                <select
                  id="role"
                  className={styles.select}
                  value={userFormData.role}
                  onChange={(e) => setUserFormData({...userFormData, role: e.target.value})}
                >
                  <option value="analyst">Analyst</option>
                  <option value="admin">Admin</option>
                  <option value="read_only">Read Only</option>
                </select>
              </div>

              {editingUser && (
                <div className={styles.formGroup}>
                  <label
                    className={styles.checkbox}
                    htmlFor="forcePasswordReset"
                  >
                    <input
                      type="checkbox"
                      id="forcePasswordReset"
                      checked={userFormData.force_password_reset}
                      onChange={(e) => setUserFormData({...userFormData, force_password_reset: e.target.checked})}
                      style={{ width: '18px', height: '18px' }}
                    />
                    <div>
                      <div className={styles.forceResetLabel}>Force Password Reset</div>
                      <div className={styles.forceResetHint}>
                        User will be required to change their password on next login
                      </div>
                    </div>
                  </label>
                </div>
              )}

              <div className={styles.formActions}>
                <button
                  type="submit"
                  className={`${styles.button} ${styles.buttonPrimary} ${styles.formActionButton}`}
                >
                  {editingUser ? 'Update User' : 'Create User'}
                </button>
                <button
                  type="button"
                  className={`${styles.button} ${styles.buttonSecondary} ${styles.formActionButton}`}
                  onClick={() => setShowUserForm(false)}
                >
                  Cancel
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}

export default AdminDashboard;


