/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

import React, { useState, useEffect } from 'react';
import { usePreferences, TIMEZONE_OPTIONS, formatInTimezone, getTimezoneAbbr } from '../hooks/usePreferences';
import { API_BASE_URL, getCsrfToken } from '../utils/api';

function UserProfile({ user, onLogout }) {
  const { preferences, updatePreference, saving } = usePreferences();
  const [showPasswordModal, setShowPasswordModal] = useState(false);
  const [passwordData, setPasswordData] = useState({
    currentPassword: '',
    newPassword: '',
    confirmPassword: ''
  });
  const [passwordError, setPasswordError] = useState('');
  const [passwordSuccess, setPasswordSuccess] = useState('');
  const [changingPassword, setChangingPassword] = useState(false);
  const [userStats, setUserStats] = useState(null);
  const [activeTab, setActiveTab] = useState('preferences');

  useEffect(() => {
    loadUserStats();
  }, []);

  const loadUserStats = async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/api/v1/admin/logs?limit=100`);
      if (response.ok) {
        const logs = await response.json();
        const userLogs = logs.filter(log => log.username === user?.username);
        setUserStats({
          totalActions: userLogs.length,
          lastLogin: new Date().toISOString(),
          recentActions: userLogs.slice(0, 5)
        });
      }
    } catch (error) {
    }
  };

  const validatePassword = (password) => {
    if (password.length < 8) return 'Password must be at least 8 characters';
    if (!/[A-Z]/.test(password)) return 'Password must contain at least one uppercase letter';
    if (!/[a-z]/.test(password)) return 'Password must contain at least one lowercase letter';
    if (!/[0-9]/.test(password)) return 'Password must contain at least one number';
    return null;
  };

  const handlePasswordChange = async (e) => {
    e.preventDefault();
    setPasswordError('');
    setPasswordSuccess('');

    if (passwordData.newPassword !== passwordData.confirmPassword) {
      setPasswordError('New passwords do not match');
      return;
    }

    const validationError = validatePassword(passwordData.newPassword);
    if (validationError) {
      setPasswordError(validationError);
      return;
    }

    if (passwordData.newPassword === passwordData.currentPassword) {
      setPasswordError('New password must be different from current password');
      return;
    }

    setChangingPassword(true);

    try {
      const csrf = getCsrfToken();
      const headers = { 'Content-Type': 'application/json' };
      if (csrf) headers['X-CSRF-Token'] = csrf;

      const response = await fetch(`${API_BASE_URL}/api/v1/admin/password-change`, {
        method: 'POST',
        headers,
        credentials: 'include',
        body: JSON.stringify({
          current_password: passwordData.currentPassword,
          new_password: passwordData.newPassword
        })
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.detail || 'Failed to change password');
      }

      setPasswordSuccess('Password changed successfully!');
      setPasswordData({ currentPassword: '', newPassword: '', confirmPassword: '' });
      setTimeout(() => {
        setShowPasswordModal(false);
        setPasswordSuccess('');
      }, 2000);
    } catch (err) {
      setPasswordError(err.message || 'Failed to change password');
    } finally {
      setChangingPassword(false);
    }
  };

  const getRoleColor = (role) => {
    switch (role?.toLowerCase()) {
      case 'admin': return { bg: 'rgba(139, 92, 246, 0.15)', color: '#5eead4', border: 'rgba(139, 92, 246, 0.3)' };
      case 'analyst': return { bg: 'rgba(59, 130, 246, 0.15)', color: '#60a5fa', border: 'rgba(59, 130, 246, 0.3)' };
      case 'viewer': return { bg: 'rgba(34, 197, 94, 0.15)', color: '#4ade80', border: 'rgba(34, 197, 94, 0.3)' };
      default: return { bg: 'rgba(107, 114, 128, 0.15)', color: '#9ca3af', border: 'rgba(107, 114, 128, 0.3)' };
    }
  };

  const roleStyle = getRoleColor(user?.role);

  const Toggle = ({ checked, onChange, disabled }) => (
    <button
      type="button"
      disabled={disabled}
      onClick={onChange}
      style={{
        width: '48px',
        height: '26px',
        borderRadius: '13px',
        background: checked ? 'var(--primary)' : 'var(--bg-tertiary)',
        border: '1px solid',
        borderColor: checked ? 'var(--primary)' : 'var(--border-color)',
        cursor: disabled ? 'not-allowed' : 'pointer',
        position: 'relative',
        transition: 'all 0.2s ease',
        opacity: disabled ? 0.5 : 1
      }}
    >
      <div style={{
        position: 'absolute',
        top: '2px',
        left: checked ? '23px' : '2px',
        width: '20px',
        height: '20px',
        borderRadius: '50%',
        background: 'white',
        transition: 'left 0.2s ease',
        boxShadow: '0 1px 3px rgba(0,0,0,0.2)'
      }} />
    </button>
  );

  return (
    <div style={{ padding: '2rem', maxWidth: '1100px', margin: '0 auto' }}>
      {/* Header */}
      <div style={{ marginBottom: '2rem' }}>
        <h1 style={{ fontSize: '1.5rem', fontWeight: '600', marginBottom: '0.25rem', color: 'var(--text-primary)' }}>
          Account Settings
        </h1>
        <p style={{ color: 'var(--text-muted)', fontSize: '0.875rem' }}>
          Manage your profile, preferences, and security settings
        </p>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '280px 1fr', gap: '1.5rem' }}>
        {/* Left Sidebar - Profile Card */}
        <div>
          <div style={{
            background: 'var(--bg-secondary)',
            borderRadius: '12px',
            border: '1px solid var(--border-color)',
            overflow: 'hidden'
          }}>
            {/* Profile Header */}
            <div style={{
              padding: '1.5rem',
              textAlign: 'center',
              borderBottom: '1px solid var(--border-color)'
            }}>
              <div style={{
                width: '80px',
                height: '80px',
                borderRadius: '50%',
                background: 'linear-gradient(135deg, var(--primary) 0%, #3CB371 100%)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                fontSize: '2rem',
                fontWeight: '600',
                color: 'white',
                margin: '0 auto 1rem',
                boxShadow: '0 4px 12px rgba(102, 126, 234, 0.3)'
              }}>
                {(user?.username || 'U')[0].toUpperCase()}
              </div>
              <div style={{ fontSize: '1.125rem', fontWeight: '600', marginBottom: '0.5rem', color: 'var(--text-primary)' }}>
                {user?.username || 'User'}
              </div>
              <div style={{
                display: 'inline-block',
                padding: '0.25rem 0.75rem',
                background: roleStyle.bg,
                color: roleStyle.color,
                border: `1px solid ${roleStyle.border}`,
                borderRadius: '20px',
                fontSize: '0.75rem',
                fontWeight: '500',
                textTransform: 'capitalize'
              }}>
                {user?.role || 'User'}
              </div>
            </div>

            {/* Navigation */}
            <div style={{ padding: '0.5rem' }}>
              {[
                { id: 'preferences', label: 'Preferences', icon: 'M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z' },
                { id: 'notifications', label: 'Notifications', icon: 'M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9' },
                { id: 'security', label: 'Security', icon: 'M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z' },
                { id: 'activity', label: 'Activity', icon: 'M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-3 7h3m-3 4h3m-6-4h.01M9 16h.01' }
              ].map(item => (
                <button
                  key={item.id}
                  onClick={() => setActiveTab(item.id)}
                  style={{
                    width: '100%',
                    padding: '0.75rem 1rem',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.75rem',
                    background: activeTab === item.id ? 'var(--primary-light)' : 'transparent',
                    border: 'none',
                    borderRadius: '8px',
                    color: activeTab === item.id ? 'var(--primary)' : 'var(--text-secondary)',
                    fontSize: '0.875rem',
                    fontWeight: activeTab === item.id ? '500' : '400',
                    cursor: 'pointer',
                    transition: 'all 0.15s ease',
                    textAlign: 'left'
                  }}
                >
                  <svg style={{ width: '18px', height: '18px' }} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                    <path strokeLinecap="round" strokeLinejoin="round" d={item.icon} />
                  </svg>
                  {item.label}
                </button>
              ))}
            </div>

            {/* Logout Button */}
            <div style={{ padding: '0.5rem', borderTop: '1px solid var(--border-color)', marginTop: '0.5rem' }}>
              <button
                onClick={onLogout}
                style={{
                  width: '100%',
                  padding: '0.75rem 1rem',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.75rem',
                  background: 'transparent',
                  border: 'none',
                  borderRadius: '8px',
                  color: 'var(--danger)',
                  fontSize: '0.875rem',
                  cursor: 'pointer',
                  transition: 'all 0.15s ease',
                  textAlign: 'left'
                }}
              >
                <svg style={{ width: '18px', height: '18px' }} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" />
                </svg>
                Sign Out
              </button>
            </div>
          </div>

          {/* Quick Stats */}
          {userStats && (
            <div style={{
              background: 'var(--bg-secondary)',
              borderRadius: '12px',
              border: '1px solid var(--border-color)',
              padding: '1.25rem',
              marginTop: '1rem'
            }}>
              <div style={{ fontSize: '0.75rem', fontWeight: '500', color: 'var(--text-muted)', marginBottom: '1rem', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                Session Info
              </div>
              <div style={{ display: 'grid', gap: '0.75rem' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span style={{ fontSize: '0.875rem', color: 'var(--text-secondary)' }}>Status</span>
                  <span style={{
                    fontSize: '0.75rem',
                    fontWeight: '500',
                    padding: '0.25rem 0.5rem',
                    background: 'rgba(34, 197, 94, 0.15)',
                    color: '#22c55e',
                    borderRadius: '4px'
                  }}>Active</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span style={{ fontSize: '0.875rem', color: 'var(--text-secondary)' }}>Session Duration</span>
                  <span style={{ fontSize: '0.875rem', color: 'var(--text-primary)', fontWeight: '500' }}>24h</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span style={{ fontSize: '0.875rem', color: 'var(--text-secondary)' }}>Actions Today</span>
                  <span style={{ fontSize: '0.875rem', color: 'var(--text-primary)', fontWeight: '500' }}>{userStats.totalActions}</span>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Main Content */}
        <div>
          {/* Preferences Tab */}
          {activeTab === 'preferences' && (
            <div style={{
              background: 'var(--bg-secondary)',
              borderRadius: '12px',
              border: '1px solid var(--border-color)'
            }}>
              <div style={{ padding: '1.25rem 1.5rem', borderBottom: '1px solid var(--border-color)' }}>
                <h2 style={{ fontSize: '1rem', fontWeight: '600', color: 'var(--text-primary)' }}>Display Preferences</h2>
                <p style={{ fontSize: '0.8125rem', color: 'var(--text-muted)', marginTop: '0.25rem' }}>
                  Customize how information is displayed in the application
                </p>
              </div>
              <div style={{ padding: '0.5rem 1.5rem' }}>
                {[
                  {
                    key: 'theme',
                    label: 'Theme',
                    desc: 'Choose your preferred color scheme',
                    type: 'select',
                    options: [
                      { value: 'dark', label: 'Dark' },
                      { value: 'light', label: 'Light' },
                      { value: 'system', label: 'System' }
                    ],
                    value: preferences.theme || 'dark'
                  },
                  {
                    key: 'timezone',
                    label: 'Display Timezone',
                    desc: 'Convert all timestamps to this timezone',
                    type: 'select',
                    options: TIMEZONE_OPTIONS.map(tz => ({
                      value: tz.value,
                      label: tz.label + (tz.offset !== null && tz.offset !== 0 ? ` (UTC${tz.offset >= 0 ? '+' : ''}${tz.offset})` : '')
                    })),
                    value: preferences.timezone || 'local'
                  },
                  {
                    key: 'dateFormat',
                    label: 'Date Format',
                    desc: 'How timestamps are displayed',
                    type: 'select',
                    options: [
                      { value: 'relative', label: 'Relative (2 hours ago)' },
                      { value: 'absolute', label: 'Absolute (Dec 19, 2024)' }
                    ],
                    value: preferences.dateFormat || 'relative'
                  },
                  {
                    key: 'alertsPerPage',
                    label: 'Items Per Page',
                    desc: 'Default number of items in lists',
                    type: 'select',
                    options: [
                      { value: 10, label: '10 items' },
                      { value: 25, label: '25 items' },
                      { value: 50, label: '50 items' },
                      { value: 100, label: '100 items' }
                    ],
                    value: preferences.alertsPerPage || 25
                  },
                  {
                    key: 'showAlertPreview',
                    label: 'Alert Preview Panel',
                    desc: 'Show detailed preview when selecting alerts',
                    type: 'toggle',
                    value: preferences.showAlertPreview !== false
                  }
                ].map((setting, idx, arr) => (
                  <div key={setting.key} style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    padding: '1rem 0',
                    borderBottom: idx < arr.length - 1 ? '1px solid var(--border-color)' : 'none'
                  }}>
                    <div>
                      <div style={{ fontSize: '0.875rem', fontWeight: '500', color: 'var(--text-primary)' }}>{setting.label}</div>
                      <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.125rem' }}>{setting.desc}</div>
                    </div>
                    {setting.type === 'select' ? (
                      <select
                        value={setting.value}
                        onChange={(e) => {
                          const val = setting.key === 'alertsPerPage' ? parseInt(e.target.value) : e.target.value;
                          updatePreference(setting.key, val);
                        }}
                        disabled={saving}
                        style={{
                          padding: '0.5rem 0.75rem',
                          background: 'var(--bg-tertiary)',
                          border: '1px solid var(--border-color)',
                          borderRadius: '6px',
                          color: 'var(--text-primary)',
                          fontSize: '0.8125rem',
                          minWidth: '160px',
                          cursor: 'pointer'
                        }}
                      >
                        {setting.options.map(opt => (
                          <option key={opt.value} value={opt.value}>{opt.label}</option>
                        ))}
                      </select>
                    ) : (
                      <Toggle
                        checked={setting.value}
                        onChange={() => updatePreference(setting.key, !setting.value)}
                        disabled={saving}
                      />
                    )}
                  </div>
                ))}
              </div>

              {/* Timezone Preview */}
              {preferences.timezone && preferences.timezone !== 'local' && (
                <div style={{
                  margin: '0 1.5rem 1.5rem',
                  padding: '1rem',
                  background: 'rgba(102, 126, 234, 0.1)',
                  borderRadius: '8px',
                  border: '1px solid rgba(102, 126, 234, 0.2)'
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.5rem' }}>
                    <span style={{ fontSize: '1rem' }}>🕐</span>
                    <span style={{ fontSize: '0.8125rem', fontWeight: '500', color: 'var(--primary)' }}>
                      Current Time Preview
                    </span>
                    <span style={{
                      fontSize: '0.7rem',
                      padding: '2px 6px',
                      background: 'rgba(102, 126, 234, 0.2)',
                      borderRadius: '4px',
                      color: 'var(--primary)'
                    }}>
                      {getTimezoneAbbr(preferences.timezone)}
                    </span>
                  </div>
                  <div style={{ fontSize: '1.125rem', fontFamily: 'monospace', color: 'var(--text-primary)' }}>
                    {formatInTimezone(new Date(), preferences.timezone)}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Notifications Tab */}
          {activeTab === 'notifications' && (
            <div style={{
              background: 'var(--bg-secondary)',
              borderRadius: '12px',
              border: '1px solid var(--border-color)'
            }}>
              <div style={{ padding: '1.25rem 1.5rem', borderBottom: '1px solid var(--border-color)' }}>
                <h2 style={{ fontSize: '1rem', fontWeight: '600', color: 'var(--text-primary)' }}>Notification Settings</h2>
                <p style={{ fontSize: '0.8125rem', color: 'var(--text-muted)', marginTop: '0.25rem' }}>
                  Configure how and when you receive notifications
                </p>
              </div>
              <div style={{ padding: '0.5rem 1.5rem' }}>
                {[
                  { key: 'desktop', label: 'Desktop Notifications', desc: 'Show browser notifications for new alerts', value: preferences.notifications?.desktop || false },
                  { key: 'sound', label: 'Sound Alerts', desc: 'Play audio notification sounds', value: preferences.notifications?.sound || false },
                  { key: 'criticalOnly', label: 'Critical Alerts Only', desc: 'Only notify for critical severity events', value: preferences.notifications?.criticalOnly !== false }
                ].map((setting, idx) => (
                  <div key={setting.key} style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    padding: '1rem 0',
                    borderBottom: idx < 2 ? '1px solid var(--border-color)' : 'none'
                  }}>
                    <div>
                      <div style={{ fontSize: '0.875rem', fontWeight: '500', color: 'var(--text-primary)' }}>{setting.label}</div>
                      <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.125rem' }}>{setting.desc}</div>
                    </div>
                    <Toggle
                      checked={setting.value}
                      onChange={() => {
                        const newNotifs = { ...preferences.notifications, [setting.key]: !setting.value };
                        updatePreference('notifications', newNotifs);
                      }}
                      disabled={saving}
                    />
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Security Tab */}
          {activeTab === 'security' && (
            <div style={{
              background: 'var(--bg-secondary)',
              borderRadius: '12px',
              border: '1px solid var(--border-color)'
            }}>
              <div style={{ padding: '1.25rem 1.5rem', borderBottom: '1px solid var(--border-color)' }}>
                <h2 style={{ fontSize: '1rem', fontWeight: '600', color: 'var(--text-primary)' }}>Security Settings</h2>
                <p style={{ fontSize: '0.8125rem', color: 'var(--text-muted)', marginTop: '0.25rem' }}>
                  Manage your password and account security
                </p>
              </div>
              <div style={{ padding: '1.5rem' }}>
                <div style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  padding: '1rem 1.25rem',
                  background: 'var(--bg-tertiary)',
                  borderRadius: '8px',
                  border: '1px solid var(--border-color)'
                }}>
                  <div>
                    <div style={{ fontSize: '0.875rem', fontWeight: '500', color: 'var(--text-primary)' }}>Password</div>
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.25rem' }}>
                      Last changed: Never
                    </div>
                  </div>
                  <button
                    onClick={() => setShowPasswordModal(true)}
                    style={{
                      padding: '0.5rem 1rem',
                      background: 'var(--primary)',
                      border: 'none',
                      borderRadius: '6px',
                      color: 'white',
                      fontSize: '0.8125rem',
                      fontWeight: '500',
                      cursor: 'pointer',
                      transition: 'opacity 0.15s'
                    }}
                  >
                    Change Password
                  </button>
                </div>

                <div style={{
                  marginTop: '1rem',
                  padding: '1rem 1.25rem',
                  background: 'rgba(59, 130, 246, 0.1)',
                  borderRadius: '8px',
                  border: '1px solid rgba(59, 130, 246, 0.2)'
                }}>
                  <div style={{ display: 'flex', alignItems: 'flex-start', gap: '0.75rem' }}>
                    <svg style={{ width: '20px', height: '20px', color: '#3b82f6', flexShrink: 0, marginTop: '1px' }} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                      <path strokeLinecap="round" strokeLinejoin="round" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                    <div>
                      <div style={{ fontSize: '0.8125rem', fontWeight: '500', color: '#3b82f6' }}>Security Recommendation</div>
                      <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: '0.25rem' }}>
                        We recommend changing your password every 90 days and using a unique password for this account.
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Activity Tab */}
          {activeTab === 'activity' && (
            <div style={{
              background: 'var(--bg-secondary)',
              borderRadius: '12px',
              border: '1px solid var(--border-color)'
            }}>
              <div style={{ padding: '1.25rem 1.5rem', borderBottom: '1px solid var(--border-color)' }}>
                <h2 style={{ fontSize: '1rem', fontWeight: '600', color: 'var(--text-primary)' }}>Recent Activity</h2>
                <p style={{ fontSize: '0.8125rem', color: 'var(--text-muted)', marginTop: '0.25rem' }}>
                  Your recent actions and audit trail
                </p>
              </div>
              <div style={{ padding: '0.5rem' }}>
                {userStats?.recentActions?.length > 0 ? (
                  userStats.recentActions.map((action, index) => (
                    <div key={index} style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: '1rem',
                      padding: '1rem 1.25rem',
                      borderBottom: index < userStats.recentActions.length - 1 ? '1px solid var(--border-color)' : 'none'
                    }}>
                      <div style={{
                        width: '36px',
                        height: '36px',
                        borderRadius: '8px',
                        background: 'var(--primary-light)',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        flexShrink: 0
                      }}>
                        <svg style={{ width: '18px', height: '18px', color: 'var(--primary)' }} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                          <path strokeLinecap="round" strokeLinejoin="round" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
                        </svg>
                      </div>
                      <div style={{ flex: 1, minWidth: 0 }}>
                        <div style={{ fontSize: '0.875rem', color: 'var(--text-primary)', fontWeight: '500' }}>
                          {action.action || action.message || 'Action performed'}
                        </div>
                        <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.125rem' }}>
                          {action.resource_type && <span style={{ textTransform: 'capitalize' }}>{action.resource_type}</span>}
                          {action.resource_type && ' • '}
                          {new Date(action.created_at || action.timestamp).toLocaleString()}
                        </div>
                      </div>
                    </div>
                  ))
                ) : (
                  <div style={{ padding: '3rem 1.5rem', textAlign: 'center' }}>
                    <svg style={{ width: '48px', height: '48px', color: 'var(--text-muted)', margin: '0 auto 1rem' }} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1}>
                      <path strokeLinecap="round" strokeLinejoin="round" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" />
                    </svg>
                    <div style={{ fontSize: '0.875rem', color: 'var(--text-muted)' }}>No recent activity</div>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Password Change Modal */}
      {showPasswordModal && (
        <div
          onClick={() => setShowPasswordModal(false)}
          style={{
            position: 'fixed',
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            background: 'rgba(0,0,0,0.6)',
            backdropFilter: 'blur(4px)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 10000
          }}
        >
          <div
            onClick={(e) => e.stopPropagation()}
            style={{
              background: 'var(--bg-secondary)',
              borderRadius: '12px',
              padding: '1.5rem',
              width: '100%',
              maxWidth: '420px',
              border: '1px solid var(--border-color)',
              boxShadow: '0 20px 40px rgba(0,0,0,0.4)'
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1.5rem' }}>
              <h3 style={{ fontSize: '1.125rem', fontWeight: '600', color: 'var(--text-primary)' }}>Change Password</h3>
              <button
                onClick={() => setShowPasswordModal(false)}
                style={{
                  background: 'none',
                  border: 'none',
                  padding: '0.25rem',
                  cursor: 'pointer',
                  color: 'var(--text-muted)'
                }}
              >
                <svg style={{ width: '20px', height: '20px' }} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>

            <form onSubmit={handlePasswordChange}>
              {passwordError && (
                <div style={{
                  padding: '0.75rem 1rem',
                  background: 'rgba(239, 68, 68, 0.1)',
                  border: '1px solid rgba(239, 68, 68, 0.2)',
                  borderRadius: '8px',
                  color: '#ef4444',
                  fontSize: '0.8125rem',
                  marginBottom: '1rem'
                }}>
                  {passwordError}
                </div>
              )}
              {passwordSuccess && (
                <div style={{
                  padding: '0.75rem 1rem',
                  background: 'rgba(34, 197, 94, 0.1)',
                  border: '1px solid rgba(34, 197, 94, 0.2)',
                  borderRadius: '8px',
                  color: '#22c55e',
                  fontSize: '0.8125rem',
                  marginBottom: '1rem'
                }}>
                  {passwordSuccess}
                </div>
              )}

              <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                <div>
                  <label style={{ display: 'block', fontSize: '0.8125rem', fontWeight: '500', color: 'var(--text-secondary)', marginBottom: '0.5rem' }}>
                    Current Password
                  </label>
                  <input
                    type="password"
                    value={passwordData.currentPassword}
                    onChange={(e) => setPasswordData({ ...passwordData, currentPassword: e.target.value })}
                    placeholder="Enter current password"
                    required
                    style={{
                      width: '100%',
                      padding: '0.625rem 0.875rem',
                      background: 'var(--bg-tertiary)',
                      border: '1px solid var(--border-color)',
                      borderRadius: '6px',
                      color: 'var(--text-primary)',
                      fontSize: '0.875rem'
                    }}
                  />
                </div>
                <div>
                  <label style={{ display: 'block', fontSize: '0.8125rem', fontWeight: '500', color: 'var(--text-secondary)', marginBottom: '0.5rem' }}>
                    New Password
                  </label>
                  <input
                    type="password"
                    value={passwordData.newPassword}
                    onChange={(e) => setPasswordData({ ...passwordData, newPassword: e.target.value })}
                    placeholder="Enter new password"
                    required
                    style={{
                      width: '100%',
                      padding: '0.625rem 0.875rem',
                      background: 'var(--bg-tertiary)',
                      border: '1px solid var(--border-color)',
                      borderRadius: '6px',
                      color: 'var(--text-primary)',
                      fontSize: '0.875rem'
                    }}
                  />
                </div>
                <div>
                  <label style={{ display: 'block', fontSize: '0.8125rem', fontWeight: '500', color: 'var(--text-secondary)', marginBottom: '0.5rem' }}>
                    Confirm New Password
                  </label>
                  <input
                    type="password"
                    value={passwordData.confirmPassword}
                    onChange={(e) => setPasswordData({ ...passwordData, confirmPassword: e.target.value })}
                    placeholder="Confirm new password"
                    required
                    style={{
                      width: '100%',
                      padding: '0.625rem 0.875rem',
                      background: 'var(--bg-tertiary)',
                      border: '1px solid var(--border-color)',
                      borderRadius: '6px',
                      color: 'var(--text-primary)',
                      fontSize: '0.875rem'
                    }}
                  />
                </div>

                <div style={{
                  padding: '0.75rem 1rem',
                  background: 'var(--bg-tertiary)',
                  borderRadius: '6px',
                  fontSize: '0.75rem',
                  color: 'var(--text-muted)'
                }}>
                  <strong style={{ color: 'var(--text-secondary)' }}>Requirements:</strong>
                  <ul style={{ margin: '0.5rem 0 0', paddingLeft: '1rem', lineHeight: '1.6' }}>
                    <li>At least 8 characters</li>
                    <li>One uppercase letter</li>
                    <li>One lowercase letter</li>
                    <li>One number</li>
                  </ul>
                </div>

                <div style={{ display: 'flex', gap: '0.75rem', marginTop: '0.5rem' }}>
                  <button
                    type="button"
                    onClick={() => setShowPasswordModal(false)}
                    style={{
                      flex: 1,
                      padding: '0.625rem 1rem',
                      background: 'var(--bg-tertiary)',
                      border: '1px solid var(--border-color)',
                      borderRadius: '6px',
                      color: 'var(--text-secondary)',
                      fontSize: '0.875rem',
                      fontWeight: '500',
                      cursor: 'pointer'
                    }}
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    disabled={changingPassword}
                    style={{
                      flex: 1,
                      padding: '0.625rem 1rem',
                      background: 'var(--primary)',
                      border: 'none',
                      borderRadius: '6px',
                      color: 'white',
                      fontSize: '0.875rem',
                      fontWeight: '500',
                      cursor: changingPassword ? 'not-allowed' : 'pointer',
                      opacity: changingPassword ? 0.6 : 1
                    }}
                  >
                    {changingPassword ? 'Updating...' : 'Update Password'}
                  </button>
                </div>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}

export default UserProfile;


