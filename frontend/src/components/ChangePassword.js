/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

import React, { useState } from 'react';
import { API_BASE_URL, getCsrfToken } from '../utils/api';
import styles from './ChangePassword.module.css';
import { Button, Input } from './ui';
import { KeyRound } from 'lucide-react';

function ChangePassword({ user, onPasswordChanged, onLogout }) {
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const passwordChecks = {
    length: newPassword.length >= 12,
    upper: /[A-Z]/.test(newPassword),
    lower: /[a-z]/.test(newPassword),
    digit: /\d/.test(newPassword),
    special: /[!@#$%^&*()_+\-=[\]{}|;:,.<>?]/.test(newPassword),
  };
  const allChecksPassed = Object.values(passwordChecks).every(Boolean);
  const passwordsMatch = newPassword && confirmPassword && newPassword === confirmPassword;

  const validatePassword = () => {
    if (!allChecksPassed) {
      return 'Please meet all password requirements below';
    }
    return null;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');

    if (!passwordsMatch) {
      setError('New passwords do not match');
      return;
    }

    const validationError = validatePassword();
    if (validationError) {
      setError(validationError);
      return;
    }

    if (newPassword === currentPassword) {
      setError('New password must be different from current password');
      return;
    }

    setLoading(true);

    try {
      const csrf = getCsrfToken();
      const headers = { 'Content-Type': 'application/json' };
      if (csrf) headers['X-CSRF-Token'] = csrf;

      const response = await fetch(`${API_BASE_URL}/api/v1/admin/password-change`, {
        method: 'POST',
        headers,
        credentials: 'include',
        body: JSON.stringify({
          current_password: currentPassword,
          new_password: newPassword
        })
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.detail || 'Failed to change password');
      }

      onPasswordChanged();
    } catch (err) {
      setError(err.message || 'Failed to change password');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className={styles.overlay}>
      <div className={styles.container}>
        <div className={styles.header}>
          <KeyRound size={28} />
          <h2 className={styles.title}>Password Change Required</h2>
          <p className={styles.subtitle}>
            {user?.username ? `User ${user.username}` : 'Update your password to continue.'}
          </p>
        </div>

        <form onSubmit={handleSubmit} className={styles.form}>
          {error && <div className={styles.error}>{error}</div>}

          <Input
            label="Current Password"
            type="password"
            value={currentPassword}
            onChange={(e) => setCurrentPassword(e.target.value)}
            required
          />

          <Input
            label="New Password"
            type="password"
            value={newPassword}
            onChange={(e) => setNewPassword(e.target.value)}
            required
          />

          {newPassword && (
            <div className={styles.requirements}>
              <div className={passwordChecks.length ? styles.reqMet : styles.reqUnmet}>
                {passwordChecks.length ? '\u2713' : '\u2022'} 12+ characters
              </div>
              <div className={passwordChecks.upper ? styles.reqMet : styles.reqUnmet}>
                {passwordChecks.upper ? '\u2713' : '\u2022'} Uppercase letter
              </div>
              <div className={passwordChecks.lower ? styles.reqMet : styles.reqUnmet}>
                {passwordChecks.lower ? '\u2713' : '\u2022'} Lowercase letter
              </div>
              <div className={passwordChecks.digit ? styles.reqMet : styles.reqUnmet}>
                {passwordChecks.digit ? '\u2713' : '\u2022'} Digit
              </div>
              <div className={passwordChecks.special ? styles.reqMet : styles.reqUnmet}>
                {passwordChecks.special ? '\u2713' : '\u2022'} Special character (!@#$%...)
              </div>
            </div>
          )}

          <Input
            label="Confirm New Password"
            type="password"
            value={confirmPassword}
            onChange={(e) => setConfirmPassword(e.target.value)}
            required
          />

          {confirmPassword && !passwordsMatch && (
            <div className={styles.reqUnmet}>Passwords do not match</div>
          )}
          {passwordsMatch && (
            <div className={styles.reqMet}>{'\u2713'} Passwords match</div>
          )}

          <div className={styles.footer}>
            <Button variant="ghost" type="button" onClick={onLogout} disabled={loading}>
              Logout
            </Button>
            <Button type="submit" disabled={loading}>
              {loading ? 'Updating...' : 'Update Password'}
            </Button>
          </div>
        </form>
      </div>
    </div>
  );
}

export default ChangePassword;
