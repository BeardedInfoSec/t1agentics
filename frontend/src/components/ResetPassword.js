/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

import React, { useState, useEffect } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import './PasswordReset.css';
import { API_BASE_URL } from '../utils/api';
import { AuthLayout } from '../layouts';
import { Button, Input } from './ui';
import { Shield, CheckCircle, AlertTriangle, ArrowLeft } from 'lucide-react';

function ResetPassword() {
  const [searchParams] = useSearchParams();
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [success, setSuccess] = useState(false);
  const [error, setError] = useState('');
  const [token, setToken] = useState('');
  // tokenStatus: 'checking' | 'valid' | 'invalid' | 'used' | 'expired'
  const [tokenStatus, setTokenStatus] = useState('checking');

  const navigate = useNavigate();

  useEffect(() => {
    const tokenParam = searchParams.get('token');
    if (!tokenParam) {
      setTokenStatus('invalid');
      setError('Invalid reset link. Please request a new password reset.');
      return;
    }
    setToken(tokenParam);

    // Verify with backend on mount so we can show "already used" / "expired"
    // without making the user submit and fail.
    let cancelled = false;
    (async () => {
      try {
        const res = await fetch(
          `${API_BASE_URL}/api/v1/admin/password-reset/verify?token=${encodeURIComponent(tokenParam)}`,
          { method: 'GET' }
        );
        const data = await res.json().catch(() => ({}));
        if (cancelled) return;
        if (res.ok && data.valid) {
          setTokenStatus('valid');
        } else {
          setTokenStatus(data.reason || 'invalid');
        }
      } catch {
        if (!cancelled) setTokenStatus('invalid');
      }
    })();
    return () => { cancelled = true; };
  }, [searchParams]);

  const passwordRules = [
    { id: 'length',  test: (p) => p.length >= 12,           label: 'At least 12 characters' },
    { id: 'upper',   test: (p) => /[A-Z]/.test(p),          label: 'One uppercase letter (A-Z)' },
    { id: 'lower',   test: (p) => /[a-z]/.test(p),          label: 'One lowercase letter (a-z)' },
    { id: 'digit',   test: (p) => /\d/.test(p),             label: 'One digit (0-9)' },
    { id: 'special', test: (p) => /[!@#$%^&*()_+\-=[\]{}|;:,.<>?]/.test(p), label: 'One special character (!@#$%^&* etc.)' },
  ];

  const passwordChecks = passwordRules.map((r) => ({ ...r, ok: r.test(newPassword) }));
  const allRulesPass = passwordChecks.every((c) => c.ok);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');

    if (!allRulesPass) {
      const firstFail = passwordChecks.find((c) => !c.ok);
      setError(`Password must satisfy: ${firstFail.label.toLowerCase()}`);
      return;
    }

    if (newPassword !== confirmPassword) {
      setError('Passwords do not match');
      return;
    }

    setLoading(true);

    try {
      const response = await fetch(`${API_BASE_URL}/api/v1/admin/password-reset/confirm`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          token: token,
          new_password: newPassword,
        }),
      });

      const data = await response.json();

      if (response.ok) {
        setSuccess(true);
        setTimeout(() => {
          navigate('/login');
        }, 3000);
      } else {
        setError(data.detail || 'Failed to reset password');
      }
    } catch (err) {
      setError('Connection error. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  if (success) {
    return (
      <AuthLayout>
        <div className="reset-container">
          <div className="reset-header">
            <div className="logo-section">
              <Shield size={20} className="logo-icon" />
              <h1>T1 Agentics</h1>
            </div>
            <h2>Password Reset Complete</h2>
          </div>

          <div className="success-message">
            <CheckCircle size={24} className="success-icon" />
            <p>Your password has been reset successfully.</p>
            <p className="help-text">Redirecting to login page...</p>
          </div>

          <Button onClick={() => navigate('/login')}>Go to Login</Button>
        </div>
      </AuthLayout>
    );
  }

  if (tokenStatus === 'checking') {
    return (
      <AuthLayout>
        <div className="reset-container">
          <div className="reset-header">
            <div className="logo-section">
              <Shield size={20} className="logo-icon" />
              <h1>T1 Agentics</h1>
            </div>
            <h2>Verifying reset link…</h2>
          </div>
        </div>
      </AuthLayout>
    );
  }

  if (tokenStatus !== 'valid') {
    const headlines = {
      used:    'This Reset Link Has Already Been Used',
      expired: 'This Reset Link Has Expired',
      invalid: 'Invalid Reset Link',
    };
    const messages = {
      used:    'For security, password reset links can only be used once. If you need to reset your password again, request a new link.',
      expired: 'Reset links are valid for one hour. Request a new link to continue.',
      invalid: error || 'This password reset link is invalid. Please request a new one.',
    };
    return (
      <AuthLayout>
        <div className="reset-container">
          <div className="reset-header">
            <div className="logo-section">
              <Shield size={20} className="logo-icon" />
              <h1>T1 Agentics</h1>
            </div>
            <h2>{headlines[tokenStatus] || headlines.invalid}</h2>
          </div>

          <div className="error-message">
            <AlertTriangle size={16} className="error-icon" />
            {messages[tokenStatus] || messages.invalid}
          </div>

          <Button onClick={() => navigate('/forgot-password')}>Request New Reset Link</Button>
        </div>
      </AuthLayout>
    );
  }

  return (
    <AuthLayout>
      <div className="reset-container">
        <div className="reset-header">
          <div className="logo-section">
            <Shield size={20} className="logo-icon" />
            <h1>T1 Agentics</h1>
          </div>
          <h2>Reset Password</h2>
          <p className="subtitle">Create a new password for your account</p>
        </div>

        <form onSubmit={handleSubmit} className="reset-form">
          {error && (
            <div className="error-message">
              <AlertTriangle size={16} className="error-icon" />
              {error}
            </div>
          )}

          <div className="form-group">
            <Input
              label="New Password"
              type="password"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              placeholder="Enter new password"
              required
              autoFocus
            />
            <ul style={{
              listStyle: 'none',
              padding: 0,
              margin: '0.5rem 0 0',
              fontSize: '0.78rem',
              lineHeight: 1.6,
            }}>
              {passwordChecks.map((c) => (
                <li key={c.id} style={{
                  color: c.ok ? 'var(--primary, #3CB371)' : 'var(--text-muted, #94a3b8)',
                }}>
                  {c.ok ? '✓' : '•'} {c.label}
                </li>
              ))}
            </ul>
          </div>

          <div className="form-group">
            <Input
              label="Confirm Password"
              type="password"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              placeholder="Confirm new password"
              required
            />
          </div>

          <Button type="submit" disabled={loading || !allRulesPass || newPassword !== confirmPassword}>
            {loading ? 'Resetting...' : 'Reset Password'}
          </Button>

          <Button variant="ghost" type="button" onClick={() => navigate('/login')}>
            <ArrowLeft size={14} />
            Back to Login
          </Button>
        </form>
      </div>
    </AuthLayout>
  );
}

export default ResetPassword;
