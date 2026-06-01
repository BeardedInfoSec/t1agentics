/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import './PasswordReset.css';
import { API_BASE_URL } from '../utils/api';
import { AuthLayout } from '../layouts';
import { Button, Input } from './ui';
import { Shield, Mail, Wrench, AlertTriangle, ArrowLeft } from 'lucide-react';

function ForgotPassword() {
  const [email, setEmail] = useState('');
  const [loading, setLoading] = useState(false);
  const [success, setSuccess] = useState(false);
  const [error, setError] = useState('');
  const [devToken, setDevToken] = useState('');
  
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      const response = await fetch(`${API_BASE_URL}/api/v1/admin/password-reset/request`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ email }),
      });

      const data = await response.json();

      if (response.ok) {
        setSuccess(true);
        if (data.dev_token) {
          setDevToken(data.dev_token);
        }
      } else {
        setError(data.detail || 'An error occurred');
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
            <h2>Check Your Email</h2>
          </div>

          <div className="success-message">
            <Mail size={24} className="success-icon" />
            <p>If an account exists with <strong>{email}</strong>, you will receive a password reset link.</p>
            <p className="help-text">The link will expire in 1 hour.</p>
          </div>

          {devToken && (
            <div className="dev-mode-box">
              <h3 className="dev-mode-title">
                <Wrench size={16} />
                Development Mode
              </h3>
              <p>Reset Token: <code>{devToken}</code></p>
              <Button onClick={() => navigate(`/reset-password?token=${devToken}`)}>
                Go to Reset Page
              </Button>
            </div>
          )}

          <Button variant="secondary" onClick={() => navigate('/login')}>
            Back to Login
          </Button>
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
          <p className="subtitle">Enter your email to receive a reset link</p>
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
              label="Email Address"
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="you@example.com"
              required
              autoFocus
            />
          </div>

          <Button type="submit" disabled={loading}>
            {loading ? 'Sending...' : 'Send Reset Link'}
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

export default ForgotPassword;
