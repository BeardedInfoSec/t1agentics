/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

import React, { useState, useEffect } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { API_BASE_URL } from '../utils/api';
import { setTenantCookie, getTenantCookie } from './TenantSelect';
import './Login.css';
import { AuthLayout } from '../layouts';

function Login({ onLogin }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [tenant, setTenant] = useState('');
  const [tenantInfo, setTenantInfo] = useState(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [tenantLoading, setTenantLoading] = useState(false);
  const [step, setStep] = useState(1); // 1 = org, 2 = credentials
  const [rememberOrg, setRememberOrg] = useState(() => !!getTenantCookie());
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();

  // Detect IP addresses to avoid parsing them as subdomains
  const isIPAddress = (hostname) => /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname);

  // Subdomain helpers
  const getBaseDomain = () => {
    const parts = window.location.hostname.split('.');
    if (parts.length >= 2) return parts.slice(-2).join('.');
    return window.location.hostname;
  };

  const isOnSubdomain = () => {
    const hostname = window.location.hostname;
    const parts = hostname.split('.');
    return parts.length > 2
      && !hostname.startsWith('www')
      && !hostname.startsWith('app')
      && !isIPAddress(hostname);
  };

  const isLocalDev = () => {
    const hostname = window.location.hostname;
    return hostname === 'localhost' || isIPAddress(hostname);
  };

  // Redirect to tenant subdomain (used on main domain only)
  const redirectToSubdomain = (slug) => {
    const baseDomain = getBaseDomain();
    window.location.href = `${window.location.protocol}//${slug}.${baseDomain}/login`;
  };

  // Check for tenant in URL params, saved cookie, or subdomain
  useEffect(() => {
    // Check subdomain first: barbas-rooster-co.t1agentics.ai
    if (isOnSubdomain()) {
      const subdomain = window.location.hostname.split('.')[0];
      setTenant(subdomain);
      fetchTenantInfo(subdomain, true);
      return;
    }

    // Check URL param: /login?tenant=acme (used for localhost dev)
    const urlTenant = searchParams.get('tenant');
    if (urlTenant) {
      setTenant(urlTenant);
      fetchTenantInfo(urlTenant, true);
      return;
    }

    // Check saved cookie — pre-fill org field (but don't auto-redirect)
    const savedTenant = getTenantCookie();
    if (savedTenant) {
      setTenant(savedTenant);
      if (isLocalDev()) {
        // On localhost, auto-advance with cookie
        fetchTenantInfo(savedTenant, true);
      }
      // On main domain: just pre-fill, let user click Continue
    }
  }, [searchParams]);

  const fetchTenantInfo = async (slug, autoAdvance = false) => {
    if (!slug) return;
    setTenantLoading(true);
    setError('');
    try {
      const response = await fetch(`${API_BASE_URL}/api/v1/admin/tenant/${slug}`);
      if (response.ok) {
        const data = await response.json();
        setTenantInfo(data);
        if (autoAdvance) {
          if (rememberOrg) {
            setTenantCookie(slug);
          }
          // On main domain: redirect to tenant subdomain
          // On subdomain or localhost: advance to Step 2
          if (!isOnSubdomain() && !isLocalDev()) {
            redirectToSubdomain(slug);
          } else {
            setStep(2);
          }
        }
      } else if (response.status === 404) {
        setError(`Organization "${slug}" not found. Please check the slug and try again.`);
      }
    } catch (err) {
      setError('Cannot connect to server. Please try again.');
    } finally {
      setTenantLoading(false);
    }
  };

  const handleTenantChange = (e) => {
    const value = e.target.value.toLowerCase().replace(/[^a-z0-9-]/g, '');
    setTenant(value);
    setTenantInfo(null);
    setError('');
  };

  const handleTenantContinue = (e) => {
    e.preventDefault();
    if (tenant && tenant.length >= 3) {
      fetchTenantInfo(tenant, true);
    } else {
      setError('Please enter a valid organization slug (at least 3 characters).');
    }
  };

  const handleBackToOrg = () => {
    setStep(1);
    setTenantInfo(null);
    setUsername('');
    setPassword('');
    setError('');
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      const response = await fetch(`${API_BASE_URL}/api/v1/admin/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        credentials: 'include',
        body: JSON.stringify({ username, password, tenant: tenant || undefined }),
      });

      if (!response.ok) {
        const data = await response.json().catch(() => ({}));
        throw new Error(data.detail || 'Login failed');
      }

      const data = await response.json();

      if (data.username) {
        const userData = {
          username: data.username,
          role: data.role,
          tenant_id: data.tenant_id,
          tenant_name: data.tenant_name,
          license_tier: data.license_tier,
          force_password_reset: data.force_password_reset
        };
        onLogin(userData);

        // Post-login: redirect to the tenant subdomain so the session
        // browses against barbas-rooster-co.t1agentics.ai instead of the
        // apex. Tenant cookie + JWT cover .t1agentics.ai already, so the
        // session carries across the redirect.
        // Skip on localhost / IP / when already on the right subdomain /
        // when no slug is known (rare — login form requires one).
        const slug = (tenant || '').trim().toLowerCase();
        if (slug && !isLocalDev() && !isOnSubdomain()) {
          const baseDomain = getBaseDomain();
          window.location.href = `${window.location.protocol}//${slug}.${baseDomain}/dashboard`;
          return;
        }
        navigate('/dashboard');
      } else {
        setError('Login failed. Please try again.');
      }
    } catch (err) {
      if (err.message.includes('Failed to fetch') || err.message.includes('NetworkError')) {
        setError('Cannot connect to backend. Please ensure the backend is running on port 8000.');
      } else {
        setError(err.message || 'Login failed');
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <AuthLayout>
      <a
        href={isOnSubdomain() ? `https://${getBaseDomain()}` : '/'}
        className="back-to-main-link"
      >
        <svg viewBox="0 0 24 24" fill="none" width="16" height="16">
          <path d="M19 12H5M5 12L12 5M5 12L12 19" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
        </svg>
        {isOnSubdomain() ? 't1agentics.ai' : 'Home'}
      </a>
      <div className="login-wrapper">
        {/* Branding above card */}
        <div className="login-branding">
          <div className="brand-logo">
            <img src="/T1_Agentics_Logo-removebg-preview.png" alt="T1 Agentics" className="logo-image t1-logo-dark" />
            <img src="/T1_Agentics_Light_Logo.png" alt="T1 Agentics" className="logo-image t1-logo-light" />
          </div>
          <p className="brand-tagline">Autonomous Security Operations Center</p>
        </div>

        {/* Login card */}
        <div className="login-box">
          <div className="login-header">
            {step === 1 ? (
              <>
                <h2>Welcome back</h2>
                <p>Enter your organization to get started</p>
              </>
            ) : (
              <>
                <h2>{tenantInfo?.name || tenant}</h2>
                <p>Sign in to access your SOC dashboard</p>
              </>
            )}
          </div>

          <form onSubmit={step === 1 ? handleTenantContinue : handleSubmit} className="login-form">
            {error && (
              <div className="error-message">
                <svg className="error-icon-svg" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                  <circle cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="2"/>
                  <path d="M12 8V12M12 16H12.01" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
                </svg>
                {error}
              </div>
            )}

            {step === 1 ? (
              <>
                {/* Step 1: Organization field */}
                <div className="form-group">
                  <label htmlFor="tenant">Organization</label>
                  <div className="input-wrapper">
                    <input
                      id="tenant"
                      type="text"
                      value={tenant}
                      onChange={handleTenantChange}
                      placeholder="your-organization"
                      autoComplete="organization"
                      autoFocus
                      disabled={tenantLoading}
                    />
                    <svg className="input-icon-svg" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                      <path d="M19 21V5C19 3.89543 18.1046 3 17 3H7C5.89543 3 5 3.89543 5 5V21M19 21L21 21M19 21H14M5 21L3 21M5 21H10M9 7H10M9 11H10M14 7H15M14 11H15M10 21V16C10 15.4477 10.4477 15 11 15H13C13.5523 15 14 15.4477 14 16V21M10 21H14" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                    </svg>
                  </div>
                  <span className="input-hint">Enter your organization's slug (e.g., acme-corp)</span>
                </div>

                <label className="remember-org">
                  <input
                    type="checkbox"
                    checked={rememberOrg}
                    onChange={(e) => setRememberOrg(e.target.checked)}
                  />
                  <span className="remember-org-check">
                    {rememberOrg && (
                      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3">
                        <polyline points="20 6 9 17 4 12"/>
                      </svg>
                    )}
                  </span>
                  <span className="remember-org-text">Remember my organization</span>
                </label>

                <button
                  type="submit"
                  className="login-button"
                  disabled={tenantLoading || !tenant || tenant.length < 3}
                >
                  {tenantLoading ? (
                    <>
                      <span className="spinner"></span>
                      Checking...
                    </>
                  ) : (
                    <>
                      Continue
                      <svg className="arrow-icon" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                        <path d="M5 12H19M19 12L12 5M19 12L12 19" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                      </svg>
                    </>
                  )}
                </button>
              </>
            ) : (
              <>
                {/* Step 2: Org badge + credentials */}
                <button type="button" className="org-badge" onClick={handleBackToOrg}>
                  <svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" width="16" height="16">
                    <path d="M19 21V5C19 3.89543 18.1046 3 17 3H7C5.89543 3 5 3.89543 5 5V21M19 21L21 21M19 21H14M5 21L3 21M5 21H10M9 7H10M9 11H10M14 7H15M14 11H15M10 21V16C10 15.4477 10.4477 15 11 15H13C13.5523 15 14 15.4477 14 16V21M10 21H14" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                  </svg>
                  <span>{tenantInfo?.name || tenant}</span>
                  <svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" width="14" height="14" className="org-badge-change">
                    <path d="M15 19L8 12L15 5" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                  </svg>
                  <span className="org-badge-hint">Change</span>
                </button>

                <div className="form-group">
                  <label htmlFor="username">Username</label>
                  <div className="input-wrapper">
                    <input
                      id="username"
                      type="text"
                      value={username}
                      onChange={(e) => setUsername(e.target.value)}
                      placeholder="Enter your username"
                      required
                      autoComplete="username"
                      autoFocus
                    />
                    <svg className="input-icon-svg" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                      <circle cx="12" cy="8" r="4" stroke="currentColor" strokeWidth="2"/>
                      <path d="M4 20C4 16.6863 7.58172 14 12 14C16.4183 14 20 16.6863 20 20" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
                    </svg>
                  </div>
                </div>

                <div className="form-group">
                  <label htmlFor="password">Password</label>
                  <div className="input-wrapper">
                    <input
                      id="password"
                      type="password"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      placeholder="Enter your password"
                      required
                      autoComplete="current-password"
                    />
                    <svg className="input-icon-svg" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                      <rect x="5" y="11" width="14" height="10" rx="2" stroke="currentColor" strokeWidth="2"/>
                      <path d="M8 11V7C8 4.79086 9.79086 3 12 3C14.2091 3 16 4.79086 16 7V11" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
                    </svg>
                  </div>
                </div>

                <button
                  type="submit"
                  className="login-button"
                  disabled={loading}
                >
                  {loading ? (
                    <>
                      <span className="spinner"></span>
                      Signing in...
                    </>
                  ) : (
                    <>
                      Sign In
                      <svg className="arrow-icon" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                        <path d="M5 12H19M19 12L12 5M19 12L12 19" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                      </svg>
                    </>
                  )}
                </button>

                <div className="forgot-password-link">
                  <button
                    type="button"
                    onClick={() => navigate('/forgot-password')}
                    className="link-button"
                  >
                    Forgot password?
                  </button>
                </div>
              </>
            )}
          </form>

          {/* SECURITY: Demo credentials removed for production */}
        </div>

        {/* Security badge */}
        <div className="security-badge">
          <svg className="lock-icon" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
            <rect x="5" y="11" width="14" height="10" rx="2" stroke="currentColor" strokeWidth="2"/>
            <path d="M8 11V7C8 4.79086 9.79086 3 12 3C14.2091 3 16 4.79086 16 7V11" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
            <circle cx="12" cy="16" r="1" fill="currentColor"/>
          </svg>
          <span>Secured with JWT Authentication</span>
        </div>
      </div>
    </AuthLayout>
  );
}

export default Login;
