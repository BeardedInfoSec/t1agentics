/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { API_BASE_URL } from '../utils/api';
import { AuthLayout } from '../layouts';
import './TenantSelect.css';

// Cookie helpers
const TENANT_COOKIE_NAME = 't1a_tenant';
const COOKIE_MAX_AGE = 30 * 24 * 60 * 60; // 30 days

export function setTenantCookie(slug) {
  document.cookie = `${TENANT_COOKIE_NAME}=${slug}; path=/; max-age=${COOKIE_MAX_AGE}; SameSite=Lax`;
}

export function getTenantCookie() {
  const match = document.cookie.match(new RegExp(`(^| )${TENANT_COOKIE_NAME}=([^;]+)`));
  return match ? match[2] : null;
}

function clearTenantCookie() {
  document.cookie = `${TENANT_COOKIE_NAME}=; path=/; max-age=0`;
}

function TenantSelect() {
  const [orgInput, setOrgInput] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [hasSavedTenant, setHasSavedTenant] = useState(false);
  const [rememberOrg, setRememberOrg] = useState(true);
  const navigate = useNavigate();

  const isIPAddress = (hostname) => /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname);
  const isLocalDev = () => {
    const hostname = window.location.hostname;
    return hostname === 'localhost' || isIPAddress(hostname);
  };
  const getBaseDomain = () => {
    const parts = window.location.hostname.split('.');
    if (parts.length >= 2) return parts.slice(-2).join('.');
    return window.location.hostname;
  };
  const redirectToSubdomain = (slug) => {
    const baseDomain = getBaseDomain();
    window.location.href = `${window.location.protocol}//${slug}.${baseDomain}/login`;
  };

  // Check if we already have a tenant cookie — redirect to subdomain or login
  useEffect(() => {
    const savedTenant = getTenantCookie();
    if (savedTenant) {
      setHasSavedTenant(true);
      if (!isLocalDev()) {
        redirectToSubdomain(savedTenant);
      } else {
        navigate(`/login?tenant=${savedTenant}`);
      }
    }
  }, [navigate]);

  // Convert input to slug format
  const toSlug = (input) => {
    return input
      .toLowerCase()
      .trim()
      .replace(/[^a-z0-9\s-]/g, '')
      .replace(/\s+/g, '-')
      .replace(/-+/g, '-');
  };

  const handleInputChange = (e) => {
    setOrgInput(e.target.value);
    setError('');
  };

  const handleContinue = async () => {
    if (!orgInput.trim()) {
      setError('Please enter your organization name');
      return;
    }

    setLoading(true);
    setError('');

    const slug = toSlug(orgInput);

    try {
      const response = await fetch(`${API_BASE_URL}/api/v1/admin/tenant/${slug}`);

      if (!response.ok) {
        // Generic error — don't reveal whether org exists
        setError('Invalid organization. Please check the name and try again.');
        setLoading(false);
        return;
      }

      const tenant = await response.json();

      // Save to cookie only if user opted in
      if (rememberOrg) {
        setTenantCookie(tenant.slug);
      } else {
        clearTenantCookie();
      }

      // Redirect to tenant subdomain (or query param on localhost)
      if (!isLocalDev()) {
        redirectToSubdomain(tenant.slug);
      } else {
        navigate(`/login?tenant=${tenant.slug}`);
      }

    } catch (err) {
      setError('Unable to connect. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const handleKeyPress = (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      handleContinue();
    }
  };

  const handleDifferentOrg = () => {
    clearTenantCookie();
    setHasSavedTenant(false);
    setOrgInput('');
  };

  // Don't render while redirecting from saved cookie
  if (hasSavedTenant) return null;

  return (
    <AuthLayout>
      <div className="tenant-select-wrapper">
        {/* Branding */}
        <div className="tenant-branding">
          <div className="brand-logo">
            <img src="/T1_Agentics_Logo-removebg-preview.png" alt="T1 Agentics" className="logo-image t1-logo-dark" />
            <img src="/T1_Agentics_Light_Logo.png" alt="T1 Agentics" className="logo-image t1-logo-light" />
          </div>
          <p className="brand-tagline">Autonomous Security Operations Center</p>
        </div>

        {/* Selection card */}
        <div className="tenant-select-box">
          <div className="tenant-header">
            <h2>Welcome</h2>
            <p>Enter your organization to continue</p>
          </div>

          {error && (
            <div className="error-message">
              <svg className="error-icon-svg" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                <circle cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="2"/>
                <path d="M12 8V12M12 16H12.01" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
              </svg>
              {error}
            </div>
          )}

          <div className="tenant-form">
            <div className="form-group">
              <label htmlFor="org-input">Organization Name</label>
              <div className="input-wrapper">
                <input
                  id="org-input"
                  name="org-input-field"
                  type="text"
                  value={orgInput}
                  onChange={handleInputChange}
                  onKeyPress={handleKeyPress}
                  placeholder="Enter your organization"
                  autoComplete="off"
                  autoCorrect="off"
                  autoCapitalize="off"
                  spellCheck="false"
                  data-form-type="other"
                  data-lpignore="true"
                  data-1p-ignore="true"
                  autoFocus
                />
                {!orgInput && (
                  <svg className="input-icon-svg" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                    <path d="M19 21V5C19 3.89543 18.1046 3 17 3H7C5.89543 3 5 3.89543 5 5V21M19 21L21 21M19 21H14M5 21L3 21M5 21H10M9 7H10M9 11H10M14 7H15M14 11H15M10 21V16C10 15.4477 10.4477 15 11 15H13C13.5523 15 14 15.4477 14 16V21M10 21H14" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                  </svg>
                )}
              </div>
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
              className="continue-button"
              onClick={handleContinue}
              disabled={loading || !orgInput.trim()}
            >
              {loading ? (
                <>
                  <span className="spinner"></span>
                  Verifying...
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

            <p className="help-text">
              Enter your organization's name as provided by your administrator.
            </p>
          </div>
        </div>

        {/* Security badge */}
        <div className="security-badge">
          <svg className="lock-icon" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
            <rect x="5" y="11" width="14" height="10" rx="2" stroke="currentColor" strokeWidth="2"/>
            <path d="M8 11V7C8 4.79086 9.79086 3 12 3C14.2091 3 16 4.79086 16 7V11" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
            <circle cx="12" cy="16" r="1" fill="currentColor"/>
          </svg>
          <span>Secured with Enterprise Authentication</span>
        </div>
      </div>
    </AuthLayout>
  );
}

export default TenantSelect;
