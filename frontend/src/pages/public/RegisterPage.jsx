/** Copyright (c) 2025-2026 T1 Agentics LLC. SPDX-License-Identifier: Apache-2.0 */

import React, { useState, useEffect, useRef } from 'react';
import { Link, useSearchParams } from 'react-router-dom';

function slugify(text) {
  return text
    .toLowerCase()
    .replace(/\s+/g, '-')
    .replace(/[^a-z0-9-]/g, '')
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '');
}

function passwordStrength(pw) {
  const checks = {
    length: pw.length >= 12,
    upper: /[A-Z]/.test(pw),
    lower: /[a-z]/.test(pw),
    digit: /\d/.test(pw),
    special: /[!@#$%^&*()_+\-=[\]{}|;:,.<>?]/.test(pw),
  };
  const passed = Object.values(checks).filter(Boolean).length;
  return { checks, passed, total: 5 };
}

const s = {
  page: {
    display: 'flex',
    justifyContent: 'center',
    alignItems: 'flex-start',
    padding: '4rem 2rem 5rem',
    minHeight: 'calc(100vh - 64px)',
  },
  card: {
    background: 'var(--glass-bg-solid)',
    border: '1px solid var(--glass-border)',
    borderRadius: 'var(--radius-xl)',
    padding: '2.5rem',
    width: '100%',
    maxWidth: '480px',
    backdropFilter: 'blur(12px)',
    WebkitBackdropFilter: 'blur(12px)',
    boxShadow: 'var(--glass-shadow)',
  },
  title: {
    fontFamily: 'var(--font-sans)',
    fontWeight: 700,
    fontSize: 'var(--text-2xl)',
    color: 'var(--text-primary)',
    textAlign: 'center',
    marginBottom: '0.25rem',
  },
  subtitle: {
    fontFamily: 'var(--font-sans)',
    fontSize: 'var(--text-base)',
    color: 'var(--text-secondary)',
    textAlign: 'center',
    marginBottom: '2rem',
    lineHeight: 1.5,
  },
  pocBanner: {
    background: 'var(--primary-light)',
    border: '1px solid var(--border-accent)',
    borderRadius: 'var(--radius-md)',
    padding: '0.75rem 1rem',
    marginBottom: '1.5rem',
    color: 'var(--primary)',
    fontFamily: 'var(--font-sans)',
    fontSize: 'var(--text-sm)',
    textAlign: 'center',
    fontWeight: 500,
  },
  formGroup: {
    marginBottom: '1.25rem',
  },
  label: {
    display: 'block',
    fontFamily: 'var(--font-sans)',
    fontSize: 'var(--text-sm)',
    color: 'var(--text-secondary)',
    fontWeight: 500,
    marginBottom: '0.375rem',
  },
  input: {
    width: '100%',
    padding: '0.625rem 0.875rem',
    borderRadius: 'var(--radius-md)',
    border: '1px solid var(--border-color)',
    background: 'var(--bg-primary)',
    color: 'var(--text-primary)',
    fontFamily: 'var(--font-sans)',
    fontSize: 'var(--text-base)',
    outline: 'none',
    transition: 'border-color var(--transition-fast)',
    boxSizing: 'border-box',
  },
  inputFocus: {
    borderColor: 'var(--primary)',
    boxShadow: '0 0 0 2px var(--primary-light)',
  },
  strengthBar: {
    display: 'flex',
    gap: '4px',
    marginTop: '0.5rem',
    marginBottom: '0.25rem',
  },
  strengthSegment: (active, color) => ({
    height: '3px',
    flex: 1,
    borderRadius: '2px',
    background: active ? color : 'var(--bg-tertiary)',
    transition: 'background var(--transition-fast)',
  }),
  strengthReq: (met) => ({
    fontFamily: 'var(--font-sans)',
    fontSize: '0.7rem',
    color: met ? 'var(--primary)' : 'var(--text-muted)',
    display: 'flex',
    alignItems: 'center',
    gap: '0.25rem',
    marginBottom: '0.125rem',
  }),
  checkboxRow: {
    display: 'flex',
    alignItems: 'flex-start',
    gap: '0.5rem',
    marginBottom: '1.5rem',
  },
  checkbox: {
    marginTop: '3px',
    accentColor: 'var(--primary)',
    cursor: 'pointer',
  },
  checkboxLabel: {
    fontFamily: 'var(--font-sans)',
    fontSize: 'var(--text-sm)',
    color: 'var(--text-secondary)',
    lineHeight: 1.5,
  },
  submitBtn: (disabled) => ({
    display: 'block',
    width: '100%',
    padding: '0.75rem',
    borderRadius: 'var(--radius-md)',
    background: disabled ? 'var(--bg-tertiary)' : 'var(--btn-glass-gradient)',
    color: disabled ? 'var(--text-muted)' : '#fff',
    fontFamily: 'var(--font-sans)',
    fontSize: '1rem',
    fontWeight: 600,
    border: 'none',
    cursor: disabled ? 'default' : 'pointer',
    boxShadow: disabled ? 'none' : '0 2px 12px rgba(60,179,113,0.3)',
    transition: 'all var(--transition-fast)',
    opacity: disabled ? 0.6 : 1,
  }),
  error: {
    background: 'var(--danger-light)',
    border: '1px solid rgba(239,68,68,0.3)',
    borderRadius: 'var(--radius-md)',
    padding: '0.75rem 1rem',
    marginBottom: '1.25rem',
    color: 'var(--danger)',
    fontFamily: 'var(--font-sans)',
    fontSize: 'var(--text-sm)',
  },
  link: {
    color: 'var(--primary)',
    textDecoration: 'none',
    fontWeight: 500,
  },
  footerText: {
    fontFamily: 'var(--font-sans)',
    fontSize: 'var(--text-sm)',
    color: 'var(--text-secondary)',
    textAlign: 'center',
    marginTop: '1.5rem',
  },
  /* Success state */
  successContainer: {
    textAlign: 'center',
    padding: '2rem 0',
  },
  successIcon: {
    width: '72px',
    height: '72px',
    borderRadius: '50%',
    background: 'var(--primary-light)',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    margin: '0 auto 1.5rem',
    fontSize: '2rem',
    color: 'var(--primary)',
  },
  successTitle: {
    fontFamily: 'var(--font-sans)',
    fontWeight: 700,
    fontSize: 'var(--text-xl)',
    color: 'var(--text-primary)',
    marginBottom: '0.75rem',
  },
  successDesc: {
    fontFamily: 'var(--font-sans)',
    fontSize: 'var(--text-base)',
    color: 'var(--text-secondary)',
    lineHeight: 1.6,
    maxWidth: '360px',
    margin: '0 auto',
  },
};

export default function RegisterPage() {
  const [searchParams] = useSearchParams();
  const planParam = (searchParams.get('plan') || 'community').toLowerCase();
  const isPoc = planParam === 'poc';
  const isPaidPlan = ['professional', 'enterprise', 'enterprise_plus'].includes(planParam);
  const planLabel = {
    professional: 'Professional',
    enterprise: 'Enterprise',
    enterprise_plus: 'Enterprise Plus',
  }[planParam] || '';

  const refParam = searchParams.get('ref') || '';

  const [form, setForm] = useState({
    fullName: '',
    email: '',
    password: '',
    confirmPassword: '',
    tenantName: '',
    tenantSlug: '',
    agreeTerms: false,
    referralCode: refParam.toUpperCase(),
  });
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState(false);
  const [focusedField, setFocusedField] = useState('');
  const [tosScrolled, setTosScrolled] = useState(false);
  const tosRef = useRef(null);
  const [referralOrg, setReferralOrg] = useState(refParam ? 'validating' : '');

  useEffect(() => {
    if (refParam) validateReferralCode(refParam.toUpperCase());
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const validateReferralCode = async (code) => {
    if (!code) { setReferralOrg(''); return; }
    try {
      const res = await fetch(`/api/v1/affiliate/validate/${encodeURIComponent(code)}`);
      if (res.ok) {
        const data = await res.json();
        setReferralOrg(data.valid ? data.referrer_org : 'invalid');
      } else {
        setReferralOrg('invalid');
      }
    } catch {
      setReferralOrg('');
    }
  };

  const handleTosScroll = () => {
    const el = tosRef.current;
    if (!el) return;
    if (el.scrollHeight - el.scrollTop - el.clientHeight < 24) {
      setTosScrolled(true);
    }
  };

  const pw = passwordStrength(form.password);
  const strengthColor = pw.passed <= 1 ? 'var(--danger)' : pw.passed <= 2 ? 'var(--warning)' : pw.passed <= 3 ? '#eab308' : pw.passed <= 4 ? '#eab308' : 'var(--primary)';

  // Auto-generate slug from tenant name (hidden from user, sent via email)
  useEffect(() => {
    setForm((prev) => ({ ...prev, tenantSlug: slugify(prev.tenantName) }));
  }, [form.tenantName]);

  const handleChange = (field) => (e) => {
    const value = field === 'agreeTerms' ? e.target.checked : e.target.value;
    setForm((prev) => ({ ...prev, [field]: value }));
    if (error) setError('');
  };

  const passwordsMatch = form.password && form.confirmPassword && form.password === form.confirmPassword;

  const missingFields = [];
  if (!form.fullName.trim()) missingFields.push('Full Name');
  if (!form.email.trim()) missingFields.push('Email');
  if (pw.passed < 5) missingFields.push('Password (all 5 requirements above)');
  if (form.password && !passwordsMatch) missingFields.push('Passwords must match');
  if (!form.tenantName.trim()) missingFields.push('Organization Name');
  if (!form.agreeTerms) missingFields.push('Agree to the Terms (scroll to bottom and check the box)');

  const canSubmit =
    form.fullName.trim() &&
    form.email.trim() &&
    pw.passed === 5 &&
    passwordsMatch &&
    form.tenantName.trim() &&
    form.tenantSlug.trim() &&
    form.agreeTerms &&
    !submitting;

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!canSubmit) return;
    setSubmitting(true);
    setError('');

    try {
      const res = await fetch('/api/v1/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          full_name: form.fullName.trim(),
          email: form.email.trim(),
          password: form.password,
          tenant_name: form.tenantName.trim(),
          tenant_slug: form.tenantSlug.trim(),
          plan: isPaidPlan ? planParam : isPoc ? 'poc' : 'community',
          agreed_to_terms: form.agreeTerms,
          referral_code: form.referralCode.trim() || undefined,
        }),
      });

      if (res.ok) {
        setSuccess(true);
      } else {
        const data = await res.json().catch(() => ({}));
        // Extract meaningful validation errors from FastAPI 422 responses
        if (data.validation_errors && data.validation_errors.length > 0) {
          setError(data.validation_errors.map(e => e.message).join('. '));
        } else if (data.detail && typeof data.detail === 'string') {
          setError(data.detail);
        } else if (data.detail && Array.isArray(data.detail)) {
          setError(data.detail.map(e => e.msg || e.message || JSON.stringify(e)).join('. '));
        } else {
          setError(data.message || 'Registration failed. Please try again.');
        }
      }
    } catch {
      setError('Network error. Please check your connection and try again.');
    } finally {
      setSubmitting(false);
    }
  };

  const inputStyle = (field) => ({
    ...s.input,
    ...(focusedField === field ? s.inputFocus : {}),
  });

  if (success) {
    return (
      <div style={s.page}>
        <div style={s.card}>
          <div style={s.successContainer}>
            <div style={s.successIcon}>{'\u2709'}</div>
            <div style={s.successTitle}>Check Your Email</div>
            <div style={s.successDesc}>
              We sent a verification link to <strong style={{ color: 'var(--text-primary)' }}>{form.email}</strong>.
              Click the link in the email to verify your account and activate your tenant.
            </div>
          </div>
          <div style={s.footerText}>
            <Link to="/login" style={s.link}>Back to Login</Link>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div style={s.page}>
      <div style={s.card}>
        <h1 style={s.title}>Create Your Account</h1>
        <p style={s.subtitle}>
          {isPaidPlan
            ? `Sign up for the ${planLabel} plan`
            : isPoc
              ? 'Start your 30-day free trial'
              : 'Get started with T1 Agentics for free'}
        </p>

        {isPoc && (
          <div style={s.pocBanner}>
            30-day Proof of Concept -- full platform access, no credit card required.
          </div>
        )}

        {isPaidPlan && (
          <div style={s.pocBanner}>
            After verifying your email, you'll be redirected to checkout to activate your {planLabel} plan.
          </div>
        )}

        {error && <div style={s.error}>{error}</div>}

        <form onSubmit={handleSubmit}>
          {/* Full Name */}
          <div style={s.formGroup}>
            <label style={s.label} htmlFor="reg-name">Full Name</label>
            <input
              id="reg-name"
              type="text"
              value={form.fullName}
              onChange={handleChange('fullName')}
              onFocus={() => setFocusedField('fullName')}
              onBlur={() => setFocusedField('')}
              style={inputStyle('fullName')}
              placeholder="Jane Smith"
              autoComplete="name"
            />
          </div>

          {/* Email */}
          <div style={s.formGroup}>
            <label style={s.label} htmlFor="reg-email">Email</label>
            <input
              id="reg-email"
              type="email"
              value={form.email}
              onChange={handleChange('email')}
              onFocus={() => setFocusedField('email')}
              onBlur={() => setFocusedField('')}
              style={inputStyle('email')}
              placeholder="jane@company.com"
              autoComplete="email"
            />
          </div>

          {/* Password */}
          <div style={s.formGroup}>
            <label style={s.label} htmlFor="reg-password">Password</label>
            <input
              id="reg-password"
              type="password"
              value={form.password}
              onChange={handleChange('password')}
              onFocus={() => setFocusedField('password')}
              onBlur={() => setFocusedField('')}
              style={inputStyle('password')}
              placeholder="Create a strong password"
              autoComplete="new-password"
            />
            {form.password && (
              <div style={s.strengthBar}>
                {[1, 2, 3, 4, 5].map((i) => (
                  <div key={i} style={s.strengthSegment(pw.passed >= i, strengthColor)} />
                ))}
              </div>
            )}
            <div style={{
              marginTop: '0.5rem',
              padding: '0.625rem 0.75rem',
              background: 'var(--bg-tertiary)',
              border: '1px solid var(--border-color)',
              borderRadius: 'var(--radius-md)',
              fontFamily: 'var(--font-sans)',
              fontSize: '0.72rem',
              color: 'var(--text-secondary)',
            }}>
              <div style={{ fontWeight: 600, marginBottom: '0.35rem', color: 'var(--text-primary)' }}>
                Password must include all of the following:
              </div>
              <div style={s.strengthReq(pw.checks.length)}>
                {pw.checks.length ? '\u2713' : '\u2022'} At least 12 characters
              </div>
              <div style={s.strengthReq(pw.checks.upper)}>
                {pw.checks.upper ? '\u2713' : '\u2022'} Uppercase letter (A-Z)
              </div>
              <div style={s.strengthReq(pw.checks.lower)}>
                {pw.checks.lower ? '\u2713' : '\u2022'} Lowercase letter (a-z)
              </div>
              <div style={s.strengthReq(pw.checks.digit)}>
                {pw.checks.digit ? '\u2713' : '\u2022'} Digit (0-9)
              </div>
              <div style={s.strengthReq(pw.checks.special)}>
                {pw.checks.special ? '\u2713' : '\u2022'} Special character (!@#$%^&*)
              </div>
            </div>
          </div>

          {/* Confirm Password */}
          <div style={s.formGroup}>
            <label style={s.label} htmlFor="reg-confirm-password">Confirm Password</label>
            <input
              id="reg-confirm-password"
              type="password"
              value={form.confirmPassword}
              onChange={handleChange('confirmPassword')}
              onFocus={() => setFocusedField('confirmPassword')}
              onBlur={() => setFocusedField('')}
              style={inputStyle('confirmPassword')}
              placeholder="Re-enter your password"
              autoComplete="new-password"
            />
            {form.confirmPassword && !passwordsMatch && (
              <div style={{ fontFamily: 'var(--font-sans)', fontSize: '0.7rem', color: 'var(--danger)', marginTop: '0.25rem' }}>
                Passwords do not match
              </div>
            )}
            {passwordsMatch && (
              <div style={{ fontFamily: 'var(--font-sans)', fontSize: '0.7rem', color: 'var(--primary)', marginTop: '0.25rem' }}>
                {'\u2713'} Passwords match
              </div>
            )}
          </div>

          {/* Tenant Name */}
          <div style={s.formGroup}>
            <label style={s.label} htmlFor="reg-tenant">Organization Name</label>
            <input
              id="reg-tenant"
              type="text"
              value={form.tenantName}
              onChange={handleChange('tenantName')}
              onFocus={() => setFocusedField('tenantName')}
              onBlur={() => setFocusedField('')}
              style={inputStyle('tenantName')}
              placeholder="Acme Security"
              autoComplete="organization"
            />
          </div>

          {/* Referral Code (optional) */}
          <div style={s.formGroup}>
            <label style={s.label} htmlFor="reg-referral">
              Referral Code
              <span style={{ fontWeight: 400, color: 'var(--text-muted)', marginLeft: '0.5rem' }}>— optional</span>
            </label>
            <input
              id="reg-referral"
              type="text"
              value={form.referralCode}
              onChange={(e) => {
                const val = e.target.value.toUpperCase();
                setForm((prev) => ({ ...prev, referralCode: val }));
                setReferralOrg('');
              }}
              onBlur={(e) => {
                setFocusedField('');
                validateReferralCode(e.target.value.trim().toUpperCase());
              }}
              onFocus={() => setFocusedField('referralCode')}
              style={inputStyle('referralCode')}
              placeholder="T1-XXXXXX"
              autoComplete="off"
              maxLength={10}
            />
            {referralOrg === 'validating' && (
              <div style={{ fontFamily: 'var(--font-sans)', fontSize: '0.72rem', color: 'var(--text-muted)', marginTop: '0.25rem' }}>
                Validating...
              </div>
            )}
            {referralOrg && referralOrg !== 'invalid' && referralOrg !== 'validating' && (
              <div style={{ fontFamily: 'var(--font-sans)', fontSize: '0.72rem', color: 'var(--primary)', marginTop: '0.25rem' }}>
                {'\u2713'} Referred by {referralOrg} — 10% off your first month applied at checkout
              </div>
            )}
          </div>

          {/* Terms — scrollable, must reach bottom before checkbox enables */}
          <div style={s.formGroup}>
            <label style={s.label}>Terms of Service &amp; Acceptable Use Policy</label>

            {/* Scrollable content box */}
            <div
              ref={tosRef}
              onScroll={handleTosScroll}
              style={{
                height: '220px',
                overflowY: 'auto',
                border: `1px solid ${tosScrolled ? 'var(--primary)' : 'var(--border-color)'}`,
                borderRadius: 'var(--radius-md)',
                padding: '1rem 1.1rem',
                marginBottom: '0.5rem',
                background: 'var(--bg-primary)',
                fontSize: '0.78rem',
                lineHeight: 1.7,
                color: 'var(--text-secondary)',
                transition: 'border-color 0.2s',
              }}
            >
              <p style={{ fontWeight: 600, color: 'var(--text-primary)', marginBottom: '0.5rem' }}>
                T1 Agentics LLC — Terms of Service Summary
              </p>
              <p style={{ marginBottom: '0.75rem' }}>
                By creating an account you enter a binding agreement with T1 Agentics LLC. The full
                documents are available at the links below; key terms are summarized here.
              </p>

              <p style={{ fontWeight: 600, color: 'var(--text-primary)', marginBottom: '0.25rem' }}>1. Account Responsibilities</p>
              <p style={{ marginBottom: '0.75rem' }}>
                You are responsible for all activity under your account. You must provide accurate
                information, keep credentials confidential, and ensure all users in your tenant comply
                with these terms. You must be at least 18 years old.
              </p>

              <p style={{ fontWeight: 600, color: 'var(--text-primary)', marginBottom: '0.25rem' }}>2. Acceptable Use</p>
              <p style={{ marginBottom: '0.4rem' }}>
                The platform is for legitimate security operations — monitoring, triage, investigation,
                threat intelligence, and SOAR workflows — on systems you own or have explicit written
                authorization to protect. You may not use the Service to:
              </p>
              <ul style={{ paddingLeft: '1.2rem', marginBottom: '0.75rem' }}>
                <li style={{ marginBottom: '0.2rem' }}>Conduct unauthorized access or attacks against any system.</li>
                <li style={{ marginBottom: '0.2rem' }}>Store or distribute malware, exploits, or malicious code intended to harm third parties.</li>
                <li style={{ marginBottom: '0.2rem' }}>Plan, coordinate, or execute cyberattacks against third parties.</li>
                <li style={{ marginBottom: '0.2rem' }}>Create multiple accounts to circumvent usage limits.</li>
                <li style={{ marginBottom: '0.2rem' }}>Reverse engineer, decompile, or derive the source code of the Service.</li>
                <li style={{ marginBottom: '0.2rem' }}>Resell or redistribute access to the Service without written consent.</li>
                <li style={{ marginBottom: '0.2rem' }}>Engage in surveillance of individuals without proper legal authority.</li>
                <li>Violate any applicable local, state, national, or international law.</li>
              </ul>

              <p style={{ fontWeight: 600, color: 'var(--text-primary)', marginBottom: '0.25rem' }}>3. Data Ownership</p>
              <p style={{ marginBottom: '0.75rem' }}>
                You retain ownership of all data you submit. T1 Agentics processes your data solely to
                provide the Service and does not sell it to third parties.
              </p>

              <p style={{ fontWeight: 600, color: 'var(--text-primary)', marginBottom: '0.25rem' }}>4. AI-Assisted Analysis</p>
              <p style={{ marginBottom: '0.75rem' }}>
                The platform uses AI models to assist with triage,
                investigation, and playbook automation. AI outputs are advisory — you retain full
                responsibility for all security decisions made using the platform.
              </p>

              <p style={{ fontWeight: 600, color: 'var(--text-primary)', marginBottom: '0.25rem' }}>5. Limitation of Liability</p>
              <p style={{ marginBottom: '0.75rem' }}>
                T1 Agentics' total liability is limited to amounts paid in the prior 12 months or $100,
                whichever is greater. We are not liable for indirect, incidental, or consequential damages.
              </p>

              <p style={{ fontWeight: 600, color: 'var(--text-primary)', marginBottom: '0.25rem' }}>6. Termination</p>
              <p style={{ marginBottom: '0.75rem' }}>
                We may suspend or terminate accounts that violate these terms immediately and without
                notice. Free-tier accounts inactive for more than 90 days may be terminated with 30 days'
                notice.
              </p>

              <p style={{ fontWeight: 600, color: 'var(--text-primary)', marginBottom: '0.25rem' }}>7. Governing Law</p>
              <p style={{ marginBottom: '0.75rem' }}>
                These Terms are governed by the laws of the State of Delaware, United States. Disputes
                shall be resolved in Delaware state or federal courts.
              </p>

            </div>

            {/* Scroll prompt / confirmation */}
            {!tosScrolled ? (
              <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textAlign: 'center', marginBottom: '0.75rem' }}>
                Scroll to the bottom to accept
              </div>
            ) : (
              <div style={s.checkboxRow}>
                <input
                  type="checkbox"
                  id="reg-terms"
                  checked={form.agreeTerms}
                  onChange={handleChange('agreeTerms')}
                  style={s.checkbox}
                />
                <label htmlFor="reg-terms" style={s.checkboxLabel}>
                  I have read and agree to the Terms of Service, Acceptable Use Policy, Privacy Policy, and AI Governance Policy
                </label>
              </div>
            )}
          </div>

          {/* Missing fields hint */}
          {!canSubmit && missingFields.length > 0 && (
            <div style={{
              marginBottom: '0.75rem',
              padding: '0.625rem 0.875rem',
              background: 'var(--warning-light, rgba(234,179,8,0.08))',
              border: '1px solid var(--warning, #eab308)',
              borderRadius: 'var(--radius-md)',
              fontFamily: 'var(--font-sans)',
              fontSize: '0.78rem',
              color: 'var(--text-secondary)',
            }}>
              <div style={{ fontWeight: 600, marginBottom: '0.25rem', color: 'var(--text-primary)' }}>
                Before creating your account, please complete:
              </div>
              <ul style={{ margin: 0, paddingLeft: '1.1rem' }}>
                {missingFields.map((f) => (
                  <li key={f} style={{ marginBottom: '0.15rem' }}>{f}</li>
                ))}
              </ul>
            </div>
          )}

          {/* Submit */}
          <button
            type="submit"
            style={s.submitBtn(!canSubmit)}
            disabled={!canSubmit}
          >
            {submitting ? 'Creating Account...' : 'Create Account'}
          </button>
        </form>

        <div style={s.footerText}>
          Already have an account?{' '}
          <Link to="/login" style={s.link}>Sign in</Link>
        </div>
      </div>
    </div>
  );
}
