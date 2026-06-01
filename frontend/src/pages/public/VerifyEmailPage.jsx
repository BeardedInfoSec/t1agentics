/** Copyright (c) 2025-2026 T1 Agentics LLC. SPDX-License-Identifier: Apache-2.0 */

import React, { useState, useEffect } from 'react';
import { Link, useSearchParams } from 'react-router-dom';

const s = {
  page: {
    display: 'flex',
    justifyContent: 'center',
    alignItems: 'flex-start',
    padding: '6rem 2rem 5rem',
    minHeight: 'calc(100vh - 64px)',
  },
  card: {
    background: 'var(--glass-bg-solid)',
    border: '1px solid var(--glass-border)',
    borderRadius: 'var(--radius-xl)',
    padding: '3rem',
    width: '100%',
    maxWidth: '440px',
    backdropFilter: 'blur(12px)',
    WebkitBackdropFilter: 'blur(12px)',
    boxShadow: 'var(--glass-shadow)',
    textAlign: 'center',
  },
  iconCircle: (color) => ({
    width: '80px',
    height: '80px',
    borderRadius: '50%',
    background: color === 'green'
      ? 'var(--primary-light)'
      : color === 'red'
        ? 'var(--danger-light)'
        : 'var(--bg-tertiary)',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    margin: '0 auto 1.5rem',
    fontSize: '2.25rem',
    color: color === 'green'
      ? 'var(--primary)'
      : color === 'red'
        ? 'var(--danger)'
        : 'var(--text-muted)',
  }),
  title: {
    fontFamily: 'var(--font-sans)',
    fontWeight: 700,
    fontSize: 'var(--text-xl)',
    color: 'var(--text-primary)',
    marginBottom: '0.75rem',
  },
  desc: {
    fontFamily: 'var(--font-sans)',
    fontSize: 'var(--text-base)',
    color: 'var(--text-secondary)',
    lineHeight: 1.6,
    marginBottom: '2rem',
  },
  btn: {
    display: 'inline-flex',
    alignItems: 'center',
    padding: '0.65rem 2rem',
    borderRadius: 'var(--radius-md)',
    background: 'var(--btn-glass-gradient)',
    color: '#fff',
    fontFamily: 'var(--font-sans)',
    fontSize: 'var(--text-base)',
    fontWeight: 600,
    textDecoration: 'none',
    border: 'none',
    cursor: 'pointer',
    boxShadow: '0 2px 12px rgba(60,179,113,0.3)',
    transition: 'all var(--transition-fast)',
  },
  spinner: {
    width: '40px',
    height: '40px',
    border: '3px solid var(--bg-tertiary)',
    borderTop: '3px solid var(--primary)',
    borderRadius: '50%',
    animation: 'verify-spin 0.8s linear infinite',
    margin: '0 auto 1.5rem',
  },
  linkText: {
    fontFamily: 'var(--font-sans)',
    fontSize: 'var(--text-sm)',
    color: 'var(--text-secondary)',
    marginTop: '1rem',
  },
  link: {
    color: 'var(--primary)',
    textDecoration: 'none',
    fontWeight: 500,
  },
};

export default function VerifyEmailPage() {
  const [searchParams] = useSearchParams();
  const token = searchParams.get('token');

  const [status, setStatus] = useState('loading'); // loading | success | redirecting | error
  const [errorMsg, setErrorMsg] = useState('');
  const [tenantSlug, setTenantSlug] = useState('');

  useEffect(() => {
    if (!token) {
      setStatus('error');
      setErrorMsg('No verification token provided. Please check your email for the correct link.');
      return;
    }

    let cancelled = false;

    const verify = async () => {
      try {
        const res = await fetch(`/api/v1/register/verify?token=${encodeURIComponent(token)}`);
        if (cancelled) return;

        if (res.ok) {
          const data = await res.json();
          // If the backend returned a checkout_url, redirect to Stripe
          if (data.tenant?.slug) {
            setTenantSlug(data.tenant.slug);
          }
          if (data.checkout_url) {
            setStatus('redirecting');
            window.location.href = data.checkout_url;
          } else {
            setStatus('success');
          }
        } else {
          const data = await res.json().catch(() => ({}));
          setStatus('error');
          setErrorMsg(data.message || data.detail || 'Verification failed. The token may be expired or invalid.');
        }
      } catch {
        if (!cancelled) {
          setStatus('error');
          setErrorMsg('Network error. Please check your connection and try again.');
        }
      }
    };

    verify();

    return () => {
      cancelled = true;
    };
  }, [token]);

  return (
    <div style={s.page}>
      <div style={s.card}>
        {status === 'loading' && (
          <>
            <div style={s.spinner} />
            <div style={s.title}>Verifying Your Email</div>
            <div style={s.desc}>Please wait while we verify your email address...</div>
          </>
        )}

        {status === 'redirecting' && (
          <>
            <div style={s.spinner} />
            <div style={s.title}>Email Verified!</div>
            <div style={s.desc}>
              Redirecting you to checkout to activate your plan...
            </div>
          </>
        )}

        {status === 'success' && (
          <>
            <div style={s.iconCircle('green')}>{'\u2713'}</div>
            <div style={s.title}>Email Verified!</div>
            <div style={s.desc}>
              Your email has been verified and your workspace has been created.
              You can now log in to start using T1 Agentics.
            </div>
            <Link to={tenantSlug ? `/login?tenant=${tenantSlug}` : '/login'} style={s.btn}>Go to Login</Link>
          </>
        )}

        {status === 'error' && (
          <>
            <div style={s.iconCircle('red')}>{'\u2717'}</div>
            <div style={s.title}>Verification Failed</div>
            <div style={s.desc}>{errorMsg}</div>
            <div style={s.linkText}>
              <Link to="/register" style={s.link}>Try Again</Link>
            </div>
          </>
        )}
      </div>

      <style>{`
        @keyframes verify-spin {
          0% { transform: rotate(0deg); }
          100% { transform: rotate(360deg); }
        }
      `}</style>
    </div>
  );
}
