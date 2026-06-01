/**
 * Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0
 */

/*
 * GuidedTour — in-product spotlight tour for the authenticated app.
 *
 * Forked from DemoSpotlightTour with three extensions:
 *  1. Pluggable scripts (platform / virustotal / inbox) loaded from
 *     TOUR_SCRIPTS so we can chain or branch tours.
 *  2. URL-based resume (?tour=ID&step=N) so OAuth round-trips can pick
 *     up where they left off after the provider redirects back.
 *  3. External trigger via the `t1-tour-start` custom event (used by the
 *     user-pill replay button + Riggs chat action chips).
 *
 * Each step targets a DOM element via `data-tour="key"`, dims the rest
 * of the page with an SVG mask cutout, and shows a tooltip with a
 * pulsing green outline around the target.
 *
 * Step shape:
 *   {
 *     target?: string,              // data-tour key (omit for centered modal)
 *     path?: string,                // route to navigate to before showing
 *     placement?: 'top'|'bottom'|'left'|'right'|'center',
 *     title: string,
 *     body: string|ReactNode,
 *     waitFor?: () => boolean,      // optional: pause until predicate true
 *     skipIf?: () => boolean,       // optional: auto-skip when predicate true
 *     onEnter?: () => void,         // side effects when step opens
 *     primaryLabel?: string,        // override "Next" button text
 *   }
 */

import React, { useEffect, useRef, useState, useCallback } from 'react';
import { useLocation, useNavigate, useSearchParams } from 'react-router-dom';
import { TOUR_SCRIPTS } from './tourScripts';

const LS_KEY = 't1-app-tour-seen-v1';
const RESUME_KEY = 't1-app-tour-resume-v1';

export default function GuidedTour() {
  const [tourId, setTourId] = useState(null);   // null = inactive
  const [step, setStep] = useState(0);
  const [rect, setRect] = useState(null);
  const [waiting, setWaiting] = useState(false);
  const navigate = useNavigate();
  const location = useLocation();
  const [searchParams, setSearchParams] = useSearchParams();
  const rafRef = useRef(null);
  const waitTimerRef = useRef(null);

  const script = tourId ? TOUR_SCRIPTS[tourId] : null;
  const open = !!script;
  const steps = script?.steps || [];
  const currentStep = steps[step];
  const isLast = step === steps.length - 1;

  // ── External + auto triggers ─────────────────────────────────────────
  // 1. First-login auto-fire. After login the app redirects to
  //    /dashboard, so that's the canonical first-page-seen for any new
  //    user. We auto-fire there (and on the bare root, which itself
  //    redirects to /dashboard for authed users) and nowhere else —
  //    users navigating to /queue or /investigations are no longer
  //    "new", they're doing work, and a tour popping up mid-task is
  //    obnoxious.
  useEffect(() => {
    const AUTOFIRE_PATHS = new Set([
      '/', '/dashboard',
      '/dashboard/overview', '/dashboard/management', '/dashboard/operations',
    ]);
    if (!AUTOFIRE_PATHS.has(location.pathname)) return;
    if (tourId) return;
    try {
      if (localStorage.getItem(LS_KEY) === 'seen') return;
    } catch { /* ignore */ }
    const t = setTimeout(() => {
      setTourId('platform');
      setStep(0);
    }, 800);
    return () => clearTimeout(t);
  }, [location.pathname, tourId]);

  // 2. URL resume: ?tour=virustotal&step=4 (used after OAuth callback)
  useEffect(() => {
    const urlTour = searchParams.get('tour');
    const urlStep = parseInt(searchParams.get('step') || '0', 10);
    if (urlTour && TOUR_SCRIPTS[urlTour] && !tourId) {
      setTourId(urlTour);
      setStep(Number.isFinite(urlStep) ? urlStep : 0);
      // Clean up URL so refreshes don't re-fire
      const next = new URLSearchParams(searchParams);
      next.delete('tour');
      next.delete('step');
      setSearchParams(next, { replace: true });
    }
  }, [searchParams, tourId, setSearchParams]);

  // 3. localStorage resume — if a previous session navigated away mid-tour
  //    (e.g. browser refresh during OAuth), pick up where we left off.
  useEffect(() => {
    if (tourId) return;
    try {
      const raw = localStorage.getItem(RESUME_KEY);
      if (!raw) return;
      const parsed = JSON.parse(raw);
      if (parsed?.tour && TOUR_SCRIPTS[parsed.tour]) {
        setTourId(parsed.tour);
        setStep(parsed.step || 0);
      }
    } catch { /* ignore */ }
  }, [tourId]);

  // 4. External event trigger (replay button, Riggs chat action)
  useEffect(() => {
    const handler = (e) => {
      const detail = e.detail || {};
      const which = detail.tour || 'platform';
      if (!TOUR_SCRIPTS[which]) return;
      setTourId(which);
      setStep(detail.step || 0);
    };
    window.addEventListener('t1-tour-start', handler);
    return () => window.removeEventListener('t1-tour-start', handler);
  }, []);

  // 5. Global click interceptor for `t1://tour/<id>` and `t1://tour/<id>?step=N` links.
  //    This is how Riggs starts a tour from chat: it emits a markdown link
  //    with that href, and any click anywhere in the app fires the tour.
  useEffect(() => {
    const onClick = (e) => {
      // Walk up to the nearest anchor — chat libraries often wrap link text.
      let el = e.target;
      while (el && el !== document && el.tagName !== 'A') el = el.parentElement;
      if (!el || el.tagName !== 'A') return;
      const href = el.getAttribute('href') || '';
      if (!href.startsWith('t1://tour/')) return;
      e.preventDefault();
      e.stopPropagation();
      try {
        const url = new URL(href);
        const which = url.pathname.replace(/^\/+/, '') || url.host || 'platform';
        const stepNum = parseInt(url.searchParams.get('step') || '0', 10);
        if (!TOUR_SCRIPTS[which]) return;
        setTourId(which);
        setStep(Number.isFinite(stepNum) ? stepNum : 0);
      } catch {
        // Malformed link — best-effort fall back to platform tour
        setTourId('platform');
        setStep(0);
      }
    };
    document.addEventListener('click', onClick, true);
    return () => document.removeEventListener('click', onClick, true);
  }, []);

  // ── Persist tour state for OAuth resume ──────────────────────────────
  useEffect(() => {
    if (!tourId) {
      try { localStorage.removeItem(RESUME_KEY); } catch { /* ignore */ }
      return;
    }
    try {
      localStorage.setItem(RESUME_KEY, JSON.stringify({ tour: tourId, step }));
    } catch { /* ignore */ }
  }, [tourId, step]);

  // ── Auto-skip / waitFor handling ─────────────────────────────────────
  useEffect(() => {
    if (!open || !currentStep) return undefined;
    if (currentStep.skipIf && currentStep.skipIf()) {
      // Schedule next-tick advance so React isn't mid-render
      const t = setTimeout(() => advance(), 0);
      return () => clearTimeout(t);
    }
    if (currentStep.onEnter) {
      try { currentStep.onEnter(); } catch { /* ignore */ }
    }
    // waitFor: poll until predicate true, then AUTO-ADVANCE. Once the
    // user has done what we asked (opened the wizard, pasted the key,
    // passed auth test), the spotlight should follow them forward
    // without making them hunt for the Next button.
    if (currentStep.waitFor) {
      setWaiting(true);
      const poll = () => {
        try {
          if (currentStep.waitFor()) {
            setWaiting(false);
            waitTimerRef.current = null;
            // Short delay so the user gets a beat to register what
            // happened before the spotlight jumps to the next target.
            setTimeout(() => advance(), 150);
          } else {
            waitTimerRef.current = setTimeout(poll, 200);
          }
        } catch {
          waitTimerRef.current = setTimeout(poll, 400);
        }
      };
      poll();
      return () => {
        if (waitTimerRef.current) clearTimeout(waitTimerRef.current);
        setWaiting(false);
      };
    }
    setWaiting(false);
    return undefined;
  }, [open, step, currentStep]); // eslint-disable-line

  // ── Navigation when a step requires a specific path ──────────────────
  // Compare the full path+search so `/connect?tab=marketplace` is treated
  // as a different destination from `/connect?tab=builder`. Without this,
  // tour steps that switch tabs via query string never actually navigate
  // (pathname matches → no-op).
  useEffect(() => {
    if (!open || !currentStep?.path) return;
    const currentFull = location.pathname + (location.search || '');
    // Normalize: if step.path has no query and we're on the same pathname
    // with any search, treat as match (don't strip user's existing params).
    const stepHasQuery = currentStep.path.includes('?');
    const target = currentStep.path;
    const isMatch = stepHasQuery
      ? currentFull === target
      : location.pathname === target;
    if (!isMatch) navigate(target);
  }, [open, step]); // eslint-disable-line

  // ── Target element tracking ──────────────────────────────────────────
  useEffect(() => {
    if (!open || !currentStep) return undefined;
    if (!currentStep.target) { setRect(null); return undefined; }

    let cancelled = false;
    let tries = 0;
    const find = () => {
      if (cancelled) return;
      const el = document.querySelector(`[data-tour="${currentStep.target}"]`);
      if (el) {
        // Scroll the element into view (smoothly) so the cutout matches
        // what the user actually sees.
        try {
          el.scrollIntoView({ block: 'center', inline: 'nearest', behavior: 'smooth' });
        } catch { /* ignore */ }
        const r = el.getBoundingClientRect();
        setRect({ top: r.top, left: r.left, width: r.width, height: r.height });
      } else if (tries < 60) {
        tries += 1;
        rafRef.current = requestAnimationFrame(find);
      } else {
        // Target never showed up — render the tooltip centered so the
        // tour doesn't get stuck.
        setRect(null);
      }
    };
    find();

    const update = () => {
      const el = document.querySelector(`[data-tour="${currentStep.target}"]`);
      if (!el) return;
      const r = el.getBoundingClientRect();
      setRect({ top: r.top, left: r.left, width: r.width, height: r.height });
    };
    window.addEventListener('scroll', update, true);
    window.addEventListener('resize', update);
    return () => {
      cancelled = true;
      if (rafRef.current) cancelAnimationFrame(rafRef.current);
      window.removeEventListener('scroll', update, true);
      window.removeEventListener('resize', update);
    };
  }, [open, step, location.pathname, currentStep]);

  // Esc to skip
  useEffect(() => {
    if (!open) return undefined;
    const onKey = (e) => { if (e.key === 'Escape') dismiss(); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  });

  const advance = useCallback(() => {
    setStep((p) => {
      // If we're at the last step of THIS tour, see if it chains into
      // another tour (defined as script.next on the final step's tour
      // object — used for "tour another integration?" prompts).
      if (p >= steps.length - 1) {
        if (script?.nextTour && TOUR_SCRIPTS[script.nextTour]) {
          setTourId(script.nextTour);
          return 0;
        }
        dismiss();
        return p;
      }
      return p + 1;
    });
  }, [steps.length, script]); // eslint-disable-line

  const dismiss = useCallback(() => {
    try {
      localStorage.setItem(LS_KEY, 'seen');
      localStorage.removeItem(RESUME_KEY);
    } catch { /* ignore */ }
    setTourId(null);
    setStep(0);
  }, []);

  // ── Render ───────────────────────────────────────────────────────────
  if (!open || !currentStep) return null;

  const pad = 8;
  const cut = rect ? {
    top: rect.top - pad,
    left: rect.left - pad,
    width: rect.width + pad * 2,
    height: rect.height + pad * 2,
  } : null;

  // Tooltip absolute position
  const TOOLTIP_W = 380;
  const TOOLTIP_H = 240;
  const PAD = 16;
  const vw = typeof window !== 'undefined' ? window.innerWidth : 1200;
  const vh = typeof window !== 'undefined' ? window.innerHeight : 800;

  let absLeft, absTop;
  const placement = currentStep.placement || (cut ? 'bottom' : 'center');
  if (!cut || placement === 'center') {
    absLeft = (vw - TOOLTIP_W) / 2;
    absTop = (vh - TOOLTIP_H) / 2;
  } else if (placement === 'top') {
    absLeft = cut.left + cut.width / 2 - TOOLTIP_W / 2;
    absTop = cut.top - 16 - TOOLTIP_H;
  } else if (placement === 'bottom') {
    absLeft = cut.left + cut.width / 2 - TOOLTIP_W / 2;
    absTop = cut.top + cut.height + 16;
  } else if (placement === 'left') {
    absLeft = cut.left - 16 - TOOLTIP_W;
    absTop = cut.top + cut.height / 2 - TOOLTIP_H / 2;
  } else { // right
    absLeft = cut.left + cut.width + 16;
    absTop = cut.top + cut.height / 2 - TOOLTIP_H / 2;
  }
  absLeft = Math.max(PAD, Math.min(absLeft, vw - TOOLTIP_W - PAD));
  absTop = Math.max(PAD, Math.min(absTop, vh - TOOLTIP_H - PAD));

  const primaryLabel = currentStep.primaryLabel || (isLast ? (script?.nextTour ? 'Continue →' : 'Start exploring') : 'Next →');

  return (
    <>
      {/*
        Dim overlay: 4 strips surrounding the cutout instead of one
        full-screen SVG. That way the cutout area genuinely passes
        clicks through (so the user can interact with the spotlighted
        element) while the dim outside the cutout absorbs stray clicks
        and keeps the user focused on the highlighted thing.

        When there's no target (centered tooltip), one full-screen dim
        is used instead.
      */}
      {cut ? (() => {
        // Add a 4px buffer between the dim strips and the cutout. The
        // strips have pointer-events: auto and live just below the
        // pulsing ring; without a buffer, sub-pixel rounding can leave
        // the strip overlapping the highlighted element and silently
        // eating clicks. Buffer is fully transparent so it doesn't
        // change the visual but guarantees the button under the
        // highlight stays clickable.
        const BUF = 4;
        const cTop    = cut.top - BUF;
        const cLeft   = cut.left - BUF;
        const cBottom = cut.top + cut.height + BUF;
        const cRight  = cut.left + cut.width + BUF;
        return (
          <>
            <div style={{ position: 'fixed', top: 0, left: 0, right: 0, height: Math.max(0, cTop), background: 'rgba(0,0,0,0.65)', zIndex: 9000, pointerEvents: 'auto', transition: 'all 0.18s ease' }} />
            <div style={{ position: 'fixed', top: cBottom, left: 0, right: 0, bottom: 0, background: 'rgba(0,0,0,0.65)', zIndex: 9000, pointerEvents: 'auto', transition: 'all 0.18s ease' }} />
            <div style={{ position: 'fixed', top: cTop, left: 0, width: Math.max(0, cLeft), height: Math.max(0, cBottom - cTop), background: 'rgba(0,0,0,0.65)', zIndex: 9000, pointerEvents: 'auto', transition: 'all 0.18s ease' }} />
            <div style={{ position: 'fixed', top: cTop, left: cRight, right: 0, height: Math.max(0, cBottom - cTop), background: 'rgba(0,0,0,0.65)', zIndex: 9000, pointerEvents: 'auto', transition: 'all 0.18s ease' }} />
          </>
        );
      })() : (
        <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.65)', zIndex: 9000, pointerEvents: 'auto' }} />
      )}

      {cut && (
        <div
          style={{
            position: 'fixed',
            top: cut.top - 2,
            left: cut.left - 2,
            width: cut.width + 4,
            height: cut.height + 4,
            borderRadius: '8px',
            border: '2px solid var(--primary, #3CB371)',
            boxShadow: '0 0 0 4px rgba(60,179,113,0.25), 0 0 24px rgba(60,179,113,0.55)',
            pointerEvents: 'none',
            zIndex: 9001,
            animation: 't1TourPulse 1.6s ease-in-out infinite',
            transition: 'all 0.25s ease',
          }}
        />
      )}

      <div
        style={{
          position: 'fixed',
          top: absTop,
          left: absLeft,
          zIndex: 9002,
          maxWidth: `${TOOLTIP_W}px`,
          width: 'calc(100vw - 2rem)',
          background: 'var(--bg-primary, #080a0f)',
          border: '1px solid rgba(60,179,113,0.5)',
          borderRadius: '10px',
          padding: '1rem 1.15rem 0.9rem',
          fontFamily: 'var(--font-sans)',
          color: 'var(--text-primary)',
          boxShadow: '0 20px 60px rgba(0,0,0,0.6), 0 0 30px rgba(60,179,113,0.18)',
        }}
      >
        <div style={{ display: 'flex', gap: '0.2rem', marginBottom: '0.7rem' }}>
          {steps.map((_, i) => (
            <span key={i} style={{
              flex: 1, height: '3px',
              background: i <= step ? 'var(--primary, #3CB371)' : 'rgba(255,255,255,0.08)',
              borderRadius: '2px',
              transition: 'background 0.2s',
            }} />
          ))}
        </div>

        <div style={{
          fontSize: '0.62rem', fontWeight: 700, textTransform: 'uppercase',
          letterSpacing: '0.06em', color: 'var(--text-muted)', marginBottom: '0.3rem',
          display: 'flex', justifyContent: 'space-between', alignItems: 'center',
        }}>
          <span>{script?.label || 'Tour'} · step {step + 1} of {steps.length}</span>
          {waiting && <span style={{ color: 'var(--primary)' }}>waiting…</span>}
        </div>
        <div style={{ fontSize: '1rem', fontWeight: 700, marginBottom: '0.45rem', lineHeight: 1.3 }}>
          {currentStep.title}
        </div>
        <div style={{ fontSize: '0.84rem', color: 'var(--text-secondary)', lineHeight: 1.55, marginBottom: '0.85rem' }}>
          {currentStep.body}
        </div>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '0.5rem' }}>
          <button onClick={dismiss} style={skipBtn}>Skip tour</button>
          <div style={{ display: 'flex', gap: '0.4rem' }}>
            {step > 0 && (
              <button onClick={() => setStep((p) => Math.max(0, p - 1))} style={secondaryBtn}>Back</button>
            )}
            <button onClick={advance} disabled={waiting} style={{ ...primaryBtn, opacity: waiting ? 0.5 : 1, cursor: waiting ? 'wait' : 'pointer' }}>
              {primaryLabel}
            </button>
          </div>
        </div>
      </div>

      <style>{`
        @keyframes t1TourPulse {
          0%, 100% { box-shadow: 0 0 0 4px rgba(60,179,113,0.25), 0 0 24px rgba(60,179,113,0.55); }
          50%      { box-shadow: 0 0 0 8px rgba(60,179,113,0.1),  0 0 32px rgba(60,179,113,0.75); }
        }
      `}</style>
    </>
  );
}

const baseBtn = {
  padding: '0.45rem 1rem',
  borderRadius: '6px',
  fontFamily: 'var(--font-sans)',
  fontSize: '0.82rem',
  fontWeight: 600,
};
const primaryBtn = { ...baseBtn, background: '#3CB371', color: '#fff', border: '1px solid rgba(60,179,113,0.6)' };
const secondaryBtn = { ...baseBtn, background: 'transparent', color: 'var(--text-secondary)', border: '1px solid var(--border-color)', cursor: 'pointer' };
const skipBtn = { ...baseBtn, background: 'transparent', color: 'var(--text-muted)', border: 'none', padding: '0.45rem 0.2rem', cursor: 'pointer' };

// Public helper — fire this from anywhere (e.g. user-pill menu, Riggs chat).
export function startTour(tour = 'platform', step = 0) {
  window.dispatchEvent(new CustomEvent('t1-tour-start', { detail: { tour, step } }));
}
