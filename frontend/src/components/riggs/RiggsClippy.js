/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

import React, { useState, useCallback, useRef, useEffect, useMemo } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { X, MessageCircle, Send } from 'lucide-react';
import { usePreferences } from '../../hooks/usePreferences';
import { API_BASE_URL, getAuthHeaders, getCsrfToken } from '../../utils/api';
import RiggsAvatar from '../onboarding/RiggsAvatar';
import { getTipsForRoute } from './contextualTips';
import styles from './RiggsClippy.module.css';

export default function RiggsClippy() {
  const { preferences, updatePreferences } = usePreferences();
  const location = useLocation();
  const navigate = useNavigate();

  const [open, setOpen] = useState(false);
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);

  const messagesEndRef = useRef(null);
  const inputRef = useRef(null);

  const clippy = preferences?.riggs_clippy;
  const isInvestigationPage = location.pathname.startsWith('/investigation/');

  // Proactive tips driven by live platform state — SLA breaches, unassigned
  // NEEDS_REVIEW, high-risk entities, pending recommended actions, related
  // investigations on the current case. Re-fetched on route change and
  // every 60s while Clippy is open.
  const [proactiveTips, setProactiveTips] = useState([]);
  useEffect(() => {
    let cancelled = false;
    const fetchProactive = async () => {
      try {
        const url = `${API_BASE_URL}/api/v1/riggs/proactive-tips?route=${encodeURIComponent(location.pathname)}`;
        const res = await fetch(url, { headers: getAuthHeaders() });
        if (!res.ok) return;
        const data = await res.json();
        if (!cancelled) setProactiveTips(Array.isArray(data.tips) ? data.tips : []);
      } catch { /* silent */ }
    };
    fetchProactive();
    // Poll while open at 60s. Poll while closed at 5min so a critical
    // SLA breach developing mid-session can still trigger the auto-pop
    // below without burning request volume.
    const interval = setInterval(fetchProactive, open ? 60000 : 300000);
    return () => { cancelled = true; clearInterval(interval); };
  }, [location.pathname, open]);

  // Auto-pop: if any live tip comes back critical-severity and the panel
  // is closed, pop it open once per session so the analyst can't miss a
  // real fire. Tracked in sessionStorage so reloading the tab counts as
  // a fresh session (intentional — a refresh means the user just looked
  // away, give the pop another chance).
  useEffect(() => {
    if (open) return;
    const hasCritical = proactiveTips.some((t) => t.severity === 'critical');
    if (!hasCritical) return;
    try {
      const k = 't1-clippy-autopop-session';
      if (sessionStorage.getItem(k)) return;
      sessionStorage.setItem(k, '1');
    } catch { /* sessionStorage blocked — fall through and pop anyway */ }
    setOpen(true);
  }, [proactiveTips, open]);

  // Merge proactive (live) tips with static (route-based) tips. Proactive
  // first because they're actionable; static tips are educational fallback.
  const tips = useMemo(() => {
    const staticTips = getTipsForRoute(location.pathname);
    const dismissed = clippy?.dismissed_tips || [];
    // Normalize proactive tips to the static-tip shape so the renderer's
    // tip.action?.navigate check actually fires. Previously these were
    // mapped to {action: <label string>, route: <link>}, which the
    // renderer doesn't understand — so the "Go there" link never showed
    // up on live, actionable tips like "12 past SLA". The severity tag
    // is preserved on _severity for the styling pass.
    const proactive = proactiveTips.map((t) => ({
      id: `live:${t.id}`,
      text: t.text,
      action: t.action?.link
        ? { navigate: t.action.link, label: t.action.label || 'Go there' }
        : undefined,
      _live: true,
      _severity: t.severity,
    }));
    const combined = [...proactive, ...staticTips];
    return combined.filter((tip) => !dismissed.includes(tip.id));
  }, [location.pathname, clippy?.dismissed_tips, proactiveTips]);

  // Scroll to bottom when messages change
  useEffect(() => {
    if (messagesEndRef.current) {
      messagesEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [messages, loading]);

  // Focus input when panel opens
  useEffect(() => {
    if (open && inputRef.current) {
      // Slight delay so the animation finishes
      const timer = setTimeout(() => inputRef.current?.focus(), 220);
      return () => clearTimeout(timer);
    }
  }, [open]);

  // Dismiss a tip
  const dismissTip = useCallback(
    (tipId) => {
      const currentDismissed = clippy?.dismissed_tips || [];
      if (currentDismissed.includes(tipId)) return;
      updatePreferences({
        riggs_clippy: {
          ...clippy,
          dismissed_tips: [...currentDismissed, tipId],
        },
      });
    },
    [clippy, updatePreferences]
  );

  // Send a message to Riggs
  const sendMessage = useCallback(async () => {
    const text = input.trim();
    if (!text || loading) return;

    const userMessage = { role: 'user', content: text };
    setMessages((prev) => [...prev, userMessage]);
    setInput('');
    setLoading(true);

    try {
      const csrf = getCsrfToken();
      const headers = {
        ...getAuthHeaders(),
      };
      if (csrf) {
        headers['X-CSRF-Token'] = csrf;
      }

      // Extract investigation_id from /investigation/:id (or /investigations/:id)
      // so backend can resolve the underlying alert for "build a playbook" intent.
      const invMatch = location.pathname.match(/\/investigations?\/([0-9a-fA-F-]{8,})/);
      const investigationId = invMatch ? invMatch[1] : null;

      const response = await fetch(`${API_BASE_URL}/api/v1/riggs/assist`, {
        method: 'POST',
        headers,
        credentials: 'include',
        body: JSON.stringify({
          message: text,
          context: {
            page: location.pathname,
            ...(investigationId ? { investigation_id: investigationId } : {}),
          },
        }),
      });

      if (!response.ok) {
        throw new Error(`Request failed with status ${response.status}`);
      }

      const data = await response.json();
      setMessages((prev) => [
        ...prev,
        { role: 'assistant', content: data.response || 'No response received.' },
      ]);
    } catch (err) {
      setMessages((prev) => [
        ...prev,
        {
          role: 'assistant',
          content: 'Sorry, I was unable to process your request. Please try again.',
        },
      ]);
    } finally {
      setLoading(false);
    }
  }, [input, loading, location.pathname]);

  // Handle Enter key in input
  const handleKeyDown = useCallback(
    (e) => {
      if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        sendMessage();
      }
    },
    [sendMessage]
  );

  // Navigate from a tip action
  const handleTipAction = useCallback(
    (action) => {
      if (action?.navigate) {
        navigate(action.navigate);
        setOpen(false);
      }
    },
    [navigate]
  );

  // Do not render if disabled or on investigation pages (Riggs is embedded there)
  if (!clippy?.enabled || isInvestigationPage) {
    return null;
  }

  // Collapsed state: floating button
  if (!open) {
    return (
      <div className={styles.container}>
        <button
          className={styles.trigger}
          onClick={() => setOpen(true)}
          aria-label="Open Riggs assistant"
          title="Ask Riggs"
        >
          <MessageCircle className={styles.triggerIcon} />
          {tips.length > 0 && (
            <span className={styles.badge}>{tips.length}</span>
          )}
        </button>
      </div>
    );
  }

  // Expanded state: chat panel
  return (
    <div className={styles.container}>
      <div className={styles.panel}>
        {/* Header */}
        <div className={styles.header}>
          <div className={styles.headerLeft}>
            <RiggsAvatar size={24} />
            <div>
              <div className={styles.headerTitle}>Riggs</div>
              <div className={styles.headerSubtitle}>AI Assistant</div>
            </div>
          </div>
          <button
            className={styles.closeBtn}
            onClick={() => setOpen(false)}
            aria-label="Close Riggs assistant"
          >
            <X className={styles.closeBtnIcon} />
          </button>
        </div>

        {/* Messages Area */}
        <div className={styles.messages}>
          {/* Contextual Tips */}
          {tips.length > 0 && (
            <div className={styles.tipsSection}>
              <div className={styles.tipsLabel}>Tips for this page</div>
              {tips.map((tip) => {
                const sevColor = tip._live
                  ? ({ critical: '#ef4444', high: '#f97316', medium: '#eab308', info: '#14b8a6' })[tip._severity] || '#14b8a6'
                  : null;
                return (
                  <div
                    key={tip.id}
                    className={styles.tip}
                    style={sevColor ? { borderLeft: `3px solid ${sevColor}`, paddingLeft: '0.55rem' } : undefined}
                  >
                    <span className={styles.tipText}>
                      {tip.text}
                      {tip.action?.navigate && (
                        <>
                          {' '}
                          <span
                            className={styles.tipAction}
                            onClick={() => handleTipAction(tip.action)}
                            role="button"
                            tabIndex={0}
                            onKeyDown={(e) => {
                              if (e.key === 'Enter') handleTipAction(tip.action);
                            }}
                          >
                            {tip.action.label || 'Go there'}
                          </span>
                        </>
                      )}
                    </span>
                    <button
                      className={styles.tipDismiss}
                      onClick={() => dismissTip(tip.id)}
                      aria-label="Dismiss tip"
                      title="Dismiss"
                    >
                      <X className={styles.tipDismissIcon} />
                    </button>
                  </div>
                );
              })}
            </div>
          )}

          {/* Chat Messages */}
          {messages.length === 0 && tips.length === 0 && (
            <div className={styles.emptyState}>
              <RiggsAvatar size={48} mood="idea" />
              <div className={styles.emptyStateTitle}>How can I help?</div>
              <div>
                Ask me about navigating the platform, understanding alerts,
                building playbooks, or anything else.
              </div>
            </div>
          )}

          {messages.map((msg, i) => (
            <div
              key={i}
              className={`${styles.message} ${
                msg.role === 'user' ? styles.messageUser : styles.messageAssistant
              }`}
            >
              <div className={styles.messageRole}>
                {msg.role === 'user' ? 'You' : 'Riggs'}
              </div>
              <div className={styles.messageBubble}>{msg.content}</div>
            </div>
          ))}

          {/* Loading indicator */}
          {loading && (
            <div className={styles.loading}>
              <span className={styles.loadingDot} />
              <span className={styles.loadingDot} />
              <span className={styles.loadingDot} />
            </div>
          )}

          <div ref={messagesEndRef} />
        </div>

        {/* Input Area */}
        <div className={styles.inputArea}>
          <input
            ref={inputRef}
            className={styles.input}
            type="text"
            placeholder="Ask Riggs..."
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={handleKeyDown}
            disabled={loading}
            maxLength={2000}
          />
          <button
            className={styles.sendBtn}
            onClick={sendMessage}
            disabled={!input.trim() || loading}
            aria-label="Send message"
            title="Send"
          >
            <Send className={styles.sendIcon} />
          </button>
        </div>
      </div>
    </div>
  );
}
