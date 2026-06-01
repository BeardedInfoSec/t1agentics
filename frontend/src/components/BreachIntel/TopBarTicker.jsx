/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

/**
 * TopBarTicker
 *
 * Compact "Latest RSS" ticker that lives inside the topbar between the
 * global search input and the action buttons. Shows one breach-intel
 * headline at a time: fade in → hold ~6s → fade out → next item.
 *
 * Sources from `/api/v1/breach-intel?severity=critical,high` (the same
 * platform feed as the old BreachTicker, which we're replacing).
 */

import React, { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';

const SEVERITY_COLOR = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#3b82f6',
  info: '#6b7280',
};

const TYPE_LABEL = {
  data_breach: 'BREACH',
  ransomware: 'RANSOMWARE',
  vulnerability: 'VULN',
  apt_campaign: 'APT',
  supply_chain: 'SUPPLY CHAIN',
  ddos: 'DDOS',
  insider_threat: 'INSIDER',
  government_alert: 'ADVISORY',
  other: 'ALERT',
};

// Cadence — slow enough that the ticker fades into the background
// rather than feeling like alerts are streaming in. 25s per item with
// a long fade means the topbar mostly looks static; the rotation is
// peripheral, not foregrounded.
const HOLD_MS = 25000;
const FADE_MS = 700;
const REFRESH_MS = 10 * 60_000; // re-poll the feed every 10 min

export default function TopBarTicker() {
  const navigate = useNavigate();
  const [items, setItems] = useState([]);
  const [idx, setIdx] = useState(0);
  const [opacity, setOpacity] = useState(0);

  // Click handler — prefer the article's source URL so the user lands on
  // the actual headline. Falls back to the in-app breach-intel center if
  // the row has no source_url (rare; depends on the RSS source).
  const handleClick = (item) => {
    const externalUrl = item?.source_url || item?.url;
    if (externalUrl && /^https?:\/\//i.test(externalUrl)) {
      window.open(externalUrl, '_blank', 'noopener,noreferrer');
    } else {
      navigate('/breach-intel');
    }
  };

  // Fetch the feed (and re-fetch periodically). Same endpoint that powered
  // the legacy BreachTicker — now actually returning rows since the
  // severity filter was fixed server-side.
  useEffect(() => {
    let cancelled = false;
    const fetchItems = async () => {
      try {
        // Only pull breach intel from the last 7 days — without this the
        // ticker scrolls through the entire historical archive (1600+ rows
        // for crit/high), which the user perceives as spam. 7 days keeps
        // the rotation tight and the headlines actually fresh.
        const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString();
        const params = new URLSearchParams({
          limit: '15',
          severity: 'critical,high',
          date_from: sevenDaysAgo,
        });
        const res = await fetch(`/api/v1/breach-intel?${params.toString()}`, {
          credentials: 'include',
        });
        if (!res.ok) return;
        const data = await res.json();
        if (!cancelled) {
          setItems(Array.isArray(data.items) ? data.items : []);
        }
      } catch {
        /* silent — ticker just stays empty */
      }
    };
    fetchItems();
    const interval = setInterval(fetchItems, REFRESH_MS);
    return () => { cancelled = true; clearInterval(interval); };
  }, []);

  // Drive the fade cycle. Each loop: fade in → hold → fade out → advance.
  // Stable across item-list changes — idx wraps via modulo.
  useEffect(() => {
    if (items.length === 0) {
      setOpacity(0);
      return undefined;
    }
    let stopped = false;
    setOpacity(0);
    // Fade in
    const tIn = setTimeout(() => { if (!stopped) setOpacity(1); }, 30);
    // Hold then fade out
    const tHold = setTimeout(() => { if (!stopped) setOpacity(0); }, HOLD_MS + FADE_MS);
    // Advance after fade-out completes
    const tNext = setTimeout(() => {
      if (!stopped) setIdx((i) => (i + 1) % items.length);
    }, HOLD_MS + FADE_MS * 2);
    return () => {
      stopped = true;
      clearTimeout(tIn);
      clearTimeout(tHold);
      clearTimeout(tNext);
    };
  }, [idx, items.length]);

  const item = useMemo(() => items[idx % Math.max(items.length, 1)], [items, idx]);

  if (!item) return null;

  const sevColor = SEVERITY_COLOR[(item.severity || '').toLowerCase()] || SEVERITY_COLOR.info;
  const typeLabel = TYPE_LABEL[item.incident_type] || 'ALERT';

  return (
    <div
      role="button"
      tabIndex={0}
      onClick={() => handleClick(item)}
      onKeyDown={(e) => (e.key === 'Enter' || e.key === ' ') && handleClick(item)}
      title={item.source_url || item.url
        ? `Open article: ${item.title}`
        : 'Open breach intel center'}
      style={{
        // Foregrounded pill — full opacity, faint severity-tinted background,
        // wider width so headlines actually finish reading. Still bounded so
        // the topbar doesn't reflow, but reads as an active feed item not
        // ambient noise.
        display: 'flex',
        alignItems: 'center',
        gap: '10px',
        flex: '0 0 auto',
        minWidth: 0,
        width: 'min(560px, 38vw)',
        height: 30,
        padding: '0 14px',
        borderRadius: 999,
        border: `1px solid ${sevColor}33`,
        background: `linear-gradient(90deg, ${sevColor}22 0%, ${sevColor}0d 100%)`,
        cursor: 'pointer',
        opacity,
        transition: `opacity ${FADE_MS}ms ease-in-out`,
        userSelect: 'none',
        overflow: 'hidden',
      }}
    >
      <span
        aria-hidden="true"
        style={{
          width: 8,
          height: 8,
          borderRadius: '50%',
          background: sevColor,
          flexShrink: 0,
          boxShadow: `0 0 6px ${sevColor}99`,
        }}
      />
      <span
        style={{
          fontSize: '0.62rem',
          fontWeight: 700,
          letterSpacing: '0.4px',
          color: sevColor,
          textTransform: 'uppercase',
          flexShrink: 0,
        }}
      >
        {typeLabel}
      </span>
      <span
        style={{
          fontSize: '0.78rem',
          color: 'var(--text-primary, #e6edf3)',
          whiteSpace: 'nowrap',
          overflow: 'hidden',
          textOverflow: 'ellipsis',
          flex: 1,
          minWidth: 0,
          fontWeight: 500,
        }}
      >
        {item.title}
      </span>
    </div>
  );
}
