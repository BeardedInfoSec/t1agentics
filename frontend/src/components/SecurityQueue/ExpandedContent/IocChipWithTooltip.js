/**
 * Copyright (c) 2025-2026 T1 Agentics LLC. SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useRef, useCallback } from 'react';
import { createPortal } from 'react-dom';
import styles from '../SecurityQueue.module.css';

export default function IocChipWithTooltip({ ioc, chipClass, typeConfig, enrichmentDetails = [], loading = false }) {
  const [show, setShow] = useState(false);
  const [copied, setCopied] = useState(false);
  const [pos, setPos] = useState({ top: 0, left: 0 });
  const wrapperRef = useRef(null);

  const onEnter = useCallback(() => {
    if (!wrapperRef.current) return;
    const rect = wrapperRef.current.getBoundingClientRect();
    const tooltipWidth = 500;
    let left = rect.left + rect.width / 2;
    // Keep tooltip from overflowing the right edge
    if (left + tooltipWidth / 2 > window.innerWidth - 16) {
      left = window.innerWidth - tooltipWidth / 2 - 16;
    }
    // Keep from overflowing left edge
    if (left - tooltipWidth / 2 < 16) {
      left = tooltipWidth / 2 + 16;
    }
    setPos({
      top: rect.top - 8,
      left,
    });
    setShow(true);
  }, []);

  const onLeave = useCallback(() => {
    setShow(false);
    setCopied(false);
  }, []);

  const handleClick = useCallback(() => {
    if (!ioc.value) return;
    navigator.clipboard.writeText(ioc.value).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  }, [ioc.value]);

  const fullValue = ioc.value;

  return (
    <div
      ref={wrapperRef}
      className={styles.iocChipWrapper}
      onMouseEnter={onEnter}
      onMouseLeave={onLeave}
      onClick={handleClick}
      style={{ cursor: 'pointer' }}
    >
      <div className={chipClass}>
        <span className={styles.iocIcon} style={{ color: typeConfig.color }}>
          {typeConfig.icon}
        </span>
        <span className={styles.iocChipValue}>{fullValue}</span>
      </div>
      {show && createPortal(
        <div
          style={{
            position: 'fixed',
            top: pos.top,
            left: pos.left,
            transform: 'translate(-50%, -100%)',
            minWidth: 220,
            maxWidth: 500,
            padding: '0.75rem',
            background: 'var(--bg-primary)',
            border: '1px solid var(--border-color)',
            borderRadius: 6,
            boxShadow: '0 4px 16px rgba(0, 0, 0, 0.5)',
            zIndex: 10000,
            fontSize: '0.7rem',
            pointerEvents: 'none',
          }}
        >
          {copied ? (
            <div style={{ textAlign: 'center', padding: '0.25rem 0', color: 'var(--success)', fontWeight: 600 }}>
              Copied to clipboard
            </div>
          ) : (
            <>
              <div className={styles.iocTooltipRow}>
                <span className={styles.iocTooltipLabel}>Type</span>
                <span className={styles.iocTooltipValue}>{(ioc.type || 'unknown').toUpperCase()}</span>
              </div>
              <div className={styles.iocTooltipRow}>
                <span className={styles.iocTooltipLabel}>Value</span>
                <span className={styles.iocTooltipValue} style={{ fontFamily: 'monospace', fontSize: '0.7rem', wordBreak: 'break-all' }}>
                  {fullValue}
                </span>
              </div>
              {enrichmentDetails.map((detail, dIdx) => (
                <div key={dIdx} className={styles.iocTooltipRow}>
                  <span className={styles.iocTooltipLabel}>{detail.label}</span>
                  <span className={styles.iocTooltipValue}>{detail.value}</span>
                </div>
              ))}
              {enrichmentDetails.length === 0 && !loading && (
                <div className={styles.iocTooltipRow}>
                  <span className={styles.iocTooltipValue} style={{ color: 'var(--text-muted)', fontStyle: 'italic' }}>
                    No enrichment data available
                  </span>
                </div>
              )}
              {loading && enrichmentDetails.length === 0 && (
                <div className={styles.iocTooltipRow}>
                  <span className={styles.iocTooltipValue} style={{ color: 'var(--text-muted)', fontStyle: 'italic' }}>
                    Loading enrichment...
                  </span>
                </div>
              )}
              <div style={{ textAlign: 'center', marginTop: '0.35rem', color: 'var(--text-muted)', fontSize: '0.6rem' }}>
                Click to copy
              </div>
            </>
          )}
        </div>,
        document.body
      )}
    </div>
  );
}
