/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

/**
 * Design Tokens
 *
 * Single source of truth for all design values.
 * These map 1:1 to CSS custom properties in App.css (--text-*, --space-*, etc.)
 * Use CSS variables in stylesheets; use these JS tokens only when
 * you need values in JavaScript (e.g., chart libraries, canvas).
 */

export const spacing = {
  '2xs': '0.125rem',
  xs: '0.25rem',
  sm: '0.5rem',
  md: '0.75rem',
  lg: '1rem',
  xl: '1.5rem',
  '2xl': '2rem',
  '3xl': '3rem',
};

export const fontSizes = {
  xs: '0.75rem',      // --text-xs   (labels, captions) ~12px
  sm: '0.8125rem',    // --text-sm   (secondary text, table cells) ~13px
  base: '0.9375rem',  // --text-base (body, default) ~15px
  lg: '1.0625rem',    // --text-lg   (subheadings) ~17px
  xl: '1.25rem',      // --text-xl   (section headings)
  '2xl': '1.5rem',    // --text-2xl  (page titles)
  '3xl': '2rem',      // --text-3xl  (hero text)
};

export const fontWeights = {
  regular: 400,
  medium: 500,
  semibold: 600,
  bold: 700,
};

export const radii = {
  sm: '4px',    // --radius-sm
  md: '8px',    // --radius-md
  lg: '12px',   // --radius-lg
  xl: '16px',   // --radius-xl
  '2xl': '24px', // --radius-2xl
  full: '9999px', // --radius-full
};

export const shadows = {
  sm: '0 1px 2px rgba(0, 0, 0, 0.3)',
  md: '0 4px 6px rgba(0, 0, 0, 0.4)',
  lg: '0 10px 15px rgba(0, 0, 0, 0.5)',
  xl: '0 20px 25px rgba(0, 0, 0, 0.6)',
  glow: '0 0 20px rgba(60, 179, 113, 0.3)',
  glowLg: '0 0 40px rgba(60, 179, 113, 0.4)',
};

export const zIndex = {
  dropdown: 100,
  sticky: 200,
  overlay: 300,
  modal: 400,
  toast: 500,
  tooltip: 600,
};

export const transitions = {
  fast: '150ms ease',
  base: '200ms ease',
  slow: '300ms ease',
  bounce: '300ms cubic-bezier(0.68, -0.55, 0.265, 1.55)',
};

export const colors = {
  bg: {
    primary: '#080a0f',
    secondary: '#0d1117',
    tertiary: '#151b23',
    elevated: '#1a2332',
    hover: '#1c2530',
    active: '#243142',
  },
  text: {
    primary: '#f0f6fc',
    secondary: '#8b949e',
    muted: '#7d8590',
    disabled: '#545d68',
  },
  brand: {
    emerald: '#3CB371',
    emeraldLight: '#4fd1a4',
    emeraldDark: '#2e8b57',
  },
  status: {
    success: '#3CB371',
    warning: '#f59e0b',
    danger: '#ef4444',
    info: '#3b82f6',
  },
  severity: {
    low: '#22c55e',
    medium: '#eab308',
    high: '#f97316',
    critical: '#ef4444',
  },
  border: {
    default: 'rgba(48, 54, 61, 0.8)',
    subtle: 'rgba(60, 179, 113, 0.1)',
    accent: 'rgba(60, 179, 113, 0.25)',
    hover: 'rgba(60, 179, 113, 0.4)',
  },
};
