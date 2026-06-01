/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

import { spacing, fontSizes, fontWeights, radii, shadows, zIndex, transitions, colors } from './tokens';

export const darkTheme = {
  name: 'dark',
  spacing,
  fontSizes,
  fontWeights,
  radii,
  shadows,
  zIndex,
  transitions,
  colors,
};

export const lightTheme = {
  name: 'light',
  spacing,
  fontSizes,
  fontWeights,
  radii,
  shadows: {
    ...shadows,
    sm: '0 1px 2px rgba(0, 0, 0, 0.04), 0 1px 3px rgba(0, 0, 0, 0.06)',
    md: '0 2px 4px rgba(0, 0, 0, 0.04), 0 4px 8px rgba(0, 0, 0, 0.06)',
    lg: '0 4px 8px rgba(0, 0, 0, 0.04), 0 8px 16px rgba(0, 0, 0, 0.08)',
    xl: '0 8px 16px rgba(0, 0, 0, 0.06), 0 16px 32px rgba(0, 0, 0, 0.1)',
  },
  zIndex,
  transitions,
  colors: {
    ...colors,
    bg: {
      primary: '#f8fafb',
      secondary: '#ffffff',
      tertiary: '#f1f4f7',
      elevated: '#ffffff',
      hover: '#eef2f6',
      active: '#e4eaf0',
    },
    text: {
      primary: '#1a2332',
      secondary: '#4a5568',
      muted: '#718096',
      disabled: '#a0aec0',
    },
    brand: {
      emerald: '#2e8b57',
      emeraldLight: '#3cb371',
      emeraldDark: '#1e6b47',
    },
    status: {
      success: '#059669',
      warning: '#d97706',
      danger: '#dc2626',
      info: '#2563eb',
    },
    border: {
      default: '#e2e8f0',
      subtle: 'rgba(46, 139, 87, 0.1)',
      accent: 'rgba(46, 139, 87, 0.25)',
      hover: 'rgba(46, 139, 87, 0.4)',
    },
  },
};

export const theme = darkTheme;
