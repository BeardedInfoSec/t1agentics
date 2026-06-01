/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

/**
 * Density Context and Hook
 *
 * Provides a global density preference that affects spacing
 * and sizing across all components.
 *
 * Modes:
 * - compact: Tight spacing, smaller elements (data-dense views)
 * - comfortable: Default balanced spacing
 * - spacious: More breathing room, larger touch targets
 */

import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';

/**
 * @typedef {'compact'|'comfortable'|'spacious'} DensityMode
 */

/**
 * Density configuration values
 */
export const DENSITY_CONFIG = {
  compact: {
    spacing: {
      xs: '0.25rem',
      sm: '0.375rem',
      md: '0.5rem',
      lg: '0.75rem',
      xl: '1rem'
    },
    fontSize: {
      xs: '0.625rem',
      sm: '0.6875rem',
      md: '0.75rem',
      lg: '0.8125rem',
      xl: '0.875rem'
    },
    rowHeight: '32px',
    cardPadding: '0.75rem',
    borderRadius: '6px'
  },
  comfortable: {
    spacing: {
      xs: '0.375rem',
      sm: '0.5rem',
      md: '0.75rem',
      lg: '1rem',
      xl: '1.5rem'
    },
    fontSize: {
      xs: '0.6875rem',
      sm: '0.75rem',
      md: '0.8125rem',
      lg: '0.875rem',
      xl: '1rem'
    },
    rowHeight: '44px',
    cardPadding: '1rem',
    borderRadius: '8px'
  },
  spacious: {
    spacing: {
      xs: '0.5rem',
      sm: '0.75rem',
      md: '1rem',
      lg: '1.5rem',
      xl: '2rem'
    },
    fontSize: {
      xs: '0.75rem',
      sm: '0.8125rem',
      md: '0.875rem',
      lg: '1rem',
      xl: '1.125rem'
    },
    rowHeight: '56px',
    cardPadding: '1.5rem',
    borderRadius: '10px'
  }
};

/**
 * Storage key for persisting preference
 */
const STORAGE_KEY = 'ui_density_preference';

/**
 * Density context value type
 * @typedef {Object} DensityContextValue
 * @property {DensityMode} density - Current density mode
 * @property {function(DensityMode): void} setDensity - Set density mode
 * @property {Object} config - Current density configuration
 * @property {function(): void} cycleNext - Cycle to next density mode
 */

/**
 * Create the density context
 */
const DensityContext = createContext(null);

/**
 * Get initial density from storage or default
 * @returns {DensityMode}
 */
function getInitialDensity() {
  if (typeof window === 'undefined') return 'comfortable';

  const stored = localStorage.getItem(STORAGE_KEY);
  if (stored && ['compact', 'comfortable', 'spacious'].includes(stored)) {
    return stored;
  }
  return 'comfortable';
}

/**
 * Apply density CSS variables to document
 * @param {DensityMode} density
 */
function applyDensityToDocument(density) {
  const config = DENSITY_CONFIG[density];

  document.documentElement.style.setProperty('--density-spacing-xs', config.spacing.xs);
  document.documentElement.style.setProperty('--density-spacing-sm', config.spacing.sm);
  document.documentElement.style.setProperty('--density-spacing-md', config.spacing.md);
  document.documentElement.style.setProperty('--density-spacing-lg', config.spacing.lg);
  document.documentElement.style.setProperty('--density-spacing-xl', config.spacing.xl);

  document.documentElement.style.setProperty('--density-font-xs', config.fontSize.xs);
  document.documentElement.style.setProperty('--density-font-sm', config.fontSize.sm);
  document.documentElement.style.setProperty('--density-font-md', config.fontSize.md);
  document.documentElement.style.setProperty('--density-font-lg', config.fontSize.lg);
  document.documentElement.style.setProperty('--density-font-xl', config.fontSize.xl);

  document.documentElement.style.setProperty('--density-row-height', config.rowHeight);
  document.documentElement.style.setProperty('--density-card-padding', config.cardPadding);
  document.documentElement.style.setProperty('--density-border-radius', config.borderRadius);

  document.documentElement.setAttribute('data-density', density);
}

/**
 * DensityProvider Component
 *
 * Wrap your app with this to enable density preferences.
 */
export function DensityProvider({ children, defaultDensity }) {
  const [density, setDensityState] = useState(() => defaultDensity || getInitialDensity());

  // Apply density on mount and changes
  useEffect(() => {
    applyDensityToDocument(density);
    localStorage.setItem(STORAGE_KEY, density);
  }, [density]);

  // Set density with validation
  const setDensity = useCallback((newDensity) => {
    if (['compact', 'comfortable', 'spacious'].includes(newDensity)) {
      setDensityState(newDensity);
    }
  }, []);

  // Cycle to next density mode
  const cycleNext = useCallback(() => {
    const modes = ['compact', 'comfortable', 'spacious'];
    const currentIndex = modes.indexOf(density);
    const nextIndex = (currentIndex + 1) % modes.length;
    setDensityState(modes[nextIndex]);
  }, [density]);

  const value = {
    density,
    setDensity,
    config: DENSITY_CONFIG[density],
    cycleNext
  };

  return (
    <DensityContext.Provider value={value}>
      {children}
    </DensityContext.Provider>
  );
}

/**
 * Hook to access density settings
 * @returns {DensityContextValue}
 */
export function useDensity() {
  const context = useContext(DensityContext);

  if (!context) {
    // Return default values if used outside provider
    return {
      density: 'comfortable',
      setDensity: () => {},
      config: DENSITY_CONFIG.comfortable,
      cycleNext: () => {}
    };
  }

  return context;
}

/**
 * Density Toggle Component
 *
 * A compact toggle button for switching density modes.
 */
export function DensityToggle({ className }) {
  const { density, setDensity } = useDensity();

  const modes = [
    { value: 'compact', label: 'Compact', icon: '▪' },
    { value: 'comfortable', label: 'Comfortable', icon: '▫' },
    { value: 'spacious', label: 'Spacious', icon: '□' }
  ];

  return (
    <div
      className={className}
      role="group"
      aria-label="Display density"
      style={{
        display: 'flex',
        gap: '2px',
        padding: '3px',
        background: 'rgba(148, 163, 184, 0.1)',
        borderRadius: '8px'
      }}
    >
      {modes.map(mode => (
        <button
          key={mode.value}
          onClick={() => setDensity(mode.value)}
          title={mode.label}
          aria-pressed={density === mode.value}
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            width: '28px',
            height: '28px',
            padding: 0,
            background: density === mode.value ? 'rgba(56, 189, 248, 0.15)' : 'transparent',
            border: 'none',
            borderRadius: '6px',
            color: density === mode.value ? '#38bdf8' : 'rgba(148, 163, 184, 0.7)',
            fontSize: mode.value === 'compact' ? '10px' : mode.value === 'comfortable' ? '12px' : '14px',
            cursor: 'pointer',
            transition: 'all 0.15s ease'
          }}
        >
          {mode.icon}
        </button>
      ))}
    </div>
  );
}

export default useDensity;
