/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

import { useState, useEffect, useCallback, createContext, useContext } from 'react';
import { API_BASE_URL } from '../utils/api';

// Default preferences
const defaultPreferences = {
  theme: 'dark',
  sidebarCollapsed: false,
  alertsPerPage: 25,
  dashboardRefreshInterval: 30000, // 30 seconds
  showAlertPreview: true,
  dateFormat: 'absolute', // 'relative' or 'absolute'
  timezone: 'local', // 'local', 'UTC', or IANA timezone like 'America/New_York'
  alertColumns: ['severity', 'title', 'source', 'status', 'created_at'],
  investigationColumns: ['priority', 'title', 'status', 'owner', 'created_at'],
  notifications: {
    sound: false,
    desktop: false,
    criticalOnly: true
  },
  roi: {
    costPerHour: 120,
    humanActionMins: 12,
    automationActionMins: 2
  },
  onboarding: {
    completed: false,
    skipped: false,
    current_step: 0,
    steps_completed: [],
    user_role: null,
    goals: []
  },
  tours: {
    completed: [],
    dismissed: []
  },
  riggs_clippy: {
    enabled: true,
    minimized: false,
    dismissed_tips: []
  },
  v3_card_order: ['status', 'key_facts', 'iocs', 'notes', 'timeline', 'linked_alerts', 'mitre', 'raw_data'],
  v3_collapsed_cards: []
};

// Common timezone options
export const TIMEZONE_OPTIONS = [
  { value: 'local', label: 'Local Browser Time', offset: null },
  { value: 'UTC', label: 'UTC (Coordinated Universal Time)', offset: 0 },
  // Americas
  { value: 'America/New_York', label: 'Eastern Time (ET)', offset: -5 },
  { value: 'America/Chicago', label: 'Central Time (CT)', offset: -6 },
  { value: 'America/Denver', label: 'Mountain Time (MT)', offset: -7 },
  { value: 'America/Los_Angeles', label: 'Pacific Time (PT)', offset: -8 },
  { value: 'America/Anchorage', label: 'Alaska Time (AKT)', offset: -9 },
  { value: 'Pacific/Honolulu', label: 'Hawaii Time (HST)', offset: -10 },
  // Europe
  { value: 'Europe/London', label: 'London (GMT/BST)', offset: 0 },
  { value: 'Europe/Paris', label: 'Central European (CET)', offset: 1 },
  { value: 'Europe/Helsinki', label: 'Eastern European (EET)', offset: 2 },
  { value: 'Europe/Moscow', label: 'Moscow Time (MSK)', offset: 3 },
  // Asia/Pacific
  { value: 'Asia/Dubai', label: 'Gulf Time (GST)', offset: 4 },
  { value: 'Asia/Kolkata', label: 'India Standard (IST)', offset: 5.5 },
  { value: 'Asia/Singapore', label: 'Singapore Time (SGT)', offset: 8 },
  { value: 'Asia/Tokyo', label: 'Japan Time (JST)', offset: 9 },
  { value: 'Australia/Sydney', label: 'Australian Eastern (AEST)', offset: 10 },
  { value: 'Pacific/Auckland', label: 'New Zealand (NZST)', offset: 12 },
];

/**
 * Format a date/time string to the user's preferred timezone
 * @param {string|Date} dateInput - ISO date string or Date object
 * @param {string} timezone - Timezone preference ('local', 'UTC', or IANA timezone)
 * @param {object} options - Intl.DateTimeFormat options
 * @returns {string} Formatted date string
 */
export function formatInTimezone(dateInput, timezone = 'local', options = {}) {
  if (!dateInput) return 'N/A';

  try {
    const date = typeof dateInput === 'string' ? new Date(dateInput) : dateInput;

    if (isNaN(date.getTime())) return 'Invalid Date';

    const defaultOptions = {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: false,
      ...options
    };

    if (timezone === 'local') {
      return date.toLocaleString(undefined, defaultOptions);
    }

    return date.toLocaleString(undefined, {
      ...defaultOptions,
      timeZone: timezone
    });
  } catch (error) {
    return String(dateInput);
  }
}

/**
 * Format a date as relative time (e.g., "5 minutes ago") or absolute based on preference
 * @param {string|Date} dateInput - ISO date string or Date object
 * @param {string} dateFormat - 'relative' or 'absolute'
 * @param {string} timezone - Timezone preference
 * @returns {string} Formatted date string
 */
export function formatDateTime(dateInput, dateFormat = 'relative', timezone = 'local') {
  if (!dateInput) return 'N/A';

  try {
    const date = typeof dateInput === 'string' ? new Date(dateInput) : dateInput;

    if (isNaN(date.getTime())) return 'Invalid Date';

    if (dateFormat === 'relative') {
      const now = new Date();
      const diffMs = now - date;
      const diffSecs = Math.floor(diffMs / 1000);
      const diffMins = Math.floor(diffSecs / 60);
      const diffHours = Math.floor(diffMins / 60);
      const diffDays = Math.floor(diffHours / 24);

      if (diffSecs < 60) return 'Just now';
      if (diffMins < 60) return `${diffMins}m ago`;
      if (diffHours < 24) return `${diffHours}h ago`;
      if (diffDays < 7) return `${diffDays}d ago`;

      // Fall back to absolute for older dates
      return formatInTimezone(date, timezone, {
        year: 'numeric',
        month: 'short',
        day: 'numeric'
      });
    }

    // Absolute format
    return formatInTimezone(date, timezone);
  } catch (error) {
    return String(dateInput);
  }
}

/**
 * Get the current timezone abbreviation
 * @param {string} timezone - Timezone preference
 * @returns {string} Timezone abbreviation (e.g., "EST", "UTC")
 */
export function getTimezoneAbbr(timezone = 'local') {
  if (timezone === 'local') {
    const date = new Date();
    const tzString = date.toLocaleTimeString('en-US', { timeZoneName: 'short' });
    const match = tzString.match(/[A-Z]{2,5}$/);
    return match ? match[0] : 'Local';
  }

  if (timezone === 'UTC') return 'UTC';

  try {
    const date = new Date();
    const tzString = date.toLocaleTimeString('en-US', {
      timeZone: timezone,
      timeZoneName: 'short'
    });
    const match = tzString.match(/[A-Z]{2,5}$/);
    return match ? match[0] : timezone.split('/').pop();
  } catch {
    return timezone.split('/').pop();
  }
}

// Context for preferences
const PreferencesContext = createContext(null);

export function PreferencesProvider({ children }) {
  const [preferences, setPreferences] = useState(() => {
    // Initialize from localStorage for immediate use
    const cached = localStorage.getItem('userPreferences');
    if (cached) {
      try {
        return { ...defaultPreferences, ...JSON.parse(cached) };
      } catch {
        return defaultPreferences;
      }
    }
    return defaultPreferences;
  });
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);

  // Apply theme to document
  const applyTheme = useCallback((theme) => {
    const effectiveTheme = theme === 'system'
      ? (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light')
      : theme;
    document.documentElement.setAttribute('data-theme', effectiveTheme);
  }, []);

  // Apply theme whenever preferences change
  useEffect(() => {
    applyTheme(preferences.theme || 'dark');
  }, [preferences.theme, applyTheme]);

  // Listen for system theme changes when theme is set to 'system'
  useEffect(() => {
    if (preferences.theme !== 'system') return;

    const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
    const handleChange = () => applyTheme('system');

    mediaQuery.addEventListener('change', handleChange);
    return () => mediaQuery.removeEventListener('change', handleChange);
  }, [preferences.theme, applyTheme]);

  // Load preferences from server on mount
  // Try user-specific endpoint first, fall back to admin endpoint, then localStorage
  useEffect(() => {
    const loadPreferences = async () => {
      try {
        // Primary: user-specific preferences endpoint
        let response = await fetch(`${API_BASE_URL}/api/v1/users/me/preferences`, {
          credentials: 'include'
        });

        // Fallback: admin preferences endpoint (legacy)
        if (!response.ok) {
          response = await fetch(`${API_BASE_URL}/api/v1/admin/preferences`, {
            credentials: 'include'
          });
        }

        if (response.ok) {
          const data = await response.json();
          const prefsData = data.preferences || data;
          if (prefsData && typeof prefsData === 'object' && Object.keys(prefsData).length > 0) {
            const merged = { ...defaultPreferences, ...prefsData };
            setPreferences(merged);
            localStorage.setItem('userPreferences', JSON.stringify(merged));
          }
        }
      } catch (error) {
        // Falls back to localStorage (already loaded in initial state)
      } finally {
        setLoading(false);
      }
    };

    loadPreferences();
  }, []);

  // Save all preferences
  // Persists to localStorage immediately, then syncs to backend
  const savePreferences = useCallback(async (newPrefs) => {
    setSaving(true);

    // Update local state immediately
    setPreferences(newPrefs);
    localStorage.setItem('userPreferences', JSON.stringify(newPrefs));

    try {
      // Primary: user-specific preferences endpoint
      const response = await fetch(`${API_BASE_URL}/api/v1/users/me/preferences`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(newPrefs),
        credentials: 'include'
      });

      if (!response.ok) {
        // Fallback: legacy admin preferences endpoint
        const fallbackResponse = await fetch(`${API_BASE_URL}/api/v1/admin/preferences`, {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(newPrefs),
          credentials: 'include'
        });
        setSaving(false);
        return fallbackResponse.ok;
      }

      setSaving(false);
      return response.ok;
    } catch (error) {
      setSaving(false);
      return false;
    }
  }, []);

  // Update a single preference
  const updatePreference = useCallback(async (key, value) => {
    const newPrefs = { ...preferences, [key]: value };
    return savePreferences(newPrefs);
  }, [preferences, savePreferences]);

  // Update nested preference (e.g., notifications.sound)
  const updateNestedPreference = useCallback(async (parentKey, childKey, value) => {
    const newPrefs = {
      ...preferences,
      [parentKey]: {
        ...preferences[parentKey],
        [childKey]: value
      }
    };
    return savePreferences(newPrefs);
  }, [preferences, savePreferences]);

  // Shallow-merge partial updates into preferences
  const updatePreferences = useCallback(async (partial) => {
    const newPrefs = { ...preferences, ...partial };
    return savePreferences(newPrefs);
  }, [preferences, savePreferences]);

  // Reset to defaults
  const resetPreferences = useCallback(async () => {
    return savePreferences(defaultPreferences);
  }, [savePreferences]);

  const value = {
    preferences,
    loading,
    saving,
    savePreferences,
    updatePreference,
    updatePreferences,
    updateNestedPreference,
    resetPreferences,
    defaultPreferences
  };

  return (
    <PreferencesContext.Provider value={value}>
      {children}
    </PreferencesContext.Provider>
  );
}

// Hook to use preferences
export function usePreferences() {
  const context = useContext(PreferencesContext);
  if (!context) {
    throw new Error('usePreferences must be used within a PreferencesProvider');
  }
  return context;
}

export default usePreferences;
