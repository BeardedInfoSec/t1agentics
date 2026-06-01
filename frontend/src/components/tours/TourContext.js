/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

import React, { createContext, useContext, useState, useCallback } from 'react';
import { usePreferences } from '../../hooks/usePreferences';

const TourContext = createContext(null);

/**
 * TourProvider - Manages feature tour state across the application.
 *
 * Provides methods to start, end, complete, and dismiss tours.
 * Persists completed/dismissed tour IDs via user preferences so
 * tours are not repeated after a user finishes or skips them.
 *
 * Only one tour may be active at a time. Starting a new tour while
 * one is already active will replace the current tour.
 */
export function TourProvider({ children }) {
  const [activeTour, setActiveTour] = useState(null);
  const { preferences, savePreferences } = usePreferences();

  const tourPrefs = preferences.tours || { completed: [], dismissed: [] };

  /**
   * Start a tour by its ID. Replaces any currently active tour.
   * Does nothing if the tour has already been completed or dismissed.
   */
  const startTour = useCallback((tourId) => {
    if (!tourId) return;
    const completed = tourPrefs.completed || [];
    const dismissed = tourPrefs.dismissed || [];
    if (completed.includes(tourId) || dismissed.includes(tourId)) return;
    setActiveTour(tourId);
  }, [tourPrefs]);

  /**
   * End the active tour without marking it completed or dismissed.
   * The tour can be started again later.
   */
  const endTour = useCallback(() => {
    setActiveTour(null);
  }, []);

  /**
   * Mark a tour as completed and end it.
   * The tour will not auto-start again.
   */
  const completeTour = useCallback((tourId) => {
    const completed = tourPrefs.completed || [];
    if (!completed.includes(tourId)) {
      const newTours = {
        ...tourPrefs,
        completed: [...completed, tourId],
      };
      savePreferences({ ...preferences, tours: newTours });
    }
    setActiveTour(null);
  }, [tourPrefs, preferences, savePreferences]);

  /**
   * Mark a tour as dismissed (skipped) and end it.
   * The tour will not auto-start again.
   */
  const dismissTour = useCallback((tourId) => {
    const dismissed = tourPrefs.dismissed || [];
    if (!dismissed.includes(tourId)) {
      const newTours = {
        ...tourPrefs,
        dismissed: [...dismissed, tourId],
      };
      savePreferences({ ...preferences, tours: newTours });
    }
    setActiveTour(null);
  }, [tourPrefs, preferences, savePreferences]);

  /**
   * Check whether a tour has been completed.
   */
  const isTourCompleted = useCallback((tourId) => {
    const completed = tourPrefs.completed || [];
    return completed.includes(tourId);
  }, [tourPrefs]);

  /**
   * Check whether a tour has been dismissed.
   */
  const isTourDismissed = useCallback((tourId) => {
    const dismissed = tourPrefs.dismissed || [];
    return dismissed.includes(tourId);
  }, [tourPrefs]);

  const value = {
    activeTour,
    startTour,
    endTour,
    completeTour,
    dismissTour,
    isTourCompleted,
    isTourDismissed,
  };

  return (
    <TourContext.Provider value={value}>
      {children}
    </TourContext.Provider>
  );
}

/**
 * Hook to access tour context.
 * Must be used within a TourProvider.
 */
export function useTour() {
  const context = useContext(TourContext);
  if (!context) {
    throw new Error('useTour must be used within a TourProvider');
  }
  return context;
}

export default TourContext;
