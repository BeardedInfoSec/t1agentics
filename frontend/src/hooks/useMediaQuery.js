/**
 * Copyright (c) 2025-2026 T1 Agentics LLC. SPDX-License-Identifier: Apache-2.0
 *
 * useMediaQuery - React hook for responsive media queries.
 */

import { useState, useEffect } from 'react';

/**
 * Custom hook that listens to a CSS media query and returns whether it matches.
 *
 * @param {string} query - A valid CSS media query string, e.g. '(max-width: 768px)'
 * @returns {boolean} True if the media query currently matches, false otherwise.
 */
export function useMediaQuery(query) {
  const [matches, setMatches] = useState(() => {
    if (typeof window === 'undefined') {
      return false;
    }
    return window.matchMedia(query).matches;
  });

  useEffect(() => {
    if (typeof window === 'undefined') {
      return;
    }

    const mediaQueryList = window.matchMedia(query);

    // Set initial value in case it changed between render and effect
    setMatches(mediaQueryList.matches);

    const handleChange = (event) => {
      setMatches(event.matches);
    };

    // Modern browsers support addEventListener; fall back to addListener for older ones
    if (mediaQueryList.addEventListener) {
      mediaQueryList.addEventListener('change', handleChange);
    } else if (mediaQueryList.addListener) {
      mediaQueryList.addListener(handleChange);
    }

    return () => {
      if (mediaQueryList.removeEventListener) {
        mediaQueryList.removeEventListener('change', handleChange);
      } else if (mediaQueryList.removeListener) {
        mediaQueryList.removeListener(handleChange);
      }
    };
  }, [query]);

  return matches;
}
