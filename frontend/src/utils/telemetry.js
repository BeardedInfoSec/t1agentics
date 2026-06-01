/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

/**
 * UX Telemetry Tracker
 *
 * Lightweight client-side telemetry for tracking feature usage,
 * investigation decision times, and analyst workflows.
 * Events are batched and sent to the backend every 30s or on page unload.
 */

import { getAuthHeaders, API_BASE_URL } from './api';

const BATCH_INTERVAL = 30000; // 30 seconds
const MAX_BATCH_SIZE = 50;
const MAX_QUEUE_SIZE = 200;

class TelemetryTracker {
  constructor() {
    this.queue = [];
    this.sessionId = typeof crypto !== 'undefined' && crypto.randomUUID
      ? crypto.randomUUID()
      : `${Date.now()}-${Math.random().toString(36).slice(2)}`;
    this.flushTimer = null;
    this._started = false;
  }

  /**
   * Start the tracker (call once at app init).
   * Deferred start to avoid issues during SSR or tests.
   */
  start() {
    if (this._started) return;
    this._started = true;
    this.flushTimer = setInterval(() => this.flush(), BATCH_INTERVAL);
    if (typeof window !== 'undefined') {
      window.addEventListener('beforeunload', () => this.flush());
      window.addEventListener('visibilitychange', () => {
        if (document.visibilityState === 'hidden') this.flush();
      });
    }
  }

  /**
   * Track a UX event.
   * @param {string} eventType - Category (e.g. 'queue', 'investigation', 'execution', 'ui')
   * @param {string} eventName - Specific event (e.g. 'queue.row_click', 'investigation.verdict_set')
   * @param {Object} properties - Event-specific data
   */
  track(eventType, eventName, properties = {}) {
    if (!this._started) this.start();

    this.queue.push({
      event_type: eventType,
      event_name: eventName,
      properties,
      page: typeof window !== 'undefined' ? window.location.pathname : '',
      session_id: this.sessionId,
      timestamp: new Date().toISOString(),
    });

    if (this.queue.length >= MAX_BATCH_SIZE) {
      this.flush();
    }
  }

  /**
   * Send queued events to the backend.
   */
  async flush() {
    if (this.queue.length === 0) return;

    const batch = this.queue.splice(0, MAX_BATCH_SIZE);

    try {
      const url = `${API_BASE_URL}/api/v1/telemetry/events`;
      // Use sendBeacon for page unload, fetch otherwise
      if (typeof navigator !== 'undefined' && navigator.sendBeacon && document.visibilityState === 'hidden') {
        const blob = new Blob([JSON.stringify(batch)], { type: 'application/json' });
        navigator.sendBeacon(url, blob);
      } else {
        await fetch(url, {
          method: 'POST',
          headers: { ...getAuthHeaders(), 'Content-Type': 'application/json' },
          credentials: 'include',
          body: JSON.stringify(batch),
        });
      }
    } catch {
      // Re-queue on failure (drop if queue grows too large to avoid memory leak)
      if (this.queue.length < MAX_QUEUE_SIZE) {
        this.queue.unshift(...batch);
      }
    }
  }

  /**
   * Stop the tracker and flush remaining events.
   */
  destroy() {
    if (this.flushTimer) {
      clearInterval(this.flushTimer);
      this.flushTimer = null;
    }
    this.flush();
    this._started = false;
  }
}

export const telemetry = new TelemetryTracker();
