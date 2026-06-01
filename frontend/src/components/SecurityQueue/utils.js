/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

/**
 * SecurityQueue Utility Functions
 *
 * Formatting helpers for dates, SLA time remaining, and status badge mapping.
 * Used by SecurityQueueTable and QueueRow components.
 */

/**
 * Format an ISO date string for display in queue table cells.
 * Returns relative time for recent dates ("5m ago", "2h ago", "3d ago")
 * and absolute date for older ones (e.g., "Jan 15, 2026").
 *
 * @param {string} isoString - ISO 8601 date string
 * @returns {string} Human-readable date string
 */
export function formatDate(isoString) {
  if (!isoString) return '-';

  const date = new Date(isoString);
  if (isNaN(date.getTime())) return '-';

  const now = new Date();
  const diffMs = now - date;

  // Future dates (clock skew)
  if (diffMs < 0) return 'just now';

  const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
                  'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
  const month = months[date.getMonth()];
  const day = date.getDate();
  const year = date.getFullYear();
  const currentYear = now.getFullYear();

  // Format time as h:mm AM/PM
  let hours = date.getHours();
  const minutes = date.getMinutes().toString().padStart(2, '0');
  const ampm = hours >= 12 ? 'PM' : 'AM';
  hours = hours % 12 || 12;
  const time = `${hours}:${minutes} ${ampm}`;

  // Today — just show time
  if (date.toDateString() === now.toDateString()) {
    return time;
  }

  // Yesterday
  const yesterday = new Date(now);
  yesterday.setDate(yesterday.getDate() - 1);
  if (date.toDateString() === yesterday.toDateString()) {
    return `Yesterday ${time}`;
  }

  // Same year
  if (year === currentYear) {
    return `${month} ${day}, ${time}`;
  }

  // Different year
  return `${month} ${day}, ${year} ${time}`;
}

/**
 * Format remaining SLA time in minutes to a human-readable string.
 * Returns compact strings like "45m", "2h 30m", "1d 4h".
 *
 * @param {number} minutes - Remaining time in minutes
 * @returns {string} Formatted time string
 */
export function formatTimeRemaining(minutes) {
  if (minutes == null || isNaN(minutes)) return '-';

  // Negative means breached
  if (minutes <= 0) return '0m';

  const totalMinutes = Math.floor(minutes);
  const days = Math.floor(totalMinutes / (60 * 24));
  const hours = Math.floor((totalMinutes % (60 * 24)) / 60);
  const mins = totalMinutes % 60;

  if (days > 0) {
    if (hours > 0) return `${days}d ${hours}h`;
    return `${days}d`;
  }

  if (hours > 0) {
    if (mins > 0) return `${hours}h ${mins}m`;
    return `${hours}h`;
  }

  return `${mins}m`;
}

/**
 * Status-to-badge mapping for alerts.
 * @type {Object<string, {variant: string, text: string, pulse: boolean}>}
 */
const ALERT_STATUS_MAP = {
  open:          { variant: 'warning', text: 'Open',          pulse: false },
  investigating: { variant: 'info',    text: 'Investigating', pulse: true  },
  in_progress:   { variant: 'info',    text: 'In Progress',   pulse: false },
  needs_review:  { variant: 'danger',  text: 'Needs Review',  pulse: false },
  resolved:      { variant: 'success', text: 'Resolved',      pulse: false },
  closed:        { variant: 'default', text: 'Closed',        pulse: false },
};

/**
 * Status-to-badge mapping for investigations.
 * @type {Object<string, {variant: string, text: string, pulse: boolean}>}
 */
const INVESTIGATION_STATUS_MAP = {
  open:          { variant: 'warning', text: 'Open',          pulse: false },
  investigating: { variant: 'info',    text: 'Investigating', pulse: true  },
  in_progress:   { variant: 'info',    text: 'In Progress',   pulse: false },
  needs_review:  { variant: 'danger',  text: 'Needs Review',  pulse: false },
  resolved:      { variant: 'success', text: 'Resolved',      pulse: false },
  closed:        { variant: 'default', text: 'Closed',        pulse: false },
};

/**
 * Get badge properties for a security queue item based on its type and status.
 * Returns an object with variant, text, and pulse for rendering a Badge component.
 *
 * @param {import('./types').SecurityQueueItem} item - Security queue item
 * @returns {{ variant: string, text: string, pulse: boolean }}
 */
export function getStatusBadge(item) {
  if (!item || !item.status) {
    return { variant: 'default', text: 'Unknown', pulse: false };
  }

  const statusMap = item.item_type === 'investigation'
    ? INVESTIGATION_STATUS_MAP
    : ALERT_STATUS_MAP;

  const mapped = statusMap[item.status];
  if (mapped) return mapped;

  // Fallback for unrecognized statuses - display the raw status
  return {
    variant: 'default',
    text: item.status.replace(/_/g, ' '),
    pulse: false,
  };
}
