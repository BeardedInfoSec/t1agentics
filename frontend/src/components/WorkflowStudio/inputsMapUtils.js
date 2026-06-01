/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

export function normalizeInputsEntries(value) {
  if (!value) return [];
  if (Array.isArray(value)) {
    return value.map((entry) => ({
      key: entry?.key || '',
      path: entry?.path || '',
    }));
  }

  const parsed = safeParseJson(value);
  if (parsed && typeof parsed === 'object') {
    return Object.entries(parsed).map(([key, path]) => ({
      key,
      path: path == null ? '' : String(path),
    }));
  }

  return [];
}

export function entriesToInputObject(entries) {
  if (!Array.isArray(entries)) {
    return {};
  }
  return entries.reduce((acc, entry) => {
    const key = (entry?.key || '').trim();
    if (!key) return acc;
    acc[key] = entry?.path ?? '';
    return acc;
  }, {});
}

function safeParseJson(value) {
  if (value == null) return null;
  if (typeof value === 'object') return value;
  if (typeof value !== 'string' || value.trim() === '') return null;
  try {
    return JSON.parse(value);
  } catch (err) {
    return null;
  }
}
