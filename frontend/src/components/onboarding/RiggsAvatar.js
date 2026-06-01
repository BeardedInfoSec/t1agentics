/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

import React from 'react';

/**
 * RiggsAvatar - Reusable image avatar for the Riggs AI assistant.
 *
 * Renders the real Riggs PNG mascot from /public. Pass `mood` to switch
 * which expression is shown:
 *   - 'default' / undefined  → Riggs_secret_agent.png (calm baseline)
 *   - 'idea'                 → riggs_idea.png (for tips / suggestions)
 *   - 'investigating'        → riggs_investigating.png (analysis / triage)
 *   - 'error'                → riggs_error.png (failure / breach)
 *
 * The image is masked into a circle with a subtle green ring so it
 * reads as the Riggs persona consistently across onboarding, Clippy,
 * feature tours, etc.
 *
 * @param {number} size       Width/height in pixels (default 48)
 * @param {string} mood       Which expression to render
 * @param {string} className  Optional CSS class
 */
const MOOD_TO_SRC = {
  default:        '/Riggs_secret_agent.png',
  idea:           '/riggs_idea.png',
  investigating:  '/riggs_investigating.png',
  error:          '/riggs_error.png',
};

export default function RiggsAvatar({ size = 48, mood = 'default', className }) {
  const src = MOOD_TO_SRC[mood] || MOOD_TO_SRC.default;
  return (
    <span
      className={className}
      aria-label="Riggs AI Assistant"
      role="img"
      style={{
        display: 'inline-block',
        width: size,
        height: size,
        borderRadius: '50%',
        background: '#151b23',
        border: `1.5px solid #3CB371`,
        boxShadow: '0 0 12px rgba(60, 179, 113, 0.25)',
        overflow: 'hidden',
        flexShrink: 0,
      }}
    >
      <img
        src={src}
        alt=""
        width={size}
        height={size}
        style={{
          width: '100%',
          height: '100%',
          objectFit: 'cover',
          display: 'block',
        }}
        draggable={false}
      />
    </span>
  );
}
