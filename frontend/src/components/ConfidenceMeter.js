/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

import React from 'react';

function ConfidenceMeter({ confidence, label, showPercentage = true }) {
  // Ensure confidence is between 0 and 100
  const normalizedConfidence = Math.max(0, Math.min(100, confidence || 0));
  
  const getConfidenceLevel = (conf) => {
    if (conf >= 80) return 'High';
    if (conf >= 60) return 'Medium';
    if (conf >= 40) return 'Low';
    return 'Very Low';
  };
  
  const confidenceLevel = getConfidenceLevel(normalizedConfidence);
  
  return (
    <div className="confidence-meter">
      <div className="confidence-meter-label">
        <span>{label || 'Confidence'}</span>
        {showPercentage && (
          <span style={{ fontWeight: '600', color: 'var(--text-primary)' }}>
            {normalizedConfidence}% • {confidenceLevel}
          </span>
        )}
      </div>
      <div className="confidence-meter-bar">
        <div
          className="confidence-meter-fill"
          style={{ width: `${normalizedConfidence}%` }}
        />
      </div>
    </div>
  );
}

export default ConfidenceMeter;
