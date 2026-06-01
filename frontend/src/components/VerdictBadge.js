/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

import React from 'react';

function VerdictBadge({ verdict, size = 'md' }) {
  const getVerdictType = (v) => {
    const vLower = (v || '').toLowerCase();
    if (vLower.includes('malicious') || vLower.includes('true positive')) return 'malicious';
    if (vLower.includes('suspicious') || vLower.includes('high')) return 'suspicious';
    if (vLower.includes('benign') || vLower.includes('false positive')) return 'benign';
    return 'unknown';
  };
  
  const getVerdictIcon = (type) => {
    switch (type) {
      case 'malicious': return '⚠️';
      case 'suspicious': return '⚡';
      case 'benign': return '✅';
      default: return '❓';
    }
  };
  
  const verdictType = getVerdictType(verdict);
  const icon = getVerdictIcon(verdictType);
  
  const sizeClasses = {
    sm: { fontSize: '0.65rem', padding: '4px 8px' },
    md: { fontSize: '0.75rem', padding: '6px 12px' },
    lg: { fontSize: '0.875rem', padding: '8px 16px' }
  };
  
  return (
    <span
      className={`verdict-badge ${verdictType}`}
      style={sizeClasses[size]}
    >
      <span>{icon}</span>
      <span>{verdict || 'Unknown'}</span>
    </span>
  );
}

export default VerdictBadge;
