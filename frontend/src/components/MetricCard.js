/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

import React from 'react';

function MetricCard({ title, value, delta, deltaType, icon, iconBg, sparklineData }) {
  const deltaColor = deltaType === 'positive' ? 'var(--success)' : 
                     deltaType === 'negative' ? 'var(--danger)' : 
                     'var(--text-secondary)';
  
  const deltaIcon = deltaType === 'positive' ? '↑' : 
                    deltaType === 'negative' ? '↓' : '→';
  
  return (
    <div className="metric-card">
      <div className="metric-card-header">
        <div className="metric-card-title">{title}</div>
        <div className="metric-card-icon" style={{ background: iconBg }}>
          {icon}
        </div>
      </div>
      
      <div className="metric-card-value">{value}</div>
      
      <div className="metric-card-footer">
        {delta !== undefined && (
          <div className={`metric-card-delta ${deltaType}`} style={{ color: deltaColor }}>
            <span>{deltaIcon}</span>
            <span>{Math.abs(delta)}%</span>
          </div>
        )}
        <span style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>
          vs last week
        </span>
        
        {sparklineData && sparklineData.length > 0 && (
          <div className="metric-card-sparkline">
            <MiniSparkline data={sparklineData} />
          </div>
        )}
      </div>
    </div>
  );
}

function MiniSparkline({ data }) {
  if (!data || data.length === 0) return null;
  
  const max = Math.max(...data);
  const min = Math.min(...data);
  const range = max - min || 1;
  
  const points = data.map((value, index) => {
    const x = (index / (data.length - 1)) * 100;
    const y = 100 - ((value - min) / range) * 100;
    return `${x},${y}`;
  }).join(' ');
  
  return (
    <svg
      width="100%"
      height="100%"
      viewBox="0 0 100 100"
      preserveAspectRatio="none"
      style={{ overflow: 'visible' }}
    >
      <polyline
        points={points}
        fill="none"
        stroke="var(--primary)"
        strokeWidth="3"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

export default MetricCard;
