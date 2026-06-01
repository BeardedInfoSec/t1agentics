/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

import React, { useState, useEffect } from 'react';
import { API_BASE_URL } from '../utils/api';
import './InvestigationEnhancements.css';

function FrameworkMappingPanel({ investigationId }) {
  const [frameworks, setFrameworks] = useState({});
  const [loading, setLoading] = useState(true);
  const [expanded, setExpanded] = useState(true);

  useEffect(() => {
    if (investigationId) {
      fetchFrameworks();
    }
  }, [investigationId]);

  const fetchFrameworks = async () => {
    try {
      const response = await fetch(
        `${API_BASE_URL}/api/v1/investigations/${investigationId}/frameworks`
      );
      const data = await response.json();
      setFrameworks(data);
      setLoading(false);
    } catch (error) {
      setLoading(false);
    }
  };

  const getFrameworkIcon = (framework) => {
    const icons = {
      mitre_attack: '🎯',
      mitre_tactics: '⚔️',
      nist_csf: '🛡️',
      cis_controls: '📋',
      kill_chain: '⛓️',
      nist_800_61: '📘',
      iso_27001: '🏛️',
      sans_picerl: '🚨',
      zero_trust: '🔐'
    };
    return icons[framework] || '📌';
  };

  const getFrameworkName = (framework) => {
    const names = {
      mitre_attack: 'MITRE ATT&CK Techniques',
      mitre_tactics: 'MITRE ATT&CK Tactics',
      nist_csf: 'NIST Cybersecurity Framework',
      cis_controls: 'CIS Controls v8',
      kill_chain: 'Cyber Kill Chain',
      nist_800_61: 'NIST 800-61 (Incident Handling)',
      iso_27001: 'ISO 27001 Controls',
      sans_picerl: 'SANS PICERL',
      zero_trust: 'Zero Trust Architecture'
    };
    return names[framework] || framework.replace('_', ' ').toUpperCase();
  };

  const getFrameworkColor = (framework) => {
    const colors = {
      mitre_attack: '#dc2626',
      mitre_tactics: '#ea580c',
      nist_csf: '#3b82f6',
      cis_controls: '#3CB371',
      kill_chain: '#ec4899',
      nist_800_61: '#06b6d4',
      iso_27001: '#10b981',
      sans_picerl: '#f59e0b',
      zero_trust: '#3CB371'
    };
    return colors[framework] || '#3CB371';
  };

  if (loading) {
    return (
      <div className="framework-mapping-panel">
        <div className="loading">Loading frameworks...</div>
      </div>
    );
  }

  const totalControls = Object.values(frameworks).reduce(
    (sum, controls) => sum + (controls?.length || 0),
    0
  );

  if (totalControls === 0) {
    return null; // Don't show if no frameworks matched
  }

  return (
    <div className="framework-mapping-panel">
      <div className="panel-header" onClick={() => setExpanded(!expanded)}>
        <h3>🎯 Cybersecurity Framework Mappings</h3>
        <div className="panel-header-right">
          <span className="total-count">{totalControls} controls matched</span>
          <span className="expand-icon">{expanded ? '▼' : '▶'}</span>
        </div>
      </div>
      
      {expanded && (
        <div className="framework-grid">
          {Object.entries(frameworks).map(([framework, controls]) => {
            // Ensure controls is an array
            if (!controls || !Array.isArray(controls) || controls.length === 0) return null;
            
            return (
              <div
                key={framework}
                className="framework-card"
                style={{ borderColor: getFrameworkColor(framework) }}
              >
                <div className="framework-header">
                  <span className="framework-icon">{getFrameworkIcon(framework)}</span>
                  <div className="framework-info">
                    <span className="framework-name">{getFrameworkName(framework)}</span>
                    <span
                      className="control-count"
                      style={{ background: getFrameworkColor(framework) }}
                    >
                      {Array.isArray(controls) ? controls.length : 0}
                    </span>
                  </div>
                </div>
                
                <div className="control-list">
                  {Array.isArray(controls) && controls.slice(0, 5).map((control, idx) => (
                    <div key={idx} className="control-item">
                      <code>{typeof control === 'string' ? control : JSON.stringify(control)}</code>
                    </div>
                  ))}
                  {Array.isArray(controls) && controls.length > 5 && (
                    <div className="more-controls">
                      +{controls.length - 5} more controls
                    </div>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

export default FrameworkMappingPanel;
