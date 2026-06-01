/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { API_BASE_URL } from '../utils/api';
import './InvestigationEnhancements.css';

function RelatedActivity({ investigationId }) {
  const [related, setRelated] = useState({
    related_alerts: [],
    related_investigations: [],
    shared_iocs: [],
    correlation_score: 0
  });
  const [loading, setLoading] = useState(true);
  const [expanded, setExpanded] = useState(true);

  useEffect(() => {
    if (investigationId) {
      fetchRelated();
    }
  }, [investigationId]);

  const fetchRelated = async () => {
    try {
      const response = await fetch(
        `${API_BASE_URL}/api/v1/investigations/${investigationId}/related`,
        {
          headers: {
            'Content-Type': 'application/json'
          }
        }
      );
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }
      const data = await response.json();
      setRelated(data);
      setLoading(false);
    } catch (error) {
      setLoading(false);
    }
  };

  const getSeverityColor = (severity) => {
    const colors = {
      critical: '#dc2626',
      high: '#ea580c',
      medium: '#eab308',
      low: '#3b82f6'
    };
    return colors[severity?.toLowerCase()] || '#6b7280';
  };

  const getVerdictColor = (verdict) => {
    const colors = {
      malicious: '#dc2626',
      suspicious: '#f59e0b',
      benign: '#22c55e',
      inconclusive: '#6b7280'
    };
    return colors[verdict?.toLowerCase()] || '#6b7280';
  };

  if (loading) {
    return (
      <div className="related-activity">
        <div className="loading">Loading related activity...</div>
      </div>
    );
  }

  const totalRelated =
    related.related_alerts.length +
    related.related_investigations.length +
    related.shared_iocs.length;

  if (totalRelated === 0) {
    return null; // Don't show if no related items
  }

  return (
    <div className="related-activity">
      <div className="panel-header" onClick={() => setExpanded(!expanded)}>
        <h3>🔗 Related Activity</h3>
        <div className="panel-header-right">
          <span className="total-count">{totalRelated} related items</span>
          <span className="expand-icon">{expanded ? '▼' : '▶'}</span>
        </div>
      </div>

      {expanded && (
        <>
          {/* Correlation Score */}
          <div className="correlation-score">
            <span className="score-label">Correlation Strength</span>
            <div className="score-bar">
              <div
                className="score-fill"
                style={{
                  width: `${related.correlation_score}%`,
                  background:
                    related.correlation_score > 70
                      ? '#dc2626'
                      : related.correlation_score > 40
                      ? '#f59e0b'
                      : '#22c55e'
                }}
              />
            </div>
            <span className="score-value">{related.correlation_score}/100</span>
          </div>

          {/* Related Alerts */}
          {related.related_alerts.length > 0 && (
            <div className="related-section">
              <h4>📨 Related Alerts ({related.related_alerts.length})</h4>
              <div className="related-list">
                {Array.isArray(related.related_alerts) && related.related_alerts.slice(0, 5).map((alert, idx) => (
                  <div key={idx} className="related-item">
                    <div className="related-item-header">
                      <Link to={`/queue?highlight=${alert.alert_id}`} className="related-link">
                        {alert.title}
                      </Link>
                      <div className="related-badges">
                        <span
                          className="badge"
                          style={{ background: getSeverityColor(alert.severity) }}
                        >
                          {alert.severity}
                        </span>
                      </div>
                    </div>
                    <div className="related-meta">
                      <span className="meta-item">
                        <strong>{alert.match_count}</strong> shared IOCs
                      </span>
                      <span className="meta-item">Source: {alert.source}</span>
                    </div>
                  </div>
                ))}
                {related.related_alerts.length > 5 && (
                  <div className="show-more">
                    +{related.related_alerts.length - 5} more alerts
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Related Investigations */}
          {related.related_investigations.length > 0 && (
            <div className="related-section">
              <h4>🔍 Related Investigations ({related.related_investigations.length})</h4>
              <div className="related-list">
                {Array.isArray(related.related_investigations) && related.related_investigations.slice(0, 5).map((inv, idx) => (
                  <div key={idx} className="related-item">
                    <div className="related-item-header">
                      <Link
                        to={`/investigation/${inv.investigation_id}`}
                        className="related-link"
                      >
                        {inv.summary || inv.investigation_id}
                      </Link>
                      <div className="related-badges">
                        <span
                          className="badge"
                          style={{ background: getVerdictColor(inv.verdict) }}
                        >
                          {inv.verdict}
                        </span>
                        <span
                          className="badge"
                          style={{ background: getSeverityColor(inv.severity) }}
                        >
                          {inv.severity}
                        </span>
                      </div>
                    </div>
                    <div className="related-meta">
                      <span className="meta-item">
                        <strong>{inv.match_count}</strong> shared IOCs
                      </span>
                      <span className="meta-item">
                        {new Date(inv.created_at).toLocaleDateString()}
                      </span>
                    </div>
                  </div>
                ))}
                {related.related_investigations.length > 5 && (
                  <div className="show-more">
                    +{related.related_investigations.length - 5} more investigations
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Shared IOCs */}
          {related.shared_iocs.length > 0 && (
            <div className="related-section">
              <h4>🎯 Shared IOCs ({related.shared_iocs.length})</h4>
              <div className="ioc-list">
                {Array.isArray(related.shared_iocs) && related.shared_iocs.slice(0, 10).map((ioc, idx) => (
                  <div key={idx} className="ioc-item">
                    <code className="ioc-value">{ioc.value}</code>
                    <div className="ioc-stats">
                      <span className="ioc-stat">{ioc.alert_count} alerts</span>
                      <span className="ioc-stat">{ioc.investigation_count} investigations</span>
                      <span
                        className="risk-score"
                        style={{
                          background:
                            ioc.risk_score > 70
                              ? '#dc2626'
                              : ioc.risk_score > 40
                              ? '#f59e0b'
                              : '#22c55e'
                        }}
                      >
                        Risk: {ioc.risk_score}
                      </span>
                    </div>
                  </div>
                ))}
                {related.shared_iocs.length > 10 && (
                  <div className="show-more">
                    +{related.shared_iocs.length - 10} more IOCs
                  </div>
                )}
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}

export default RelatedActivity;


