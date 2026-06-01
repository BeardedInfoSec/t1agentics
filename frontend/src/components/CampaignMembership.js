/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { API_BASE_URL } from '../utils/api';
import './InvestigationEnhancements.css';

/**
 * CampaignMembership Component
 *
 * Displays campaigns that an investigation belongs to,
 * along with related alerts from those campaigns.
 */
function CampaignMembership({ investigationId, investigationData }) {
  const [campaigns, setCampaigns] = useState([]);
  const [relatedAlerts, setRelatedAlerts] = useState([]);
  const [correlationEvents, setCorrelationEvents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [expanded, setExpanded] = useState(true);

  useEffect(() => {
    // First try to use data from investigationData prop (from API)
    if (investigationData) {
      if (investigationData.campaigns) {
        setCampaigns(investigationData.campaigns);
      }
      if (investigationData.related_alerts) {
        setRelatedAlerts(investigationData.related_alerts);
      }
      if (investigationData.correlation_events) {
        setCorrelationEvents(investigationData.correlation_events);
      }
      setLoading(false);
    } else if (investigationId) {
      fetchCampaignData();
    }
  }, [investigationId, investigationData]);

  const fetchCampaignData = async () => {
    try {
      const response = await fetch(
        `${API_BASE_URL}/api/v1/investigations/${investigationId}`
      );
      const data = await response.json();

      if (data.campaigns) {
        setCampaigns(data.campaigns);
      }
      if (data.related_alerts) {
        setRelatedAlerts(data.related_alerts);
      }
      if (data.correlation_events) {
        setCorrelationEvents(data.correlation_events);
      }
      setLoading(false);
    } catch (error) {
      console.error('Campaign data fetch error:', error);
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

  const getCampaignTypeIcon = (type) => {
    const icons = {
      apt: '🎯',
      ransomware: '🔐',
      phishing: '🎣',
      malware: '🦠',
      botnet: '🤖',
      data_exfil: '📤',
      lateral_movement: '↔️',
      credential_theft: '🔑',
      unknown: '❓'
    };
    return icons[type?.toLowerCase()] || '📊';
  };

  const getStatusColor = (status) => {
    const colors = {
      active: '#dc2626',
      investigating: '#f59e0b',
      contained: '#3b82f6',
      resolved: '#22c55e',
      false_positive: '#6b7280'
    };
    return colors[status?.toLowerCase()] || '#6b7280';
  };

  if (loading) {
    return (
      <div className="campaign-membership">
        <div className="loading">Loading campaign data...</div>
      </div>
    );
  }

  // Don't render if no campaign data
  if (campaigns.length === 0 && correlationEvents.length === 0) {
    return null;
  }

  return (
    <div className="campaign-membership">
      <div className="panel-header" onClick={() => setExpanded(!expanded)}>
        <h3>🎯 Campaign Membership</h3>
        <div className="panel-header-right">
          <span className="total-count">
            {campaigns.length} campaign{campaigns.length !== 1 ? 's' : ''}
          </span>
          <span className="expand-icon">{expanded ? '▼' : '▶'}</span>
        </div>
      </div>

      {expanded && (
        <>
          {/* Active Campaigns */}
          {campaigns.length > 0 && (
            <div className="campaign-section">
              <h4>📊 Active Campaigns</h4>
              <div className="campaign-list">
                {campaigns.map((campaign, idx) => (
                  <div key={idx} className="campaign-card">
                    <div className="campaign-header">
                      <span className="campaign-icon">
                        {getCampaignTypeIcon(campaign.campaign_type)}
                      </span>
                      <div className="campaign-title">
                        <Link
                          to={`/campaigns/${campaign.campaign_id}`}
                          className="campaign-link"
                        >
                          {campaign.name || campaign.campaign_id}
                        </Link>
                        <span className="campaign-id">{campaign.campaign_id}</span>
                      </div>
                      <div className="campaign-badges">
                        <span
                          className="badge"
                          style={{ background: getSeverityColor(campaign.severity) }}
                        >
                          {campaign.severity}
                        </span>
                        <span
                          className="badge"
                          style={{ background: getStatusColor(campaign.status) }}
                        >
                          {campaign.status}
                        </span>
                      </div>
                    </div>

                    <div className="campaign-stats">
                      <div className="stat">
                        <span className="stat-value">{campaign.alert_count || 0}</span>
                        <span className="stat-label">Alerts</span>
                      </div>
                      <div className="stat">
                        <span className="stat-value">{campaign.ioc_count || 0}</span>
                        <span className="stat-label">IOCs</span>
                      </div>
                      {campaign.confidence && (
                        <div className="stat">
                          <span className="stat-value">{Math.round(campaign.confidence)}%</span>
                          <span className="stat-label">Confidence</span>
                        </div>
                      )}
                    </div>

                    {campaign.correlation_reason && (
                      <div className="campaign-reason">
                        <span className="reason-label">Linked by:</span>
                        <span className="reason-value">{campaign.correlation_reason}</span>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Related Alerts from Campaigns */}
          {relatedAlerts.length > 0 && (
            <div className="campaign-section">
              <h4>🔗 Related Alerts ({relatedAlerts.length})</h4>
              <div className="related-list">
                {relatedAlerts.slice(0, 5).map((alert, idx) => (
                  <div key={idx} className="related-item">
                    <div className="related-item-header">
                      <Link
                        to={`/queue?highlight=${alert.alert_id}`}
                        className="related-link"
                      >
                        {alert.title}
                      </Link>
                      <span
                        className="badge"
                        style={{ background: getSeverityColor(alert.severity) }}
                      >
                        {alert.severity}
                      </span>
                    </div>
                    <div className="related-meta">
                      <span className="meta-item">Status: {alert.status}</span>
                      {alert.created_at && (
                        <span className="meta-item">
                          {new Date(alert.created_at).toLocaleDateString()}
                        </span>
                      )}
                    </div>
                  </div>
                ))}
                {relatedAlerts.length > 5 && (
                  <div className="show-more">
                    +{relatedAlerts.length - 5} more related alerts
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Correlation Events */}
          {correlationEvents.length > 0 && (
            <div className="campaign-section">
              <h4>⚡ Correlation Events</h4>
              <div className="correlation-events">
                {correlationEvents.map((event, idx) => (
                  <div key={idx} className="correlation-event">
                    <div className="event-header">
                      <span className="event-rule">{event.rule_name}</span>
                      <span className="event-type">{event.correlation_type}</span>
                    </div>
                    <div className="event-details">
                      {event.correlation_score && (
                        <span className="event-score">
                          Score: {Math.round(event.correlation_score)}
                        </span>
                      )}
                      {event.campaign_id && (
                        <Link
                          to={`/campaigns/${event.campaign_id}`}
                          className="event-campaign"
                        >
                          → {event.campaign_id}
                        </Link>
                      )}
                    </div>
                    {event.ioc_values && event.ioc_values.length > 0 && (
                      <div className="event-iocs">
                        <span className="iocs-label">Matched IOCs:</span>
                        {event.ioc_values.slice(0, 3).map((ioc, i) => (
                          <code key={i} className="ioc-value">{ioc}</code>
                        ))}
                        {event.ioc_values.length > 3 && (
                          <span className="more-iocs">+{event.ioc_values.length - 3} more</span>
                        )}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}

export default CampaignMembership;
