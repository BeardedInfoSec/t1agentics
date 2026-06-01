/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

import React, { useState, useEffect, useMemo } from 'react';
import { API_BASE_URL } from '../utils/api';
import './InvestigationEnhancements.css';

// Event type configurations
const EVENT_TYPE_CONFIG = {
  'investigation_created': { icon: '🆕', color: '#3b82f6', label: 'Created' },
  'state_change': { icon: '🔄', color: '#8b5cf6', label: 'State Change' },
  'alert_linked': { icon: '🔗', color: '#f59e0b', label: 'Alert Linked' },
  'enrichment': { icon: '🔍', color: '#06b6d4', label: 'Enrichment' },
  'ai_analysis': { icon: '🤖', color: '#10b981', label: 'AI Analysis' },
  'riggs_analysis': { icon: '🔮', color: '#14b8a6', label: 'Riggs Analysis' },
  'human_action': { icon: '👤', color: '#ec4899', label: 'Human Action' },
  'disposition_set': { icon: '✅', color: '#22c55e', label: 'Disposition' },
  'comment': { icon: '💬', color: '#6366f1', label: 'Comment' },
  'escalation': { icon: '⚠️', color: '#ef4444', label: 'Escalation' },
  'response_action': { icon: '⚡', color: '#f97316', label: 'Response Action' },
  'default': { icon: '📌', color: '#6b7280', label: 'Event' }
};

function InvestigationTimeline({ investigationId }) {
  const [timeline, setTimeline] = useState([]);
  const [loading, setLoading] = useState(true);
  const [expanded, setExpanded] = useState(true);

  // Filter state
  const [viewMode, setViewMode] = useState('list'); // 'list' or 'graph'
  const [selectedTypes, setSelectedTypes] = useState(new Set(['all']));
  const [dateRange, setDateRange] = useState('all'); // 'all', '1h', '24h', '7d', '30d'
  const [showFilters, setShowFilters] = useState(false);

  useEffect(() => {
    if (investigationId) {
      fetchTimeline();
    }
  }, [investigationId]);

  const fetchTimeline = async () => {
    try {
      const response = await fetch(
        `${API_BASE_URL}/api/v1/investigations/${investigationId}/timeline`
      );
      const data = await response.json();
      setTimeline(data);
      setLoading(false);
    } catch (error) {
      setLoading(false);
    }
  };

  // Get unique event types from timeline
  const eventTypes = useMemo(() => {
    const types = new Set(timeline.map(e => e.type || 'default'));
    return Array.from(types);
  }, [timeline]);

  // Filter timeline based on selected filters
  const filteredTimeline = useMemo(() => {
    let filtered = [...timeline];

    // Filter by event type
    if (!selectedTypes.has('all')) {
      filtered = filtered.filter(e => selectedTypes.has(e.type));
    }

    // Filter by date range
    if (dateRange !== 'all') {
      const now = new Date();
      let cutoff;
      switch (dateRange) {
        case '1h': cutoff = new Date(now - 60 * 60 * 1000); break;
        case '24h': cutoff = new Date(now - 24 * 60 * 60 * 1000); break;
        case '7d': cutoff = new Date(now - 7 * 24 * 60 * 60 * 1000); break;
        case '30d': cutoff = new Date(now - 30 * 24 * 60 * 60 * 1000); break;
        default: cutoff = null;
      }
      if (cutoff) {
        filtered = filtered.filter(e => new Date(e.timestamp) >= cutoff);
      }
    }

    return filtered;
  }, [timeline, selectedTypes, dateRange]);

  // Calculate time statistics
  const timeStats = useMemo(() => {
    if (filteredTimeline.length < 2) return null;

    const timestamps = filteredTimeline.map(e => new Date(e.timestamp).getTime()).sort();
    const firstEvent = timestamps[0];
    const lastEvent = timestamps[timestamps.length - 1];
    const duration = lastEvent - firstEvent;

    return {
      firstEvent: new Date(firstEvent),
      lastEvent: new Date(lastEvent),
      durationMs: duration,
      durationFormatted: formatDuration(duration)
    };
  }, [filteredTimeline]);

  const formatTime = (timestamp) => {
    const date = new Date(timestamp);
    return date.toLocaleString('en-US', {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit'
    });
  };

  const formatDuration = (ms) => {
    const seconds = Math.floor(ms / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);
    const days = Math.floor(hours / 24);

    if (days > 0) return `${days}d ${hours % 24}h`;
    if (hours > 0) return `${hours}h ${minutes % 60}m`;
    if (minutes > 0) return `${minutes}m ${seconds % 60}s`;
    return `${seconds}s`;
  };

  const getEventConfig = (type) => {
    return EVENT_TYPE_CONFIG[type] || EVENT_TYPE_CONFIG.default;
  };

  const toggleEventType = (type) => {
    const newSet = new Set(selectedTypes);
    if (type === 'all') {
      setSelectedTypes(new Set(['all']));
    } else {
      newSet.delete('all');
      if (newSet.has(type)) {
        newSet.delete(type);
        if (newSet.size === 0) newSet.add('all');
      } else {
        newSet.add(type);
      }
      setSelectedTypes(newSet);
    }
  };

  if (loading) {
    return (
      <div className="investigation-timeline">
        <div className="loading">Loading timeline...</div>
      </div>
    );
  }

  if (timeline.length === 0) {
    return null;
  }

  return (
    <div className="investigation-timeline enhanced-timeline">
      <div className="panel-header" onClick={() => setExpanded(!expanded)}>
        <h3>Investigation Timeline</h3>
        <div className="panel-header-right">
          <span className="total-count">{filteredTimeline.length} / {timeline.length} events</span>
          <span className="expand-icon">{expanded ? '▼' : '▶'}</span>
        </div>
      </div>

      {expanded && (
        <>
          {/* Timeline Controls */}
          <div className="timeline-controls">
            <div className="control-group">
              {/* View Toggle */}
              <div className="view-toggle">
                <button
                  className={viewMode === 'list' ? 'active' : ''}
                  onClick={() => setViewMode('list')}
                  title="List View"
                >
                  ☰
                </button>
                <button
                  className={viewMode === 'graph' ? 'active' : ''}
                  onClick={() => setViewMode('graph')}
                  title="Graph View"
                >
                  📊
                </button>
              </div>

              {/* Date Range Filter */}
              <select
                value={dateRange}
                onChange={(e) => setDateRange(e.target.value)}
                className="date-filter"
              >
                <option value="all">All Time</option>
                <option value="1h">Last Hour</option>
                <option value="24h">Last 24 Hours</option>
                <option value="7d">Last 7 Days</option>
                <option value="30d">Last 30 Days</option>
              </select>

              {/* Filter Toggle */}
              <button
                className={`filter-toggle ${showFilters ? 'active' : ''}`}
                onClick={() => setShowFilters(!showFilters)}
              >
                🔽 Filter Types
              </button>
            </div>

            {/* Time Stats */}
            {timeStats && (
              <div className="time-stats">
                <span className="stat">Duration: <strong>{timeStats.durationFormatted}</strong></span>
              </div>
            )}
          </div>

          {/* Event Type Filters */}
          {showFilters && (
            <div className="type-filters">
              <button
                className={`type-chip ${selectedTypes.has('all') ? 'active' : ''}`}
                onClick={() => toggleEventType('all')}
              >
                All
              </button>
              {eventTypes.map(type => {
                const config = getEventConfig(type);
                return (
                  <button
                    key={type}
                    className={`type-chip ${selectedTypes.has(type) ? 'active' : ''}`}
                    onClick={() => toggleEventType(type)}
                    style={{ '--chip-color': config.color }}
                  >
                    {config.icon} {config.label}
                  </button>
                );
              })}
            </div>
          )}

          {/* Timeline Content */}
          {viewMode === 'list' ? (
            <div className="timeline-container">
              {filteredTimeline.map((event, index) => {
                const config = getEventConfig(event.type);
                return (
                  <div key={index} className="timeline-event">
                    <div
                      className="timeline-marker"
                      style={{ background: event.color || config.color }}
                    >
                      <span className="timeline-icon">{event.icon || config.icon}</span>
                    </div>

                    <div className="timeline-content">
                      <div className="timeline-header">
                        <span className="timeline-type" style={{ color: config.color }}>
                          {config.label}
                        </span>
                        <span className="timeline-time">
                          {formatTime(event.timestamp)}
                        </span>
                      </div>

                      <div className="timeline-description">
                        {event.description}
                      </div>

                      {event.metadata && Object.keys(event.metadata).length > 0 && (
                        <div className="timeline-metadata">
                          {Object.entries(event.metadata).slice(0, 3).map(([key, value]) => (
                            <div key={key} className="metadata-item">
                              <span className="metadata-key">{key}:</span>
                              <span className="metadata-value">
                                {typeof value === 'object'
                                  ? JSON.stringify(value).slice(0, 50) + '...'
                                  : String(value).slice(0, 50)}
                              </span>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          ) : (
            <TimelineGraph events={filteredTimeline} getEventConfig={getEventConfig} />
          )}
        </>
      )}
    </div>
  );
}

// Graphical Timeline Component
function TimelineGraph({ events, getEventConfig }) {
  if (events.length === 0) {
    return <div className="timeline-graph-empty">No events to display</div>;
  }

  // Calculate time range
  const timestamps = events.map(e => new Date(e.timestamp).getTime());
  const minTime = Math.min(...timestamps);
  const maxTime = Math.max(...timestamps);
  const timeRange = maxTime - minTime || 1; // Avoid division by zero

  // Group events by hour for the bar chart
  const hourlyGroups = {};
  events.forEach(event => {
    const date = new Date(event.timestamp);
    const hourKey = `${date.getFullYear()}-${date.getMonth()}-${date.getDate()}-${date.getHours()}`;
    if (!hourlyGroups[hourKey]) {
      hourlyGroups[hourKey] = { timestamp: date.setMinutes(0, 0, 0), events: [] };
    }
    hourlyGroups[hourKey].events.push(event);
  });

  const hourlyData = Object.values(hourlyGroups).sort((a, b) => a.timestamp - b.timestamp);
  const maxEventsInHour = Math.max(...hourlyData.map(h => h.events.length));

  return (
    <div className="timeline-graph">
      {/* Horizontal Timeline */}
      <div className="graph-timeline">
        <div className="graph-track">
          {events.map((event, index) => {
            const config = getEventConfig(event.type);
            const position = ((new Date(event.timestamp).getTime() - minTime) / timeRange) * 100;
            return (
              <div
                key={index}
                className="graph-marker"
                style={{
                  left: `${Math.min(Math.max(position, 2), 98)}%`,
                  backgroundColor: config.color
                }}
                title={`${config.label}: ${event.description}\n${new Date(event.timestamp).toLocaleString()}`}
              >
                <span className="marker-icon">{config.icon}</span>
              </div>
            );
          })}
        </div>
        <div className="graph-axis">
          <span className="axis-label start">
            {new Date(minTime).toLocaleString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })}
          </span>
          <span className="axis-label end">
            {new Date(maxTime).toLocaleString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })}
          </span>
        </div>
      </div>

      {/* Event Distribution Bar Chart */}
      <div className="graph-distribution">
        <div className="distribution-title">Event Distribution</div>
        <div className="distribution-bars">
          {hourlyData.map((hour, index) => {
            const height = (hour.events.length / maxEventsInHour) * 100;
            const typeGroups = {};
            hour.events.forEach(e => {
              const type = e.type || 'default';
              typeGroups[type] = (typeGroups[type] || 0) + 1;
            });

            return (
              <div
                key={index}
                className="distribution-bar-container"
                title={`${new Date(hour.timestamp).toLocaleString('en-US', { hour: '2-digit', minute: '2-digit' })}: ${hour.events.length} events`}
              >
                <div
                  className="distribution-bar"
                  style={{ height: `${height}%` }}
                >
                  {Object.entries(typeGroups).map(([type, count], i) => {
                    const config = getEventConfig(type);
                    const segmentHeight = (count / hour.events.length) * 100;
                    return (
                      <div
                        key={type}
                        className="bar-segment"
                        style={{
                          height: `${segmentHeight}%`,
                          backgroundColor: config.color
                        }}
                      />
                    );
                  })}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Event Type Legend */}
      <div className="graph-legend">
        {Object.entries(EVENT_TYPE_CONFIG).slice(0, -1).map(([type, config]) => (
          <div key={type} className="legend-item">
            <span className="legend-color" style={{ backgroundColor: config.color }} />
            <span className="legend-label">{config.icon} {config.label}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

export default InvestigationTimeline;
