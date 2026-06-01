/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

import { useState, useEffect, useCallback } from 'react';
import { API_BASE_URL, authFetch } from '../utils/api';

// Format helpers
const formatNumber = (num) => {
  if (!num) return '0';
  if (num >= 1000000) return (num / 1000000).toFixed(1) + 'M';
  if (num >= 1000) return (num / 1000).toFixed(1) + 'K';
  return num.toLocaleString();
};

const formatMs = (ms) => {
  if (ms === null || ms === undefined) return '-';
  if (ms < 1000) return `${Math.round(ms)}ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
  return `${(ms / 60000).toFixed(1)}m`;
};

const formatPercent = (value) => value === null || value === undefined ? '-' : `${value.toFixed(1)}%`;

const formatTimeAgo = (timestamp) => {
  if (!timestamp) return '-';
  const seconds = Math.floor((Date.now() - new Date(timestamp).getTime()) / 1000);
  if (seconds < 60) return 'just now';
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
};

// Color helpers
const getLatencyColor = (ms, thresholds = { good: 2000, warn: 5000 }) => {
  if (ms === null || ms === undefined) return 'var(--text-muted)';
  if (ms <= thresholds.good) return '#22c55e';
  if (ms <= thresholds.warn) return '#f97316';
  return '#dc2626';
};

const getAccuracyColor = (rate) => {
  if (rate === null || rate === undefined) return 'var(--text-muted)';
  if (rate >= 90) return '#22c55e';
  if (rate >= 75) return '#f97316';
  return '#dc2626';
};

// Verdict styling
const getVerdictStyle = (verdict) => {
  const styles = {
    'TRUE_POSITIVE': { bg: '#dc262620', color: '#dc2626', icon: '!' },
    'FALSE_POSITIVE': { bg: '#22c55e20', color: '#22c55e', icon: '✓' },
    'SUSPICIOUS': { bg: '#f9731620', color: '#f97316', icon: '?' },
    'NEEDS_INVESTIGATION': { bg: '#3b82f620', color: '#3b82f6', icon: '🔍' },
    'ESCALATED': { bg: '#8b5cf620', color: '#8b5cf6', icon: '↑' },
    'CLOSED': { bg: '#6b728020', color: '#6b7280', icon: '✓' },
  };
  return styles[verdict] || { bg: '#6b728020', color: '#6b7280', icon: '•' };
};

function AgentOperationsCenter() {
  const [recentExecutions, setRecentExecutions] = useState([]);
  const [metrics, setMetrics] = useState({
    totalTokensToday: 0,
    avgResolutionTime: 0,
    eventsProcessed24h: 0,
    successRate: 0,
    eventsCoverage: { totalEvents: 0, eventsTouched: 0, eventsClosed: 0, touchRate: 0, closeRate: 0 }
  });
  const [timingBreakdown, setTimingBreakdown] = useState(null);
  const [telemetryMetrics, setTelemetryMetrics] = useState(null);
  const [loading, setLoading] = useState(true);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [riggsStopped, setRiggsStopped] = useState(false);
  const [emergencyStopLoading, setEmergencyStopLoading] = useState(false);
  const [daysRange, setDaysRange] = useState(7);

  const fetchData = useCallback(async () => {
    try {
      const [executionsRes, metricsRes, telemetryRes, timingRes] = await Promise.all([
        authFetch(`${API_BASE_URL}/api/v1/agents/ops/executions/recent?limit=20`).catch(() => ({ ok: false })),
        authFetch(`${API_BASE_URL}/api/v1/agents/ops/metrics`).catch(() => ({ ok: false })),
        authFetch(`${API_BASE_URL}/api/v1/telemetry/dashboard?days=${daysRange}`).catch(() => ({ ok: false })),
        authFetch(`${API_BASE_URL}/api/v1/telemetry/timing/breakdown?days=${daysRange}`).catch(() => ({ ok: false }))
      ]);

      if (executionsRes.ok) {
        const data = await executionsRes.json();
        setRecentExecutions(data.executions || data || []);
      }

      if (metricsRes.ok) {
        const data = await metricsRes.json();
        setMetrics(prev => ({ ...prev, ...data }));
        setRiggsStopped(data.emergencyStopped || false);
      }

      if (telemetryRes.ok) {
        setTelemetryMetrics(await telemetryRes.json());
      }

      if (timingRes.ok) {
        setTimingBreakdown(await timingRes.json());
      }
    } catch (err) {
    } finally {
      setLoading(false);
    }
  }, [daysRange]);

  useEffect(() => { fetchData(); }, [fetchData]);

  useEffect(() => {
    if (!autoRefresh) return;
    const interval = setInterval(fetchData, 30000);
    return () => clearInterval(interval);
  }, [autoRefresh, fetchData]);

  const handleEmergencyStop = async () => {
    setEmergencyStopLoading(true);
    try {
      const endpoint = riggsStopped ? 'emergency-resume' : 'emergency-stop';
      const response = await authFetch(`${API_BASE_URL}/api/v1/agents/ops/${endpoint}`, {
        method: 'POST'
      });
      if (response.ok) {
        setRiggsStopped(!riggsStopped);
        fetchData();
      }
    } catch (err) {
    } finally {
      setEmergencyStopLoading(false);
    }
  };

  if (loading) {
    return (
      <div style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-secondary)' }}>
        Loading...
      </div>
    );
  }

  // Derived performance metrics
  const avgResponseTime = timingBreakdown?.avg_total_ms || telemetryMetrics?.timing?.avg_execution_ms || null;
  const avgModelLatency = timingBreakdown?.avg_model_call_ms || null;
  const avgToolExecution = timingBreakdown?.avg_tool_execution_ms || null;
  const p95ResponseTime = timingBreakdown?.p95_total_ms || null;
  const errorRate = telemetryMetrics?.errors?.error_rate || 0;

  return (
    <div style={{ padding: '0' }}>
      {/* Header with Riggs Status */}
      <div style={{
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        marginBottom: '0.75rem',
        background: 'var(--bg-secondary)',
        borderRadius: '10px',
        padding: '0.75rem 1rem',
        border: '1px solid var(--border-color)'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <div style={{
            width: '36px',
            height: '36px',
            background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
            borderRadius: '8px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            fontSize: '1.25rem'
          }}>
            🤖
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <span style={{ fontWeight: '600', color: 'var(--text-primary)' }}>Riggs</span>
              <div style={{
                width: '8px',
                height: '8px',
                borderRadius: '50%',
                background: riggsStopped ? '#dc2626' : '#22c55e',
                boxShadow: `0 0 6px ${riggsStopped ? '#dc2626' : '#22c55e'}`
              }} />
              <span style={{ fontSize: '0.8rem', color: riggsStopped ? '#dc2626' : '#22c55e' }}>
                {riggsStopped ? 'Stopped' : 'Active'}
              </span>
            </div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
              Expert Security Analyst
            </div>
          </div>
        </div>

        <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
          <select value={daysRange} onChange={(e) => setDaysRange(Number(e.target.value))}
            style={{ padding: '0.35rem 0.5rem', background: 'var(--bg-tertiary)', border: '1px solid var(--border-color)', borderRadius: '6px', color: 'var(--text-primary)', fontSize: '0.8rem', cursor: 'pointer' }}>
            <option value={1}>24h</option>
            <option value={7}>7d</option>
            <option value={30}>30d</option>
          </select>
          <button
            onClick={() => setAutoRefresh(!autoRefresh)}
            style={{
              padding: '0.4rem 0.75rem',
              background: autoRefresh ? 'rgba(60, 179, 113, 0.15)' : 'var(--bg-tertiary)',
              border: `1px solid ${autoRefresh ? '#3CB371' : 'var(--border-color)'}`,
              borderRadius: '6px',
              color: autoRefresh ? '#3CB371' : 'var(--text-secondary)',
              cursor: 'pointer',
              fontSize: '0.8rem'
            }}
          >
            {autoRefresh ? '🔄 Auto' : '⏸️ Paused'}
          </button>
          <button
            onClick={handleEmergencyStop}
            disabled={emergencyStopLoading}
            style={{
              padding: '0.4rem 0.75rem',
              background: riggsStopped ? '#22c55e' : '#dc2626',
              border: 'none',
              borderRadius: '6px',
              color: 'white',
              cursor: emergencyStopLoading ? 'wait' : 'pointer',
              fontSize: '0.8rem',
              fontWeight: '600'
            }}
          >
            {riggsStopped ? '▶ Resume' : '⏹ Stop'}
          </button>
        </div>
      </div>

      {/* Emergency Stop Banner */}
      {riggsStopped && (
        <div style={{
          background: '#dc262615',
          border: '1px solid #dc262640',
          borderRadius: '8px',
          padding: '0.6rem 1rem',
          marginBottom: '0.75rem',
          display: 'flex',
          alignItems: 'center',
          gap: '0.5rem',
          fontSize: '0.85rem'
        }}>
          <span>⚠️</span>
          <span style={{ color: '#dc2626', fontWeight: '500' }}>Emergency stop active</span>
          <span style={{ color: 'var(--text-secondary)' }}>- Riggs will not process alerts</span>
        </div>
      )}

      {/* Quick Stats Row */}
      <div style={{
        display: 'flex',
        background: 'var(--bg-secondary)',
        borderRadius: '8px',
        border: '1px solid var(--border-color)',
        marginBottom: '0.75rem',
        overflow: 'hidden'
      }}>
        <QuickStat label="Processed (24h)" value={metrics.eventsProcessed24h || 0} />
        <QuickStat label="Success Rate" value={`${metrics.successRate || 0}%`} color="#22c55e" />
        <QuickStat label="Analyzed" value={`${metrics.eventsCoverage?.touchRate || 0}%`} color="#3b82f6" />
        <QuickStat label="Auto-Closed" value={`${metrics.eventsCoverage?.closeRate || 0}%`} color="#22c55e" border={false} />
      </div>

      {/* Performance Metrics Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '0.5rem', marginBottom: '0.75rem' }}>
        <MetricCard
          label="Avg Response"
          value={formatMs(avgResponseTime)}
          detail="end-to-end"
          color={getLatencyColor(avgResponseTime, { good: 3000, warn: 8000 })}
        />
        <MetricCard
          label="P95 Response"
          value={formatMs(p95ResponseTime)}
          detail="95th percentile"
          color={getLatencyColor(p95ResponseTime, { good: 10000, warn: 20000 })}
        />
        <MetricCard
          label="Model Latency"
          value={formatMs(avgModelLatency)}
          detail="avg API call"
          color={getLatencyColor(avgModelLatency, { good: 1500, warn: 3000 })}
        />
        <MetricCard
          label="Tool Execution"
          value={formatMs(avgToolExecution)}
          detail="avg per tool"
          color={getLatencyColor(avgToolExecution, { good: 500, warn: 1500 })}
        />
      </div>

      {/* Secondary Metrics */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '0.5rem', marginBottom: '0.75rem' }}>
        <MetricCard
          label="Accuracy"
          value={formatPercent(telemetryMetrics?.accuracy?.accuracy_rate)}
          detail={`${telemetryMetrics?.accuracy?.correct || 0}/${telemetryMetrics?.accuracy?.total_verdicts || 0}`}
          color={getAccuracyColor(telemetryMetrics?.accuracy?.accuracy_rate)}
        />
        <MetricCard
          label="Error Rate"
          value={formatPercent(errorRate)}
          detail={`${telemetryMetrics?.errors?.total_errors || 0} errors`}
          color={errorRate <= 2 ? '#22c55e' : errorRate <= 5 ? '#f97316' : '#dc2626'}
        />
        <MetricCard
          label="Tokens Today"
          value={formatNumber(metrics.totalTokensToday || 0)}
          detail="total usage"
          color="var(--text-primary)"
        />
        <MetricCard
          label="Total Executions"
          value={formatNumber(telemetryMetrics?.volume?.total_executions)}
          detail={`${daysRange}d`}
          color="var(--text-primary)"
        />
      </div>

      {/* Processing Breakdown */}
      {timingBreakdown && (
        <div style={{ background: 'var(--bg-secondary)', borderRadius: '8px', border: '1px solid var(--border-color)', padding: '0.75rem', marginBottom: '0.75rem' }}>
          <div style={{ fontSize: '0.75rem', fontWeight: '500', color: 'var(--text-secondary)', marginBottom: '0.5rem' }}>Processing Breakdown</div>
          <ProcessingBar breakdown={timingBreakdown} />
        </div>
      )}

      {/* Recent Activity */}
      <div style={{
        background: 'var(--bg-secondary)',
        borderRadius: '8px',
        border: '1px solid var(--border-color)',
        padding: '0.75rem'
      }}>
        <div style={{ fontSize: '0.75rem', fontWeight: '500', color: 'var(--text-secondary)', marginBottom: '0.5rem' }}>
          Recent Activity
        </div>

        {recentExecutions.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '1.5rem', color: 'var(--text-secondary)', fontSize: '0.85rem' }}>
            No recent activity
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
            {recentExecutions.slice(0, 10).map((exec, idx) => {
              const verdict = getVerdictStyle(exec.outcome?.verdict);
              return (
                <div
                  key={idx}
                  style={{
                    background: 'var(--bg-primary)',
                    borderRadius: '6px',
                    padding: '0.5rem 0.75rem',
                    border: '1px solid var(--border-color)',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.75rem'
                  }}
                >
                  <div style={{
                    width: '26px',
                    height: '26px',
                    borderRadius: '6px',
                    background: verdict.bg,
                    color: verdict.color,
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    fontWeight: '700',
                    fontSize: '0.85rem',
                    flexShrink: 0
                  }}>
                    {verdict.icon}
                  </div>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                      <span style={{ color: 'var(--text-primary)', fontWeight: '500', fontSize: '0.8rem' }}>
                        {exec.outcome?.verdict || exec.status}
                      </span>
                      {exec.alert_id && (
                        <span style={{
                          fontSize: '0.65rem',
                          color: 'var(--text-secondary)',
                          background: 'var(--bg-tertiary)',
                          padding: '0.1rem 0.35rem',
                          borderRadius: '3px'
                        }}>
                          {exec.alert_id}
                        </span>
                      )}
                    </div>
                    <div style={{
                      fontSize: '0.7rem',
                      color: 'var(--text-secondary)',
                      whiteSpace: 'nowrap',
                      overflow: 'hidden',
                      textOverflow: 'ellipsis'
                    }}>
                      {exec.outcome?.summary || exec.reason || 'Processing completed'}
                    </div>
                  </div>
                  <div style={{ textAlign: 'right', flexShrink: 0 }}>
                    <div style={{ color: getLatencyColor(exec.duration_ms, { good: 3000, warn: 8000 }), fontSize: '0.75rem', fontWeight: '600' }}>
                      {formatMs(exec.duration_ms)}
                    </div>
                    <div style={{ color: 'var(--text-muted)', fontSize: '0.65rem' }}>
                      {formatTimeAgo(exec.started_at)}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}

// Quick stat cell for top row
function QuickStat({ label, value, color, border = true }) {
  return (
    <div style={{
      flex: 1,
      padding: '0.5rem 0.75rem',
      borderRight: border ? '1px solid var(--border-color)' : 'none',
      textAlign: 'center'
    }}>
      <div style={{ fontSize: '0.65rem', color: 'var(--text-secondary)', marginBottom: '0.1rem' }}>
        {label}
      </div>
      <div style={{ fontSize: '0.95rem', fontWeight: '700', color: color || 'var(--text-primary)' }}>
        {value}
      </div>
    </div>
  );
}

// Metric card component
function MetricCard({ label, value, detail, color }) {
  return (
    <div style={{
      background: 'var(--bg-secondary)',
      borderRadius: '6px',
      border: '1px solid var(--border-color)',
      padding: '0.5rem 0.75rem'
    }}>
      <div style={{ fontSize: '0.65rem', color: 'var(--text-secondary)', marginBottom: '0.1rem' }}>{label}</div>
      <div style={{ fontSize: '1.1rem', fontWeight: '700', color: color || 'var(--text-primary)', lineHeight: 1.1 }}>{value}</div>
      {detail && <div style={{ fontSize: '0.6rem', color: 'var(--text-muted)', marginTop: '0.1rem' }}>{detail}</div>}
    </div>
  );
}

// Processing breakdown bar
function ProcessingBar({ breakdown }) {
  const total = breakdown.avg_total_ms || 1;
  const modelPct = ((breakdown.avg_model_call_ms || 0) / total) * 100;
  const toolPct = ((breakdown.avg_tool_execution_ms || 0) / total) * 100;
  const otherPct = Math.max(0, 100 - modelPct - toolPct);

  return (
    <div>
      <div style={{ display: 'flex', height: '18px', borderRadius: '4px', overflow: 'hidden', marginBottom: '0.5rem' }}>
        <div style={{ width: `${modelPct}%`, background: '#3b82f6', minWidth: modelPct > 0 ? '2px' : 0 }} title={`Model: ${modelPct.toFixed(1)}%`} />
        <div style={{ width: `${toolPct}%`, background: '#22c55e', minWidth: toolPct > 0 ? '2px' : 0 }} title={`Tools: ${toolPct.toFixed(1)}%`} />
        <div style={{ width: `${otherPct}%`, background: '#6b7280', minWidth: otherPct > 0 ? '2px' : 0 }} title={`Other: ${otherPct.toFixed(1)}%`} />
      </div>
      <div style={{ display: 'flex', gap: '1rem', fontSize: '0.7rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
          <div style={{ width: '8px', height: '8px', borderRadius: '2px', background: '#3b82f6' }} />
          <span style={{ color: 'var(--text-secondary)' }}>Model</span>
          <span style={{ color: 'var(--text-primary)', fontWeight: '500' }}>{formatMs(breakdown.avg_model_call_ms)}</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
          <div style={{ width: '8px', height: '8px', borderRadius: '2px', background: '#22c55e' }} />
          <span style={{ color: 'var(--text-secondary)' }}>Tools</span>
          <span style={{ color: 'var(--text-primary)', fontWeight: '500' }}>{formatMs(breakdown.avg_tool_execution_ms)}</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
          <div style={{ width: '8px', height: '8px', borderRadius: '2px', background: '#6b7280' }} />
          <span style={{ color: 'var(--text-secondary)' }}>Other</span>
          <span style={{ color: 'var(--text-primary)', fontWeight: '500' }}>{formatMs((breakdown.avg_total_ms || 0) - (breakdown.avg_model_call_ms || 0) - (breakdown.avg_tool_execution_ms || 0))}</span>
        </div>
      </div>
    </div>
  );
}

export default AgentOperationsCenter;


