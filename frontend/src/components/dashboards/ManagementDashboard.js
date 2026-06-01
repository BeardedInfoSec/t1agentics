/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

/**
 * Management Dashboard Component
 *
 * Executive SOC summary with strategic metrics, ROI calculations,
 * and risk visibility for leadership.
 */

import { useMemo } from 'react';
import styles from '../Dashboard.module.css';
import { useDashboardStats } from './useDashboardStats';
import { DashboardSection, TrendChart, KpiCard, TimeRangeSelector } from '../Dashboard';
import { LoadingState, ErrorState } from './DashboardStates';
import RecentEventsTable from './RecentEventsTable';
import { usePreferences } from '../../hooks/usePreferences';
import {
  ARIA_LABELS,
  DEFAULT_ROI_CONFIG,
  formatNumber,
  formatPercent,
  formatCurrency
} from './DashboardConfig';

function ManagementDashboard() {
  const {
    stats,
    loading,
    error,
    timeRange,
    setTimeRange,
    getTimeRangeLabel,
    refresh,
    alertTrendData,
    automationTrendData,
    severityDistribution,
    severityTotal,
    criticalCount,
    automationRate,
    recentAlerts
  } = useDashboardStats('90d');

  const { preferences, updateNestedPreference } = usePreferences();

  // ROI configuration with defaults from config
  const roiPrefs = preferences?.roi || {};
  const costPerHour = Number(roiPrefs.costPerHour ?? DEFAULT_ROI_CONFIG.costPerHour);
  const humanActionMins = Number(roiPrefs.humanActionMins ?? DEFAULT_ROI_CONFIG.humanActionMins);
  const automationActionMins = Number(roiPrefs.automationActionMins ?? DEFAULT_ROI_CONFIG.automationActionMins);

  // Memoized ROI calculations
  const roiMetrics = useMemo(() => {
    const actionsExecuted = stats?.ai_impact?.actions_executed || 0;
    const reportedHoursSaved = stats?.ai_impact?.hours_saved || 0;
    const modeledHoursSaved = Math.max(humanActionMins - automationActionMins, 0) * actionsExecuted / 60;
    const estimatedSavings = modeledHoursSaved * costPerHour;
    const speedup = automationActionMins > 0 ? (humanActionMins / automationActionMins) : 0;

    return {
      actionsExecuted,
      reportedHoursSaved,
      modeledHoursSaved,
      estimatedSavings,
      speedup
    };
  }, [stats?.ai_impact, humanActionMins, automationActionMins, costPerHour]);

  // Loading state
  if (loading && !stats) {
    return (
      <div className={styles.dashboardContainer}>
        <LoadingState
          message="Loading executive dashboard..."
          size="medium"
          fullPage
        />
      </div>
    );
  }

  // Error state
  if (error && !stats) {
    return (
      <div className={styles.dashboardContainer}>
        <ErrorState
          error={error}
          title="Unable to Load Dashboard"
          onRetry={refresh}
          retryLabel="Retry"
        />
      </div>
    );
  }

  return (
    <div className={styles.dashboardContainer}>
      {/* Header */}
      <header className={styles.header}>
        <div>
          <h1 className={styles.headerTitle}>Executive SOC Summary</h1>
          <p className={styles.headerSubtitle}>
            Strategic posture • {getTimeRangeLabel()}
          </p>
        </div>
        <div className={styles.headerActions}>
          <TimeRangeSelector
            timeRange={timeRange}
            setTimeRange={setTimeRange}
          />
          <button
            className={styles.refreshButton}
            onClick={refresh}
            aria-label={ARIA_LABELS.refreshButton}
            title="Refresh data"
          >
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M23 4v6h-6" />
              <path d="M1 20v-6h6" />
              <path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15" />
            </svg>
          </button>
        </div>
      </header>

      {/* Error banner (when data exists but refresh failed) */}
      {error && stats && (
        <div className={styles.errorBanner} role="alert">
          <span>Failed to refresh data. Showing cached results.</span>
          <button onClick={refresh}>Retry</button>
        </div>
      )}

      {/* Executive Pulse Section */}
      <DashboardSection title="Executive Pulse" subtitle="High-level KPIs for leadership visibility">
        <div className={styles.kpiRow}>
          <KpiCard
            label="Active Incidents"
            value={formatNumber(stats?.open_investigations || 0)}
            trend={`${stats?.investigation_delta || 0} vs prior`}
            trendDir={(stats?.investigation_delta || 0) >= 0 ? 'up' : 'down'}
            tone="critical"
          />
          <KpiCard
            label="Critical Alerts (24h)"
            value={formatNumber(criticalCount)}
            trend={`${stats?.critical_delta || 0} vs prior`}
            trendDir={(stats?.critical_delta || 0) >= 0 ? 'up' : 'down'}
            tone="high"
          />
          <KpiCard
            label="MTTR"
            value={stats?.mttr?.label || '0m'}
            trend={`${stats?.mttr?.delta || 0}%`}
            trendDir={(stats?.mttr?.delta || 0) <= 0 ? 'down' : 'up'}
            tone="neutral"
          />
          <KpiCard
            label="Automation Rate"
            value={formatPercent(automationRate)}
            trend={`${stats?.automation_delta || 0}%`}
            trendDir={(stats?.automation_delta || 0) >= 0 ? 'up' : 'down'}
            tone="success"
          />
        </div>
      </DashboardSection>

      {/* Risk & Exposure Section */}
      <DashboardSection title="Risk & Exposure" subtitle="Severity mix and volume movement">
        <div className={styles.twoColumn}>
          {/* Severity Mix Card */}
          <div className={styles.card}>
            <div className={styles.cardHeader}>
              <h3>Severity Mix</h3>
              <span>{getTimeRangeLabel()}</span>
            </div>
            <div
              className={styles.severityBar}
              role="img"
              aria-label={ARIA_LABELS.severityBar}
            >
              {['critical', 'high', 'medium', 'low'].map((level) => {
                const count = severityDistribution[level] || 0;
                const pct = severityTotal ? (count / severityTotal) * 100 : 0;
                return (
                  <div
                    key={level}
                    className={`${styles.severitySegment} ${styles[`severity-${level}`]}`}
                    style={{ width: `${pct}%` }}
                    title={`${level}: ${count} (${pct.toFixed(0)}%)`}
                  >
                    {pct >= 8 && (
                      <span className={styles.severitySegmentLabel}>{count}</span>
                    )}
                  </div>
                );
              })}
            </div>
            <div className={styles.severityLegend}>
              {['critical', 'high', 'medium', 'low'].map((level) => (
                <div key={level} className={styles.severityLegendItem}>
                  <span className={`${styles.severityDot} ${styles[`severity-${level}`]}`} />
                  <span className={styles.severityLabel}>{level}</span>
                  <span className={styles.severityValue}>{severityDistribution[level] || 0}</span>
                </div>
              ))}
            </div>
            <div className={styles.trendBlock}>
              <div className={styles.trendBlockHeader}>
                <div className={styles.trendLabel}>Alert volume trend</div>
                <div className={styles.trendValue}>{formatNumber(stats?.total_alerts || 0)} total</div>
              </div>
              <TrendChart data={alertTrendData} dataKey="count" xKey="time" stroke="var(--accent-amber)" />
            </div>
          </div>

          {/* Automation Value Card */}
          <div className={styles.card}>
            <div className={styles.cardHeader}>
              <h3>Automation Value</h3>
              <span>Efficiency gains</span>
            </div>
            <div className={styles.roiConfig}>
              <div className={styles.roiField}>
                <label className={styles.roiLabel} htmlFor="costPerHour">
                  Cost per hour
                </label>
                <div className={styles.roiInputWrap}>
                  <input
                    type="number"
                    id="costPerHour"
                    className={styles.roiInput}
                    value={costPerHour}
                    min={0}
                    step={10}
                    onChange={(event) => updateNestedPreference('roi', 'costPerHour', Number(event.target.value))}
                    aria-label="Cost per hour in USD"
                  />
                  <span className={styles.roiUnit}>USD</span>
                </div>
              </div>
              <div className={styles.roiField}>
                <label className={styles.roiLabel} htmlFor="humanActionMins">
                  Human action avg
                </label>
                <div className={styles.roiInputWrap}>
                  <input
                    type="number"
                    id="humanActionMins"
                    className={styles.roiInput}
                    value={humanActionMins}
                    min={0}
                    step={1}
                    onChange={(event) => updateNestedPreference('roi', 'humanActionMins', Number(event.target.value))}
                    aria-label="Average human action time in minutes"
                  />
                  <span className={styles.roiUnit}>MIN</span>
                </div>
              </div>
              <div className={styles.roiField}>
                <label className={styles.roiLabel} htmlFor="automationActionMins">
                  Automation avg
                </label>
                <div className={styles.roiInputWrap}>
                  <input
                    type="number"
                    id="automationActionMins"
                    className={styles.roiInput}
                    value={automationActionMins}
                    min={0}
                    step={1}
                    onChange={(event) => updateNestedPreference('roi', 'automationActionMins', Number(event.target.value))}
                    aria-label="Average automation time in minutes"
                  />
                  <span className={styles.roiUnit}>MIN</span>
                </div>
              </div>
            </div>
            <div className={styles.impactGrid}>
              <div className={styles.impactMetric}>
                <div className={styles.impactValue}>{formatNumber(roiMetrics.actionsExecuted)}</div>
                <div className={styles.impactLabel}>Automated actions</div>
              </div>
              <div className={styles.impactMetric}>
                <div className={styles.impactValue}>{roiMetrics.reportedHoursSaved}h</div>
                <div className={styles.impactLabel}>Reported hours saved</div>
              </div>
              <div className={styles.impactMetric}>
                <div className={styles.impactValue}>{roiMetrics.modeledHoursSaved.toFixed(1)}h</div>
                <div className={styles.impactLabel}>Modeled hours saved</div>
              </div>
              <div className={styles.impactMetric}>
                <div className={styles.impactValue}>{formatCurrency(roiMetrics.estimatedSavings)}</div>
                <div className={styles.impactLabel}>Estimated savings</div>
              </div>
              <div className={styles.impactMetric}>
                <div className={styles.impactValue}>
                  {roiMetrics.speedup ? `${roiMetrics.speedup.toFixed(1)}x` : '—'}
                </div>
                <div className={styles.impactLabel}>Speedup vs human</div>
              </div>
            </div>
            <div className={styles.trendBlock}>
              <div className={styles.trendBlockHeader}>
                <div className={styles.trendLabel}>AI confidence</div>
                <div className={styles.trendValue}>{formatPercent(stats?.ai_impact?.accuracy_percent || 0)}</div>
              </div>
              <TrendChart data={automationTrendData} dataKey="automated" xKey="date" stroke="var(--accent-green)" />
            </div>
          </div>
        </div>
      </DashboardSection>

      {/* Executive Watchlist Section */}
      <DashboardSection title="Executive Watchlist" subtitle="Critical events requiring leadership awareness">
        <div className={styles.card}>
          <RecentEventsTable
            alerts={recentAlerts}
            emptyMessage={`No critical alerts in ${getTimeRangeLabel().toLowerCase()}`}
            storageKey="dashboardManagementRecentEventsColumns"
          />
        </div>
      </DashboardSection>
    </div>
  );
}

export default ManagementDashboard;
