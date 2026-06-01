/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

/**
 * Operations Dashboard Component
 *
 * Analyst workflow view with workload metrics, queue distribution,
 * and automation health indicators.
 */

import styles from '../Dashboard.module.css';
import { useDashboardStats } from './useDashboardStats';
import { DashboardSection, TrendChart, KpiCard, TimeRangeSelector } from '../Dashboard';
import { LoadingState, ErrorState } from './DashboardStates';
import { ARIA_LABELS, formatNumber, formatPercent } from './DashboardConfig';
import RecentEventsTable from './RecentEventsTable';

function OperationsDashboard() {
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
    automationRate,
    automationManualSplit,
    analystLoad,
    recentAlerts
  } = useDashboardStats('7d');

  // Loading state
  if (loading && !stats) {
    return (
      <div className={styles.dashboardContainer}>
        <LoadingState
          message="Loading operations dashboard..."
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
          <h1 className={styles.headerTitle}>SOC Operations</h1>
          <p className={styles.headerSubtitle}>
            Analyst workflow view • {getTimeRangeLabel()}
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

      {/* Triage Now Section */}
      <DashboardSection title="Triage Now" subtitle="Immediate workload and manual pressure">
        <div className={styles.kpiRow}>
          <KpiCard
            label="Total Alerts"
            value={formatNumber(stats?.total_alerts || 0)}
            trend={`${stats?.alert_delta || 0} vs prior`}
            trendDir={(stats?.alert_delta || 0) >= 0 ? 'up' : 'down'}
            tone="info"
          />
          <KpiCard
            label="Open Investigations"
            value={formatNumber(stats?.open_investigations || 0)}
            trend={`${stats?.investigation_delta || 0} vs prior`}
            trendDir={(stats?.investigation_delta || 0) >= 0 ? 'up' : 'down'}
            tone="critical"
          />
          <KpiCard
            label="Manual Workload"
            value={formatNumber(automationManualSplit.manual)}
            trend={automationManualSplit.manual > 0 ? 'Needs review' : 'Stable'}
            trendDir={automationManualSplit.manual > 0 ? 'up' : 'flat'}
            tone="high"
          />
          <KpiCard
            label="Automation Coverage"
            value={formatPercent(automationRate)}
            trend={`${stats?.automation_delta || 0}%`}
            trendDir={(stats?.automation_delta || 0) >= 0 ? 'up' : 'down'}
            tone="success"
          />
        </div>
      </DashboardSection>

      {/* Volume Trend Section */}
      <DashboardSection title="Volume Trend" subtitle="Alert volume movement over time">
        <div className={styles.card}>
          <div className={styles.cardHeader}>
            <h3>Alert Flow</h3>
            <span>{getTimeRangeLabel()}</span>
          </div>
          <div className={styles.trendBlock}>
            <div className={styles.trendBlockHeader}>
              <div className={styles.trendLabel}>Alert volume trend</div>
              <div className={styles.trendValue}>{formatNumber(stats?.total_alerts || 0)} total</div>
            </div>
            <TrendChart data={alertTrendData} dataKey="count" xKey="time" stroke="var(--accent-amber)" />
          </div>
        </div>
      </DashboardSection>

      {/* Queue Distribution Section */}
      <DashboardSection title="Queue Distribution" subtitle="Where analyst effort is going">
        <div className={styles.twoColumn}>
          {/* Investigation Status Card */}
          <div className={styles.card}>
            <div className={styles.cardHeader}>
              <h3>Investigation Status</h3>
              <span>Open workload</span>
            </div>
            <div className={styles.loadGrid}>
              {Object.entries(analystLoad).map(([status, count]) => (
                <div key={status} className={styles.loadTile}>
                  <div className={styles.loadValue}>{formatNumber(count)}</div>
                  <div className={styles.loadLabel}>{status.replace(/_/g, ' ')}</div>
                </div>
              ))}
            </div>
            <div className={styles.splitRow}>
              <div className={styles.splitItem}>
                <div className={styles.splitLabel}>Automated</div>
                <div className={styles.splitValue}>{formatNumber(automationManualSplit.automated)}</div>
              </div>
              <div className={styles.splitItem}>
                <div className={styles.splitLabel}>Manual</div>
                <div className={styles.splitValue}>{formatNumber(automationManualSplit.manual)}</div>
              </div>
            </div>
          </div>

          {/* Automation Health Card */}
          <div className={styles.card}>
            <div className={styles.cardHeader}>
              <h3>Automation Health</h3>
              <span>Confidence over time</span>
            </div>
            <div className={styles.impactGrid}>
              <div className={styles.impactMetric}>
                <div className={styles.impactValue}>{formatNumber(stats?.ai_impact?.alerts_auto_closed || 0)}</div>
                <div className={styles.impactLabel}>Auto-closed</div>
              </div>
              <div className={styles.impactMetric}>
                <div className={styles.impactValue}>{stats?.ai_impact?.hours_saved || 0}h</div>
                <div className={styles.impactLabel}>Hours saved</div>
              </div>
              <div className={styles.impactMetric}>
                <div className={styles.impactValue}>{formatPercent(stats?.ai_impact?.accuracy_percent || 0)}</div>
                <div className={styles.impactLabel}>AI confidence</div>
              </div>
            </div>
            <div className={styles.trendBlock}>
              <div className={styles.trendBlockHeader}>
                <div className={styles.trendLabel}>Automation trend</div>
                <div className={styles.trendValue}>{formatPercent(automationRate)} coverage</div>
              </div>
              <TrendChart data={automationTrendData} dataKey="automated" xKey="date" stroke="var(--accent-green)" />
            </div>
          </div>
        </div>
      </DashboardSection>

      {/* Recent Critical Events Section */}
      <DashboardSection title="Recent Critical Events" subtitle="Latest high-severity activity">
        <div className={styles.card}>
          <RecentEventsTable
            alerts={recentAlerts}
            emptyMessage={`No critical alerts in ${getTimeRangeLabel().toLowerCase()}`}
            storageKey="dashboardOperationsRecentEventsColumns"
          />
        </div>
      </DashboardSection>
    </div>
  );
}

export default OperationsDashboard;
