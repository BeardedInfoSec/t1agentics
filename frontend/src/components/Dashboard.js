/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

/**
 * Dashboard Component
 *
 * Security Operations Center overview dashboard.
 * Displays KPIs, threat activity, analyst workload, and AI impact metrics.
 */

import { useNavigate } from 'react-router-dom';
import {
  LineChart,
  Line,
  AreaChart,
  Area,
  CartesianGrid,
  XAxis,
  YAxis,
  ResponsiveContainer,
  Tooltip,
} from 'recharts';
import Badge from './ui/Badge';
import { severityToBadgeVariant } from '../styles/colors';
import GlobeBackground from './GlobeBackground';
import styles from './Dashboard.module.css';
import { useDashboardStats } from './dashboards/useDashboardStats';
import { LoadingState, ErrorState, EmptyState } from './dashboards/DashboardStates';
import RecentEventsTable from './dashboards/RecentEventsTable';
import {
  TIME_RANGES,
  ARIA_LABELS,
  formatNumber,
  formatPercent
} from './dashboards/DashboardConfig';

/**
 * Dashboard Section Component
 * Reusable section wrapper with title and optional actions
 */
function DashboardSection({ title, subtitle, children, actions }) {
  return (
    <section className={styles.section} aria-labelledby={`section-${title.replace(/\s+/g, '-').toLowerCase()}`}>
      <div className={styles.sectionHeader}>
        <div>
          <h2
            id={`section-${title.replace(/\s+/g, '-').toLowerCase()}`}
            className={styles.sectionTitle}
          >
            {title}
          </h2>
          {subtitle && <p className={styles.sectionSubtitle}>{subtitle}</p>}
        </div>
        {actions && <div className={styles.sectionActions}>{actions}</div>}
      </div>
      <div className={styles.sectionBody}>{children}</div>
    </section>
  );
}

/**
 * Trend Sparkline Component
 * Small inline chart for trend visualization
 */
function TrendSparkline({ data, dataKey = 'value', stroke = 'var(--accent-blue)' }) {
  if (!data || data.length === 0) {
    return <div className={styles.sparkline} aria-hidden="true" />;
  }

  return (
    <div className={styles.sparkline} aria-hidden="true">
      <ResponsiveContainer width="100%" height={56}>
        <LineChart data={data}>
          <Tooltip
            contentStyle={{
              background: 'var(--bg-secondary, rgba(15, 23, 42, 0.95))',
              border: '1px solid var(--border-color, rgba(148, 163, 184, 0.2))',
              borderRadius: 10,
              fontSize: 11,
              color: 'var(--text-primary, #e2e8f0)'
            }}
            itemStyle={{ color: 'var(--text-primary, #e2e8f0)' }}
            labelStyle={{ color: 'var(--text-secondary, rgba(148, 163, 184, 0.9))' }}
          />
          <Line
            type="monotone"
            dataKey={dataKey}
            stroke={stroke}
            strokeWidth={2}
            dot={false}
          />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}

/**
 * Trend Chart Component
 *
 * Full-axis chart used inside Threat Activity / Automation cards. Unlike
 * TrendSparkline, it has gridlines, Y-axis tick values, and date ticks
 * on the X-axis so the line has reference points instead of being a
 * decorative squiggle.
 */
function TrendChart({ data, dataKey = 'value', xKey = 'date', stroke = 'var(--accent-blue)', height = 140, formatXTick }) {
  if (!data || data.length === 0) {
    return (
      <div className={styles.trendChartEmpty} aria-hidden="true">
        No data in selected range
      </div>
    );
  }

  const defaultFormatter = (v) => {
    if (!v) return '';
    const d = new Date(v);
    if (Number.isNaN(d.getTime())) return String(v).slice(0, 6);
    return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
  };

  return (
    <div className={styles.trendChart}>
      <ResponsiveContainer width="100%" height={height}>
        <AreaChart data={data} margin={{ top: 6, right: 8, left: -10, bottom: 0 }}>
          <defs>
            <linearGradient id={`trendChartFill-${dataKey}`} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={stroke} stopOpacity={0.35} />
              <stop offset="100%" stopColor={stroke} stopOpacity={0} />
            </linearGradient>
          </defs>
          <CartesianGrid stroke="rgba(148,163,184,0.12)" strokeDasharray="3 3" vertical={false} />
          <XAxis
            dataKey={xKey}
            stroke="rgba(148,163,184,0.7)"
            tick={{ fontSize: 11 }}
            tickFormatter={formatXTick || defaultFormatter}
            minTickGap={24}
          />
          <YAxis
            stroke="rgba(148,163,184,0.7)"
            tick={{ fontSize: 11 }}
            width={36}
            allowDecimals={false}
          />
          <Tooltip
            contentStyle={{
              background: 'var(--bg-secondary, rgba(15, 23, 42, 0.95))',
              border: '1px solid var(--border-color, rgba(148, 163, 184, 0.2))',
              borderRadius: 10,
              fontSize: 12,
              color: 'var(--text-primary, #e2e8f0)',
            }}
            itemStyle={{ color: 'var(--text-primary, #e2e8f0)' }}
            labelStyle={{ color: 'var(--text-secondary, rgba(148, 163, 184, 0.9))' }}
            labelFormatter={(v) => defaultFormatter(v)}
          />
          <Area
            type="monotone"
            dataKey={dataKey}
            stroke={stroke}
            strokeWidth={2}
            fill={`url(#trendChartFill-${dataKey})`}
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}

/**
 * SLA Card Component
 *
 * Renders one SLA dimension (ack or close) — compliance %, breach count,
 * and per-severity target vs met rows. Visually consistent with KpiCard
 * but expanded so analysts can see *where* breaches concentrate.
 */
function SLACard({ kind, sla, onBreachClick }) {
  const isAck = kind === 'ack';
  const title = isAck ? 'Response SLA' : 'Resolution SLA';
  const subtitle = isAck ? 'Time to acknowledge' : 'Time to close';
  const compliance = isAck ? sla?.ack_compliance_pct : sla?.close_compliance_pct;
  const breaches = isAck ? sla?.ack_breaches : sla?.close_breaches;
  const targetKey = isAck ? 'ack_target_minutes' : 'close_target_minutes';
  const metKey = isAck ? 'ack_met' : 'close_met';
  const pctKey = isAck ? 'ack_compliance_pct' : 'close_compliance_pct';

  const tone = compliance == null
    ? 'neutral'
    : compliance >= 90 ? 'success'
    : compliance >= 75 ? 'info'
    : 'critical';

  const formatTarget = (mins) => {
    if (mins == null) return '—';
    if (mins < 60) return `${mins}m`;
    if (mins < 1440) return `${Math.round(mins / 60)}h`;
    return `${Math.round(mins / 1440)}d`;
  };

  return (
    <div className={`${styles.card} ${styles.slaCard} ${styles[`sla-${tone}`]}`}>
      <div className={styles.cardHeader}>
        <h3>{title}</h3>
        <span>{subtitle}</span>
      </div>
      <div className={styles.slaHeadline}>
        <div className={styles.slaPct}>
          {compliance == null ? '—' : `${compliance}%`}
        </div>
        <button
          type="button"
          className={`${styles.slaBreaches} ${breaches > 0 ? styles.slaBreachesActive : ''}`}
          onClick={onBreachClick}
          disabled={!breaches}
          title={breaches ? `View ${breaches} breached items` : 'No breaches in range'}
        >
          {breaches || 0} breach{breaches === 1 ? '' : 'es'}
        </button>
      </div>
      <div className={styles.slaTable} role="table" aria-label={`${title} by severity`}>
        <div className={styles.slaTableHead} role="row">
          <span role="columnheader">Severity</span>
          <span role="columnheader">Target</span>
          <span role="columnheader">Met / Closed</span>
          <span role="columnheader">Compliance</span>
        </div>
        {(sla?.by_severity || []).map((row) => (
          <div key={row.severity} className={styles.slaTableRow} role="row">
            <span role="cell">
              <span className={`${styles.severityDot} ${styles[`severity-${row.severity}`]}`} />
              {row.severity}
            </span>
            <span role="cell">{formatTarget(row[targetKey])}</span>
            <span role="cell">{row[metKey]} / {row.closed}</span>
            <span role="cell" className={
              row[pctKey] == null ? styles.slaCellMuted :
              row[pctKey] >= 90 ? styles.slaCellGood :
              row[pctKey] >= 75 ? styles.slaCellWarn :
              styles.slaCellBad
            }>
              {row[pctKey] == null ? '—' : `${row[pctKey]}%`}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

/**
 * KPI Card Component
 * Displays a key performance indicator with optional trend
 */
function KpiCard({ label, value, trend, trendDir = 'up', tone = 'neutral', onClick }) {
  const getTrendIcon = () => {
    if (trendDir === 'up') return '\u2191';
    if (trendDir === 'down') return '\u2193';
    return '\u2022';
  };

  const Tag = onClick ? 'button' : 'div';

  return (
    <Tag
      className={`${styles.kpiCard} ${styles[`kpi-${tone}`]} ${onClick ? styles.kpiClickable : ''}`}
      role="group"
      aria-label={ARIA_LABELS.kpiCard(label)}
      onClick={onClick}
      title={onClick ? `View ${label.toLowerCase()} in queue` : undefined}
    >
      <div className={styles.kpiLabel}>{label}</div>
      <div className={styles.kpiValue}>{value}</div>
      {trend && (
        <div className={`${styles.kpiTrend} ${styles[`trend-${trendDir}`]}`}>
          <span aria-hidden="true">{getTrendIcon()}</span>
          <span>{trend}</span>
        </div>
      )}
    </Tag>
  );
}

/**
 * Time Range Selector Component
 * Buttons for selecting dashboard time range
 */
function TimeRangeSelector({ timeRange, setTimeRange, ranges = TIME_RANGES }) {
  return (
    <div
      className={styles.timeRangeContainer}
      role="group"
      aria-label={ARIA_LABELS.timeRangeSelector}
    >
      {Object.entries(ranges).map(([key, config]) => (
        <button
          key={key}
          onClick={() => setTimeRange(key)}
          className={`${styles.timeRangeButton} ${timeRange === key ? styles.active : ''}`}
          aria-pressed={timeRange === key}
          aria-label={config.label}
        >
          {config.label}
        </button>
      ))}
    </div>
  );
}

/**
 * Main Dashboard Component
 */
function DashboardImproved() {
  const navigate = useNavigate();
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
    automationManualSplit,
    analystLoad,
    recentAlerts
  } = useDashboardStats('30d');

  // Loading state
  if (loading && !stats) {
    return (
      <div className={styles.dashboardContainer}>
        <LoadingState
          message="Loading dashboard..."
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
    <div className={styles.dashboardContainer} style={{ position: 'relative', overflow: 'hidden' }}>
      {/* Animated Globe Background */}
      <GlobeBackground size={600} opacity={0.3} />

      {/* Header */}
      <header className={styles.header} style={{ position: 'relative', zIndex: 1 }}>
        <div>
          <h1 className={styles.headerTitle}>Security Operations Center</h1>
          <p className={styles.headerSubtitle}>
            Real-time threat posture • {getTimeRangeLabel()}
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

      {/* SOC Health Snapshot */}
      <DashboardSection
        title="SOC Health Snapshot"
        subtitle="High-level operational signal for rapid triage"
      >
        <div className={styles.kpiRow} data-tour="dashboard-kpis">
          <KpiCard
            label="Active Incidents"
            value={formatNumber(stats?.open_investigations || 0)}
            trend={`${stats?.investigation_delta || 0} vs prior`}
            trendDir={(stats?.investigation_delta || 0) >= 0 ? 'up' : 'down'}
            tone="critical"
            onClick={() => navigate('/investigations')}
          />
          <KpiCard
            label="Critical Alerts (24h)"
            value={formatNumber(criticalCount)}
            trend={`${stats?.critical_delta || 0} vs prior`}
            trendDir={(stats?.critical_delta || 0) >= 0 ? 'up' : 'down'}
            tone="high"
            onClick={() => navigate('/events?severity=critical')}
          />
          <KpiCard
            label="Automation Rate"
            value={formatPercent(automationRate)}
            trend={`${stats?.automation_delta || 0}%`}
            trendDir={(stats?.automation_delta || 0) >= 0 ? 'up' : 'down'}
            tone="success"
          />
          <KpiCard
            label="MTTR"
            value={stats?.mttr?.label || '0m'}
            trend={`${stats?.mttr?.delta || 0}%`}
            trendDir={(stats?.mttr?.delta || 0) <= 0 ? 'down' : 'up'}
            tone="neutral"
          />
          <KpiCard
            label="AI Confidence"
            value={formatPercent(stats?.ai_impact?.accuracy_percent || 0)}
            trend={`${stats?.ai_impact?.confidence_delta || 0}%`}
            trendDir={(stats?.ai_impact?.confidence_delta || 0) >= 0 ? 'up' : 'down'}
            tone="info"
          />
        </div>
      </DashboardSection>

      {/* Threat & Workload Overview */}
      <DashboardSection
        title="Threat & Workload Overview"
        subtitle="Threat activity on the left, analyst load on the right"
      >
        <div className={styles.twoColumn}>
          {/* Threat Activity Card */}
          <div className={styles.card} data-tour="dashboard-threats">
            <div className={styles.cardHeader}>
              <h3>Threat Activity</h3>
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
                    style={{ width: `${pct}%`, cursor: 'pointer' }}
                    title={`${level}: ${count} (${pct.toFixed(0)}%) - Click to view`}
                    onClick={() => navigate(`/events?severity=${level}`)}
                    role="button"
                    tabIndex={0}
                    onKeyDown={(e) => e.key === 'Enter' && navigate(`/events?severity=${level}`)}
                  >
                    {pct >= 8 && (
                      <span className={styles.severitySegmentLabel}>
                        {count}
                      </span>
                    )}
                  </div>
                );
              })}
            </div>
            <div className={styles.severityLegend}>
              {['critical', 'high', 'medium', 'low'].map((level) => (
                <button
                  key={level}
                  className={styles.severityLegendItem}
                  onClick={() => navigate(`/events?severity=${level}`)}
                  title={`View ${level} alerts`}
                >
                  <span className={`${styles.severityDot} ${styles[`severity-${level}`]}`} />
                  <span className={styles.severityLabel}>{level}</span>
                  <span className={styles.severityValue}>{severityDistribution[level] || 0}</span>
                </button>
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

          {/* Analyst Load Card */}
          <div className={styles.card} data-tour="dashboard-workload">
            <div className={styles.cardHeader}>
              <h3>Analyst Load</h3>
              <span>Current workload</span>
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
        </div>
      </DashboardSection>

      {/* Service Level Agreements */}
      <DashboardSection
        title="Service Level Agreements"
        subtitle={`Response and resolution targets • ${getTimeRangeLabel()}`}
      >
        <div className={styles.twoColumn}>
          <SLACard
            kind="ack"
            sla={stats?.sla}
            onBreachClick={() => navigate('/queue?sla=exceeded')}
          />
          <SLACard
            kind="close"
            sla={stats?.sla}
            onBreachClick={() => navigate('/queue?sla=exceeded')}
          />
        </div>
      </DashboardSection>

      {/* Automation & AI Impact */}
      <DashboardSection
        title="Automation & AI Impact"
        subtitle="Compact view of savings and confidence"
      >
        <div className={`${styles.card} ${styles.compactImpact}`}>
          <div className={styles.compactImpactGrid}>
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
          <div className={styles.compactImpactTrend}>
            <div className={styles.trendBlockHeader}>
              <div className={styles.trendLabel}>Automation trend</div>
              <div className={styles.trendValue}>
                {formatNumber(stats?.ai_impact?.alerts_auto_closed || 0)} auto-closed
              </div>
            </div>
            <TrendChart
              data={automationTrendData}
              dataKey="automated"
              xKey="date"
              stroke="var(--accent-green)"
            />
          </div>
        </div>
      </DashboardSection>

      {/* Recent Critical Events */}
      <DashboardSection
        title="Recent Critical Events"
        subtitle="Latest high-severity activity requiring review"
      >
        <div className={styles.card}>
          <RecentEventsTable
            alerts={recentAlerts}
            emptyMessage={`No critical alerts in ${getTimeRangeLabel().toLowerCase()}`}
            storageKey="dashboardOverviewRecentEventsColumns"
          />
        </div>
      </DashboardSection>
    </div>
  );
}

export default DashboardImproved;
export { DashboardSection, TrendSparkline, TrendChart, KpiCard, TimeRangeSelector };
export { generateAutomationData, getRecentAlerts } from './dashboards/dashboardUtils';
