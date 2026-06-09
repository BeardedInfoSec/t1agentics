/**
/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

import React, { useState, useEffect, Suspense } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate, useLocation } from 'react-router-dom';
import { useMediaQuery } from './hooks/useMediaQuery';
import SlideOutNav from './components/SlideOutNav';
import TopBar from './components/TopBar';
import GuidedTour from './components/GuidedTour';
import Dashboard from './components/Dashboard';
import AlertViewer from './components/AlertViewer';
import InvestigationsList from './components/InvestigationsList';
import { SecurityQueue } from './components/SecurityQueue';
import NewInvestigation from './components/NewInvestigation';
import Login from './components/Login';
import TenantSelect from './components/TenantSelect';
import RBACManagement from './components/RBACManagement';
import IOCCenter from './components/IOCCenter';
import IOCDetail from './components/IOCDetail';
import ThreatFeeds from './components/ThreatFeeds';
import EDLManagement from './components/EDLManagement';
import GlobalSearch from './components/GlobalSearch';
import Settings from './components/Settings';
import UserProfile from './components/UserProfile';
import ForgotPassword from './components/ForgotPassword';
import ResetPassword from './components/ResetPassword';
import ChangePassword from './components/ChangePassword';
import Breadcrumb from './components/Breadcrumb';
import ErrorBoundary from './components/ErrorBoundary';
import { PreferencesProvider, usePreferences } from './hooks/usePreferences';
import { KeyboardShortcutsProvider } from './hooks/useKeyboardShortcuts';
import { ToastProvider } from './components/ui/Toast';
import { clearLicenseCache } from './utils/licenseCache';
import { telemetry } from './utils/telemetry';
import { TourProvider } from './components/tours/TourContext';
import { PLATFORM_OWNER_TENANT_ID } from './config/platform';
import './App.css';

const OnboardingWizard = React.lazy(() => import('./components/onboarding/OnboardingWizard'));
const RiggsClippy = React.lazy(() => import('./components/riggs/RiggsClippy'));
const FeatureTourManager = React.lazy(() => import('./components/tours/FeatureTourManager'));

const AdminDashboard = React.lazy(() => import('./components/AdminDashboard'));
const Connect = React.lazy(() => import('./components/Connect/Connect'));
const AgentOperationsCenter = React.lazy(() => import('./components/AgentOperationsCenter'));
const CollectorManager = React.lazy(() => import('./components/CollectorManager'));
const KnowledgeBase = React.lazy(() => import('./components/KnowledgeBase'));
const ActionApprovals = React.lazy(() => import('./components/ActionApprovals'));
const InvestigationWorkbenchV2 = React.lazy(() => import('./components/InvestigationWorkbenchV2'));
const ManagementDashboard = React.lazy(() => import('./components/dashboards/ManagementDashboard'));
const OperationsDashboard = React.lazy(() => import('./components/dashboards/OperationsDashboard'));
const IntakeFormsList = React.lazy(() => import('./components/IntakeFormsList'));
const IntakeFormsEditor = React.lazy(() => import('./components/IntakeFormsEditor'));
const IntakeFormSubmit = React.lazy(() => import('./components/IntakeFormSubmit'));
import AssetInventory from './components/AssetInventory';
import InboundEmailIntegration from './components/InboundEmailIntegration';
import PostResolution from './components/PostResolution';

const WorkflowStudio = React.lazy(() => import('./components/WorkflowStudio/WorkflowStudio'));
// RiggsStudio is the unified Playbooks hub: it renders a single page with
// internal tabs for My Playbooks, Build with Riggs, Marketplace, Import,
// and Intelligence. The four playbook routes below all render RiggsStudio,
// which picks the right tab from the URL so deep-links and back/forward
// keep working.
const RiggsStudio = React.lazy(() => import('./components/RiggsStudio/RiggsStudio'));
const PlatformAdminDashboard = React.lazy(() => import('./components/PlatformAdmin/PlatformAdminDashboard'));
const InteractiveApiDocs = React.lazy(() => import('./pages/InteractiveApiDocs'));
const BreachIntelDashboard = React.lazy(() => import('./components/BreachIntel/BreachIntelDashboard'));

// Unauthenticated auth pages (lazy loaded). The marketing/demo website was
// removed for the open-source self-hosted build; the only pages reachable
// while logged out are login/register/verify-email/forgot-password/reset.
const RegisterPage = React.lazy(() => import('./pages/public/RegisterPage'));
const VerifyEmailPage = React.lazy(() => import('./pages/public/VerifyEmailPage'));

// Prefetch all lazy chunks after login so navigation feels instant.
// Each import() is cached by webpack -- subsequent React.lazy renders
// resolve immediately from the module cache with no spinner.
function prefetchAppChunks() {
  const delay = (ms) => new Promise((r) => setTimeout(r, ms));

  // Stagger imports so we don't saturate the connection all at once.
  // Priority 1: pages the user is most likely to visit first
  const p1 = [
    () => import('./components/SecurityQueue'),
    () => import('./components/Dashboard'),
    () => import('./components/InvestigationWorkbenchV2'),
    () => import('./components/SlideOutNav'),
    () => import('./components/TopBar'),
  ];
  // Priority 2: common app pages
  const p2 = [
    () => import('./components/Connect/Connect'),
    () => import('./components/IOCCenter'),
    () => import('./components/KnowledgeBase'),
    () => import('./components/WorkflowStudio/WorkflowStudio'),
    () => import('./components/RiggsStudio/RiggsStudio'),
    () => import('./components/PlaybookMarketplace'),
    () => import('./components/dashboards/ManagementDashboard'),
    () => import('./components/dashboards/OperationsDashboard'),
    () => import('./components/AgentOperationsCenter'),
    () => import('./components/ActionApprovals'),
    () => import('./components/BreachIntel/BreachIntelDashboard'),
  ];
  // Priority 3: less-frequent pages + admin
  const p3 = [
    () => import('./components/AdminDashboard'),
    () => import('./components/PlatformAdmin/PlatformAdminDashboard'),
    () => import('./components/CollectorManager'),
    () => import('./pages/PlaybookConverterCodex'),
    () => import('./pages/InteractiveApiDocs'),
    () => import('./components/onboarding/OnboardingWizard'),
    () => import('./components/riggs/RiggsClippy'),
    () => import('./components/tours/FeatureTourManager'),
  ];

  // Fire priority 1 immediately, then stagger the rest
  p1.forEach((fn) => fn());
  delay(1000).then(() => p2.forEach((fn) => fn()));
  delay(3000).then(() => p3.forEach((fn) => fn()));
}

/**
 * LegacyQueueRedirect
 *
 * Forwards legacy routes (/events, /alerts, /investigations) to /queue while
 * preserving any incoming query string. Plain <Navigate to="/queue"> drops
 * the search portion, which breaks every dashboard drill-in that passes
 * filters like ?severity=critical or ?sla=exceeded.
 */
function LegacyQueueRedirect({ view }) {
  const location = useLocation();
  const params = new URLSearchParams(location.search);
  // Only set view if the incoming URL didn't already specify one — that way
  // an explicit ?view=investigations still wins over the route's default.
  if (view && !params.has('view')) {
    params.set('view', view);
  }
  const qs = params.toString();
  return <Navigate to={qs ? `/queue?${qs}` : '/queue'} replace />;
}

function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [navCollapsed, setNavCollapsed] = useState(false);
  const [forcePasswordReset, setForcePasswordReset] = useState(false);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  // Initialize UX telemetry tracker
  useEffect(() => { telemetry.start(); return () => telemetry.destroy(); }, []);

  // Check server session on mount
  useEffect(() => {
    let mounted = true;
    const checkSession = async () => {
      try {
        const res = await fetch('/api/v1/users/me');
        if (res.ok) {
          const data = await res.json();
          if (mounted) {
            setIsAuthenticated(true);
            setUser({ username: data.username, role: data.role, license_tier: data.license_tier, tenant_id: data.tenant_id });
            prefetchAppChunks();
          }
        } else {
          if (mounted) {
            setIsAuthenticated(false);
            setUser(null);
          }
        }
      } catch {
        if (mounted) {
          setIsAuthenticated(false);
          setUser(null);
        }
      } finally {
        if (mounted) setLoading(false);
      }
    };

    checkSession();
    return () => {
      mounted = false;
    };
  }, []);

  const handleLogin = (loginData) => {
    setIsAuthenticated(true);
    setUser({
      username: loginData.username,
      role: loginData.role,
      license_tier: loginData.license_tier,
      tenant_id: loginData.tenant_id
    });
    setForcePasswordReset(!!loginData.force_password_reset);
    prefetchAppChunks();
  };

  const handlePasswordChanged = () => {
    setForcePasswordReset(false);
  };

  const handleLogout = async () => {
    try {
      await fetch('/api/v1/admin/logout', { method: 'POST' });
    } catch {
      // ignore logout errors
    }
    clearLicenseCache();
    setIsAuthenticated(false);
    setUser(null);
    setForcePasswordReset(false);
  };

  if (loading) {
    return (
      <div className="loading-container">
        <img
          src="/riggs_investigating.png"
          alt="Loading"
          style={{ width: '100px', height: 'auto', marginBottom: '16px', opacity: 0.85, animation: 'riggsPulse 2s ease-in-out infinite' }}
        />
        <p className="ds-text-secondary">Loading T1 Agentics...</p>
        <style>{`@keyframes riggsPulse { 0%,100% { transform: scale(1); opacity: 0.85; } 50% { transform: scale(1.05); opacity: 1; } }`}</style>
      </div>
    );
  }

  // Force password change screen (must be authenticated)
  if (isAuthenticated && forcePasswordReset) {
    return (
      <ChangePassword
        user={user}
        onPasswordChanged={handlePasswordChanged}
        onLogout={handleLogout}
      />
    );
  }

  // If authenticated, show the full app
  if (isAuthenticated) {
    return (
      <PreferencesProvider>
        <TourProvider>
        <ToastProvider>
        <Router future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
          <KeyboardShortcutsProvider>
            <Suspense fallback={<div className="loading-container"><div className="spinner"></div></div>}>
              <Routes>
                {/* Auth pages redirect to dashboard when logged in */}
                <Route path="/register" element={<Navigate to="/dashboard" replace />} />
                <Route path="/verify-email" element={<Navigate to="/dashboard" replace />} />
                <Route path="/login" element={<Navigate to="/dashboard" replace />} />
                <Route path="/select-org" element={<Navigate to="/dashboard" replace />} />

                {/* Platform admin - admin/platform_owner role + platform owner tenant required */}
                {(user?.role === 'admin' || user?.role === 'platform_owner') && user?.tenant_id === PLATFORM_OWNER_TENANT_ID ? (
                  <Route path="/platform-admin" element={<PlatformAdminDashboard />} />
                ) : (
                  <Route path="/platform-admin" element={<Navigate to="/dashboard" replace />} />
                )}

                {/* Intake form submission — bare layout for end users. Renders
                    outside AppShell so non-SOC tenant users don't see the
                    Dashboards / Triage / Playbooks chrome when they land
                    here to submit something to security. */}
                <Route path="/intake/:slug" element={<IntakeFormSubmit />} />

                {/* Authenticated app shell */}
                <Route path="/*" element={
                  <AppShellWithThemeToggle
                    user={user}
                    navCollapsed={navCollapsed}
                    onToggleNav={() => setNavCollapsed(!navCollapsed)}
                    onLogout={handleLogout}
                    mobileMenuOpen={mobileMenuOpen}
                    setMobileMenuOpen={setMobileMenuOpen}
                  />
                } />
              </Routes>
            </Suspense>
          </KeyboardShortcutsProvider>
        </Router>
        </ToastProvider>
        </TourProvider>
      </PreferencesProvider>
    );
  }

  // Not authenticated - show bare auth pages only (no marketing chrome)
  return (
    <Router future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
      <Suspense fallback={<div className="loading-container"><div className="spinner"></div></div>}>
        <Routes>
          {/* Auth pages — always available */}
          <Route path="/login" element={<Login onLogin={handleLogin} />} />
          <Route path="/select-org" element={<TenantSelect />} />
          <Route path="/forgot-password" element={<ForgotPassword />} />
          <Route path="/reset-password" element={<ResetPassword />} />
          <Route path="/platform-admin" element={<Navigate to="/login" replace />} />
          <Route path="/register" element={<RegisterPage />} />
          <Route path="/verify-email" element={<VerifyEmailPage />} />

          {/* No public landing page anymore — send everything else to login */}
          <Route path="*" element={<Navigate to="/login" replace />} />
        </Routes>
      </Suspense>
    </Router>
  );
}

// Wrapper to handle theme toggle from keyboard shortcuts
function AppShellWithThemeToggle(props) {
  const { preferences, updatePreference } = usePreferences();

  useEffect(() => {
    const handleToggleTheme = () => {
      const currentTheme = preferences.theme || 'dark';
      const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
      telemetry.track('ui', 'ui.theme_change', { theme: newTheme });
      updatePreference('theme', newTheme);
    };

    window.addEventListener('toggleTheme', handleToggleTheme);
    return () => window.removeEventListener('toggleTheme', handleToggleTheme);
  }, [preferences.theme, updatePreference]);

  return <AppShell {...props} />;
}

function AppShell({ user, navCollapsed, onToggleNav, onLogout, mobileMenuOpen, setMobileMenuOpen }) {
  const location = useLocation();
  const isMobile = useMediaQuery('(max-width: 768px)');
  const isPlaybookEditorRoute =
    location.pathname.startsWith('/playbooks/') &&
    !['/playbooks', '/playbooks/import-soar', '/playbooks/intelligence'].includes(location.pathname);
  const mainClass = `app-main ${isMobile ? 'app-main--mobile' : (!isPlaybookEditorRoute && navCollapsed ? 'nav-collapsed' : '')} ${isPlaybookEditorRoute ? 'app-main--full' : ''}`;
  const contentClass = `app-content ${isPlaybookEditorRoute ? 'app-content--full' : ''}`;
  const containerClass = `app-container ${isPlaybookEditorRoute ? 'app-container--full' : ''}`;

  return (
    <div className={containerClass}>
      {/* Skip-to-content link for keyboard/screen-reader users */}
      <a href="#main-content" className="skip-to-content">
        Skip to main content
      </a>

      {/* Top Bar */}
      {!isPlaybookEditorRoute && (
        <TopBar
          user={user}
          onLogout={onLogout}
          isMobile={isMobile}
          onToggleMobileMenu={() => setMobileMenuOpen(prev => !prev)}
        />
      )}

      {/* In-product guided tour. Lives at the app-shell level so it can
          spotlight sidebar + topbar + page content from the same overlay. */}
      <GuidedTour />

      {/* Breach Intel ticker moved into the topbar (TopBar.js → TopBarTicker).
          The legacy full-width bar below the topbar is removed to recover
          screen real estate. */}

      {/* Left Slide-Out Navigation */}
      {!isPlaybookEditorRoute && (
        <SlideOutNav
          collapsed={navCollapsed}
          onToggle={onToggleNav}
          user={user}
          mobileOpen={mobileMenuOpen}
          onMobileClose={() => setMobileMenuOpen(false)}
        />
      )}

      {/* Main Content */}
      <main id="main-content" className={mainClass} role="main">
        {/* Breadcrumb Navigation */}
        {!isPlaybookEditorRoute && <Breadcrumb />}

        {/* Page Content */}
        <div className={contentClass}>
          <ErrorBoundary message="This page encountered an error. Try navigating to a different page or refresh.">
            <Suspense fallback={
              <div className="loading-container">
                <img src="/riggs_investigating.png" alt="Loading" style={{ width: '80px', height: 'auto', marginBottom: '12px', opacity: 0.8 }} />
                <p className="ds-text-secondary">Riggs is on it...</p>
              </div>
            }>
              <Routes>
            <Route path="/" element={<Navigate to="/queue" replace />} />
            <Route path="/dashboard" element={<Dashboard />} />
            <Route path="/dashboard/overview" element={<Dashboard />} />
            <Route path="/dashboard/management" element={<ManagementDashboard />} />
            <Route path="/dashboard/operations" element={<OperationsDashboard />} />
            <Route path="/workbench" element={<AgentOperationsCenter />} />
            <Route path="/workbench/approvals" element={<ActionApprovals />} />
            {/* Triage - Unified view for alerts and investigations */}
            <Route path="/queue" element={<SecurityQueue defaultViewMode="all" />} />
            {/* Legacy routes - forward to unified queue while preserving query
                string and mapping the legacy path to a view= filter. Plain
                Navigate drops the query, breaking dashboard drill-in. */}
            <Route path="/events" element={<LegacyQueueRedirect view="alerts" />} />
            <Route path="/alerts" element={<LegacyQueueRedirect view="alerts" />} />
            <Route path="/investigations" element={<LegacyQueueRedirect view="investigations" />} />
            <Route path="/search" element={<GlobalSearch />} />
            <Route path="/investigation/:id" element={<InvestigationWorkbenchV2 />} />
            <Route path="/investigate" element={<NewInvestigation />} />
            <Route path="/threat-intel" element={<IOCCenter />} />
            <Route path="/threat-intel/iocs" element={<IOCCenter />} />
            <Route path="/threat-intel/database" element={<IOCCenter />} />
            <Route path="/threat-intel/lookup" element={<IOCCenter />} />
            <Route path="/threat-intel/submit" element={<IOCCenter />} />
            <Route path="/threat-intel/whitelist" element={<IOCCenter />} />
            <Route path="/threat-intel/feeds" element={<ThreatFeeds />} />
            <Route path="/threat-intel/edl" element={<EDLManagement />} />
            <Route path="/threat-intel/:iocValue" element={<IOCDetail />} />
            {/* Breach Intelligence */}
            <Route path="/breach-intel" element={<BreachIntelDashboard />} />
            {/* Legacy routes - redirect to new paths */}
            <Route path="/ioc-center" element={<Navigate to="/threat-intel" replace />} />
            <Route path="/ioc/:iocValue" element={<IOCDetail />} />
            <Route path="/knowledge-base" element={<KnowledgeBase user={user} />} />
            {/* Playbooks Hub - all five entries render RiggsStudio, which
                picks its internal tab from the URL. Adds /playbooks/intelligence
                as a new deep-link target for the Intelligence tab. */}
            <Route path="/playbooks" element={<RiggsStudio />} />
            <Route path="/playbook-marketplace" element={<RiggsStudio />} />
            <Route path="/automation-studio" element={<RiggsStudio />} />
            <Route path="/playbooks/import-soar" element={<RiggsStudio />} />
            <Route path="/playbooks/intelligence" element={<RiggsStudio />} />
            {/* Workflow Studio editor routes stay standalone (full-screen
                editor mode preserved by AppShell isPlaybookEditorRoute). */}
            <Route path="/playbooks/new" element={<WorkflowStudio />} />
            <Route path="/playbooks/:id" element={<WorkflowStudio />} />
            <Route path="/assets" element={<AssetInventory />} />
            <Route path="/collectors" element={<CollectorManager />} />
            <Route path="/alert-tuning" element={<Navigate to="/settings" replace />} />
            <Route path="/profile" element={<UserProfile user={user} onLogout={onLogout} />} />
            <Route path="/connect" element={<Connect user={user} />} />
            <Route path="/integrations" element={<Navigate to="/connect" replace />} />
            <Route path="/integrations/inbound-email" element={<InboundEmailIntegration />} />
            <Route path="/phishing-reports" element={<Navigate to="/integrations/inbound-email" replace />} />
            <Route path="/api-docs/interactive" element={<InteractiveApiDocs />} />
            {(user?.role === 'admin' || user?.role === 'platform_owner') && (
              <>
                <Route path="/admin" element={<AdminDashboard />} />
                <Route path="/admin/rbac" element={<RBACManagement />} />
                <Route path="/admin/post-resolution" element={<PostResolution />} />
                <Route path="/admin/intake-forms" element={<IntakeFormsList />} />
                <Route path="/admin/intake-forms/new" element={<IntakeFormsEditor />} />
                <Route path="/admin/intake-forms/:id" element={<IntakeFormsEditor />} />
                <Route path="/settings" element={<Settings user={user} />} />
              </>
            )}
            {/* Platform Admin handled by top-level route */}
            {/* /intake/:slug also handled at top level so it renders
                without the SOC sidebar for end-user submitters */}
            <Route path="*" element={<Navigate to="/" replace />} />
              </Routes>
            </Suspense>
          </ErrorBoundary>
        </div>
      </main>

      {/* Onboarding Wizard — shown on first login */}
      <Suspense fallback={null}>
        <OnboardingWizard />
      </Suspense>

      {/* Riggs Clippy — floating AI assistant */}
      <Suspense fallback={null}>
        <RiggsClippy />
      </Suspense>

      {/* Feature Tour Manager — react-joyride wrapper */}
      <Suspense fallback={null}>
        <FeatureTourManager />
      </Suspense>
    </div>
  );
}

export default App;
