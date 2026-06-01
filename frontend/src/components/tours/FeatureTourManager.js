/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

import React, { useState, useEffect, useCallback, useRef } from 'react';
import { useLocation } from 'react-router-dom';
import { useTour } from './TourContext';
import TourTooltip from './TourTooltip';

// ---------------------------------------------------------------------------
// Tour Definitions
// ---------------------------------------------------------------------------
// Each tour has an id, the route pathname it applies to, and an ordered
// list of steps. Each step specifies a CSS selector for the target element,
// a title, descriptive content, and preferred tooltip placement.
// ---------------------------------------------------------------------------

const TOUR_DEFINITIONS = {
  'dashboard-intro': {
    id: 'dashboard-intro',
    route: '/dashboard',
    steps: [
      {
        target: '.metric-cards, .dashboard-metrics, [class*="metricCards"], [class*="MetricCard"]',
        title: 'Metrics at a Glance',
        content:
          'These cards show key operational metrics -- open alerts, active investigations, and mean response times. They update in real time so you always know where things stand.',
        placement: 'bottom',
      },
      {
        target: '.quick-actions, .dashboard-actions, [class*="quickAction"], [class*="QuickAction"]',
        title: 'Quick Actions',
        content:
          'Jump straight into common tasks from here: create an investigation, run a playbook, or search for IOCs without navigating away from the dashboard.',
        placement: 'bottom',
      },
      {
        target: '.recent-activity, .dashboard-activity, [class*="recentActivity"], [class*="ActivityFeed"]',
        title: 'Recent Activity',
        content:
          'This feed shows the latest events across your environment -- new alerts, investigation updates, and playbook executions -- so nothing slips through the cracks.',
        placement: 'top',
      },
    ],
  },

  'security-queue-intro': {
    id: 'security-queue-intro',
    route: '/queue',
    steps: [
      {
        target: '.queue-filters, [class*="queueFilters"], [class*="QueueFilters"], [class*="filterBar"]',
        title: 'Filter the Queue',
        content:
          'Narrow the queue by severity, status, source, SLA status, or time range. Switch between All, Alerts, and Investigations views to focus on what matters most.',
        placement: 'bottom',
      },
      {
        target: '.queue-table tbody tr, [class*="queueRow"], [class*="QueueRow"], [class*="securityQueueTable"] tr',
        title: 'Queue Items',
        content:
          'Each row is an alert or investigation. Click any row to expand its details with IOCs, AI triage results, and enrichment data. Select the checkbox for bulk actions.',
        placement: 'bottom',
      },
      {
        target: '.bulk-actions, [class*="bulkActions"], [class*="BulkActions"]',
        title: 'Bulk Actions',
        content:
          'Select multiple items and act on them at once -- assign, change status, escalate, or close. Great for clearing a backlog quickly.',
        placement: 'top',
      },
    ],
  },

  'playbook-intro': {
    id: 'playbook-intro',
    route: '/playbooks/',
    steps: [
      {
        target: '.node-palette, [class*="nodePalette"], [class*="NodePalette"], [class*="palette"]',
        title: 'Node Palette',
        content:
          'Drag nodes from this palette onto the canvas to build your playbook. Node types include triggers, actions, conditions, enrichments, Python code, and Riggs AI.',
        placement: 'right',
      },
      {
        target: '.react-flow, .reactflow-wrapper, [class*="canvasArea"], [class*="workflowCanvas"]',
        title: 'Playbook Canvas',
        content:
          'This is where your automation comes together. Connect nodes by dragging between their ports to define the execution flow. Use the toolbar to zoom, fit, or undo.',
        placement: 'left',
      },
    ],
  },

  'connect-intro': {
    id: 'connect-intro',
    route: '/connect',
    steps: [
      {
        target: '[class*="myConnections"], [class*="ConnectionList"], [class*="connectionCard"]',
        title: 'Your Connections',
        content:
          'This shows your active integrations. Each card displays the connection status and lets you manage credentials, test connectivity, or reconfigure.',
        placement: 'bottom',
      },
      {
        target: '[class*="marketplace"], [class*="Marketplace"], [class*="categoryFilter"]',
        title: 'Integration Marketplace',
        content:
          'Browse 733 integrations across 31 categories. Click any connector to see its actions, setup instructions, and connect it to your workspace.',
        placement: 'bottom',
      },
    ],
  },

  'threat-intel-intro': {
    id: 'threat-intel-intro',
    route: '/threat-intel',
    steps: [
      {
        target: '[class*="iocTable"], [class*="IOCCenter"], [class*="iocList"]',
        title: 'IOC Center',
        content:
          'Track all Indicators of Compromise across your investigations -- IPs, domains, hashes, and URLs. Each IOC shows reputation, enrichment data, and linked investigations.',
        placement: 'bottom',
      },
      {
        target: '[class*="feedConfig"], [class*="ThreatFeed"], [class*="feedList"]',
        title: 'Threat Feeds and EDLs',
        content:
          'Configure threat intelligence feeds for automated enrichment and manage External Dynamic Lists (EDLs) that your firewalls can pull from.',
        placement: 'bottom',
      },
    ],
  },
};

// Map routes to tour IDs for auto-start detection.
// Uses startsWith matching so /playbooks/abc triggers playbook-intro.
const ROUTE_TOUR_MAP = Object.values(TOUR_DEFINITIONS).map((t) => ({
  tourId: t.id,
  route: t.route,
}));

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Attempt to find a DOM element matching one of the comma-separated selectors.
 * Returns the first match or null.
 */
function queryTarget(selectorGroup) {
  if (!selectorGroup) return null;
  const selectors = selectorGroup.split(',').map((s) => s.trim());
  for (const sel of selectors) {
    try {
      const el = document.querySelector(sel);
      if (el) return el;
    } catch {
      // invalid selector -- skip
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

/**
 * FeatureTourManager - Orchestrates feature tours.
 *
 * Listens for route changes and auto-starts the relevant tour when the
 * user visits a page for the first time (tour not yet completed or
 * dismissed). Renders a TourTooltip anchored to the current step's
 * target element and manages step navigation (next, back, skip, done).
 *
 * This is a pure React implementation -- no external tour libraries.
 */
export default function FeatureTourManager() {
  const location = useLocation();
  const { activeTour, startTour, completeTour, dismissTour, isTourCompleted, isTourDismissed } = useTour();

  const [currentStep, setCurrentStep] = useState(0);
  const [targetRect, setTargetRect] = useState(null);
  const autoStartedRef = useRef(new Set());
  const observerRef = useRef(null);

  // -----------------------------------------------------------------------
  // Auto-start tours on route change
  // -----------------------------------------------------------------------
  useEffect(() => {
    // Small delay to let the page render before checking for targets
    const timer = setTimeout(() => {
      for (const { tourId, route } of ROUTE_TOUR_MAP) {
        const pathMatches =
          location.pathname === route ||
          (route.endsWith('/') && location.pathname.startsWith(route));

        if (!pathMatches) continue;
        if (autoStartedRef.current.has(tourId)) continue;
        if (isTourCompleted(tourId) || isTourDismissed(tourId)) continue;
        if (activeTour) continue; // another tour already running

        // Mark as attempted so we don't retry on every re-render
        autoStartedRef.current.add(tourId);
        startTour(tourId);
        break;
      }
    }, 800);

    return () => clearTimeout(timer);
  }, [location.pathname, activeTour, startTour, isTourCompleted, isTourDismissed]);

  // -----------------------------------------------------------------------
  // Reset step index when a new tour starts
  // -----------------------------------------------------------------------
  useEffect(() => {
    if (activeTour) {
      setCurrentStep(0);
    } else {
      setTargetRect(null);
    }
  }, [activeTour]);

  // -----------------------------------------------------------------------
  // Locate the target element for the current step and track its position
  // -----------------------------------------------------------------------
  useEffect(() => {
    if (!activeTour) return;

    const tourDef = TOUR_DEFINITIONS[activeTour];
    if (!tourDef || !tourDef.steps[currentStep]) {
      setTargetRect(null);
      return;
    }

    const step = tourDef.steps[currentStep];

    const updateRect = () => {
      const el = queryTarget(step.target);
      if (el) {
        setTargetRect(el.getBoundingClientRect());
      } else {
        setTargetRect(null);
      }
    };

    // Initial attempt -- the element may not be rendered yet
    updateRect();

    // Retry a few times in case the element appears after async rendering
    const retries = [200, 500, 1000, 2000];
    const retryTimers = retries.map((delay) => setTimeout(updateRect, delay));

    // Keep position up to date on scroll / resize
    const handleScrollResize = () => {
      requestAnimationFrame(updateRect);
    };
    window.addEventListener('scroll', handleScrollResize, true);
    window.addEventListener('resize', handleScrollResize);

    // Observe DOM mutations so we catch dynamically inserted elements
    if (typeof MutationObserver !== 'undefined') {
      observerRef.current = new MutationObserver(() => {
        updateRect();
      });
      observerRef.current.observe(document.body, {
        childList: true,
        subtree: true,
        attributes: true,
        attributeFilter: ['class'],
      });
    }

    return () => {
      retryTimers.forEach(clearTimeout);
      window.removeEventListener('scroll', handleScrollResize, true);
      window.removeEventListener('resize', handleScrollResize);
      if (observerRef.current) {
        observerRef.current.disconnect();
        observerRef.current = null;
      }
    };
  }, [activeTour, currentStep]);

  // -----------------------------------------------------------------------
  // Navigation handlers
  // -----------------------------------------------------------------------

  const tourDef = activeTour ? TOUR_DEFINITIONS[activeTour] : null;
  const totalSteps = tourDef ? tourDef.steps.length : 0;
  const step = tourDef?.steps[currentStep];

  const handleNext = useCallback(() => {
    if (currentStep < totalSteps - 1) {
      setCurrentStep((prev) => prev + 1);
    }
  }, [currentStep, totalSteps]);

  const handleBack = useCallback(() => {
    if (currentStep > 0) {
      setCurrentStep((prev) => prev - 1);
    }
  }, [currentStep]);

  const handleSkip = useCallback(() => {
    if (activeTour) {
      dismissTour(activeTour);
    }
  }, [activeTour, dismissTour]);

  const handleDone = useCallback(() => {
    if (activeTour) {
      completeTour(activeTour);
    }
  }, [activeTour, completeTour]);

  // -----------------------------------------------------------------------
  // Keyboard navigation
  // -----------------------------------------------------------------------
  useEffect(() => {
    if (!activeTour) return;

    const handleKey = (e) => {
      if (e.key === 'Escape') {
        handleSkip();
      } else if (e.key === 'ArrowRight' || e.key === 'Enter') {
        if (currentStep < totalSteps - 1) {
          handleNext();
        } else {
          handleDone();
        }
      } else if (e.key === 'ArrowLeft') {
        handleBack();
      }
    };

    window.addEventListener('keydown', handleKey);
    return () => window.removeEventListener('keydown', handleKey);
  }, [activeTour, currentStep, totalSteps, handleNext, handleBack, handleSkip, handleDone]);

  // -----------------------------------------------------------------------
  // Render
  // -----------------------------------------------------------------------

  if (!activeTour || !step || !targetRect) return null;

  return (
    <TourTooltip
      title={step.title}
      content={step.content}
      placement={step.placement}
      stepIndex={currentStep}
      totalSteps={totalSteps}
      onNext={handleNext}
      onBack={handleBack}
      onSkip={handleSkip}
      onDone={handleDone}
      targetRect={targetRect}
    />
  );
}
