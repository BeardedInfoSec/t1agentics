/**
 * Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0
 */

/*
 * Tour scripts for the authenticated app.
 *
 * Each tour: { label, steps: [...], nextTour?: 'next-tour-id' }
 * Step shape: see GuidedTour.jsx
 *
 * Scripts:
 *   - platform  : orientation walk (~14 steps), chains into virustotal
 *   - virustotal: hands-on guided setup of a VirusTotal connector
 *   - inbox     : hands-on guided setup of an email-monitoring connector
 *                 (survives the OAuth round-trip via ?tour=inbox&step=N)
 *
 * Conventions for "live" predicates:
 *   - skipIf:  return true to skip this step (e.g. integration already configured)
 *   - waitFor: return true once the user has done what we asked them to do
 *              (e.g. a modal is open, a field has a value) so the tour
 *              can advance with their progress rather than against it
 */

// Tiny predicate helpers — kept inline so the script file has no
// dependency on app internals beyond document.querySelector.
const $ = (sel) => document.querySelector(sel);
const visible = (sel) => {
  const el = $(sel);
  if (!el) return false;
  const r = el.getBoundingClientRect();
  return r.width > 0 && r.height > 0;
};

// "Is integration X configured?" probe.
//
// We deliberately do NOT cache permanently — the waitFor on the
// activate step needs to see the new instance show up moments after
// the user activates. Without periodic refresh, the predicate stays
// false forever and the tour gets stuck on Activate. Throttle to one
// fetch per 1.5s to keep load light during the ~5x/s poll loop.
let _instancesCache = null;
let _instancesLastFetchedAt = 0;
let _instancesInFlight = null;

function refreshInstances() {
  if (_instancesInFlight) return _instancesInFlight;
  if (Date.now() - _instancesLastFetchedAt < 1500) return Promise.resolve(_instancesCache || []);
  _instancesInFlight = (async () => {
    try {
      const res = await fetch('/api/v1/connect/instances', { credentials: 'include' });
      if (res.ok) {
        const data = await res.json();
        _instancesCache = Array.isArray(data) ? data : (data.instances || []);
        _instancesLastFetchedAt = Date.now();
      }
    } catch {
      /* keep previous cache */
    }
    _instancesInFlight = null;
    return _instancesCache || [];
  })();
  return _instancesInFlight;
}

function hasInstanceOfVendor(vendorSubstring) {
  // Kick off a refresh (no-op if already in-flight or recently fetched).
  // Returns the latest cached answer synchronously; the next poll tick
  // sees the fresh result.
  refreshInstances();
  if (!_instancesCache) return false;
  const needle = vendorSubstring.toLowerCase();
  return _instancesCache.some((i) =>
    (i.connector_name || i.name || '').toLowerCase().includes(needle)
    || (i.vendor || '').toLowerCase().includes(needle)
  );
}

// DOM-based fallback signal for "wizard activation just completed".
// The ConnectSetupWizard switches its footer to a success state with
// text like "Activated" / "Setup Complete" / "View connector" once
// activation succeeds. Match that as a backup so the tour can advance
// even if /api/v1/connect/instances takes its time to reflect the new
// instance.
function wizardActivationComplete() {
  const modal = document.querySelector('[data-tour="connect-wizard-modal"]');
  if (!modal) return false;
  const text = modal.textContent || '';
  return /\b(setup complete|installation complete|activation complete|connector installed|view connector|completed successfully|activated)\b/i.test(text);
}


export const TOUR_SCRIPTS = {

  // ─────────────────────────────────────────────────────────────────────
  // Platform orientation
  // ─────────────────────────────────────────────────────────────────────
  platform: {
    label: 'Welcome tour',
    nextTour: 'virustotal',
    steps: [
      {
        target: null,
        placement: 'center',
        title: 'Welcome to T1 Agentics',
        body: 'Let me walk you through the platform in about a minute. You\'ll see where alerts land, how investigations group correlated activity, and how Riggs gives you next-step recommendations. Skip any time.',
      },
      {
        path: '/queue',
        target: 'nav-sidebar',
        placement: 'right',
        title: 'Everything starts in the sidebar',
        body: 'Triage is your queue. Playbooks runs the automations. Intake Forms turns external submissions into alerts. Threat Intel, Breach Intel, Connect, Knowledge Base — each has its own home here.',
      },
      {
        path: '/queue',
        target: 'queue-table',
        placement: 'top',
        title: 'Security Queue',
        body: 'Every alert lands here. Rows tagged "A" are standalone alerts. "I" is an investigation. "M N" means an investigation that\'s grouping N correlated child alerts — when the badge is red, at least one of those children flagged non-benign and needs your eyes.',
      },
      {
        path: '/queue',
        target: 'queue-filters',
        placement: 'bottom',
        title: 'Slice the queue',
        body: 'Filter by status, severity, source, SLA, or disposition. Use the search box for free-text across IDs and titles. Filters persist in the URL so you can bookmark a view (or share it).',
      },
      {
        path: '/queue',
        target: 'queue-table',
        placement: 'top',
        title: 'Click any row',
        body: 'Expanding a row opens the AI Triage panel — verdict, confidence, key findings, IOCs, and (for investigations) recommended next-step actions. Try it after the tour.',
      },
      {
        path: '/queue',
        target: 'queue-bulk',
        placement: 'top',
        title: 'Bulk actions',
        body: 'Check multiple rows to bulk-assign, bulk-resolve, or change severity at once. The bar appears at the top of the table when you have a selection.',
      },
      {
        path: '/queue',
        target: 'topbar-search',
        placement: 'bottom',
        title: 'Press "/" to search anywhere',
        body: 'Jump to any alert, investigation, playbook, or KB article from any page. Autocomplete shows what kind of result each match is so you can tab through quickly.',
      },
      {
        path: '/queue',
        target: 'topbar-notifications',
        placement: 'bottom',
        title: 'Live notifications',
        body: 'The bell surfaces tenant-wide events as they happen — new alerts, auto-closes, escalations, and Riggs actions. Click to open the dropdown; it caches the last 20.',
      },
      {
        path: '/queue',
        target: 'user-pill',
        placement: 'bottom',
        title: 'Your menu lives here',
        body: 'Profile, settings, logout — and the "Replay welcome tour" link, so you can rerun this walkthrough any time you want.',
      },
      // ── Playbooks: marketplace + Build with Riggs ───────────────────
      {
        path: '/playbook-marketplace',
        target: 'playbooks-tab-marketplace',
        placement: 'bottom',
        title: 'Playbooks: Marketplace',
        body: 'Browse 200+ ready-made playbooks across phishing, ransomware, lateral movement, account takeover, and more. Each card shows the trigger conditions, connector dependencies, and what it does — clone one to your tenant in a click.',
      },
      {
        path: '/automation-studio',
        target: 'playbooks-tab-build',
        placement: 'bottom',
        title: 'Playbooks: Build with Riggs',
        body: 'Don\'t want to start from a template? Describe what you want in plain English ("Investigate suspicious logins, MFA-prompt if anomalous, lock the account if MFA fails") and Riggs drafts a working playbook you can edit on the canvas.',
      },

      // ── Intake Forms: browse templates + Build with Riggs ───────────
      {
        path: '/admin/intake-forms',
        target: 'intake-browse-templates',
        placement: 'bottom',
        title: 'Intake Forms: Browse templates',
        body: 'Pre-built form templates for the most common intake scenarios — phishing report, suspicious file submission, access request, incident report. Pick one and you\'re collecting submissions in two clicks.',
      },
      {
        path: '/admin/intake-forms',
        target: 'intake-new-form',
        placement: 'bottom',
        title: 'Intake Forms: Build with Riggs',
        body: 'Or start from scratch. The form builder takes a natural-language description and lets Riggs scaffold the fields, validation, and submission flow. Edit anything inline before publishing.',
      },

      // ── Threat Intel: database + feeds + EDLs ───────────────────────
      {
        path: '/threat-intel/database',
        target: 'threat-intel-tab-database',
        placement: 'bottom',
        title: 'Threat Intel: IOC Database',
        body: 'Every IP, domain, hash, URL, and email indicator you\'ve seen — enriched, scored, and searchable. Each alert\'s IOCs auto-enrich against this; you can also lookup, submit, or whitelist indicators directly.',
      },
      {
        path: '/threat-intel/feeds',
        target: 'threat-intel-tab-feeds',
        placement: 'bottom',
        title: 'Threat Intel: Threat Feeds',
        body: 'Commercial + open-source feeds that populate the IOC database. Toggle individual feeds on / off, set sync cadence, see status and indicator counts. The more feeds enabled, the wider the enrichment surface.',
      },
      {
        path: '/threat-intel/edl',
        target: 'threat-intel-tab-edl',
        placement: 'bottom',
        title: 'Threat Intel: EDLs',
        body: 'External Dynamic Lists — block lists you publish out to firewalls, proxies, and email gateways. Auto-populated from confirmed malicious IOCs so your perimeter stays in sync with what Riggs has classified.',
      },

      // ── Connect: marketplace + webhooks + build your own ────────────
      {
        path: '/connect?tab=marketplace',
        target: 'connect-tab-marketplace',
        placement: 'bottom',
        title: 'Connect: Marketplace',
        body: '700+ connectors across EDR, SIEM, identity, email, cloud, ticketing. Each one exposes specific actions to playbooks and the recommended-actions engine — pick the ones your stack uses, configure once, reuse everywhere.',
      },
      {
        path: '/connect?tab=webhooks',
        target: 'connect-tab-webhooks',
        placement: 'bottom',
        title: 'Connect: Webhooks',
        body: 'Pre-wired webhooks for sending alerts and investigation events out to anywhere — Slack, PagerDuty, custom HTTP endpoints, SIEM forwarders. Configure once and any playbook or recommended-action can fire them.',
      },
      {
        path: '/connect?tab=builder',
        target: 'connect-tab-builder',
        placement: 'bottom',
        title: 'Connect: Build your own',
        body: 'Don\'t see the integration you need? Build your own. Describe the API, pick the auth method, define the actions — and it lands alongside the built-in connectors. Useful for internal-tool integrations or niche vendors.',
      },
      {
        target: null,
        placement: 'center',
        title: 'Ready to connect your first integration?',
        body: 'I\'ll walk you through hooking up VirusTotal next — it\'s the most common first integration and it powers IOC enrichment across every alert. Should take about 90 seconds.',
        primaryLabel: 'Continue to VirusTotal →',
      },
    ],
  },

  // ─────────────────────────────────────────────────────────────────────
  // VirusTotal onboarding
  // ─────────────────────────────────────────────────────────────────────
  virustotal: {
    label: 'Connect VirusTotal',
    // Inbox tour navigates to /integrations/inbound-email — different
    // page from the VT wizard, so the wizard unmounts cleanly on the
    // chain and the inbox tour's spotlight lands on the fresh page.
    nextTour: 'inbox',
    steps: [
      {
        target: null,
        placement: 'center',
        title: 'VirusTotal v3 in 5 steps',
        body: 'You\'ll need a VirusTotal v3 API key — free tier is fine to start. If you don\'t have one yet, sign up at virustotal.com (top right → API key in your profile), then come back here. I\'ll wait.',
        // If VT already configured, skip the whole tour.
        skipIf: () => hasInstanceOfVendor('virustotal'),
      },
      {
        path: '/connect?tab=marketplace',
        target: 'connect-marketplace-search',
        placement: 'bottom',
        title: 'Find VirusTotal v3',
        body: 'I\'ve auto-typed "virustotal v3" in the search box so the right card filters in. There\'s also a legacy v2 — we\'re using v3 because the actions are richer and the API is what VirusTotal supports going forward.',
        onEnter: () => {
          // Auto-type virustotal v3 to filter directly to the right card.
          // The input might not be mounted on the FIRST tick if we just
          // navigated tabs — give it up to ~2s to appear.
          let tries = 0;
          const tryType = () => {
            const input = document.querySelector('[data-tour="connect-search-input"]');
            if (input) {
              if (input.value.toLowerCase() !== 'virustotal v3') {
                const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set;
                setter.call(input, 'virustotal v3');
                input.dispatchEvent(new Event('input', { bubbles: true }));
              }
              return;
            }
            if (tries++ < 20) setTimeout(tryType, 100);
          };
          tryType();
        },
        // No waitFor — analyst clicks Next when they spot the card.
      },
      {
        path: '/connect?tab=marketplace',
        target: 'connect-vt-card',
        placement: 'right',
        title: 'Open VirusTotal v3',
        body: 'Click the VirusTotal v3 card (the highlighted one — not plain "VirusTotal", which is the older v2 integration). The setup wizard pops up with the actions it exposes (Enrich IP, Enrich Domain, File Lookup, etc.) and a credentials step.',
        waitFor: () => visible('[data-tour="connect-wizard-modal"]'),
      },
      {
        target: 'connect-wizard-next',
        placement: 'right',
        title: 'Review and continue',
        body: 'This page summarizes what the connector does — actions, vendor, auth method. When you\'re ready, click "Next" in the wizard footer to move to the credentials step where the API key lives.',
        waitFor: () => visible('[data-tour="connect-credentials-form"]'),
      },
      {
        target: 'connect-credentials-form',
        placement: 'right',
        title: 'Paste your API key',
        body: 'Drop your VirusTotal API key into the API Key field (the password-style field, not Credential Name or Base URL). It\'s stored encrypted at rest, Fernet per-tenant key.',
        waitFor: () => {
          // Only match password inputs — text fields like "Credential Name"
          // and "Base URL" come pre-filled and would falsely trip an
          // "input has content > 20 chars" predicate. VT API keys are 64
          // hex chars; gate on length > 30 to be tolerant of short test
          // keys without false-positives.
          const fields = document.querySelectorAll('[data-tour="connect-credentials-form"] input[type="password"]');
          for (const el of fields) {
            if (el.value && el.value.length > 30) return true;
          }
          return false;
        },
      },
      {
        target: 'connect-test-button',
        placement: 'top',
        title: 'Test authentication',
        body: 'Click "Test Authentication". I\'ll wait until you get a green check — that confirms your key is valid and VT is reachable from the platform.',
        waitFor: () => !!document.querySelector('[data-tour="connect-test-success"]'),
      },
      {
        target: 'connect-save-button',
        placement: 'top',
        title: 'Activate the connection',
        body: 'Hit "Activate Connection". The instance is now live — every new IOC across every alert will auto-enrich against VirusTotal from this point forward.',
        // Two-signal check: the API instance appearing OR the wizard's
        // own success state showing. Either flips us forward — so if the
        // instances API takes a beat to refresh, the DOM signal catches
        // it, and vice versa.
        waitFor: () => hasInstanceOfVendor('virustotal') || wizardActivationComplete(),
      },
      {
        target: null,
        placement: 'center',
        title: 'VirusTotal is connected',
        body: 'IOC enrichment is now running on autopilot. Last step: let\'s hook up an inbox so phishing reports can land in your queue automatically.',
        primaryLabel: 'Continue to Inbox →',
      },
    ],
  },

  // ─────────────────────────────────────────────────────────────────────
  // Inbox onboarding — points at the Inbound Email Integration config
  // page, not the Connect marketplace. T1's monitored-inbox flow uses
  // IMAP credentials on a dedicated page rather than the marketplace
  // wizard, so the tour walks the form there.
  // ─────────────────────────────────────────────────────────────────────
  inbox: {
    label: 'Connect a mailbox',
    steps: [
      {
        // Navigate immediately so any leftover wizard from a preceding
        // tour (VT) unmounts when the route changes. Welcome card
        // shows after the page lands.
        path: '/integrations/inbound-email',
        target: null,
        placement: 'center',
        title: 'Connect a mailbox',
        body: 'A monitored inbox is how user-reported phishing flows into T1. Users forward suspicious emails to a dedicated mailbox (e.g. security@yourcompany.com); we triage every message and surface real threats as alerts in your queue.',
      },
      {
        path: '/integrations/inbound-email',
        target: 'inbox-add-button',
        placement: 'left',
        title: 'Add your first mailbox',
        body: 'Click "Add Mailbox" (or "Add Your First Mailbox" if this is your first one). A form opens where you\'ll configure the IMAP connection T1 uses to read the mailbox.',
        waitFor: () => visible('[data-tour="inbox-form-modal"]'),
      },
      {
        target: 'inbox-form-modal',
        placement: 'right',
        title: 'Fill in the mailbox details',
        body: 'Give it a name (e.g. "Phishing Reports Inbox"), pick a type (Phishing Reports or Alert Inbox), and drop in the IMAP server, port, username, and password. For Gmail use imap.gmail.com:993 with an app password. For Microsoft 365, outlook.office365.com:993.',
        // Advance when the user has filled in enough to save — server
        // + username are the minimum required signals.
        waitFor: () => {
          const modal = document.querySelector('[data-tour="inbox-form-modal"]');
          if (!modal) return false;
          const inputs = modal.querySelectorAll('input');
          let filled = 0;
          for (const el of inputs) {
            if (el.type === 'number') continue;
            if (el.value && el.value.length > 0) filled += 1;
          }
          // Name + server + username + password = 4 filled text fields.
          return filled >= 4;
        },
      },
      {
        target: 'inbox-form-modal',
        placement: 'right',
        title: 'Save the mailbox',
        body: 'When the fields look right, click "Add Mailbox" at the bottom of the modal. T1 will store the IMAP credentials encrypted and start polling for new messages within a minute.',
        // We can\'t reliably tag the Modal\'s internal confirm button, so
        // we wait for the modal to close (form-modal element gone) AND
        // a mailbox to appear in the list as the success signal.
        waitFor: () => {
          const modalGone = !visible('[data-tour="inbox-form-modal"]');
          return modalGone;
        },
      },
      {
        target: null,
        placement: 'center',
        title: 'Mailbox connected',
        body: 'Done. Your mailbox shows up in the "Configured Mailboxes" list with a test-connection button next to it — hit it any time to verify the IMAP link is still healthy. From here, every email that lands in the mailbox is automatically triaged by Riggs and surfaces in /queue as an alert.',
        primaryLabel: 'Finish',
      },
    ],
  },
};
