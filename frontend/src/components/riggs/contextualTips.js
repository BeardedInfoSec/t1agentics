/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

/**
 * Contextual tips for the Riggs Clippy assistant.
 * Returns route-aware tip suggestions to help users navigate the platform.
 *
 * Route map (current as of Feb 2026):
 *   /queue             - Security Queue (unified triage)
 *   /dashboard         - SOC Dashboard (3 sub-dashboards)
 *   /investigation/:id - Investigation Workbench V2
 *   /playbooks         - Playbook list + Marketplace + Executions
 *   /playbooks/new     - Workflow Studio (visual builder)
 *   /automation-studio - Riggs AI playbook builder
 *   /threat-intel      - IOC Center + Feeds + EDL
 *   /connect           - T1 Connect (733 integrations)
 *   /knowledge-base    - 274 articles, semantic search
 *   /settings          - User preferences
 *   /admin             - Tenant admin (users, RBAC, alert tuning)
 */

const TIPS = {
  '/dashboard': [
    {
      id: 'dashboard-metrics',
      text: 'Your dashboard shows real-time metrics including open alerts, active investigations, and mean time to respond. Click any metric card to drill into the details.',
    },
    {
      id: 'dashboard-views',
      text: 'There are three dashboard views: SOC Overview, Management, and Operations. Switch between them using the Dashboards submenu in the sidebar.',
    },
    {
      id: 'dashboard-queue',
      text: 'Head to Triage in the sidebar to view and respond to incoming alerts and investigations in one unified queue.',
      action: { navigate: '/queue' },
    },
  ],

  '/queue': [
    {
      id: 'queue-filters',
      text: 'Use the filter bar to narrow items by severity, status, source, SLA status, or time range. Switch between All, Alerts, and Investigations views.',
    },
    {
      id: 'queue-bulk',
      text: 'Select multiple items with checkboxes to perform bulk actions like closing, escalating, or assigning them all at once.',
    },
    {
      id: 'queue-expand',
      text: 'Click any row to expand it and see full details, extracted IOCs, and AI triage results. Use keyboard shortcuts J/K to navigate between items.',
    },
  ],

  '/investigation': [
    {
      id: 'inv-workflow',
      text: 'Each investigation follows checkpoints: Triage, Analysis, Response, and Resolved. Riggs tracks progress and evidence automatically.',
    },
    {
      id: 'inv-riggs',
      text: 'Click "Ask Riggs" to open the AI chat panel. Riggs has full context of the investigation, IOCs, and enrichment data to help you analyze threats.',
    },
    {
      id: 'inv-deepdive',
      text: 'Use the Deep Dive button for comprehensive AI analysis including threat narrative, root cause, MITRE ATT&CK mapping, and response recommendations.',
    },
  ],


  '/playbooks': [
    {
      id: 'pb-list',
      text: 'View your playbooks here. Click any playbook to open it in the visual Workflow Studio editor where you can drag and drop nodes.',
    },
    {
      id: 'pb-marketplace',
      text: 'Browse 200 pre-built playbook templates in the Marketplace covering phishing response, malware containment, and more.',
      action: { navigate: '/playbook-marketplace' },
    },
    {
      id: 'pb-executions',
      text: 'Check the Executions tab to see playbook run history, step-by-step timelines, and troubleshoot any failures.',
      action: { navigate: '/playbooks' },
    },
  ],

  '/automation-studio': [
    {
      id: 'riggs-studio',
      text: 'Describe what you want in plain English and Riggs will generate a complete automation playbook for you. For example: "When a critical alert comes in, enrich all IOCs and notify the team."',
    },
    {
      id: 'riggs-review',
      text: 'Always review the generated playbook before deploying. You can edit it in the visual Workflow Studio to fine-tune the logic.',
    },
  ],

  '/threat-intel': [
    {
      id: 'ti-iocs',
      text: 'The IOC Center tracks all Indicators of Compromise across your investigations -- IPs, domains, hashes, and URLs with enrichment data and reputation scores.',
    },
    {
      id: 'ti-feeds',
      text: 'Configure threat feeds under the Feeds tab. Subscribe to sources like AlienVault OTX, AbuseIPDB, and VirusTotal for automated IOC enrichment.',
      action: { navigate: '/threat-intel/feeds' },
    },
    {
      id: 'ti-edl',
      text: 'Use EDL Management to create External Dynamic Lists that your firewalls can pull from automatically for blocking.',
      action: { navigate: '/threat-intel/edl' },
    },
  ],

  '/connect': [
    {
      id: 'connect-marketplace',
      text: 'T1 Connect has 733 integrations across 31 categories including SIEM, EDR, ticketing, cloud, email security, and more. Browse the Marketplace tab to find your tools.',
    },
    {
      id: 'connect-credentials',
      text: 'Integration credentials are encrypted at rest with Fernet encryption. Use the Test Connection button to verify setup before using integrations in playbooks.',
    },
    {
      id: 'connect-email',
      text: 'Set up the Email Inbox integration to automatically ingest phishing reports and suspicious emails directly into your alert queue.',
      action: { navigate: '/integrations/inbound-email' },
    },
  ],

  '/knowledge-base': [
    {
      id: 'kb-search',
      text: 'Search 274 articles covering threats, response procedures, and platform guides. Results are ranked by relevance using semantic vector search.',
    },
    {
      id: 'kb-submit',
      text: 'Contribute your own articles and runbooks. Riggs references Knowledge Base content when providing investigation recommendations.',
    },
  ],

  '/settings': [
    {
      id: 'settings-prefs',
      text: 'Customize your experience with theme selection (dark/light/system), date format, timezone, and notification preferences.',
    },
    {
      id: 'settings-config',
      text: 'System configuration includes AI provider settings, webhook management, and integration credentials.',
    },
  ],

  '/admin': [
    {
      id: 'admin-users',
      text: 'Manage user accounts, assign roles, and control access to platform features using role-based access control (RBAC).',
    },
    {
      id: 'admin-tuning',
      text: 'Alert processing settings let you configure deduplication rules, exclusion lists, and correlation parameters to reduce noise in your queue.',
      action: { navigate: '/settings' },
    },
    {
      id: 'admin-rbac',
      text: 'Set up fine-grained permissions under RBAC to control who can view, edit, and execute actions across the platform.',
      action: { navigate: '/admin/rbac' },
    },
  ],
};

const DEFAULT_TIPS = [
  {
    id: 'general-nav',
    text: 'Use the sidebar to navigate between Triage, Playbooks, Threat Intel, Dashboards, Connect, and more. Click the collapse button for more workspace.',
  },
  {
    id: 'general-riggs',
    text: 'I am Riggs, your AI assistant. Ask me anything about using the platform, understanding alerts, or building playbooks. I am here to help.',
  },
  {
    id: 'general-shortcuts',
    text: 'Press ? anywhere in the app to see available keyboard shortcuts for the current page.',
  },
];

/**
 * Get contextual tips for the current route.
 * @param {string} pathname - The current route pathname
 * @returns {Array<{id: string, text: string, action?: {navigate?: string}}>}
 */
export function getTipsForRoute(pathname) {
  if (!pathname) return DEFAULT_TIPS;

  // Normalize pathname: strip trailing slash, lowercase
  const normalized = pathname.replace(/\/+$/, '').toLowerCase();

  // Direct match
  if (TIPS[normalized]) {
    return TIPS[normalized];
  }

  // Prefix match (e.g., /investigation/123 matches /investigation)
  for (const [route, tips] of Object.entries(TIPS)) {
    if (normalized.startsWith(route)) {
      return tips;
    }
  }

  return DEFAULT_TIPS;
}

export default getTipsForRoute;
