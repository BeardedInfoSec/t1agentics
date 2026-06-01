/* Copyright (c) 2024-2026 T1 Agentics LLC -- SPDX-License-Identifier: Apache-2.0 */

/**
 * Onboarding Wizard - Step configuration data
 *
 * Defines the roles, goals, steps, and quick-start options
 * shown during the first-login onboarding experience.
 *
 * Updated Feb 2026 to reflect current platform state:
 *   733 connectors, 200 playbook templates, 274 KB articles
 */

export const ROLES = [
  { id: 'soc_analyst', label: 'SOC Analyst', description: 'Triage alerts, investigate incidents, respond to threats' },
  { id: 'security_engineer', label: 'Security Engineer', description: 'Build automations, manage integrations, tune detections' },
  { id: 'ciso_manager', label: 'CISO / Manager', description: 'Oversee operations, track metrics, manage teams' },
  { id: 'it_admin', label: 'IT Admin', description: 'Manage infrastructure, deploy collectors, configure systems' },
  { id: 'other', label: 'Other', description: 'Exploring T1 Agentics for a different use case' },
];

export const GOALS = [
  { id: 'automate_triage', label: 'Automate alert triage', description: 'Let Riggs AI handle initial alert analysis and prioritization' },
  { id: 'build_playbooks', label: 'Build playbooks', description: 'Create automated response workflows in the visual Workflow Studio' },
  { id: 'connect_integrations', label: 'Connect integrations', description: 'Link your SIEM, EDR, ticketing, and other tools via T1 Connect' },
  { id: 'threat_intel', label: 'Threat intel analysis', description: 'Analyze IOCs, track threat feeds, manage EDLs, and enrich indicators' },
  { id: 'incident_response', label: 'Incident response', description: 'Investigate and respond to security incidents with AI assistance' },
  { id: 'compliance_reporting', label: 'Compliance reporting', description: 'Generate reports and track metrics for audits and compliance' },
];

export const STEPS = [
  {
    id: 'welcome',
    title: 'Welcome to T1 Agentics',
    description: 'Your AI-powered security operations platform. Let Riggs, your AI assistant, help you get started.',
  },
  {
    id: 'role_select',
    title: 'What is your role?',
    description: 'This helps us tailor the experience to your needs.',
  },
  {
    id: 'goals',
    title: 'What are your goals?',
    description: 'Select one or more objectives. You can always explore other features later.',
  },
  {
    id: 'integrations',
    title: 'Connect your tools',
    description: 'T1 Connect has 733 integrations across 31 categories. Here are the most common starting points.',
  },
  {
    id: 'playbooks',
    title: 'Start with a playbook',
    description: 'Choose from 200 pre-built templates or build your own in Workflow Studio.',
  },
  {
    id: 'finish',
    title: 'You are all set',
    description: 'Your workspace is ready. Riggs is always available to help -- look for the floating assistant in the bottom-right corner.',
  },
];

export const INTEGRATION_FEATURES = [
  { id: 'siem', label: 'SIEM', description: 'Splunk, Elastic, Sentinel, QRadar, Wazuh', icon: 'shield' },
  { id: 'edr', label: 'EDR', description: 'CrowdStrike, SentinelOne, Defender, Carbon Black', icon: 'monitor' },
  { id: 'ticketing', label: 'Ticketing', description: 'ServiceNow, Jira, PagerDuty, Zendesk', icon: 'clipboard' },
  { id: 'email', label: 'Email Security', description: 'Proofpoint, Mimecast, Microsoft 365, Google Workspace', icon: 'mail' },
];

export const PLAYBOOK_OPTIONS = [
  { id: 'phishing_triage', label: 'Phishing triage', description: 'Automatically analyze suspicious emails, extract IOCs, check reputation, and determine verdict' },
  { id: 'malware_containment', label: 'Malware containment', description: 'Isolate infected hosts, block malicious hashes, notify stakeholders, and create tickets' },
  { id: 'alert_enrichment', label: 'Alert enrichment', description: 'Enrich alerts with threat intel, asset context, user information, and geolocation data' },
];

export const POPULAR_FEEDS = [
  { id: 'alienvault_otx', label: 'AlienVault OTX', description: 'Open threat intelligence community with millions of indicators' },
  { id: 'abuseipdb', label: 'AbuseIPDB', description: 'Community-driven IP address abuse reporting and lookup' },
  { id: 'virustotal', label: 'VirusTotal', description: 'Multi-engine file and URL analysis service by Google' },
];
