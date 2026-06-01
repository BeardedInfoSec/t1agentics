const WIDGET_TYPES = [
  'iocs_with_reputation',
  'mitre',
  'timeline',
  'key_findings',
  'entities',
  'impact',
  'infection_vector',
  'network_traffic',
  'enrichment',
  'alert_details',
  'affected_hosts',
  'custom'
];

const WIDGET_PRIORITY = {
  iocs_with_reputation: 1,
  malicious_iocs: 1,
  mitre: 2,
  timeline: 3,
  impact: 4,
  infection_vector: 5,
  affected_hosts: 6,
  entities: 7,
  enrichment: 8,
  network_traffic: 9,
  alert_details: 10,
  key_findings: 11,
  custom: 50
};

const ALERT_DETAIL_FIELDS = [
  'ransom_note',
  'extension_pattern',
  'files_affected',
  'command_line',
  'detection_name',
  'threat_family',
  'parent_process',
  'process_name',
  'file_path',
  'registry_key',
  'network_connection',
  'email_subject'
];

function formatTitle(key) {
  return key
    .replace(/_/g, ' ')
    .replace(/([a-z])([A-Z])/g, '$1 $2')
    .split(' ')
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1).toLowerCase())
    .join(' ');
}

function normalizeConfidence(val) {
  if (val == null) return 0;
  const num = Number(val);
  if (Number.isNaN(num)) return 0;
  return num > 1 ? Math.min(num, 100) : Math.min(num * 100, 100);
}

function safeParseJSON(value) {
  if (!value) return value;
  if (typeof value !== 'string') return value;
  try {
    return JSON.parse(value);
  } catch {
    return value;
  }
}

function buildIocItem(ioc, enrichmentMap) {
  let type;
  let value;
  let verdict;
  let enrichment;

  if (typeof ioc === 'string') {
    const parts = ioc.split(':');
    if (parts.length >= 2) {
      type = parts[0].trim();
      value = parts.slice(1).join(':').trim();
    } else {
      value = ioc;
      if (/^\d{1,3}(\.\d{1,3}){3}$/.test(ioc)) type = 'IP';
      else if (ioc.includes('@')) type = 'Email';
      else if (ioc.includes('.') && !ioc.includes(' ')) type = 'Domain';
      else if (/^[a-f0-9]{32,64}$/i.test(ioc)) type = 'Hash';
      else type = 'IOC';
    }
  } else if (ioc && typeof ioc === 'object') {
    type = ioc.type || ioc.ioc_type || 'IOC';
    value = ioc.value || ioc.indicator || ioc.ioc || ioc.label || '';
    verdict = ioc.reputation || ioc.verdict || ioc.status || 'unknown';
    enrichment = ioc.enrichment || ioc.enrichments || null;
  }

  if (!value) return null;

  if (!verdict && enrichmentMap && enrichmentMap.has(value.toLowerCase())) {
    const enrich = enrichmentMap.get(value.toLowerCase());
    verdict = enrich.reputation || verdict;
    enrichment = enrichment || enrich.enrichment;
  }

  return {
    type: String(type || 'IOC').toUpperCase().replace('_', ' ').slice(0, 12),
    label: String(value).slice(0, 80),
    verdict: verdict || 'unknown',
    enrichment
  };
}

function buildEnrichmentMap({ alertData, invData, analysis, tier1, tier2 }) {
  const map = new Map();

  const results = alertData?._extracted?.enrichment?.results || {};
  ['ips', 'domains', 'hashes', 'urls'].forEach((key) => {
    const list = results[key];
    if (Array.isArray(list)) {
      list.forEach((item) => {
        if (item?.value) {
          map.set(item.value.toLowerCase(), {
            reputation: item.verdict || item.reputation || 'unknown',
            confidence: item.confidence,
            enrichment: item
          });
        }
      });
    }
  });

  const iocEnrichment = invData?.ioc_enrichment || analysis?.ioc_enrichment || tier1?.ioc_enrichment || tier2?.ioc_enrichment || {};
  Object.entries(iocEnrichment || {}).forEach(([value, enrich]) => {
    if (value && enrich) {
      map.set(value.toLowerCase(), {
        reputation: enrich.verdict || enrich.reputation || 'unknown',
        confidence: enrich.confidence,
        enrichment: enrich
      });
    }
  });

  const enrichmentResults = invData?.enrichment_results || analysis?.enrichment_results || {};
  Object.entries(enrichmentResults || {}).forEach(([value, enrich]) => {
    if (value && enrich && !map.has(value.toLowerCase())) {
      map.set(value.toLowerCase(), {
        reputation: enrich.verdict || enrich.reputation || 'unknown',
        confidence: enrich.confidence,
        enrichment: enrich
      });
    }
  });

  if (Array.isArray(alertData?.iocs)) {
    alertData.iocs.forEach((ioc) => {
      const value = ioc?.value || ioc?.indicator || ioc?.ioc;
      if (value && !map.has(value.toLowerCase())) {
        map.set(value.toLowerCase(), {
          reputation: ioc.verdict || ioc.reputation || ioc.status || 'unknown',
          enrichment: ioc.enrichment || ioc
        });
      }
    });
  }

  return map;
}

function buildCoreInfo({ investigation, analysis, riggsAnalysis, tier1, tier2, apiVerdict, apiConfidence, apiThreatType, apiKeyFindings, apiAiTriage, alertData, rawEvent }) {
  const confidenceSignals = [];
  const whatWouldChange = [];

  const keyFindingsSource = apiKeyFindings?.length > 0 ? apiKeyFindings : analysis?.key_findings;
  if (Array.isArray(keyFindingsSource)) {
    keyFindingsSource.slice(0, 3).forEach((finding) => {
      const value = typeof finding === 'string' ? finding : (finding.finding || finding.description || finding.text);
      if (value) confidenceSignals.push({ signal: value, weight: 'high' });
    });
  }

  if (Array.isArray(analysis?.what_would_change)) {
    analysis.what_would_change.slice(0, 3).forEach((item) => {
      const value = typeof item === 'string' ? item : (item.condition || item.reason || item.text);
      if (value) whatWouldChange.push(value);
    });
  }

  const verdict = apiVerdict || analysis?.verdict || tier1?.verdict || tier2?.verdict || investigation?.disposition || 'UNKNOWN';
  const confidence = apiConfidence ?? analysis?.confidence ?? tier1?.confidence ?? tier2?.confidence ?? 0;
  const threatType = apiThreatType || analysis?.threat_type || tier1?.threat_type || tier2?.threat_type || 'unknown';

  return {
    verdict,
    verdictTitle: apiAiTriage?.verdict_title || riggsAnalysis?.verdict_title || analysis?.verdict_title || '',
    confidence,
    threatType,
    threatCategory: riggsAnalysis?.threat_category || analysis?.threat_category || '',
    summary: investigation?.ai_summary || analysis?.summary || tier1?.summary || tier2?.summary || analysis?.reasoning || '',
    attackNarrative: riggsAnalysis?.attack_narrative || analysis?.attack_narrative || '',
    businessImpact: riggsAnalysis?.business_impact || analysis?.business_impact || '',
    relatedThreats: riggsAnalysis?.related_threats || analysis?.related_threats || [],
    source: alertData?.source || rawEvent?.source || investigation?.source || 'Unknown',
    confidenceSignals: confidenceSignals.slice(0, 5),
    whatWouldChange: whatWouldChange.slice(0, 3)
  };
}

function normalizeWidget(widget) {
  if (!widget || !widget.title) return null;
  const type = widget.type && WIDGET_TYPES.includes(widget.type) ? widget.type : 'custom';
  const items = Array.isArray(widget.items) ? widget.items : [];
  return {
    type,
    title: widget.title,
    color: widget.color || '#6b7280',
    fullWidth: !!widget.fullWidth,
    items,
    source: widget.source || 'riggs'
  };
}

function buildWidgetsFromRiggs(displayWidgets, enrichmentMap) {
  if (!Array.isArray(displayWidgets)) return [];
  const widgets = [];

  displayWidgets.forEach((widget) => {
    const titleLower = (widget.title || '').toLowerCase();
    if (!widget.title) return;
    if (['source', 'verdict', 'confidence', 'summary', 'threat type'].some((s) => titleLower.includes(s))) return;

    if (titleLower.includes('recommend')) return;

    if (titleLower.includes('ioc')) {
      const items = (widget.items || []).map((item) => buildIocItem(item, enrichmentMap)).filter(Boolean);
      if (items.length) {
        widgets.push(normalizeWidget({
          type: 'iocs_with_reputation',
          title: widget.title || 'Key IOCs',
          color: widget.color || '#f59e0b',
          items
        }));
      }
      return;
    }

    const items = (widget.items || []).map((item) => {
      if (typeof item === 'string') return { label: item };
      return {
        ...item,
        label: item.label || item.value || item.text || item.name || item.technique_name || JSON.stringify(item)
      };
    });

    widgets.push(normalizeWidget({
      type: widget.type || 'custom',
      title: widget.title,
      color: widget.color,
      items
    }));
  });

  return widgets.filter(Boolean);
}

function buildWidgetsFromFallback({ analysis, riggsAnalysis, tier1, tier2, alertData, rawEvent, enrichmentMap, investigation }) {
  const widgets = [];

  const collectedIocs = [];
  const extractedIocs = analysis?.extracted_iocs || tier1?.extracted_iocs || tier2?.extracted_iocs || [];
  if (Array.isArray(extractedIocs)) collectedIocs.push(...extractedIocs);
  if (Array.isArray(rawEvent?.iocs)) collectedIocs.push(...rawEvent.iocs);
  if (Array.isArray(alertData?.iocs)) collectedIocs.push(...alertData.iocs);

  const iocItems = collectedIocs.map((ioc) => buildIocItem(ioc, enrichmentMap)).filter(Boolean).slice(0, 10);
  if (iocItems.length) {
    widgets.push({
      type: 'iocs_with_reputation',
      title: 'Key IOCs',
      color: '#f59e0b',
      items: iocItems,
      source: 'fallback'
    });
  }

  const mitreList = riggsAnalysis?.mitre || riggsAnalysis?.mitre_techniques || analysis?.mitre_techniques || tier1?.mitre_techniques || tier2?.mitre_techniques || [];
  if (Array.isArray(mitreList) && mitreList.length) {
    const items = mitreList.slice(0, 8).map((tech) => ({
      technique_id: tech.technique_id || tech.id || tech.technique || tech.tid,
      technique_name: tech.technique_name || tech.name || tech.technique || '',
      tactic: tech.tactic || tech.phase || tech.category || ''
    })).filter((item) => item.technique_id || item.technique_name);
    if (items.length) {
      widgets.push({
        type: 'mitre',
        title: 'MITRE ATT&CK',
        color: '#8b5cf6',
        items,
        source: 'fallback'
      });
    }
  }

  const timelineEvents = riggsAnalysis?.timeline || rawEvent?.timeline || rawEvent?.events || rawEvent?.activity_log || [];
  if (Array.isArray(timelineEvents) && timelineEvents.length) {
    const timelineData = timelineEvents.map((evt) => {
      const ts = evt.timestamp || evt.time || evt.date || evt.when;
      const date = ts ? new Date(ts) : null;
      return {
        timestamp: date && !Number.isNaN(date.valueOf()) ? date : null,
        label: evt.description || evt.event || evt.action || evt.message || 'Event',
        type: evt.type || evt.phase || 'event',
        severity: evt.severity || 'medium'
      };
    }).filter((evt) => evt.timestamp);

    if (timelineData.length) {
      widgets.push({
        type: 'timeline',
        title: 'Attack Timeline',
        color: '#8b5cf6',
        fullWidth: true,
        timelineData: timelineData.slice(0, 8),
        items: [],
        source: 'fallback'
      });
    }
  }

  if (rawEvent?.affected_hosts?.length) {
    widgets.push({
      type: 'affected_hosts',
      title: 'Affected Hosts',
      color: '#f97316',
      items: rawEvent.affected_hosts.slice(0, 6).map((host) => ({
        label: `${host.hostname || host.host || host.name || 'Host'}${host.cpu_usage ? ` (CPU: ${host.cpu_usage})` : ''}${host.status ? ` - ${host.status}` : ''}`
      })),
      source: 'fallback'
    });
  }

  if (rawEvent?.impact && typeof rawEvent.impact === 'object') {
    const items = Object.entries(rawEvent.impact)
      .filter(([, value]) => value && typeof value !== 'object')
      .slice(0, 6)
      .map(([key, value]) => ({ label: `${formatTitle(key)}: ${value}` }));
    if (items.length) {
      widgets.push({
        type: 'impact',
        title: 'Impact Assessment',
        color: '#ef4444',
        items,
        source: 'fallback'
      });
    }
  }

  if (rawEvent?.infection_vector && typeof rawEvent.infection_vector === 'object') {
    const items = Object.entries(rawEvent.infection_vector)
      .filter(([, value]) => value && typeof value !== 'object')
      .slice(0, 6)
      .map(([key, value]) => ({ label: `${formatTitle(key)}: ${value}` }));
    if (items.length) {
      widgets.push({
        type: 'infection_vector',
        title: 'Infection Vector',
        color: '#dc2626',
        items,
        source: 'fallback'
      });
    }
  }

  if (rawEvent?.network_traffic && typeof rawEvent.network_traffic === 'object') {
    const items = [];
    const nt = rawEvent.network_traffic;
    if (nt.ports_used?.length) items.push({ label: `Ports: ${nt.ports_used.join(', ')}` });
    if (nt.mining_protocol) items.push({ label: `Protocol: ${nt.mining_protocol}` });
    if (nt.outbound_connections) items.push({ label: `Outbound Connections: ${nt.outbound_connections}` });
    if (nt.data_sent_mb) items.push({ label: `Data Sent: ${nt.data_sent_mb} MB` });
    if (items.length) {
      widgets.push({
        type: 'network_traffic',
        title: 'Network Activity',
        color: '#3b82f6',
        items,
        source: 'fallback'
      });
    }
  }

  const enrichments = investigation?.enrichment_summary || alertData?.enrichment_data || {};
  if (enrichments && Object.keys(enrichments).length) {
    const items = Object.entries(enrichments).slice(0, 4).map(([provider, data]) => ({
      label: provider,
      status: data?.verdict || data?.status || 'complete',
      score: data?.score
    }));
    widgets.push({
      type: 'enrichment',
      title: 'Enrichment Results',
      color: '#22c55e',
      items,
      source: 'fallback'
    });
  }

  const alertDetails = [];
  ALERT_DETAIL_FIELDS.forEach((field) => {
    const value = rawEvent?.[field];
    if (typeof value === 'string' && value.length) {
      alertDetails.push({ label: `${formatTitle(field)}: ${value.slice(0, 80)}` });
    }
  });
  if (alertDetails.length) {
    widgets.push({
      type: 'alert_details',
      title: 'Alert Details',
      color: '#6366f1',
      items: alertDetails.slice(0, 6),
      source: 'fallback'
    });
  }

  return widgets;
}

function sortWidgets(widgets) {
  const unique = [];
  const seen = new Set();
  widgets.forEach((widget) => {
    const key = `${widget.type}:${widget.title}`.toLowerCase();
    if (!seen.has(key)) {
      seen.add(key);
      unique.push(widget);
    }
  });

  return unique.sort((a, b) => {
    const priA = WIDGET_PRIORITY[a.type] ?? WIDGET_PRIORITY.custom;
    const priB = WIDGET_PRIORITY[b.type] ?? WIDGET_PRIORITY.custom;
    if (priA !== priB) return priA - priB;
    return (a.title || '').localeCompare(b.title || '');
  });
}

export function buildRiggsInsights(investigation, alertData) {
  let invData = safeParseJSON(investigation?.investigation_data || {});
  if (!invData || typeof invData !== 'object') invData = {};

  const riggsAnalysis = invData.riggs_analysis || {};
  const tier2 = invData.tier2_analysis || {};
  const tier1 = invData.tier1_analysis || invData.tier1_findings || {};

  const analysis = riggsAnalysis.verdict
    ? riggsAnalysis
    : (tier1.key_findings?.length ? tier1 : (tier2.verdict ? tier2 : tier1));

  const apiVerdict = investigation?.ai_verdict || investigation?.final_verdict || investigation?.provisional_verdict;
  const apiConfidence = investigation?.ai_confidence ?? investigation?.final_confidence ?? investigation?.provisional_confidence ?? investigation?.confidence;
  const apiKeyFindings = investigation?.key_findings;
  const apiThreatType = investigation?.threat_type;
  const apiAiTriage = investigation?.ai_triage || {};

  let rawEvent = safeParseJSON(invData?.raw_alert || invData?.raw_event || {});
  if (!rawEvent.affected_hosts && alertData?.affected_hosts) rawEvent = { ...rawEvent, ...alertData };
  if (!rawEvent.impact && alertData?.impact) rawEvent = { ...rawEvent, ...alertData };
  if (!rawEvent.recommendations && alertData?.recommendations) rawEvent = { ...rawEvent, ...alertData };
  if (!rawEvent.infection_vector && alertData?.infection_vector) rawEvent = { ...rawEvent, ...alertData };
  if (!rawEvent.network_traffic && alertData?.network_traffic) rawEvent = { ...rawEvent, ...alertData };

  const enrichmentMap = buildEnrichmentMap({ alertData, invData, analysis, tier1, tier2 });
  const coreInfo = buildCoreInfo({
    investigation,
    analysis,
    riggsAnalysis,
    tier1,
    tier2,
    apiVerdict,
    apiConfidence,
    apiThreatType,
    apiKeyFindings,
    apiAiTriage,
    alertData,
    rawEvent
  });

  const riggsWidgets = apiAiTriage.display_widgets || tier1.display_widgets || tier2.display_widgets || analysis.display_widgets;

  let widgets = [];
  if (Array.isArray(riggsWidgets) && riggsWidgets.length) {
    widgets = buildWidgetsFromRiggs(riggsWidgets, enrichmentMap);
  } else {
    widgets = buildWidgetsFromFallback({
      analysis,
      riggsAnalysis,
      tier1,
      tier2,
      alertData,
      rawEvent,
      enrichmentMap,
      investigation
    });
  }

  return {
    coreInfo: {
      ...coreInfo,
      confidence: normalizeConfidence(coreInfo.confidence)
    },
    widgets: sortWidgets(widgets)
  };
}

export { WIDGET_TYPES };
