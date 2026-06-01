# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Action Mapping Tables

Maps actions from SOAR platforms to T1 Agentics native node types.
Each entry maps: source_action -> (node_type, base_config)

Supported platforms:
- Splunk SOAR (Phantom)
- Palo Alto XSOAR (Demisto)
- Tines
- Swimlane
- Google Chronicle SOAR (Siemplify)
- IBM QRadar SOAR (Resilient)
"""

from typing import Dict, Tuple, Any


# ============================================================================
# Splunk SOAR (Phantom) Action Mappings
# ============================================================================

SPLUNK_SOAR_ACTIONS: Dict[str, Tuple[str, Dict[str, Any]]] = {
    # Enrichment - IP
    'ip_reputation': ('enrich', {'integration': 'virustotal', 'observable_type': 'ip'}),
    'ip_lookup': ('enrich', {'integration': 'virustotal', 'observable_type': 'ip'}),
    'geolocate_ip': ('enrich', {'integration': 'ipinfo', 'observable_type': 'ip'}),
    'whois_ip': ('enrich', {'integration': 'whois', 'observable_type': 'ip'}),
    'reverse_ip': ('enrich', {'integration': 'dns', 'observable_type': 'ip'}),
    'hunt_ip': ('enrich', {'integration': 'threat_intel', 'observable_type': 'ip'}),

    # Enrichment - Domain
    'domain_reputation': ('enrich', {'integration': 'virustotal', 'observable_type': 'domain'}),
    'domain_lookup': ('enrich', {'integration': 'virustotal', 'observable_type': 'domain'}),
    'whois_domain': ('enrich', {'integration': 'whois', 'observable_type': 'domain'}),
    'dns_lookup': ('enrich', {'integration': 'dns', 'observable_type': 'domain'}),
    'hunt_domain': ('enrich', {'integration': 'threat_intel', 'observable_type': 'domain'}),

    # Enrichment - Hash/File
    'file_reputation': ('enrich', {'integration': 'virustotal', 'observable_type': 'hash'}),
    'hunt_file': ('enrich', {'integration': 'virustotal', 'observable_type': 'hash'}),
    'detonate_file': ('enrich', {'integration': 'sandbox', 'observable_type': 'hash'}),
    'get_file': ('enrich', {'integration': 'edr', 'observable_type': 'hash'}),
    'get_file_info': ('enrich', {'integration': 'edr', 'observable_type': 'hash'}),

    # Enrichment - URL
    'url_reputation': ('enrich', {'integration': 'virustotal', 'observable_type': 'url'}),
    'detonate_url': ('enrich', {'integration': 'urlscan', 'observable_type': 'url'}),

    # Enrichment - User
    'get_user_attributes': ('enrich', {'integration': 'ldap', 'observable_type': 'user'}),
    'lookup_user': ('enrich', {'integration': 'identity', 'observable_type': 'user'}),

    # Enrichment - Host/System
    'get_system_info': ('enrich', {'integration': 'edr', 'observable_type': 'host'}),
    'list_processes': ('enrich', {'integration': 'edr', 'observable_type': 'host'}),
    'list_connections': ('enrich', {'integration': 'edr', 'observable_type': 'host'}),

    # Enrichment - SIEM
    'run_query': ('enrich', {'integration': 'siem', 'observable_type': 'query'}),
    'get_events': ('enrich', {'integration': 'siem', 'observable_type': 'events'}),

    # Containment - Host
    'quarantine_device': ('action', {'action_type': 'contain_host', 'requires_approval': True}),
    'contain_device': ('action', {'action_type': 'contain_host', 'requires_approval': True}),
    'isolate_device': ('action', {'action_type': 'contain_host', 'requires_approval': True}),
    'unquarantine_device': ('action', {'action_type': 'uncontain_host', 'requires_approval': True}),
    'terminate_process': ('action', {'action_type': 'kill_process', 'requires_approval': True}),

    # Containment - Network
    'block_ip': ('action', {'action_type': 'block_ip', 'requires_approval': True}),
    'unblock_ip': ('action', {'action_type': 'unblock_ip', 'requires_approval': True}),
    'block_domain': ('action', {'action_type': 'block_domain', 'requires_approval': True}),
    'block_url': ('action', {'action_type': 'block_url', 'requires_approval': True}),
    'block_hash': ('action', {'action_type': 'block_hash', 'requires_approval': True}),

    # Containment - User
    'disable_user': ('action', {'action_type': 'disable_user', 'requires_approval': True}),
    'enable_user': ('action', {'action_type': 'enable_user', 'requires_approval': True}),
    'reset_password': ('action', {'action_type': 'reset_password', 'requires_approval': True}),
    'revoke_sessions': ('action', {'action_type': 'revoke_sessions', 'requires_approval': True}),

    # Ticketing
    'create_ticket': ('create_ticket', {'integration': 'servicenow'}),
    'update_ticket': ('action', {'action_type': 'update_ticket'}),
    'get_ticket': ('enrich', {'integration': 'servicenow', 'observable_type': 'ticket'}),
    'close_ticket': ('action', {'action_type': 'close_ticket'}),

    # Notification
    'send_email': ('notify', {'channel': 'email'}),
    'send_message': ('notify', {'channel': 'slack'}),
    'post_slack_message': ('notify', {'channel': 'slack'}),
    'send_teams_message': ('notify', {'channel': 'teams'}),

    # Flow Control
    'decision': ('condition', {}),
    'filter': ('condition', {}),
    'prompt': ('approval_gate', {}),
    'playbook': ('action', {'action_type': 'run_playbook'}),

    # Custom Code
    'code': ('python_code', {}),
    'custom_function': ('function_call', {}),

    # Data
    'format': ('transform', {'transform_type': 'format'}),
    'join': ('transform', {'transform_type': 'join'}),
    'split': ('transform', {'transform_type': 'split'}),
}


# ============================================================================
# Palo Alto XSOAR (Demisto) Command Mappings
# ============================================================================

XSOAR_COMMANDS: Dict[str, Tuple[str, Dict[str, Any]]] = {
    # Enrichment - IP
    '!ip': ('enrich', {'observable_type': 'ip'}),
    'ip': ('enrich', {'observable_type': 'ip'}),
    '!vt_ip_reputation': ('enrich', {'integration': 'virustotal', 'observable_type': 'ip'}),
    '!shodan_ip_info': ('enrich', {'integration': 'shodan', 'observable_type': 'ip'}),
    '!abuseipdb_check_ip': ('enrich', {'integration': 'abuseipdb', 'observable_type': 'ip'}),
    '!greynoise_ip': ('enrich', {'integration': 'greynoise', 'observable_type': 'ip'}),

    # Enrichment - Domain
    '!domain': ('enrich', {'observable_type': 'domain'}),
    'domain': ('enrich', {'observable_type': 'domain'}),
    '!vt_domain_reputation': ('enrich', {'integration': 'virustotal', 'observable_type': 'domain'}),
    '!whois': ('enrich', {'integration': 'whois', 'observable_type': 'domain'}),

    # Enrichment - Hash/File
    '!file': ('enrich', {'observable_type': 'hash'}),
    'file': ('enrich', {'observable_type': 'hash'}),
    '!vt_file_reputation': ('enrich', {'integration': 'virustotal', 'observable_type': 'hash'}),
    '!wildfire_get_report': ('enrich', {'integration': 'wildfire', 'observable_type': 'hash'}),
    '!cve_search': ('enrich', {'integration': 'cve', 'observable_type': 'vulnerability'}),
    '!cve': ('enrich', {'integration': 'cve', 'observable_type': 'vulnerability'}),

    # Enrichment - URL
    '!url': ('enrich', {'observable_type': 'url'}),
    'url': ('enrich', {'observable_type': 'url'}),
    '!urlscan_submit': ('enrich', {'integration': 'urlscan', 'observable_type': 'url'}),

    # Enrichment - Threat Intel
    '!threatstream_ip_reputation': ('enrich', {'integration': 'anomali', 'observable_type': 'ip'}),
    '!threatstream_domain_reputation': ('enrich', {'integration': 'anomali', 'observable_type': 'domain'}),
    '!threatstream_file_reputation': ('enrich', {'integration': 'anomali', 'observable_type': 'hash'}),
    '!misp_search': ('enrich', {'integration': 'misp', 'observable_type': 'indicator'}),
    '!misp_search_events': ('enrich', {'integration': 'misp', 'observable_type': 'events'}),

    # EDR - CrowdStrike
    '!cs_falcon_search_device': ('enrich', {'integration': 'crowdstrike', 'observable_type': 'host'}),
    '!cs_falcon_host_containment': ('action', {'action_type': 'contain_host', 'integration': 'crowdstrike', 'requires_approval': True}),
    '!cs_falcon_lift_host_containment': ('action', {'action_type': 'uncontain_host', 'integration': 'crowdstrike', 'requires_approval': True}),
    '!cs_falcon_run_command': ('action', {'action_type': 'run_command', 'integration': 'crowdstrike', 'requires_approval': True}),

    # EDR - SentinelOne
    '!sentinelone_get_agent': ('enrich', {'integration': 'sentinelone', 'observable_type': 'host'}),
    '!sentinelone_disconnect_agent': ('action', {'action_type': 'contain_host', 'integration': 'sentinelone', 'requires_approval': True}),
    '!sentinelone_connect_agent': ('action', {'action_type': 'uncontain_host', 'integration': 'sentinelone', 'requires_approval': True}),

    # EDR - Cortex XDR
    '!cortex_xdr_isolate_endpoint': ('action', {'action_type': 'contain_host', 'integration': 'cortex_xdr', 'requires_approval': True}),
    '!cortex_xdr_unisolate_endpoint': ('action', {'action_type': 'uncontain_host', 'integration': 'cortex_xdr', 'requires_approval': True}),
    '!cortex_xdr_get_incidents': ('enrich', {'integration': 'cortex_xdr', 'observable_type': 'incident'}),

    # EDR - Generic
    '!endpoint_isolate': ('action', {'action_type': 'contain_host', 'requires_approval': True}),
    '!endpoint_unisolate': ('action', {'action_type': 'uncontain_host', 'requires_approval': True}),

    # Identity - AD
    '!ad_disable_user': ('action', {'action_type': 'disable_user', 'integration': 'active_directory', 'requires_approval': True}),
    '!ad_enable_user': ('action', {'action_type': 'enable_user', 'integration': 'active_directory', 'requires_approval': True}),
    '!ad_reset_password': ('action', {'action_type': 'reset_password', 'integration': 'active_directory', 'requires_approval': True}),
    '!ad_get_user': ('enrich', {'integration': 'active_directory', 'observable_type': 'user'}),

    # Identity - Okta
    '!okta_deactivate_user': ('action', {'action_type': 'disable_user', 'integration': 'okta', 'requires_approval': True}),
    '!okta_activate_user': ('action', {'action_type': 'enable_user', 'integration': 'okta', 'requires_approval': True}),
    '!okta_clear_sessions': ('action', {'action_type': 'revoke_sessions', 'integration': 'okta', 'requires_approval': True}),

    # Firewall - Palo Alto
    '!pan_os_block_ip': ('action', {'action_type': 'block_ip', 'integration': 'palo_alto', 'requires_approval': True}),
    '!pan_os_unblock_ip': ('action', {'action_type': 'unblock_ip', 'integration': 'palo_alto', 'requires_approval': True}),
    '!panorama_create_rule': ('action', {'action_type': 'create_rule', 'integration': 'palo_alto', 'requires_approval': True}),
    '!panorama_commit': ('action', {'action_type': 'commit_config', 'integration': 'palo_alto', 'requires_approval': True}),

    # Ticketing
    '!servicenow_create_ticket': ('create_ticket', {'integration': 'servicenow'}),
    '!servicenow_update_ticket': ('action', {'action_type': 'update_ticket', 'integration': 'servicenow'}),
    '!jira_create_issue': ('create_ticket', {'integration': 'jira'}),
    '!jira_edit_issue': ('action', {'action_type': 'update_ticket', 'integration': 'jira'}),

    # Notification
    '!send_mail': ('notify', {'channel': 'email'}),
    '!slack_send': ('notify', {'channel': 'slack'}),
    '!ms_teams_send_message': ('notify', {'channel': 'teams'}),

    # Utilities
    '!set': ('variable_set', {}),
    '!setincident': ('action', {'action_type': 'update_incident'}),
    '!closeInvestigation': ('end', {'disposition': 'completed'}),
    '!sleep': ('delay', {}),

    # Custom
    '!script': ('python_code', {}),
    'automation': ('python_code', {}),
}


# ============================================================================
# Tines Agent Type Mappings
# ============================================================================

TINES_AGENTS: Dict[str, Tuple[str, Dict[str, Any]]] = {
    # Core Agents
    'httpRequestAgent': ('webhook_call', {}),
    'webhookAgent': ('trigger', {'trigger_type': 'webhook'}),
    'scheduleAgent': ('trigger', {'trigger_type': 'schedule'}),
    'receiveEventsAgent': ('trigger', {'trigger_type': 'event'}),
    'emitEventsAgent': ('notify', {}),

    # Logic
    'eventTransformationAgent': ('transform', {}),
    'triggerAgent': ('condition', {}),
    'ifThenAgent': ('condition', {}),
    'delayAgent': ('delay', {}),

    # Human in the Loop
    'humanInTheLoopAgent': ('approval_gate', {}),
    'formAgent': ('webform', {}),
    'sendEmailAgent': ('notify', {'channel': 'email'}),
    'slackAgent': ('notify', {'channel': 'slack'}),

    # Data
    'dataLookupAgent': ('list_lookup', {}),
    'storeAgent': ('variable_set', {}),
    'readAgent': ('variable_get', {}),
    'dedupeAgent': ('transform', {'transform_type': 'dedupe'}),

    # Enrichment (inferred from HTTP calls)
    'virusTotal': ('enrich', {'integration': 'virustotal'}),
    'urlscan': ('enrich', {'integration': 'urlscan'}),
    'shodan': ('enrich', {'integration': 'shodan'}),

    # Actions (inferred from HTTP calls)
    'crowdstrike': ('action', {'integration': 'crowdstrike'}),
    'okta': ('action', {'integration': 'okta'}),
    'servicenow': ('action', {'integration': 'servicenow'}),
}


# ============================================================================
# Swimlane Action Mappings
# ============================================================================

SWIMLANE_ACTIONS: Dict[str, Tuple[str, Dict[str, Any]]] = {
    # Flow Control
    'trigger': ('trigger', {'trigger_type': 'alert'}),
    'condition': ('condition', {}),
    'script': ('python_code', {}),
    'subplaybook': ('action', {'action_type': 'run_playbook'}),
    'sub_playbook': ('action', {'action_type': 'run_playbook'}),
    'utility': ('transform', {}),

    # Enrichment by family
    'ip_reputation': ('enrich', {'observable_type': 'ip'}),
    'ip_lookup': ('enrich', {'observable_type': 'ip'}),
    'domain_reputation': ('enrich', {'observable_type': 'domain'}),
    'domain_lookup': ('enrich', {'observable_type': 'domain'}),
    'file_reputation': ('enrich', {'observable_type': 'hash'}),
    'file_lookup': ('enrich', {'observable_type': 'hash'}),
    'url_reputation': ('enrich', {'observable_type': 'url'}),
    'url_lookup': ('enrich', {'observable_type': 'url'}),
    'hash_lookup': ('enrich', {'observable_type': 'hash'}),
    'whois': ('enrich', {'integration': 'whois'}),
    'dns_lookup': ('enrich', {'integration': 'dns'}),
    'geolocation': ('enrich', {'integration': 'ipinfo'}),

    # Containment
    'isolate_endpoint': ('action', {'action_type': 'contain_host', 'requires_approval': True}),
    'contain_host': ('action', {'action_type': 'contain_host', 'requires_approval': True}),
    'block_ip': ('action', {'action_type': 'block_ip', 'requires_approval': True}),
    'block_domain': ('action', {'action_type': 'block_domain', 'requires_approval': True}),
    'block_hash': ('action', {'action_type': 'block_hash', 'requires_approval': True}),
    'disable_user': ('action', {'action_type': 'disable_user', 'requires_approval': True}),
    'reset_password': ('action', {'action_type': 'reset_password', 'requires_approval': True}),

    # Ticketing
    'create_record': ('create_ticket', {}),
    'update_record': ('action', {'action_type': 'update_ticket'}),
    'create_incident': ('create_ticket', {}),
    'close_incident': ('action', {'action_type': 'close_ticket'}),

    # Notification
    'send_email': ('notify', {'channel': 'email'}),
    'send_slack': ('notify', {'channel': 'slack'}),
    'send_teams': ('notify', {'channel': 'teams'}),
    'send_notification': ('notify', {}),

    # Data
    'set_variable': ('variable_set', {}),
    'get_variable': ('variable_get', {}),
    'transform_data': ('transform', {}),
}


# ============================================================================
# Google Chronicle SOAR (Siemplify) Action Mappings
# ============================================================================

CHRONICLE_SOAR_ACTIONS: Dict[str, Tuple[str, Dict[str, Any]]] = {
    # Enrichment - integration.action format "Integration.Action"
    'virustotal.scan_ip': ('enrich', {'integration': 'virustotal', 'observable_type': 'ip'}),
    'virustotal.scan_domain': ('enrich', {'integration': 'virustotal', 'observable_type': 'domain'}),
    'virustotal.scan_hash': ('enrich', {'integration': 'virustotal', 'observable_type': 'hash'}),
    'virustotal.scan_url': ('enrich', {'integration': 'virustotal', 'observable_type': 'url'}),
    'virustotal.scan_file': ('enrich', {'integration': 'virustotal', 'observable_type': 'hash'}),

    'urlscan.submit_url': ('enrich', {'integration': 'urlscan', 'observable_type': 'url'}),
    'shodan.search_ip': ('enrich', {'integration': 'shodan', 'observable_type': 'ip'}),
    'abuseipdb.check_ip': ('enrich', {'integration': 'abuseipdb', 'observable_type': 'ip'}),
    'whois.lookup': ('enrich', {'integration': 'whois'}),

    # EDR
    'crowdstrike.contain_host': ('action', {'action_type': 'contain_host', 'integration': 'crowdstrike', 'requires_approval': True}),
    'crowdstrike.lift_containment': ('action', {'action_type': 'uncontain_host', 'integration': 'crowdstrike', 'requires_approval': True}),
    'crowdstrike.get_device': ('enrich', {'integration': 'crowdstrike', 'observable_type': 'host'}),
    'sentinelone.isolate_agent': ('action', {'action_type': 'contain_host', 'integration': 'sentinelone', 'requires_approval': True}),
    'carbon_black.isolate_device': ('action', {'action_type': 'contain_host', 'integration': 'carbon_black', 'requires_approval': True}),

    # Network
    'firewall.block_ip': ('action', {'action_type': 'block_ip', 'requires_approval': True}),
    'firewall.unblock_ip': ('action', {'action_type': 'unblock_ip', 'requires_approval': True}),
    'firewall.block_domain': ('action', {'action_type': 'block_domain', 'requires_approval': True}),

    # Identity
    'active_directory.disable_user': ('action', {'action_type': 'disable_user', 'integration': 'active_directory', 'requires_approval': True}),
    'active_directory.get_user': ('enrich', {'integration': 'active_directory', 'observable_type': 'user'}),
    'okta.deactivate_user': ('action', {'action_type': 'disable_user', 'integration': 'okta', 'requires_approval': True}),

    # Ticketing
    'servicenow.create_ticket': ('create_ticket', {'integration': 'servicenow'}),
    'servicenow.update_ticket': ('action', {'action_type': 'update_ticket', 'integration': 'servicenow'}),
    'jira.create_issue': ('create_ticket', {'integration': 'jira'}),
    'jira.update_issue': ('action', {'action_type': 'update_ticket', 'integration': 'jira'}),

    # Notification
    'email.send': ('notify', {'channel': 'email'}),
    'email.send_email': ('notify', {'channel': 'email'}),
    'slack.send_message': ('notify', {'channel': 'slack'}),
    'teams.send_message': ('notify', {'channel': 'teams'}),

    # SIEM
    'siemplify.get_alerts': ('enrich', {'integration': 'siem', 'observable_type': 'alerts'}),
    'siemplify.close_case': ('end', {'disposition': 'completed'}),
    'siemplify.add_comment': ('action', {'action_type': 'add_comment'}),

    # Step types (as fallback)
    'trigger': ('trigger', {'trigger_type': 'alert'}),
    'condition': ('condition', {}),
    'parallel': ('transform', {'transform_type': 'parallel'}),
    'placeholder': ('approval_gate', {}),
}


# ============================================================================
# IBM QRadar SOAR (Resilient) Action Mappings
# ============================================================================

QRADAR_SOAR_ACTIONS: Dict[str, Tuple[str, Dict[str, Any]]] = {
    # Functions map: fn_name → (node_type, config)
    # Enrichment
    'fn_virustotal': ('enrich', {'integration': 'virustotal'}),
    'fn_virustotal_scan': ('enrich', {'integration': 'virustotal'}),
    'fn_urlscanio': ('enrich', {'integration': 'urlscan'}),
    'fn_shodan': ('enrich', {'integration': 'shodan'}),
    'fn_whois': ('enrich', {'integration': 'whois'}),
    'fn_abuseipdb': ('enrich', {'integration': 'abuseipdb'}),
    'fn_misp': ('enrich', {'integration': 'misp'}),
    'fn_greynoise': ('enrich', {'integration': 'greynoise'}),
    'fn_hibp': ('enrich', {'integration': 'haveibeenpwned'}),
    'fn_qradar_search': ('enrich', {'integration': 'qradar', 'observable_type': 'query'}),

    # EDR
    'fn_crowdstrike_falcon': ('action', {'integration': 'crowdstrike', 'requires_approval': True}),
    'fn_sentinelone': ('action', {'integration': 'sentinelone', 'requires_approval': True}),
    'fn_carbon_black': ('action', {'integration': 'carbon_black', 'requires_approval': True}),
    'fn_microsoft_defender': ('action', {'integration': 'microsoft_defender', 'requires_approval': True}),

    # Network
    'fn_palo_alto': ('action', {'action_type': 'firewall_action', 'integration': 'palo_alto', 'requires_approval': True}),
    'fn_cisco_asa': ('action', {'action_type': 'firewall_action', 'integration': 'cisco_asa', 'requires_approval': True}),

    # Identity
    'fn_ldap': ('action', {'integration': 'ldap'}),
    'fn_active_directory': ('action', {'integration': 'active_directory'}),
    'fn_okta': ('action', {'integration': 'okta', 'requires_approval': True}),

    # Ticketing
    'fn_servicenow': ('create_ticket', {'integration': 'servicenow'}),
    'fn_jira': ('create_ticket', {'integration': 'jira'}),

    # Notification
    'fn_email': ('notify', {'channel': 'email'}),
    'fn_slack': ('notify', {'channel': 'slack'}),
    'fn_teams': ('notify', {'channel': 'teams'}),

    # Utilities
    'fn_utilities': ('transform', {}),
    'fn_timer': ('delay', {}),
    'fn_parse_utilities': ('transform', {'transform_type': 'parse'}),

    # Cloud
    'fn_aws_iam': ('action', {'integration': 'aws_iam', 'requires_approval': True}),
    'fn_aws_guardduty': ('enrich', {'integration': 'aws_guardduty'}),
    'fn_azure_automation': ('action', {'integration': 'azure', 'requires_approval': True}),

    # BPMN element types (for XML parsing)
    'startevent': ('trigger', {'trigger_type': 'alert'}),
    'endevent': ('end', {'disposition': 'completed'}),
    'exclusivegateway': ('condition', {}),
    'scripttask': ('python_code', {}),
    'servicetask': ('action', {'auto_mapped': True}),
}


# ============================================================================
# Microsoft Sentinel (Azure Logic Apps) Action Mappings
# ============================================================================

SENTINEL_ACTIONS: Dict[str, Tuple[str, Dict[str, Any]]] = {
    # Sentinel Connectors (by apiId / connection name)
    'azuresentinel': ('enrich', {'integration': 'sentinel', 'observable_type': 'incident'}),
    'azuresentinel_get_incident': ('enrich', {'integration': 'sentinel', 'observable_type': 'incident'}),
    'azuresentinel_update_incident': ('action', {'action_type': 'update_incident', 'integration': 'sentinel'}),
    'azuresentinel_add_comment': ('action', {'action_type': 'add_comment', 'integration': 'sentinel'}),
    'azuresentinel_change_incident_status': ('action', {'action_type': 'update_status', 'integration': 'sentinel'}),
    'azuresentinel_entities_get_ips': ('enrich', {'integration': 'sentinel', 'observable_type': 'ip'}),
    'azuresentinel_entities_get_accounts': ('enrich', {'integration': 'sentinel', 'observable_type': 'user'}),
    'azuresentinel_entities_get_hosts': ('enrich', {'integration': 'sentinel', 'observable_type': 'host'}),
    'azuresentinel_entities_get_urls': ('enrich', {'integration': 'sentinel', 'observable_type': 'url'}),
    'azuresentinel_entities_get_filehashes': ('enrich', {'integration': 'sentinel', 'observable_type': 'hash'}),

    # Office 365 / Exchange
    'office365': ('action', {'integration': 'office365'}),
    'office365_send_email': ('notify', {'channel': 'email', 'integration': 'office365'}),
    'office365_get_email': ('enrich', {'integration': 'office365', 'observable_type': 'email'}),
    'office365_delete_email': ('action', {'action_type': 'delete_email', 'integration': 'office365', 'requires_approval': True}),
    'office365_soft_delete_email': ('action', {'action_type': 'delete_email', 'integration': 'office365', 'requires_approval': True}),

    # Azure AD / Entra ID
    'azuread': ('action', {'integration': 'azure_ad'}),
    'azuread_get_user': ('enrich', {'integration': 'azure_ad', 'observable_type': 'user'}),
    'azuread_disable_user': ('action', {'action_type': 'disable_user', 'integration': 'azure_ad', 'requires_approval': True}),
    'azuread_enable_user': ('action', {'action_type': 'enable_user', 'integration': 'azure_ad', 'requires_approval': True}),
    'azuread_revoke_sessions': ('action', {'action_type': 'revoke_sessions', 'integration': 'azure_ad', 'requires_approval': True}),
    'azuread_reset_password': ('action', {'action_type': 'reset_password', 'integration': 'azure_ad', 'requires_approval': True}),
    'azuread_get_group_members': ('enrich', {'integration': 'azure_ad', 'observable_type': 'group'}),

    # Microsoft Teams
    'teams': ('notify', {'channel': 'teams'}),
    'teams_post_message': ('notify', {'channel': 'teams'}),
    'teams_post_adaptive_card': ('notify', {'channel': 'teams', 'card_type': 'adaptive'}),

    # Microsoft Defender for Endpoint
    'wdatp': ('action', {'integration': 'microsoft_defender'}),
    'wdatp_isolate_machine': ('action', {'action_type': 'contain_host', 'integration': 'microsoft_defender', 'requires_approval': True}),
    'wdatp_unisolate_machine': ('action', {'action_type': 'uncontain_host', 'integration': 'microsoft_defender', 'requires_approval': True}),
    'wdatp_run_antivirus_scan': ('action', {'action_type': 'scan_host', 'integration': 'microsoft_defender'}),
    'wdatp_get_machine_info': ('enrich', {'integration': 'microsoft_defender', 'observable_type': 'host'}),
    'wdatp_stop_and_quarantine_file': ('action', {'action_type': 'quarantine_file', 'integration': 'microsoft_defender', 'requires_approval': True}),
    'wdatp_collect_investigation_package': ('enrich', {'integration': 'microsoft_defender', 'observable_type': 'forensics'}),

    # VirusTotal
    'virustotal': ('enrich', {'integration': 'virustotal'}),
    'virustotal_get_ip_report': ('enrich', {'integration': 'virustotal', 'observable_type': 'ip'}),
    'virustotal_get_domain_report': ('enrich', {'integration': 'virustotal', 'observable_type': 'domain'}),
    'virustotal_get_file_report': ('enrich', {'integration': 'virustotal', 'observable_type': 'hash'}),
    'virustotal_get_url_report': ('enrich', {'integration': 'virustotal', 'observable_type': 'url'}),

    # ServiceNow
    'servicenow': ('create_ticket', {'integration': 'servicenow'}),
    'servicenow_create_record': ('create_ticket', {'integration': 'servicenow'}),
    'servicenow_update_record': ('action', {'action_type': 'update_ticket', 'integration': 'servicenow'}),

    # Jira
    'jira': ('create_ticket', {'integration': 'jira'}),

    # CrowdStrike
    'crowdstrike_falcon': ('action', {'integration': 'crowdstrike'}),

    # Logic App Built-in Action Types
    'http': ('webhook_call', {}),
    'compose': ('transform', {'transform_type': 'compose'}),
    'parsejson': ('transform', {'transform_type': 'parse_json'}),
    'select': ('transform', {'transform_type': 'select'}),
    'filter': ('condition', {}),
    'join': ('transform', {'transform_type': 'join'}),
    'createarray': ('transform', {'transform_type': 'create_array'}),
    'initializevariable': ('variable_set', {}),
    'setvariable': ('variable_set', {}),
    'appendtoarrayvariable': ('variable_set', {'append': True}),
    'incrementvariable': ('variable_set', {'increment': True}),
    'terminate': ('end', {'disposition': 'completed'}),
    'response': ('notify', {'channel': 'webhook_response'}),
    'delay': ('delay', {}),
    'wait': ('delay', {}),

    # Flow Control
    'if': ('condition', {}),
    'switch': ('condition', {'condition_type': 'switch'}),
    'foreach': ('transform', {'transform_type': 'loop'}),
    'until': ('transform', {'transform_type': 'loop'}),
    'scope': ('transform', {'transform_type': 'scope'}),

    # Triggers (mapped in converter detect, but useful for fallback)
    'when_a_response_to_an_azure_sentinel_alert_is_triggered': ('trigger', {'trigger_type': 'sentinel_alert'}),
    'when_azure_sentinel_incident_creation_rule_was_triggered': ('trigger', {'trigger_type': 'sentinel_incident'}),
    'recurrence': ('trigger', {'trigger_type': 'schedule'}),
}


# ============================================================================
# FortiSOAR (Fortinet) Action Mappings
# ============================================================================

FORTISOAR_ACTIONS: Dict[str, Tuple[str, Dict[str, Any]]] = {
    # Step Types
    'startstep': ('trigger', {'trigger_type': 'alert'}),
    'endstep': ('end', {'disposition': 'completed'}),
    'decision': ('condition', {}),
    'approval': ('approval_gate', {}),
    'manualinput': ('approval_gate', {'input_type': 'manual'}),
    'setvariable': ('variable_set', {}),
    'set_variable': ('variable_set', {}),
    'delay': ('delay', {}),
    'executeplaybook': ('action', {'action_type': 'run_playbook'}),
    'execute_playbook': ('action', {'action_type': 'run_playbook'}),

    # API Steps
    'api': ('webhook_call', {}),
    'api_call': ('webhook_call', {}),

    # Connector: VirusTotal
    'virustotal': ('enrich', {'integration': 'virustotal'}),
    'virustotal_get_ip_reputation': ('enrich', {'integration': 'virustotal', 'observable_type': 'ip'}),
    'virustotal_get_domain_reputation': ('enrich', {'integration': 'virustotal', 'observable_type': 'domain'}),
    'virustotal_get_hash_reputation': ('enrich', {'integration': 'virustotal', 'observable_type': 'hash'}),
    'virustotal_get_url_reputation': ('enrich', {'integration': 'virustotal', 'observable_type': 'url'}),
    'virustotal_scan_file': ('enrich', {'integration': 'virustotal', 'observable_type': 'hash'}),
    'virustotal_scan_url': ('enrich', {'integration': 'virustotal', 'observable_type': 'url'}),

    # Connector: CrowdStrike
    'crowdstrike': ('action', {'integration': 'crowdstrike'}),
    'crowdstrike_contain_host': ('action', {'action_type': 'contain_host', 'integration': 'crowdstrike', 'requires_approval': True}),
    'crowdstrike_lift_containment': ('action', {'action_type': 'uncontain_host', 'integration': 'crowdstrike', 'requires_approval': True}),
    'crowdstrike_get_device_details': ('enrich', {'integration': 'crowdstrike', 'observable_type': 'host'}),
    'crowdstrike_search_detections': ('enrich', {'integration': 'crowdstrike', 'observable_type': 'detection'}),

    # Connector: SentinelOne
    'sentinelone': ('action', {'integration': 'sentinelone'}),
    'sentinelone_disconnect_agent': ('action', {'action_type': 'contain_host', 'integration': 'sentinelone', 'requires_approval': True}),
    'sentinelone_connect_agent': ('action', {'action_type': 'uncontain_host', 'integration': 'sentinelone', 'requires_approval': True}),

    # Connector: Active Directory
    'activedirectory': ('action', {'integration': 'active_directory'}),
    'active_directory': ('action', {'integration': 'active_directory'}),
    'activedirectory_disable_user': ('action', {'action_type': 'disable_user', 'integration': 'active_directory', 'requires_approval': True}),
    'activedirectory_enable_user': ('action', {'action_type': 'enable_user', 'integration': 'active_directory', 'requires_approval': True}),
    'activedirectory_get_user': ('enrich', {'integration': 'active_directory', 'observable_type': 'user'}),
    'activedirectory_reset_password': ('action', {'action_type': 'reset_password', 'integration': 'active_directory', 'requires_approval': True}),

    # Connector: FortiGate
    'fortigate': ('action', {'integration': 'fortigate'}),
    'fortigate_block_ip': ('action', {'action_type': 'block_ip', 'integration': 'fortigate', 'requires_approval': True}),
    'fortigate_unblock_ip': ('action', {'action_type': 'unblock_ip', 'integration': 'fortigate', 'requires_approval': True}),
    'fortigate_add_address': ('action', {'action_type': 'add_address', 'integration': 'fortigate'}),
    'fortigate_get_policy': ('enrich', {'integration': 'fortigate', 'observable_type': 'policy'}),

    # Connector: FortiSIEM
    'fortisiem': ('enrich', {'integration': 'fortisiem'}),
    'fortisiem_get_events': ('enrich', {'integration': 'fortisiem', 'observable_type': 'events'}),
    'fortisiem_search': ('enrich', {'integration': 'fortisiem', 'observable_type': 'query'}),

    # Connector: URLScan
    'urlscan': ('enrich', {'integration': 'urlscan'}),
    'urlscan_submit_url': ('enrich', {'integration': 'urlscan', 'observable_type': 'url'}),

    # Connector: Shodan
    'shodan': ('enrich', {'integration': 'shodan'}),
    'shodan_search_ip': ('enrich', {'integration': 'shodan', 'observable_type': 'ip'}),

    # Connector: AbuseIPDB
    'abuseipdb': ('enrich', {'integration': 'abuseipdb'}),
    'abuseipdb_check_ip': ('enrich', {'integration': 'abuseipdb', 'observable_type': 'ip'}),

    # Connector: WHOIS
    'whois': ('enrich', {'integration': 'whois'}),
    'whois_lookup': ('enrich', {'integration': 'whois'}),

    # Connector: MISP
    'misp': ('enrich', {'integration': 'misp'}),
    'misp_search': ('enrich', {'integration': 'misp', 'observable_type': 'indicator'}),

    # Ticketing
    'servicenow': ('create_ticket', {'integration': 'servicenow'}),
    'servicenow_create_record': ('create_ticket', {'integration': 'servicenow'}),
    'servicenow_update_record': ('action', {'action_type': 'update_ticket', 'integration': 'servicenow'}),
    'jira': ('create_ticket', {'integration': 'jira'}),
    'jira_create_issue': ('create_ticket', {'integration': 'jira'}),

    # Notification
    'smtp': ('notify', {'channel': 'email'}),
    'send_email': ('notify', {'channel': 'email'}),
    'email': ('notify', {'channel': 'email'}),
    'slack': ('notify', {'channel': 'slack'}),
    'slack_send_message': ('notify', {'channel': 'slack'}),
    'microsoft_teams': ('notify', {'channel': 'teams'}),
    'teams_send_message': ('notify', {'channel': 'teams'}),

    # Utilities
    'utilities': ('transform', {}),
    'code_snippet': ('python_code', {}),
    'create_record': ('action', {'action_type': 'create_record'}),
    'update_record': ('action', {'action_type': 'update_record'}),
    'fetch_record': ('enrich', {'observable_type': 'record'}),
}


# ============================================================================
# ServiceNow Security Operations (Flow Designer) Action Mappings
# ============================================================================

SERVICENOW_SECOPS_ACTIONS: Dict[str, Tuple[str, Dict[str, Any]]] = {
    # Security Incident Management
    'sn_si.create_security_incident': ('create_ticket', {'integration': 'servicenow', 'ticket_type': 'security_incident'}),
    'sn_si.update_security_incident': ('action', {'action_type': 'update_ticket', 'integration': 'servicenow'}),
    'sn_si.close_security_incident': ('action', {'action_type': 'close_ticket', 'integration': 'servicenow'}),
    'sn_si.add_observable': ('action', {'action_type': 'add_observable', 'integration': 'servicenow'}),
    'sn_si.run_playbook': ('action', {'action_type': 'run_playbook', 'integration': 'servicenow'}),
    'sn_si.add_affected_ci': ('action', {'action_type': 'add_affected_ci', 'integration': 'servicenow'}),
    'sn_si.lookup_observable': ('enrich', {'integration': 'servicenow', 'observable_type': 'indicator'}),
    'sn_si.get_threat_score': ('enrich', {'integration': 'servicenow', 'observable_type': 'threat_score'}),
    'sn_si.request_approval': ('approval_gate', {'integration': 'servicenow'}),

    # Vulnerability Response
    'sn_vul.create_vulnerable_item': ('create_ticket', {'integration': 'servicenow', 'ticket_type': 'vulnerability'}),
    'sn_vul.update_vulnerable_item': ('action', {'action_type': 'update_ticket', 'integration': 'servicenow'}),
    'sn_vul.assign_remediation': ('action', {'action_type': 'assign_ticket', 'integration': 'servicenow'}),

    # Threat Intelligence
    'sn_ti.lookup_observable': ('enrich', {'integration': 'servicenow_ti', 'observable_type': 'indicator'}),
    'sn_ti.create_sighting': ('action', {'action_type': 'create_sighting', 'integration': 'servicenow_ti'}),
    'sn_ti.enrich_observable': ('enrich', {'integration': 'servicenow_ti', 'observable_type': 'enrichment'}),

    # Global / Built-in Actions
    'global.run_script': ('python_code', {'integration': 'servicenow'}),
    'global.http': ('webhook_call', {}),
    'global.send_email': ('notify', {'channel': 'email'}),
    'global.send_notification': ('notify', {'channel': 'servicenow'}),
    'global.slack_post': ('notify', {'channel': 'slack'}),
    'global.teams_post': ('notify', {'channel': 'teams'}),
    'global.approval': ('approval_gate', {}),
    'global.wait_for': ('delay', {}),
    'global.create_record': ('create_ticket', {'integration': 'servicenow'}),
    'global.update_record': ('action', {'action_type': 'update_record', 'integration': 'servicenow'}),
    'global.lookup_record': ('enrich', {'integration': 'servicenow', 'observable_type': 'record'}),
    'global.delete_record': ('action', {'action_type': 'delete_record', 'integration': 'servicenow', 'requires_approval': True}),
    'global.transform_data': ('transform', {}),
    'global.log_message': ('action', {'action_type': 'log_message'}),

    # Flow Logic Types
    'global.if': ('condition', {}),
    'global.else_if': ('condition', {}),
    'global.do_until': ('transform', {'transform_type': 'loop'}),
    'global.for_each': ('transform', {'transform_type': 'loop'}),

    # CMDB
    'global.lookup_ci': ('enrich', {'integration': 'servicenow_cmdb', 'observable_type': 'ci'}),
    'global.update_ci': ('action', {'action_type': 'update_ci', 'integration': 'servicenow_cmdb'}),

    # Orchestration
    'sn_orchestration.run_command': ('action', {'action_type': 'run_command', 'integration': 'servicenow', 'requires_approval': True}),
    'sn_orchestration.ssh_command': ('action', {'action_type': 'ssh_command', 'integration': 'servicenow', 'requires_approval': True}),
    'sn_orchestration.powershell': ('action', {'action_type': 'powershell', 'integration': 'servicenow', 'requires_approval': True}),

    # Integration Hub Spokes
    'crowdstrike.contain_host': ('action', {'action_type': 'contain_host', 'integration': 'crowdstrike', 'requires_approval': True}),
    'crowdstrike.lift_containment': ('action', {'action_type': 'uncontain_host', 'integration': 'crowdstrike', 'requires_approval': True}),
    'crowdstrike.get_device': ('enrich', {'integration': 'crowdstrike', 'observable_type': 'host'}),
    'palo_alto.block_ip': ('action', {'action_type': 'block_ip', 'integration': 'palo_alto', 'requires_approval': True}),
    'active_directory.disable_user': ('action', {'action_type': 'disable_user', 'integration': 'active_directory', 'requires_approval': True}),
    'active_directory.enable_user': ('action', {'action_type': 'enable_user', 'integration': 'active_directory', 'requires_approval': True}),
    'active_directory.reset_password': ('action', {'action_type': 'reset_password', 'integration': 'active_directory', 'requires_approval': True}),
    'active_directory.get_user': ('enrich', {'integration': 'active_directory', 'observable_type': 'user'}),
    'okta.deactivate_user': ('action', {'action_type': 'disable_user', 'integration': 'okta', 'requires_approval': True}),
    'okta.clear_sessions': ('action', {'action_type': 'revoke_sessions', 'integration': 'okta', 'requires_approval': True}),
    'virustotal.scan_ip': ('enrich', {'integration': 'virustotal', 'observable_type': 'ip'}),
    'virustotal.scan_domain': ('enrich', {'integration': 'virustotal', 'observable_type': 'domain'}),
    'virustotal.scan_hash': ('enrich', {'integration': 'virustotal', 'observable_type': 'hash'}),
    'virustotal.scan_url': ('enrich', {'integration': 'virustotal', 'observable_type': 'url'}),

    # Trigger types (used for detection/fallback)
    'record_created': ('trigger', {'trigger_type': 'record_created'}),
    'record_updated': ('trigger', {'trigger_type': 'record_updated'}),
    'scheduled': ('trigger', {'trigger_type': 'schedule'}),
    'inbound_email': ('trigger', {'trigger_type': 'email'}),
    'rest_api': ('trigger', {'trigger_type': 'webhook'}),
}


# ============================================================================
# Exabeam (New-Scale SOAR) Action Mappings
# ============================================================================

EXABEAM_ACTIONS: Dict[str, Tuple[str, Dict[str, Any]]] = {
    # CrowdStrike
    'crowdstrike.contain_host': ('action', {'action_type': 'contain_host', 'integration': 'crowdstrike', 'requires_approval': True}),
    'crowdstrike.lift_containment': ('action', {'action_type': 'uncontain_host', 'integration': 'crowdstrike', 'requires_approval': True}),
    'crowdstrike.get_device': ('enrich', {'integration': 'crowdstrike', 'observable_type': 'host'}),
    'crowdstrike.search_detections': ('enrich', {'integration': 'crowdstrike', 'observable_type': 'detection'}),
    'crowdstrike.get_incidents': ('enrich', {'integration': 'crowdstrike', 'observable_type': 'incident'}),

    # SentinelOne
    'sentinelone.isolate_agent': ('action', {'action_type': 'contain_host', 'integration': 'sentinelone', 'requires_approval': True}),
    'sentinelone.reconnect_agent': ('action', {'action_type': 'uncontain_host', 'integration': 'sentinelone', 'requires_approval': True}),
    'sentinelone.get_agent': ('enrich', {'integration': 'sentinelone', 'observable_type': 'host'}),

    # Carbon Black
    'carbon_black.isolate_device': ('action', {'action_type': 'contain_host', 'integration': 'carbon_black', 'requires_approval': True}),
    'carbon_black.unisolate_device': ('action', {'action_type': 'uncontain_host', 'integration': 'carbon_black', 'requires_approval': True}),

    # Microsoft Defender
    'microsoft_defender.isolate_machine': ('action', {'action_type': 'contain_host', 'integration': 'microsoft_defender', 'requires_approval': True}),
    'microsoft_defender.unisolate_machine': ('action', {'action_type': 'uncontain_host', 'integration': 'microsoft_defender', 'requires_approval': True}),
    'microsoft_defender.run_scan': ('action', {'action_type': 'scan_host', 'integration': 'microsoft_defender'}),

    # VirusTotal
    'virustotal.scan_ip': ('enrich', {'integration': 'virustotal', 'observable_type': 'ip'}),
    'virustotal.scan_domain': ('enrich', {'integration': 'virustotal', 'observable_type': 'domain'}),
    'virustotal.scan_hash': ('enrich', {'integration': 'virustotal', 'observable_type': 'hash'}),
    'virustotal.scan_url': ('enrich', {'integration': 'virustotal', 'observable_type': 'url'}),
    'virustotal.get_report': ('enrich', {'integration': 'virustotal'}),

    # URLScan
    'urlscan.submit_url': ('enrich', {'integration': 'urlscan', 'observable_type': 'url'}),
    'urlscan.get_result': ('enrich', {'integration': 'urlscan', 'observable_type': 'url'}),

    # Shodan
    'shodan.search_ip': ('enrich', {'integration': 'shodan', 'observable_type': 'ip'}),

    # AbuseIPDB
    'abuseipdb.check_ip': ('enrich', {'integration': 'abuseipdb', 'observable_type': 'ip'}),

    # WHOIS
    'whois.lookup': ('enrich', {'integration': 'whois'}),

    # Active Directory
    'active_directory.disable_user': ('action', {'action_type': 'disable_user', 'integration': 'active_directory', 'requires_approval': True}),
    'active_directory.enable_user': ('action', {'action_type': 'enable_user', 'integration': 'active_directory', 'requires_approval': True}),
    'active_directory.reset_password': ('action', {'action_type': 'reset_password', 'integration': 'active_directory', 'requires_approval': True}),
    'active_directory.get_user': ('enrich', {'integration': 'active_directory', 'observable_type': 'user'}),
    'active_directory.get_group_members': ('enrich', {'integration': 'active_directory', 'observable_type': 'group'}),

    # Okta
    'okta.disable_user': ('action', {'action_type': 'disable_user', 'integration': 'okta', 'requires_approval': True}),
    'okta.enable_user': ('action', {'action_type': 'enable_user', 'integration': 'okta', 'requires_approval': True}),
    'okta.clear_sessions': ('action', {'action_type': 'revoke_sessions', 'integration': 'okta', 'requires_approval': True}),
    'okta.get_user': ('enrich', {'integration': 'okta', 'observable_type': 'user'}),
    'okta.suspend_user': ('action', {'action_type': 'disable_user', 'integration': 'okta', 'requires_approval': True}),

    # Azure AD / Entra ID
    'azure_ad.disable_user': ('action', {'action_type': 'disable_user', 'integration': 'azure_ad', 'requires_approval': True}),
    'azure_ad.revoke_sessions': ('action', {'action_type': 'revoke_sessions', 'integration': 'azure_ad', 'requires_approval': True}),

    # Firewall
    'palo_alto.block_ip': ('action', {'action_type': 'block_ip', 'integration': 'palo_alto', 'requires_approval': True}),
    'palo_alto.unblock_ip': ('action', {'action_type': 'unblock_ip', 'integration': 'palo_alto', 'requires_approval': True}),
    'fortinet.block_ip': ('action', {'action_type': 'block_ip', 'integration': 'fortinet', 'requires_approval': True}),

    # Ticketing
    'servicenow.create_incident': ('create_ticket', {'integration': 'servicenow'}),
    'servicenow.update_incident': ('action', {'action_type': 'update_ticket', 'integration': 'servicenow'}),
    'servicenow.create_ticket': ('create_ticket', {'integration': 'servicenow'}),
    'jira.create_issue': ('create_ticket', {'integration': 'jira'}),
    'jira.update_issue': ('action', {'action_type': 'update_ticket', 'integration': 'jira'}),

    # Notification
    'email.send': ('notify', {'channel': 'email'}),
    'email.send_email': ('notify', {'channel': 'email'}),
    'slack.send_message': ('notify', {'channel': 'slack'}),
    'slack.post_message': ('notify', {'channel': 'slack'}),
    'teams.send_message': ('notify', {'channel': 'teams'}),
    'pagerduty.trigger_incident': ('notify', {'channel': 'pagerduty'}),

    # SIEM / Exabeam native
    'exabeam.search_events': ('enrich', {'integration': 'exabeam', 'observable_type': 'events'}),
    'exabeam.get_user_timeline': ('enrich', {'integration': 'exabeam', 'observable_type': 'timeline'}),
    'exabeam.get_risk_score': ('enrich', {'integration': 'exabeam', 'observable_type': 'risk_score'}),
    'exabeam.get_notable_sessions': ('enrich', {'integration': 'exabeam', 'observable_type': 'sessions'}),
    'exabeam.get_peer_groups': ('enrich', {'integration': 'exabeam', 'observable_type': 'peer_groups'}),
    'exabeam.close_incident': ('action', {'action_type': 'close_incident', 'integration': 'exabeam'}),
    'exabeam.update_incident': ('action', {'action_type': 'update_incident', 'integration': 'exabeam'}),

    # AWS
    'aws.disable_access_key': ('action', {'action_type': 'disable_access_key', 'integration': 'aws', 'requires_approval': True}),
    'aws.get_guardduty_findings': ('enrich', {'integration': 'aws', 'observable_type': 'findings'}),
    'aws.revoke_security_group_ingress': ('action', {'action_type': 'revoke_sg_rule', 'integration': 'aws', 'requires_approval': True}),

    # GCP
    'gcp.disable_service_account': ('action', {'action_type': 'disable_service_account', 'integration': 'gcp', 'requires_approval': True}),

    # Task types (used for detection/fallback)
    'action': ('action', {}),
    'decision': ('condition', {}),
    'manual': ('approval_gate', {}),
    'script': ('python_code', {}),
    'notification': ('notify', {}),
    'enrichment': ('enrich', {}),
}


# ============================================================================
# LogicHub (SOAR + SIEM) Action Mappings
# ============================================================================

LOGICHUB_ACTIONS: Dict[str, Tuple[str, Dict[str, Any]]] = {
    # Integration Actions — VirusTotal
    'virustotal.lookup_ip': ('enrich', {'integration': 'virustotal', 'observable_type': 'ip'}),
    'virustotal.lookup_domain': ('enrich', {'integration': 'virustotal', 'observable_type': 'domain'}),
    'virustotal.lookup_hash': ('enrich', {'integration': 'virustotal', 'observable_type': 'hash'}),
    'virustotal.lookup_url': ('enrich', {'integration': 'virustotal', 'observable_type': 'url'}),
    'virustotal.scan_file': ('enrich', {'integration': 'virustotal', 'observable_type': 'hash'}),
    'virustotal.scan_url': ('enrich', {'integration': 'virustotal', 'observable_type': 'url'}),
    'virustotal.get_report': ('enrich', {'integration': 'virustotal'}),

    # Integration Actions — CrowdStrike
    'crowdstrike.contain_host': ('action', {'action_type': 'contain_host', 'integration': 'crowdstrike', 'requires_approval': True}),
    'crowdstrike.lift_containment': ('action', {'action_type': 'uncontain_host', 'integration': 'crowdstrike', 'requires_approval': True}),
    'crowdstrike.get_device': ('enrich', {'integration': 'crowdstrike', 'observable_type': 'host'}),
    'crowdstrike.search_detections': ('enrich', {'integration': 'crowdstrike', 'observable_type': 'detection'}),
    'crowdstrike.get_incidents': ('enrich', {'integration': 'crowdstrike', 'observable_type': 'incident'}),
    'crowdstrike.run_rtr_command': ('action', {'action_type': 'run_command', 'integration': 'crowdstrike', 'requires_approval': True}),

    # Integration Actions — Splunk (SIEM)
    'splunk.search_events': ('enrich', {'integration': 'splunk', 'observable_type': 'events'}),
    'splunk.run_query': ('enrich', {'integration': 'splunk', 'observable_type': 'query'}),
    'splunk.get_notable': ('enrich', {'integration': 'splunk', 'observable_type': 'notable'}),
    'splunk.update_notable': ('action', {'action_type': 'update_notable', 'integration': 'splunk'}),

    # Integration Actions — ServiceNow
    'servicenow.create_incident': ('create_ticket', {'integration': 'servicenow'}),
    'servicenow.update_incident': ('action', {'action_type': 'update_ticket', 'integration': 'servicenow'}),
    'servicenow.close_incident': ('action', {'action_type': 'close_ticket', 'integration': 'servicenow'}),
    'servicenow.create_ticket': ('create_ticket', {'integration': 'servicenow'}),
    'servicenow.get_ticket': ('enrich', {'integration': 'servicenow', 'observable_type': 'ticket'}),

    # Integration Actions — Okta
    'okta.disable_user': ('action', {'action_type': 'disable_user', 'integration': 'okta', 'requires_approval': True}),
    'okta.enable_user': ('action', {'action_type': 'enable_user', 'integration': 'okta', 'requires_approval': True}),
    'okta.clear_sessions': ('action', {'action_type': 'revoke_sessions', 'integration': 'okta', 'requires_approval': True}),
    'okta.suspend_user': ('action', {'action_type': 'disable_user', 'integration': 'okta', 'requires_approval': True}),
    'okta.get_user': ('enrich', {'integration': 'okta', 'observable_type': 'user'}),

    # Integration Actions — PAN-OS
    'pan_os.block_ip': ('action', {'action_type': 'block_ip', 'integration': 'palo_alto', 'requires_approval': True}),
    'pan_os.unblock_ip': ('action', {'action_type': 'unblock_ip', 'integration': 'palo_alto', 'requires_approval': True}),
    'pan_os.block_url': ('action', {'action_type': 'block_url', 'integration': 'palo_alto', 'requires_approval': True}),
    'pan_os.create_rule': ('action', {'action_type': 'create_rule', 'integration': 'palo_alto', 'requires_approval': True}),
    'pan_os.commit': ('action', {'action_type': 'commit_config', 'integration': 'palo_alto', 'requires_approval': True}),

    # Integration Actions — Active Directory
    'active_directory.disable_user': ('action', {'action_type': 'disable_user', 'integration': 'active_directory', 'requires_approval': True}),
    'active_directory.enable_user': ('action', {'action_type': 'enable_user', 'integration': 'active_directory', 'requires_approval': True}),
    'active_directory.reset_password': ('action', {'action_type': 'reset_password', 'integration': 'active_directory', 'requires_approval': True}),
    'active_directory.get_user': ('enrich', {'integration': 'active_directory', 'observable_type': 'user'}),

    # Integration Actions — URLScan
    'urlscan.submit_url': ('enrich', {'integration': 'urlscan', 'observable_type': 'url'}),
    'urlscan.get_result': ('enrich', {'integration': 'urlscan', 'observable_type': 'url'}),

    # Integration Actions — Shodan
    'shodan.search_ip': ('enrich', {'integration': 'shodan', 'observable_type': 'ip'}),
    'shodan.search_query': ('enrich', {'integration': 'shodan', 'observable_type': 'query'}),

    # Integration Actions — AbuseIPDB
    'abuseipdb.check_ip': ('enrich', {'integration': 'abuseipdb', 'observable_type': 'ip'}),
    'abuseipdb.report_ip': ('action', {'action_type': 'report_ip', 'integration': 'abuseipdb'}),

    # Integration Actions — WHOIS
    'whois.lookup': ('enrich', {'integration': 'whois'}),
    'whois.lookup_domain': ('enrich', {'integration': 'whois', 'observable_type': 'domain'}),

    # Integration Actions — SentinelOne
    'sentinelone.isolate_agent': ('action', {'action_type': 'contain_host', 'integration': 'sentinelone', 'requires_approval': True}),
    'sentinelone.reconnect_agent': ('action', {'action_type': 'uncontain_host', 'integration': 'sentinelone', 'requires_approval': True}),
    'sentinelone.get_agent': ('enrich', {'integration': 'sentinelone', 'observable_type': 'host'}),

    # Integration Actions — Jira
    'jira.create_issue': ('create_ticket', {'integration': 'jira'}),
    'jira.update_issue': ('action', {'action_type': 'update_ticket', 'integration': 'jira'}),
    'jira.close_issue': ('action', {'action_type': 'close_ticket', 'integration': 'jira'}),

    # Integration Actions — Notification
    'email.send': ('notify', {'channel': 'email'}),
    'slack.send_message': ('notify', {'channel': 'slack'}),
    'slack.post_message': ('notify', {'channel': 'slack'}),
    'teams.send_message': ('notify', {'channel': 'teams'}),
    'pagerduty.trigger': ('notify', {'channel': 'pagerduty'}),

    # Generic action names (from integration.action field)
    'lookup_ip': ('enrich', {'observable_type': 'ip'}),
    'lookup_domain': ('enrich', {'observable_type': 'domain'}),
    'lookup_hash': ('enrich', {'observable_type': 'hash'}),
    'lookup_url': ('enrich', {'observable_type': 'url'}),
    'contain_host': ('action', {'action_type': 'contain_host', 'requires_approval': True}),
    'isolate_host': ('action', {'action_type': 'contain_host', 'requires_approval': True}),
    'block_ip': ('action', {'action_type': 'block_ip', 'requires_approval': True}),
    'unblock_ip': ('action', {'action_type': 'unblock_ip', 'requires_approval': True}),
    'disable_user': ('action', {'action_type': 'disable_user', 'requires_approval': True}),
    'enable_user': ('action', {'action_type': 'enable_user', 'requires_approval': True}),
    'reset_password': ('action', {'action_type': 'reset_password', 'requires_approval': True}),
    'search_events': ('enrich', {'observable_type': 'events'}),
    'create_incident': ('create_ticket', {}),
    'update_incident': ('action', {'action_type': 'update_ticket'}),
    'close_incident': ('action', {'action_type': 'close_ticket'}),
    'send_notification': ('notify', {}),
    'send_email': ('notify', {'channel': 'email'}),

    # Node type mappings (LogicHub node types)
    'integration': ('action', {'auto_mapped': True}),
    'decision': ('condition', {}),
    'script': ('python_code', {}),
    'input': ('trigger', {'trigger_type': 'input'}),
    'output': ('end', {'disposition': 'completed'}),
    'transform': ('transform', {}),
    'batch': ('transform', {'transform_type': 'batch'}),
    'alert': ('notify', {}),
    'notification': ('notify', {}),
}


# ============================================================================
# Resolve (Resolve Systems) Runbook Action Mappings
# ============================================================================

RESOLVE_ACTIONS: Dict[str, Tuple[str, Dict[str, Any]]] = {
    # Module: network
    'network.block_ip': ('action', {'action_type': 'block_ip', 'integration': 'firewall', 'requires_approval': True}),
    'network.unblock_ip': ('action', {'action_type': 'unblock_ip', 'integration': 'firewall', 'requires_approval': True}),
    'network.block_port': ('action', {'action_type': 'block_port', 'integration': 'firewall', 'requires_approval': True}),
    'network.ping_host': ('enrich', {'integration': 'network', 'observable_type': 'host'}),
    'network.traceroute': ('enrich', {'integration': 'network', 'observable_type': 'route'}),
    'network.dns_lookup': ('enrich', {'integration': 'dns', 'observable_type': 'domain'}),
    'network.port_scan': ('enrich', {'integration': 'network', 'observable_type': 'ports'}),
    'network.get_interface_status': ('enrich', {'integration': 'network', 'observable_type': 'interface'}),
    'network.restart_interface': ('action', {'action_type': 'restart_interface', 'integration': 'network', 'requires_approval': True}),

    # Module: endpoint
    'endpoint.isolate_host': ('action', {'action_type': 'contain_host', 'requires_approval': True}),
    'endpoint.unisolate_host': ('action', {'action_type': 'uncontain_host', 'requires_approval': True}),
    'endpoint.get_host_info': ('enrich', {'observable_type': 'host'}),
    'endpoint.scan_host': ('action', {'action_type': 'scan_host'}),
    'endpoint.kill_process': ('action', {'action_type': 'kill_process', 'requires_approval': True}),
    'endpoint.restart_service': ('action', {'action_type': 'restart_service', 'requires_approval': True}),
    'endpoint.get_running_processes': ('enrich', {'observable_type': 'process'}),
    'endpoint.collect_forensics': ('enrich', {'observable_type': 'forensics'}),
    'endpoint.patch_host': ('action', {'action_type': 'patch_host', 'requires_approval': True}),
    'endpoint.run_command': ('action', {'action_type': 'run_command', 'requires_approval': True}),

    # Module: identity
    'identity.disable_account': ('action', {'action_type': 'disable_user', 'requires_approval': True}),
    'identity.enable_account': ('action', {'action_type': 'enable_user', 'requires_approval': True}),
    'identity.reset_password': ('action', {'action_type': 'reset_password', 'requires_approval': True}),
    'identity.revoke_sessions': ('action', {'action_type': 'revoke_sessions', 'requires_approval': True}),
    'identity.get_user_info': ('enrich', {'observable_type': 'user'}),
    'identity.get_group_members': ('enrich', {'observable_type': 'group'}),
    'identity.add_to_group': ('action', {'action_type': 'add_to_group', 'requires_approval': True}),
    'identity.remove_from_group': ('action', {'action_type': 'remove_from_group', 'requires_approval': True}),
    'identity.unlock_account': ('action', {'action_type': 'unlock_account', 'requires_approval': True}),

    # Module: ticketing
    'ticketing.create_ticket': ('create_ticket', {}),
    'ticketing.update_ticket': ('action', {'action_type': 'update_ticket'}),
    'ticketing.close_ticket': ('action', {'action_type': 'close_ticket'}),
    'ticketing.assign_ticket': ('action', {'action_type': 'assign_ticket'}),
    'ticketing.add_comment': ('action', {'action_type': 'add_comment'}),
    'ticketing.get_ticket': ('enrich', {'observable_type': 'ticket'}),
    'ticketing.escalate_ticket': ('action', {'action_type': 'escalate_ticket'}),

    # Module: cloud
    'cloud.disable_access_key': ('action', {'action_type': 'disable_access_key', 'integration': 'aws', 'requires_approval': True}),
    'cloud.revoke_security_group': ('action', {'action_type': 'revoke_sg_rule', 'integration': 'aws', 'requires_approval': True}),
    'cloud.stop_instance': ('action', {'action_type': 'stop_instance', 'integration': 'cloud', 'requires_approval': True}),
    'cloud.get_instance_info': ('enrich', {'integration': 'cloud', 'observable_type': 'instance'}),
    'cloud.snapshot_volume': ('action', {'action_type': 'snapshot_volume', 'integration': 'cloud'}),
    'cloud.get_security_groups': ('enrich', {'integration': 'cloud', 'observable_type': 'security_group'}),
    'cloud.disable_service_account': ('action', {'action_type': 'disable_service_account', 'integration': 'cloud', 'requires_approval': True}),

    # Module: email
    'email.send_notification': ('notify', {'channel': 'email'}),
    'email.send_email': ('notify', {'channel': 'email'}),
    'email.delete_email': ('action', {'action_type': 'delete_email', 'requires_approval': True}),
    'email.quarantine_email': ('action', {'action_type': 'quarantine_email', 'requires_approval': True}),
    'email.get_email_headers': ('enrich', {'observable_type': 'email'}),

    # Generic function names (from step.function field)
    'block_ip': ('action', {'action_type': 'block_ip', 'requires_approval': True}),
    'unblock_ip': ('action', {'action_type': 'unblock_ip', 'requires_approval': True}),
    'isolate_host': ('action', {'action_type': 'contain_host', 'requires_approval': True}),
    'unisolate_host': ('action', {'action_type': 'uncontain_host', 'requires_approval': True}),
    'disable_account': ('action', {'action_type': 'disable_user', 'requires_approval': True}),
    'enable_account': ('action', {'action_type': 'enable_user', 'requires_approval': True}),
    'reset_password': ('action', {'action_type': 'reset_password', 'requires_approval': True}),
    'create_ticket': ('create_ticket', {}),
    'update_ticket': ('action', {'action_type': 'update_ticket'}),
    'close_ticket': ('action', {'action_type': 'close_ticket'}),
    'send_notification': ('notify', {}),
    'send_email': ('notify', {'channel': 'email'}),
    'kill_process': ('action', {'action_type': 'kill_process', 'requires_approval': True}),
    'restart_service': ('action', {'action_type': 'restart_service', 'requires_approval': True}),
    'run_command': ('action', {'action_type': 'run_command', 'requires_approval': True}),
    'get_host_info': ('enrich', {'observable_type': 'host'}),
    'get_user_info': ('enrich', {'observable_type': 'user'}),
    'ping_host': ('enrich', {'observable_type': 'host'}),
    'dns_lookup': ('enrich', {'observable_type': 'domain'}),
    'collect_forensics': ('enrich', {'observable_type': 'forensics'}),

    # Step type mappings (Resolve step types)
    'action': ('action', {'auto_mapped': True}),
    'decision': ('condition', {}),
    'approval': ('approval_gate', {}),
    'wait': ('delay', {}),
    'script': ('python_code', {}),
    'parallel': ('transform', {'transform_type': 'parallel'}),
    'rest_call': ('webhook_call', {}),
    'sub_runbook': ('action', {'action_type': 'run_playbook'}),
    'start': ('trigger', {'trigger_type': 'alert'}),
    'end': ('end', {'disposition': 'completed'}),
}


# ============================================================================
# Rapid7 InsightConnect (Komand) Action Mappings
# ============================================================================

INSIGHT_CONNECT_ACTIONS: Dict[str, Tuple[str, Dict[str, Any]]] = {
    # Step types
    'trigger': ('trigger', {'trigger_type': 'alert'}),
    'action': ('action', {'auto_mapped': True}),
    'decision': ('condition', {}),
    'loop': ('transform', {'transform_type': 'loop'}),
    'artifact': ('enrich', {'auto_mapped': True}),
    'delay': ('delay', {}),
    'human_decision': ('approval_gate', {}),

    # Enrichment - VirusTotal plugin
    'virustotal.lookup_hash': ('enrich', {'integration': 'virustotal', 'observable_type': 'hash'}),
    'virustotal.lookup_url': ('enrich', {'integration': 'virustotal', 'observable_type': 'url'}),
    'virustotal.lookup_domain': ('enrich', {'integration': 'virustotal', 'observable_type': 'domain'}),
    'virustotal.lookup_ip': ('enrich', {'integration': 'virustotal', 'observable_type': 'ip'}),
    'virustotal.scan_file': ('enrich', {'integration': 'virustotal', 'observable_type': 'hash'}),
    'virustotal.scan_url': ('enrich', {'integration': 'virustotal', 'observable_type': 'url'}),
    'virustotal.get_file_report': ('enrich', {'integration': 'virustotal', 'observable_type': 'hash'}),

    # Enrichment - Threat Intel
    'abuseipdb.check_ip': ('enrich', {'integration': 'abuseipdb', 'observable_type': 'ip'}),
    'abuseipdb.check_cidr': ('enrich', {'integration': 'abuseipdb', 'observable_type': 'ip'}),
    'shodan.host_information': ('enrich', {'integration': 'shodan', 'observable_type': 'ip'}),
    'shodan.search': ('enrich', {'integration': 'shodan', 'observable_type': 'query'}),
    'urlscan.submit_url': ('enrich', {'integration': 'urlscan', 'observable_type': 'url'}),
    'urlscan.get_scan_results': ('enrich', {'integration': 'urlscan', 'observable_type': 'url'}),
    'whois.lookup': ('enrich', {'integration': 'whois', 'observable_type': 'domain'}),
    'whois.domain_lookup': ('enrich', {'integration': 'whois', 'observable_type': 'domain'}),
    'greynoise.ip_lookup': ('enrich', {'integration': 'greynoise', 'observable_type': 'ip'}),
    'misp.search_events': ('enrich', {'integration': 'misp', 'observable_type': 'events'}),
    'misp.add_attribute': ('action', {'integration': 'misp', 'action_type': 'add_indicator'}),
    'threatconnect.get_indicator': ('enrich', {'integration': 'threatconnect', 'observable_type': 'indicator'}),

    # Enrichment - DNS
    'dns.forward_lookup': ('enrich', {'integration': 'dns', 'observable_type': 'domain'}),
    'dns.reverse_lookup': ('enrich', {'integration': 'dns', 'observable_type': 'ip'}),

    # EDR - CrowdStrike Falcon
    'crowdstrike_falcon.contain_host': ('action', {'action_type': 'contain_host', 'integration': 'crowdstrike', 'requires_approval': True}),
    'crowdstrike_falcon.lift_containment': ('action', {'action_type': 'uncontain_host', 'integration': 'crowdstrike', 'requires_approval': True}),
    'crowdstrike_falcon.search_devices': ('enrich', {'integration': 'crowdstrike', 'observable_type': 'host'}),
    'crowdstrike_falcon.get_device_details': ('enrich', {'integration': 'crowdstrike', 'observable_type': 'host'}),
    'crowdstrike_falcon.search_detections': ('enrich', {'integration': 'crowdstrike', 'observable_type': 'detection'}),
    'crowdstrike_falcon.get_detection_details': ('enrich', {'integration': 'crowdstrike', 'observable_type': 'detection'}),
    'crowdstrike_falcon.search_events': ('enrich', {'integration': 'crowdstrike', 'observable_type': 'events'}),
    'crowdstrike_falcon.rtr_run_command': ('action', {'action_type': 'run_command', 'integration': 'crowdstrike', 'requires_approval': True}),

    # EDR - Carbon Black
    'carbon_black.isolate_device': ('action', {'action_type': 'contain_host', 'integration': 'carbon_black', 'requires_approval': True}),
    'carbon_black.unisolate_device': ('action', {'action_type': 'uncontain_host', 'integration': 'carbon_black', 'requires_approval': True}),
    'carbon_black.get_device_info': ('enrich', {'integration': 'carbon_black', 'observable_type': 'host'}),

    # EDR - SentinelOne
    'sentinelone.disconnect_agent': ('action', {'action_type': 'contain_host', 'integration': 'sentinelone', 'requires_approval': True}),
    'sentinelone.connect_agent': ('action', {'action_type': 'uncontain_host', 'integration': 'sentinelone', 'requires_approval': True}),
    'sentinelone.get_agent_details': ('enrich', {'integration': 'sentinelone', 'observable_type': 'host'}),

    # Identity - Active Directory LDAP
    'active_directory_ldap.search': ('enrich', {'integration': 'active_directory', 'observable_type': 'user'}),
    'active_directory_ldap.disable_user': ('action', {'action_type': 'disable_user', 'integration': 'active_directory', 'requires_approval': True}),
    'active_directory_ldap.enable_user': ('action', {'action_type': 'enable_user', 'integration': 'active_directory', 'requires_approval': True}),
    'active_directory_ldap.reset_password': ('action', {'action_type': 'reset_password', 'integration': 'active_directory', 'requires_approval': True}),
    'active_directory_ldap.modify_groups': ('action', {'action_type': 'modify_groups', 'integration': 'active_directory', 'requires_approval': True}),

    # Identity - Azure AD
    'azure_ad.disable_user': ('action', {'action_type': 'disable_user', 'integration': 'azure_ad', 'requires_approval': True}),
    'azure_ad.enable_user': ('action', {'action_type': 'enable_user', 'integration': 'azure_ad', 'requires_approval': True}),
    'azure_ad.get_user': ('enrich', {'integration': 'azure_ad', 'observable_type': 'user'}),
    'azure_ad.revoke_sessions': ('action', {'action_type': 'revoke_sessions', 'integration': 'azure_ad', 'requires_approval': True}),

    # Identity - Okta
    'okta.deactivate_user': ('action', {'action_type': 'disable_user', 'integration': 'okta', 'requires_approval': True}),
    'okta.activate_user': ('action', {'action_type': 'enable_user', 'integration': 'okta', 'requires_approval': True}),
    'okta.clear_sessions': ('action', {'action_type': 'revoke_sessions', 'integration': 'okta', 'requires_approval': True}),
    'okta.get_user': ('enrich', {'integration': 'okta', 'observable_type': 'user'}),

    # Firewall / Network
    'palo_alto_pan_os.block_ip': ('action', {'action_type': 'block_ip', 'integration': 'palo_alto', 'requires_approval': True}),
    'palo_alto_pan_os.unblock_ip': ('action', {'action_type': 'unblock_ip', 'integration': 'palo_alto', 'requires_approval': True}),
    'palo_alto_pan_os.add_address_object': ('action', {'action_type': 'create_rule', 'integration': 'palo_alto', 'requires_approval': True}),
    'cisco_firepower.block_ip': ('action', {'action_type': 'block_ip', 'integration': 'cisco_firepower', 'requires_approval': True}),

    # SIEM
    'splunk.search': ('enrich', {'integration': 'splunk', 'observable_type': 'query'}),
    'splunk.run_saved_search': ('enrich', {'integration': 'splunk', 'observable_type': 'query'}),
    'elasticsearch.search': ('enrich', {'integration': 'elasticsearch', 'observable_type': 'query'}),
    'qradar.search': ('enrich', {'integration': 'qradar', 'observable_type': 'query'}),

    # Ticketing
    'servicenow.create_incident': ('create_ticket', {'integration': 'servicenow'}),
    'servicenow.update_incident': ('action', {'action_type': 'update_ticket', 'integration': 'servicenow'}),
    'servicenow.search_incidents': ('enrich', {'integration': 'servicenow', 'observable_type': 'ticket'}),
    'jira.create_issue': ('create_ticket', {'integration': 'jira'}),
    'jira.update_issue': ('action', {'action_type': 'update_ticket', 'integration': 'jira'}),

    # Notification
    'microsoft_teams.send_message': ('notify', {'channel': 'teams'}),
    'slack.send_message': ('notify', {'channel': 'slack'}),
    'smtp.send_email': ('notify', {'channel': 'email'}),

    # Email Security
    'microsoft_office365_email.get_email': ('enrich', {'integration': 'office365', 'observable_type': 'email'}),
    'microsoft_office365_email.delete_email': ('action', {'action_type': 'delete_email', 'integration': 'office365', 'requires_approval': True}),
    'proofpoint_tap.get_delivered_threats': ('enrich', {'integration': 'proofpoint', 'observable_type': 'email'}),

    # Cloud
    'aws_iam.disable_access_key': ('action', {'action_type': 'disable_access_key', 'integration': 'aws_iam', 'requires_approval': True}),
    'aws_ec2.stop_instance': ('action', {'action_type': 'stop_instance', 'integration': 'aws_ec2', 'requires_approval': True}),
    'aws_security_hub.get_findings': ('enrich', {'integration': 'aws_security_hub', 'observable_type': 'findings'}),

    # Utility
    'type_converter.convert': ('transform', {'transform_type': 'convert'}),
    'math.calculate': ('transform', {'transform_type': 'calculate'}),
    'string_operations.upper': ('transform', {'transform_type': 'format'}),
    'string_operations.lower': ('transform', {'transform_type': 'format'}),
    'base64.encode': ('transform', {'transform_type': 'encode'}),
    'base64.decode': ('transform', {'transform_type': 'decode'}),
    'json_edit.update': ('transform', {'transform_type': 'json_edit'}),
    'python_3_script.run': ('python_code', {}),
    'powershell_script.run': ('python_code', {'script_type': 'powershell'}),
}


# ============================================================================
# TheHive / Cortex Action Mappings
# ============================================================================

THEHIVE_ACTIONS: Dict[str, Tuple[str, Dict[str, Any]]] = {
    # Cortex Analyzers - enrichment
    'virustotal_scan': ('enrich', {'integration': 'virustotal'}),
    'virustotal_getreport': ('enrich', {'integration': 'virustotal'}),
    'virustotal_scan_3_1': ('enrich', {'integration': 'virustotal'}),
    'abuseipdb_1_0': ('enrich', {'integration': 'abuseipdb', 'observable_type': 'ip'}),
    'abuseipdb': ('enrich', {'integration': 'abuseipdb', 'observable_type': 'ip'}),
    'shodan_host': ('enrich', {'integration': 'shodan', 'observable_type': 'ip'}),
    'shodan_infodb': ('enrich', {'integration': 'shodan', 'observable_type': 'ip'}),
    'urlscan_io_scan': ('enrich', {'integration': 'urlscan', 'observable_type': 'url'}),
    'urlscan_io_search': ('enrich', {'integration': 'urlscan', 'observable_type': 'url'}),
    'whois': ('enrich', {'integration': 'whois', 'observable_type': 'domain'}),
    'dns_resolve': ('enrich', {'integration': 'dns', 'observable_type': 'domain'}),
    'greynoise': ('enrich', {'integration': 'greynoise', 'observable_type': 'ip'}),
    'maxmind_geoip': ('enrich', {'integration': 'maxmind', 'observable_type': 'ip'}),
    'misp_2_1': ('enrich', {'integration': 'misp', 'observable_type': 'indicator'}),
    'misp_warninglists': ('enrich', {'integration': 'misp', 'observable_type': 'indicator'}),
    'otx_query': ('enrich', {'integration': 'otx', 'observable_type': 'indicator'}),
    'dnsdb_dnsdbquery': ('enrich', {'integration': 'dnsdb', 'observable_type': 'domain'}),
    'cuckoo_file_analysis': ('enrich', {'integration': 'cuckoo', 'observable_type': 'hash'}),
    'yara_analyzer': ('enrich', {'integration': 'yara', 'observable_type': 'hash'}),
    'hippocampe_hipposcore': ('enrich', {'integration': 'hippocampe', 'observable_type': 'indicator'}),
    'censys': ('enrich', {'integration': 'censys', 'observable_type': 'ip'}),
    'hybridanalysis_getreport': ('enrich', {'integration': 'hybrid_analysis', 'observable_type': 'hash'}),
    'joe_sandbox_file_analysis': ('enrich', {'integration': 'joe_sandbox', 'observable_type': 'hash'}),
    'cortex_responder': ('action', {'auto_mapped': True}),

    # Cortex Responders - actions
    'mailer_1_0': ('notify', {'channel': 'email'}),
    'mailer': ('notify', {'channel': 'email'}),
    'thehive_case_close': ('end', {'disposition': 'completed'}),
    'velociraptor': ('action', {'integration': 'velociraptor', 'requires_approval': True}),
    'crowdstrike': ('action', {'integration': 'crowdstrike', 'requires_approval': True}),
    'wazuh': ('action', {'integration': 'wazuh'}),

    # Responder operations (from operations array)
    'addtagtocase': ('action', {'action_type': 'add_tag'}),
    'addtagtoalert': ('action', {'action_type': 'add_tag'}),
    'closecase': ('end', {'disposition': 'completed'}),
    'assigncase': ('action', {'action_type': 'assign'}),
    'adddistributionrule': ('action', {'action_type': 'distribute'}),
    'addcustomfield': ('action', {'action_type': 'update_field'}),
    'createtask': ('create_ticket', {'integration': 'thehive'}),
    'createalert': ('create_ticket', {'integration': 'thehive', 'ticket_type': 'alert'}),
    'updatecase': ('action', {'action_type': 'update_case'}),
    'addartifact': ('action', {'action_type': 'add_artifact'}),
    'addlog': ('action', {'action_type': 'add_comment'}),

    # Task group/category mappings (from case templates)
    'identification': ('enrich', {'phase': 'identification'}),
    'containment': ('action', {'phase': 'containment', 'requires_approval': True}),
    'eradication': ('action', {'phase': 'eradication', 'requires_approval': True}),
    'recovery': ('action', {'phase': 'recovery', 'requires_approval': True}),
    'lessons_learned': ('notify', {'phase': 'lessons_learned'}),
    'communication': ('notify', {'phase': 'communication'}),
    'investigation': ('enrich', {'phase': 'investigation'}),
    'remediation': ('action', {'phase': 'remediation', 'requires_approval': True}),
    'notification': ('notify', {}),
    'documentation': ('action', {'action_type': 'document'}),
    'analysis': ('enrich', {'phase': 'analysis'}),
    'triage': ('enrich', {'phase': 'triage'}),

    # Generic data type based mappings (for analyzer auto-detection)
    'ip': ('enrich', {'observable_type': 'ip'}),
    'domain': ('enrich', {'observable_type': 'domain'}),
    'hash': ('enrich', {'observable_type': 'hash'}),
    'url': ('enrich', {'observable_type': 'url'}),
    'mail': ('enrich', {'observable_type': 'email'}),
    'filename': ('enrich', {'observable_type': 'file'}),
    'fqdn': ('enrich', {'observable_type': 'domain'}),
}


# ============================================================================
# Shuffle (Open Source SOAR) Action Mappings
# ============================================================================

SHUFFLE_ACTIONS: Dict[str, Tuple[str, Dict[str, Any]]] = {
    # Core Shuffle Tools
    'shuffle_tools': ('transform', {}),
    'shuffle_tools_execute_python': ('python_code', {}),
    'shuffle_tools_filter_list': ('condition', {'condition_type': 'filter'}),
    'shuffle_tools_multi_list_filter': ('condition', {'condition_type': 'filter'}),
    'shuffle_tools_regex_capture_group': ('transform', {'transform_type': 'regex'}),
    'shuffle_tools_regex_replace': ('transform', {'transform_type': 'regex_replace'}),
    'shuffle_tools_parse_list': ('transform', {'transform_type': 'parse_list'}),
    'shuffle_tools_merge_lists': ('transform', {'transform_type': 'merge'}),
    'shuffle_tools_send_sms': ('notify', {'channel': 'sms'}),
    'shuffle_tools_send_email': ('notify', {'channel': 'email'}),
    'shuffle_tools_repeat_back_to_me': ('transform', {'transform_type': 'passthrough'}),
    'shuffle_tools_parse_ioc': ('enrich', {'observable_type': 'ioc'}),
    'shuffle_tools_translate_value': ('transform', {'transform_type': 'translate'}),
    'shuffle_tools_cidr_ip_match': ('condition', {'condition_type': 'cidr_match'}),
    'shuffle_tools_set_cache': ('variable_set', {}),
    'shuffle_tools_get_cache': ('variable_get', {}),
    'shuffle_tools_delete_cache': ('variable_set', {'action': 'delete'}),
    'shuffle_tools_date_to_epoch': ('transform', {'transform_type': 'date_convert'}),

    # HTTP App
    'http': ('webhook_call', {}),
    'http_curl': ('webhook_call', {}),

    # Email
    'email': ('notify', {'channel': 'email'}),
    'email_send': ('notify', {'channel': 'email'}),
    'email_get': ('enrich', {'integration': 'email', 'observable_type': 'email'}),

    # TheHive
    'thehive': ('action', {'integration': 'thehive'}),
    'thehive_create_case': ('create_ticket', {'integration': 'thehive'}),
    'thehive_create_alert': ('create_ticket', {'integration': 'thehive', 'ticket_type': 'alert'}),
    'thehive_update_case': ('action', {'action_type': 'update_ticket', 'integration': 'thehive'}),
    'thehive_close_case': ('action', {'action_type': 'close_ticket', 'integration': 'thehive'}),
    'thehive_get_case': ('enrich', {'integration': 'thehive', 'observable_type': 'case'}),
    'thehive_search_cases': ('enrich', {'integration': 'thehive', 'observable_type': 'case'}),
    'thehive_add_observable': ('action', {'action_type': 'add_observable', 'integration': 'thehive'}),
    'thehive_run_analyzer': ('enrich', {'integration': 'cortex'}),

    # Cortex
    'cortex': ('enrich', {'integration': 'cortex'}),
    'cortex_run_analyzer': ('enrich', {'integration': 'cortex'}),

    # VirusTotal
    'virustotal': ('enrich', {'integration': 'virustotal'}),
    'virustotal_get_ip_report': ('enrich', {'integration': 'virustotal', 'observable_type': 'ip'}),
    'virustotal_get_domain_report': ('enrich', {'integration': 'virustotal', 'observable_type': 'domain'}),
    'virustotal_get_hash_report': ('enrich', {'integration': 'virustotal', 'observable_type': 'hash'}),
    'virustotal_get_url_report': ('enrich', {'integration': 'virustotal', 'observable_type': 'url'}),
    'virustotal_scan_file': ('enrich', {'integration': 'virustotal', 'observable_type': 'hash'}),
    'virustotal_scan_url': ('enrich', {'integration': 'virustotal', 'observable_type': 'url'}),

    # CrowdStrike
    'crowdstrike': ('action', {'integration': 'crowdstrike'}),
    'crowdstrike_falcon': ('action', {'integration': 'crowdstrike'}),
    'crowdstrike_contain_host': ('action', {'action_type': 'contain_host', 'integration': 'crowdstrike', 'requires_approval': True}),
    'crowdstrike_lift_containment': ('action', {'action_type': 'uncontain_host', 'integration': 'crowdstrike', 'requires_approval': True}),
    'crowdstrike_get_device': ('enrich', {'integration': 'crowdstrike', 'observable_type': 'host'}),
    'crowdstrike_search_detections': ('enrich', {'integration': 'crowdstrike', 'observable_type': 'detection'}),

    # MISP
    'misp': ('enrich', {'integration': 'misp'}),
    'misp_search_events': ('enrich', {'integration': 'misp', 'observable_type': 'events'}),
    'misp_add_event': ('action', {'action_type': 'create_event', 'integration': 'misp'}),
    'misp_add_attribute': ('action', {'action_type': 'add_attribute', 'integration': 'misp'}),

    # Slack
    'slack': ('notify', {'channel': 'slack'}),
    'slack_send_message': ('notify', {'channel': 'slack'}),
    'slack_post_message': ('notify', {'channel': 'slack'}),

    # Microsoft Teams
    'microsoft_teams': ('notify', {'channel': 'teams'}),
    'teams': ('notify', {'channel': 'teams'}),
    'teams_send_message': ('notify', {'channel': 'teams'}),

    # ServiceNow
    'servicenow': ('create_ticket', {'integration': 'servicenow'}),
    'servicenow_create_incident': ('create_ticket', {'integration': 'servicenow'}),
    'servicenow_update_incident': ('action', {'action_type': 'update_ticket', 'integration': 'servicenow'}),
    'servicenow_get_incident': ('enrich', {'integration': 'servicenow', 'observable_type': 'ticket'}),

    # Jira
    'jira': ('create_ticket', {'integration': 'jira'}),
    'jira_create_issue': ('create_ticket', {'integration': 'jira'}),
    'jira_update_issue': ('action', {'action_type': 'update_ticket', 'integration': 'jira'}),

    # Active Directory / LDAP
    'activedirectory': ('action', {'integration': 'active_directory'}),
    'active_directory': ('action', {'integration': 'active_directory'}),
    'ldap': ('enrich', {'integration': 'ldap'}),

    # Okta
    'okta': ('action', {'integration': 'okta'}),
    'okta_deactivate_user': ('action', {'action_type': 'disable_user', 'integration': 'okta', 'requires_approval': True}),
    'okta_clear_sessions': ('action', {'action_type': 'revoke_sessions', 'integration': 'okta', 'requires_approval': True}),

    # URLScan
    'urlscan': ('enrich', {'integration': 'urlscan'}),
    'urlscan_submit_url': ('enrich', {'integration': 'urlscan', 'observable_type': 'url'}),

    # Shodan
    'shodan': ('enrich', {'integration': 'shodan'}),
    'shodan_search_ip': ('enrich', {'integration': 'shodan', 'observable_type': 'ip'}),

    # AbuseIPDB
    'abuseipdb': ('enrich', {'integration': 'abuseipdb'}),
    'abuseipdb_check_ip': ('enrich', {'integration': 'abuseipdb', 'observable_type': 'ip'}),

    # WHOIS
    'whois': ('enrich', {'integration': 'whois'}),
    'whois_lookup': ('enrich', {'integration': 'whois'}),

    # Splunk
    'splunk': ('enrich', {'integration': 'splunk', 'observable_type': 'query'}),
    'splunk_search': ('enrich', {'integration': 'splunk', 'observable_type': 'query'}),

    # QRadar
    'qradar': ('enrich', {'integration': 'qradar', 'observable_type': 'query'}),

    # PagerDuty
    'pagerduty': ('notify', {'integration': 'pagerduty'}),
    'pagerduty_create_incident': ('notify', {'integration': 'pagerduty'}),

    # AWS
    'aws': ('action', {'integration': 'aws'}),
    'aws_s3': ('action', {'integration': 'aws_s3'}),
    'aws_ec2': ('action', {'integration': 'aws_ec2'}),
    'aws_iam': ('action', {'integration': 'aws_iam', 'requires_approval': True}),
    'aws_lambda': ('action', {'integration': 'aws_lambda'}),

    # Trigger types
    'webhook': ('trigger', {'trigger_type': 'webhook'}),
    'schedule': ('trigger', {'trigger_type': 'schedule'}),
    'userinput': ('approval_gate', {}),
    'subflow': ('action', {'action_type': 'run_playbook'}),
}


# ============================================================================
# Torq (Hyperautomation) Action Mappings
# ============================================================================

TORQ_ACTIONS: Dict[str, Tuple[str, Dict[str, Any]]] = {
    # Step Types
    'integration': ('action', {}),
    'condition': ('condition', {}),
    'loop': ('transform', {'transform_type': 'loop'}),
    'transform': ('transform', {}),
    'human_task': ('approval_gate', {}),
    'subworkflow': ('action', {'action_type': 'run_playbook'}),
    'http': ('webhook_call', {}),
    'script': ('python_code', {}),
    'delay': ('delay', {}),

    # CrowdStrike actions
    'crowdstrike.contain_host': ('action', {'action_type': 'contain_host', 'integration': 'crowdstrike', 'requires_approval': True}),
    'crowdstrike.lift_containment': ('action', {'action_type': 'uncontain_host', 'integration': 'crowdstrike', 'requires_approval': True}),
    'crowdstrike.get_device': ('enrich', {'integration': 'crowdstrike', 'observable_type': 'host'}),
    'crowdstrike.search_detections': ('enrich', {'integration': 'crowdstrike', 'observable_type': 'detection'}),
    'crowdstrike.get_incident': ('enrich', {'integration': 'crowdstrike', 'observable_type': 'incident'}),
    'crowdstrike.run_rtr_command': ('action', {'action_type': 'run_command', 'integration': 'crowdstrike', 'requires_approval': True}),

    # SentinelOne actions
    'sentinelone.disconnect_agent': ('action', {'action_type': 'contain_host', 'integration': 'sentinelone', 'requires_approval': True}),
    'sentinelone.connect_agent': ('action', {'action_type': 'uncontain_host', 'integration': 'sentinelone', 'requires_approval': True}),
    'sentinelone.get_agent': ('enrich', {'integration': 'sentinelone', 'observable_type': 'host'}),
    'sentinelone.get_threats': ('enrich', {'integration': 'sentinelone', 'observable_type': 'threat'}),
    'sentinelone.initiate_scan': ('action', {'action_type': 'scan_host', 'integration': 'sentinelone'}),

    # Microsoft Defender actions
    'microsoft_defender.isolate_machine': ('action', {'action_type': 'contain_host', 'integration': 'microsoft_defender', 'requires_approval': True}),
    'microsoft_defender.unisolate_machine': ('action', {'action_type': 'uncontain_host', 'integration': 'microsoft_defender', 'requires_approval': True}),
    'microsoft_defender.get_machine': ('enrich', {'integration': 'microsoft_defender', 'observable_type': 'host'}),
    'microsoft_defender.run_antivirus_scan': ('action', {'action_type': 'scan_host', 'integration': 'microsoft_defender'}),

    # Okta actions
    'okta.suspend_user': ('action', {'action_type': 'disable_user', 'integration': 'okta', 'requires_approval': True}),
    'okta.unsuspend_user': ('action', {'action_type': 'enable_user', 'integration': 'okta', 'requires_approval': True}),
    'okta.clear_sessions': ('action', {'action_type': 'revoke_sessions', 'integration': 'okta', 'requires_approval': True}),
    'okta.reset_password': ('action', {'action_type': 'reset_password', 'integration': 'okta', 'requires_approval': True}),
    'okta.get_user': ('enrich', {'integration': 'okta', 'observable_type': 'user'}),
    'okta.list_user_groups': ('enrich', {'integration': 'okta', 'observable_type': 'group'}),

    # Active Directory
    'active_directory.disable_user': ('action', {'action_type': 'disable_user', 'integration': 'active_directory', 'requires_approval': True}),
    'active_directory.enable_user': ('action', {'action_type': 'enable_user', 'integration': 'active_directory', 'requires_approval': True}),
    'active_directory.reset_password': ('action', {'action_type': 'reset_password', 'integration': 'active_directory', 'requires_approval': True}),
    'active_directory.get_user': ('enrich', {'integration': 'active_directory', 'observable_type': 'user'}),

    # VirusTotal
    'virustotal.lookup_ip': ('enrich', {'integration': 'virustotal', 'observable_type': 'ip'}),
    'virustotal.lookup_domain': ('enrich', {'integration': 'virustotal', 'observable_type': 'domain'}),
    'virustotal.lookup_hash': ('enrich', {'integration': 'virustotal', 'observable_type': 'hash'}),
    'virustotal.lookup_url': ('enrich', {'integration': 'virustotal', 'observable_type': 'url'}),
    'virustotal.scan_file': ('enrich', {'integration': 'virustotal', 'observable_type': 'hash'}),
    'virustotal.scan_url': ('enrich', {'integration': 'virustotal', 'observable_type': 'url'}),

    # URLScan
    'urlscan.submit_scan': ('enrich', {'integration': 'urlscan', 'observable_type': 'url'}),
    'urlscan.get_result': ('enrich', {'integration': 'urlscan', 'observable_type': 'url'}),

    # Shodan
    'shodan.search_ip': ('enrich', {'integration': 'shodan', 'observable_type': 'ip'}),
    'shodan.search_query': ('enrich', {'integration': 'shodan', 'observable_type': 'query'}),

    # AbuseIPDB
    'abuseipdb.check_ip': ('enrich', {'integration': 'abuseipdb', 'observable_type': 'ip'}),
    'abuseipdb.report_ip': ('action', {'action_type': 'report_ip', 'integration': 'abuseipdb'}),

    # GreyNoise
    'greynoise.lookup_ip': ('enrich', {'integration': 'greynoise', 'observable_type': 'ip'}),

    # Slack
    'slack.send_message': ('notify', {'channel': 'slack'}),
    'slack.post_message': ('notify', {'channel': 'slack'}),
    'slack.create_channel': ('action', {'action_type': 'create_channel', 'integration': 'slack'}),
    'slack.upload_file': ('action', {'action_type': 'upload_file', 'integration': 'slack'}),

    # Microsoft Teams
    'teams.send_message': ('notify', {'channel': 'teams'}),
    'teams.post_adaptive_card': ('notify', {'channel': 'teams', 'card_type': 'adaptive'}),

    # Email
    'email.send_email': ('notify', {'channel': 'email'}),
    'email.send': ('notify', {'channel': 'email'}),

    # PagerDuty
    'pagerduty.create_incident': ('notify', {'integration': 'pagerduty'}),
    'pagerduty.acknowledge': ('action', {'action_type': 'acknowledge', 'integration': 'pagerduty'}),
    'pagerduty.resolve': ('action', {'action_type': 'resolve', 'integration': 'pagerduty'}),

    # ServiceNow
    'servicenow.create_incident': ('create_ticket', {'integration': 'servicenow'}),
    'servicenow.update_incident': ('action', {'action_type': 'update_ticket', 'integration': 'servicenow'}),
    'servicenow.get_incident': ('enrich', {'integration': 'servicenow', 'observable_type': 'ticket'}),
    'servicenow.close_incident': ('action', {'action_type': 'close_ticket', 'integration': 'servicenow'}),

    # Jira
    'jira.create_issue': ('create_ticket', {'integration': 'jira'}),
    'jira.update_issue': ('action', {'action_type': 'update_ticket', 'integration': 'jira'}),
    'jira.add_comment': ('action', {'action_type': 'add_comment', 'integration': 'jira'}),

    # AWS
    'aws.lambda_invoke': ('action', {'integration': 'aws_lambda'}),
    'aws.s3_get_object': ('enrich', {'integration': 'aws_s3', 'observable_type': 'object'}),
    'aws.ec2_describe_instances': ('enrich', {'integration': 'aws_ec2', 'observable_type': 'instance'}),
    'aws.iam_disable_access_key': ('action', {'action_type': 'disable_key', 'integration': 'aws_iam', 'requires_approval': True}),
    'aws.guardduty_get_findings': ('enrich', {'integration': 'aws_guardduty', 'observable_type': 'findings'}),
    'aws.security_hub_get_findings': ('enrich', {'integration': 'aws_security_hub', 'observable_type': 'findings'}),

    # Azure
    'azure.disable_user': ('action', {'action_type': 'disable_user', 'integration': 'azure_ad', 'requires_approval': True}),
    'azure.revoke_sessions': ('action', {'action_type': 'revoke_sessions', 'integration': 'azure_ad', 'requires_approval': True}),

    # GCP
    'gcp.disable_service_account': ('action', {'action_type': 'disable_key', 'integration': 'gcp', 'requires_approval': True}),

    # Firewall / Network
    'palo_alto.block_ip': ('action', {'action_type': 'block_ip', 'integration': 'palo_alto', 'requires_approval': True}),
    'palo_alto.unblock_ip': ('action', {'action_type': 'unblock_ip', 'integration': 'palo_alto', 'requires_approval': True}),
    'palo_alto.create_rule': ('action', {'action_type': 'create_rule', 'integration': 'palo_alto', 'requires_approval': True}),
    'fortinet.block_ip': ('action', {'action_type': 'block_ip', 'integration': 'fortinet', 'requires_approval': True}),

    # SIEM
    'splunk.search': ('enrich', {'integration': 'splunk', 'observable_type': 'query'}),
    'qradar.search': ('enrich', {'integration': 'qradar', 'observable_type': 'query'}),
    'elastic.search': ('enrich', {'integration': 'elastic', 'observable_type': 'query'}),
    'chronicle.search': ('enrich', {'integration': 'chronicle', 'observable_type': 'query'}),

    # MISP
    'misp.search_events': ('enrich', {'integration': 'misp', 'observable_type': 'events'}),
    'misp.add_attribute': ('action', {'action_type': 'add_attribute', 'integration': 'misp'}),

    # Trigger types
    'webhook': ('trigger', {'trigger_type': 'webhook'}),
    'schedule': ('trigger', {'trigger_type': 'schedule'}),
    'alert': ('trigger', {'trigger_type': 'alert'}),
    'manual': ('trigger', {'trigger_type': 'manual'}),
}


# ============================================================================
# BlinkOps Action Mappings
# ============================================================================

BLINKOPS_ACTIONS: Dict[str, Tuple[str, Dict[str, Any]]] = {
    # Step Types
    'action': ('action', {}),
    'condition': ('condition', {}),
    'loop': ('transform', {'transform_type': 'loop'}),
    'delay': ('delay', {}),
    'approval': ('approval_gate', {}),
    'script': ('python_code', {}),
    'http': ('webhook_call', {}),
    'transform': ('transform', {}),

    # Trigger types
    'webhook': ('trigger', {'trigger_type': 'webhook'}),
    'schedule': ('trigger', {'trigger_type': 'schedule'}),
    'alert': ('trigger', {'trigger_type': 'alert'}),
    'manual': ('trigger', {'trigger_type': 'manual'}),
    'event': ('trigger', {'trigger_type': 'event'}),

    # AWS Plugin Actions
    'aws.list_ec2_instances': ('enrich', {'integration': 'aws', 'observable_type': 'host'}),
    'aws.describe_ec2_instance': ('enrich', {'integration': 'aws', 'observable_type': 'host'}),
    'aws.stop_ec2_instance': ('action', {'action_type': 'stop_instance', 'integration': 'aws', 'requires_approval': True}),
    'aws.terminate_ec2_instance': ('action', {'action_type': 'terminate_instance', 'integration': 'aws', 'requires_approval': True}),
    'aws.disable_access_key': ('action', {'action_type': 'disable_access_key', 'integration': 'aws', 'requires_approval': True}),
    'aws.revoke_security_group_ingress': ('action', {'action_type': 'revoke_sg_rule', 'integration': 'aws', 'requires_approval': True}),
    'aws.get_guardduty_findings': ('enrich', {'integration': 'aws', 'observable_type': 'findings'}),
    'aws.get_s3_bucket_policy': ('enrich', {'integration': 'aws', 'observable_type': 'policy'}),
    'aws.block_s3_public_access': ('action', {'action_type': 'block_public_access', 'integration': 'aws', 'requires_approval': True}),

    # CrowdStrike Plugin Actions
    'crowdstrike.contain_host': ('action', {'action_type': 'contain_host', 'integration': 'crowdstrike', 'requires_approval': True}),
    'crowdstrike.lift_containment': ('action', {'action_type': 'uncontain_host', 'integration': 'crowdstrike', 'requires_approval': True}),
    'crowdstrike.get_device_details': ('enrich', {'integration': 'crowdstrike', 'observable_type': 'host'}),
    'crowdstrike.search_detections': ('enrich', {'integration': 'crowdstrike', 'observable_type': 'detection'}),
    'crowdstrike.get_incidents': ('enrich', {'integration': 'crowdstrike', 'observable_type': 'incident'}),
    'crowdstrike.run_rtr_command': ('action', {'action_type': 'run_command', 'integration': 'crowdstrike', 'requires_approval': True}),

    # SentinelOne Plugin Actions
    'sentinelone.disconnect_agent': ('action', {'action_type': 'contain_host', 'integration': 'sentinelone', 'requires_approval': True}),
    'sentinelone.reconnect_agent': ('action', {'action_type': 'uncontain_host', 'integration': 'sentinelone', 'requires_approval': True}),
    'sentinelone.get_agent': ('enrich', {'integration': 'sentinelone', 'observable_type': 'host'}),
    'sentinelone.get_threats': ('enrich', {'integration': 'sentinelone', 'observable_type': 'threat'}),
    'sentinelone.initiate_scan': ('action', {'action_type': 'scan_host', 'integration': 'sentinelone'}),

    # Okta Plugin Actions
    'okta.suspend_user': ('action', {'action_type': 'disable_user', 'integration': 'okta', 'requires_approval': True}),
    'okta.unsuspend_user': ('action', {'action_type': 'enable_user', 'integration': 'okta', 'requires_approval': True}),
    'okta.deactivate_user': ('action', {'action_type': 'disable_user', 'integration': 'okta', 'requires_approval': True}),
    'okta.clear_user_sessions': ('action', {'action_type': 'revoke_sessions', 'integration': 'okta', 'requires_approval': True}),
    'okta.reset_password': ('action', {'action_type': 'reset_password', 'integration': 'okta', 'requires_approval': True}),
    'okta.get_user': ('enrich', {'integration': 'okta', 'observable_type': 'user'}),
    'okta.list_user_factors': ('enrich', {'integration': 'okta', 'observable_type': 'mfa'}),
    'okta.reset_factors': ('action', {'action_type': 'reset_mfa', 'integration': 'okta', 'requires_approval': True}),

    # VirusTotal Plugin Actions
    'virustotal.get_ip_report': ('enrich', {'integration': 'virustotal', 'observable_type': 'ip'}),
    'virustotal.get_domain_report': ('enrich', {'integration': 'virustotal', 'observable_type': 'domain'}),
    'virustotal.get_hash_report': ('enrich', {'integration': 'virustotal', 'observable_type': 'hash'}),
    'virustotal.get_url_report': ('enrich', {'integration': 'virustotal', 'observable_type': 'url'}),
    'virustotal.scan_file': ('enrich', {'integration': 'virustotal', 'observable_type': 'hash'}),
    'virustotal.scan_url': ('enrich', {'integration': 'virustotal', 'observable_type': 'url'}),

    # Jira Plugin Actions
    'jira.create_issue': ('create_ticket', {'integration': 'jira'}),
    'jira.update_issue': ('action', {'action_type': 'update_ticket', 'integration': 'jira'}),
    'jira.add_comment': ('action', {'action_type': 'add_comment', 'integration': 'jira'}),
    'jira.transition_issue': ('action', {'action_type': 'update_status', 'integration': 'jira'}),

    # PagerDuty Plugin Actions
    'pagerduty.create_incident': ('notify', {'channel': 'pagerduty'}),
    'pagerduty.resolve_incident': ('action', {'action_type': 'resolve_incident', 'integration': 'pagerduty'}),
    'pagerduty.acknowledge_incident': ('action', {'action_type': 'acknowledge', 'integration': 'pagerduty'}),

    # Slack Plugin Actions
    'slack.send_message': ('notify', {'channel': 'slack'}),
    'slack.post_message': ('notify', {'channel': 'slack'}),
    'slack.create_channel': ('action', {'action_type': 'create_channel', 'integration': 'slack'}),
    'slack.upload_file': ('action', {'action_type': 'upload_file', 'integration': 'slack'}),

    # ServiceNow Plugin Actions
    'servicenow.create_incident': ('create_ticket', {'integration': 'servicenow'}),
    'servicenow.update_incident': ('action', {'action_type': 'update_ticket', 'integration': 'servicenow'}),
    'servicenow.close_incident': ('action', {'action_type': 'close_ticket', 'integration': 'servicenow'}),
    'servicenow.create_record': ('create_ticket', {'integration': 'servicenow'}),

    # Microsoft Defender Plugin Actions
    'microsoft_defender.isolate_machine': ('action', {'action_type': 'contain_host', 'integration': 'microsoft_defender', 'requires_approval': True}),
    'microsoft_defender.unisolate_machine': ('action', {'action_type': 'uncontain_host', 'integration': 'microsoft_defender', 'requires_approval': True}),
    'microsoft_defender.run_antivirus_scan': ('action', {'action_type': 'scan_host', 'integration': 'microsoft_defender'}),
    'microsoft_defender.get_machine': ('enrich', {'integration': 'microsoft_defender', 'observable_type': 'host'}),

    # Azure AD Plugin Actions
    'azure_ad.disable_user': ('action', {'action_type': 'disable_user', 'integration': 'azure_ad', 'requires_approval': True}),
    'azure_ad.revoke_sessions': ('action', {'action_type': 'revoke_sessions', 'integration': 'azure_ad', 'requires_approval': True}),
    'azure_ad.get_user': ('enrich', {'integration': 'azure_ad', 'observable_type': 'user'}),
    'azure_ad.reset_password': ('action', {'action_type': 'reset_password', 'integration': 'azure_ad', 'requires_approval': True}),

    # Generic Enrichment (fallback by plugin name)
    'urlscan.submit_url': ('enrich', {'integration': 'urlscan', 'observable_type': 'url'}),
    'urlscan.get_result': ('enrich', {'integration': 'urlscan', 'observable_type': 'url'}),
    'shodan.search_ip': ('enrich', {'integration': 'shodan', 'observable_type': 'ip'}),
    'abuseipdb.check_ip': ('enrich', {'integration': 'abuseipdb', 'observable_type': 'ip'}),
    'whois.lookup': ('enrich', {'integration': 'whois'}),
    'greynoise.ip_lookup': ('enrich', {'integration': 'greynoise', 'observable_type': 'ip'}),
    'hybrid_analysis.submit_file': ('enrich', {'integration': 'hybrid_analysis', 'observable_type': 'hash'}),
    'misp.search_event': ('enrich', {'integration': 'misp', 'observable_type': 'indicator'}),

    # Email Plugin Actions
    'email.send_email': ('notify', {'channel': 'email'}),
    'microsoft_365.send_email': ('notify', {'channel': 'email', 'integration': 'office365'}),
    'microsoft_365.delete_email': ('action', {'action_type': 'delete_email', 'integration': 'office365', 'requires_approval': True}),

    # Active Directory Plugin Actions
    'active_directory.disable_user': ('action', {'action_type': 'disable_user', 'integration': 'active_directory', 'requires_approval': True}),
    'active_directory.enable_user': ('action', {'action_type': 'enable_user', 'integration': 'active_directory', 'requires_approval': True}),
    'active_directory.reset_password': ('action', {'action_type': 'reset_password', 'integration': 'active_directory', 'requires_approval': True}),
    'active_directory.get_user': ('enrich', {'integration': 'active_directory', 'observable_type': 'user'}),

    # Firewall Plugin Actions
    'palo_alto.block_ip': ('action', {'action_type': 'block_ip', 'integration': 'palo_alto', 'requires_approval': True}),
    'palo_alto.unblock_ip': ('action', {'action_type': 'unblock_ip', 'integration': 'palo_alto', 'requires_approval': True}),
    'fortinet.block_ip': ('action', {'action_type': 'block_ip', 'integration': 'fortinet', 'requires_approval': True}),
}


# ============================================================================
# D3 Security (Smart SOAR) Action Mappings
# ============================================================================

D3_SECURITY_ACTIONS: Dict[str, Tuple[str, Dict[str, Any]]] = {
    # Command Types
    'integration': ('action', {}),
    'condition': ('condition', {}),
    'manual_task': ('approval_gate', {}),
    'timer': ('delay', {}),
    'set_variable': ('variable_set', {}),
    'sub_playbook': ('action', {'action_type': 'run_playbook'}),
    'notification': ('notify', {}),
    'script': ('python_code', {}),

    # VirusTotal Integration
    'virustotal.scan_ip': ('enrich', {'integration': 'virustotal', 'observable_type': 'ip'}),
    'virustotal.scan_domain': ('enrich', {'integration': 'virustotal', 'observable_type': 'domain'}),
    'virustotal.scan_hash': ('enrich', {'integration': 'virustotal', 'observable_type': 'hash'}),
    'virustotal.scan_url': ('enrich', {'integration': 'virustotal', 'observable_type': 'url'}),
    'virustotal.get_file_report': ('enrich', {'integration': 'virustotal', 'observable_type': 'hash'}),
    'virustotal.get_ip_report': ('enrich', {'integration': 'virustotal', 'observable_type': 'ip'}),
    'virustotal.get_domain_report': ('enrich', {'integration': 'virustotal', 'observable_type': 'domain'}),

    # CrowdStrike Falcon Integration
    'crowdstrike_falcon.isolate_endpoint': ('action', {'action_type': 'contain_host', 'integration': 'crowdstrike', 'requires_approval': True}),
    'crowdstrike_falcon.lift_containment': ('action', {'action_type': 'uncontain_host', 'integration': 'crowdstrike', 'requires_approval': True}),
    'crowdstrike_falcon.get_device': ('enrich', {'integration': 'crowdstrike', 'observable_type': 'host'}),
    'crowdstrike_falcon.search_detections': ('enrich', {'integration': 'crowdstrike', 'observable_type': 'detection'}),
    'crowdstrike_falcon.get_incidents': ('enrich', {'integration': 'crowdstrike', 'observable_type': 'incident'}),
    'crowdstrike_falcon.rtr_command': ('action', {'action_type': 'run_command', 'integration': 'crowdstrike', 'requires_approval': True}),

    # Microsoft Defender Integration
    'microsoft_defender.isolate_machine': ('action', {'action_type': 'contain_host', 'integration': 'microsoft_defender', 'requires_approval': True}),
    'microsoft_defender.unisolate_machine': ('action', {'action_type': 'uncontain_host', 'integration': 'microsoft_defender', 'requires_approval': True}),
    'microsoft_defender.run_scan': ('action', {'action_type': 'scan_host', 'integration': 'microsoft_defender'}),
    'microsoft_defender.get_machine': ('enrich', {'integration': 'microsoft_defender', 'observable_type': 'host'}),
    'microsoft_defender.get_alerts': ('enrich', {'integration': 'microsoft_defender', 'observable_type': 'alert'}),
    'microsoft_defender.stop_and_quarantine': ('action', {'action_type': 'quarantine_file', 'integration': 'microsoft_defender', 'requires_approval': True}),

    # Carbon Black Integration
    'carbon_black.isolate_device': ('action', {'action_type': 'contain_host', 'integration': 'carbon_black', 'requires_approval': True}),
    'carbon_black.unisolate_device': ('action', {'action_type': 'uncontain_host', 'integration': 'carbon_black', 'requires_approval': True}),
    'carbon_black.get_device': ('enrich', {'integration': 'carbon_black', 'observable_type': 'host'}),
    'carbon_black.ban_hash': ('action', {'action_type': 'block_hash', 'integration': 'carbon_black', 'requires_approval': True}),

    # SentinelOne Integration
    'sentinelone.disconnect_agent': ('action', {'action_type': 'contain_host', 'integration': 'sentinelone', 'requires_approval': True}),
    'sentinelone.reconnect_agent': ('action', {'action_type': 'uncontain_host', 'integration': 'sentinelone', 'requires_approval': True}),
    'sentinelone.get_agent': ('enrich', {'integration': 'sentinelone', 'observable_type': 'host'}),

    # Okta Integration
    'okta.disable_user_account': ('action', {'action_type': 'disable_user', 'integration': 'okta', 'requires_approval': True}),
    'okta.enable_user_account': ('action', {'action_type': 'enable_user', 'integration': 'okta', 'requires_approval': True}),
    'okta.suspend_user': ('action', {'action_type': 'disable_user', 'integration': 'okta', 'requires_approval': True}),
    'okta.clear_sessions': ('action', {'action_type': 'revoke_sessions', 'integration': 'okta', 'requires_approval': True}),
    'okta.reset_password': ('action', {'action_type': 'reset_password', 'integration': 'okta', 'requires_approval': True}),
    'okta.get_user': ('enrich', {'integration': 'okta', 'observable_type': 'user'}),

    # Active Directory Integration
    'active_directory.disable_user': ('action', {'action_type': 'disable_user', 'integration': 'active_directory', 'requires_approval': True}),
    'active_directory.enable_user': ('action', {'action_type': 'enable_user', 'integration': 'active_directory', 'requires_approval': True}),
    'active_directory.reset_password': ('action', {'action_type': 'reset_password', 'integration': 'active_directory', 'requires_approval': True}),
    'active_directory.get_user': ('enrich', {'integration': 'active_directory', 'observable_type': 'user'}),

    # ServiceNow Integration
    'servicenow.create_incident': ('create_ticket', {'integration': 'servicenow'}),
    'servicenow.update_incident': ('action', {'action_type': 'update_ticket', 'integration': 'servicenow'}),
    'servicenow.close_incident': ('action', {'action_type': 'close_ticket', 'integration': 'servicenow'}),
    'servicenow.create_ticket': ('create_ticket', {'integration': 'servicenow'}),
    'servicenow.get_ticket': ('enrich', {'integration': 'servicenow', 'observable_type': 'ticket'}),

    # Jira Integration
    'jira.create_issue': ('create_ticket', {'integration': 'jira'}),
    'jira.update_issue': ('action', {'action_type': 'update_ticket', 'integration': 'jira'}),

    # Email Integration
    'email.send_email': ('notify', {'channel': 'email'}),
    'email.send_notification': ('notify', {'channel': 'email'}),

    # Slack Integration
    'slack.send_message': ('notify', {'channel': 'slack'}),
    'slack.post_message': ('notify', {'channel': 'slack'}),

    # Teams Integration
    'teams.send_message': ('notify', {'channel': 'teams'}),
    'teams.post_message': ('notify', {'channel': 'teams'}),

    # PagerDuty Integration
    'pagerduty.create_incident': ('notify', {'channel': 'pagerduty'}),
    'pagerduty.resolve_incident': ('action', {'action_type': 'resolve_incident', 'integration': 'pagerduty'}),

    # Enrichment Integrations
    'urlscan.submit_url': ('enrich', {'integration': 'urlscan', 'observable_type': 'url'}),
    'shodan.search_ip': ('enrich', {'integration': 'shodan', 'observable_type': 'ip'}),
    'abuseipdb.check_ip': ('enrich', {'integration': 'abuseipdb', 'observable_type': 'ip'}),
    'whois.lookup': ('enrich', {'integration': 'whois'}),
    'greynoise.ip_lookup': ('enrich', {'integration': 'greynoise', 'observable_type': 'ip'}),
    'misp.search_event': ('enrich', {'integration': 'misp', 'observable_type': 'indicator'}),
    'hybrid_analysis.submit_file': ('enrich', {'integration': 'hybrid_analysis', 'observable_type': 'hash'}),

    # Firewall Integrations
    'palo_alto.block_ip': ('action', {'action_type': 'block_ip', 'integration': 'palo_alto', 'requires_approval': True}),
    'palo_alto.unblock_ip': ('action', {'action_type': 'unblock_ip', 'integration': 'palo_alto', 'requires_approval': True}),
    'fortinet.block_ip': ('action', {'action_type': 'block_ip', 'integration': 'fortinet', 'requires_approval': True}),
    'checkpoint.block_ip': ('action', {'action_type': 'block_ip', 'integration': 'checkpoint', 'requires_approval': True}),

    # AWS Integration
    'aws.disable_access_key': ('action', {'action_type': 'disable_access_key', 'integration': 'aws', 'requires_approval': True}),
    'aws.get_guardduty_findings': ('enrich', {'integration': 'aws', 'observable_type': 'findings'}),

    # SIEM Integration
    'splunk.run_query': ('enrich', {'integration': 'splunk', 'observable_type': 'query'}),
    'qradar.search': ('enrich', {'integration': 'qradar', 'observable_type': 'query'}),
    'elastic.search': ('enrich', {'integration': 'elastic', 'observable_type': 'query'}),

    # D3 internal actions
    'close_incident': ('end', {'disposition': 'completed'}),
    'update_incident': ('action', {'action_type': 'update_incident'}),
    'add_artifact': ('action', {'action_type': 'add_artifact'}),
    'run_playbook': ('action', {'action_type': 'run_playbook'}),
}


# ============================================================================
# Combined Action Map
# ============================================================================

ACTION_MAPS = {
    'splunk_soar': SPLUNK_SOAR_ACTIONS,
    'xsoar': XSOAR_COMMANDS,
    'tines': TINES_AGENTS,
    'swimlane': SWIMLANE_ACTIONS,
    'chronicle_soar': CHRONICLE_SOAR_ACTIONS,
    'qradar_soar': QRADAR_SOAR_ACTIONS,
    'sentinel': SENTINEL_ACTIONS,
    'fortisoar': FORTISOAR_ACTIONS,
    'servicenow_secops': SERVICENOW_SECOPS_ACTIONS,
    'exabeam': EXABEAM_ACTIONS,
    'logichub': LOGICHUB_ACTIONS,
    'resolve': RESOLVE_ACTIONS,
    'insight_connect': INSIGHT_CONNECT_ACTIONS,
    'thehive': THEHIVE_ACTIONS,
    'shuffle': SHUFFLE_ACTIONS,
    'torq': TORQ_ACTIONS,
    'blinkops': BLINKOPS_ACTIONS,
    'd3_security': D3_SECURITY_ACTIONS,
}


# ============================================================================
# Helper Functions
# ============================================================================

def get_action_map(platform: str) -> Dict[str, Tuple[str, Dict[str, Any]]]:
    """Get action map for a platform."""
    return ACTION_MAPS.get(platform, {})


def find_best_mapping(
    action_name: str,
    platform: str
) -> Tuple[str, Dict[str, Any]]:
    """
    Find the best mapping for an action.

    Tries exact match, then partial match, then returns unmapped.
    """
    action_map = get_action_map(platform)
    normalized = action_name.lower().replace('-', '_').replace(' ', '_')

    # Exact match
    if normalized in action_map:
        return action_map[normalized]

    # Remove leading ! for XSOAR commands
    if normalized.startswith('!'):
        clean_name = normalized[1:]
        if clean_name in action_map:
            return action_map[clean_name]

    # For Chronicle SOAR: try integration.action format
    if '.' in normalized:
        if normalized in action_map:
            return action_map[normalized]
        # Try just the action part
        action_part = normalized.split('.')[-1]
        if action_part in action_map:
            return action_map[action_part]

    # For QRadar SOAR: try fn_ prefix
    if not normalized.startswith('fn_'):
        fn_name = f'fn_{normalized}'
        if fn_name in action_map:
            return action_map[fn_name]

    # Partial match
    for key, value in action_map.items():
        if key in normalized or normalized in key:
            return value

    # Check for common patterns across all platforms
    if any(word in normalized for word in ['enrich', 'lookup', 'reputation', 'get_', 'scan', 'search', 'check']):
        return ('enrich', {'auto_mapped': True})

    if any(word in normalized for word in ['block', 'disable', 'quarantine', 'isolate', 'contain', 'terminate', 'kill']):
        return ('action', {'requires_approval': True, 'auto_mapped': True})

    if any(word in normalized for word in ['notify', 'send', 'alert', 'email', 'slack', 'teams', 'message']):
        return ('notify', {'auto_mapped': True})

    if any(word in normalized for word in ['ticket', 'incident', 'case', 'issue', 'create_record']):
        return ('create_ticket', {'auto_mapped': True})

    if any(word in normalized for word in ['close', 'resolve', 'complete']):
        return ('end', {'disposition': 'completed', 'auto_mapped': True})

    # No mapping
    return ('unmapped', {'original_action': action_name})
