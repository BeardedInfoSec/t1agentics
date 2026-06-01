-- Migration: Add sample collectors and source types
-- Run this on an existing database to add sample data

-- First ensure the tables exist (they should from init-db.sql)

-- Insert default log source types if not already present
INSERT INTO log_source_types (source_type, display_name, description, category, supported_platforms, default_index_name, parser_type, vendor, product, is_builtin) VALUES
    -- Endpoint sources
    ('windows_security', 'Windows Security Events', 'Windows Security Event Log (4624, 4625, 4688, etc.)', 'endpoint', ARRAY['windows'], 'security', 'json', 'Microsoft', 'Windows', true),
    ('windows_sysmon', 'Windows Sysmon', 'System Monitor events (process, network, file operations)', 'endpoint', ARRAY['windows'], 'endpoint', 'json', 'Microsoft', 'Sysmon', true),
    ('windows_powershell', 'Windows PowerShell', 'PowerShell script block and module logging', 'endpoint', ARRAY['windows'], 'endpoint', 'json', 'Microsoft', 'PowerShell', true),
    ('windows_defender', 'Windows Defender', 'Microsoft Defender antivirus events', 'endpoint', ARRAY['windows'], 'security', 'json', 'Microsoft', 'Defender', true),
    ('linux_auditd', 'Linux Audit', 'Linux auditd security events', 'endpoint', ARRAY['linux'], 'security', 'syslog', 'Linux', 'auditd', true),
    ('linux_syslog', 'Linux Syslog', 'Standard Linux system logs', 'endpoint', ARRAY['linux'], 'main', 'syslog', 'Linux', 'syslog', true),
    ('macos_unified', 'macOS Unified Logs', 'macOS unified logging system', 'endpoint', ARRAY['macos'], 'endpoint', 'json', 'Apple', 'macOS', true),
    -- Network sources
    ('firewall_generic', 'Generic Firewall', 'Generic firewall logs', 'network', ARRAY['windows', 'linux'], 'network', 'syslog', NULL, NULL, true),
    ('firewall_palo_alto', 'Palo Alto Firewall', 'Palo Alto Networks firewall traffic and threat logs', 'network', ARRAY['windows', 'linux'], 'network', 'syslog', 'Palo Alto Networks', 'PAN-OS', true),
    ('dns_logs', 'DNS Query Logs', 'DNS server query and response logs', 'network', ARRAY['windows', 'linux'], 'network', 'syslog', NULL, NULL, true),
    ('netflow', 'NetFlow/IPFIX', 'Network flow data (NetFlow v5/v9, IPFIX)', 'network', ARRAY['windows', 'linux'], 'network', 'json', NULL, NULL, true),
    -- Identity sources
    ('ldap_audit', 'LDAP/AD Audit', 'Active Directory and LDAP authentication events', 'identity', ARRAY['windows'], 'auth', 'json', 'Microsoft', 'Active Directory', true),
    -- Application sources
    ('web_access', 'Web Server Access', 'Apache/Nginx access logs', 'application', ARRAY['linux'], 'application', 'regex', NULL, NULL, true),
    ('database_audit', 'Database Audit', 'Database query and access audit logs', 'database', ARRAY['windows', 'linux'], 'admin', 'json', NULL, NULL, true)
ON CONFLICT (source_type) DO NOTHING;

-- Update log_source_types with default_index_id from log_indexes
UPDATE log_source_types lst
SET default_index_id = li.id
FROM log_indexes li
WHERE lst.default_index_name = li.name
  AND lst.default_index_id IS NULL;

-- Insert sample log collectors for demonstration
INSERT INTO log_agents (agent_id, hostname, os_type, os_version, ip_address, agent_version, status, tags, metadata, last_heartbeat, events_received_total) VALUES
    ('agent-dc01-prod', 'DC01.corp.local', 'windows', 'Windows Server 2022', '10.0.1.10', '1.2.0', 'active', ARRAY['domain-controller', 'production', 'tier0'], '{"location": "HQ", "department": "IT"}', NOW() - INTERVAL '2 minutes', 1523847),
    ('agent-dc02-prod', 'DC02.corp.local', 'windows', 'Windows Server 2022', '10.0.1.11', '1.2.0', 'active', ARRAY['domain-controller', 'production', 'tier0'], '{"location": "HQ", "department": "IT"}', NOW() - INTERVAL '1 minute', 1489234),
    ('agent-web01-prod', 'web01.corp.local', 'linux', 'Ubuntu 22.04 LTS', '10.0.2.20', '1.2.0', 'active', ARRAY['web-server', 'production', 'dmz'], '{"location": "HQ", "department": "Engineering"}', NOW() - INTERVAL '30 seconds', 8234567),
    ('agent-web02-prod', 'web02.corp.local', 'linux', 'Ubuntu 22.04 LTS', '10.0.2.21', '1.2.0', 'active', ARRAY['web-server', 'production', 'dmz'], '{"location": "HQ", "department": "Engineering"}', NOW() - INTERVAL '45 seconds', 7891234),
    ('agent-db01-prod', 'db01.corp.local', 'linux', 'RHEL 8.8', '10.0.3.30', '1.1.5', 'active', ARRAY['database', 'production', 'tier1'], '{"location": "HQ", "department": "DBA"}', NOW() - INTERVAL '1 minute', 2345678),
    ('agent-mail01-prod', 'mail01.corp.local', 'windows', 'Windows Server 2019', '10.0.4.40', '1.2.0', 'active', ARRAY['email', 'production'], '{"location": "HQ", "department": "IT"}', NOW() - INTERVAL '2 minutes', 456789),
    ('agent-fw01-prod', 'fw01.corp.local', 'linux', 'PAN-OS 11.0', '10.0.0.1', '1.2.0', 'active', ARRAY['firewall', 'production', 'perimeter'], '{"location": "HQ", "department": "Security"}', NOW() - INTERVAL '15 seconds', 45678901),
    ('agent-siem01-prod', 'siem01.corp.local', 'linux', 'Ubuntu 20.04 LTS', '10.0.5.50', '1.2.0', 'maintenance', ARRAY['siem', 'production'], '{"location": "HQ", "department": "Security"}', NOW() - INTERVAL '1 hour', 12345678),
    ('agent-laptop001', 'LAPTOP-JSmith', 'windows', 'Windows 11 Pro', '192.168.1.101', '1.2.0', 'active', ARRAY['endpoint', 'workstation'], '{"location": "Remote", "department": "Sales", "user": "jsmith"}', NOW() - INTERVAL '5 minutes', 234567),
    ('agent-laptop002', 'LAPTOP-AJones', 'macos', 'macOS Sonoma 14.2', '192.168.1.102', '1.2.0', 'inactive', ARRAY['endpoint', 'workstation'], '{"location": "Remote", "department": "Marketing", "user": "ajones"}', NOW() - INTERVAL '2 days', 123456)
ON CONFLICT (agent_id) DO UPDATE SET
    last_heartbeat = EXCLUDED.last_heartbeat,
    status = EXCLUDED.status;

-- Assign some sources to the sample collectors
-- DC01 - Windows Security and AD events
INSERT INTO collector_source_assignments (agent_id, agent_hostname, source_type_id, source_type, target_index_name, is_enabled, status, events_collected)
SELECT la.id, la.hostname, lst.id, lst.source_type, lst.default_index_name, true, 'active', 500000
FROM log_agents la, log_source_types lst
WHERE la.agent_id = 'agent-dc01-prod' AND lst.source_type IN ('windows_security', 'ldap_audit')
ON CONFLICT (agent_id, source_type_id) DO NOTHING;

-- Web servers - Linux audit and web access
INSERT INTO collector_source_assignments (agent_id, agent_hostname, source_type_id, source_type, target_index_name, is_enabled, status, events_collected)
SELECT la.id, la.hostname, lst.id, lst.source_type, lst.default_index_name, true, 'active', 2000000
FROM log_agents la, log_source_types lst
WHERE la.agent_id = 'agent-web01-prod' AND lst.source_type IN ('linux_auditd', 'web_access', 'linux_syslog')
ON CONFLICT (agent_id, source_type_id) DO NOTHING;

-- Firewall - Network traffic
INSERT INTO collector_source_assignments (agent_id, agent_hostname, source_type_id, source_type, target_index_name, is_enabled, status, events_collected)
SELECT la.id, la.hostname, lst.id, lst.source_type, lst.default_index_name, true, 'active', 15000000
FROM log_agents la, log_source_types lst
WHERE la.agent_id = 'agent-fw01-prod' AND lst.source_type IN ('firewall_palo_alto', 'dns_logs', 'netflow')
ON CONFLICT (agent_id, source_type_id) DO NOTHING;

-- Database server
INSERT INTO collector_source_assignments (agent_id, agent_hostname, source_type_id, source_type, target_index_name, is_enabled, status, events_collected)
SELECT la.id, la.hostname, lst.id, lst.source_type, lst.default_index_name, true, 'active', 800000
FROM log_agents la, log_source_types lst
WHERE la.agent_id = 'agent-db01-prod' AND lst.source_type IN ('linux_auditd', 'database_audit')
ON CONFLICT (agent_id, source_type_id) DO NOTHING;

-- Laptop with Sysmon
INSERT INTO collector_source_assignments (agent_id, agent_hostname, source_type_id, source_type, target_index_name, is_enabled, status, events_collected)
SELECT la.id, la.hostname, lst.id, lst.source_type, lst.default_index_name, true, 'active', 100000
FROM log_agents la, log_source_types lst
WHERE la.agent_id = 'agent-laptop001' AND lst.source_type IN ('windows_sysmon', 'windows_defender', 'windows_powershell')
ON CONFLICT (agent_id, source_type_id) DO NOTHING;

SELECT 'Sample collectors and assignments created successfully!' as result;
