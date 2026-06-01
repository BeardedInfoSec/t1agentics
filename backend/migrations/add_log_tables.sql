-- Migration: Add missing log management tables
-- Run this on existing database to add log indexes, collectors, etc.

-- ============================================================================
-- LOG COLLECTION AGENTS
-- ============================================================================

CREATE TABLE IF NOT EXISTS log_agents (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    agent_id VARCHAR(255) UNIQUE NOT NULL,
    hostname VARCHAR(255) NOT NULL,
    os_type VARCHAR(50) NOT NULL CHECK (os_type IN ('windows', 'linux', 'macos', 'other')),
    os_version VARCHAR(100),
    ip_address INET,
    agent_version VARCHAR(50),
    status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'inactive', 'maintenance', 'decommissioned')),
    last_heartbeat TIMESTAMP WITH TIME ZONE,
    last_event_received TIMESTAMP WITH TIME ZONE,
    events_received_total BIGINT DEFAULT 0,
    config JSONB DEFAULT '{}',
    tags TEXT[] DEFAULT ARRAY[]::TEXT[],
    registered_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    registered_by VARCHAR(255),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    metadata JSONB DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_log_agents_hostname ON log_agents(hostname);
CREATE INDEX IF NOT EXISTS idx_log_agents_os_type ON log_agents(os_type);
CREATE INDEX IF NOT EXISTS idx_log_agents_status ON log_agents(status);
CREATE INDEX IF NOT EXISTS idx_log_agents_last_heartbeat ON log_agents(last_heartbeat);
CREATE INDEX IF NOT EXISTS idx_log_agents_tags ON log_agents USING GIN(tags);

-- ============================================================================
-- LOG INDEXES (Splunk-style)
-- ============================================================================

CREATE TABLE IF NOT EXISTS log_indexes (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(100) UNIQUE NOT NULL,
    display_name VARCHAR(255) NOT NULL,
    description TEXT,
    index_pattern VARCHAR(255) NOT NULL,
    data_classification VARCHAR(50) DEFAULT 'internal' CHECK (data_classification IN (
        'public', 'internal', 'confidential', 'restricted'
    )),
    retention_days INTEGER DEFAULT 90,
    is_active BOOLEAN DEFAULT true,
    is_default BOOLEAN DEFAULT false,
    source_types TEXT[],
    tags TEXT[],
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by VARCHAR(100)
);

CREATE INDEX IF NOT EXISTS idx_log_indexes_name ON log_indexes(name);
CREATE INDEX IF NOT EXISTS idx_log_indexes_pattern ON log_indexes(index_pattern);
CREATE INDEX IF NOT EXISTS idx_log_indexes_active ON log_indexes(is_active);
CREATE INDEX IF NOT EXISTS idx_log_indexes_classification ON log_indexes(data_classification);

-- Role-Index Permissions
CREATE TABLE IF NOT EXISTS role_index_permissions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    role VARCHAR(50) NOT NULL,
    index_id UUID REFERENCES log_indexes(id) ON DELETE CASCADE,
    index_name VARCHAR(100) NOT NULL,
    can_read BOOLEAN DEFAULT false,
    can_write BOOLEAN DEFAULT false,
    can_delete BOOLEAN DEFAULT false,
    can_admin BOOLEAN DEFAULT false,
    allowed_fields JSONB DEFAULT NULL,
    denied_fields JSONB DEFAULT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by VARCHAR(100),
    UNIQUE(role, index_id)
);

CREATE INDEX IF NOT EXISTS idx_role_index_perms_role ON role_index_permissions(role);
CREATE INDEX IF NOT EXISTS idx_role_index_perms_index ON role_index_permissions(index_id);
CREATE INDEX IF NOT EXISTS idx_role_index_perms_name ON role_index_permissions(index_name);

-- User-specific Index Overrides
CREATE TABLE IF NOT EXISTS user_index_permissions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    username VARCHAR(100) NOT NULL,
    index_id UUID REFERENCES log_indexes(id) ON DELETE CASCADE,
    index_name VARCHAR(100) NOT NULL,
    can_read BOOLEAN DEFAULT NULL,
    can_write BOOLEAN DEFAULT NULL,
    can_delete BOOLEAN DEFAULT NULL,
    reason TEXT,
    expires_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by VARCHAR(100),
    UNIQUE(user_id, index_id)
);

CREATE INDEX IF NOT EXISTS idx_user_index_perms_user ON user_index_permissions(user_id);
CREATE INDEX IF NOT EXISTS idx_user_index_perms_username ON user_index_permissions(username);
CREATE INDEX IF NOT EXISTS idx_user_index_perms_index ON user_index_permissions(index_id);

-- Log Search Audit (SOC2 compliance)
CREATE TABLE IF NOT EXISTS log_search_audit (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    username VARCHAR(100) NOT NULL,
    user_role VARCHAR(50),
    search_query TEXT NOT NULL,
    index_names TEXT[],
    time_range VARCHAR(50),
    results_count INTEGER,
    execution_time_ms INTEGER,
    ip_address INET,
    user_agent TEXT,
    success BOOLEAN DEFAULT true,
    error_message TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_log_search_audit_user ON log_search_audit(username, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_log_search_audit_time ON log_search_audit(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_log_search_audit_indexes ON log_search_audit USING GIN(index_names);

-- ============================================================================
-- LOG SOURCE TYPES
-- ============================================================================

CREATE TABLE IF NOT EXISTS log_source_types (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    source_type VARCHAR(100) UNIQUE NOT NULL,
    display_name VARCHAR(255) NOT NULL,
    description TEXT,
    category VARCHAR(50) NOT NULL CHECK (category IN (
        'endpoint', 'network', 'cloud', 'application', 'identity', 'email', 'database', 'custom'
    )),
    supported_platforms TEXT[] DEFAULT ARRAY['windows', 'linux', 'macos']::TEXT[],
    default_index_id UUID REFERENCES log_indexes(id) ON DELETE SET NULL,
    default_index_name VARCHAR(100),
    default_config JSONB DEFAULT '{}',
    schema_definition JSONB DEFAULT '{}',
    parser_type VARCHAR(50) DEFAULT 'json' CHECK (parser_type IN ('json', 'syslog', 'cef', 'leef', 'csv', 'regex', 'xml', 'custom')),
    parser_config JSONB DEFAULT '{}',
    is_builtin BOOLEAN DEFAULT false,
    is_enabled BOOLEAN DEFAULT true,
    vendor VARCHAR(100),
    product VARCHAR(100),
    icon_name VARCHAR(50),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by VARCHAR(100)
);

CREATE INDEX IF NOT EXISTS idx_log_source_types_category ON log_source_types(category);
CREATE INDEX IF NOT EXISTS idx_log_source_types_enabled ON log_source_types(is_enabled);
CREATE INDEX IF NOT EXISTS idx_log_source_types_platforms ON log_source_types USING GIN(supported_platforms);

-- ============================================================================
-- COLLECTOR SOURCE ASSIGNMENTS
-- ============================================================================

CREATE TABLE IF NOT EXISTS collector_source_assignments (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    agent_id UUID REFERENCES log_agents(id) ON DELETE CASCADE,
    agent_hostname VARCHAR(255) NOT NULL,
    source_type_id UUID REFERENCES log_source_types(id) ON DELETE CASCADE,
    source_type VARCHAR(100) NOT NULL,
    target_index_id UUID REFERENCES log_indexes(id) ON DELETE SET NULL,
    target_index_name VARCHAR(100),
    config_overrides JSONB DEFAULT '{}',
    include_filters JSONB DEFAULT '[]',
    exclude_filters JSONB DEFAULT '[]',
    is_enabled BOOLEAN DEFAULT true,
    status VARCHAR(30) DEFAULT 'active' CHECK (status IN ('active', 'paused', 'error', 'configuring')),
    last_event_at TIMESTAMP WITH TIME ZONE,
    events_collected BIGINT DEFAULT 0,
    error_message TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by VARCHAR(100),
    UNIQUE(agent_id, source_type_id)
);

CREATE INDEX IF NOT EXISTS idx_collector_assignments_agent ON collector_source_assignments(agent_id);
CREATE INDEX IF NOT EXISTS idx_collector_assignments_source ON collector_source_assignments(source_type_id);
CREATE INDEX IF NOT EXISTS idx_collector_assignments_status ON collector_source_assignments(status);
CREATE INDEX IF NOT EXISTS idx_collector_assignments_enabled ON collector_source_assignments(is_enabled);

-- ============================================================================
-- COLLECTOR GROUPS
-- ============================================================================

CREATE TABLE IF NOT EXISTS collector_groups (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(100) UNIQUE NOT NULL,
    display_name VARCHAR(255) NOT NULL,
    description TEXT,
    auto_membership_rules JSONB DEFAULT NULL,
    is_enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by VARCHAR(100)
);

CREATE INDEX IF NOT EXISTS idx_collector_groups_name ON collector_groups(name);
CREATE INDEX IF NOT EXISTS idx_collector_groups_enabled ON collector_groups(is_enabled);

CREATE TABLE IF NOT EXISTS collector_group_membership (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    group_id UUID REFERENCES collector_groups(id) ON DELETE CASCADE,
    agent_id UUID REFERENCES log_agents(id) ON DELETE CASCADE,
    is_manual BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(group_id, agent_id)
);

CREATE INDEX IF NOT EXISTS idx_collector_membership_group ON collector_group_membership(group_id);
CREATE INDEX IF NOT EXISTS idx_collector_membership_agent ON collector_group_membership(agent_id);

CREATE TABLE IF NOT EXISTS group_source_assignments (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    group_id UUID REFERENCES collector_groups(id) ON DELETE CASCADE,
    group_name VARCHAR(100) NOT NULL,
    source_type_id UUID REFERENCES log_source_types(id) ON DELETE CASCADE,
    source_type VARCHAR(100) NOT NULL,
    target_index_id UUID REFERENCES log_indexes(id) ON DELETE SET NULL,
    target_index_name VARCHAR(100),
    config_overrides JSONB DEFAULT '{}',
    include_filters JSONB DEFAULT '[]',
    exclude_filters JSONB DEFAULT '[]',
    priority INTEGER DEFAULT 0,
    is_enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by VARCHAR(100),
    UNIQUE(group_id, source_type_id)
);

CREATE INDEX IF NOT EXISTS idx_group_assignments_group ON group_source_assignments(group_id);
CREATE INDEX IF NOT EXISTS idx_group_assignments_source ON group_source_assignments(source_type_id);
CREATE INDEX IF NOT EXISTS idx_group_assignments_priority ON group_source_assignments(priority DESC);

-- ============================================================================
-- DETECTION RULES (if not exists)
-- ============================================================================

-- Detection rules table might already exist, so just ensure the detection_hits table exists
CREATE TABLE IF NOT EXISTS detection_hits (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    rule_id UUID REFERENCES detection_rules(id) ON DELETE SET NULL,
    rule_name VARCHAR(255) NOT NULL,
    event_id VARCHAR(255) NOT NULL,
    event_index VARCHAR(255) NOT NULL,
    event_timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    matched_fields JSONB NOT NULL,
    severity VARCHAR(20) NOT NULL,
    agent_id UUID REFERENCES log_agents(id) ON DELETE SET NULL,
    hostname VARCHAR(255),
    source_ip INET,
    alert_created BOOLEAN DEFAULT false,
    alert_id UUID REFERENCES alerts(id) ON DELETE SET NULL,
    disposition VARCHAR(50) CHECK (disposition IN ('true_positive', 'false_positive', 'benign', 'inconclusive', NULL)),
    disposition_by VARCHAR(255),
    disposition_at TIMESTAMP WITH TIME ZONE,
    disposition_notes TEXT,
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_detection_hits_rule ON detection_hits(rule_id);
CREATE INDEX IF NOT EXISTS idx_detection_hits_event ON detection_hits(event_id);
CREATE INDEX IF NOT EXISTS idx_detection_hits_timestamp ON detection_hits(event_timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_detection_hits_severity ON detection_hits(severity);
CREATE INDEX IF NOT EXISTS idx_detection_hits_agent ON detection_hits(agent_id);
CREATE INDEX IF NOT EXISTS idx_detection_hits_hostname ON detection_hits(hostname);
CREATE INDEX IF NOT EXISTS idx_detection_hits_alert ON detection_hits(alert_id);
CREATE INDEX IF NOT EXISTS idx_detection_hits_disposition ON detection_hits(disposition);
CREATE INDEX IF NOT EXISTS idx_detection_hits_detected ON detection_hits(detected_at DESC);

-- ============================================================================
-- RETENTION POLICIES
-- ============================================================================

CREATE TABLE IF NOT EXISTS retention_policies (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(100) UNIQUE NOT NULL,
    description TEXT,
    data_type VARCHAR(50) NOT NULL CHECK (data_type IN ('logs', 'alerts', 'investigations', 'audit_logs', 'detection_hits')),
    index_pattern VARCHAR(255),
    hot_days INTEGER DEFAULT 7,
    warm_days INTEGER DEFAULT 30,
    cold_days INTEGER DEFAULT 365,
    delete_after_days INTEGER DEFAULT 2555,
    compliance_requirement VARCHAR(255),
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by VARCHAR(255),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_by VARCHAR(255)
);

CREATE INDEX IF NOT EXISTS idx_retention_policies_data_type ON retention_policies(data_type);
CREATE INDEX IF NOT EXISTS idx_retention_policies_active ON retention_policies(is_active);

-- ============================================================================
-- LOG SOURCE CONFIGS
-- ============================================================================

CREATE TABLE IF NOT EXISTS log_source_configs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    source_type VARCHAR(100) UNIQUE NOT NULL,
    display_name VARCHAR(255) NOT NULL,
    description TEXT,
    parser_type VARCHAR(50) DEFAULT 'json' CHECK (parser_type IN ('json', 'syslog', 'cef', 'leef', 'csv', 'regex', 'xml')),
    parser_config JSONB DEFAULT '{}',
    field_mappings JSONB DEFAULT '{}',
    auto_enrichments JSONB DEFAULT '[]',
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_log_source_configs_type ON log_source_configs(source_type);
CREATE INDEX IF NOT EXISTS idx_log_source_configs_active ON log_source_configs(is_active);

-- ============================================================================
-- INSERT DEFAULT DATA
-- ============================================================================

-- Default log indexes (Splunk-style)
INSERT INTO log_indexes (name, display_name, description, index_pattern, data_classification, source_types, tags, is_default) VALUES
    ('main', 'Main', 'Default index for general logs', 'logs-main-*', 'internal', ARRAY['generic'], ARRAY['default'], true),
    ('security', 'Security Events', 'Security-related events from all sources', 'logs-security-*', 'confidential', ARRAY['edr_process', 'edr_network', 'edr_file', 'windows_security', 'linux_auditd'], ARRAY['security', 'siem', 'detection']),
    ('endpoint', 'Endpoint Telemetry', 'EDR and endpoint monitoring data', 'logs-endpoint-*', 'confidential', ARRAY['edr_process', 'edr_network', 'edr_file'], ARRAY['edr', 'endpoint', 'telemetry']),
    ('network', 'Network Traffic', 'Firewall, proxy, and network flow data', 'logs-network-*', 'internal', ARRAY['firewall', 'proxy', 'netflow', 'dns'], ARRAY['network', 'traffic', 'firewall']),
    ('auth', 'Authentication', 'Login and authentication events', 'logs-auth-*', 'confidential', ARRAY['windows_security', 'linux_auth', 'sso', 'mfa'], ARRAY['auth', 'login', 'identity']),
    ('admin', 'Administrative', 'Privileged operations and admin actions', 'logs-admin-*', 'restricted', ARRAY['admin_audit', 'privileged'], ARRAY['admin', 'privileged', 'sensitive']),
    ('application', 'Application Logs', 'Application-level events and errors', 'logs-app-*', 'internal', ARRAY['app_error', 'app_access', 'app_audit'], ARRAY['application', 'errors']),
    ('threat_intel', 'Threat Intelligence', 'IOC matches and threat feed hits', 'logs-threat-*', 'confidential', ARRAY['ioc_match', 'threat_feed'], ARRAY['threat', 'intel', 'ioc'])
ON CONFLICT (name) DO NOTHING;

-- Admin: Full access to everything
INSERT INTO role_index_permissions (role, index_id, index_name, can_read, can_write, can_delete, can_admin)
SELECT 'admin', id, name, true, true, true, true FROM log_indexes
ON CONFLICT (role, index_id) DO NOTHING;

-- Analyst: Read/write to most indexes
INSERT INTO role_index_permissions (role, index_id, index_name, can_read, can_write, can_delete, can_admin)
SELECT 'analyst', id, name, true, true, false, false
FROM log_indexes
WHERE name NOT IN ('admin')
ON CONFLICT (role, index_id) DO NOTHING;

-- Analyst: Limited access to admin index
INSERT INTO role_index_permissions (role, index_id, index_name, can_read, can_write, can_delete, can_admin, denied_fields)
SELECT 'analyst', id, name, true, false, false, false, '["credentials.*", "api_key.*", "secret.*"]'::jsonb
FROM log_indexes
WHERE name = 'admin'
ON CONFLICT (role, index_id) DO NOTHING;

-- Read-only: Can only read from certain indexes
INSERT INTO role_index_permissions (role, index_id, index_name, can_read, can_write, can_delete, can_admin)
SELECT 'read_only', id, name, true, false, false, false
FROM log_indexes
WHERE name IN ('main', 'auth', 'application')
ON CONFLICT (role, index_id) DO NOTHING;

-- Default log source types
INSERT INTO log_source_types (source_type, display_name, description, category, supported_platforms, default_index_name, parser_type, vendor, product, is_builtin) VALUES
    ('windows_security', 'Windows Security Events', 'Windows Security Event Log (4624, 4625, 4688, etc.)', 'endpoint', ARRAY['windows'], 'security', 'json', 'Microsoft', 'Windows', true),
    ('windows_sysmon', 'Windows Sysmon', 'System Monitor events (process, network, file operations)', 'endpoint', ARRAY['windows'], 'endpoint', 'json', 'Microsoft', 'Sysmon', true),
    ('windows_powershell', 'Windows PowerShell', 'PowerShell script block and module logging', 'endpoint', ARRAY['windows'], 'endpoint', 'json', 'Microsoft', 'PowerShell', true),
    ('windows_defender', 'Windows Defender', 'Microsoft Defender antivirus events', 'endpoint', ARRAY['windows'], 'security', 'json', 'Microsoft', 'Defender', true),
    ('linux_auditd', 'Linux Audit', 'Linux auditd security events', 'endpoint', ARRAY['linux'], 'security', 'syslog', 'Linux', 'auditd', true),
    ('linux_syslog', 'Linux Syslog', 'Standard Linux system logs', 'endpoint', ARRAY['linux'], 'main', 'syslog', 'Linux', 'syslog', true),
    ('macos_unified', 'macOS Unified Logs', 'macOS unified logging system', 'endpoint', ARRAY['macos'], 'endpoint', 'json', 'Apple', 'macOS', true),
    ('firewall_generic', 'Generic Firewall', 'Generic firewall logs', 'network', ARRAY['windows', 'linux'], 'network', 'syslog', NULL, NULL, true),
    ('firewall_palo_alto', 'Palo Alto Firewall', 'Palo Alto Networks firewall traffic and threat logs', 'network', ARRAY['windows', 'linux'], 'network', 'syslog', 'Palo Alto Networks', 'PAN-OS', true),
    ('dns_logs', 'DNS Query Logs', 'DNS server query and response logs', 'network', ARRAY['windows', 'linux'], 'network', 'syslog', NULL, NULL, true),
    ('netflow', 'NetFlow/IPFIX', 'Network flow data (NetFlow v5/v9, IPFIX)', 'network', ARRAY['windows', 'linux'], 'network', 'json', NULL, NULL, true),
    ('ldap_audit', 'LDAP/AD Audit', 'Active Directory and LDAP authentication events', 'identity', ARRAY['windows'], 'auth', 'json', 'Microsoft', 'Active Directory', true),
    ('web_access', 'Web Server Access', 'Apache/Nginx access logs', 'application', ARRAY['linux'], 'application', 'regex', NULL, NULL, true),
    ('database_audit', 'Database Audit', 'Database query and access audit logs', 'database', ARRAY['windows', 'linux'], 'admin', 'json', NULL, NULL, true)
ON CONFLICT (source_type) DO NOTHING;

-- Update log_source_types with default_index_id
UPDATE log_source_types lst
SET default_index_id = li.id
FROM log_indexes li
WHERE lst.default_index_name = li.name
  AND lst.default_index_id IS NULL;

-- Default retention policies
INSERT INTO retention_policies (name, description, data_type, index_pattern, hot_days, warm_days, cold_days, delete_after_days, compliance_requirement, created_by)
VALUES
    ('Security Events - PCI', 'Security event logs per PCI-DSS 10.7', 'logs', 'security-events-*', 7, 30, 365, 2555, 'PCI-DSS 10.7 - Retain audit trail history for at least one year', 'system'),
    ('Audit Logs - SOC2', 'System audit logs per SOC2 CC7.2', 'audit_logs', NULL, 30, 90, 365, 2555, 'SOC2 CC7.2 - System monitoring and anomaly detection', 'system'),
    ('Alerts', 'Security alerts retention', 'alerts', NULL, 30, 90, 365, 2555, 'SOC2/PCI - Security incident records', 'system'),
    ('Investigations', 'Investigation case files', 'investigations', NULL, 90, 180, 730, 2555, 'Legal hold and compliance review', 'system'),
    ('Detection Hits', 'Detection rule matches', 'detection_hits', NULL, 30, 90, 365, 2555, 'Detection tuning and metrics', 'system')
ON CONFLICT (name) DO NOTHING;

-- Default log source configs
INSERT INTO log_source_configs (source_type, display_name, description, parser_type, parser_config)
VALUES
    ('windows_security', 'Windows Security Events', 'Windows Security Event Log (Event IDs 4624, 4625, 4688, etc.)', 'json', '{"event_id_field": "EventID", "timestamp_field": "TimeCreated"}'),
    ('windows_sysmon', 'Windows Sysmon', 'Sysmon process and network monitoring', 'json', '{"event_id_field": "EventID", "timestamp_field": "UtcTime"}'),
    ('linux_syslog', 'Linux Syslog', 'Standard Linux syslog messages', 'syslog', '{"facility_field": "facility", "severity_field": "severity"}'),
    ('linux_auditd', 'Linux Auditd', 'Linux Audit Daemon logs', 'json', '{"type_field": "type", "timestamp_field": "timestamp"}'),
    ('network_firewall', 'Firewall Logs', 'Generic firewall connection logs', 'json', '{}'),
    ('cloud_audit', 'Cloud Audit Logs', 'AWS CloudTrail, Azure Activity, GCP Audit', 'json', '{}')
ON CONFLICT (source_type) DO NOTHING;

SELECT 'Log management tables created successfully!' as result;
