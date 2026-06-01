-- Migration: 050_recommended_actions.sql
-- Recommended Actions: Riggs AI suggests actionable responses based on IOCs and available connectors

CREATE TABLE IF NOT EXISTS recommended_actions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    investigation_id UUID NOT NULL,

    -- What Riggs recommends
    action_type VARCHAR(50) NOT NULL,  -- block_ip, block_hash, enrich_ip, enrich_hash, enrich_domain, isolate_host, disable_user, etc.
    title VARCHAR(255) NOT NULL,       -- Human-readable: "Block IP 1.2.3.4 via CrowdStrike"
    description TEXT,                  -- Why Riggs recommends this
    priority VARCHAR(10) NOT NULL DEFAULT 'medium',  -- high, medium, low

    -- IOC context
    ioc_type VARCHAR(50),             -- ip, domain, hash, url, email, hostname, username
    ioc_value TEXT,                    -- The actual indicator value

    -- Connector mapping
    connector_id UUID,                 -- References connector_definitions.id (NULL if no connector available)
    instance_id UUID,                  -- References connect_instances.id (NULL if not installed)
    connector_action_id VARCHAR(100),  -- The specific action from integration.json (e.g., "block_ip", "enrich_file_hash")
    connector_name VARCHAR(255),       -- Denormalized for display: "CrowdStrike Falcon"

    -- State
    status VARCHAR(20) NOT NULL DEFAULT 'pending',  -- pending, approved, executing, completed, failed, dismissed

    -- Execution tracking
    approved_by UUID,                  -- User who approved
    approved_at TIMESTAMPTZ,
    executed_at TIMESTAMPTZ,
    execution_result JSONB,            -- Response from connector action execution
    dismissed_by UUID,
    dismissed_at TIMESTAMPTZ,
    dismiss_reason TEXT,

    -- Metadata
    riggs_analysis_id TEXT,            -- Links back to the Riggs analysis that generated this
    metadata JSONB DEFAULT '{}',       -- Extra context from Riggs

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_recommended_actions_tenant ON recommended_actions(tenant_id);
CREATE INDEX IF NOT EXISTS idx_recommended_actions_investigation ON recommended_actions(investigation_id);
CREATE INDEX IF NOT EXISTS idx_recommended_actions_status ON recommended_actions(status);
CREATE INDEX IF NOT EXISTS idx_recommended_actions_tenant_investigation ON recommended_actions(tenant_id, investigation_id);

-- RLS
ALTER TABLE recommended_actions ENABLE ROW LEVEL SECURITY;

CREATE POLICY recommended_actions_tenant_isolation ON recommended_actions
    USING (tenant_id = current_setting('app.current_tenant_id')::uuid);
