-- Add sensitivity column to alerts and investigations
-- Sensitivity levels: public, internal, confidential, restricted
-- Controls who can view/edit based on RBAC permissions

-- Add to alerts table
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS sensitivity VARCHAR(20) NOT NULL DEFAULT 'internal';

-- Add to investigations table
ALTER TABLE investigations ADD COLUMN IF NOT EXISTS sensitivity VARCHAR(20) NOT NULL DEFAULT 'internal';

-- Index for filtering by sensitivity
CREATE INDEX IF NOT EXISTS ix_alerts_sensitivity ON alerts(tenant_id, sensitivity);
CREATE INDEX IF NOT EXISTS ix_investigations_sensitivity ON investigations(tenant_id, sensitivity);
