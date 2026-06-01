-- Migration 031: Add tenant_id to api_keys table for multi-tenant isolation
-- Without this, API keys are global and could access any tenant's data

-- Add tenant_id column (nullable first for existing rows)
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS tenant_id UUID;

-- Set existing keys to the platform owner tenant
UPDATE api_keys SET tenant_id = '00000000-0000-0000-0000-000000000001' WHERE tenant_id IS NULL;

-- Make it NOT NULL after backfill
ALTER TABLE api_keys ALTER COLUMN tenant_id SET NOT NULL;

-- Add foreign key constraint
ALTER TABLE api_keys ADD CONSTRAINT fk_api_keys_tenant
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE;

-- Add index for tenant lookups
CREATE INDEX IF NOT EXISTS idx_api_keys_tenant_id ON api_keys(tenant_id);

-- Add RLS policy for tenant isolation
ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY;

CREATE POLICY api_keys_tenant_isolation ON api_keys
    USING (tenant_id::text = current_setting('app.current_tenant_id', true));
