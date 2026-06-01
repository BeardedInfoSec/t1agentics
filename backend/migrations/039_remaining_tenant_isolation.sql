-- Migration 039: Add tenant_id and RLS to remaining core tables missing tenant isolation
-- Hackathon multi-tenant readiness: these core tables were identified in the audit
-- as storing per-tenant data without any tenant_id column or RLS policy.
-- Covers: users, investigations, alerts, iocs, integrations, webhooks,
--         credentials, ai_agents, threat_feeds, campaigns, action_requests, teams

DO $$
DECLARE
    tbl TEXT;
    tables_to_fix TEXT[] := ARRAY[
        'users',
        'investigations',
        'alerts',
        'iocs',
        'integrations',
        'webhooks',
        'credentials',
        'ai_agents',
        'threat_feeds',
        'campaigns',
        'action_requests',
        'teams'
    ];
BEGIN
    FOREACH tbl IN ARRAY tables_to_fix
    LOOP
        -- Check if table exists
        IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = tbl AND table_schema = 'public') THEN
            -- Check if tenant_id column already exists
            IF NOT EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_name = tbl AND column_name = 'tenant_id' AND table_schema = 'public'
            ) THEN
                -- Add tenant_id column (nullable first)
                EXECUTE format('ALTER TABLE %I ADD COLUMN tenant_id UUID', tbl);

                -- Backfill with platform owner tenant
                EXECUTE format(
                    'UPDATE %I SET tenant_id = ''00000000-0000-0000-0000-000000000001'' WHERE tenant_id IS NULL',
                    tbl
                );

                -- Add FK constraint
                BEGIN
                    EXECUTE format(
                        'ALTER TABLE %I ADD CONSTRAINT fk_%s_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE',
                        tbl, tbl
                    );
                EXCEPTION WHEN OTHERS THEN
                    RAISE NOTICE 'Could not add FK on %: %', tbl, SQLERRM;
                END;

                -- Add index on tenant_id
                EXECUTE format('CREATE INDEX IF NOT EXISTS idx_%s_tenant_id ON %I(tenant_id)', tbl, tbl);

                RAISE NOTICE 'Added tenant_id to %', tbl;
            END IF;

            -- Enable RLS (idempotent)
            EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', tbl);

            -- Create tenant isolation policy (drop first if exists to avoid duplicates)
            EXECUTE format('DROP POLICY IF EXISTS %s_tenant_isolation ON %I', tbl, tbl);
            EXECUTE format(
                'CREATE POLICY %s_tenant_isolation ON %I USING (tenant_id::text = current_setting(''app.current_tenant_id'', true))',
                tbl, tbl
            );

            -- Create platform admin bypass policy
            EXECUTE format('DROP POLICY IF EXISTS %s_platform_admin_bypass ON %I', tbl, tbl);
            EXECUTE format(
                'CREATE POLICY %s_platform_admin_bypass ON %I USING (current_setting(''app.is_platform_admin'', true) = ''true'')',
                tbl, tbl
            );

            RAISE NOTICE 'RLS enabled on %', tbl;
        ELSE
            RAISE NOTICE 'Table % does not exist, skipping', tbl;
        END IF;
    END LOOP;
END $$;
