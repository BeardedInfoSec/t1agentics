-- Migration 038: Add tenant_id to tables missing tenant isolation
-- Identified in audit checklist item 4.1

-- Helper: add tenant_id + index + FK to tables that exist but lack it
DO $$
DECLARE
    tbl TEXT;
    tables_to_fix TEXT[] := ARRAY[
        'soar_executions',
        'soar_playbooks',
        'trusted_senders'
    ];
BEGIN
    FOREACH tbl IN ARRAY tables_to_fix
    LOOP
        IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = tbl AND table_schema = 'public') THEN
            IF NOT EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_name = tbl AND column_name = 'tenant_id' AND table_schema = 'public'
            ) THEN
                EXECUTE format('ALTER TABLE %I ADD COLUMN tenant_id UUID', tbl);

                -- Backfill with platform owner tenant
                EXECUTE format(
                    'UPDATE %I SET tenant_id = ''00000000-0000-0000-0000-000000000001'' WHERE tenant_id IS NULL',
                    tbl
                );

                -- Add FK
                BEGIN
                    EXECUTE format(
                        'ALTER TABLE %I ADD CONSTRAINT fk_%s_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE',
                        tbl, tbl
                    );
                EXCEPTION WHEN OTHERS THEN
                    RAISE NOTICE 'Could not add FK on %: %', tbl, SQLERRM;
                END;

                -- Add index
                EXECUTE format('CREATE INDEX IF NOT EXISTS idx_%s_tenant_id ON %I(tenant_id)', tbl, tbl);

                RAISE NOTICE 'Added tenant_id to %', tbl;
            ELSE
                RAISE NOTICE 'Table % already has tenant_id', tbl;
            END IF;
        ELSE
            RAISE NOTICE 'Table % does not exist, skipping', tbl;
        END IF;
    END LOOP;
END $$;
