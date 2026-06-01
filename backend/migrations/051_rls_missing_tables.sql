-- ============================================================================
-- Migration 051: Enable RLS on tables that have tenant_id but were missing RLS
-- ============================================================================
-- Found by comprehensive audit on 2026-02-25:
--   - ioc_feed_appearances (567K rows - critical gap)
--   - affiliate_codes (empty)
--   - kb_community_submissions (empty)
-- ============================================================================

-- ioc_feed_appearances
ALTER TABLE ioc_feed_appearances ENABLE ROW LEVEL SECURITY;
ALTER TABLE ioc_feed_appearances FORCE ROW LEVEL SECURITY;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'ioc_feed_appearances' AND policyname = 'tenant_isolation_policy') THEN
    CREATE POLICY tenant_isolation_policy ON ioc_feed_appearances FOR ALL
      USING (
        current_setting('app.is_platform_admin'::text, true) = 'true'::text
        OR tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid
      )
      WITH CHECK (
        current_setting('app.is_platform_admin'::text, true) = 'true'::text
        OR tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid
      );
  END IF;
END $$;

-- affiliate_codes
ALTER TABLE affiliate_codes ENABLE ROW LEVEL SECURITY;
ALTER TABLE affiliate_codes FORCE ROW LEVEL SECURITY;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'affiliate_codes' AND policyname = 'tenant_isolation_policy') THEN
    CREATE POLICY tenant_isolation_policy ON affiliate_codes FOR ALL
      USING (
        current_setting('app.is_platform_admin'::text, true) = 'true'::text
        OR tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid
      )
      WITH CHECK (
        current_setting('app.is_platform_admin'::text, true) = 'true'::text
        OR tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid
      );
  END IF;
END $$;

-- kb_community_submissions
ALTER TABLE kb_community_submissions ENABLE ROW LEVEL SECURITY;
ALTER TABLE kb_community_submissions FORCE ROW LEVEL SECURITY;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'kb_community_submissions' AND policyname = 'tenant_isolation_policy') THEN
    CREATE POLICY tenant_isolation_policy ON kb_community_submissions FOR ALL
      USING (
        current_setting('app.is_platform_admin'::text, true) = 'true'::text
        OR tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid
      )
      WITH CHECK (
        current_setting('app.is_platform_admin'::text, true) = 'true'::text
        OR tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid
      );
  END IF;
END $$;
