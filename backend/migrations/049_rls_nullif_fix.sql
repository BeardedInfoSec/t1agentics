-- ============================================================================
-- Migration 049: Fix RLS policies to handle empty tenant_id setting
-- ============================================================================
-- Problem: When app.current_tenant_id is set to '' (empty string),
-- the cast ''::uuid crashes with "invalid input syntax for type uuid".
-- PostgreSQL evaluates ALL parts of an OR expression before short-circuiting,
-- so the platform_admin_bypass OR branch does NOT prevent the crash.
--
-- Fix: Wrap with NULLIF so empty string becomes NULL (valid UUID cast):
--   BEFORE: (current_setting('app.current_tenant_id'::text, true))::uuid
--   AFTER:  (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid
--
-- This affects all policies created/modified by migration 045.
-- Must fix BOTH the USING and WITH CHECK clauses.
-- ============================================================================
-- Idempotent: Detects current policy definition, skips if already fixed.
-- ============================================================================

-- Phase 1: Fix standard policies (tenant_id = setting::uuid pattern)
DO $body$
DECLARE
    pol RECORD;
    new_using TEXT;
    new_check TEXT;
    cmd_type TEXT;
    create_sql TEXT;
    fixed_count INT := 0;
    old_pat TEXT := '(current_setting(''app.current_tenant_id''::text, true))';
    new_pat TEXT := '(NULLIF(current_setting(''app.current_tenant_id''::text, true), ''''::text))';
BEGIN
    FOR pol IN
        SELECT schemaname, tablename, policyname, cmd, qual, with_check
        FROM pg_policies
        WHERE (qual LIKE '%current_setting%tenant_id%' AND qual NOT LIKE '%NULLIF%')
           OR (with_check LIKE '%current_setting%tenant_id%' AND with_check NOT LIKE '%NULLIF%')
    LOOP
        new_using := pol.qual;
        new_check := pol.with_check;

        IF new_using IS NOT NULL AND new_using != '' THEN
            new_using := replace(new_using, old_pat, new_pat);
        END IF;

        IF new_check IS NOT NULL AND new_check != '' THEN
            new_check := replace(new_check, old_pat, new_pat);
        END IF;

        cmd_type := CASE pol.cmd WHEN '*' THEN 'ALL' ELSE UPPER(pol.cmd) END;

        EXECUTE format('DROP POLICY IF EXISTS %I ON %I.%I',
            pol.policyname, pol.schemaname, pol.tablename);

        create_sql := format('CREATE POLICY %I ON %I.%I FOR %s',
            pol.policyname, pol.schemaname, pol.tablename, cmd_type);

        IF new_using IS NOT NULL AND new_using != '' THEN
            create_sql := create_sql || ' USING (' || new_using || ')';
        END IF;

        IF new_check IS NOT NULL AND new_check != '' THEN
            create_sql := create_sql || ' WITH CHECK (' || new_check || ')';
        END IF;

        EXECUTE create_sql;
        fixed_count := fixed_count + 1;
    END LOOP;
    RAISE NOTICE 'Phase 1: Fixed % policies (standard pattern)', fixed_count;
END
$body$;

-- Phase 2: Fix edl_lists (uses tenant_id::text = current_setting(...) pattern)
DO $body$
DECLARE
    pol RECORD;
    old_pat TEXT := 'current_setting(''app.current_tenant_id''::text, true)';
    new_pat TEXT := 'NULLIF(current_setting(''app.current_tenant_id''::text, true), ''''::text)';
    new_using TEXT;
    new_check TEXT;
    cmd_type TEXT;
    create_sql TEXT;
    fixed_count INT := 0;
BEGIN
    FOR pol IN
        SELECT schemaname, tablename, policyname, cmd, qual, with_check
        FROM pg_policies
        WHERE tablename = 'edl_lists'
          AND ((qual LIKE '%current_setting%tenant_id%' AND qual NOT LIKE '%NULLIF%')
            OR (with_check LIKE '%current_setting%tenant_id%' AND with_check NOT LIKE '%NULLIF%'))
    LOOP
        new_using := replace(pol.qual, old_pat, new_pat);
        new_check := pol.with_check;
        IF new_check IS NOT NULL THEN
            new_check := replace(new_check, old_pat, new_pat);
        END IF;

        cmd_type := CASE pol.cmd WHEN '*' THEN 'ALL' ELSE UPPER(pol.cmd) END;

        EXECUTE format('DROP POLICY IF EXISTS %I ON %I.%I',
            pol.policyname, pol.schemaname, pol.tablename);

        create_sql := format('CREATE POLICY %I ON %I.%I FOR %s USING (%s)',
            pol.policyname, pol.schemaname, pol.tablename, cmd_type, new_using);

        IF new_check IS NOT NULL THEN
            create_sql := create_sql || ' WITH CHECK (' || new_check || ')';
        END IF;

        EXECUTE create_sql;
        fixed_count := fixed_count + 1;
    END LOOP;
    RAISE NOTICE 'Phase 2: Fixed % policies (edl_lists pattern)', fixed_count;
END
$body$;
