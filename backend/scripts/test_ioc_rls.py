"""Test IOC RLS with barbas-rooster-co tenant context"""
import asyncio
from services.postgres_db import postgres_db, set_platform_admin_mode

BARBAS_TENANT = "00000000-0000-0000-0000-000000000002"

async def test():
    await postgres_db.connect()

    # Test 1: admin mode (should see all IOCs)
    set_platform_admin_mode(True)
    async with postgres_db.tenant_acquire() as conn:
        total = await conn.fetchval("SELECT COUNT(*) FROM iocs")
        barbas_count = await conn.fetchval(
            "SELECT COUNT(*) FROM iocs WHERE tenant_id = $1::uuid", BARBAS_TENANT
        )
        print(f"[ADMIN] Total IOCs: {total}")
        print(f"[ADMIN] Barbas IOCs: {barbas_count}")
    set_platform_admin_mode(False)

    # Test 2: raw connection with barbas tenant context (simulates what middleware does)
    async with postgres_db.pool.acquire() as conn:
        await conn.execute(
            "SELECT set_config('app.current_tenant_id', $1, false)", BARBAS_TENANT
        )
        await conn.execute(
            "SELECT set_config('app.is_platform_admin', 'false', false)"
        )
        count = await conn.fetchval("SELECT COUNT(*) FROM iocs")
        print(f"\n[RAW CONN - barbas tenant] IOCs visible: {count}")

        if count > 0:
            row = await conn.fetchrow("SELECT ioc_value, ioc_type, tenant_id::text FROM iocs LIMIT 1")
            print(f"  Sample: value={row[0][:60]}, type={row[1]}, tenant={row[2]}")
        else:
            print("  No rows returned with barbas tenant context!")

    # Test 3: tenant_acquire with ContextVar set (what the actual middleware path does)
    from middleware.tenant_middleware import current_tenant_id
    token = current_tenant_id.set(BARBAS_TENANT)
    try:
        async with postgres_db.tenant_acquire() as conn:
            count = await conn.fetchval("SELECT COUNT(*) FROM iocs")
            print(f"\n[tenant_acquire + ContextVar] IOCs visible: {count}")

            if count > 0:
                row = await conn.fetchrow("SELECT ioc_value, ioc_type, tenant_id::text FROM iocs LIMIT 1")
                print(f"  Sample: value={row[0][:60]}, type={row[1]}, tenant={row[2]}")
            else:
                print("  No rows returned with tenant_acquire!")

                # Debug: check what set_config values are
                tid = await conn.fetchval("SELECT current_setting('app.current_tenant_id', true)")
                admin = await conn.fetchval("SELECT current_setting('app.is_platform_admin', true)")
                print(f"  Connection settings: tenant_id={tid}, is_admin={admin}")
    finally:
        current_tenant_id.reset(token)

    # Test 4: Check the RLS policy definition
    set_platform_admin_mode(True)
    async with postgres_db.tenant_acquire() as conn:
        policies = await conn.fetch("""
            SELECT polname, pg_get_expr(polqual, polrelid) as qual
            FROM pg_policy
            WHERE polrelid = 'iocs'::regclass
        """)
        print(f"\n[RLS POLICIES on iocs]")
        for p in policies:
            print(f"  {p['polname']}: {p['qual']}")
    set_platform_admin_mode(False)

asyncio.run(test())
