-- 067: Per-tenant BYO LLM configuration
--
-- T1 historically supported BYO models with clustering/load balancing.
-- When the platform went hosted on Anthropic, we collapsed onto a single
-- platform key with shared quota + a daily kill switch. This table
-- restores BYO as an opt-in: when a tenant is allowed AND enabled AND
-- has a key, their calls use their own provider and bypass platform
-- quota / kill-switch.
--
-- Two scoped flags:
--   byo_allowed - written by platform admin (T1) only
--   byo_enabled - written by tenant admin (the customer)
-- Both must be true for BYO to take effect.
--
-- Chat and embeddings configure independently — a tenant can BYO chat
-- while leaving embeddings on the platform default.

CREATE TABLE IF NOT EXISTS tenant_ai_config (
    tenant_id                       UUID PRIMARY KEY,
    byo_allowed                     BOOLEAN NOT NULL DEFAULT FALSE,
    byo_enabled                     BOOLEAN NOT NULL DEFAULT FALSE,

    -- Chat / triage provider
    chat_provider                   TEXT CHECK (chat_provider IS NULL OR chat_provider IN ('anthropic','openai','self_hosted')),
    chat_api_key_encrypted          TEXT,
    chat_model                      TEXT,
    chat_base_url                   TEXT,
    chat_api_style                  TEXT CHECK (chat_api_style IS NULL OR chat_api_style IN ('anthropic','openai')),

    -- Embeddings provider (separate, optional)
    embed_provider                  TEXT CHECK (embed_provider IS NULL OR embed_provider IN ('openai','self_hosted','disabled')),
    embed_api_key_encrypted         TEXT,
    embed_model                     TEXT,
    embed_base_url                  TEXT,
    embed_dimensions                INT,

    last_validated_at               TIMESTAMPTZ,
    last_validation_error           TEXT,
    updated_at                      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by                      UUID
);

ALTER TABLE tenant_ai_config ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_ai_config_isolation ON tenant_ai_config;
CREATE POLICY tenant_ai_config_isolation ON tenant_ai_config
    USING      (tenant_id = current_setting('app.current_tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::uuid);

DROP POLICY IF EXISTS tenant_ai_config_platform_admin_bypass ON tenant_ai_config;
CREATE POLICY tenant_ai_config_platform_admin_bypass ON tenant_ai_config
    USING      (current_setting('app.is_platform_admin', true) = 'true')
    WITH CHECK (current_setting('app.is_platform_admin', true) = 'true');
