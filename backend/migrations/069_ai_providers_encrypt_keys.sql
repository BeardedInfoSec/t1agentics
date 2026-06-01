-- 069: Encrypt the legacy ai_providers.api_key column
--
-- The global ai_providers table (created back in the original "BYO from
-- the AI Workbench" era) has been storing api_key in plaintext. Now
-- that we have CredentialsVault Fernet helpers for the new per-tenant
-- tenant_ai_config.chat_api_key_encrypted column, retrofit the same
-- protection here.
--
-- Two-step migration to allow rollback:
--   069 (this file): add api_key_encrypted column. App startup runs a
--                    one-shot Python pass to encrypt any existing
--                    plaintext value into the new column.
--   (future)       : drop the plaintext column after one deploy cycle.
--
-- Reads transparently prefer encrypted; writes go only to encrypted.

ALTER TABLE ai_providers
    ADD COLUMN IF NOT EXISTS api_key_encrypted TEXT;
