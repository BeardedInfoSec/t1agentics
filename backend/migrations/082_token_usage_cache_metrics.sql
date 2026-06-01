-- 082_token_usage_cache_metrics.sql
-- Add Anthropic prompt-caching columns to ai_token_usage so we can verify
-- caching is firing and measure actual cost savings.
--
-- cache_creation_input_tokens : tokens written into the cache (1.25× cost of input)
-- cache_read_input_tokens     : tokens read from cache (0.1× cost of input — 90% savings)

ALTER TABLE ai_token_usage
    ADD COLUMN IF NOT EXISTS cache_creation_tokens INTEGER NOT NULL DEFAULT 0;

ALTER TABLE ai_token_usage
    ADD COLUMN IF NOT EXISTS cache_read_tokens INTEGER NOT NULL DEFAULT 0;

-- Index to query cache-hit rate over time
CREATE INDEX IF NOT EXISTS idx_ai_token_usage_cache_read
    ON ai_token_usage (created_at DESC)
    WHERE cache_read_tokens > 0;
