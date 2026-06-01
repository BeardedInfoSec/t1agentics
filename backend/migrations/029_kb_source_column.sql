-- Migration 029: Add source column to knowledge_base for builtin content protection
-- Prevents subtenants from deleting seed/builtin KB articles

-- Add source column
ALTER TABLE knowledge_base ADD COLUMN IF NOT EXISTS source VARCHAR(20) DEFAULT 'user';

-- Mark all existing articles created by 'admin' or 'system' as builtin
UPDATE knowledge_base SET source = 'builtin' WHERE created_by IN ('admin', 'system');

-- Index for filtering
CREATE INDEX IF NOT EXISTS idx_kb_source ON knowledge_base(source);
