-- Migration: 064_pgvector_kb_embeddings
-- Description: Enable pgvector + add embedding column / HNSW index to knowledge_base
-- Date: 2026-05-11
--
-- Requires postgres image with pgvector available (pgvector/pgvector:pg15).
-- If the extension is unavailable, the runner logs the failure and FTS fallback
-- continues to serve semantic search calls.

CREATE EXTENSION IF NOT EXISTS vector;

-- 1536 = OpenAI text-embedding-3-small. knowledge_base_service.py uses this
-- model as primary; rows without an embedding stay NULL and the search path
-- transparently falls back to to_tsvector FTS.
ALTER TABLE knowledge_base
    ADD COLUMN IF NOT EXISTS embedding VECTOR(1536);

CREATE INDEX IF NOT EXISTS idx_kb_embedding_hnsw
    ON knowledge_base
    USING hnsw (embedding vector_cosine_ops)
    WITH (m = 16, ef_construction = 64);

-- Helps the backfill script find unembedded rows quickly.
CREATE INDEX IF NOT EXISTS idx_kb_embedding_missing
    ON knowledge_base (kb_id)
    WHERE embedding IS NULL AND is_active = TRUE;
