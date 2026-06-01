-- Migration: 009_enable_semantic_search
-- Description: Enable pgvector extension and add embedding column for semantic search
-- Date: 2026-02-03
--
-- Purpose: Add vector similarity search to knowledge base for better AI-powered recommendations

-- Enable pgvector extension for vector operations
CREATE EXTENSION IF NOT EXISTS vector;

-- Add embedding column to knowledge_base table (OpenAI ada-002 uses 1536 dimensions)
ALTER TABLE knowledge_base ADD COLUMN IF NOT EXISTS embedding VECTOR(1536);

-- Create HNSW index for fast similarity search
-- HNSW (Hierarchical Navigable Small World) is optimized for high-dimensional vectors
CREATE INDEX IF NOT EXISTS idx_kb_embedding_hnsw ON knowledge_base
    USING hnsw (embedding vector_cosine_ops)
    WITH (m = 16, ef_construction = 64);

-- Alternative: IVFFlat index (faster build, slightly slower search)
-- Uncomment if HNSW index build is too slow:
-- CREATE INDEX IF NOT EXISTS idx_kb_embedding_ivfflat ON knowledge_base
--     USING ivfflat (embedding vector_cosine_ops)
--     WITH (lists = 100);

-- Add index on ai_processed for filtering entries that need embeddings
CREATE INDEX IF NOT EXISTS idx_kb_ai_processed ON knowledge_base(ai_processed) WHERE ai_processed = false;

-- Function to find similar KB entries by embedding
-- Usage: SELECT * FROM find_similar_kb_entries(query_embedding, limit);
CREATE OR REPLACE FUNCTION find_similar_kb_entries(
    query_embedding VECTOR(1536),
    result_limit INT DEFAULT 10,
    min_similarity FLOAT DEFAULT 0.7
)
RETURNS TABLE (
    kb_id VARCHAR(20),
    title VARCHAR(500),
    content_type VARCHAR(50),
    category VARCHAR(100),
    similarity FLOAT
) AS $$
BEGIN
    RETURN QUERY
    SELECT
        kb.kb_id,
        kb.title,
        kb.content_type,
        kb.category,
        1 - (kb.embedding <=> query_embedding) AS similarity
    FROM knowledge_base kb
    WHERE kb.is_active = TRUE
        AND kb.embedding IS NOT NULL
        AND (1 - (kb.embedding <=> query_embedding)) >= min_similarity
    ORDER BY kb.embedding <=> query_embedding
    LIMIT result_limit;
END;
$$ LANGUAGE plpgsql STABLE;

-- Function to batch update embeddings for existing entries (run once after migration)
-- This will be called from Python to populate embeddings for existing KB entries
CREATE OR REPLACE FUNCTION get_kb_entries_without_embeddings(batch_size INT DEFAULT 100)
RETURNS TABLE (
    kb_id VARCHAR(20),
    title VARCHAR(500),
    content TEXT
) AS $$
BEGIN
    RETURN QUERY
    SELECT
        kb.kb_id,
        kb.title,
        kb.content
    FROM knowledge_base kb
    WHERE kb.embedding IS NULL
        AND kb.is_active = TRUE
    ORDER BY kb.created_at DESC
    LIMIT batch_size;
END;
$$ LANGUAGE plpgsql STABLE;

COMMENT ON COLUMN knowledge_base.embedding IS 'OpenAI text-embedding-ada-002 vector (1536 dimensions) for semantic similarity search';
COMMENT ON INDEX idx_kb_embedding_hnsw IS 'HNSW index for fast cosine similarity search on KB embeddings';
COMMENT ON FUNCTION find_similar_kb_entries IS 'Find knowledge base entries semantically similar to a query embedding';
COMMENT ON FUNCTION get_kb_entries_without_embeddings IS 'Get batch of KB entries that need embeddings generated';
