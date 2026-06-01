-- Migration 052: Add auto-response toggle to connect instances
-- Allows Riggs to automatically execute recommended actions per-integration

ALTER TABLE connect_instances ADD COLUMN IF NOT EXISTS auto_response_enabled BOOLEAN NOT NULL DEFAULT false;
