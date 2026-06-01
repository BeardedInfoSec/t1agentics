-- Migration: Add investigation_id to alert_attachments for investigation-scoped uploads
-- Copyright (c) 2024-2026 T1 Agentics LLC. SPDX-License-Identifier: Apache-2.0

ALTER TABLE alert_attachments ADD COLUMN IF NOT EXISTS investigation_id VARCHAR(255) REFERENCES investigations(investigation_id) ON DELETE CASCADE;
ALTER TABLE alert_attachments ALTER COLUMN alert_id DROP NOT NULL;
CREATE INDEX IF NOT EXISTS idx_attachments_investigation ON alert_attachments(investigation_id);
