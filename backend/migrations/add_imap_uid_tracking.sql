-- Add UID-based tracking to inbound_mailboxes for reliable email polling
-- Replaces UNSEEN-based search which misses emails read during outages
ALTER TABLE inbound_mailboxes ADD COLUMN IF NOT EXISTS last_uid_synced BIGINT DEFAULT 0;
