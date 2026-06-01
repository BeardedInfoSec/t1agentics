-- 076: Track acknowledgment timestamp on investigations for Response SLA
--
-- The Response SLA on the SOC dashboard measures the time between an
-- investigation being created and an analyst acknowledging it (taking
-- ownership / moving it out of NEW). We previously had no clean signal —
-- assigned_at is the closest proxy but is overloaded with reassignments,
-- and updated_at moves on every field touch.
--
-- A dedicated column lets us:
--   1. Stamp the first human/AI acknowledgment exactly once.
--   2. Backfill from assigned_at so existing investigations still have data.
--   3. Decouple the SLA from assignment semantics if they change later.

ALTER TABLE investigations
    ADD COLUMN IF NOT EXISTS acknowledged_at TIMESTAMP WITH TIME ZONE;

-- Backfill: for already-assigned investigations, treat the first assignment
-- as the acknowledgment. For investigations that skipped straight to a
-- terminal state without assignment (auto-resolved by Riggs), use
-- completed_at as a best-effort ack timestamp.
UPDATE investigations
   SET acknowledged_at = COALESCE(assigned_at, completed_at)
 WHERE acknowledged_at IS NULL
   AND (assigned_at IS NOT NULL OR completed_at IS NOT NULL);

CREATE INDEX IF NOT EXISTS idx_investigations_acknowledged_at
    ON investigations(acknowledged_at) WHERE acknowledged_at IS NOT NULL;

-- Backfill alert.closed_at from the linked investigation's completed_at for
-- alerts that were "resolved" via the runtime status-sync path (which never
-- wrote closed_at). Without this, the SecurityQueue SLA calc falls back to
-- updated_at and falsely flags fast-closed items as breached as the row
-- gets touched by enrichment, dedup, etc.
UPDATE alerts a
   SET closed_at = i.completed_at
  FROM investigations i
 WHERE a.investigation_id = i.id
   AND a.closed_at IS NULL
   AND i.completed_at IS NOT NULL
   AND (i.state IN ('CLOSED', 'RESOLVED')
        OR i.disposition IN ('FALSE_POSITIVE', 'TRUE_POSITIVE', 'MALICIOUS', 'BENIGN'));

-- For closed investigations that somehow never got completed_at stamped
-- (older code paths), use updated_at as the best-available close timestamp.
-- Imperfect, but stops the SLA from drifting forward forever.
UPDATE investigations
   SET completed_at = updated_at
 WHERE state IN ('CLOSED', 'RESOLVED')
   AND completed_at IS NULL
   AND updated_at IS NOT NULL;
