-- 087: Keep alert resolved/closed timestamps consistent via a trigger
--
-- Different code paths close alerts and some only set one of status /
-- resolved_at / closed_at. Notably, alerts get resolved with resolved_at
-- set but closed_at left NULL, which zeroes out the dashboard's
-- resolution-time metrics (they key off closed_at).
--
-- This trigger stamps the missing lifecycle timestamps on the row no
-- matter which path writes it, so the data is always internally
-- consistent regardless of caller.

CREATE OR REPLACE FUNCTION alerts_stamp_lifecycle() RETURNS trigger AS $fn$
BEGIN
  IF NEW.status = 'resolved' AND NEW.resolved_at IS NULL THEN NEW.resolved_at := now(); END IF;
  IF NEW.status = 'closed' THEN
    IF NEW.closed_at  IS NULL THEN NEW.closed_at  := now(); END IF;
    IF NEW.resolved_at IS NULL THEN NEW.resolved_at := now(); END IF;
  END IF;
  RETURN NEW;
END; $fn$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_alerts_stamp_lifecycle ON alerts;
CREATE TRIGGER trg_alerts_stamp_lifecycle BEFORE INSERT OR UPDATE OF status, resolved_at, closed_at ON alerts FOR EACH ROW EXECUTE FUNCTION alerts_stamp_lifecycle();
