ALTER TABLE approvals
  ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ;

ALTER TABLE approvals
  DROP CONSTRAINT IF EXISTS approvals_status_check;

ALTER TABLE approvals
  ADD CONSTRAINT approvals_status_check
  CHECK (status IN ('pending', 'approved', 'denied', 'consumed', 'expired'));

CREATE INDEX IF NOT EXISTS approvals_pending_expiry_idx
  ON approvals (status, expires_at);
