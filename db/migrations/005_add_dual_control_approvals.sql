ALTER TABLE approvals
  ADD COLUMN IF NOT EXISTS first_approver_id TEXT NULL;

ALTER TABLE approvals
  DROP CONSTRAINT IF EXISTS approvals_status_check;

ALTER TABLE approvals
  ADD CONSTRAINT approvals_status_check
  CHECK (status IN ('pending', 'first_approved', 'approved', 'denied', 'consumed', 'expired'));
