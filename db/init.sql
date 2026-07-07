CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS approvals (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id TEXT NOT NULL,
  session_id TEXT NOT NULL,
  action TEXT NOT NULL,
  tool TEXT NOT NULL,
  context JSONB NOT NULL DEFAULT '{}'::jsonb,
  status TEXT NOT NULL CHECK (status IN ('pending', 'first_approved', 'approved', 'denied', 'consumed', 'expired')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  resolved_at TIMESTAMPTZ NULL,
  approver_id TEXT NULL,
  first_approver_id TEXT NULL,
  requester_id TEXT NULL,
  expires_at TIMESTAMPTZ NULL
);

CREATE INDEX IF NOT EXISTS approvals_tenant_status_created_idx
  ON approvals (tenant_id, status, created_at DESC);

CREATE INDEX IF NOT EXISTS approvals_pending_expiry_idx
  ON approvals (status, expires_at);

CREATE TABLE IF NOT EXISTS policy_exceptions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id TEXT NOT NULL,
  tool TEXT NOT NULL,
  context_match JSONB NOT NULL DEFAULT '{}'::jsonb,
  reason TEXT NULL,
  created_by TEXT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('active', 'expired', 'revoked'))
);

CREATE INDEX IF NOT EXISTS policy_exceptions_tenant_active_idx
  ON policy_exceptions (tenant_id, status, expires_at DESC);

CREATE INDEX IF NOT EXISTS policy_exceptions_active_expiry_idx
  ON policy_exceptions (status, expires_at);
