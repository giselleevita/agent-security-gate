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
