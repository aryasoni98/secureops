-- 006_usage_audit — LLM token/cost usage + the tamper-evident, APPEND-ONLY
-- audit log (PRODUCT.md Phase 5 LAW ⑤: REVOKE UPDATE, DELETE on every mutation).

CREATE TABLE IF NOT EXISTS usage (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   TEXT        NOT NULL,
    provider    TEXT        NOT NULL,
    tokens_in   BIGINT      NOT NULL DEFAULT 0,
    tokens_out  BIGINT      NOT NULL DEFAULT 0,
    cost_cents  BIGINT      NOT NULL DEFAULT 0,
    ts          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_usage_tenant_ts ON usage (tenant_id, ts);

-- Hash-chained audit log. Each row commits to its predecessor (prev_hash) so any
-- edit/delete breaks the chain. Mirrors the daemon's signed log (secureops-auditlog).
CREATE TABLE IF NOT EXISTS audit_log (
    seq         BIGSERIAL PRIMARY KEY,
    tenant_id   TEXT        NOT NULL,
    ts          TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor       TEXT        NOT NULL,
    action      TEXT        NOT NULL,
    before      JSONB,
    after       JSONB,
    prev_hash   TEXT        NOT NULL,
    hash        TEXT        NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_log_tenant_ts ON audit_log (tenant_id, ts);

-- Enforce append-only at the database: the application role may INSERT/SELECT
-- but can NEVER mutate history. Revoked from PUBLIC and from the app role if it
-- exists (provisioned by the operator / Helm pre-install job).
REVOKE UPDATE, DELETE, TRUNCATE ON audit_log FROM PUBLIC;
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'secureops_app') THEN
        REVOKE UPDATE, DELETE, TRUNCATE ON audit_log FROM secureops_app;
        GRANT INSERT, SELECT ON audit_log TO secureops_app;
        GRANT USAGE, SELECT ON SEQUENCE audit_log_seq_seq TO secureops_app;
    END IF;
END
$$;
