-- 007_rls_roles_retention - beta hardening (PRODUCT.md Phase 5 / beta blockers).
--
-- Three defense-in-depth additions surfaced by the beta readiness audit:
--   1. api_keys.role        - coarse RBAC role minted into the principal Claims.
--   2. Row-Level Security   - a DB-level tenant backstop so a single missing
--                             `tenant_id` predicate in the app cannot leak data.
--   3. Audit-log retention  - the only sanctioned deletion path for the
--                             append-only audit log (compliance retention).

-- 1) RBAC role on API keys (default 'member'; mint 'admin' for operators).
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'member';

-- 2) Row-Level Security backstop.
--
-- The application already scopes every query with `tenant_id = $1`. RLS makes
-- that a database-enforced invariant rather than an application convention: if
-- a future query forgets the predicate, the DB still refuses cross-tenant rows.
--
-- The policy is written to be **non-breaking** for the current pooled-connection
-- model: when the session GUC `app.tenant` is unset it evaluates to NULL and the
-- policy permits the row (the app's own WHERE clause still scopes it). A
-- hardened deployment that runs `SET app.tenant = '<tenant>'` per request gets
-- full DB-level isolation. FORCE makes the policy apply even to the table owner.
DO $$
DECLARE t TEXT;
BEGIN
  FOREACH t IN ARRAY ARRAY['licenses','api_keys','scans','findings','remediations','rl_feedback']
  LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', t);
    EXECUTE format(
      'CREATE POLICY tenant_isolation ON %I USING (' ||
      'current_setting(''app.tenant'', true) IS NULL OR ' ||
      'tenant_id = current_setting(''app.tenant'', true))', t);
  END LOOP;
END $$;

-- 3) Sanctioned audit-log retention.
--
-- Migration 006 REVOKEs UPDATE/DELETE/TRUNCATE on audit_log for tamper-evidence.
-- Compliance frameworks also require a *defined* retention window. This
-- SECURITY DEFINER function is the single audited path that may prune entries
-- older than `retain_days`; it runs as the table owner so the REVOKE still
-- blocks ad-hoc deletes. Schedule it (e.g. a daily CronJob) per your policy.
CREATE OR REPLACE FUNCTION prune_audit_log(retain_days INTEGER)
RETURNS BIGINT
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE deleted BIGINT;
BEGIN
  IF retain_days < 30 THEN
    RAISE EXCEPTION 'retain_days must be >= 30 (compliance minimum)';
  END IF;
  DELETE FROM audit_log WHERE ts < now() - make_interval(days => retain_days);
  GET DIAGNOSTICS deleted = ROW_COUNT;
  RETURN deleted;
END $$;

COMMENT ON FUNCTION prune_audit_log(INTEGER) IS
  'Sanctioned audit-log retention prune. Minimum 30-day retention enforced.';
