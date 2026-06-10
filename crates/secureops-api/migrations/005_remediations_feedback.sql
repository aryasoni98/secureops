-- 005_remediations_feedback — self-healing queue (P7) + RL feedback signal (P7).

CREATE TABLE IF NOT EXISTS remediations (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   TEXT        NOT NULL,
    -- TEXT (not a findings FK): the API accepts arbitrary external finding ids.
    finding_id  TEXT        NOT NULL,
    playbook    TEXT        NOT NULL,
    class       TEXT        NOT NULL CHECK (class IN ('safe', 'reversible', 'destructive')),
    state       TEXT        NOT NULL DEFAULT 'pending'
                CHECK (state IN ('pending', 'approved', 'denied', 'completed', 'rolled_back', 'aborted', 'failed')),
    approved_by TEXT,
    reason      TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_remediations_tenant_state ON remediations (tenant_id, state);

-- One row per analyst decision; feeds the LinUCB bandit's online update (P7).
CREATE TABLE IF NOT EXISTS rl_feedback (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   TEXT        NOT NULL,
    finding_id  TEXT        NOT NULL,
    action      TEXT        NOT NULL CHECK (action IN ('confirm', 'dismiss', 'escalate')),
    reward      DOUBLE PRECISION NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_rl_feedback_tenant ON rl_feedback (tenant_id);
