-- 004_findings - scan jobs + their findings (RL-ranked in P7, graphed in P6).

CREATE TABLE IF NOT EXISTS scans (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   TEXT        NOT NULL,
    scope       TEXT        NOT NULL,          -- all | aws | gcp | azure | <asset_id>
    kind        TEXT        NOT NULL DEFAULT 'scan',  -- scan | bughunt
    status      TEXT        NOT NULL DEFAULT 'queued'
                CHECK (status IN ('queued', 'running', 'completed', 'failed')),
    created_at  BIGINT      NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scans_tenant ON scans (tenant_id);

CREATE TABLE IF NOT EXISTS findings (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     TEXT        NOT NULL,
    scan_id       UUID        REFERENCES scans (id) ON DELETE SET NULL,
    title         TEXT        NOT NULL,
    severity      TEXT        NOT NULL
                  CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    status        TEXT        NOT NULL DEFAULT 'open'
                  CHECK (status IN ('open', 'confirmed', 'dismissed', 'escalated')),
    cloud         TEXT,
    blast_radius  BIGINT      NOT NULL DEFAULT 0,
    rl_score      DOUBLE PRECISION NOT NULL DEFAULT 0,  -- P7 ranking
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_findings_tenant_status ON findings (tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings (tenant_id, severity);
