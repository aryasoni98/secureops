-- 001_licenses - license activation + API-key auth (PRODUCT.md Phase 5).
-- Run by sqlx::migrate!("./migrations") in 5b.

CREATE TABLE IF NOT EXISTS licenses (
    lic_id      TEXT PRIMARY KEY,
    tenant_id   TEXT        NOT NULL,
    tier        TEXT        NOT NULL CHECK (tier IN ('community', 'pro', 'enterprise')),
    seats       INTEGER     NOT NULL DEFAULT 1,
    features    JSONB       NOT NULL DEFAULT '[]'::jsonb,
    issued      BIGINT      NOT NULL,
    expiry      BIGINT      NOT NULL,
    mode        TEXT        NOT NULL DEFAULT 'online',
    grace_days  INTEGER     NOT NULL DEFAULT 0,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_licenses_tenant ON licenses (tenant_id);

-- Per-tenant API keys, stored as SHA-256 hashes (never the raw key).
CREATE TABLE IF NOT EXISTS api_keys (
    key_hash    TEXT PRIMARY KEY,
    tenant_id   TEXT        NOT NULL,
    sub         TEXT        NOT NULL,
    tier        TEXT        NOT NULL,
    features    JSONB       NOT NULL DEFAULT '[]'::jsonb,
    revoked     BOOLEAN     NOT NULL DEFAULT false,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_api_keys_tenant ON api_keys (tenant_id);
