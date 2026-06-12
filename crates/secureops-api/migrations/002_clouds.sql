-- 002_clouds - connected cloud accounts + (encrypted) LLM provider keys.

CREATE TABLE IF NOT EXISTS clouds (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   TEXT        NOT NULL,
    provider    TEXT        NOT NULL CHECK (provider IN ('aws', 'gcp', 'azure')),
    -- role_arn (aws) | sa_email (gcp) | client_id (azure)
    credential  TEXT        NOT NULL,
    display_name TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_clouds_tenant ON clouds (tenant_id);

-- BYO LLM keys, stored encrypted at rest (AES-GCM; key in the daemon keystore).
CREATE TABLE IF NOT EXISTS llm_keys (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     TEXT        NOT NULL,
    provider      TEXT        NOT NULL CHECK (provider IN ('openai', 'anthropic', 'local')),
    key_encrypted BYTEA       NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_llm_keys_tenant ON llm_keys (tenant_id);
