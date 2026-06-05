-- 003_assets_identities — the inventory the graph (P6) and scanner build on.

CREATE TABLE IF NOT EXISTS assets (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   TEXT        NOT NULL,
    cloud       TEXT        NOT NULL,
    kind        TEXT        NOT NULL,          -- ec2 | s3 | rds | gke | ...
    external_id TEXT        NOT NULL,          -- provider-native id/arn
    tags        JSONB       NOT NULL DEFAULT '{}'::jsonb,
    exposed     BOOLEAN     NOT NULL DEFAULT false,  -- reachable from internet
    sensitive   BOOLEAN     NOT NULL DEFAULT false,  -- holds sensitive data
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, cloud, external_id)
);
CREATE INDEX IF NOT EXISTS idx_assets_tenant ON assets (tenant_id);

CREATE TABLE IF NOT EXISTS identities (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   TEXT        NOT NULL,
    cloud       TEXT        NOT NULL,
    principal   TEXT        NOT NULL,          -- role/user/sa principal id
    kind        TEXT        NOT NULL,          -- role | user | service_account
    permissions JSONB       NOT NULL DEFAULT '[]'::jsonb,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, cloud, principal)
);
CREATE INDEX IF NOT EXISTS idx_identities_tenant ON identities (tenant_id);
