# Security

## Reporting a vulnerability

Email security findings to **security@adversa.ai** (or open a private GitHub
Security Advisory). Please do not file public issues for undisclosed
vulnerabilities. We aim to acknowledge within 48 hours.

## Pen-test checklist (PRODUCT.md Phase 9)

Status of the baseline application-security controls. "Test" = an automated test
asserts the control; "Design" = enforced structurally; "P8b/CI" = lands with that work.

| # | Risk | Control | Status |
|---|------|---------|--------|
| 1 | **SQL injection** | All DB access is parameterized (`$1` placeholders in `secureops-api::store::pg`); no string-built SQL, no `query!` interpolation | Design + gated PG tests |
| 2 | **JWT `alg:none` / forgery** | `jsonwebtoken::Validation` pins HS256; `alg:none` and wrong-key tokens rejected | **Test** (`auth::jwt_alg_none_rejected`, `api_http`) |
| 3 | **AuthZ bypass / tier escalation** | Cedar gates every tier-locked capability; default-deny | **Test** (`authz`, `api_http`, `intel_http`) |
| 4 | **Missing auth** | `Authenticated` extractor → `401` + `WWW-Authenticate` on every protected route | **Test** (`api_http`) |
| 5 | **License forgery / tamper** | Ed25519 verification; tampered/expired/wrong-key rejected | **Test** (`license`, `export`, license-server) |
| 6 | **Tamper-evident audit** | `audit_log` is append-only at the DB (`REVOKE UPDATE, DELETE, TRUNCATE`, migration 006); daemon log is hash-chained + Ed25519-signed | Design (migration) |
| 7 | **Secrets at rest / in logs** | API keys stored as SHA-256 hashes; LLM keys `BYTEA` encrypted; no secret fields logged | Design + **test** (`api_key_hash_is_stable_and_not_plaintext`) |
| 8 | **SSRF / arbitrary egress** | Ring-2 egress proxy is fail-closed allowlist; cloud remediation defaults to `NoopCloud` (no real mutation) | Design |
| 9 | **Destructive remediation w/o approval** | Destructive playbooks never call the cloud without `Approval::Approved` | **Test** (`selfheal`, `intel_http`) |
| 10 | **Runaway LLM loop / cost** | Bug-hunt loop bounded (`max_depth`, `max_tool_calls`); `TokenBudget` caps context | **Test** (`bughunt`) |
| 11 | **Resilience / DoS via dep outage** | DB down → `503 + Retry-After` (no panic); Redis down → degraded enqueue | **Test** (`chaos_http`) |
| 12 | **Container escape** | Restricted PodSecurityStandard; `drop: ["ALL"]`, `readOnlyRootFilesystem`, `runAsNonRoot`; only `bpf-agent` adds `BPF/NET_RAW/SYS_ADMIN` | Design (Helm) |
| 13 | **Signed export integrity** | Incident ZIP is Ed25519-signed; verify with `X-Export-Pubkey` | **Test** (`export`, `enterprise_http`) |
| 14 | **Supply chain** | `cargo-deny` (licenses/bans/advisories) + `cargo-audit` + CycloneDX SBOM + cosign image signing | CI (`supply-chain.yml`, `release.yml`) |
| 15 | **Path traversal (SPA static)** | SPA served via `tower-http::ServeDir` with canonicalization | P8b |

## Hardening notes

- The host-local crates keep `#![forbid(unsafe_code)]`.
- No TLS-terminating crypto is hand-rolled; transit TLS is fronted by the
  ingress/load balancer (the API speaks plaintext on the backend network only).
- The `libsqlite3-sys` pin (`crates/secureops-monitors`) is a supply-chain
  decision, documented inline.
