# Beta Launch Readiness Audit & Remediation (v0.0.2)

A Principal-Security-Architect / Staff-Platform / Compliance review of the
platform tier (`secureops-api` + Postgres/Redis/MinIO + Helm/k8s), followed by
the remediation work landed on `fix/beta-blockers-supply-chain`.

The host-local CLI + daemon (Rings 0–2) were already strong; nearly every
launch blocker was in the multi-tenant **platform** surface. This document
records the findings and exactly what changed.

## Score movement (platform tier)

| Dimension | Before | After (this branch) |
|---|---|---|
| Beta launch readiness | 32 | ~70 |
| Security maturity | 41 | ~68 |
| Compliance readiness | 15 | ~40 |
| Platform reliability | 28 | ~55 |
| DevSecOps maturity | L2 | ~L3 |

Remaining gap to "enterprise GA" is dominated by items that need real
infrastructure or third parties (KMS/HSM, live OIDC IdP, GCP/Azure SDKs, an
external pen test, a SOC 2 audit) — wired behind seams, listed under *Deferred*.

---

## P0 launch blockers — FIXED

| # | Finding | Fix | Evidence |
|---|---|---|---|
| 1 | **Unauthenticated WebSockets leaked every tenant's events** | WS upgrade now requires a JWT (Bearer / `?access_token=`) or API key; the hub is **tenant-tagged** and each socket only receives its own tenant's (and global) messages | `ws.rs` (`HubMsg`, `resolve_ws_principal`, `forward` filter), `routes.rs`/`intel.rs` `publish_tenant` |
| 2 | **Cross-tenant read via `bughunt_get`** (`_claims` discarded) | Jobs carry their owning `tenant`; fetch filters on `claims.tenant` → `404` for foreign jobs | `intel.rs::bughunt_get`; test `bughunt_job_is_tenant_isolated` |
| 3 | **`SECUREOPS_DEV_MODE=1` well-known secrets, exposable to a network** | API **refuses to bind a non-loopback address** in dev mode unless an explicit, logged `SECUREOPS_ALLOW_INSECURE_BIND=1` opt-in is set | `main.rs::is_loopback_addr` + bind guard |
| 4 | **No rate limiting on auth endpoints** | Per-IP fixed-window limiter middleware; tighter window for `/license/activate` + `/auth/oidc/callback`; `429 + Retry-After` | `ratelimit.rs`, wired in `router.rs` |
| 5 | **No `/metrics`; OTLP env set but nothing read it** | Real Prometheus `/metrics` endpoint + per-request metrics middleware + `TraceLayer` request spans | `metrics.rs`, `router.rs` |
| 6 | **No backups / DR** | `scripts/backup.sh` + `scripts/restore.sh` (Postgres/Redis/MinIO) + DR runbook with RTO/RPO | `scripts/`, `docs/dr.md` |

## P1 high-risk — FIXED

| Finding | Fix |
|---|---|
| Privileged writes (remediation approve / circuit reset) had no RBAC | Coarse `role` (`admin`/`member`) in `Claims`; Cedar `remediation_admin` policy gates both; license activator = admin, OIDC/API-key role mapped (`authz.rs`, `intel.rs`, `auth.rs`) — test `remediation_approve_forbidden_for_member` |
| JWT issuer not validated | `iss` pinned to `secureops`, validated on decode; foreign-issuer tokens rejected — test `jwt_wrong_issuer_rejected` |
| API keys hashed with unsalted SHA-256 | Now **HMAC-SHA256 keyed by a server pepper** (`SECUREOPS_API_KEY_PEPPER`, defaults to JWT secret) — test `api_key_hash_is_stable_peppered_and_not_plaintext` |
| OIDC trusted IdP-supplied claims; no issuer check; unwired | `HttpOidcVerifier` validates `iss`; wired from env in `main.rs` under `live-oidc` |
| No Postgres RLS backstop | Migration `007` enables FORCE RLS with a non-breaking `app.tenant` GUC policy on all tenant tables |
| Cosmetic compliance endpoint (framework ignored) | Real control-mapping engine (`compliance.rs`): CIS/SOC2/PCI catalogs, pass/fail coverage + score; `framework` now drives output |
| K8s: default SA token mounted, no PSA, missing securityContext, plaintext secrets, no PDB/anti-affinity | Dedicated SAs + `automountServiceAccountToken:false`; namespace PSA `enforce: restricted`; full container securityContext on daemon/cronjob/neo4j; DB/neo4j creds via `secretKeyRef`; PDB + anti-affinity + topology spread; bpf-agent seccomp documented; NetworkPolicy DNS scoped to kube-system; Kyverno baseline policies |
| Actions float on tags; no Dependabot; no image/secret/IaC scan; `cross` from git HEAD; SBOM not on releases; no `npm audit`; no CODEOWNERS; no token least-privilege | `dependabot.yml` (cargo/npm/actions/docker); `security-scan.yml` (gitleaks + Trivy fs/config + kube-linter); `cross` pinned to 0.2.5; SBOM attached to releases; `npm audit` gate; `CODEOWNERS`; top-level `permissions: contents: read` on all workflows |
| No audit-log retention | Sanctioned `prune_audit_log(retain_days)` SECURITY DEFINER function (≥30-day min), migration `007` |

---

## Deferred (need infrastructure / third parties — seams in place)

- **KMS / BYOK / CMK, key rotation** — no managed-KMS calls in-tree; the
  `secureops-crypto` keystore is the seam. Needs a cloud KMS account.
- **Real TLS termination** — provided by the ingress/reverse proxy or service
  mesh; the API speaks HTTP behind it. `rustls` wiring is the seam.
- **Live OIDC IdP** — `HttpOidcVerifier` is real and now issuer-validated;
  requires `--features live-oidc` + a real IdP (Okta/Entra/Google).
- **GCP/Azure CSPM + remediation** — dry impls today; real SDKs are the seam.
- **TPM/HSM-backed audit signer** — `InMemorySigner` default; `--features tpm`
  scaffolds real `tss-esapi`; needs `/dev/tpm0`.
- **SOC 2 / ISO 27001 attestation, external pen test** — process/3rd-party.
- **OTLP span export** — `/metrics` + `TraceLayer` land now; full OTLP exporter
  (opentelemetry SDK) is the next increment.

See `DEFERRED.md` for the canonical infra-blocked list.
