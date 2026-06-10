# SecureOps Pen-Test Checklist (PRODUCT.md Phase 9 — GA gate)

Use this list before every tagged release. Every item must be reproducible by
an external pentester with only the public Helm chart and `cargo run`.

## 1. Input handling

- [ ] SQLi: `POST /findings?filter=' OR 1=1--` → `400` (handlers reject; sqlx is
      parameterized end-to-end; no `format!` builds SQL).
- [ ] Path traversal: `GET /evidence/../../../etc/passwd` → `400`. ServeDir
      strict-mode rejects parent traversals.
- [ ] Untrusted YAML: a hand-crafted playbook with billion-laughs / aliases is
      rejected (serde_yaml safe deserialization).

## 2. Authentication & session

- [ ] `Authorization: Bearer <jwt-alg-none>` → `401`. The `none` algorithm is
      explicitly blocked in `auth.rs`.
- [ ] Wrong HMAC key → `401`.
- [ ] Expired JWT → `401` with `WWW-Authenticate`.
- [ ] Per-tenant API key: stored as a SHA-256 hash; lookup is constant-time.

## 3. Authorization (Cedar policy)

- [ ] Community license requesting `bughunt` / `compliance` / `sso` →
      `403 Forbidden` (Cedar gate, not handler fallthrough).
- [ ] Tampered license signature → `403 invalid_signature`.
- [ ] Expired license → `403 license_expired`.

## 4. Network egress

- [ ] Outbound traffic from the daemon hits the allowlist proxy first; deny is
      fail-closed.
- [ ] SSRF: `POST /clouds` with `http://169.254.169.254/...` is rejected by the
      egress allowlist.

## 5. Secrets in telemetry

- [ ] `grep -RInE "password|api[_-]?key|secret|token" target/release` produces
      no matches inside compiled binaries' strings (per-binary cargo-auditable
      check).
- [ ] All `tracing` calls in the codebase use field redaction for sensitive
      values (`?token = "***"`).

## 6. Container surface

- [ ] No `CAP_SYS_ADMIN` outside the eBPF DaemonSet (`securityContext.capabilities`).
- [ ] Root filesystem is read-only; only `/data/openclaw` is mounted RW.
- [ ] User is `65532:65532` (distroless nonroot).

## 7. Supply chain

- [ ] `cargo deny check` exits 0 (no banned licenses, no RustSec advisories).
- [ ] `cargo audit` exits 0.
- [ ] CycloneDX SBOM enumerates all 18 workspace crates + transitives.
- [ ] `cosign verify ghcr.io/<org>/secureops:<tag>` → "Verified OK".

## 8. Upgrade safety

- [ ] `just platform-upgrade` under 100 req/s `k6` load: zero `5xx`, p99 < 500 ms.
- [ ] A broken migration produces a Helm-hook failure; the old version stays
      live.

## 9. Audit log integrity

- [ ] `audit_log` Postgres role lacks UPDATE/DELETE; attempting either fails
      with "permission denied".
- [ ] Exported incident ZIP carries an Ed25519 signature that verifies with the
      pubkey exposed via the `X-Export-Pubkey` header.
