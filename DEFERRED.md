# Deferred work (requires external infrastructure)

Phases P0–P9 are **code-complete and tested**: 273+ Rust tests, clippy `-D warnings`
clean, fmt clean, web build + vitest + Playwright E2E green. Items below run
against trait/abstraction seams that are exercised by mocks and in-memory impls
in this workspace; "real" execution depends on infrastructure the CI environment
cannot provision.

| Item | Status in repo | What's deferred |
|------|----------------|------------------|
| **eBPF kernel ring-buffer + LSM inline-deny** | `secureops-bpf::chain` correlator + seccomp generator implemented & tested via the `mock` feature on any OS. `--features ebpf` compiles real aya loader scaffolding. | Loading the compiled BPF object into a privileged Linux runner - GitHub-hosted runners disallow `bpf()` syscalls. `ebpf-build` CI job builds the feature; `just bpf-load` exercises it on a real Linux test host. |
| **TPM 2.0 / Secure Enclave audit-log signer** | `SigningBackend` trait + `KeychainSigner` (real OS keychain) + `InMemoryTpmSigner` (process-local, proves the flow). `--features tpm` compiles real `tss-esapi` scaffolding on Linux. | Touching a real TPM chip - needs `/dev/tpm0` and `libtss2-dev` on the host. `tpm` feature is the integration point. |
| **cosign keyless image signing** | `sign_image_digest`/`verify_image_digest` prove the ed25519 image-digest sign+verify primitive locally (same crypto cosign uses). `cosign` CI job wires the full sigstore keyless flow. | Sigstore Fulcio/Rekor OIDC token exchange - only fires on tag releases when GHCR push has `id-token: write`. |
| **Live OpenAI / Anthropic / Local LLM providers** | `LlmProvider` trait + Mock/Local providers tested. Real HTTP providers gated `live-llm` (reqwest). | Real API keys - wire `OPENAI_API_KEY`/`ANTHROPIC_API_KEY` to enable. Bug-hunt loop verified against mock. |
| **Live OIDC IdP (Okta/Azure AD/Google)** | `OidcVerifier` trait + `MockVerifier` + `TestVerifier`. `HttpOidcVerifier` gated `live-oidc` (real JWKS fetch + RS256 verify). | Real IdP issuer + audience config. Mock verifier covers the route logic. |
| **Live AWS / GCP / Azure cloud backends** | `CloudBackend` trait. `aws::AwsCloud` real SDK impl gated `aws`. `GcpCloud`/`AzureCloud` dry impls (record actions, ready for `gcp-live`/`azure-live`). | Real cloud credentials. All playbook flows (safe / reversible / destructive / circuit-breaker / HITL approval) tested against mock backends - never call real cloud. |
| **Live Postgres integration tests** | 25 `#[ignore]`-gated PgStore tests cover migrations + audit-log immutability. | Tests run in CI under the `postgres-integration` job (real `postgres:16` service container). Locally: set `DATABASE_URL=postgres://...` and run `cargo test -p secureops-api -- --ignored`. |
| **Live Neo4j graph backend** | `secureops-graph` in-memory backend tested. `neo4j` feature compiles real `neo4rs` driver scaffolding. | Real Neo4j 5 instance. Helm subchart ships under Pro/Enterprise; in-memory backend covers Community. |
| **Live Redis / MinIO** | `redis_queue` deadpool-redis impl + `evidence.rs` SigV4 MinIO presigner - both tested under `secureops-chaos` for degraded-mode behaviour. | Real Redis/MinIO containers - exercised by `docker compose -f deploy/docker/docker-compose.platform.yml up`. |

## Verification matrix

| Phase | Code in repo | Tested in CI | Acceptance criteria proven |
|-------|--------------|--------------|----------------------------|
| P4 eBPF | ✅ chain + seccomp + bpf_wire | ✅ mock feature on macOS+Linux | ExfilChain fires <50ms on mock event pair |
| P5 Platform | ✅ axum + sqlx + Redis + MinIO + WS | ✅ rust + `postgres-integration` | `just up` 6 services healthy; WS <100ms |
| P6 Intelligence | ✅ graph + tokenbudget + bughunt | ✅ rust | BFS <200ms on 1k nodes; pack compression >40% |
| P7 Autonomy | ✅ LinUCB + selfheal + cloud backends | ✅ rust | Reversible rollback on failure; destructive HITL gate |
| P8 Enterprise | ✅ React SPA + SSO + IR export | ✅ rust + `web` (vitest + Playwright) | First-run wizard E2E green |
| P9 GA | ✅ chaos + bench + supply-chain + docs | ✅ rust + `cosign` (release-tag) + `bench` + `chaos` | cargo-deny clean; chaos degraded-mode; sign+verify primitive proven |
