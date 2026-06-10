# Contributing to SecureOps

Issues, bug reports, and PRs are welcome.

## Quick start

1. Fork and branch from `master`.
2. Make your change; add tests for new behavior.
3. Keep the gate green before opening a PR:

   ```bash
   just ci
   # or, equivalently:
   cargo fmt --all --check
   cargo clippy --workspace -- -D warnings
   cargo test --workspace
   ```

4. For web changes, also run:

   ```bash
   cd web && npm ci && npm run build && npm test && npm run e2e
   ```

5. Open a PR describing the change and its rationale.

## Orientation

New to the codebase? Read in this order:

1. [PRODUCT.md](PRODUCT.md) - the architecture and phase plan (trust rings, PDP/PEP spine).
2. `crates/secureops-core` - the frozen type/scoring contract everything binds to.
3. [docs/RUNNING.md](docs/RUNNING.md) - hands-on workflows.
4. [DEFERRED.md](DEFERRED.md) - what intentionally needs external infrastructure and the trait seam each item plugs into.

## Ground rules

- **Keep the JSON wire format stable** with the `@aryasoni98/secureops` TypeScript tool (v2.2.0 reference). `secureops-core` types are frozen; changes there need strong justification.
- **MSRV**: host-local crates 1.80; `secureops-api` 1.82. Don't raise it casually.
- **Fail closed.** Enforcement-path code (proxy, sandbox, policy, kill switch) must treat every error as deny, never as an implicit allow.
- **No new panics in runtime paths.** `unwrap()`/`expect()` are fine in tests; daemon/API/CLI code paths return `Result`.
- **Insecure defaults only behind `SECUREOPS_DEV_MODE=1`.** Production binaries must refuse to start without real secrets.
- **Conventional commits** (`feat:`, `fix:`, `docs:`, `chore:` …) with a clear subject.
- Dependency caution: keep `cargo deny` clean; note the tree-sitter `cc < 1.1` cap before adding cc-heavy transitive deps.

## Reporting security issues

Do **not** open a public issue for vulnerabilities - see [SECURITY.md](SECURITY.md).
