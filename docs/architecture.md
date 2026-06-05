# Architecture

## Trust rings (host tool)

- **Ring 0 — Untrusted:** the agent, LLM, skills, secrets. Assumed compromisable.
- **Ring 1 — Degraded trust:** in-process audit/monitor logic (CLI, N-API).
- **Ring 2 — Root of trust:** `secureops-daemon` — egress proxy (fail-closed),
  PDP, runtime monitors, kill switch, hash-chained Ed25519-signed audit log, and
  the eBPF kernel PEP (exfil-chain correlation; LSM-BPF inline deny on Linux).

## Platform services (Phase 5–8)

```
                 ┌────────── frontend net ──────────┐
   clients ──▶  ingress ──▶  secureops-api (axum)
                                  │  (backend net, internal)
        ┌─────────────┬───────────┼───────────┬──────────────┐
     Postgres       Redis       MinIO     otel-collector   (scanner worker)
   (sqlx/tokio-pg) (queue)   (evidence)    (traces)         (P6/P7)
```

The API composes the engine crates:

| Crate | Role |
|---|---|
| `secureops-graph` | security knowledge graph; attack-path Dijkstra; blast radius |
| `secureops-tokenbudget` | LLM context packing (knapsack + dedup/schema-ref/diff/map-reduce) |
| `secureops-bughunt` | bounded agentic LLM bug-hunt loop → strict `FindingReport` |
| `secureops-rl` | LinUCB finding ranking (Sherman-Morrison online updates) |
| `secureops-selfheal` | YAML self-healing playbooks (safe/reversible/destructive + HITL) |
| `secureops-license-server` | stateless Ed25519 license heartbeat/revoke |

## Build phases

`P0–P3` foundation + audit/harden + Ring-2 enforcement · `P4` eBPF kernel PEP ·
`P5` platform API + storage · `P6` intelligence engines · `P7` autonomy
(RL + self-heal) · `P8` enterprise (export/SSO/license-server/dashboard) ·
`P9` GA hardening (supply-chain, chaos, perf, docs).

## Dependency discipline

Pure-Rust, `cc`-light dependency choices throughout (tokio-postgres over sqlx;
hand-rolled SigV4 over aws-sdk; Sherman-Morrison over BLAS; stored-only ZIP) to
stay under `tree-sitter-javascript`'s `cc <1.1` cap — see `SECURITY.md` and the
inline pin in `crates/secureops-monitors/Cargo.toml`.
