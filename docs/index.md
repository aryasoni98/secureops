# SecureOps

Out-of-band security for AI agents **and** a self-hosted, AI-native multi-cloud
security platform.

- **Host tool (Rings 0–2):** `secureops` CLI + `secureops-daemon` — audit,
  harden, fail-closed egress proxy, runtime monitors, kill switch, signed log,
  and (Phase 4) the eBPF exfil-chain kernel PEP.
- **Platform (Phase 5–8):** `secureops-api` — license/auth/Cedar/WebSocket over
  Postgres + Redis + MinIO, with a knowledge graph, LLM bug-hunt, RL ranking,
  self-healing playbooks, signed incident export, SSO, and a license server.

See **[Architecture](architecture.md)** for the layout, **[Running locally](RUNNING.md)**
to start, and **[Deploy](DEPLOY_AWS_K8S.md)** for production.
