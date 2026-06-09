# Platform API

The HTTP API is generated from `utoipa` and served at `/api/v1/openapi.json`.
Below is a curated reference of the routes the dashboard + Justfile use most.

All routes require `Authorization: Bearer <token>` except `POST /license/activate`.
Tier-locked routes are gated through Cedar (Community → `403 Forbidden`).

## License & auth

| Method | Path | Description |
| --- | --- | --- |
| `POST` | `/api/v1/license/activate` | Verify an Ed25519 license + mint a JWT |
| `GET`  | `/api/v1/license` | Inspect the active license (tier + features) |
| `GET`  | `/api/v1/auth/oidc/metadata` | OIDC discovery (Enterprise) |
| `POST` | `/api/v1/auth/oidc/callback` | Exchange IdP token → SecureOps JWT |

## Scans + findings

| Method | Path | Description |
| --- | --- | --- |
| `POST` | `/api/v1/scans` | Queue a scan (`{scope: "aws"\|"gcp"\|"azure"\|"all"\|<id>}`) |
| `GET`  | `/api/v1/scans/{id}` | Fetch a scan |
| `GET`  | `/api/v1/findings` | List findings (RL-ranked) |
| `POST` | `/api/v1/findings/{id}/action` | Confirm / dismiss / escalate |
| `GET`  | `/api/v1/compliance/reports` | JSON / CSV / signed ZIP |

## Intelligence

| Method | Path | Description |
| --- | --- | --- |
| `POST` | `/api/v1/graph/rebuild` | Ingest a topology |
| `GET`  | `/api/v1/graph/paths` | Internet → sensitive attack paths |
| `GET`  | `/api/v1/graph/blast-radius/{node}` | Blast radius of a node |
| `POST` | `/api/v1/bughunt` | Queue a bug-hunt |
| `GET`  | `/api/v1/bughunt/{job_id}` | Result of a bug-hunt |

## Autonomy

| Method | Path | Description |
| --- | --- | --- |
| `GET`  | `/api/v1/remediations/queue` | HITL queue |
| `POST` | `/api/v1/remediations` | Queue a remediation |
| `POST` | `/api/v1/remediations/{id}/approve` | Approve + execute |
| `POST` | `/api/v1/remediations/{id}/deny` | Deny (no cloud call) |
| `POST` | `/api/v1/remediations/circuit/{class}/reset` | Reset a halted class |
| `GET`  | `/api/v1/rl/stats` | LinUCB telemetry |
| `POST` | `/api/v1/rl/feedback` | Train the ranker |

## WebSocket

| Path | Stream |
| --- | --- |
| `/ws/findings` | Finding inserts + status changes |
| `/ws/scan-progress` | Per-scan progress events |
| `/ws/remediation` | Queue + execution updates |
