# Licensing

SecureOps licenses are Ed25519-signed JWTs issued by the SecureOps license
server (`tools/license-server/`). Activation happens client-side; the platform
never phones home except for an optional heartbeat.

## Tiers

| Tier | Capabilities |
| --- | --- |
| `community` | Audit, hardening, monitors, kill switch — host-local only |
| `pro` | Adds: API, findings DB, attack-path graph, RL ranking |
| `enterprise` | Adds: SSO, signed IR export, bughunt, federated IOC, BYO model |

Capabilities are enforced via Cedar policy. Calling a higher-tier route with a
lower-tier token returns `403 Forbidden`.

## Activating

```bash
curl -X POST http://127.0.0.1:8080/api/v1/license/activate \
  -H 'content-type: application/json' \
  -d '{"key":"-----BEGIN SECUREOPS LICENSE-----..."}'
```

The response carries `tier`, `expiry`, `features`, and a session JWT.

## License server

```bash
just license-server
```

| Method | Path | Description |
| --- | --- | --- |
| `POST` | `/heartbeat` | `{lic_id, instance_fingerprint, version}` → `{status, expiry}` |
| `POST` | `/revoke` | Admin-only revocation |

Set `SECUREOPS_ADMIN_KEY` to enable `/revoke`.

## Grace period

If the license API is unreachable, the platform stays operational for the
grace window declared in the license. After expiry, features degrade to
community-tier; ingest + audit continue.

## Verifying signatures

The pubkey is bundled into binaries at build time. To verify off-host:

```bash
secureops verify-license --key /path/to/key
```
