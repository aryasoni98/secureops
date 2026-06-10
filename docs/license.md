# Licensing

SecureOps licenses are Ed25519-signed keys issued by the SecureOps license
server (`crates/secureops-license-server`). Activation happens client-side; the
platform never phones home except for an optional heartbeat.

## Tiers

| Tier | Capabilities |
| --- | --- |
| `community` | Audit, hardening, monitors, kill switch - host-local only |
| `pro` | Adds: API, findings DB, attack-path graph, RL ranking |
| `enterprise` | Adds: SSO, signed IR export, bughunt, federated IOC, BYO model |

Capabilities are enforced via Cedar policy. Calling a higher-tier route with a
lower-tier token returns `403 Forbidden`.

## Getting a license (beta)

The host-local CLI (`community` tier: audit, hardening, monitors, kill switch)
needs **no license at all** - install and run.

For the platform API during the beta, mint a self-signed dev license and run
the API in dev mode:

```bash
# 1. Start the API accepting the built-in dev key (local only - never in production)
SECUREOPS_DEV_MODE=1 just api

# 2. Mint an enterprise-tier dev license (or: just dev-license)
secureops-license-server mint --dev --tenant my-team --tier enterprise --days 365

# 3. Activate it (returns a session JWT)
curl -X POST http://127.0.0.1:8080/api/v1/license/activate \
  -H 'content-type: application/json' -d '{"key":"<minted key>"}'
```

For production, mint with a real vendor key instead: set `SECUREOPS_SIGNING_KEY`
(base64url 32-byte Ed25519 seed), drop `--dev`, and configure the matching
`SECUREOPS_LICENSE_PUBKEY` on the API and license server.

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

To verify a key offline and print its claims:

```bash
secureops-license-server verify --key '<license key>'          # uses SECUREOPS_LICENSE_PUBKEY
secureops-license-server verify --dev --key '<license key>'    # against the built-in dev key
```
