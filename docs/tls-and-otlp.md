# In-process TLS & OTLP trace export

Two optional, feature-gated capabilities for the platform API. Both are **off by
default** (the default build is unchanged and CI-lean); enable them at build time
with Cargo features and configure at runtime via env.

## TLS termination (`--features tls`)

Serve HTTPS directly from `secureops-api` (via `axum-server` + rustls, ring
crypto provider — no aws-lc/C build) instead of requiring an external TLS
terminator for single-binary deployments.

```bash
cargo build -p secureops-api --features tls --release
```

Runtime env:

| Var | Meaning |
|-----|---------|
| `SECUREOPS_TLS_CERT` | Path to the PEM certificate chain |
| `SECUREOPS_TLS_KEY`  | Path to the PEM private key |
| `SECUREOPS_API_ADDR` | Must be `ip:port` (e.g. `0.0.0.0:8443`) when TLS is on |

Behaviour:
- Both vars set → serves HTTPS, logs `listening on https://… (TLS terminated in-process)`.
- Feature built but vars unset → logs a warning and falls back to plain HTTP.
- Feature not built → plain HTTP (front with an ingress/mesh TLS terminator).

Local self-signed cert for testing:

```bash
openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem \
  -days 365 -subj "/CN=localhost"
SECUREOPS_TLS_CERT=cert.pem SECUREOPS_TLS_KEY=key.pem \
  SECUREOPS_API_ADDR=0.0.0.0:8443 secureops-api
```

> Defence in depth: even with in-process TLS, keep the API on a private network
> and terminate/observe TLS at the ingress where you can. This feature removes
> the *hard dependency* on an external terminator; it isn't a reason to expose
> the API directly to the internet.

## OTLP trace export (`--features otlp`)

Export tracing spans to an OpenTelemetry collector over **HTTP/protobuf** (no
tonic/gRPC, leaner dependency tree). Closes the gap where
`OTEL_EXPORTER_OTLP_ENDPOINT` was set in compose/Helm but nothing read it.

```bash
cargo build -p secureops-api --features otlp --release
```

Runtime env:

| Var | Meaning |
|-----|---------|
| `OTEL_EXPORTER_OTLP_ENDPOINT` | Collector base URL. **Use the HTTP port `:4318`** (the exporter appends `/v1/traces`), e.g. `http://otel-collector:4318`. |

The bundled collector (`deploy/docker/otel-collector.yaml`) already exposes the
OTLP HTTP receiver on `4318`; swap its `debug` exporter for a real backend
(Tempo/Jaeger/Honeycomb) in production. If the exporter fails to initialise the
API logs a warning and continues with stdout-only tracing (never fails to boot).

> Note: the `/metrics` Prometheus endpoint and per-request `TraceLayer` spans
> ship in the **default** build. The `otlp` feature adds span *export* on top.
