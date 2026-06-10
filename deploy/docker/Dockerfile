# SecureOps Rust — multi-stage image (CLI + Ring-2 daemon + platform API)
# Build context: repo root   (docker build -f deploy/docker/Dockerfile .)

# Pin the toolchain minor so image rebuilds are reproducible (MSRV: api crate 1.82).
FROM rust:1.85-bookworm AS builder

WORKDIR /build
COPY . .
RUN cargo build --release -p secureops-cli -p secureops-daemon -p secureops-api -p secureops-scanner -p secureops-license-server

# -----------------------------------------------------------------------------

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates tini \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/secureops /usr/local/bin/secureops
COPY --from=builder /build/target/release/secureops-daemon /usr/local/bin/secureops-daemon
COPY --from=builder /build/target/release/secureops-api /usr/local/bin/secureops-api
COPY --from=builder /build/target/release/secureops-scanner /usr/local/bin/secureops-scanner
COPY --from=builder /build/target/release/secureops-license-server /usr/local/bin/secureops-license-server

ENV OPENCLAW_STATE_DIR=/data/openclaw
RUN mkdir -p /data/openclaw && chown -R 65532:65532 /data/openclaw

USER 65532:65532
VOLUME ["/data/openclaw"]

# Default: long-running Ring-2 daemon (override for one-shot audit jobs)
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["secureops-daemon"]
