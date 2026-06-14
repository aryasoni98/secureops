# SecureOps Rust - multi-stage image (CLI + Ring-2 daemon + platform API)
# Build context: repo root   (docker build -f deploy/docker/Dockerfile .)

# Latest stable Rust on Debian (aws-sdk deps currently need ≥1.91.1).
FROM rust:bookworm AS builder

WORKDIR /build
COPY . .
RUN cargo build --release -p secureops-cli -p secureops-daemon -p secureops-api -p secureops-license-server \
    && cargo build --release -p secureops-scanner --features aws

# -----------------------------------------------------------------------------

# Runtime base pinned by multi-arch index digest (resolved 2026-06-10) so a
# repository retag can never silently change what ships.
FROM debian:bookworm-slim@sha256:0104b334637a5f19aa9c983a91b54c89887c0984081f2068983107a6f6c21eeb AS runtime

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
