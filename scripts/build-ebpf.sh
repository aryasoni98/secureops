#!/usr/bin/env bash
# Build the secureops-ebpf eBPF programs (Linux kernel-side, bpfel-unknown-none target).
# Run this on Linux before starting secureops-daemon with SECUREOPS_BPF_OBJ set.
#
# Usage: ./scripts/build-ebpf.sh [--release]
set -euo pipefail

RELEASE="${1:-}"
PROFILE="debug"
CARGO_FLAGS=""
if [[ "$RELEASE" == "--release" ]]; then
  PROFILE="release"
  CARGO_FLAGS="--release"
fi

# Install bpf-linker if missing.
if ! command -v bpf-linker &>/dev/null; then
  echo "Installing bpf-linker..."
  cargo install bpf-linker
fi

cd "$(dirname "$0")/../ebpf"

echo "Compiling eBPF programs (target: bpfel-unknown-none, profile: $PROFILE)..."
CARGO_TARGET_BPFEL_UNKNOWN_NONE_LINKER=bpf-linker \
  cargo build \
    --target bpfel-unknown-none \
    -Z build-std=core \
    $CARGO_FLAGS

OBJ="target/bpfel-unknown-none/${PROFILE}/secureops-ebpf"
echo "BPF object: $(realpath "$OBJ")"
echo ""
echo "Start the daemon with:"
echo "  SECUREOPS_BPF_OBJ=$(realpath "$OBJ") cargo run -p secureops-daemon"
