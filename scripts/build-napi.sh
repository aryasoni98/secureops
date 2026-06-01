#!/usr/bin/env bash
# Build the secureops N-API Rust addon and copy it to the TS package.
# Requires Node 18+ (for napi-build) and Rust 1.77+.
#
# Usage: ./scripts/build-napi.sh [--release]
set -euo pipefail

RELEASE="${1:---release}"  # default to release for production use
PROFILE="release"
if [[ "$RELEASE" != "--release" ]]; then
  PROFILE="debug"
  RELEASE=""
fi

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

echo "Building secureops-napi (profile: $PROFILE)..."
cd "$REPO_ROOT/rust"
/opt/homebrew/bin/cargo build $RELEASE -p secureops-napi

# Determine addon filename per platform.
case "$(uname -s)" in
  Darwin) EXT="dylib" ;;
  Linux)  EXT="so"   ;;
  *)      echo "Unsupported platform: $(uname -s)" && exit 1 ;;
esac

SRC="target/${PROFILE}/libsecureops_napi.${EXT}"
DST="$REPO_ROOT/secureops/secureops.node"

cp "$SRC" "$DST"
echo "Addon copied to: $DST"
echo ""
echo "Load it in Node.js:"
echo '  const secureops = require("./secureops.node");'
echo '  const report    = await secureops.auditToJson(stateDir, false, false);'
