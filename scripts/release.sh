#!/usr/bin/env bash
# Cut a SecureOps release: bump version, build/test gate, tag, push.
# Usage: ./scripts/release.sh <version>
# Example: ./scripts/release.sh 0.2.0
#
# This repo is the Rust workspace at its root. The npm shim
# (@aryasoni98/secureops) is released from its own repository.
set -euo pipefail

VERSION="${1:-}"
if [[ -z "$VERSION" ]]; then
  echo "Usage: $0 <version>  (e.g. 0.2.0)"
  exit 1
fi

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

echo "=== Releasing v$VERSION ==="

# 1. Verify working tree is clean.
if ! git diff --quiet || ! git diff --cached --quiet; then
  echo "ERROR: uncommitted changes. Commit or stash first."
  exit 1
fi

# 2. Bump workspace version ([workspace.package] version).
sed -i.bak "s/^version = \".*\"/version = \"$VERSION\"/" Cargo.toml
rm -f Cargo.toml.bak

# 2b. Keep inter-crate dependency versions in sync (crates.io requires a
#     version on every published dependency; these are pinned inline next to
#     `path = "..."`). Updates the version literal inside any secureops-* dep.
for f in Cargo.toml crates/*/Cargo.toml; do
  perl -i -pe 's/(secureops-[A-Za-z0-9_-]+\s*=\s*\{[^}]*version\s*=\s*")[0-9]+\.[0-9]+\.[0-9]+(")/${1}'"$VERSION"'${2}/g if /secureops-/' "$f"
done

# 3. Build + test gate (matches CI).
echo "--- Rust CI gate ---"
cargo build --workspace
cargo test --workspace
cargo clippy --workspace -- -D warnings
cargo fmt --all --check

# 4. Refresh Cargo.lock with the new version.
cargo generate-lockfile

# 5. Commit version bump.
git add Cargo.toml Cargo.lock crates/*/Cargo.toml
git commit -m "chore: release v$VERSION"

# 6. Tag.
git tag -a "v$VERSION" -m "SecureOps v$VERSION"

echo ""
echo "=== Release v$VERSION prepared ==="
echo ""
echo "Push to GitHub (creates the release + triggers publish workflows):"
echo "  git push origin master v$VERSION"
echo ""
echo "If 'origin' is not configured yet:"
echo "  git remote add origin https://github.com/aryasoni98/secureops.git"
echo "  git push --set-upstream origin master"
echo "  git push origin v$VERSION"
