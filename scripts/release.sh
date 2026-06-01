#!/usr/bin/env bash
# Cut a SecureOps release: bump versions, tag, push.
# Usage: ./scripts/release.sh <version>
# Example: ./scripts/release.sh 3.0.0
set -euo pipefail

VERSION="${1:-}"
if [[ -z "$VERSION" ]]; then
  echo "Usage: $0 <version>  (e.g. 3.0.0)"
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

# 2. Bump workspace Cargo.toml version.
sed -i.bak "s/^version = \".*\"/version = \"$VERSION\"/" rust/Cargo.toml
rm -f rust/Cargo.toml.bak

# 3. Bump npm package version.
cd secureops
npm version "$VERSION" --no-git-tag-version
cd "$REPO_ROOT"

# 4. Build + test.
echo "--- Rust CI gate ---"
cd rust
/opt/homebrew/bin/cargo build --workspace
/opt/homebrew/bin/cargo test --workspace
/opt/homebrew/bin/cargo clippy --workspace -- -D warnings
/opt/homebrew/bin/cargo fmt --all --check
cd "$REPO_ROOT"

echo "--- TS CI gate ---"
cd secureops && npm run build && npm test && cd "$REPO_ROOT"

# 5. Update Cargo.lock.
cd rust && /opt/homebrew/bin/cargo generate-lockfile && cd "$REPO_ROOT"

# 6. Commit version bump.
git add rust/Cargo.toml rust/Cargo.lock secureops/package.json secureops/package-lock.json
git commit -m "chore: release v$VERSION"

# 7. Tag.
git tag -a "v$VERSION" -m "SecureOps v$VERSION"

echo ""
echo "=== Release v$VERSION prepared ==="
echo ""
echo "Push to GitHub (creates the release + triggers publish workflows):"
echo "  git push origin main v$VERSION"
echo ""
echo "Or push to a remote named 'origin' if not yet configured:"
echo "  git remote add origin https://github.com/adversa-ai/secureops.git"
echo "  git push --set-upstream origin main"
echo "  git push origin v$VERSION"
