#!/usr/bin/env bash
# Rename the repo directory from secureclaw → secureops.
# Run from the PARENT of the repo dir, not inside it.
#
# Usage: cd ~/Documents/opensource && bash secureclaw/scripts/rename-repo.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OLD_DIR="$(dirname "$SCRIPT_DIR")"         # …/opensource/secureclaw
PARENT="$(dirname "$OLD_DIR")"             # …/opensource
OLD_NAME="$(basename "$OLD_DIR")"          # secureclaw
NEW_NAME="secureops"

if [[ "$OLD_NAME" == "$NEW_NAME" ]]; then
  echo "Already renamed to $NEW_NAME. Nothing to do."
  exit 0
fi

NEW_DIR="$PARENT/$NEW_NAME"

if [[ -e "$NEW_DIR" ]]; then
  echo "ERROR: $NEW_DIR already exists. Remove it first."
  exit 1
fi

echo "Renaming $OLD_DIR → $NEW_DIR"
mv "$OLD_DIR" "$NEW_DIR"

echo ""
echo "Done. Update your shell session:"
echo "  cd $NEW_DIR"
echo ""
echo "If you have Claude Code open, restart it or run:"
echo "  cd $NEW_DIR"
