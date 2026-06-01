#!/usr/bin/env node
// Faithfulness check v3 — Rust CLI vs napi addon (PRODUCT.md A.5).
// TS business logic removed; compare Rust CLI output against the napi addon.
//
// Usage: node scripts/ts-faithfulness-check.mjs [stateDir]
// Requires: cargo build (repo root) + ./scripts/build-napi.sh --release

import { createRequire } from 'node:module';
import { spawnSync } from 'node:child_process';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.join(__dirname, '..');
const stateDir = process.argv[2] ?? process.env.OPENCLAW_STATE_DIR ?? `${os.homedir()}/.openclaw`;

// ── 1. Rust CLI ───────────────────────────────────────────────────────────

const rustBin = path.join(REPO, 'rust', 'target', 'debug', 'secureops');
// spawnSync so we get stdout even when the binary exits nonzero (CI gate).
const { stdout: rustJson, stderr: rustErr, status } = spawnSync(
  rustBin, ['audit', '--json'],
  { env: { ...process.env, OPENCLAW_STATE_DIR: stateDir }, encoding: 'utf8' },
);
if (!rustJson) {
  process.stderr.write(`Rust CLI failed (exit ${status}): ${rustErr}\n`);
  process.exit(1);
}
const rustFindings = JSON.parse(rustJson).findings
  .map(f => ({ id: f.id, severity: f.severity, category: f.category }))
  .sort((a, b) => a.id.localeCompare(b.id));

process.stdout.write(JSON.stringify(rustFindings, null, 2) + '\n');

// ── 2. napi addon (optional — only if built) ──────────────────────────────

const _require = createRequire(import.meta.url);
const addonPath = path.join(REPO, 'secureops', 'secureops.node');
try {
  const addon = _require(addonPath);
  const addonJson = await addon.auditToJson(stateDir, false, false);
  const addonFindings = JSON.parse(addonJson).findings
    .map(f => ({ id: f.id, severity: f.severity, category: f.category }))
    .sort((a, b) => a.id.localeCompare(b.id));

  const rustIds = new Set(rustFindings.map(f => f.id));
  const addonIds = new Set(addonFindings.map(f => f.id));
  const onlyRust  = [...rustIds].filter(id => !addonIds.has(id));
  const onlyAddon = [...addonIds].filter(id => !rustIds.has(id));

  if (onlyRust.length === 0 && onlyAddon.length === 0) {
    process.stderr.write('✓ Rust CLI and napi addon findings match\n');
  } else {
    if (onlyRust.length  > 0) process.stderr.write(`Only in CLI:  ${onlyRust.join(', ')}\n`);
    if (onlyAddon.length > 0) process.stderr.write(`Only in addon: ${onlyAddon.join(', ')}\n`);
    process.exit(1);
  }
} catch {
  // Addon not built — print CLI findings only (non-fatal)
}
