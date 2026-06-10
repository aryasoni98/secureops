## What & why

<!-- What changes, and the problem it solves. Link issues with "Fixes #N". -->

## How it was tested

<!-- Commands run, new tests added, manual verification performed. -->

## Checklist

- [ ] `cargo fmt --all --check` clean
- [ ] `cargo clippy --workspace -- -D warnings` clean
- [ ] `cargo test --workspace` green (new behavior covered by tests)
- [ ] Web changes: `npm run build && npm test && npm run e2e` green
- [ ] JSON wire format unchanged (or the change is called out above)
- [ ] No insecure defaults outside `SECUREOPS_DEV_MODE=1`
- [ ] Docs/CHANGELOG updated where user-visible
