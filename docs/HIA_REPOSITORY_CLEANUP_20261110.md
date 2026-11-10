# Core-only repository cleanup

This follow-up audits the active Core-only candidate, not Git history, immutable
qualification snapshots or a running worker installation.

- Remove remaining source-adapter/scalar-oracle/migration-only documentation,
  unused source Resource-IR fixtures and the orphan Linux source-campaign runner.
- Replace the remaining generated obsolete multi-word CLI instructions with the
  installed `hia catalog` command. The old compatibility entry is not packaged.
- Remove deleted test selectors from authored cross-lane/increment inventories;
  retire legacy/migration lanes. New receipt schema names distinguish these
  Core-only inventories from historical mixed-language qualifications. Removed
  selectors are retired, never passed, and surviving tests are not filtered
  dynamically when a module is missing.
- Preserve strict outcome, exact start/stop identities, zero-skip proof gates,
  immutable-source checks and Core type/borrow/resource semantics.
- Check string-based test inventories, relative alias imports and obsolete CLI
  instructions as well as ordinary imports, package metadata and `.hepta` files.
- Explicitly label unavailable historical evidence paths instead of publishing
  broken clickable links or recreating deleted source components.

Original removed-file bytes and selector inventories are retained outside the
active source tree. Historical test and native reports remain bound to their
actual source commits. New acceptance must bind the v44 Core-only contract;
the prior v43 receipt does not qualify changed source.

See [the separate Runtime upgrade audit](HIA_RUNTIME_COMPATIBILITY_AUDIT_20261110.md).
The live worker still contains the old language; repository cleanup alone does
not migrate that deployment. Full native Agent persistence, module/build/runtime
coverage, remote cold-timeout closure and native-only project acceptance remain
open.
