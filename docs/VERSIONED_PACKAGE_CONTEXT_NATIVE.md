# Native comparison for versioned package contexts

This additional qualification is stacked only on #759 commit
`8e0ce934ddea988896086035fb560d1498f4c2f6`, tree
`a18218177d4f8aed8615a64535b13e23ca333472`. All 187 inherited files remain
byte-identical, including production code, original tests, all five workflows,
source manifests, inventories, runners and oracles. Five new files add an
independent fixture suite, strict runner, pinned origin manifest, workflow and
this scope document. No inherited gate is replaced or enlarged retrospectively.

## Contract

Run `python -B tools/qualify_versioned_package_context_native.py` with actual
GCC and pinned Rust 1.90.0 available (`RUSTC` selects its executable). Missing or
incorrect compilers fail before methods run; tests never skip for tool absence.
`--inputs-only` verifies origins without claiming any native result.

Eight ordered methods exercise finite acyclic package/module graphs:

- Highest eligible version in both candidate orders and locked/unlocked loads.
- A transitive constraint forcing fallback to the lower eligible version, in
  both orders and lock modes, with repeated aliases and diamond reuse.
- Fixed and versioned routes converging on one canonical selected root.
- An unselected library imported locally resolving its helper in the application
  context (7), while the selected dependency resolves its own helper (42).
- Candidate version upgrade invalidating the existing lock, preserving its bytes
  on stale refusal, then explicit refresh retargeting all three edges and
  changing the actual result from 42 to 24.
- Selected-file context conflicts in both import orders and both selected roots
  retaining the exact diagnostic/span before either compiler; recovery executes.
- Invalid array/table package kind during refresh preserving the previous lock;
  schema recovery and explicit refresh execute the new selected version.
- Real public CLI locked runs through both C and Rust on a fallback graph.

There are 72 direct compiler/executable comparisons (36 GCC with UBSan and 36
Rust, split evenly between O0/O3), plus two actual public CLI executions.
Each direct comparison checks the independently specified return value and empty
stdout/stderr, complete package-node/edge identities, module reuse, lock
preservation, generated-source hash, actual artifact hash and compiler identity.
The local-import case separately checks the extra local modules. CLI receipts
retain the complete emitted report. These nested executions are not additional
unittest methods. No recursive Hepta programs or cycle fixtures are executed.

The strict runner enforces exact planned/started/finished/passed method equality,
zero skips/xfails/xpasses/errors/failures, per-method backend/optimization counts,
all 187 inherited Git blob identities, the unchanged original composition origin
verifier, and before/after source and compiler hashes. The origin manifest itself
has a hard-coded SHA-256. An input-only success cannot satisfy the native gate.

## Hosted evidence

The new pull-request-only workflow selects actual Rust 1.90.0 and Python 3.13 on
Ubuntu 24.04 x86-64 and AArch64. It binds the exact PR head, exports its committed
source using `git archive`, and retains head/tree, Git blob inventory, host/tool
identities, full ordered method outcomes and native receipts outside that source
snapshot. Pipeline failures remain failures; logs upload even on failure. The
final checkout must remain unchanged. No manual dispatch is added.

## Limits

Results qualify only the exact source, hosts and finite cases actually run.
Local x86-64 evidence does not establish hosted/AArch64 success. The inherited
65-method C/Rust integration gate, 83-method scoped C gate, 14-method schema gate,
original 124-method scope, and other graph oracles remain separate obligations.
No omitted active-cycle or other cycle-specific test is added. No hardlink/output
alias, recursive execution, literal validation, signature audit or OpenVPN work
is included. Native parity here is not whole-language soundness, universal package
resolution correctness or production readiness. P01/P11/P12 remain PARTIAL.
Draft only; no merge, release or deployment.
