# Hosted versioned package-context qualification

This follow-up is based on exact #720
`54f4c67ec93ccbd997f7a4d56b3046221949e67c`, tree
`514aa3c95296de241e984bf656911b5c5deb5555`.
All 175 files from that source remain byte-identical. Only this document and
`.github/workflows/versioned-package-context.yml` are added. The original
context document describes the original head's local-only qualification;
this document records the additional hosted gate, not a retroactive result.

## Missing coverage addressed

The inherited package-integration workflow runs 65 methods and its original
three graph oracles. It does not run the 83-method scoped context inventory
or the new versioned-context oracle. Hashing those files is not execution.

The new pull-request workflow runs the **unchanged**
`tools/qualify_versioned_package_context.py` with Python 3.13, GCC, and an
explicit C backend on Ubuntu 24.04 x86-64 and AArch64. It requires the original
83 ordered methods to have identical planned, started, finished and passed
inventories, with no failures, errors, skips, xfails or xpasses. The original
parent/supplier source pins and before/after source checks remain mandatory.

That runner also executes the unchanged acyclic integration oracle (326
states, 249 transition pairs, 748 complete lock comparisons) and the
versioned-context oracle (48 exact context refusals, 16 C/Rust frontend
cases, eight actual C O0/O3 UBSan executions and one explicit lock upgrade).
Those counts describe the enforced contract, not a claim that a pending job
has passed. Nested program executions are not additional test methods.

## Evidence and source isolation

Checkout is bound to the exact pull-request head, with credentials disabled.
The workflow records the commit/tree, complete Git blob inventory, host,
Python/GCC/Git versions and executable hashes. It exports that checked-out
tree using `git archive` to a new runner-temporary directory and invokes the
original runner there. This keeps Git metadata, workflow logs and artifacts
outside the runner's complete source-byte inventory. Logs are retained with
`pipefail`, including the runner's source SHA-256 inventory, full ordered
method result and native/oracle receipts. Evidence upload runs even after a
failure; an uploaded log alone is not a passing gate.

The final checkout must remain clean at the same head. No original workflow,
inventory, source manifest, oracle, test, compiler or runtime is modified.
No manual dispatch is added. Existing gates remain independently required.

## Qualification limits

The new gate is **C native only**. Its 16 C/Rust frontend cases do not execute
Rust. It does not run the original #665 native Rust parity method or complete
124-method suite, the five omitted #698 cycle-specific methods, the #665
active-cycle method, or the other two inherited graph oracles. The separate
inherited 65-method hosted C/Rust jobs are distinct evidence and do not
establish context-native-Rust parity. This workflow does not add Python 3.11
coverage. Native Rust context parity remains open.

Completed results must be checked for the published head and each host;
parent greens, local results and queued jobs cannot fill that requirement.
P01/P11/P12 remain PARTIAL. Draft only; no merge, release or deployment.
