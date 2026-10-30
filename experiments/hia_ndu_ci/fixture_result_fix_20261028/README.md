# Minimal fleet fixture Result assertion fix

Prepared against NDU repository commit `4b6391e116949af0c7e59776baead67271856bdb` in the separate sparse worktree `/workspace/scratch/5567a9db5cf4/hepta-fleet-fixture-fix`, branch `work/fleet-fixture-result-20261028`. The original `/workspace/scratch/5567a9db5cf4/hepta-ndu-source` checkout remains clean at that exact commit, preserving the earlier NDU source identity. The initial preparation record below predates publication. `PUBLICATION.json` separately records local commit `b3a5db1a43751ad1720e47fae838866e97f64b7d` and published commit `dc984bb3b3cb21259f838a31f67a7c2983ea9510`, with the exact same Git tree `cd388fb79077d62f041c9b0c63b46be24c949d70`.

## Problem and exact change

The terminal [Ubuntu Clippy job 122633257034](https://github.com/TrillionniumFoundation/hepta-private-ci/actions/runs/40632653912/job/122633257034) rejects `expect()` on a Result in the `authority_port.rs` test fixture helper. The failure and all other terminal jobs remain preserved separately in `../final_20261028_054709/`.

The workspace denies both `clippy::unwrap_used` and `clippy::expect_used`; `codex-hepta-fleet` inherits those lints. The Clippy configuration permits unwrap/expect in tests, but the ordinary `ledger()` helper was still rejected by the actual remote lint. Nearby direct `#[test]` functions using these methods therefore do not establish a valid helper convention.

Only `tests::ledger()` in `codex-rs/hepta-fleet/src/authority_port.rs` changes. It now uses `pretty_assertions::assert_eq!(ledger.admit_host(...), Ok(()), "admit the fleet authority test host")`. The admission Result is checked in full, and unexpected errors retain contextual assertion diagnostics. `LeaseLedger::admit_host` returns `Result<(), Error>`, and its Error already implements Debug, Eq and PartialEq. The helper keeps the same return type and successful ledger construction; its caller and every production function remain byte-identical.

The crate already declares `pretty_assertions` as a dev dependency. No import, dependency, Cargo/Bazel lock, lint exemption, sandbox guard, NDU algorithm, or public API change is needed. The fully qualified macro keeps the change entirely inside the helper. `authority_port.patch` is the complete proposed patch.

## Repository requirements and validation

The root `AGENTS.md` was read before editing. No additional `AGENTS.md` exists in `codex-rs` or the fleet subtree at this commit. The relevant requirements are: use `just fmt`; run project tests through `just test`, not direct `cargo test`; prefer whole-object equality and `pretty_assertions` in tests; do not change sandbox guards; update Bazel locks if Rust dependencies change. There are no dependency changes here, so lock regeneration is not applicable. The full-suite rule for common/core/protocol changes and the large-change `just fix` rule do not apply to this single fleet test helper.

Completed lightweight checks:

- `just fmt`: exit 0, scoped by the repository's existing formatter to the single changed Rust file.
- `just fmt --check`: exit 0.
- `git diff --check`: exit 0.
- Exact source comparison: all bytes outside `tests::ledger()` remain identical; only the intended file is modified, with no staged files.
- Original NDU checkout identity and clean working tree rechecked after the edit.

Tools observed: `just 1.59.0` and `rustfmt 1.9.0-stable (59807616e1 2026-04-14)` from the installed Rust 1.95.0 toolchain. Commands, working directories, timings, source hashes, and logs are recorded in `VALIDATION.json`.

**At this preparation stage, actual crate type checking, tests, and Clippy had not been run for this patch.** The task reserves local CPU while the frozen Granite model profile runs. Formatting is not claimed as type checking or lint success. Applicable subsequent checks are `just test -p codex-hepta-fleet --locked`, `just clippy -p codex-hepta-fleet --locked`, and the unchanged remote Bazel Clippy/required workflow. The existing Unix-only authority port tests include `allocation_issue_consumes_exact_live_kernel_authority_lease` (which exercises this helper) and `allocation_binding_changes_when_owner_mutation_semantics_change`. Scoped preparation and later execution evidence are retained separately so this original validation record is not relabelled.

The previous required CI failure remains a failure. This small change addresses only the specifically diagnosed helper lint; it makes no claim to repair cargo-deny, Windows tests, cancellations, or the entire required workflow.
