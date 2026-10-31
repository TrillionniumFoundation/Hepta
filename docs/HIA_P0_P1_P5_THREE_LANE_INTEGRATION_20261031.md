# HIA P0/P1/P5 three-lane integration candidate — 2026-10-31

This report is an **integration intent and strict non-claim**, not a pass
report or permission to merge/deploy. All P0–P7 production blockers remain OPEN
until the exact integrated SHA, all mandatory native/host/economic gates, and an
independent reviewer confirm closure.

## Exact frozen sources

| Lane | Frozen candidate | Ownership |
|---|---|---|
| Common HIA Core v8 | `3201298a9828927452d42bcac146e610e1348a7f` (#418) | Shared starting semantic Core |
| P0 caller-owned Core snapshot + UTF-8 budget | `29246ef7fae6277a29f1712c352eec8f6d1e6a4f` (#458→#459) | Seven exact overlay paths |
| P1 common exits, Rust resource reporting, C/C++ migration and native controls | `bff762710946b0225d3f0f2641dd1e7fc33d996b` (#434) | Fifty-one exact overlay paths |
| P5 full-cost / ELF observation / paired replay / bounded evidence | `33d989298adbf5923bef164bd3aa17224b105428` (#455→#456→#457→#460) | Integration base |

All three overlays descend from the common #418 source. The specific seven P0
paths, fifty-one P1 paths, and seven P5 tip paths were compared before this
candidate: **zero changed-path intersections**. Each selected overlay uses
the exact existing Git object blob ID and file mode from its source tree.
This is a *structural* merge guarantee only: disjoint files can conflict
semantically, so no prior lane-specific green CI result qualifies this tree.

## Source-exact integrated matrix

- HIA opcode catalog generation on the chosen Core, including changed P1
  opcode contracts and unmodified v8 schema and round trip.
- Original + adversarial P0 mutable snapshot, UTF-8 early-byte rejection,
  canonical bytes, interpreter, owned resources, loan and composite programs.
- P1 common return/trap/cancel/stop resource contracts, independent exit
  accounting, and Rust byte-DAG shadow controls.
- P5 full-cost/paired sign math, no unaudited production authority, bounded
  evidence parsing, original actual compiled C/ELF observer and raw replay.
- Exact Git commit and no mutation of checked source during tests.

The new scoped workflow is an additional integrator test, not a substitute for
existing HIA intelligent assembly, native LLVM, C/C++ migration, broad CI, or
physical host gates. Target Rust/Clang versions and executed command identities
must be read from its real log, not inherited from earlier branches.

## Mandatory P0–P7 closures still open

| Stage | Must remain OPEN until |
|---|---|
| P0 | Same-SHA Core, versioned legacy adapter, independent checker/VM/Rust/LLVM equivalence, full clean negative and positive suite |
| P1 | Complete pointer provenance, lifetimes, resource/cancel/trap/crash and source/core/native refinement and failure proofs |
| P2 | Strong native ABI, ELF/Windows ARM64 x86-64 native host and installed target hardware evidence |
| P3 | Third-party C and C++ L0-L3 real upgrade differential, failures and measured developer effort |
| P4 | Exact candidate/refinement + strong fair Rust/C/C++ real application full-cost net improvement |
| P5 | Native NDU > same-information fixed/DP on held-out real tasks including every build/search/proof/failed/switch/human cost |
| P6 | Independent unseen Agent maintenance tasks, equal model/tools/budgets and complete accounting |
| P7 | Production final-use, generation fence, ledger, rollback, power-loss, and physical target resource/recovery evidence |

Every model-provided advice, historical receipt, arbitrary synthetic economic
positive or passed individual test remains `DENY_ALL` for production. Do not
auto-merge this candidate into main.


## First integrated CI (failed; retained)

At original integrated SHA `7cd1f68183f73fa55af848e175f71723a2f64eb5`, workflow
[41183211519](https://github.com/TrillionniumFoundation/Hepta/actions/runs/41183211519)
observed:
- Python/C-native integrated lane: 105 tests with 2 Z3 proof skips; actual
  native ELF/replay 13 tests passed. Because the two skipped proofs were
  missing their optional solver, this lane is **not** a complete P1 proof gate
  despite the job concluding success.
- Rust shadow lane: **failure before any test execution**, fresh Ubuntu
  runner had no cached locked serde crate. The test intentionally performs
  `cargo build --locked --offline`, which must not be weakened.
- Toolchain installed on that runner was Rust 1.99.1; it was not the
  experimental pinned Rust 1.95.0 source profile.

## Corrective integration increment

- Install exact declared `z3-solver==4.15.4.0`, then run full P1 proof tests.
- Install Rust 1.95.0 and perform `cargo fetch --locked` before the unchanged
  `--offline` compiled Rust shadow test. Lock identities remain unchanged.
- New `tools/qualify_hia_three_lane.py` rejects all skips (and zero-tests),
  failures, errors and post-test tracked source mutations; emits source-tree,
  exact commit and all outcomes as an exclusive per-run receipt.
- Preserve report artifacts even when a test fails. These changes are
  **qualification-only**, not modification of Core semantics, production
  admission authority, NDU score or C/C++ import assumptions.

The new integration SHA needs independent exact-head CI before any updated
passed claim. No production stage is closed from this preparation repair.

## Corrective start-path fix after first pinned dependency run

At `fc7bb2078b84699d15c092e898b84f1ca929ef81`, exact Z3 installation succeeded but the newly introduced
qualifier was invoked by file path from `tools/`. Python therefore resolved
`sys.path[0]` to `tools/` rather than the repository root; eleven test-module
imports refused before actual P0/P1/P5 tests could run. See
[workflow 41183342139](https://github.com/TrillionniumFoundation/Hepta/actions/runs/41183342139).
The refusal receipt and skipped downstream native stage are retained.

The next candidate runs the qualifier as `python -m tools.qualify_hia_three_lane`
and ensures the direct script entry point adds the exact checkout root before
loading tests. It does not bypass any assertion, skip rule, or original
source/product code. P0–P7 production gates remain open.
