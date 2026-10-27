# HIA P1/P2 — independent Rust v7 Chain Owner/Loan verification increment

**Scope:** This is an exact-source, opt-in Rust shadow extension on top of
PR #301, not a new Core authority. The existing Python
`hepta.hia_program.verify_program` remains mandatory for executable/native
admission. `whole_project_blockers_closed=false`.

## Implementation

Extends only `rust/hia-core-shadow/src/ownership.rs` and its opt-in
`--owned-shadow` route to cover the *existing* primitive
`hepta.hia.program.v7` linear recursive byte-owner chain instructions.
The existing v1-v6 profiles stay closed; even unused v1-v6 declarations of
`chain` are rejected.

- `chain.empty`, `chain.try_push`, `chain.pop`,
  `chain.is_empty`, `chain.head_read`, and `chain.head_mut`
  have exact argument, result, effect and version checks.
- Chain owners are linear through move, drop, typed calls, returns and CFG
  edge remapping. Failed `try_push` and empty `pop` retain output owner
  capabilities in both branches; this is a type/flow statement, not a
  runtime heap-failure proof.
- `chain.head_read/mut` opens a borrowed *byte view* rooted in the chain;
  parent suspension, mutable exclusivity, reborrow and `loan.end` are
  checked. An ordinary `borrow.read(chain)` or
  `buffer.len(chain)` is refused.
- v7 calls account for all returned Owner types and callee effects.
  Optional public `exports` are accepted only for existing, distinct,
  **scalar ABI** entrypoints, matching the original Core grammar.
- A new positive-scope claim
  `v7_chain_owner_loan_cfg_checked` describes this finite static checker.
  Native semantics, general provenance, source/native refinement, CPU/RSS,
  formal soundness and production-admission authority stay FALSE.

There are no new HIA ISA versions, no Python Core verifier alterations, no
native LLVM implementation changes and no automatic production activation.

## Committed executable qualification inputs

```sh
cargo test --manifest-path rust/hia-core-shadow/Cargo.toml
python -m unittest tests.test_hia_rust_chain_shadow -v
python -m unittest tests.test_hia_recursive_chain tests.test_hia_program -v
```

The Rust tests include the actual 9-function, 45KB
`examples/hia_recursive_chain/core_v7.json` HIA program, chain lifecycle
and head-borrow denials, a real branching chain-owner join, typed internal
calls, old-version rejection and scalar-export safety. The Python test
independently runs the existing canonical Python verifier on the exact
same finite corpus and compares Rust canonical document SHA; it never treats
the Rust result as a replacement for Python authorization.

**Qualification at author time:** GitHub source-object/commit identity and
static correspondence review only. Cargo/rustc are absent from the available
execution host; actual Rust compile/test, full Python/native LLVM, real
hardware and controlled live-model Agent A/B are NOT run. Any future failing
differential is a BLOCKER until corrected, not an excuse to update the
Python authority or infer a passing result.

## Still open

HIA Core/Verifier full memory and pointer provenance SSA, allocator-fault
operational refinement, concurrency and exception/Drop edges, multi-platform
C/C++ L2/L3 correctness, native backend/compiler proof, physical DMA/GPU/NPU,
statistically meaningful performance/p99, real AI provider A/B and
exact-integrated-HEAD production release qualification all remain OPEN.
