# HIA P2 — opt-in bounded Rust scalar execution oracle

**Status:** Draft experimental subprofile, not full HIA execution or safety authority.
Exact parent: PR #267 at `6eb78e43f2a6329992f20c840ddf57df5ba572bf`.
The Python `hepta.hia_program.verify_program` and original interpreter remain
the canonical acceptance path; existing Python/Rust Owner/Loan shadow gates are
unchanged. Do not use this oracle to grant production Final-use.

## What is added

- `rust/hia-core-shadow/src/scalar_vm.rs` executes independently typed,
  already-verified **resource-free scalar SSA** directly in safe Rust.
- Accepted operations: i8/i16/i32/i64/isize/u8/u16/u32/u64/usize, bool/unit
  constants, checked/wrapping integer arithmetic (including full-width u64
  products), signed truncating div/rem, checked shifts, bitwise, compare,
  boolean, cast, select, branching, block arguments, direct internal calls.
- Bounded execution: 1..1,000,000 evaluator steps, at most 32 simultaneous call frames **including the root**;
  resource/foreign opcodes rejected at whole-module verification, not deferred
  until their basic block is reached. Errors separate language traps, budgets
  and malformed/unsupported inputs.
- Input and output types are checked before execution; canonical program
  digest is re-derived from HIA bytes. The evaluator has no IO, allocator
  capability, native ABI, GPU, pointer or file access.
- CLI: `cargo run --manifest-path rust/hia-core-shadow/Cargo.toml -- --scalar-run calc '[2,3]'`
  with complete HIA JSON supplied on stdin. A fourth CLI argument may specify
  an integer step limit (1..1,000,000); the default is 100,000.
  Output is an explicit limited
  JSON report with false soundness/backend/Final-use claims.
- Rust arithmetic and CFG tests plus opt-in existing Python VM differential
  tests distinguish value results, overflow and division traps, direct/nested
  calls, SSA backedge/PHI forwarding, step exhaustion and depth exhaustion.

## Execute exact full-checkout acceptance

```sh
cargo test --manifest-path rust/hia-core-shadow/Cargo.toml
python -m unittest tests.test_hia_rust_scalar_vm -v
python -m unittest tests.test_hia_rust_shadow tests.test_hia_rust_owned_shadow \
  tests.test_hia_rust_calls_shadow tests.test_hia_program -v
```

These are executable regression inputs, **not passing test claims**. Current
environment has no Rust/Cargo or full Git checkout; no exact-head native test
was executed. Do not inherit previous commits' CI or mocked tests. This
implementation intentionally excludes Owner/Loan runtime semantics,
Memory/Provenance SSA, arbitrary C/C++ migration, LLVM backend refinement,
independent formal proofs, real Agent A/B, GPU and physical hardware.

`whole_project_blockers_closed=false`.


## 2026-10-27 P2 signed remainder overflow consistency

The existing Python HIA interpreter and LLVM backend explicitly trap
`MIN_signed / -1` and `MIN_signed % -1` before evaluating either
operation. The independent Rust shadow interpreter previously performed
division in widened i128 and checked only the final result type: remainder
zero passed, violating the HIA ISA's observable overflow-trap contract.

The Rust scalar VM now checks the signed minimum for its exact operand
width **before** both quotient and remainder. This is an execution-semantic
repair, not a new verifier, IR, optimization rule or ABI assumption.
Added direct Rust tests across i8/i16/i32/i64 and unsigned negative
controls, plus Python↔Rust finite VM differential cases (traps, returned
values and step counts). The original Python Core verifier remains the
sole production admission authority. The exact commit has not yet been
compiled with Cargo or executed through the full Hepta test runner in
this environment; code review and mathematical spot checks cannot be
reported as an end-to-end native pass.

`whole_project_blockers_closed=false`.

The native LLVM regression suite also now contains a new actual-child
SIGABRT test for signed `MIN % -1` across i8/i16/i32/i64, paired with valid
`(MIN+1) % -1 == 0` controls. It links against genuine emitted HIA LLVM
shared-library exports, not a handwritten approximation. These committed
native tests require the pinned Clang toolchain and have **not been run**
on this exact merge head in the current container.

## 2026-10-27 P2 root-inclusive recursive-call correction

The pre-existing canonical HIA VM source and its independent regression
(`tests/test_hia_vm_call_depth.py`) enforce a root-inclusive dynamic call
budget: for `max_call_depth=32`, depth 0..31 may enter, depth 32 refuses
before its invocation tick. A subsequent Rust scalar VM shadow patch
inadvertently admitted depth 32 by using `depth > MAX_CALL_DEPTH`.
The correction restores `>=`. The infinite one-call recursion fixture
therefore consumes **64**, not 66, ticks at the standard limit. The finite
boundary is `n=31` returns and `n=32` refuses. Details and negative
regressions: `docs/HIA_RUST_DEPTH_PARITY_P2_20261027.md`.

No production source→LLVM equivalence or rustc/Cargo qualification is
claimed by this documentation correction.
