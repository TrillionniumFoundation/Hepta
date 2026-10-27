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
- Bounded execution: 1..1,000,000 evaluator steps, at most 32 nested calls;
  resource/foreign opcodes rejected at whole-module verification, not deferred
  until their basic block is reached. Errors separate language traps, budgets
  and malformed/unsupported inputs.
- Input and output types are checked before execution; canonical program
  digest is re-derived from HIA bytes. The evaluator has no IO, allocator
  capability, native ABI, GPU, pointer or file access.
- CLI: `cargo run --manifest-path rust/hia-core-shadow/Cargo.toml -- --scalar-run calc '[2,3]'`
  with complete HIA JSON supplied on stdin. Output is an explicit limited
  JSON report with false soundness/backend/Final-use claims.
- Rust arithmetic and CFG tests plus opt-in existing Python VM differential
  tests distinguish value results, overflow and division traps and steps.

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
