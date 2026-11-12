# HIA P0–P2: Rust core-verification migration, first scalar shadow

Status: **implementation candidate, NOT a new semantic/admission authority**.
Parent is the exact stacked HIA convergence commit
`8a6a5ffb38f76f2dfcf4255dd197945a2ca9fdc2` (PR #209).
The canonical executable HIA program and its authoritative admission checker
remain `hepta.hia_program.verify_program`; interpreters and native builders
must **continue to use that existing checker**.

## Implemented increment

`rust/hia-core-shadow` introduces a new safe Rust 2021 crate with
`#![forbid(unsafe_code)]`. Its only accepted domain is the **resource-free
scalar subset** of the existing `hepta.hia.program.v1` through `v6`
envelopes. It does not introduce any new on-disk HIA schema or opcode.
Accepted scalar operations are checked arithmetic, wrapping operations, casts,
comparisons, boolean logic, selections and direct typed calls. It checks
full-module function inventory, closed SSA names, block-local value use,
block-argument types, branching, exact effect inclusion and reachable CFG
blocks. Unknown types, operators, resources and foreign effects reject.

The input parser refuses duplicate JSON keys, floating-point JSON numbers,
unknown fields, unrecognized versions, malformed identifiers, oversize
documents and overdeep/oversize JSON graphs. The accepted scalar program
emits a stable digest of the canonical JSON representation and an explicitly
scope-limited report. This is a **shadow verifier**, not a runtime interpreter,
not an LLVM backend, and not a native code admission signal.

The crate does not yet verify ownership/borrowing, memory/provenance SSA,
resource budgets, hardware capabilities, backend lowering or FFI. These
all explicitly remain false in the emitted report. Do not replace a
`verify_program` call with this crate or combine its false claims into true.

## Exact verification entry points

```sh
cargo test --manifest-path rust/hia-core-shadow/Cargo.toml
cargo fmt --manifest-path rust/hia-core-shadow/Cargo.toml -- --check
python -m unittest tests.test_hia_rust_shadow -v
python -m unittest tests.test_hia_program tests.test_hia_program_llvm -v
```

The Python differential suite compiles the Rust binary if cargo is available,
compares canonical Rust/Python digests on v1–v6 scalar programs, and checks
shared negative cases plus the key boundary: valid Python-owned HIA is still
rejected by the limited Rust checker. Missing cargo is a **skip**, not a pass.

This commit was authored without locally available Rust/Cargo or a complete
repository checkout; the new Rust tests and end-to-end differential suite have
NOT been run on the exact source head. Do not treat static review, a branch or
GitHub metadata as native qualification.

## Required ordered continuation

1. P0: keep one canonical HIA wire format per version, independently compare
   Rust and Python accept/reject decisions; consolidate the #209 stack without
   dropping its native empty-owner and L1 receipt fixes.
2. P1: extend Rust verification over executable Owner/Loan/Memory/Provenance
   SSA with complete CFG joins, loops, error and cleanup edges.
3. P2: differential verifier+interpreter+native execution and mechanized
   source-to-Core/Core-to-native refinement for supported profiles; only after
   that can a Rust gate become a production authority.
4. P3/P4: qualify broad C/C++ L2/L3 and multi-toolchain ABI independently.
5. P5: native CPU/GPU/NPU correct execution and unbiased performance data.
6. P6: actual model/provider Agent A/B with token/cost/error receipts.
7. P7: physical hardware, failure injection, production p99 and signed
   exact-HEAD releases.

`whole_project_blockers_closed=false`. No CI queue is used as a development
stop, but no unexecuted qualification is reported as passed.
