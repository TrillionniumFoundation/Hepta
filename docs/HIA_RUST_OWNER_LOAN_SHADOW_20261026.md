# HIA P1 Rust Ownership/Loan CFG shadow, fail-closed increment

**Status: code candidate, not full HIA authority or soundness proof.**

This is stacked on PR #211, which in turn retains the exact two-parent PR #209
integration including native empty-Owner release and C/C++ L1 receipt guards.
The existing `hepta.hia_program.verify_program` remains the sole admission
authority for Interpreter/LLVM/native builds.

## Implementation

New `rust/hia-core-shadow/src/ownership.rs` independently verifies the v1
Owner/Loan/byte-access instructions under the *existing* HIA v1–v6 envelopes.
It does not create another ISA or source parser; it reuses the crate's strict
JSON decoder, closed-field/duplicate-key policy, and scalar instruction checks.
There is a new **explicit opt-in** `--owned-shadow` mode for separate offline
validation. Normal Rust scalar shadow operation is unchanged.

The Rust module checks SSA across the whole function, precise per-block
definitions, branch/loop edge parameter types, complete reachable CFG,
linear Owner move/drop/return, borrow.read/mut permissions, live parent/child
loans, denial of suspended view access, external borrowed parameters,
cross-block capability identity/parent/root forwarding, equivalent loan
states at CFG joins, checked byte load/store and transitive declared effects.

**Versioned byte operations:** the same shadow now checks the existing
`buffer.fill/copy` under v2+, `move_within` under v3+, `swap` under v4+,
`copy_range` under v5+, and `fill_range` under v6. It verifies precise
operand and output types, independent source/destination owner roots for
`copy/copy_range`, unique mutable loan access, parent suspension and required
read/write/trap effects. Earlier schemas reject later instructions. This
does NOT discharge dynamic extent checks, runtime allocation behavior, or
LLVM refinement; those remain obligations of the existing Python verifier,
interpreter and backend.

**Deliberately rejected:** direct/interprocedural function calls and
resource transfers, raw/foreign pointers, GPU, DMA, exceptional unwind,
general Memory SSA and externally supplied provenance proofs. Native artifact
consumers do not call this Rust shadow.

The emitted `hepta.hia.rust-owner-shadow.v1` report explicitly marks
whole-language soundness, native correctness, generic Memory SSA,
interprocedural resources and production authority as **false**.
A digest proves byte identity, not source↔IR semantic refinement.

## Genuine comparison tests

```sh
cargo test --manifest-path rust/hia-core-shadow/Cargo.toml
cargo fmt --manifest-path rust/hia-core-shadow/Cargo.toml -- --check
python -m unittest tests.test_hia_rust_owned_shadow -v
python -m unittest tests.test_hia_program tests.test_hia_program_llvm -v
```

The new Rust regression tests include a legitimate Owner+Loan traveling across
two basic blocks, double-drop, use after end, owner/edge duplication, live
borrow on drop, suspended parent, missing effect, unknown field, versioned
bulk-memory acceptance, old-version refusal and distinct-owner copy rejection. The Python↔Rust test uses **existing genuine canonical** HIA
fixtures `resource_program` and `joined_loan_program`, comparing
acceptance, fail-closed negative behavior and exact canonical SHA-256.

A missing Cargo toolchain **skips** this differential suite; it does not pass.
In the authoring environment rustc/cargo and GitHub clone network are unavailable.
The Rust and native tests on this exact candidate commit have not executed.
A static review and GitHub file receipts do not change that boundary.

## Remaining P0–P7 priorities

P0: exact SHA source/release qualification and canonical schema convergence.
P1: interprocedural and exception-edge resource SSA, full memory provenance,
native verifier transition, bounded hardware capabilities.
P2: executable Core↔native/VM differential plus formal safety refinement.
P3/P4: C/C++ L2/L3 real-project coverage with independently qualified ABI.
P5: SIMD/GPU/NPU actual execution and unbiased CPU/RSS/throughput/p99.
P6: live Agent/model controlled A/B economics and crash-safe patch replay.
P7: physical DMA/IRQ/hardware, failure injection, production resource and
release gates.

`whole_project_blockers_closed=false` even if all finite Rust tests eventually pass.
