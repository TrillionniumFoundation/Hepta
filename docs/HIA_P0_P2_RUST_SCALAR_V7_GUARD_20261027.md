# HIA P0/P2: integrate bounded Rust scalar oracle without v7 authorization

## Pinned lineage

Recipient: PR #281 HEAD `2ca474be081502dd0c9d63aab1f5c9603e2ab2f7`
(on the PR #210 HIA v7 stack). Donor: PR #279 HEAD
`36be00e407dfff8d47bbed29ffccd834f1025480`.

Exact unchanged Rust Git blobs transferred: `lib.rs`, `main.rs`,
`scalar_vm.rs`. The recipient's existing `ownership.rs`, `Cargo.toml`
and `Cargo.lock` are NOT replaced; the original ownership verifier blob
matches the donor byte-for-byte. Donor regression suites were copied with
added v7 refusal controls.

## P2 behavior

The opt-in safe-Rust, bounded scalar execution oracle now has independent
scalar SSA/CFG interpretation with explicit integer type, overflow, shift,
trap, steps and recursion budgets. It reuses the existing Rust scalar verifier
and MUST NOT become canonical program admission, production Final-use or
native authorization. The Python HIA `verify_program` remains the canonical
program checker; existing HIA Core v7/Composite v2, Python VM and independent
LLVM emitter are unchanged.

Selected previously observed mismatches have new candidate repairs: signed
MIN / -1 remainder trap, root-zero recursion depth/tick parity, and optional
explicit `exports` scope. Multiple positive/negative cross-language tests
are committed.

The Rust shadow has no v7 chain/resource implementation and deliberately
recognizes scalar HIA `program.v1..v6` only. A valid Python v7 *scalar-only*
program therefore still receives a Rust unsupported-schema refusal, rather
than an automatic v7 safety claim. New Rust and Python↔Rust controls enforce
this boundary. The backend's v7 capability must be reviewed separately.

## Exact-head checks (pending actual execution)

```sh
cargo test --manifest-path rust/hia-core-shadow/Cargo.toml
python -m unittest tests.test_hia_rust_scalar_vm -v
python -m unittest tests.test_hia_rust_shadow \
  tests.test_hia_rust_owned_shadow tests.test_hia_program -v
python -m unittest tests.test_hia_p0p1_v7_guard -v
```

**Actual execution status:** the local shell cannot resolve github.com to
clone a complete source checkout and has no pinned Cargo/rustc. Git blobs,
ABI-facing entrypoint policy, and the independent Rust source diffs were
reviewed, but the full test corpus/real Rust native execution has NOT run
on the new merge head. No CI state is inferred.

## P0–P7 still open

P0: canonical producer/consumer adapters and HSIR/MIR/Resource authority.
P1: generalized v7/Memory SSA/Provenance/error edges and heap budgets.
P2: native Rust/LLVM source-to-Core refinement and complete v7 oracle.
P3–P4: real ABI matrix and broad C/C++ migration.
P5: held-out model Agent benefit; P6: physical hardware + stable p99;
P7: scoped formal refinement and production release.

`whole_project_blockers_closed=false`.
