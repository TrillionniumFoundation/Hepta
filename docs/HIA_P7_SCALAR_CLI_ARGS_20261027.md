# P7 — Bounded scalar CLI argument JSON on the existing Rust HIA shadow

**Exact parent:** PR #288 at `56fd7ccd2718d50a2ca613b6fdc92e7b487d0a35`.
**Authority:** the sole standalone program verifier remains
`hepta.hia_program.verify_program`. This change is a CLI input precondition
for an independent, non-production Rust scalar execution oracle.

## Prior behavior / scoped failure

`rust/hia-core-shadow/src/main.rs` read HIA program bytes with the 8 MiB
limit and verified them, but parsed the separate untrusted `--scalar-run`
JSON_ARGS command-line parameter directly with
`serde_json::from_str::<Vec<Value>>`. That path bypassed the bounded,
duplicate-aware, finite-depth `UniqueJson` deserializer already implemented
for canonical Core bytes. A function's scalar parameter type/arity checks
occurred only *after* this Value graph had been allocated.

## Repair, without introducing a new parser

- `hia_core_shadow::decode_scalar_arguments` reuses the existing
  `decode_hia` JSON deserializer on that argument text; the input is capped
  to **128 KiB** before any serde value materialization.
- Existing `UniqueJson` duplicate-key/node/depth/number checks remain the
  single syntax-structure authority. After decoding, the input must be an
  array of <=8,192 JSON primitive (integer/bool/null) values. The existing
  `execute_scalar` still checks the *exact* selected function's parameter
  arity and machine types. This bounded CLI profile can conservatively
  refuse oversized otherwise syntactically valid arg lists.
- No source schema, Rust Ownership/Loan verifier, LLVM lowering, HIA v7
  resource grammar, native ABI, sandbox syscall or patch transaction changed.
- Large command-line strings are already bounded by host OS limits, but those
  limits vary by host. The explicit HIA parser bounds are independent of
  the OS and avoid silent dependencies on a platform's argv policy.
- This does not claim a bound on Rust's initial `std::env::args()` allocations,
  full process RSS, allocator fragmentation or compiler/toolchain correctness.

## Actual committed regression inputs

```sh
cargo test --manifest-path rust/hia-core-shadow/Cargo.toml \
  scalar_cli_argument_decoder_is_bounded_before_untrusted_value_materialization
cargo test --manifest-path rust/hia-core-shadow/Cargo.toml
python -m unittest tests.test_hia_rust_scalar_vm -v
```

Tests cover allowed integer/bool/null inputs, wrong root type, nested JSON,
strings, floats, >128 KiB text, >8,192 entries, extreme nesting, and normal
scalar execution. The full exact-head tests have **not** run in the current
container (GitHub DNS cannot resolve and rustc/cargo are absent), so these
committed cases cannot be called PASS.

**OPEN:** P0 source authority convergence, general P1 Memory/Provenance SSA,
P2 LLVM/native refinement, P3 ABI, P4 C/C++ L2–L3, P5 agent A/B, P6 physical
hardware/p99 and P7 whole-compiler soundness/release.
`whole_project_blockers_closed=false`.
