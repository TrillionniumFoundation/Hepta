# P2: conservative Rust HIA v7 scalar-only shadow

Current HIA program v7 adds `chain` and recursive owner operations to the
existing v1–v6 typed scalar machine. This change admits **only the unchanged
scalar ISA** from v7 to the opt-in Rust shadow verifier and scalar execution
oracle. It adds no new schema, parser or executable semantic authority.

Every function is checked (including unused ones); unknown fields and v8+
schemas, buffer, chain, Owner, Loan, and foreign instructions reject. The
reported `v7_scalar_only_checked` is true only for a v7 scalar document, while
`v7_chain_resources_supported`, general soundness and backend-refinement
claims remain false. The canonical Python `verify_program` is still the
mandatory production admission and native Final-use gate.

Positive evidence inputs: standalone v7 u32 wrapping-add SSA program,
independent Python VM result and steps, Rust v1–v7 scalar format and SHA
parity. Negative inputs: v8, unknown fields and a genuine Python-accepted
v7 `chain.empty -> owner.drop` program, rejected by the Rust scalar path.

Exact-head tests to run in a complete pinned toolchain checkout:

```sh
cargo test --manifest-path rust/hia-core-shadow/Cargo.toml
python -m unittest tests.test_hia_rust_shadow tests.test_hia_rust_scalar_vm -v
python -m unittest tests.test_hia_recursive_chain tests.test_hia_program -v
```

The current container lacks cargo/rustc and a network clone; these exact
Rust/native suites were **not run**. The change is not a general P1 v7
Memory/Provenance SSA, compiler correctness proof, CPU/GPU qualification,
physical hardware or live Agent A/B outcome.
`whole_project_blockers_closed=false`.
