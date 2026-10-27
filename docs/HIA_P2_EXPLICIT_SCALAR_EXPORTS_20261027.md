# P2 — Explicit scalar export parity for the Rust HIA shadow

Base: PR #279, exact `bc630d138ec3e3a1031cf3232568be24df513dd3`.
The canonical `hepta.hia_program.verify_program` supports an optional exact
`exports` list of public scalar entrypoints; its absence retains the
historical inferred scalar export set. The conservative Rust scalar verifier
previously rejected valid HIA modules containing the optional field.

This change updates only the existing shadow verifier and evaluator. It
validates the optional list as unique identifiers naming existing scalar
functions and refuses direct execution of unexported entries. An empty list
denies every external scalar entry; internally called helpers remain allowed.
Unknown/malformed/duplicate lists reject. It preserves full-module scalar
verification and does not grant foreign, Owner, Loan or native authority.

Tests are committed but full Cargo/Hepta checkout execution is **not run** in
this environment. Execute:
```sh
cargo test --manifest-path rust/hia-core-shadow/Cargo.toml
python -m unittest tests.test_hia_rust_scalar_vm -v
```

This is an independent differential-coverage increment, not proof of
Source→Core→machine refinement or production safety.
`whole_project_blockers_closed=false`.
