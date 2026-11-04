# Native source receipt compatibility and two Rust roles

The guarded entry layout producer added `entry_layout` to every `hepta.hia.program.native.v1` receipt, including canonical builds. The existing source-stage reinspection correctly required an exact field set, but that set omitted the new field. A real checked Hepta source → Core → Clang native qualification therefore failed even though standalone native qualification passed.

The source bridge now admits exactly the expanded receipt schema and requires `entry_layout` to be an ordinary string equal to the layout of the independently emitted LLVM object. The checked-source builder continues to emit the canonical layout. This change does not add an outlined source profile, relax binary import/export checks, accept unknown receipt keys, or upgrade any proof claim. Missing, forged, unsupported, and incorrectly typed layout fields are refused.

## Two named compiler roles

| Role | Compiler | Selection |
| --- | --- | --- |
| NDU, AOT and Agent experiment consumers | Rust 1.95.0 | Existing `--rustc`; existing scientific protocols unchanged |
| Checked Hepta source borrow/type reference | Pinned Rust 1.90.0 | Required `--source-rustc`; `HIA_TEST_SOURCE_RUSTC` is scoped to the legacy source test |

The composition command requires both selections explicitly. There is no implicit compiler-version fallback in composition. The legacy test retains its historical `RUSTC` fallback when invoked independently by the existing CI workflow; composition always supplies the separately frozen source reference.

The source-reference identity reuses `hepta.backend.find_rustc` and `toolchain_info` to resolve the actual selected compiler and require the production backend's complete pinned `-vV` identity. It records the invocation, resolved executable, executable bytes, verified local sysroot and every ordinary file below that sysroot's `lib` directory. Stable streaming file hashing reuses `hepta.native_tool_identity.digest_executable`. The complete inventory is compared before and after every composition command, so executable, driver, standard-library, addition and deletion drift fail closed. This composition inventory rejects sysroot links. The system loader, libc, external linker and hardware remain trusted; content identities do not prove compiler correctness.

## Regression coverage

Composition now runs the complete `tests.test_hia_v6_differential` and `tests.test_hia_native_source_reinspect` modules. The actual legacy checked-source test observes the unmodified producer receipt and asserts its canonical layout. Reinspection controls retain the existing hostile ABI, host, cross-target, proof-scope and unknown-field cases, and add missing/forged/mistyped layout refusals. Source-reference controls check explicit selection, the distinct version pin, and executable/driver/sysroot drift.

The original published CI failure and failed local baselines are retained separately from corrected-source results. A successful rerun does not relabel the earlier measured source or its preparation and timing costs.
