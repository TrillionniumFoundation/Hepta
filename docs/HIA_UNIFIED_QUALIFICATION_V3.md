# One candidate, explicit native and Rust shadow gates

`tools/qualify_hia_unified.py` emits `hepta.hia.unified-qualification.v3`.
It executes the existing standalone HIA plan and five additional gates required
by the converged candidate:

| Gate | Actual execution | Success condition |
| --- | --- | --- |
| `rust_shadow_cargo` | The pinned Cargo and Rust compiler build and execute the real shadow crate tests, locked and offline | Nonempty complete test results, zero failures, ignored tests or filters, and successful process exit |
| `rust_shadow_parity` | The Python-to-Rust scalar, owned-verifier, call, chain, scalar VM and exact-binary crosscheck tests | A completed nonempty unittest report with zero skips, failures and errors |
| `cpp_composed_implementation_llvm` | Actual Clang AST migration of the supported composed-owner C++ implementations, direct LLVM compilation and native lifecycle controls | Fresh report, successful exit, and the existing `cpp_composed_to_llvm` replay validator |
| `llvm_local_stored_views` | Actual source-bound LLVM, Rust and C local-view execution and negative controls | Fresh report, successful exit, and the existing local-view replay validator |
| `task_io_composition` | Three repetitions of the actual task/I/O native cases | Fresh report, successful exit, and the existing task/I/O replay validator |

The existing upstream C++ library bridge gate remains separate from the actual
implementation rewrite. Its evidence cannot be used to claim that those
upstream library implementations have been translated.

## Reproducible execution

Commit tracked source before running. Select a new output directory, preferably
outside the checkout. The collector records the actual Git commit, commands,
bounded process logs, report digests and source snapshots before and after all
gates. Every planned gate executes even after another fails. A missing report,
an interrupted test suite, a skipped test or a malformed report prevents that
gate from passing. Imported native reports also replay their existing validators;
`ok=true` alone grants no qualification. Report intake reuses the existing stable,
bounded, no-follow evidence reader.

The Rust component lock now includes Cargo 1.90.0. The existing bootstrap
installer checks the official archive checksum and each installed payload.
Fetch locked dependencies before the frozen run:

```sh
cargo fetch --locked --manifest-path rust/hia-core-shadow/Cargo.toml
```

Pass the selected executable with `--cargo /absolute/path/to/cargo`. The collector
makes the same Cargo available to Python's real crosscheck tests, exports the
selected `RUSTC`, enforces offline Cargo execution, and places build outputs under
the evidence directory. It restores the caller's environment even after failure.
The qualification workflow installs pinned Cargo and fetches dependencies before
entering this offline phase.

The repository's broader `tools/release_check.py` remains the qualification plan
for the historical hosted frontend, ABI, runtime, namespace and application
profiles. Execute that plan against the same unchanged source to assess those
profiles. A passing standalone HIA report does not substitute for it.

## Scope and regressions

Rust remains a shadow; these checks do not transfer production admission from
the existing Python Core. The raw Cargo result parser counts actual test
binaries, rejects an empty run, and retains failures and ignored/filtered counts.
The collector regression exercises every planned command and confirms that
zero exits without native reports, and a forged task report containing only
success flags, cannot pass. These collector controls are protocol tests rather
than native qualification evidence.

The schema continues to report `full_seven_deliverables_complete=false`.
General recursive ADTs, universal C/C++ migration, real-model productivity,
physical devices, compiler refinement and general Rust performance superiority
require their own evidence. Adding or passing a gate does not establish any of
those broader claims.
