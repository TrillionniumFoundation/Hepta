# Rust integration review, 2026-10-30

This records the bounded review used to resolve the Rust conflicts between the
catalog integration and the later P0–P7 branch. It records integration evidence;
it does not establish whole-language soundness, native refinement, arbitrary
unwinding, or a process CPU/RSS bound.

## Fixed inputs and resolution

The reviewed inputs are:

- Catalog integration: `192d2cbba7e49bde3b03af73685ecf96f6fb1b05`.
- P0–P7 additions: `953fa62dee5aa563551d57b1374ab95b6d548b45`.
- Common base: `2cc9fb3b92a7306d2f5aae316c99e8364be700f9`.

The six files below use the P0–P7 content. Before copying, each file's complete
bytes were checked against the corresponding Git blob identity, including the
final newline. The review compared the two complete input files rather than
choosing one side merely because its commit was newer.

| Path below `rust/hia-core-shadow/` | Selected Git blob | Reason |
| --- | --- | --- |
| `src/lib.rs` | `2fa13c85c7d455ef0ba9321fb4f5c245865a849d` | Adds the byte-DAG, finite-entry heap and static-budget modules/exports; retains the existing verifier and execution exports. |
| `src/main.rs` | `3560dc3adc5e8cb06eb5c633b5b724a953440faf` | Adds explicit CLI routes for static budget, finite heap, byte-DAG admission and scoped cleanup; retains the older modes. |
| `src/scalar_vm.rs` | `7464950ad3a33b348549e488d9b0654600e29f1b` | Adds a private scoped entry and optional cleanup reservation around the same Machine; existing public execution routes pass `None`. |
| `src/scalar_vm/byte_memory.rs` | `99fc322b7b57f1153b982ccd5ebfd04c97b715ff` | Adds the private abort-cleanup module and reservation import. |
| `tests/bound_execution_v3.rs` | `57cf4098d5bdb9823cd397de49c4b9e02476c1e0` | The two input versions differ only in an ending blank line. |
| `tests/bound_execution_v4.rs` | `36e41c16287ad7a33ce2fd666aed72b2d96430ab` | The two input versions differ only in an ending blank line. |

The successfully merged crate `README.md` is retained. In particular, it retains
both the catalog branch's v3/v4 argument, failure-index and executable-custody
description and the P0–P7 branch's narrowly scoped Rust admission/static-budget
description. Replacing the whole README with only one input would lose useful
contract information.

## Semantics checked during the merge

The `scalar_vm.rs` changes keep the original execution wrappers and v1–v4 policy
parsing. They extract internal helpers carrying an `Option<u64>` cleanup bound.
Existing public paths use `None`, so they retain the stopped-resource ledger and
do not acquire an implicit cleanup claim. Only the private admitted byte-DAG
path can pass a reservation into `execute_owned_bound_v4_scoped`.

The scoped path reserves its cleanup journal before constructing/invoking the
Machine. It refuses chains and unsupported schemas. The runtime report records
the original stop and pre-cleanup ledger before the same Machine's private
ByteMemory performs cleanup. The cleanup module checks the surviving inventory,
ends children before parents using their ordered identities, and reports actual
owner/loan releases. An insufficient reservation or malformed inventory reports
failure; it must not be represented as successful discharge.

This is a finite, private, scalar-entry byte-owner invocation contract. It is
not a proof that arbitrary foreign callbacks, C++ destructors, host panic,
host allocation failure, termination, or native code will unwind safely. The
cleanup journal action bound is also not a bound on all host allocations or on
wall-clock time. The separate static-budget and finite-heap profiles retain
their own explicit assumptions and refusals.

The catalog generation and Python-side source-closure changes live outside the
six resolved Rust files. No generated catalog or opcode definition is removed
by this resolution. This review does not claim the opcode catalog generates or
proves the Rust interpreter's semantics.

## Validation status

The required command is:

```sh
cargo test --locked --offline --manifest-path rust/hia-core-shadow/Cargo.toml
```

The first attempt stopped before compilation because eleven locked crate
versions were absent from the local cache. A normal dependency fetch failed at
the sandbox proxy connection. The same `cargo fetch --locked` command through
the approved execution path then downloaded the exact locked dependencies.
The repository `Cargo.lock` was not changed.

A temporary cache-compatible dependency smoke was attempted while that access
problem was being diagnosed. It stopped at missing restored example fixtures
and is not evidence of passing tests or of satisfying the repository lock.
The authoritative result below is reserved for the exact repository-lock run.

Exact-lock test result: **121 passed, 0 failed, 0 ignored**, exit status 0,
across 21 reported suites, in 8.09 seconds including compilation. The test was
run from an isolated snapshot while the shared checkout's example fixtures were
being restored. All crate source/test files and `Cargo.lock` were checked to be
byte-identical to the merged checkout after the run. The five `include_bytes!`
fixtures were checked against their Git blob identities, which are identical in
both input commits. The manifest, full test log and machine-readable result are
in [`reports/hia-six-track-convergence-20261030/safety-dynamic/rust`](../reports/hia-six-track-convergence-20261030/safety-dynamic/rust).

This test includes the retained v3/v4 invocation contracts and the added static
budget, finite-entry heap, raw byte-DAG admission and abort-cleanup unit tests.
It supplies regression evidence for the merge; passing tests do not constitute
a proof of the full language or of native backend refinement.

The execution uses Rust 1.95.0 (`59807616e`, LLVM 22.1.2). Debug symbols and
incremental build artifacts are disabled, with two Cargo build jobs, to fit the
available scratch disk. Those build settings do not alter the selected source,
dependency versions, test selection, or the explicit runtime budget policies.
