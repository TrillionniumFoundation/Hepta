# Executed Rust byte-owner shadow: finite profile

The existing Rust scalar `Machine` now has an explicitly enabled, bounded byte
storage component. `--owned-run` executes a finite primitive HIA buffer/loan
profile after the existing `verify_owned` admission check. This does not change
Python Core authority, the production CLI, the native backend, or the
Python/Rust verifier crosscheck protocol. `--scalar-run` still rejects resource
programs.

## Execution boundary

The input must be a primitive `hepta.hia.program.v1` through `v7` document with
exactly one function and one basic block. Its external parameters and return
types must be scalars, and the block must terminate with `ret` or `trap`.
The existing strict schema, ownership/loan rules, effect checks, explicit
exports policy, and scalar argument validation apply before execution.

The complete document is checked against the execution capability profile
before constructing the `Machine`. An unsupported operation after a possible
allocation failure is still rejected before any instruction executes.

| Supported resource operation | Runtime behavior |
| --- | --- |
| `buffer.new`, `buffer.try_new` | Zero-initialized bytes, bounded live heap, deterministic allocation-failure injection |
| `buffer.len` | Underlying byte length; no byte access through a suspended parent |
| `borrow.read`, `borrow.mut` | Internal loan handles with root and parent identity, including admitted reborrows |
| `loan.end` | Ends the local loan after its children have ended |
| `owner.move`, `owner.drop` | Consumes the old SSA name; move preserves storage identity; drop records explicit cleanup |
| `buffer.load`, `buffer.store` | Checked `usize` offset and `u8` value, with bounds traps |

The existing scalar operation implementation is reused. Calls, CFG edges,
multiple functions or blocks, chain operations, bulk buffer operations,
resource entry/return types, and direct nominal/composite documents are outside
this execution profile. Primitive operations outside the profile produce
`E_HIA_RUST_UNSUPPORTED`. A direct nominal document fails the existing strict
primitive-schema check with `E_HIA_FORMAT`; no new schema fallback is installed.

Resource handles cannot be supplied or returned through JSON. Runtime owner
and loan maps supplement the existing static admission check; they are not a
replacement verifier or a second source of language rules.

## Explicit invocation and report

```text
hia-core-shadow --owned-run FUNCTION JSON_ARGS
hia-core-shadow --owned-run FUNCTION JSON_ARGS MAX_STEPS MAX_HEAP_BYTES FAIL_AT|none
```

Both forms read the complete document from standard input. The shorter form
uses 100,000 steps, a 1 MiB live-byte heap, and no injected allocation failure.
The longer form requires all three policy arguments. The profile accepts
1–1,000,000 steps, 0–16 MiB of live byte storage, and either `none` or a positive
allocation-attempt number. A zero-byte owner is a logical owner that does not
call the allocator. Object sizes above the canonical signed 64-bit limit fail
before a heap or allocator attempt. The heap budget is checked before an
injected allocation failure.

Execution reports use the new schema
`hepta.hia.rust-byte-owner-execution.v1` and profile
`single-block-byte-owner-v1`. They include the source digest, entry function,
execution policy, status, steps, scalar values or error code, and the complete
resource ledger. The general-resource, production-admission, whole-language,
native-refinement, and ABI/hardware claims remain false.

The ledger records allocations, frees, allocator attempts, owners created and
dropped, live owners/bytes, peak bytes, loans started and ended, and live local
loans. For v7, the canonical six chain counters are present and zero because no
chain opcode is admitted.

Successful returns require the explicit resource ledger to be clean. A trap
or exhausted budget reports the resources still live at that stop point,
matching Python Core. The shadow does not invent unwind drops. Rust eventually
reclaims its host containers when the execution function exits; that host
cleanup is not reported as an executed Hepta `owner.drop` or `loan.end`.

## Executed evidence

On 2026-10-27, Rust/Cargo 1.90.0 and `/usr/bin/python3` 3.12.3 executed the full
crate suite and all Rust shadow Python modules:

```bash
cargo test --locked --offline --manifest-path rust/hia-core-shadow/Cargo.toml
/usr/bin/python3 -m unittest \
  tests.test_hia_rust_shadow tests.test_hia_rust_owned_shadow \
  tests.test_hia_rust_calls_shadow tests.test_hia_rust_chain_shadow \
  tests.test_hia_rust_scalar_vm tests.test_hia_rust_crosscheck \
  tests.test_hia_rust_crosscheck_cli tests.test_hia_rust_owned_vm -v
```

Results: **52 Rust tests passed; 45 Python tests passed; zero skipped tests**.
The new dedicated Python module contributed 10 tests and **124 actual
Rust/Python full-ledger parity observations**. It builds the real binary using
Cargo's compiler-artifact executable path, verifies each positive document
with Python Core, executes both implementations, and compares every resource
field and its exact key inventory, steps, status, return values or error code.
Five additional Rust tests exercise the new public execution entry point.

The differential observations cover v1–v7 owner/move/drop execution, all small
byte read/write offsets, zero initialization, mutable and read reborrows,
suspended-parent length observation, zero-size and optional allocation,
failure at successive allocation attempts, heap/failure precedence, every
step boundary of the owner fixture, extreme offsets, oversized objects,
scalar overflow while an owner is live, and explicit traps with live loans.
Negative tests cover illegal aliases/loan lifetimes, fabricated public
handles, explicit non-exported entries, policies outside the finite bounds,
and hidden or unsupported program content.

This evidence establishes the tested finite interpreter correspondence. It
does not establish general resource execution, recursive resource calls,
chain execution, unwinding semantics, LLVM refinement, broad target support,
or production qualification. Future support must extend the same execution
profile deliberately and retain canonical Python differential evidence.
