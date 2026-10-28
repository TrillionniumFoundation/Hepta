# Executed Rust byte-owner shadow: finite profile

The earlier `cfg-call-byte-owner-bulk-v3` profile has been superseded by
`cfg-call-byte-owner-chain-v4`. The same Machine now executes primitive v7
recursive buffer chains, with iterative destruction and shared allocation/loan
ledgers; see [the chain extension](HIA_RUST_CHAIN_VM_20261027.md). Historical
execution results below retain their original source and profile scope.

The existing Rust scalar `Machine` now has an explicitly enabled, bounded byte
storage component. `--owned-run` executes a finite primitive HIA buffer/loan
profile after the existing `verify_owned` admission check. This does not change
Python Core authority, the production CLI, the native backend, or the
Python/Rust verifier crosscheck protocol. `--scalar-run` still rejects resource
programs.

## Execution boundary

The input must be a primitive `hepta.hia.program.v1` through `v7` document.
Its externally invoked function must have scalar parameters and returns.
Internal functions may consume/return byte owners and receive borrowed views;
borrowed returns remain forbidden by the existing verifier. Multiple blocks,
`jump`/`branch`, loops, and bounded recursive calls use the existing `Machine`.
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
| `buffer.fill`, `buffer.copy` | v2 full-owner fill and distinct-owner prefix copy |
| `buffer.move_within` | v3 checked in-place movement with overlap-safe memmove behavior |
| `buffer.swap` | v4 checks both offsets before either write, including identical-offset swaps |
| `buffer.copy_range`, `buffer.fill_range` | v5/v6 checked offsets and lengths; zero-length ranges still require valid endpoints |
| `call` | Consumes owner arguments, preserves allocation identity and binds independent formal loan witnesses |
| `chain.empty`, `chain.try_push`, `chain.pop`, `chain.is_empty` | v7 chain ownership, 24-byte node allocation, failure-preserving tail/payload transfer and checked consumption |
| `chain.head_read`, `chain.head_mut` | v7 head-payload loans; empty heads trap and live loans block chain consumption |

The existing scalar operation implementation is reused. Public resource
entry/return types and direct nominal/composite documents remain outside
this execution profile. Primitive operations outside the profile produce
`E_HIA_RUST_UNSUPPORTED`. A direct nominal document fails the existing strict
primitive-schema check with `E_HIA_FORMAT`; no new schema fallback is installed.

Resource handles cannot be supplied or returned through JSON. Runtime owner
and loan maps supplement the existing static admission check; they are not a
replacement verifier or a second source of language rules.

Bulk memory operations use the same owner and loan identities as byte access.
Range validation uses offset/extent subtraction before calculating an end
offset, so extreme `usize` values trap without arithmetic wraparound. Every
source and destination range is checked before modifying storage. Empty ranges
at an owner's end are admitted, while offsets beyond the end still trap even
when the length is zero. Copy requires distinct roots; move uses safe Rust
`copy_within` for either overlap direction. Distinct-root copies obtain disjoint
map entries through a safe double-ended iterator, without moving owners or
allocating a temporary proportional to the copy length. These operations do
not add language allocations, frees, or loan transitions. Host allocation and
out-of-memory behavior are not a cross-implementation equivalence guarantee.

Each borrowed call formal receives a distinct runtime identity and the exact
permission in its signature. Two readonly formals may alias a mutable caller
loan: reborrowing one suspends that formal, not its readonly sibling. All actual
views are checked before introducing formal witnesses. On normal return,
formal witnesses are retired without changing the source loan counters; a
callee cannot end its caller's loan. Owner arguments consume their caller SSA
bindings before invocation, including when a call-depth/step budget then stops
the program. These are the compatible semantics carried forward from PR #322
at `108762baaefedde931f4160dbeadb6442fbb824b`; its separate v1-only VM and JSON
options interface are not introduced alongside the shared Machine.

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
`cfg-call-byte-owner-chain-v4`. They include the source digest, entry function,
execution policy, status, steps, scalar values or error code, and the complete
resource ledger. The general-resource, production-admission, whole-language,
native-refinement, and ABI/hardware claims remain false.

The ledger records allocations, frees, allocator attempts, owners created and
dropped, live owners/bytes, peak bytes, loans started and ended, and live local
loans. For v7, the canonical six chain counters report created/consumed
descriptors and created/dropped/live nodes. They remain zero in programs which
do not execute chain operations.

The `byte_owner_cfg_and_calls`, `byte_owner_bulk_memory`,
`v7_recursive_buffer_chain_execution` and `scalar_public_entry_only` scope claims are
true; the old `single_block_scalar_entry_only` claim is false. The CLI and its
finite heap/step limits remain compatible with the earlier byte-owner profile.
Exactly 32 call frames are admitted; a thirty-third invocation stops before
its entry tick. Unsupported content is rejected across the entire module,
including an uncalled helper. A valid internal chain-typed signature is
admitted; the external JSON entry still cannot carry its handles.

Successful returns require the explicit resource ledger to be clean. A trap
or exhausted budget reports the resources still live at that stop point,
matching Python Core. The shadow does not invent unwind drops. Rust eventually
reclaims its host containers when the execution function exits; that host
cleanup is not reported as an executed Hepta `owner.drop` or `loan.end`.

## Executed evidence

### Historical implementation before workspace recovery

The initial local implementation commit was
`44e586d728cb637f91c149e856db5d741ab7cc85`, based on
`ddac4e3de71794853ccef2d012a43eb40a97d39e`. Its earlier development run recorded
52 passing Rust tests, 45 passing Python tests and 124 full-ledger differential
observations. The original scratch logs and manifest were lost when the
workspace was reclaimed. Those counts describe that historical source only;
they are not retained execution evidence for a recovered or integrated SHA.

### Recovered implementation: fresh execution

The recovered implementation was actually rerun from clean commit
`79e5dbc8916a3e426e0bf97cfcc94216a5856de5` on 2026-10-27, from
13:53:52 UTC to 13:54:05 UTC. Rust 1.90.0
(`1159e78c4 2025-09-14`), Cargo 1.90.0
(`840b83a10 2025-07-30`) and `/usr/bin/python3` 3.12.3 executed these two
commands with `CARGO_NET_OFFLINE=true` and the external
`CARGO_TARGET_DIR=/workspace/scratch/d930f2b45e07/rust-recovery-target`:

```bash
cargo test --locked --offline --manifest-path rust/hia-core-shadow/Cargo.toml
/usr/bin/python3 -m unittest \
  tests.test_hia_rust_shadow tests.test_hia_rust_owned_shadow \
  tests.test_hia_rust_calls_shadow tests.test_hia_rust_chain_shadow \
  tests.test_hia_rust_scalar_vm tests.test_hia_rust_crosscheck \
  tests.test_hia_rust_crosscheck_cli tests.test_hia_rust_owned_vm -v
```

Results: **52 Rust tests passed; 45 Python tests passed; zero skipped tests**.
The tracked source was clean before and after execution; HEAD and every
recorded implementation/authority source hash remained unchanged. These are
scoped development results for the exact recovered commit above. They do not
qualify the later integrated source SHA or substitute for its 35-gate run.

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

The fresh logs and manifest are retained under
`/workspace/scratch/d930f2b45e07/hepta-rust-recovery-validation`. The manifest
records the tested HEAD, toolchain versions, complete command arguments,
process results, timestamps, source hashes and unchanged-source checks.

| Artifact | SHA-256 |
| --- | --- |
| `cargo.log` | `b6bc7151a8b325081d8e3818f1bcd26b087c6317e5dd90e52ada19cc26c1192b` |
| `python.log` | `4840162da1ac456eb87b1d1a4248d958d36aa0e0c52d89de6b9fc11b740ec3f8` |
| `validation.json` | `c8e159dbc12846c148e8494c390c6d26befb4a68bfa1a4abda6afaf1b97e0a9b` |

That historical evidence establishes only the single-block profile tested at
the recorded SHA. It does not qualify the later CFG/call extension above.
The new tests in `tests/test_hia_rust_owned_cfg.py` compare complete ledgers,
steps, trap/budget codes and results for loops, joins, owner transfer, nested
borrowed calls, aliased readonly formals, allocator failures and recursive
call-depth stops. Their native test independently links emitted LLVM objects
with an instrumented C allocator. Fresh command results belong in the current
source-bound execution record; historical counts are not reused.

The later `tests/test_hia_rust_owned_bulk.py` extends the actual executable
comparison to all six v2-v6 byte operations. A separate list model computes a
weighted checksum so byte ordering and untouched ranges remain observable.
It checks small offset domains, both copy allocation orders, overlapping
moves, empty ranges, extreme offsets, readonly and aliased-loan refusals,
formal readonly siblings sharing a mutable caller view, allocation failure,
and every step boundary of two borrowed-call fixtures. The previously
registered byte-swap baseline and its exact candidate are now both executed
by the independent Rust VM. Their different instruction counts are preserved;
this does not assert step-budget equivalence across the rewrite.

The bulk native test compiles the exact combined Core through the LLVM emitter
and links a separate C driver that observes allocator attempts, successful
allocations, frees, live allocations, return values and actual aborts. It
includes bounds failures and injected allocation failures. These are finite
observations, not an all-input equivalence proof. Old unsupported-operation
tests now use still-unsupported chain operations rather than newly admitted
bulk operations; chain and raw nominal rejection remain required.

No result here establishes general resource execution, chain execution,
unwinding semantics, LLVM refinement, broad target support, or production
qualification. Every extension must retain canonical Python differential
evidence and explicit unsupported boundaries.
