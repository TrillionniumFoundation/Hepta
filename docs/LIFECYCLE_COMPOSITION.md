# Finite lifecycle composition qualification

`examples/composition/lifecycle.hepta` combines concrete uses of Owned generic
functions, Result error exits, mutable and copied shared stored views, ownership
transfer into workers, cooperative cancellation and joining. This qualification
uses the existing Rust backend. It does not add these facilities to the new
Executable Core or make the separate compiler profiles equivalent.

Run the complete fail-closed qualification with the pinned toolchain:

```sh
PYTHONDONTWRITEBYTECODE=1 \
RUSTC=/tmp/hepta-ai-rust-1.90.0/bin/rustc \
python3 -m tools.qualify_lifecycle_composition \
  --output NEW-lifecycle-composition.json
```

`--report` is an alias for `--output`. The destination must be new; earlier
reports are never overwritten. Without either option, the complete JSON report
is printed. Missing tools or a failed check produce a nonzero exit and a failed
report; there is no native skip or mock qualification path.

## Scope, static checks, runtime evidence and external premises

| Area | Exact scope | Static checks | Actual runtime evidence | External premise / remaining boundary |
| --- | --- | --- | --- | --- |
| Owned generic functions and Result | `forward<Buffer<u8>>`, `finish<Buffer<u8>,u8>` | Explicit transfer/consumption in Hepta; generated bodies checked by Rust | Normal result `136`; explicit error result `1013`; corresponding registered owners are freed | Compiler/standard-library correctness; no general generic composition theorem |
| Stored views | `Bytes` and `Edit` records borrow an owner inside one worker | Hepta structural/affine rules followed by actual Rust region and alias checking | Mutation, copied shared views and summation produce expected values | Hepta frontend alone does not establish these lifetime obligations |
| Tasks and cancellation | Three owned buffers cross task boundaries; every task is joined once | Owner reuse, missing join and repeated join reject | Cancelled worker observes the flag, consumes its owner and returns `2253` | Scheduling and progress; no cancellation deadline or arbitrary-schedule termination proof |
| Owner allocation observation | Three registered addresses, capacities 17/19/23, with allocation generations | Separate Rust instrumentation; exact generated-code edit sites checked | Three observed allocator callbacks and three matching deallocations, no live registered owner | System allocator contract; excludes all other process/thread allocations |
| Other profiles | Entire unchanged source module | C backend, independent Resource IR and Executable Core reject | None of these profiles executes this composition | No combined universal profile or cross-backend equivalence claim |

## Three source branches

The worker takes ownership, forwards its Buffer through an Owned generic,
creates a mutable stored view, fills bytes 1 through the end, and explicitly
consumes that view. It then copies a shared view and computes a sum. The final
shared-view use precedes moving the owner into `finish`, so Rust can end that
borrow before the ownership transfer.

- Mode 0, length 17: summing 1 through 16 returns **136**; the accepted owner is
  consumed before the normal return.
- Mode 1, length 19: `finish` consumes the rejected owner and returns `Err(13)`;
  the worker returns **1013**.
- Mode 2, length 23: the worker computes 253, observes its cooperative
  cancellation flag, consumes the retained owner and returns **2253**.

The original, unmodified generated Rust is compiled and executed separately.
Its exact stdout is `136\n1013\n2253\n`, its stderr is empty and its exit code
is zero. The report stores the original Hepta source, the complete original
generated Rust, compilation receipt, binary hash and raw process transcript.

`cancel_and_join` may set the cancellation flag before the worker starts or
before its first poll. The result therefore demonstrates cooperation and join
completion for this execution. It does not demonstrate forcibly interrupting
an already blocked worker, a maximum cancellation latency, or termination under
every possible schedule. Runtime traps use `panic=abort`; cleanup on unwinding
is not covered.

## Address-based allocator observation

An additional generated-Rust artifact installs a `GlobalAlloc` wrapper around
`std::alloc::System`. It uses a fixed table of atomics and no dynamic allocation
inside the observation lock. The wrapper records actual `alloc`/`alloc_zeroed`
callbacks for the selected capacities, including their returned addresses.
Before `payload` returns its Buffer, an inserted registration call associates
that Buffer's actual `as_ptr()` and capacity with one observed allocation.
Deallocation callbacks close the matching live allocation record.

The registry never reuses a slot. If the system allocator reuses an address for
a later Buffer, that allocation receives a new generation; it cannot erase the
earlier owner's free event. The three owners' identity is established by exact
address registration, not by allocation size alone. A missing callback,
unexpected capacity, table exhaustion, duplicate live address or tracked owner
reallocation rejects the observation.

After all joins finish, the instrumented program emits a JSON observation on
stderr. The report retains it verbatim and also validates its parsed owner
records. Successful qualification requires **3 allocations, 3 frees, 0 live
registered allocations and 0 live registered bytes**, with one allocation/free
pair for each mode. This observes only these three buffers; Rust thread setup,
Arc state, I/O and other process allocations are outside the denominator.

The observer changes the generated program and can change scheduling. Its
binary is clearly separated from the original unmodified binary. Neither
performance nor allocator behavior of every implementation is inferred from it.

### Actual induced-leak control

A third artifact replaces the two `drop(h_retained)` calls in the instrumented
Rust with `mem::forget(h_retained)`. This is an explicit mutation of generated
Rust, not an accepted lowering of the Hepta source. The generic error branch's
drop remains present.

The corrupted implementation still prints the same three numerical results.
The observer must nevertheless find **3 allocations, 1 free, 2 live registered
allocations and 40 live bytes** and exit **91**. This verifies that numeric
correctness alone cannot pass the resource observation and that the observer
detects a real missing deallocation. The deliberately leaked buffers exist only
inside that short-lived control process.

## Six dangerous source neighbours

All mutations are exact, counted replacements of the fixed source. None of the
six invalid Hepta candidates is executed.

| Candidate | Preliminary Hepta frontend | Required rejection | Native linking/execution |
| --- | --- | --- | --- |
| Shared snapshot used after the owner moves into `finish` | Accepts | Actual Rust **E0505** | Metadata-only; never linked or run |
| Owner read while a mutable stored view is still used by its later drop | Accepts | Actual Rust **E0502** | Metadata-only; never linked or run |
| Generic error branch omits owner consumption | Rejects | **E_LINEAR_UNCONSUMED** | Not compiled |
| Named payload reused after transferring it to `spawn` | Rejects | **E_USE_AFTER_MOVE** | Not compiled |
| Cancellation path omits `cancel_and_join` | Rejects | **E_LINEAR_UNCONSUMED** | Not compiled |
| Task joined a second time | Rejects | **E_USE_AFTER_MOVE** | Not compiled |

The two Rust rejections retain full compiler stderr, command, exit code,
generated source and Hepta source mappings. The qualifier requires that no
metadata artifact was emitted. A successful structural frontend check is never
promoted into independent lifetime verification.

## Evidence identity and reproduction

The JSON report binds the exact Hepta source, qualifier implementation, compiler
implementation, Rust executable/toolchain, generated source and native binary
hashes. It retains raw stdout/stderr and their hashes, all negative source
variants, Rust diagnostics, the allocation observation and the separate leak
control. The report's `scope_static_runtime_external` table mirrors the table
above. Its explicit denominators are:

- One original program execution with three source branches.
- One independent observer execution covering three registered owners.
- One generated-Rust leak control execution.
- Two metadata-only Rust lifetime rejections.
- Four frontend-only rejections.
- Zero executions of invalid Hepta candidates.

Temporary native binaries are removed after their execution and identity are
recorded; `artifact_retained: false` makes this explicit. Full source inputs and
generated text remain in the report so the artifacts can be rebuilt. Temporary
pathnames in commands identify the actual run, not retained filesystem entries.

`validate_report(report)` replays source-derived frontend/profile checks and
validates hashes, counts, exact generated edits, tool identity and process
transcripts. It does not rerun native binaries or turn a report into a
cryptographic execution attestation. Changed claims, missing negative cases,
forged aggregate balances and altered original generated code are regression
tests even when the outer report hash is recomputed.

```sh
PYTHONDONTWRITEBYTECODE=1 \
RUSTC=/tmp/hepta-ai-rust-1.90.0/bin/rustc \
python3 -m unittest tests.test_lifecycle_composition -v
```

The native test class explicitly skips when Rust is absent, as normal for a
portable unit-test suite. A skipped test run is not qualification; use the
standalone command for the acceptance gate.
