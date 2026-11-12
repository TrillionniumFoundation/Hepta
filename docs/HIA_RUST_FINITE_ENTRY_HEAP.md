# Independent Rust finite-entry live-payload admission

`raw-byte-dag-finite-heap-v1` adds a static live-payload gate to the existing
[raw byte-DAG interpreter admission](HIA_RUST_BYTE_DAG_ADMISSION.md). It derives
an upper bound before executing the program. The computation is an independent
Rust abstract analysis, not a VM run, an imported Python certificate, or a
sampled allocation peak. The private admitted snapshot and the existing v4
Machine are shared with the original route.

This is an explicit extension of the finite primitive interpreter profile.
Default/source/nominal admission, native publication and their existing
authorities are unchanged. A report cannot construct an admitted program.

## Select the gate

The Rust library provides:

```rust
analyze_finite_entry_heap(raw_core, function, scalar_arguments, heap_policy_bytes)

admit_and_run_byte_dag_heap(
    raw_core, function, scalar_arguments,
    static_policy_bytes, heap_policy_bytes, v4_policy_bytes,
)
```

The first function returns analysis only. The second first performs the
existing all-function static admission, adds the exact-entry heap gate, and
executes the same immutable canonical Core through the existing v4 executor.
The executor still rechecks the module; no unchecked Machine constructor is
introduced. The corresponding CLI forms are:

```sh
hia-core-shadow --owned-finite-heap entry '[]' \
  '{"max_live_heap_bytes":19}' < primitive-core.json

hia-core-shadow --byte-dag-heap-admit-run entry '[]' \
  '{"max_allocator_interactions":8,"max_vm_ticks":100,"max_call_depth":3}' \
  '{"max_live_heap_bytes":19}' \
  '{"max_steps":100,"max_heap_bytes":19,"max_call_depth":3,"allocation_fail_at":null}' \
  < primitive-core.json
```

These commands require a matching program; limits are input policy, not
automatically valid certificates. The heap policy is exactly one field:
`max_live_heap_bytes`, an integer from 0 through 2^63−1 in at most 1024 JSON
bytes. Duplicate fields, booleans, floating values, extras and out-of-range
values refuse admission.

The existing Python actual-process API selects this mode only when
`max_static_live_heap_bytes=<integer>` is provided. Omitting it, or passing
`None`, preserves `raw-byte-dag-v1`. The Python layer checks bounded syntax,
the executable pin, exact request/response identity, report shape and ledger
consistency. It imports no heap analyzer or Core verifier. It does not rerun
the heap semantics to authorize a result.

## Bound meaning

The accepted input is primitive `hepta.hia.program.v7` or `v8`, with the existing
byte-only operation inventory and acyclic CFG/call graph throughout the entire
module. The entry must have exact scalar parameters/results and retain the
existing public-entry rule: when `exports` is present it must name the selected
function; when omitted, the legacy scalar-function boundary applies.
Unknown opcodes, chains, cycles and invalid ownership/loan/SSA/effect graphs
remain whole-module refusals, including inside uncalled helpers.

The heap statement is for the selected scalar invocation. It bounds the sum
of live byte-owner payload extents in the abstract Machine, including execution
prefixes stopped by any allocation failure, trap, or runtime budget. It does
not establish feasible-path optimality. Both CFG alternatives are analyzed even
when an exact entry argument would select only one. Maxima of distinct returned
owners are joined separately, so correlations can make the result conservative.

The analysis maintains these resource invariants:

- Each locally owned buffer has one upper extent. `owner.move` transfers that
  extent; `owner.drop` removes it. Zero-byte owners remain logical capabilities
  even though they contribute zero payload.
- On an owning call, moved buffers leave the caller's local inventory. The
  call's live peak is retained caller payload plus the callee peak, which already
  includes the moved buffers. Returned owners rejoin the caller. This counts a
  payload once across an ownership transfer.
- A borrowed formal is an external root whose payload is still counted in the
  caller. Shared aliases add no second copy of that payload. The whole-module
  verifier, rather than an extent assertion, enforces mutable-borrow exclusion.
- The v7 analysis treats external borrowed extents as unknown. The v8 analysis
  derives their upper bounds from the checked caller roots. It never accepts an
  extent annotation or resource object supplied through the scalar boundary.
  Parameter-bound returned loans are reattached to the verified caller root,
  including reordered multiple returns and nested reborrows.
- `buffer.len` produces the interval `[0, upper]`, not an exact successful
  allocation length. A fallible request may yield an empty owner. Its later
  length can therefore cause a *larger* subsequent request. Failure-index
  sampling never specializes the static result.

A request entirely above 2^63−1 has the existing allocator behavior: fallible
allocation yields an empty owner and false, while infallible allocation stops
that abstract path. The earlier live prefix still contributes to the bound.
An interval crossing the object-size boundary refuses. Unknown allocation
sizes, unsupported arithmetic facts and overflowing bound sums also refuse;
they never become zero-sized allocations.

Scalar abstract facts use checked finite-width intervals, exact wrapping
constants, conservative casts, shifts, division/remainder, bit masks, boolean
selection and scalar call results. Memory loads do not themselves provide an
extent fact. Several known arithmetic traps conservatively refuse analysis;
other unavailable facts stay unknown (for example an exact out-of-range checked
cast). Such an unknown may be harmless if never used to derive an allocation
extent. The analyzer does not claim a general arithmetic trap summary or use
an unproved unreachable path as a success guarantee.

## Three distinct budgets

| Policy | What it controls |
| --- | --- |
| Existing all-function static policy | Conservative VM ticks, allocator interactions and call depth for every function |
| New exact-entry static heap policy | Independently derived maximum live logical payload for this scalar invocation |
| Unchanged v4 execution policy | Actual interpreter tick/frame/payload limits and exact injected allocation-failure index |

A smaller runtime limit can intentionally stop execution even after static
admission succeeds. The actual stopped ledger remains in the result, including
live payload and owners not yet cleaned up. Admission does not promise success,
unwinding, or cleanup after a stop. The checked implementation additionally
rejects an internal inconsistency if the observed Machine peak exceeds the
independent static bound; observation is a check on that bound, not its source.

The analysis itself has fixed limits, enforced before additional abstract
copies or recursion:

| Counter | Limit |
| --- | ---: |
| Distinct function/abstract-argument contexts | 1,024 |
| Block/instruction/terminator transfer events | 32,768 |
| Root-inclusive abstract call depth | 64 |
| Cumulative abstract value creation/copy events | 262,144 |

The value counter includes wide argument vectors, CFG edge states and memoized
results; a short instruction trace cannot bypass it by forwarding very wide
state. These are bounded logical analysis-work measures, not compiler wall
time or RSS guarantees. Parsing and the existing whole-module verifier/static
audit retain their separate byte/tree/function/block bounds. Allocation in the
analyzer, transport and host process is outside the program-payload statement.

## Identity and authority

Analysis emits `hepta.hia.rust-finite-entry-heap.v1` with profile
`acyclic-byte-owner-transfer-v7` or
`acyclic-byte-owner-transfer-caller-borrowed-extents-v8`. It binds canonical
Core, schema, exact function/arguments, heap limit, peak, the existing static
report digest, entry structural metrics and actual bounded analysis counters.
Its status is `conservative_finite_invocation_payload_bound_not_authority`.

Combined execution emits `hepta.hia.rust-byte-dag-heap-run.v1` with profile
`raw-byte-dag-finite-heap-v1`. The request adds `heap_policy` and uses schema
`hepta.hia.rust-byte-dag-heap-request.v1`. Its digest covers the original raw
input SHA, canonical Core SHA, exact invocation, all three policies and profile.
The nested static report and `hepta.hia.rust-bound-execution.v4` retain their
existing formats and meanings. The Python invocation envelope is separately
versioned as `hepta.hia.rust-byte-dag-heap-invocation.v1`.

The combined route has scoped Rust interpreter admission authority and
`finite_entry_live_payload_limit_checked_before_execution=true`. Claims for
all-function input extent coverage, cleanup after stops, chains, RSS/native
stack bytes, source/native refinement, whole-language soundness and native
execution remain false. Primitive normalization performed elsewhere does not
give this route source or nominal public-ABI authority.

The pinned Rust binary, its loader/libraries/kernel, and calling transport
remain trusted. Exact identity and consistency checks reject stale or changed
replies; they do not prove an arbitrarily self-consistent forged computation
from a hostile selected executable. No imported report can grant authority.

## Reproduce the focused checks

```sh
cargo test --locked --offline --manifest-path rust/hia-core-shadow/Cargo.toml
python -m unittest -v tests.test_hia_rust_finite_heap \
  tests.test_hia_rust_byte_dag tests.test_hia_routes
```

The new actual-process corpus reuses existing partial-initialization, task,
borrowed-root and failure fixtures. It is a regression and differential suite,
not a new holdout or a model-development experiment. It includes all 121
existing partial-record cases, their 11 runtime-budget cases, v8 nested read
and mutable returned loans, multiple owner returns, shared aliases, failure
indices, cancellation and every tick stop in a mixed transfer example. The
Python heap analysis and Python Machine act only as separate test oracles.

Refusal controls use the actual fixed Rust context/depth/transfer/value limits;
they do not patch them to lower test thresholds. An analysis-only 1 TiB request
demonstrates a nonzero static bound with no attempted allocation; a combined
run stops before that allocation and preserves the zero observed peak. Byte
partition tests enumerate every concrete value in reviewed signed/unsigned
intervals against ordinary integer operations. Tampered captured reports are
used only for negative consumer checks. Current source-bound results and all
development failures belong in execution evidence, not in this contract as
inherited qualifications.
