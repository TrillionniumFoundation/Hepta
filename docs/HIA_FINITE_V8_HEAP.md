# Finite v8 invocation bounds with owned and borrowed returns

`qualify_finite_entry_live_heap_budget_v8` adds a separate requested-payload
qualification for resource combinations already legal in primitive v8. The
previous finite invocation API covers v7 owner movement and owner returns;
the previous v8 entry API covers borrowed local-peak summaries but refuses
owned call boundaries. Neither could qualify a function that returns both a
transferred owner and a parameter-bound loan.

This extension reuses the same canonical verifier, interval/CFG analysis,
context cache and resource transfer engine. It changes no Core opcode, borrow
rule, Python execution rule, Rust Machine or LLVM representation. The old
APIs retain their original schemas and version restrictions.

```python
from hepta.hia_heap_bound import qualify_finite_entry_live_heap_budget_v8

bound = qualify_finite_entry_live_heap_budget_v8(
    core, "entry", [9, False], max_live_heap_bytes=16,
)
```

The result uses `hepta.hia.finite-entry-live-heap-admission.v2`, profile
`acyclic-byte-owner-transfer-parameter-loans-v8`. It binds the original input,
canonical Core, public entry, exact argument snapshot, requested limit,
computed peak, existing static tick/allocator/frame bounds and analysis work.
Its SHA-256 binds those fields; it does not authenticate an imported receipt.
No runtime, optimizer or native gate acquires admission authority from this
report automatically.

## Accounting through calls

The abstract state retains separate owned extents and loan-to-root relations.
The existing canonical checker independently establishes legal ownership,
return origins, alias permissions and the complete resource CFG first.

| Transition | Payload treatment |
| --- | --- |
| Move an owner into a call | Remove it from the caller's sum; the callee's peak includes it. |
| Pass a borrowed view | Retain its payload in the caller. The callee's external root has unknown extent and adds no duplicate payload. |
| Return an owner | Restore the callee's conservatively joined returned extent in the caller. |
| Return a loan | Resolve its declared original formal to the actual caller argument and retain that actual's existing root. A returned view creates no payload allocation. |
| Rename through a CFG edge | Apply the same resource-name mapping to owners, roots and loans. |
| Join branches | Take conservative per-owner maxima and preserve the exact loan-root relation. |

Unknown external extent is not zero. A callee that allocates directly from
`buffer.len` of its incoming loan still rejects unless existing scalar transfer
rules establish a finite bound. After a loan returns to its caller, a known
caller-owned root can bound its length. Multiple shared actuals can alias one
root without counting that payload twice. Mutable argument aliasing remains
subject to canonical v8 refusal.

Returned-loan summary positions do not carry invented byte sizes. They are
checked external formal roots, then reconnected using the already verified
`return_loans` interface at each call. A non-first loan result or a result whose
origin order differs from parameter order retains its selected actual root.
The regression with 3-byte and 11-byte roots returns them in reverse order,
then allocates from the first returned length: its peak is 25 bytes, and a
24-byte policy rejects. Substituting the smaller root would underestimate this
program and fail the independent operational observation.

## Failure, cancellation and stopped ledgers

The mixed-transfer fixture retains a 3-byte caller owner, transfers a 4-byte
owner into a helper, and may replace it with a 9-byte allocation. That helper
also returns a nested parameter-bound read loan. Its possible peak is
`3 + 4 + 9 = 16` requested payload bytes. After return, a further allocation
from the returned view's length needs only 3 bytes, producing a smaller
`3 + 9 + 3 = 15` peak.

The normal path returns 12 and explicitly releases every owner and loan.
Cancellation before replacement returns the original owner and 7; failure of
the replacement allocation does the same. Those paths reach a 10-byte peak
when the later scratch allocation succeeds. The analysis keeps its
conservative 16-byte bound even for an exact cancellation argument because it
does not assume branch reachability from that argument.

An infallible early allocation failure traps. A step, heap or call-frame limit
stops before further execution. These paths retain the actual live resource
ledger; no cleanup is fabricated after the stop. Successful cooperative task
cancellation is tested separately using the existing composite v4 partial
owner/task fixture. Its returned loan ends inside polling before task state
is carried onward. This does not admit a loan stored across suspension or add
asynchronous cancellation/unwinding.

## Finite scope and refusals

The public entry and results remain scalar. The entire verified module must
use the audited primitive v8 byte-owner operations and acyclic CFG/call
graphs. Unknown instructions, chain types (including unused helpers),
recursion and loops reject. The selected invocation is analyzed with the
existing limits of 1,024 calling contexts, 32,768 abstract-transfer steps and
64 analysis frames. Exhausting a limit yields a refusal, never a guessed
bound. These analysis limits are distinct from the runtime's frame/tick limits.

All syntactic branches are conservatively included. Fallible allocation is
bounded by its possible successful size, with the existing oversized-object
guard handled before an allocator request. The bound covers allocation
failures, explicit traps and finite execution prefixes. Per-result joins may
overestimate correlations; this is an upper bound, not a claim of minimal
memory use or global optimization.

The metric is simultaneously live requested byte payload. It excludes
allocator metadata, runtime view objects, process RSS, native stack bytes,
foreign/device memory and elapsed time. Resource legality and this payload
bound do not prove optimization equivalence, source refinement, final machine
code refinement or whole-language safety.

## Actual independent checks

`tests/test_hia_finite_v8_heap.py` covers mixed ownership/loan returns, nested
helpers, CFG renaming, reordered asymmetric origins, shared aliases,
allocation failure, explicit cancellation and all step prefixes of the mixed
fixture. It also qualifies existing composite v4 partial owners and task
cleanup through their real primitive v8 normalization.

The actual Rust checker/Machine independently parses those normalized Core
bytes and compares complete values, ticks, trap/budget reasons and resource
ledgers with Python. The bound-v2 transport exercises insufficient 1–3 frame
limits and the sufficient four-frame case. Invalid origins and ending a
suspended parent are independently refused before an immediate runtime stop
can hide them. Rust does not independently elaborate nominal source here.

The Linux Clang method compiles and executes the same mixed-transfer Core
with an independent allocator observer. It compares allocation attempts,
allocations, frees, peak/live bytes and results on normal, allocation-refusal
and explicit cancellation paths. VM stop limits are not asserted to exist in
that native executable. Native abort cleanup is not inferred from the normal
observer runs.

```sh
python -m unittest -v tests.test_hia_finite_v8_heap \
  tests.test_hia_partial_finite_bounds tests.test_hia_returned_loan_budgets \
  tests.test_hia_composite_returned_loans
```

Cargo and Linux Clang must actually be available; skipped methods cannot
qualify those layers. Setting `HEPTA_FINITE_V8_EVIDENCE_DIR` to an external
output directory retains Rust build records, canonical inputs, complete
execution/refusal observations and native driver/object/executable files with
their identities. Evidence identifies that run; it never authorizes reuse of
a self-reported success as a proof.
