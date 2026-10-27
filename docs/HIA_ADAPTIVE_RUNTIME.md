# Finite trusted native adaptation at empty-state call boundaries

`hepta.hia_adaptive.AdaptiveRuntime` implements actual native multiversion
selection for a deliberately closed, total scalar profile. The versions are
independently emitted LLVM shared libraries. Calls execute machine code through
the selected C ABI function; they are not interpreter placeholders or mocked
switches.

## Admitted state and safety boundary

An admitted program has exactly one exported function, one block ending in a
return, one to eight u64 arguments, and one u64 result. Scalar intermediate
values may be u64 or Boolean. The operation whitelist contains constants,
wrapping add/subtract/multiply, bit operations, comparisons, Boolean operations
and select. There are at most 4,096 operations.

Checked arithmetic, division, shifts, calls, loops, traps, allocation, owners,
loans, arbitrary imports and every external effect reject. Consequently there
is no admitted source-level trap that could abort the host through a legal
input, and no foreign side effect to roll back. The native compiler, linker,
loader, Python host, operating system and hardware remain trusted. This is not
a proof that a buggy compiler or compromised host cannot crash.

The complete program state schema includes the Core version, target, C calling
convention, entry name, argument names/types, return types, empty persistent
value/owner/loan/effect inventories, and the entry continuation with no active
call frames. Candidate and current schemas must agree exactly.

**Empty-state selection does not implement general live-state migration.**
Live owner/loan programs reject at admission. The implementation does not move
heap graphs, rewrite stack frames, migrate tasks or rebind active references.
Those are separate unsatisfied obligations.

## Authority and executable identity

The runtime receives Core programs. It never accepts a producer's verification
JSON, performance estimate or precompiled shared object as deployment authority.
`prepare` replays Core verification and `build_optimized_native`; the latter
independently verifies the transformation against the current program before
building exact candidate bytes.

The native artifact is read through a bounded, no-follow ordinary-file
descriptor. Its bytes are checked against the internally obtained build
identity and Core identity, copied into a Linux memfd, and sealed against
writing, shrinking, growing and removal of seals. The loader opens that sealed
descriptor. The original publication pathname is not reopened during dispatch
or selection. Replacing that pathname after loading cannot replace the loaded
code. A changed artifact before loading is refused.

Preparation returns a process-local registered token. Unknown tokens and
serialized receipts cannot name executable versions. At selection, equivalence
is rechecked from the actual immutable Core programs; checker/emitter/runtime
identity, complete state schema, sealed bytes and generation are rechecked.
An active generation change or stale implementation refuses selection.

At most sixteen versions may be loaded or preparing. A reservation closes the
concurrent-build limit race. Old versions remain loaded during operation so
reverting at a later safe point does not invalidate an earlier function pointer.
Explicit `close` (also available through a Python context manager) requires no
active dispatches or builds, then closes each dynamic library and sealed fd.
The retained build files are evidence artifacts, not live resource handles.

## Safe points and execution

The dispatcher holds a lock while choosing a version and incrementing its
active dispatch count. The native call executes after releasing the lock.
The count is decremented in `finally`. Selection and close require the count
to be zero under the same lock.

`call_many` validates at most 65,536 argument vectors, pins one version for the
whole batch, and executes each vector exactly once. The active lease remains
held through the batch; this is stricter than switching between its individual
function calls. No original request is retried after an exception, interrupted
batch or failed selection. Completed calls and incomplete batches are recorded
separately. Unknown completion never turns into a replay.

The event ring retains at most 4,096 raw events. Total event counts, per-kind
counts, completed application/shadow native calls, and the number of discarded
old raw events remain available separately. This bounds the in-memory audit
buffer; it is not an unlimited persistent audit archive. A completed shadow
measurement is stored only after rechecking that the runtime remains open and
its generation/current program and implementation identity still agree.

Only exact Python integers in the u64 domain are accepted. Booleans, negative
values, oversized values and wrong arities reject before native entry.

## Explicit and automatic selection

`select(token, mode="explicit")` is an operator-requested selection. It still
enforces all semantic, artifact, state and safe-point gates. It does not claim
the candidate is faster.

Default `mode="auto"` always retains the current version and reports
`automatic_profitable_selection_supported=false`. Measurements execute actual
paired native shadow calls with alternating order and compare all outputs.
They are bound to the current generation and candidate artifact; their returned
dictionary is a copy, not an authority object. The measurement mode is explicitly
`conservative_shadow_only`.

The current accounting subtracts candidate preparation (verification, build and
load) and all measured shadow/profiling wall time from the observed timing
difference; explicit selection records its additional measured cost. It does
not accept a producer's predicted speedup, hide
failed preparations, assume a free model, or extrapolate a future amortization
horizon. Stale, missing or nonpositive evidence never changes the current version.

This one-shot experiment **cannot** demonstrate profitable automatic selection
under its own complete-cost accounting. If original and candidate timings are
`B` and `C`, the measured experiment wall time `M` includes both, so `M >= B+C`.
For preparation cost `P`, the reported `B-C-P-M` is at most `-2C-P`. This is an
explicitly unsupported policy, not an unreachable condition presented as an
implemented adaptation strategy. The qualification retains the baseline for
automatic requests and tests real switching through the explicit operator path.
A long-horizon policy with independently obtained workload commitments, measured
uncertainty and honest amortization accounting remains future work. No global
optimality, universal speedup or general resource-state migration is claimed.

## Reproduce the actual native qualification

Linux Python must expose actual memfd sealing constants; their absence fails
closed. The qualification used the host `/usr/bin/python3`, pinned Z3 4.13.4 and
Clang 20. It did not substitute an unsealed file for a missing capability.

```sh
PYTHONPATH=/path/to/pinned-z3 \
/usr/bin/python3 tools/qualify_hia_adaptive.py \
  --workdir /tmp/new-adaptive-qualification --clang /usr/bin/clang-20

PYTHONPATH=/path/to/pinned-z3 CLANG=/usr/bin/clang-20 \
/usr/bin/python3 -m unittest tests.test_hia_adaptive -v
```

The actual development qualification uses `x+y` and the equivalent wrapping
expression `(x^y) + 2*(x&y)`. It requires their actual native artifact hashes to
differ, so selecting a second copy of identical emitted bytes cannot satisfy
the multiversion qualification. The candidate is not claimed to be faster.

The qualification retains:

- 131 inputs through both original and explicitly selected native versions,
  including unsigned wrap boundaries and deterministic random values.
- Four actual concurrent threads, each executing 65,536 native calls; all
  262,144 results agree with an independent integer oracle.
- A selection request and close request refused while those real native calls
  hold active dispatch leases; a later quiescent return to baseline succeeds.
- A real changed-artifact refusal before loading, an actual `EPERM` response to
  writing the sealed fd, and correct native calls after publication-path tamper.
- Rejection of an inequivalent candidate, fabricated receipt, expired internal
  measurement and caller-modified telemetry copy.
- Full internal verification/native build receipts, measured costs, native
  results, decision/refusal events and current-version/generation observations.

The unit suite additionally checks possible-trap/owner rejection, complete ABI
compatibility, typed input boundaries, stale generation measurements and actual
descriptor closure/reopening. These finite checks are distinct from whole-
runtime refinement and do not qualify arbitrary production workloads.
