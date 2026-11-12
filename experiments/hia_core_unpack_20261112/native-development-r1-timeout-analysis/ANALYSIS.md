# UNPACK development run 43207324933: original timeout and source costs

## Observed result

The complete 116-method phase failed at its unchanged 180-second deadline. Its
owner sent SIGKILL to the owned leader, observed return code -9, reaped it, and
then observed ECHILD with no cleanup errors or remaining direct children. The
source/input identity comparison stayed equal. Natural cleanup is not a natural
successful product exit. The final capsule remains HOLD.

This review read seven small original ZIP members, including all three caller
logs, the original request/guardian/FINAL and the installed report. Every selected
member passed ZIP CRC and matched the extracted bytes. The parent independently
owns the complete 159,656,529-byte ZIP custody; this analysis does not claim a
second whole-archive audit. `ORIGINAL-READBACK.json` retains exact member hashes,
all observed IDs, the missing IDs, and ten joins from the source files read here
to the real request and both guardian identity maps.

| Original group | Textual result | Reported unittest time |
|---|---:|---:|
| Component | 15/15, complete `OK` summary | 40.606 s |
| Original machine | 51/51, complete `OK` summary | 51.522 s |
| Original Core | First 28/50 each `ok`; no group summary | unavailable |

There are 94 completed method lines and 22 methods without a completion line.
Both complete caller JSON reports are absent. Consequently their in-memory
native counters and timing breakdown were not recovered and cannot be inferred
from the 94 textual successes. The two earlier preparation/component phase
successes are separate results, not a complete 116 pass.

The existing installed report is `INSTALLED_CORE_LOWERING_PASS`. It records
1,091 actual Core steps and 164 UNPACK returns, both UNPACK statuses 0 and 1,
profile 31404, four actual changed/missing source refusals and restored identity.
This is finite installed evidence; it is not a substitute for the missing
complete caller report.

## Exact stopping boundary

The last completed ID is
`tests.test_hia_program_native_review.DirectNativeProfileReview.test_public_loader_hook_symbols_rejected_before_object_publication`.
The next frozen ID is
`tests.test_hia_machine_lowering_edges.MachineLoweringEdgeTests.test_all_integer_cast_pairs_at_both_sides_of_each_destination_boundary`.
There is no printed `...` start for this next method.

The official CPython 3.14.4 `TestSuite.run` performs previous-class teardown,
module-fixture handling, and next-class setup before `TestCase` reaches
`TextTestResult.startTest`. The latter writes and flushes the method description;
the `ok` status is also flushed. The previous source class defines no custom
class teardown and neither adjacent module defines a module fixture. The next
substantive custom preparation is `MachineLoweringEdgeTests.setUpClass`.

This confines the gap to the transition/preparation before the next method. It
does **not** identify which operation was alive at SIGKILL, which of the five
documents had been reached, or an exact fixture duration. The ZIP's log mtime
is 11:18:36 with two-second ZIP precision; it is not a monotonic phase receipt
and must not be converted into an exact 23-second fixture duration.

That class prepares `arith`, `other`, `cast_checked`, `cast_wrap`, and `control`
in that order. Their source constructs 60, 110, 100, 100 and 5 functions. Each
document is explicitly emitted once; `compile_program_machine` independently
re-emits it for origin comparison before linking. If this setup completes, it
therefore performs ten ordinary emissions containing 750 function emissions.
The large-frame function alone contains 700 constants and 699 additions. These
are static workload facts; no claim is made that the complete workload ran in
this failed attempt.

## A concrete new cost: a fresh ctypes type for every unpack

`UnpackSession.__init__` currently executes:

```python
address = ctypes.cast(image._entry, ctypes.c_void_p).value
self.entry = ctypes.PYFUNCTYPE(
    ctypes.c_uint64, *([ctypes.c_void_p, ctypes.c_uint64] * 3)
)(address)
```

The retrieved official CPython 3.14.4 implementation of `PYFUNCTYPE` defines
and returns a new `CFunctionType` class on every call. In contrast, `CFUNCTYPE`
has an explicit signature cache. Thus every ordinary UNPACK session really
creates a new ctypes function-pointer **type**, as well as its function-pointer
instance. This is a source-established repeated allocation, not a measured
percentage of this timeout.

The smallest proposed correction caches only the fixed six-argument
`PYFUNCTYPE` type. It still reads each actual `image._entry` address and creates
a new pointer instance for each session. All fresh buffers, the Python/GIL
function flags, error state handling, HIA sources, packets, effect sequence and
reference-release order stay unchanged. No result cache, tuple shortcut,
buffer pool, generic iterator bypass, or cross-effect combination is proposed.
Factory monkeypatches and private pointer-type identity are not newly claimed
equivalent by this mechanical change. It requires a new source identity and
actual subsequent complete validation.

Official source original: `references/cpython-v3.14.4/Lib/ctypes/__init__.py`,
22,131 bytes, SHA256
`72f2df568380c275a5596944810953124ff2ee8d678c5f8ddcf50f0f77577eb3`.
All four retrieved CPython files and their URLs are pinned in
`CPYTHON-REFERENCE-PINS.json`.

## The remaining cost is a measurable question

For a normal successful unpack of arity `n`, the frozen HIA state machine asks
for GetIter, `n+1` Next operations, iterator DECREF, tuple allocation, `n` tuple
item transfers, result export, and tuple DECREF. The exact normal sequence is
listed in `STATIC-COST-ANALYSIS.json`.

| Arity | Primitive effects | HIA step returns | Transaction shim calls | Total machine crossings |
|---:|---:|---:|---:|---:|
| 1 | 8 | 9 | 7 | 16 |
| 2 | 10 | 11 | 9 | 20 |
| 3 | 12 | 13 | 11 | 24 |
| 4 | 14 | 15 | 13 | 28 |

Each session allocates 832 raw buffer bytes, excluding Python object overhead.
Each effect produces an ACK packet and each HIA request clears 32 output words.
Each transaction zeroes its 14-word frame and performs the error-state
restore/single primitive/error-state capture protocol. The qualifier also
records actual successful step returns after every native call, and each
session retains its own low-level step/primitive ledger. These operations are
visible in the source, but their time fractions were not measured here.

The low-level word helpers are already unrolled. Repeating that optimization is
not a justified next step. The `CpythonLeaves` executable mapping is created
by a cached admitted owner, **not** on every unpack; attributing a per-unpack
`mmap` cost would also be incorrect. The existing Core source admission and
origin re-emission remain required semantics and cannot be dropped for this
deadline.

The narrow ctypes-type cache is worth testing first because it removes a
specific repeated mechanism without changing the HIA policy. This record does
not predict its savings or claim that it will alone make 116 fit inside 180 s.
The new matching-cold gate draft still requires full 18 plus unsplit 116 under
the original independent deadlines; this failure does not relax either gate.

## Proposed progress evidence

`OBSERVABILITY-PROPOSAL.json` specifies a separate future source revision:
bounded JSONL events for group, test start/end and class/module preparation,
written once per transition, not per native primitive. Use the actual loader's
`suiteClass` for every nested suite, verify that all suites directly owning
the unchanged IDs use it, and preserve the original iteration order. The
CPython 3.14.4 private hook implementations are explicit dependencies.

A normal hook return, a caught fixture error, and propagation of a
`BaseException` need distinct events. A diagnostic error must not mask an
already active original exception. The log remains supplementary: no begin,
end, or `finally` event counts as a method PASS; the original loaded/executed
IDs and zero-anomaly result remain authoritative. All I/O is charged to the
same 180-second owner. The frozen product/capsule and actual failed run have
not been changed.
