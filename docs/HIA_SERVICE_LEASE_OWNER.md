# Four complete service lease control graphs

## Status and exact scope

This is a static candidate. Its HIA source has not been generated, no original
oracle has been executed, and no Source, VM, Native, SQLite, worker, installed,
resource, or caller gate has passed for this candidate. The four retained class
bodies remain byte-for-byte originals. Public lazy dispatch is an explicit new
binding; an old AST check of the retained body does not prove the public route.

The original methods are HIAAgentService.acquire_slot, _lease, invoke_lease,
and release_slot. HIA owns their branch, loop, with-exit, return, and
exception-continuation decisions. There are four modes and 54 fixed ports.
Public signatures remain unchanged. Canonical class calls and instance calls
both reach the selected dispatcher; instance/subclass overrides retain Python
lookup semantics.

| Mode | HIA control | Existing external primitives |
| --- | --- | --- |
| acquire | transaction special lookup, enter, ledger/reference choice, result, normal/exception exit, suppression | original self.store.transaction(), ledger acquire, snapshot/native callbacks |
| lease | ledger/reference choice and final return | original dynamic ledger or retained reference provider |
| invoke | both imports, dynamic _lease, tuple unpack, kind/signature checks, snapshot branches, validation, context, runner, captured-buffer loop, final result | original runner/validator, object protocols, Store publication |
| release | transaction special lookup, enter, independent ledger reads, return, normal/exception exit, suppression | original ledger/reference release |

No port calls any of the four retained complete methods. The old
_reference_slot_acquire, _reference_slot_lease, and _reference_slot_release remain
explicit original providers when _slot_ledger is None; preserving that original
public domain does not make those fallback providers native. The installed
joint gate selects the existing Slot decision and multi-SQL controllers and
poisons all three reference providers. This component does not rewrite those
controllers or SQLite itself.

## Object and exception protocol

Original explicit globals are resolved in the original namespace and captured
builtins mapping at their original evaluation position. The two import ports are
literal imports in functions defined in the service module, not early imports
of the runner and validator. The outer decode_data(wire(...)) callees are
captured before evaluating the tuple/list conditional. HIA selects every branch,
including the case where a replaceable reject provider returns normally.

Each ledger predicate and subsequent method receiver are separate dynamic
lookups. The entire captured-buffer append/Store-put expression remains one
literal primitive, preserving method lookup and dictionary expansion order.
The loop's implicit iteration does not depend on a replaceable global iter.

Acquire and release have no 'as' target. The manager and enter callable are
consumed at their original protocol positions. An enter failure does not call
exit. A normal exit result is discarded without a truth test. Exceptional exit
and its truth test execute inside the actual active exception handler.
Suppression reaches the original function end and returns None; it does not
reenter another provider branch. A failing exit replaces the pending return
according to the original exception path. HIA owns the cleanup directives.

The adapter uses fixed module-owned probe classes for runtime special lookup
and local release ordering. It does not guess a Python version threshold, create
a per-call surrogate class, call GC to normalize results, clear a user traceback,
or rewrite exception metadata. Normal completion transfers the original local
storage rather than clearing locals retained by a handled traceback. Complete
finite tests retain raw exception fields, weakrefs, requested explicit GC counts,
destructor events, and active-exception identity. These comparisons are required
before claiming this finite domain equivalent; extra Python adapter traceback/GC
objects remain a real possible failure, not an allowed normalization.

## Delivery and resource custody

INIT is before the first original foreign effect. Each primitive has a separate
claimed request and exact returned receipt. The whole method also owns a
weak-registered capture activation surviving individual port ACKs. HIA first
issues READY_RETURN or READY_PROPAGATE; after the actual outer foreign scope
exits, a distinct FINALIZE confirms the complete method. Only then does the whole
capture retire. A failed FINALIZE is not retried.

The implementation reuses DeliveryRecord/ForeignCall. It adds no registry,
path-based resource identity, SQL retry, or exception-class inference of loss.
It captures only actual child/registered resource observations, not a speculative
service.store receiver. An unused Store A is not associated merely because a
callback uses B. Weak captures cannot resurrect a dead or unregistered resource;
an opaque provider's internal effects do not become covered by this component.

Unknown native/child delivery prohibits a later business effect or success ACK.
The control does not run arbitrary user cleanup after losing authority. For a
real transaction, the resource control separately checks that a lost body
outcome does not COMMIT. Healthy ordinary errors remain ordinary and exercise
real rollback. An unfinished arbitrary context manager after unknown delivery
is an explicit custody boundary, not a successful close; each injected resource
control has its own supervised process.

## Independent qualification

The fixture contains four exact original bodies and 258 explicit inputs. No
expected output exists yet. For each backend, two fresh children execute only
the original bodies and strict fake providers. Their raw records must agree
before an expected seal is written. A third fresh child observes the selected
public VM/Native route or actual unselected public route against that seal.
Expected values are never generated by a candidate.

All observations are preserved. Each runtime produces its own originals; no
historical 3.12/3.13/3.14 output is substituted. Every VM entry uses a fresh
generic Machine with the unchanged 4,000,000 steps, 16 MiB scratch and depth 128.
The explicit prepared program only removes repeated admissible decoding; no
business-specific fast path is used.

New complete gates:

- Source3: original body/public binding/profile; full 258 VM; full 258 unselected
  plus empty-selector refusal.
- Native8: full 258 selected public observations; override/signature controls;
  complete ABI buffers against independent VM; safe preentry and actual return
  loss; thread/fork/reentry/stale ownership; complete original lease-snapshot
  workflow; loader and worker authority; actual installed worker adoption
  followed by installed public lease consumers.
- Resource4: all 12 declared actual resource controls, each in a fresh process.
  Injection follows a real native entry and actual SQLite INSERT. No test
  writes a delivery loss flag.
- Caller scopes: all nine original ordinary modules/112 methods, and all five
  direct caller modules/76 methods. They overlap and are reported separately.
  The five include the 13-method Slot integration module, which is not the
  distinct original Slot15 gate. Existing Slot15, TX11/TX61, ordinary112,
  separate128, Store130, and all existing CI gates remain intact.

Each new source/component/caller outer gate has an explicit 1800-second budget
and existing five-second owned-process cleanup. Original finite children have
180 seconds, candidate finite children 1800 within their whole finite deadline,
resource controls 180, installed inner commands 60, and the fork check ten.
No old fixture, workload, timeout, skip condition, or administrator bundle is
enlarged. A FAIL, ERROR, skip, incomplete child, unknown cleanup, or raw mismatch
is a HOLD.

Installed evidence distinguishes the actual adoption RPC from the later lease
consumer API process. Lease methods are not RPC tool names. A lost publication
ACK in that consumer must fence its actual Store and refuse close; it is not
relabeled as a running adoption request or request-key replay.

## Integration and remaining boundaries

The originals came from Slot R3 working source. They are exact in the latest
servicepair product file
decd64e208881ba64bdcb48555142bc081cfe6877653d01a9cd07888fbf1d067.
The public tail is an additive delta after servicepair wrappers. The combined
file is a separately reviewed successor, never an automatically allowed pin.

Five registration changes add one helper entry, packaged HIA source, explicit
non-runtime bootstrap/test/fixture inputs, generator, and independent CI steps
with raw artifacts. Production Python remains automatically collected. Counts
come from the registry. Any old literal helper-count expectation requires a
separate exact reviewed metadata-only successor.

The existing multi-file provenance guard must be frozen against the final
combined service/helper source. This package supplies exact before/after bytes
and reversible deltas but does not weaken or auto-accept that guard. Official
support metadata/current-source inventory and generated HIA remain pending.

Python object bridges, disposable worker orchestration, filesystem effects,
SQLite engine, CLI, compilation, and legacy default fallback providers are not
removed by these graphs. Whole-native qualification and all-version Python
compatibility remain false.
