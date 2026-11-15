# Worker UNKNOWN terminal contract

## Current-request facts and actual cleanup

This successor changes one-request termination only when the current request
actually observes delivery loss or refusal to retire its exact lost resource.
It does not classify by an exception name, treat all RuntimeError instances as
loss, scan global retained custody, or authorize cleanup. Old unrelated loss
does not poison a fresh request. A current attempt to retire the exact already
lost resource is itself a real observation.

RequestDeliveryObservation is separate from the active delivery parent chain.
It is not a NativeCall, DeliveryRecord, ForeignCall, acknowledgement, replay
authority, or cleanup permission. The first actual origin remains sticky.
Actual primary and cleanup exception objects retain their causes, contexts and
tracebacks; this code does not clear or rewrite them.

Real UNKNOWN returns exit code 2 without an ordinary completed stdout report.
The original finally attempts service.close exactly once when that original
path is reached. It is neither retried nor declared successful after refusal.
Primary, cleanup and distinct terminal exceptions are diagnosed independently.
A broken diagnostic stream cannot turn known UNKNOWN into success.

Without actual loss, the original ordinary five-family rc2 boundary and other
BaseException propagation remain. Original correlated ordinary rejected reports
remain unchanged. A class named NativeDeliveryUnknown or
ServiceVerificationUnknown is not evidence.

The actual R16b installed attempt remains rc1 with empty stdout: a real
withheld verification receipt caused ServiceVerificationUnknown, and the
original close then refused exact Store retirement with NativeDeliveryUnknown.
The failed raw attempt and absent final installed aggregate are preserved.

## Reference and native report paths

The reference path preserves the original one-close finally and checks actual
loss after wire evaluation, before stdout.write. Its ordinary exception path
checks facts before constructing a normal correlated rejection.

The selected v2 path preserves the original HIA graph, ports and provider
classification. It reads actual CALL_REGION and CLOSE_REGION state before the
provider. New installed controls require Boolean, mutually exclusive flags,
actual CALL/CLOSE error packets, and real saved policy entry calls. They do
not create a fresh active parent that could suppress the original close.

## Independent controls and readback

New Source3 covers 40 complete original-worker ordinary comparisons, 15
original/successor terminal cases and 13 request/resource/context/thread/fork
cases. Frozen complete original worker text supplies ordinary expected
behavior. These source controls lose an actual foreign-result acknowledgement;
they do not claim native execution or assign record.loss.

New Native2 retains the complete unchanged original v1 installed helper as one
method. Its other method uses the existing official explicit v2 binder, keeps
the full original installed workflow, and adds real lost-receipt swallow and
replacement requests. The complete hosted worker policy is poisoned in v2.

All installed child budgets remain 60 seconds plus 3 seconds cleanup. Original
durable state, replay, costs +1, source drift, wheel RECORD and installed
worker/backend/catalog/bundle flags remain. New v2 additionally saves exact
stdin bytes for its seven request children. The old v1 producer does not save
these new artifacts; no v1 input-byte evidence is manufactured.

The independent reader binds each parsed report to captured producer-return
or supervisor-receipt bytes, verifies complete ordered inputs and actual
streams/terminal/cleanup, then re-reads the same original pins. Wheel members
are streamed and validated against RECORD and installed files. Absent reports,
partial cases, timeout, drift, or cleanup failure cannot become PASS.

Original worker/report/request/helper/scheduling, installed-resource,
eleven-tool, shared-delivery, verification Native8 and FINALIZE Native1 gates
remain complete and separate. All original independent 112 and 128 scopes,
methods, poison, inputs, assertions and budgets remain unchanged. Overlapping
scope counts are not combined into a claimed new qualification.

## Registration and provenance

Production changes are exactly hia_agent_worker.py, hia_native_delivery.py and
hia_worker_report_native.py. The separate explicit provenance successor is
old eleven plus worker and worker_report_native: thirteen sources. Only worker
is removed from unchanged89. worker_report_native has an explicit origin; it
was not in unchanged89 or shared22. Original c019 bytes and the original 2679
domain remain unchanged; the new complete 13-source mask domain is 8192.
Neither domain was executed while authoring this layer.

Append the eleven paths in registration/SOURCE_FILES.suffix.txt after the
actual current complete prefix, preserving concurrent C/Lease/Bootstrap/budget
additions. Two independent CI classes and exact evidence paths are supplied.
Every actual Source/full-retained gate gets a fresh evidence root.

The official worker-report builder has no local INPUTS list. Matching-cold
build admission binds complete current_sources, so register new support before
the official metadata/cold fixed point. DEV is explicitly diagnostic. The
current C compile closure must be rebuilt for new shared/worker pins; no old
receipt can be reused.

## Limits

This is a static unexecuted layer: no product, test, reader, oracle, SQL, VM,
Native, compiler, generator or qualification execution occurred. Arbitrary
allocation-failure equivalence and opaque provider internals remain outside
this finite claim. A custom stdout writer can create a loss only after bytes
have already been committed; this code cannot retract those bytes. It checks
known actual facts at the real output boundary and the specified observed
delivery/retirement boundaries. This is not whole-stack closure.
