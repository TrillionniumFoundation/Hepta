# HIA P7 queued-generation final-use fence (research, 2026-10-31)

**Authority: `DENY_ALL`. Production activation prohibited. No P0–P7 checkbox is closed.**

## Exact ancestor and original defect

Parent: Hepta #477 `b2a6cabc1be1676e491804701bced9064b1b7968`
(tree already includes #467→#469→#470→#474→#475→#476→#477).
The live native owner admitted bounded immutable queue items and checked
`revision` and `owner` on execution, but **did not bind the queue to the
owner's program `_generation`**. Even a canonical queue wire checked
`generation` only at submission. `select(..., mode="explicit")` advances
the generation while retaining owner identity and state cells. Thus a
previously registered queue could cross a version cutover and enter
`_plan_queue`/native execution without explicit re-admission.

Cancelled, **never executed** queue continuation also lacked an epoch
check and could create a new suffix after an unrelated generation change.

## Exact repair scope

- `hepta/hia_stateful.py`: freeze owner generation in every queue record
  under the original owner lock (both Python queue API and canonical wire).
- `hepta/hia_queue_commit.py`: refuse stale generation before
  `_plan_queue` or native activity; mark old queue `stale`. Record actual
  execution generation only after an internally verified selection, and
  remove it on pre-activation rollback.
- `hepta/hia_continuation.py`: refuse epoch change for a cancelled,
  unexecuted queue, including no-op cell-state changes; give each fresh
  child an immutable registered generation. Preserve the original **explicit
  partially executed prefix→verified version switch→suffix** workflow:
  only a queue with native execution receipt and changed program version
  may be rebound under the owner's current lock with exact live state,
  revision and allocation checks. Record both old/new generations in
  continuation provenance. A same-version epoch bump is not a rebind.
- Regression file `tests/test_hia_p7_generation_fence.py` tests stale
  Python queue, immutable-wire use, cancelled-before-start continuation,
  child fence and a real Clang20/Z3 owner with an actual verified version
  switch, refusal of the old queue and success of a freshly registered
  queue. Bounded fake tests are **not** native qualification.
- Wire into strict zero-skips native suite in
  `tools/qualify_hia_three_lane.py`. Scoped CI runs real continuation,
  existing source-exact P0/P1/P5 Core and ELF/native replay.

Test-only **unfixed** ancestor branch commit `c60530f780b3c7d44b0d6475b854755dc0bf6a7c`
contains new tests and workflow over the original source. The workflow's
recorded terminal result must be inspected; red is NOT claimed just
because the test's design should fail on this commit.

## Evidence and nonclaims

Every actual CI run must be keyed to its own exact source SHA.
A passing test on #470, #476 or #477 is not evidence about this candidate.
The prospective merge tree on the immediate #477 parent, as well as final
HEAD's tests, must be checked independently. Any queued/unknown run is
OPEN, never green.

This is a **live-process generation admission fix only**. The runtime still
lacks external signed Final-use authorization, a durable queue journal,
transactional external effects, power-loss replay/rollback, full target
hardware coverage and independent release review. The prior
hepta-private-ci #4118 NDU study's **negative full-cost result** remains
unaltered: fixed 348.754475126 s, DP 352.591082376 s, NDU 398.457516886 s;
its broad blocking CI failed. There is no P5/P6 net-advantage claim.
Issue #471 P0–P7 must remain open and `safety_certificate=false`.
