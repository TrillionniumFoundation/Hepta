# P7 live queued-work generation fence — native regression and narrow repair

**Research-only / DENY_ALL. No P0–P7 production gate closure or deploy.**

## Exact source, defect and negative control

Base #477: `b2a6cabc1be1676e491804701bced9064b1b7968`.
The prior `submit_queue` recorded `owner` and `revision` but did not
persist the *current image generation*. `execute_owned_queue` accepted an
older registered queue when a legitimate explicit `select(mode="explicit")`
changed the image generation while leaving those other fields unchanged.
`continue_owned_queue` also checked only revision/owner on a cancelled
queue. Consequently stale queue work could execute on a newer image or
be reissued as a new continuation after a version cutover.

Test-only original-source negative commit:
`fc22fb9eb8115cee4ce721ee3387d6e415fb0e8f`.
The native tests include an immutable bytes-wire queue registered at the old
generation, real pinned Clang20/Z3 image selection, unchanged u64 data and
revision, a forbidden old-queue execution, a cancelled queue with forbidden
continuation, and a legal same-generation native execution. Preserve any red
run's exact SHA and observed test results; it is not a green qualification.

## Correction

- Bind every registered queue to the generation, in addition to owner and
  revision. Execution refuses/marks stale before planning or native mutation
  when any fence differs.
- During an internally verified *same-queue* version selection, record the
  generation actually activated so its own known partial native execution
  can be continued only within that exact generation.
- If application startup rolls back before work, restore the original
  registration generation with the existing event/cost rollback.
- A cancelled queue cannot register a suffix after any external image
  generation change. Child queue receives a fresh generation fence under
  the same lock.
- No changes to Rust verifier, Core opcode semantics, NDU scoring, native
  function arithmetic, C ABI, image validation, or real performance reports.
- Keep one targeted test in the native zero-skip qualifier, and update only
  two legacy test fixtures that construct an artificial queue without a
  generation. No change to productive public APIs or queue receipt wire
  schema in this limited patch.

## Scope and remaining hard blockers

This is a **live-process version fence**, not a durable activation journal,
external exactly-once effect contract, signed authority, cross-process
restart, crash/power-loss replay, rollback proof, general ABI safety,
full-program compiler refinement or a global NDU net-benefit result.
All Issue #471 P0–P7 checkboxes remain OPEN. This remains a Draft PR until
exact-green native and P0/P1/P5/source-bound tests on the final source,
independent review, and any prospective merge commit verification.
