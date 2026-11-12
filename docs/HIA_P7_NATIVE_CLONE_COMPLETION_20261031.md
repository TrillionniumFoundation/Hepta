# HIA P7 — incomplete native clone work must never certify complete calibration/audit

**Status:** research-only / `DENY_ALL`. All Issue #471 P0–P7 production gates stay OPEN.

## Frozen upstream and negative control

Upstream is the exact #476 research HEAD `7daaac414b41979588a962312208efb52d7ec759`
(not Hepta `main`). Test-only commits introduce two native-host interruption
regressions before the repair, at `f29eb0d1ee00599b8e323b35000f93b5b59d2b3b`.
Original run: https://github.com/TrillionniumFoundation/Hepta/actions/runs/41190749477

The original `OwnedAdaptiveRuntime._calibrate` and `audit_counterfactual`
call the real owner's `_apply_items`, which returns `False` when native
execution is cancelled/partial, yet ignore that result. The calibration loop
can compare two equally incomplete clone states and report valid paired
per-step savings. The counterfactual audit can even report equivalence if
unexecuted suffix items are no-ops, despite never executing the complete
committed replay. Equal final cell values alone do not prove full native work.

## Small correction and adversarial evidence

Both callers must require a `True` complete-work return **before**
recording sample time, comparing state, or authorizing any counterfactual
observation. A partial return raises `AdaptiveRejected`; the existing
`finally` still frees the real native clone and leaves the unexecuted owner
queue/previously completed receipt unchanged. No change to the actual native
driver, transition Core, optimization selection policy, budget threshold,
queue contents, or authority.

`tests.test_hia_stateful_clone_partial` intentionally executes the first
item on a real Clang20/Z3-backed native clone, reports interruption rather
than fabricating a completed prefix, then verifies strict refusal. A second
case uses an intentionally no-op suffix whose omission leaves the same
final values and verifies the counterfactual audit still refuses. The native
allocation ledger must not leak, and the actual owner state remains unchanged.
The regression is also included in the exact-source `native` test roster.

The dedicated push/PR workflow pins Ubuntu 24.04, LLVM/Clang20, Z3, records
the original regression test log on failure, and runs the strict full
P0/P1/P5 Core and independent native replay qualifiers after the two real
native tests pass. Do not substitute earlier-head workflow success for the
final exact HEAD or prospective merge-tree result.

## Not yet qualified

This does not establish real power-loss recovery, durable journal, an
external exactly-once transaction, arbitrary C/C++ ABI or Rust safety,
multi-target physical energy/resource economics, NDU full lifecycle net
advantage or hidden Agent productivity. No production promotion, release
certificate, merge to `main`, deployment or waiver is authorized.
