# HIA P7 — loan token collision, closed-handle resurrection and epoch fence

## Exact source and reproducible failure

**Research-only; all production P0–P7 gates stay OPEN.** Base is Hepta #475
at `267b2ad84713683fd08dab6c436b5ee41ee25900`, inheriting the
immutable owner/generation/revision queue API and exact HIA Core evidence.
The pre-fix `OwnedAdaptiveRuntime.borrow` stored one mutable/shared-loan row
under `secrets.token_hex(16)` without collision rejection. Two concurrent
shared loans that receive the same token overwrite the earlier active row.
Worse, if a loan closes and its token is later reused, its old `_Lease`
object can read/write or close the *new* loan, since lookup is only by token
and the current owner/generation.

Source-exact negative tests were published first at commit
`6eabc561080b0fee3d815c1d2586489a94429adc`, using actual production
borrow/access/end paths and injected repeated random tokens. A failure of
these security expectations is a **red regression**, not a green acceptance.

## Minimal live-process repair

- Reject active loan token collisions under the owner's existing lock.
  Do not replace an earlier loan row, mutate its lifetime or falsely release
  a capability.
- Bind every new loan to a monotonically increasing, 64-bit bounded
  `lease_epoch` in its owner. `_Lease` retains both its opaque random token
  and the exact epoch. Every access and close rechecks the epoch; an old
  object cannot regain read/write/end authority if its random token is reused.
- Close remains idempotent for the original lease, but will not close a
  different lease. Existing owner/generation, exclusivity, immutable queue
  and resource constraints stay in place.
- Epoch exhaustion rejects rather than wrapping. No unbounded set of
  retired random tokens is needed.

## Verification

```sh
python -B -m unittest tests.test_hia_stateful_loan_token_collision -v
python -B -m unittest tests.test_hia_stateful.OwnedNativeTests.test_alias_modes_bounds_and_queue_staleness_are_real_state_gates -v
python -B -m unittest tests.test_hia_stateful.OwnedNativeTests.test_native_loan_token_reuse_cannot_revive_stale_lease -v
python -B -m unittest tests.test_hia_stateful.OwnedNativeTests.test_immutable_fenced_wire_executes_real_native_owner -v
```

A dedicated GitHub Actions Ubuntu-24.04 workflow uses pinned LLVM 20,
independent Z3, actual native owner execution, new collision/revival
regressions and the unmodified Core resource suite. Tests and source are
bound to exact commit identity; no skipped native test may count as a pass.

## Nonclaims

This is a scoped **live-process lease capability** repair. It does not prove
arbitrary shared-memory/FFI safety, tamper-proof Python objects, persistent
journal/crash-restart semantics, external exactly-once effects, physical
target resource bounds, future optimization value, complete P7 or any other
P0–P7 gate. No production authority, auto-merge or deploy is granted.
