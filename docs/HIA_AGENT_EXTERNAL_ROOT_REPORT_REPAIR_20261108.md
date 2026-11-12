# Borrowed-entry stopped-report repair — 2026-11-08

Status: **PASS for the reproduced report defect and finite regression suite.**
This is not a proof of general compiler correctness, native resource semantics,
or the original unfamiliar Agent's select extension. Those stronger gates keep
their existing scope and HOLD status.

## Actual failure

The borrowed-byte workload adapter creates a distinct external byte owner for
each caller buffer. Core may reborrow that caller capability. A program trap
or evaluator quota can stop while the local reborrow is still live. The caller
storage remains live, but it is intentionally absent from the VM's allocation
and heap counters.

The old aggregate execution-report invariant required every nonzero local-loan
count to coexist with a live **VM-owned** buffer. It therefore rejected this
legitimate stopped prefix with `E_HIA_RUNTIME_INVARIANT`, masking both the real
stop and the buffer observation. The actual same-program Agent evaluation
then reported `incorrect` before starting native evaluation.

The exact baseline is `50c1578b4d4597e3070a9abc3700c9aacbf99851`.
The three changed production files are identical in the later integration
checkpoint `d6431f233619e1339cec5532741d9303ecfcf150` before this repair.
The isolated repair source commit is
`07adbf2182a00a8ced0b58576369d2175d173e8d`.

## Repair and retained checks

The reference adapter passes its actual external `_Owner` objects to
`_Machine.report`, after checking each caller `_View` has its exact runtime
type, remains active, points directly to that root, and retains its declared
read/mutable permission. The report accepts only an exact tuple of active
`_Owner` objects with distinct negative integer identities and distinct mutable
byte storage. Roots must be absent from the VM owner map by both identity and
object membership. Dead, aliased, malformed and VM-owned roots are rejected.

Only after those checks does the report supply `live_external_roots` as explicit
context to the aggregate execution-observation validator. It is not a wire
ledger field. Its default is zero, so existing raw/native consumers and ordinary
scalar VM reports retain the previous owner-backed-loan requirement.

External bytes are not added to allocations, owners, live bytes, peak bytes or
heap consumption. Exact ledger field inventories, integer checks, allocation
and owner conservation, local-loan conservation, chain-node storage accounting,
heap limits, stop classification and tick limits remain enforced. Ordinary
return still requires no live local loans or Core-owned resources. In
particular, an external root cannot substitute for the two VM-owned buffers
required by a live chain node.

This repairs the existing **aggregate backing** check. It does not introduce a
registry or a proof of every live dynamic view edge. Static Core ownership
checking and the existing runtime view operations continue to have their
separate roles.

## Unchanged subjects and actual before/after observations

Both inputs first reborrow the mutable caller buffer, then store `0xab` at
offset zero. The caller initially supplies `0000`; the explicit Core heap limit
is zero. The trap subject ends with a `bounds` trap. The quota subject has a
normal cleanup path, but the five-step limit stops before `loan.end`.

| Subject | Canonical Core SHA-256 | Old report | Repaired report |
| --- | --- | --- | --- |
| Explicit trap | `a753045d796c1f28f2e858773b4fcf704e37be507c0ed360e023e7a415dcdb4c` | `E_HIA_RUNTIME_INVARIANT` | `trapped`, `bounds`, step 6 |
| Step quota | `a6f1f2ca8c7eb918006c377104448beed839882488de600e2993ba4a932d4d4e` | `E_HIA_RUNTIME_INVARIANT` | `budget_exceeded`, `steps`, step 6 / limit 5 |

The old exception tracebacks and separately observed direct VM stopped states
are retained. Both repaired reports retain byte content `ab00`, one started
local loan, zero ended local loans, and zero Core-owned allocations, owners and
heap bytes. No destructor cleanup is invented at either stop.

The same trap subject also went through the actual Agent import, admission,
native emission, encoding check and self-evaluation path before and after the
repair. Each retained lifecycle has 13 tool calls and zero slots or leases:

| Observation | Before | After |
| --- | --- | --- |
| Self-evaluation outcome | `incorrect` | `unchanged` |
| Planned workload complete | false | true |
| Reference subprocesses | one failed report | two complete reports |
| Native invocations in that lifecycle | zero | two actual aborting invocations |
| Native termination | no native invocation | both confirmed, return code `-6` |
| Baseline/candidate VM and native bytes | lost at the old VM report boundary | all `ab00` |

The emitted shared image is byte-identical before and after:
`7c09f01f8117fc6a1ef2ae959c0054484b8b606d0c198d471bcc397f5f5e350d`.
The repair neither changes the subject nor substitutes a different native
program to obtain the corrected evaluation.

`before-retained-io` and `after-retained-io` additionally preserve original
runner stdin, stdout, stderr, artifact and post-exit backing bytes. A test-only
observer calls the original `Popen.communicate` once and returns its unchanged
result. The production runner still performs its existing process-group,
termination, artifact and buffer checks. Every captured stdout/stderr digest
and return code was matched to the resulting lifecycle measurement; both native
backing files contain the two observed bytes. The initial uninstrumented
lifecycles are retained separately.

## Validation

The final targeted run passed **61 tests, zero failures, zero skips**, covering:

```sh
PYTHONDONTWRITEBYTECODE=1 python -B -m unittest \
  tests.test_hia_agent_external_roots \
  tests.test_hia_agent_buffer_lifecycle \
  tests.test_hia_execution_contract \
  tests.test_hia_program \
  tests.test_hia_native_byte_abi -v
```

The eight new tests cover the two unchanged failed subjects; normal cleanup;
nested read-only loans over empty external storage; the default raw rejection;
counter, heap, chain and return refusals; invalid external root objects;
corrupted caller views; and the actual native self-evaluation. Existing tests
continue to check bounded buffer ABI behavior, lifecycle and lease fencing,
stopped resource ledgers and standalone ownership/CFG semantics. The first
regression invocation had one missing test-module dependency in the sparse
isolated checkout. Its complete failure log is retained; the dependency was
restored from the exact baseline before the successful full run.

An independent sibling review inspected the three production-file deltas and
their frozen hashes. It reported `PASS_SCOPED_STATIC_REVIEW`; it did not perform
another native run or make a stronger proof claim.

The evidence archive and per-file digest index are under
`review-evidence/hia-agent-external-roots-20261108-5e6c/`. They retain original
failures, both lifecycle variants, exact source snapshots, test sources and
logs. There was no deployment, slot adoption or lease acquisition in the
retained before/after regression lifecycles. The existing broader lifecycle
test suite exercises its own temporary test slots.
