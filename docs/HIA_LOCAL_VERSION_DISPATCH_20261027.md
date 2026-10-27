# Local interpreter version dispatch

`hepta.hia_version_dispatch.LocalVersionDispatcher` implements a bounded,
process-local execution increment for P6. It runs the actual standalone HIA
interpreter and changes which immutable program later calls enter. This is
not native code hot swapping, distributed generation fencing, a persistent
runtime, or completion of the general P6 stage.

## Admission and activation

The host supplies immutable primitive v1–v6 program bytes with at least one
scalar public export. The canonical `verify_program` checks those bytes;
composite and v7 input are outside this dispatch profile. Internal resources
may execute, but caller-supplied owners, loans and foreign pointers cannot
cross the scalar interpreter boundary.

Staging independently verifies candidate and baseline bytes, then invokes the
existing `rewrite_byte_swap` on the frozen baseline. A candidate must be the
baseline itself or the exact canonical result of that rewrite. A changed
constant can remain well typed and resource-valid, yet it is rejected here.
No caller receipt, claimed proof, reward, score, model output or digest alone
admits a different program. This gate establishes the narrow candidate
relationship; it is not a new general semantic-equivalence proof.

Staging never activates a version. The host explicitly calls `activate` with
a staged identity and `expected_generation`. The generation comparison and
active-version update occur under one lock. A stale generation, Boolean
generation, unknown identity or already retired candidate rejects. Selecting
the current version is a no-change operation and does not increment the
generation. NDU evaluation remains advisory and has no call path granting
activation through this module.

```python
from pathlib import Path

from hepta.hia_program import verify_program
from hepta.hia_swap_opt import rewrite_byte_swap
from hepta.hia_version_dispatch import LocalVersionDispatcher

baseline = verify_program(Path("program.hia").read_bytes())
candidate = rewrite_byte_swap(baseline).program
host = LocalVersionDispatcher(baseline.canonical_bytes, max_in_flight=16)
staged = host.stage_candidate(candidate.canonical_bytes)

# An explicit host decision after its own acceptance/evaluation policy.
activation = host.activate(staged["candidate_sha256"], expected_generation=0)
report = host.execute("exported_function", [1, 2])
host.rollback(expected_generation=activation["generation"])
```

The function name and argument list in this example must match the supplied
program. No public executor or arbitrary code hook is available.

## Calls, rollback and retirement

A call snapshots scalar arguments, then pins its current immutable version
and generation under the lock. It executes the real `execute_program` outside
that lock. Each interpreter call independently verifies its program again.
The dispatcher releases its pin in `finally`, including actual input errors,
specified traps and budget exhaustion. The original exception and resource
report propagate; releasing a dispatch reference does not invent executed
`owner.drop` or `loan.end` operations after a trap.

| Event | Effect |
| --- | --- |
| Activate a staged candidate | Increment generation; future calls enter the candidate |
| Call already executing baseline | Continue its pinned baseline and original generation |
| Roll back | Route future calls to the retained baseline; do not undo effects |
| Candidate call still executing during rollback | Keep that version available until its last call finishes |
| Last inactive candidate call finishes | Remove the candidate from the dispatch inventory |
| Select baseline while baseline is active | No generation or behavior change |

Baseline bytes are deliberately retained for rollback even when no baseline
call is active. At most the baseline and its one deterministic rewrite are
addressable. Retirement removes a candidate from the inventory; it does not
promise immediate Python heap reclamation. A retired candidate must be
staged and reverified again before activation.

`max_in_flight` is an integer in 1–1024, default 64. Additional calls fail
immediately instead of waiting or allocating an unbounded work queue. This
limits dispatcher admission only. It is not a bound on total process RSS,
stack usage, compiler memory, elapsed CPU time or all external resources.

## Actual test coverage and limits

`tests/test_hia_version_dispatch.py` runs real Core byte-owner swap programs.
Event-controlled threads delay entry into the actual interpreter without
substituting program results. The tests verify old/new program hashes and
generations, actual returned bytes, in-flight accounting and delayed retirement
across activation and rollback. Every wait and join has a finite timeout.

Other controls cover baseline/no-change, stale generations, un-staged or
retired candidates, mutable input refusal, unsupported profiles, an altered
but statically valid candidate with a different real output, and actual Core
trap, allocation failure, budget and argument failures. The existing swap
pass and Core suites remain independent checks of their narrower contracts.

The peephole reduces instruction counts. Equal `max_steps` limits can stop
different versions at different operations; the dispatch gate does not prove
equivalence of budget-exhaustion timing or general resource observations.
The existing pass's scoped behavior argument and finite tests are not a
whole-compiler or all-environment refinement proof. No performance advantage
or p99 improvement follows from these lifecycle tests.

Remaining obligations include native artifact/loading qualification,
generation-bound call gates across processes, crash recovery, signatures and
authorization, asynchronous cancellation and tasks, arbitrary candidate
equivalence, active state migration, callbacks, FFI lifetimes, device/allocator
state, native code reclamation, and production performance. Host Python
process integrity is an external assumption; object privacy is not a security
boundary against code already executing in that process. General P0–P7 and
whole-project closure remain false.

```sh
python -m unittest tests.test_hia_version_dispatch tests.test_hia_swap_opt \
  tests.test_hia_program tests.test_hia_program_tools -v
```
