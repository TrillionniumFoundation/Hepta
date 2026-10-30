# Resource and exit contract for checked leaf-call expansion

`hepta.hia_optimization_contract` adds an executable admission boundary around
the existing leaf-call expansion checker. A proposal is accepted only after
the actual original and candidate Core pass the canonical verifier, the
ordered expansion relation passes independently, and the actual budgets are
recomputed. A retained receipt is replayed against the independently supplied
policy, function and arguments. It cannot authorize a different invocation.

The scope is **one exact public scalar invocation** of a finite acyclic byte
program. In v7/v8, the existing finite invocation heap analyzer accounts for
owners transferred into and returned from calls. V8 uses its separately
reviewed caller-derived borrowed-extent profile. Legacy v1-v6 retain their
stricter all-function heap analyzer and reject unsupported owner-return
boundaries. No schema is silently upgraded. Every definition still passes
the whole-module opcode and acyclic call/CFG audits, including unused private
definitions.

## What the transformation must retain

| Outcome or boundary | Contract |
| --- | --- |
| Normal return | Same typed result and ordered resource operations; ordinary return must consume all local owners and loans. |
| Error returned as a value | Same ordinary-return rule, including explicit cleanup of a failed allocation's empty owner. |
| Allocator failure | Same allocation order and fallible-result handling under the same failure schedule. |
| First program trap | Same first trap and preceding resource operations. The stopped ledger retains live resources; no unwind is invented. |
| Explicit cooperative cancellation branch | The actual branch and its ordinary cleanup operations remain in the checked trace. This is not an asynchronous cancellation theorem. |
| Evaluator quota stop | Tick and frame counts can change. Recompute the candidate and, when requested, original budget against the actual policy. Exact stop locations are not equivalent. |
| Host interruption or forced process exit | No cleanup, rollback, automatic retry or exactly-once guarantee is introduced. |
| Module composition | Verify the complete resolved module and actual call interfaces. An unresolved import or altered callee signature cannot borrow another module's receipt. |

The transformation verifier checks ordered operations and CFG exits. Its
Python implementation remains trusted. This contract does not claim a
machine-checked correspondence between that checker and the interpreter.

## Two explicit budget modes

`candidate_requalified` requires the actual candidate to fit the supplied
limits. A source invocation may exhaust a quota that the candidate no longer
exhausts. The receipt reports this difference and always sets
`exact_budget_stop_behavior_preserved` to `false`.

`both_fit_same_quotas` also requires the source to fit those same limits. This
excludes exceeding the declared structural VM event quotas in the admitted
profile. It does not equate raw step counts, diagnostic locations, the host's
Python recursion limit, native stack use or asynchronous failure behavior.

Every policy must explicitly supply all four limits:

| Limit | Meaning | Excluded quantities |
| --- | --- | --- |
| `max_vm_ticks` | Opcode, terminator and invocation ticks in the selected interpreter event model | Native instructions, CPU time, termination of unrestricted programs |
| `max_call_depth` | Root-inclusive synchronous HIA invocation frames | Native stack bytes, task stacks, host recursion cutoff |
| `max_allocator_interactions` | Conservative potential allocation/drop events | Allocator latency, allocator metadata, external allocators |
| `max_live_heap_bytes` | Requested live HIA payload for the bound invocation | Process RSS, Python objects, allocator overhead, device memory |

The module source, opcode catalog, semantic checker, heap analyzer and runtime
all participate in the contract implementation identity. The candidate's
Core, exact invocation, policy, semantic evidence, every bound and every
scope claim participate in deterministic receipt replay.

## API

```python
from hepta.hia_call_expansion import propose_leaf_call_expansion
from hepta.hia_optimization_contract import (
    POLICY_SCHEMA, qualify_expansion_contract, execute_contracted_expansion,
)

proposal = propose_leaf_call_expansion(core, callees=["make"])
policy = {
    "schema": POLICY_SCHEMA,
    "budget_mode": "both_fit_same_quotas",
    "max_allocator_interactions": 2,
    "max_vm_ticks": 64,
    "max_call_depth": 2,
    "max_live_heap_bytes": 4,
}
receipt = qualify_expansion_contract(
    core, proposal, function="run", arguments=[False, 3], policy=policy,
)
observation = execute_contracted_expansion(
    core, proposal, "run", [False, 3], policy=policy, receipt=receipt,
)
```

Execution rechecks the contract and runs the immutable candidate with the
bound scalar arguments and actual VM limits. It returns a trap or budget-stop
ledger without relabeling either outcome as a cancellation or a successful
cleanup. It performs no retry and grants no native artifact publication
authority.

## Executed evidence

The fixed regression fixture calls a leaf that returns a fallibly allocated
four-byte owner and a success flag. The caller implements normal cleanup, an
allocation-error value, an explicit cancellation branch and an explicit
program trap while the owner is live. The accepted expansion changes the
`run` function's structural tick bound from **14 to 11** and synchronous frame
bound from **2 to 1**. The payload bound remains **4 bytes** and allocator
interaction bound remains **2**.

The qualifier retains these actual outcomes:

| Case | Candidate result | Allocations / frees | Live owners at exit |
| --- | --- | --- | --- |
| Normal `[false, 3]` | Returned `4` | `1 / 1` | `0` |
| First allocation fails | Returned error value `1` | `0 / 0` | `0`; the logical empty owner was explicitly dropped |
| Cancellation branch `[true, 0]` | Returned cancellation value `2` | `1 / 1` | `0` |
| Program trap `[false, 0]` | `division_by_zero` trap terminator | `1 / 0` | `1` |
| Frame limit `1` | Source stops; requalified candidate returns | Recorded separately | No stop-equivalence claim |
| Tick limit `11` | Source stops; requalified candidate returns | Recorded separately | No stop-equivalence claim |

The qualifier also executes the complete 13-test boundary suite with no
skips. It rejects a deleted cancellation cleanup, resource operation drift,
unresolved calls, a valid owner-carrying CFG cycle, an unused recursive-chain
definition, an unsupported legacy owner-return profile, policy/receipt
forgeries and reuse for another typed invocation.

```sh
python3 -B tools/qualify_hia_optimization_contract.py \
  --output artifacts/hia-core-contracts-20261030/resource-contract.json
```

These observations establish the stated finite contract. They do not complete
general cancellation, arbitrary C/C++ migration, native resource bounds or
whole-language safety.
