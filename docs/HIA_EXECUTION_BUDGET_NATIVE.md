# Native execution-budget policy and durable claim authority

This development candidate moves the complete bounded execution-budget policy
from the three original Agent service write sites into
`examples/hia_bootstrap/execution_budget.hepta`. Explicit selection uses
`HEPTA_HIA_EXECUTION_BUDGET_MANIFEST` before `AgentStore` construction. The
installed image is source/image bound and stays immutable for that store's
lifetime. Failed native admission or execution cannot select the hosted
reference. Current-source cold qualification, full retained regression and
deployment are separate gates; this document does not assert they have passed.

The selector is unselected only when its environment variable is absent. An explicitly present empty value is rejected before image loading or entry into the hosted reference. Remove the variable to use the unselected reference path; an empty assignment does not disable selection.

## Current source integration

This `.hepta` integration preserves the current `agent_journal` v2 owner. The
budget selector composes with both the ordinary service journal and explicit
`HEPTA_HIA_AGENT_JOURNAL_MANIFEST` selection; it does not replace either journal
with the older v67 `request_journal` implementation. Both paths use the original
SQLite database and execution-budget rows. The native suite runs the existing
Agent lifecycle/campaign and real-child lost-outcome/restart controls separately
for each path, with the hosted budget policy forbidden. The selected journal
path also forbids the hosted journal policy.

The builder, source resource, independent VM controls, native suite and installed
wheel control are registered together. CI and the qualification runner supply
the matching current-source cold report; a predecessor compiler is permitted
only through the explicit development test fixture and produces evidence marked
`matching_current_source_cold_qualified: false`. The default service selection,
release activation and whole-stack qualification remain unchanged and false.

The current integration's development run passed all 25 outer tests in
189.665 seconds, with no failures, errors, skips or expected-failure exceptions.
It separately passed all 14 unchanged lifecycle/campaign tests under the
ordinary journal and all 14 under the selected v2 journal. The two real-child
lost-outcome/restart paths and the installed-wheel control also passed. This run
used an explicitly retained predecessor compiler; the precise source/image
hashes, test results and product audit are retained in
`review-evidence/hia-native-rewrite-20261111/execution-budget/` and
`execution-budget-product-alignment.json` in its parent directory. It is
development evidence and does not qualify the changed source tree for release.

## Original journal and ordering

The authoritative table remains
`execution_budgets(context_id, used_native_ns, owner)` in the original
`state.sqlite3` database and its WAL. No schema, row identity, cost or non-null
owner is migrated or reset. The original context insertion precedes budget
creation. Request intent remains separately committed by the request journal;
the adoption/rollback effect and exact-response transactions remain their own
authority. A failed budget creation can therefore leave the same context without
execution authority that the original ordering allowed. This change does not
silently turn context creation into a new atomic transaction.

The selected adapter uses a dedicated SQLite connection to that **same journal**.
Actual service writers also issue ordinary statements outside `AgentStore.lock`;
sharing their connection would let an unrelated statement enter a budget's
transaction. SQLite instead serializes the dedicated connection's
`BEGIN IMMEDIATE` transaction against all other writers, including the ordinary
connection. The adapter checks the official main database path/identity, keeps
the original connection as a live custodian, opens with `mode=rw`, and checks the
database/WAL/shared-memory file identities before effects. A lost or replaced
path cannot silently create a separate budget namespace. Creator PID checks
precede inherited locks. A caller-owned transaction is refused rather than
borrowed as a purportedly durable preclaim.

Every budget statement explicitly names `main.execution_budgets`. A same-name
TEMP table on the connection cannot replace the durable row, claim, readback or
completion; it remains untouched. This is a binding to the original journal,
including when diagnostic host code has introduced a temporary schema.

The filesystem is the existing administrator-owned private namespace. These
observations do not defend against a malicious process that can replace and
restore paths between checks or rewrite arbitrary SQLite/Python memory.

## HIA state and fixed foreign effects

Each operation has one retained 13,568-byte HIA state block. A claim continues
using that same block after its durable preclaim. It captures the exact context,
request owner, original cumulative cost, native wall limit and start time. A
claim identity, connection identity and monotonic sequence bind every action
and outcome. State corruption, mismatched acknowledgements and sequence
exhaustion refuse further effects. The corruption guard is not an authenticity
mechanism against malicious code in the same process.

HIA emits a fixed effect vocabulary: begin transaction, read the budget row,
insert, compare-and-swap claim, compare-and-swap completion, commit, and run with
an admitted timeout. The adapter executes only the corresponding fixed SQL with
bound parameters. Every write requires one affected row and exact readback
before commit; execution is allowed only after the commit acknowledgement has
returned to HIA. The SQL connection, SQLite C implementation and process runner
remain foreign infrastructure.

The original cumulative cost is a canonical decimal **TEXT** value. HIA adds
decimal bytes directly, including values beyond signed or unsigned 64-bit
integer ranges. The bounded profile admits up to 4,300 decimal digits, matching
the ordinary interpreter's default decimal conversion bound. Malformed,
negative, fractional, noncanonical or over-cap records are refused without
normalization or mutation. Overflow leaves the original durable owner charged;
it cannot clear the owner using a truncated cost. The frozen native wall limit
remains 1..3,600,000 milliseconds and the outer remaining wall observation is
bounded by the existing 86,400,000-millisecond context profile.

HIA preclaims each runner invocation, computes its remaining timeout, and
consumes the exact returned token once. Only the literal confirmed-termination
observation can add a returned cost. An unconfirmed outcome or interrupted
handoff leaves the claim fenced and the original durable owner non-null. The
foreign runner's existing process-group and termination checks remain required;
HIA does not infer process exit from a timeout or exception.

## Failure and replay semantics

Before the claim commit, a failed private transaction can roll back without
starting native execution. A commit that succeeded but lost its acknowledgement
is ambiguous: the adapter fences that claim and does not run, retry or refund it.
An interrupted native run retains its already committed owner. Completion uses
both the original owner and the original cumulative cost as its compare-and-swap
condition; a concurrent change cannot be overwritten. A rollback of an
uncommitted completion preserves the previously committed owner.

A fresh `observe` reports the current durable row and grants no execution
authority. The three-field table cannot prove a historic completion after a
later owner or an equal-cost cycle. Equal cost and a null owner therefore do not
manufacture a completion receipt or authorize replay. The existing request
journal remains responsible for exact request replay/unknown-intent handling.
An already fenced in-process claim cannot recover authority merely because a
later read looks available.

Claim snapshots distinguish `claim_owner`, `captured_used_native_ns` and
`proposed_used_native_ns` from a fresh current-row observation. In particular, a
completed claim's captured inputs are not reported as a still-held current
SQLite owner.

Intentional strengthened behavior is explicit: selected writes check row counts
and exact readback, completion also compares the original cost, noncanonical
stored costs fail closed, and unconfirmed runner outcomes cannot release the
owner. The preserved hosted reference retains the original behavior for
independent comparisons; selected native tests must poison that reference.

## Build, admission and development evidence

The production candidate builder requires a successful matching source-complete
cold report and its compiler. It refuses before creating its output directory
when that custody does not match:

```sh
python -m tools.build_hia_execution_budget \
  --compiler /absolute/path/B3.image.bin \
  --cold-report /absolute/path/cold-report.json \
  --output /absolute/path/execution-budget-candidate
```

Select the resulting manifest with `HEPTA_HIA_EXECUTION_BUDGET_MANIFEST` before
constructing the existing service or `AgentStore`. Source changes invalidate
admission even when an earlier image was already cached. The installed wheel
contains the HIA source resource; the runtime does not import the generator or
builder. The selector is latched for the store lifetime, so changing the
environment cannot replace a live claim's policy.

The bounded entry has read-only request, mutable output and retained mutable
state buffers. Its retained state is exactly 13,568 bytes; its output capacity is
13,312 bytes. The fixed transition vocabulary is:

| Event | Native decision |
| --- | --- |
| 0 | Initialize create, claim or observation with immutable claim/connection identities |
| 1, 2, 3, 4 | Admit begin, exact row, one affected row, and confirmed commit observations |
| 5 | Preclaim one run and emit its bounded remaining timeout |
| 6 | Consume that run's exact confirmed-termination token and add its decimal cost |
| 10 | Preclaim completion against the originally captured owner and cost |
| 90 | Return retained diagnostic fields without execution authority |

The retained v67 development run r6 at implementation commit `646021c` passed all 22 outer tests
in 70.026 seconds with no skips. This includes byte-for-byte independent VM and
actual native state comparisons, real SQLite transaction conflicts and process
crashes, lost commit/outcome acknowledgements, ordinary-writer isolation, two
contending claimants, temporary-schema shadowing, database/WAL identity drift,
decimal overflow and installed-wheel custody. The same run nested all 14
unchanged Agent lifecycle/campaign tests with the hosted budget constructors and
methods forbidden; all passed without skips. Real native-child execution is
used for the request-journal lost-outcome/restart controls.

Those historical development images were compiled with an explicitly retained predecessor
compiler. They are not a new source-complete cold qualification. The original
r4 fault-harness failures and the independently reproduced pre-fix TEMP shadow
failure are retained as failed evidence; the later passing controls do not
relabel those observations. The corrected harness separately records the
runner's two reference-VM subprocesses and the target native invocation.

## Remaining production ownership

This replaces execution-budget policy and claim state. The request, context,
cost-ledger, artifact, slot, version and lease tables retain their existing
owners. Source admission, tool dispatch, worker/process control and broader
installation release lifecycle remain separately scoped. No historical
completion journal, live migration, release garbage collection, service
activation or whole-stack HIA closure is claimed here.
