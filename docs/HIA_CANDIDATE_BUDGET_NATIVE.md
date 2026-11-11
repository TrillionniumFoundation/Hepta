# Native ordinary candidate-attempt budget

`candidate_budget.hepta` owns the attempt-count transition used by the ordinary
`hia_candidate` request. Explicit selection is
`HEPTA_HIA_CANDIDATE_BUDGET_MANIFEST`, admitted before creating the service's
state directory and retained for the service lifetime. An empty, absent-file,
invalid or source-mismatched explicit selection refuses; it cannot select the
hosted reference. With the selector unset, the existing reference remains the
default. Changing the environment cannot replace an already admitted policy.

The HIA owner is reached through the original
`HIAAgentService._budget(candidate=True)` → `_consume_attempt` path. It checks
the captured candidate maximum, admits the original nonnegative SQLite integer
count, computes exactly one increment, and requires an exact update count,
readback and successful commit acknowledgement before candidate execution.
The accepted public maximum remains **1 through 4,096**. No supported ordinary
input limit, request field or artifact schema is reduced.

## Existing persistence and replay

The authoritative counter is still `main.contexts.attempts` in the same
`state.sqlite3` and WAL used by the request journal. This owner neither creates
a replacement table nor rewrites existing contexts, request keys or responses.
It reuses the existing execution-budget connection's original-database,
WAL/shared-memory, creator-process and connection custody. Its private SQLite
connection executes only this fixed vocabulary:

1. `BEGIN IMMEDIATE` and read the original context count.
2. Compare-and-swap the HIA-produced new count against the captured old count.
3. Read back the exact context identity and new count.
4. Commit and acknowledge that SQLite exited the transaction.

Every statement names `main.contexts`; a same-name temporary table cannot
redirect a charge. An existing caller transaction is refused. SQLite serializes
the private connection against ordinary and other native writers, so another
thread cannot accidentally join its attempt transaction through the official
connection. The private transaction rolls back on a precommit refusal. A
successful commit whose acknowledgement was lost is not compensated or
reissued. The uncertain result is `E_HIA_CANDIDATE_BUDGET_UNKNOWN` with
`observe_original` guidance.

The request journal still reserves the original request before this charge.
Both the ordinary journal and selected `agent_journal` v2 therefore preserve
these existing semantics:

- A successfully admitted candidate attempt consumes one count even if later
  parsing, checking or candidate construction fails.
- Exact completed-request replay returns the retained response without entering
  the candidate policy again.
- A process death with a running request keeps that original request fenced.
  Before the attempt commit its private transaction rolls back. After commit
  the attempt remains charged. Restart never infers permission to repeat it.
- Reusing a key with changed arguments remains the journal's conflict refusal.

This component does not add historical attempt receipts to the database. A fresh
count cannot by itself attribute an earlier charge to a request. Direct calls
to the private `consume` method are separate explicit operations, not an
idempotency API. The ordinary request owner supplies replay protection.

## Native protocol and remaining foreign boundary

Each invocation retains a 384-byte HIA state block. A random operation identity,
connection identity, exact context bytes, monotonic transition sequence and
state checksum bind each acknowledgement. The result is at most 272 bytes.
The checksum detects accidental/protocol corruption; it is not authentication
against code that can rewrite the same process's memory.

HIA emits only begin, read, update and commit actions. The Python adapter moves
fixed bytes and scalar observations and issues fixed parameterized SQL. It does
not decide whether the count is below the maximum or compute the increment.
Malformed/noninteger/negative persisted counters fail closed; no ordinary
product path creates those values. SQL, the existing SQLite library, descriptor
and file identity observations and process lifetime remain foreign effects.

The frozen context, installation/profile authorization, total wall-clock check,
remaining wall time, candidate semantics, request journal, costs, slots, leases
and complete service lifecycle keep their existing owners. This is a native
production-policy component, not a claim that the public worker, complete
database or whole product is HIA-native. It does not authorize deletion of
those remaining hosted modules or change a live deployed service.

## Build and validation

```sh
python -B -m tools.build_hia_candidate_budget \
  --compiler /qualified/B3.image.bin \
  --cold-report /completed-current-cold.json \
  --output /new/private/candidate-budget

python -B -m unittest \
  tests.test_hia_candidate_budget_native.CandidateBudgetSourceTests -v

HEPTA_HIA_CANDIDATE_BUDGET_COLD_REPORT=/completed-current-cold.json \
python -B -m unittest \
  tests.test_hia_candidate_budget_native.CandidateBudgetNativeTests -v
```

The builder uses the common complete-source cold gate and strict native compile
receipt before publishing a manifest. The source is explicitly included in the
sdist, wheel and installed source identity. The runtime imports no authoring
tools. The same packaging registration also retains the execution-budget
dependency's previously omitted sdist source.

Runtime selection retains the project's existing **operator-trusted image**
boundary. The five-field manifest binds the selected schema, actual source and
image bytes and records a compiler digest; the runtime does not authenticate a
cold report or prove that compiler digest came from a qualified build. The
strict builder is the qualification gate. A correctly formed development
manifest can be explicitly selected for testing, as this component's native
fixture does. Runtime hash admission by itself therefore never establishes
cold qualification, all-input equivalence or production approval.

If later service construction fails while checking artifact roots or installing
profiles, both the new candidate connection and the original AgentStore are
explicitly closed. The primary construction error remains the reported error;
any cleanup error is attached to it, without retrying an uncertain close.
The dependency's `AgentStore` construction likewise closes its official
connection if native execution-budget sidecar or connection admission fails.
The regression changes the actual opened WAL pathname during native connection
admission and verifies that both real SQLite connections become closed.

The independent Core VM checks full native state/output bytes before the native
seed. Actual native tests cover the public 4,096 boundary; 261 independent
count/maximum comparisons against the original SQL; two contending connections;
temporary-schema shadowing; foreign transactions; exact readback refusal; commit
acknowledgement loss; source custody; both ordinary request-journal routes with
the reference policy disabled; failed candidate charging; exact replay; and real
process death before and after the actual commit under each request journal.
An actual sdist → wheel → isolated installation runs the ordinary budget entry
with empty PATH, authoring imports blocked and reference policy disabled. It
also exercises maximum exhaustion, restart and missing/changed packaged source.

Without the explicit cold report, the native fixture builds a fresh B0/B1/B2
fixed point and records `BOOTSTRAP_DEVELOPMENT_ONLY`. Those executions establish
component behavior; they are not the later integrated source's cold release
qualification. `HEPTA_HIA_CANDIDATE_BUDGET_EVIDENCE` retains raw build and installed
observations in a newly created directory. Global source/CI registration and
same-source qualification belong to the integrating candidate.
