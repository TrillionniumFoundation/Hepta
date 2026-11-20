# Native delivery causality: the D0–D3 boundary

This adapter keeps an actual unconfirmed native handoff visible through
participating foreign calls, including a provider that catches the error,
returns normally, replaces it, or suppresses it from a context manager. It
does not grant effect authority, decide HIA policy, infer successful cleanup,
or establish whole-native delivery.

## Integrated operations

| Boundary | Actual participating operations |
| --- | --- |
| D0 | `hia_native_delivery`: fresh invocation records and foreign activations |
| D1 | Service context, Store lifecycle, cost ledger, evaluation, build admission, emission continuations; their context/evaluation/ledger arithmetic transports |
| D2 | Public `HIAAgentService.call`, both ordinary and native request journal lanes, `JournalSession._run`, native-journal SQL to empty ACK obligations |
| D3 | Execution-budget and candidate-budget native calls, SQL drives, run/completion invocations |
| D4 | Store artifact/profile owner is not integrated by this change |
| D5 | Other native owners, publisher/Core/CLI/process ownership and general foreign-provider failures remain outside this tracking scope |

An owner that outlives a call receives a new record for each actual operation.
The propagation chain is the live activation chain at that operation, with its
original process and thread identities. A previous administrator bundle, an
equal image, an equal service, an inactive token or a matching exception name
is not ancestry. Completed tokens cannot be reused.

## Handoff and confirmation distinctions

| State | Classification |
| --- | --- |
| S0: validation refuses before native handoff, with no pending observation | Original ordinary refusal; no loss published |
| S1: actual native handoff started, complete receipt/state/guards not confirmed | Native delivery unknown |
| S2: original native domain refusal fully validated | Original ordinary refusal; no loss inferred from local fencing |
| S3: foreign operation returns or raises its ordinary error | Original observation path and original exception handling |
| S4: an observation/effect awaits its original ACK and cannot be delivered | Unknown even when the next native call was not entered |
| S5: original ACK prefix validated | Only that prefix is confirmed |
| S6: full terminal validated, then ordinary foreign work fails | No retroactive native loss |
| S7: participating child has a real native loss | Sticky through swallowing, replacement or suppression; no success/error ACK, further effect or false terminal |

The first loss publishes only private references into the active records.
Exception classes affect only the existing caller's error normalization after
loss is known; they never prove that a loss occurred. Only the original six
request-rejection families are normalized by the new outer propagation. Foreign
`MemoryError`, other non-domain exceptions and process-control identities retain
their original paths. Each actual native-entry transport keeps its original
exception classifier. A foreign PID/thread reaches the original owner guard
before ambient activation and retains that guard's exception class and message.

Growable custody is reserved before effects, with no new numerical quota.
Successful records retire. Unknown records retain the actual owner and first
loss until process exit. There is no in-process replay, automatic refund or
claim that the resources have been cleaned up. Fork replaces the representation
lock while preserving inherited references and creator identities. An inherited
activation cannot become the child's active causal parent.

## Request durability

Both request lanes keep their exact SQL statements and literal method calls.
The guard surrounding an argument tuple runs after its original arguments,
including serialization, and before `execute`. A known causal loss cannot be
converted into an ordinary completed/rejected request by that lane. The native
journal reserves its SQL-to-empty-ACK obligation before the SQL effect and
distinguishes an ordinary SQL-provider error from native receipt loss.

Original SQLite transactions, rollback behavior, argument order and cleanup
remain unchanged. In particular, a rolled-back reservation is still absent;
an already committed running request stays running; and a foreign SQL failure
does not become native loss merely because it occurs after a commit. The
existing worker still owns its explicit finally/close behavior. No claim is
made about a user-defined SQL proxy that performs arbitrary hidden work after
the final guard, nor about an unintegrated D4/D5 provider.

## Evidence and original gates

`tests/fixtures/native_delivery_original_9c46166.json` binds the actual local
emission commit `9c461664adc27e576d33fba6618b3764672eea9d`, complete original
component modules, fixtures, caller files, 112 original ordinary caller IDs and
original SQL call ASTs. It is not described as a published remote identity.
The only admitted later registry adjustment is one exact helper-count assertion
decimal literal in `test_hia_worker_native_helpers.py`. Restoring that literal to
38 must recover the complete frozen file hash; the other 63 files remain exact.
Original test inputs, control flow, expectations and deadlines are unchanged.

The new three source controls and eight native controls are separate from the
original component evidence. They include actual cross-owner loss, active-except
cleanup, safe/confirmed negative controls, both durable lanes, serialization
and SQL/ACK gaps, long-lived budget owners, thread/fork isolation and an actual
installed worker with a pinned emission/context/journal bundle. Each report
states the scope actually observed. Existing frozen component reports retain
their original narrower coverage declarations; they do not prove the added
cross-owner mechanism.

`tools/qualify_hia_native_delivery.py` runs the focused controls, all eleven
complete original component modules, or the six existing complete caller gates.
It retains source/image/compiler readback, ordered identities, failures, skips
and unfinished tests. The outer group allowance is 1,800 seconds; all inner
original deadlines and workloads remain unchanged. Matching-current-cold and
explicit development construction are distinct. No execution result is
asserted by this document.
