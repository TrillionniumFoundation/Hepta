# Native HIA request journal owner

This component replaces the request journal decisions in `HIAAgentService.call`
when `HEPTA_HIA_REQUEST_JOURNAL_MANIFEST` selects an admitted image. HIA owns
request-key admission, exact durable row binding, replay validation custody,
one dispatch, returned-response custody, terminal completion, and transaction
cleanup claims. The original `main.requests` table and its SQLite database and
WAL remain the durable authority. No second journal, schema migration, row
reset, new-key retry, or inferred completion receipt is introduced.

The default service retains its independent original implementation in
`HIAAgentService._call_reference`. The selected implementation does not call
that implementation. SQLite, filesystem access, tool handlers, canonical JSON
and digest formation, and the Python object bridge remain foreign operations.
This is a bounded owner replacement, not a claim that the complete Agent or
production stack has become HIA-native.

## Source and runtime custody

| Responsibility | Source |
| --- | --- |
| Retained policy, transition rules, byte bounds, tokens and cleanup epochs | `examples/hia_bootstrap/request_journal.hiaasm` |
| Reproducible authoring source | `tools/generate_hia_request_journal.py` |
| Fixed SQL transport and guarded callback connection | `hepta/hia_request_journal_native.py` |
| Actual caller integration | `hepta/hia_agent_service.py`, `hepta/hia_agent_store.py` |
| Strict source-matched native build | `tools/build_hia_request_journal.py` |
| VM, actual machine, SQLite, process-exit and installed-wheel controls | `tests/test_hia_request_journal_native.py` |

The assembly is a packaged native source resource. Runtime admission binds
the selected manifest, image bytes and installed source hash. Invalid selected
admission fails before `AgentStore` creates or opens a state directory. The
installed wheel runs without importing `tools`, and the installed-wheel
control poisons the original request dispatcher and execution-budget constructors.

The image operates on one retained mutable state per request. State is not
recreated from Python flags for each decision. The checksum covers the state
header, identity bytes and active response bytes. This detects accidental
corruption and inconsistent transport; it does not authenticate a buffer
against malicious code running in the same process and able to recompute the
checksum. Host effects and cooperating SQLite writers remain trusted parts
of the adapter boundary.

## Original journal and transaction ordering

The existing six-column row remains unchanged:

```text
main.requests(key, digest, tool, state, response, started_ns)
```

HIA validates the exact key, request digest, tool, state, response presence,
timestamp and response bytes at the relevant transitions. Every fixed journal
statement explicitly names `main.requests`; a TEMP table cannot become request
authority. Inserts and completion updates require a real affected-row count of
one and an exact row readback before COMMIT. Completion uses a conditional
update over the original key, digest, tool, running state, null response and
original timestamp.

The selected adapter opens a dedicated connection to the same existing
database with `mode=rw`, WAL and `synchronous=FULL`. It retains the official
`AgentStore.db` object, main-file identity, WAL and shared-memory identities,
and creator PID. Replacement, symlink, ownership or writable-mode drift
refuses before request SQL. The official connection remains an ordinary
attribute with its original setter behavior. The private connection cannot
borrow an already active transaction from either connection.

For a new eligible key, native admission emits BEGIN, row read, running-intent
INSERT, exact readback and COMMIT. Dispatch is legal only after that commit is
confirmed. Existing rows have three distinct outcomes:

* A different request digest conflicts with the original key binding.
* A noncompleted row remains unknown; admission never reexecutes that request.
* A completed row supplies its exact stored response to replay validation.
  Validation and its final COMMIT must be acknowledged before replay bytes can
  be returned. Verification-proof replay still validates its retained scope
  inside the original request-read transaction.

Ordinary handlers run after the durable intent. Their returned or known-error
response must first enter the HIA confirmed-result phase. The original cost
ledger write still occurs before the ordinary terminal-response transaction.
HIA then opens a new private transaction, validates the original running row,
updates the exact response, checks readback and requires confirmed COMMIT.

For `hia_adopt` and `hia_rollback`, HIA opens the private effect transaction and
revalidates the original running row before emitting dispatch authority. Slot,
version and artifact-index changes, plus the exact terminal response, use that
same connection and transaction. They commit together. A known handler error
can produce a rejected response only after confirmed rollback of this effect
transaction; the rejected response then receives a separate completion
transaction. An unknown rollback or commit never manufactures a rejection.

The completed atomic path accepts a subsequent `finish` only as exact-byte
idempotent readback. It emits no new SQL. A replayed ticket cannot use that
completion operation, dispatch a handler or mutate its response.

## Explicit callback connection

The transitive effect and replay helper surface was inventoried before adding
connection plumbing. Fifteen service helpers carry an optional explicit
`_connection` argument:

```text
_context, _profile, _program, _native, _build_inputs, _build_receipt,
_subject, _verification, _check_native_refinement_evidence, _required_claims,
_slot_snapshot, _conditional_slot, _hia_adopt, _hia_rollback,
_replay_verification
```

Five store helpers carry it onward: `get`, `get_json`, `put`, `json` and
`check_profile`. Calls without a supplied capability retain their original
argument shape and official connection. There is no ambient connection
substitution or thread-local fallback.

The effect capability recognizes the twelve literal SQL statements used by
those paths and qualifies each table as `main`. It checks creator PID, calling
thread, exact state and connection ownership, native pending token, phase,
mode and the still-open transaction before each operation. Its cursor wrapper
allows guarded fetching and row-count observation, never arbitrary cursor
execution. Replay capabilities admit only the SELECT subset. Retained
connections and cursor views are revoked when the native phase changes.

The actual adopt and rollback controls deny all SQL on the official connection
during the handler and still complete the effect through the private
capability. A concurrent ordinary writer blocks independently, then commits
its own work; it cannot join or be rolled back with the private atomic effect.

## Retained state and acknowledgement boundaries

The main ABI uses a 128-byte request header and a 1024-byte state prefix plus a
bounded response buffer. Runtime response capacity is 8 MiB, matching the
existing wire bound. Tests also exercise smaller exact buffers. Request and
connection nonces bind every transition to one state instance and connection.
The 64-bit sequence refuses exhaustion instead of wrapping.

HIA validates UTF-8 and counts Unicode scalar values for the existing eligible
request-key length of 1 through 192 characters. A transport may carry at most
768 key bytes. Overlong and nonstring candidates remain ineligible for a
durable key, as in the existing service validation flow. NUL is an ordinary
key character. The bounded row format admits canonical nonnegative decimal
timestamps up to 64 digits and printable ASCII tool names up to 128 bytes;
the actual service tool names and generated timestamps are within that scope.
This does not promise equivalence for arbitrary malformed legacy SQLite rows.

| Native phase | Meaning |
| --- | --- |
| 1–5 | BEGIN, read, write, exact readback and COMMIT acknowledgement |
| 6 | Admitted request or confirmed atomic abort, with no pending callback |
| 7 | One callback dispatch has been claimed; its outcome is pending |
| 8 | Completed owned response or validated durable replay |
| 9 | Refused or uncertain state |
| 10 | Callback rollback pending |
| 11 | Durable replay validation pending |
| 12 | Exact callback result captured; terminal SQL may now be requested |

Phase 12 closes a reentrant completion window. A callback cannot call `finish`
while its own result is still pending. After it returns, native state captures
the exact serialized response before the caller receives it. Mutating the
returned Python object cannot authorize a different terminal response.
Interruption before or after native acknowledgement fences the request and
preserves the original durable row for observation.

### Native cleanup epochs

Rollback authorization is held in native state, independently of Python error
messages. Word 25 receives a new transaction epoch before every emitted BEGIN:
initial reservation, atomic effect and ordinary/rejected completion. Word 19
records the last consumed cleanup epoch.

Event 91 is a separate 32-byte cleanup-claim receipt. It validates the retained
checksum and both immutable nonces, consumes the current epoch, seals the
state, and only then grants one rollback attempt. It does not grant dispatch,
completion or ordinary transition authority. Repeating the claim returns no
grant. Every explicit and exception-cleanup SQL ROLLBACK goes through this
entry. A normal native rollback acknowledgement additionally requires the
consumed epoch to match the current epoch.

This covers a lost native return value, interruption before storing a Python
receipt and interruption while publishing cleanup diagnostics. Those failures
cannot restore rollback permission. A confirmed atomic abort followed by a
separate completion transaction receives a new epoch, so legitimate later
cleanup is still possible. If rollback cannot be confirmed, the connection
retains its actual state owner and is fenced. Closing that connection remains
foreign resource cleanup; it does not create a completed request or retry
authority.

`RequestJournalUnknown` is intentionally outside the service's known-error
formatter. A lost BEGIN, COMMIT, callback outcome, native receipt or cleanup
acknowledgement must not be turned into a completed error response. A fresh
read of the same durable row can return an already committed exact response;
a running row remains unknown. No alternate key or historical completion is
invented.

## Qualification and evidence

The strict builder accepts only a completed source-matching cold report and
its compiler image:

```sh
python -m tools.build_hia_request_journal \
  --compiler /absolute/path/to/B3.image.bin \
  --cold-report /absolute/path/to/cold-report.json \
  --output /absolute/path/to/new-request-journal-build
```

Set `HEPTA_HIA_REQUEST_JOURNAL_MANIFEST` to the resulting `manifest.json` to
select the runtime owner. Selection is explicit; this work does not flip a
production default or migrate live requests.

For integration tests, `HEPTA_HIA_REQUEST_JOURNAL_COLD_REPORT` selects that exact
report and its nested final compiler image. Both request and execution-budget
dependency images are built by their strict builders from the same report and
compiler. Combining this with
`HEPTA_HIA_REQUEST_JOURNAL_DEVELOPMENT_COMPILER` is an admission error. Invalid
cold admission fails before any evidence directory or development seed is
created. Standalone B0/B1/B2 or explicitly reused compiler runs are separately
labelled development evidence and never relabelled as source-matched cold
qualification.

Controls include independent HIA VM versus actual machine state bytes, exact
SQLite intent and completion, one concurrent winning owner, Unicode key
boundaries, malformed owner tokens and retained-state corruption, real
interpreter acknowledgement interruptions, all transaction cleanup epochs,
readonly replay and capability revocation, TEMP namespace shadows, actual
main/WAL/shm replacement, real ordinary-writer concurrency, actual Agent
artifact/adopt/rollback failures, eight process-exit boundaries with restart,
and an installed wheel with authoring and reference policy forbidden.

The unchanged original Agent tool and campaign suite runs jointly with native
request and execution-budget owners and poisoned reference constructors.
Development runs retain 34 original cases and defer only the shared discovery
source-contract check to integration. A matching cold fixture includes that
original check as well, for 35 nested cases. Independent adversarial review
also exercises exact interpreter opcode and return-value boundaries.

Two actual failures are retained as failures: the original `cea9531` cleanup
could attempt three rollbacks after one unconfirmed rollback, and `b291c7e`
could attempt a second rollback if Python poison publication was interrupted.
The native transaction-epoch guard in `b7be6d9` closes those reproduced cases.
Its independent actual-machine review passed twelve scenarios without changing
the reviewed source or image. Later fixture and test changes do not relabel the
old failures or expand that independent review's source scope.

The final author development run, `hia-request-journal-development-r8`, passed
all 22 outer tests in 97.096 seconds with zero skips. Its nested original suite
passed 34 cases with zero skips. The separately retained independent review
passed twelve actual-machine scenarios. The author run uses an explicitly
reused predecessor compiler, so these results are development evidence, not
qualification of a new integrated cold source profile. Its exact native source
hash is `be7c5f3c19fcd6275b9a0d62c7122f2098b7f5e00890ed3214cc80dc85ec253c`
and image hash is
`3bf79d8e9a6353356f773bbdc8f2454e79f8952a48c96b27c6c7f45bf3e027e6`.

## Remaining owners

Request sequencing is now an explicit selected native owner. It does not
replace context creation and mutation, artifact file/index policy, slot and
lease policy, worker scheduling and continuation decisions, cost-ledger policy,
proof and plan semantics, or SQLite's transaction engine. The atomic helper
connection is a constrained adapter to those existing owners, not a claim that
their policy has moved into this HIA module. There is no row garbage collector,
retention policy, destructive retirement, production activation or full-stack
closure claim. Those boundaries remain separate qualification and migration
work before the original implementation can be removed.
