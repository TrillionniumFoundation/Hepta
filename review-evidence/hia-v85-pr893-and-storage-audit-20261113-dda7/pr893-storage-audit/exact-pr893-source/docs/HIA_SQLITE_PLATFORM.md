# HIA SQLite platform foundation — development prototype

## Status and exact scope

This component is a new, explicitly selected development prototype. Its sources
are being authored and checked against the existing compiler profile. No native
execution, cold qualification, default-service activation, or whole-native
completion is established by this document.

The first end-to-end target is the existing public local consumer method
`release_slot(lease)`. An original service must create and close its real
private database before the prototype opens that same database. The native
process opens both its main and budget-role connections itself. It never accepts
a Python SQLite connection or a caller-selected raw address.

HIA owns the original ten application table definitions, SQL statement bytes,
parameter choices, transaction progression, lease lookup, active/slot/generation
short-circuit, whole issued-artifact comparison, update and commit/rollback
decisions. The first implementation uses the original integer-only native JSON
canonicalizer for the issued descriptor domain: exactly the ordinary
`id/sha256/uri` string descriptor issued by AgentStore. JSON integers remain
integers; no host precomputed descriptor-equality boolean is accepted.

The bridge contains only a closed C-call and Linux byte/resource transport.
System SQLite, its system dependencies, the dynamic loader, and build-time
GNU assembly/linking remain explicit external dependencies. The existing HIA
ELF linker is not silently extended into a dynamic linker. Ordinary Core still
has no foreign-call operation, SQLite resource type or platform effect.

The normal source checkout, normal wheel and ordinary service still use their
existing owner. This prototype does not add an environment fallback and does
not delete a live owner.

## Required continuation after the first release transaction

The first transaction is not the complete effect foundation. The same native
store must next implement the existing durable request reservation and exact
completed-response replay. Native adopt/rollback must publish the original
slot/version changes and durable request response in the same main connection
transaction; a second connection or an independently committed helper would be
incorrect. The original proof/evaluation/ABI decisions must also be migrated or
bound to their real admitted results, not replaced by an untrusted boolean.

The budget role is initialized and kept distinct, but its business claim,
completion, CAS and interruption state machine is not implemented here yet.
Those changes must preserve the original prohibition on a budget operation
while the main connection is in a transaction. Failures after a successful
commit or after losing an acknowledgement must fence the state and preserve
the real uncertainty; they must not create a compensating transaction.

The original `AgentStore.transaction` also has a specific exception boundary:
exceptions in its body cause ROLLBACK, while an exception thrown by its COMMIT
in the `else` clause does not enter that rollback handler. The prototype keeps
a separate committing state. An ordinary explicit close later releases
connections; the bridge does not invent a SQL compensation when its protocol
or transport fails.

## Trust boundary

Only the fixed source-bound HIA driver embedded into the admitted ELF emits
effect packets. fd0 carries request packets; an event/effect magic received
from the public input is rejected before dispatch. Events are constructed by
the bridge after the exact operation returns. Only an explicitly installed
trusted platform program gets this bridge. Arbitrary user Core is never
allowed to choose an entry address, external symbol, connection pointer or SQL
engine callback.

A handle is `(role, slot, generation)`. Actual `sqlite3*` and
`sqlite3_stmt*` addresses exist only in a private native table. Main and budget
have distinct slots. A statement has a role, generation, exact parent role and
parent generation. Every operation checks the complete tuple against the live
table. Finalization destroys the statement even when SQLite returns an error.
Close publishes an invalid handle only when SQLite reports successful close.

The first serial protocol has two live DB handles and at most one live
statement. The three-slot bridge table is an internal live-resource invariant,
not a limit on stored leases, versions, slots or history. Later protocols must
prove their own live-resource bound; none may impose a smaller public row cap.

## Packet format

All integers below are little-endian u64. Every packet has a 128-byte header,
a field-length table of `count * 8` bytes, and the exact concatenated fields.
Length admission subtracts from the remaining physical extent before advancing
an offset. There is no wrapped `offset + length` authority.

| Byte offset | Meaning |
| --- | --- |
| 0 | Request `HIASQRQ1`, event `HIASQEV1`, or effect `HIASQFX1` |
| 8 | Request or effect opcode |
| 16 | Native effect sequence; caller requests set zero |
| 24 | Raw C/SQLite return code in events |
| 32 | Resource role: none 0, main 1, budget 2, statement 3 |
| 40 | Resource table slot |
| 48 | Resource generation |
| 56 | Statement parent role, or observed euid for lstat |
| 64, 72, 80, 88 | Operation-specific scalar observations/arguments |
| 96 | Total payload byte count |
| 104 | Number of byte fields |
| 112, 120 | Reserved, must be zero |
| 128 onward | Field lengths, then exact field bytes |

At process startup the closed bridge emits the fixed eight-byte loader-ready
marker `HIASQOK1`. The custody adapter observes the actual waiting child PID
and loaded dependency device/inode identities before it sends the first
database request. This marker is not a SQL result or an HIA authorization.

Requests are initialize (0), release-slot (1) and close (2). The first
initialization field is the existing absolute database path. Release carries
captured key/value pairs. HIA, after BEGIN IMMEDIATE, checks the exact four
outer fields and their meanings. Host serialization does not remove extra
keys or collapse wrong types into an apparently valid descriptor.

Typed fields use separate null, false, true, signed-integer, binary64, UTF-8
string, byte-buffer, captured JSON-container, unsupported-value and encoding
failure tags. Signed integers use a sign byte plus little-endian magnitude;
HIA, not Python, decides the SQLite signed-64 binding boundary. Strings and
BLOBs remain distinct. A serialization failure is recorded as an observation
and is not raised before the HIA state machine reaches that field.

## Closed effects

| Opcode | Bridge operation |
| --- | --- |
| 0 | Publish the exact HIA response |
| 1 | `sqlite3_open_v2` on the HIA-supplied path and role |
| 2 | `sqlite3_close` on a checked DB handle |
| 3 | `sqlite3_busy_timeout` |
| 4 | `sqlite3_prepare_v2` on exact HIA-owned statement bytes |
| 5 | One null/int64/double/text64/blob64 bind chosen by HIA |
| 6 | One `sqlite3_step` |
| 7 | Copy one raw typed SQLite column before its lifetime ends |
| 8 | One `sqlite3_finalize` |
| 9 | Observe `sqlite3_get_autocommit` |
| 10 | Invoke the fixed embedded HIA JSON canonicalizer |
| 11 | Observe Linux `lstat`, mode, owner, dev and inode |
| 12 | Exit after all native resource handles are closed |

There is no `sqlite3_exec`, SQL script interpreter in the bridge,
`dlopen/dlsym`, external symbol name input, process-spawn effect, callback
pointer, or action-to-SQL dispatch outside HIA. Error cleanup may finalize and
close live native resources; it cannot publish a successful business response.

## HIA-owned release sequence

1. Recheck the official main DB and WAL/SHM namespace and the two autocommit
   states. The constructor has previously checked the private owning directory
   and established the named-file identities.
2. BEGIN IMMEDIATE on the main connection.
3. Validate the exact outer lease fields; query the retained row by captured id.
4. Reject unknown/inactive/slot/generation mismatch before decoding artifact
   data. Preserve the returned row in private HIA memory.
5. Decode/canonicalize the DB artifact, then the captured caller artifact,
   and compare the complete issued descriptor. A BLOB containing valid UTF-8
   JSON remains a supported DB representation.
6. UPDATE using the frozen returned row id. The caller object is never read
   after the input frame is captured.
7. COMMIT and check the actual main autocommit result before publishing the
   HIA success response. Body failures execute ROLLBACK; committing failures
   are fenced with their real SQLite code.

Open, busy-timeout and close failures bind the return code from that exact
completed C call before publishing a SQLite-error response. A new release
clears its retained error code; only status 5 carries a SQLite code, while
successful and other non-SQL responses carry zero. The body-failure ROLLBACK
and COMMIT-failure fence remain distinct; a failed COMMIT is not converted
into a compensating SQL transaction.

The cursor and row bytes needed after a C call are copied before another
operation can invalidate the C pointer. The HIA workspace grows mechanically;
the public historical-row domain is not narrowed to a fixed workspace row cap.


## Resource-capacity proof

The bridge grows buffers before each HIA invocation and never retries a failed
HIA invocation. Let M be the largest complete input frame seen so far, including
every actual SQLite column and canonicalizer result event. M is updated before
the event is consumed. Let P be the captured database path, R the captured
release request, D0 through D4 the five frozen column byte extents, and Z the
canonical DB artifact extent. Their live private-workspace end is exactly

`1024 + P + R + D0 + D1 + D2 + D3 + D4 + Z`.

Each column or canonical event has a 136-byte header. Thus P, each Di and Z
are at most M-136, and R is at most M. The live end is at most `8*M+72`.
Every new release resets the append cursor after its own captured request;
there is no accumulation across requests, histories or result rows. The
existing checked `16*M+65536` allocation therefore covers the complete state.

Every effect has 136 header bytes. Its payload is a captured path (plus at most
four suffix bytes), at most one captured field, one canonical input, the frozen
generation response, or an HIA-owned SQL literal of at most 202 bytes.
The required complete output is at most `max(M+136,338)`, below the existing
checked `2*M+4096` allocation. Header publication occurs only after the HIA
effect writer has checked the whole extent.

For a canonical input of B bytes, the original decoder first uses its output
buffer as a key table, then as a container stack, then as canonical JSON output.
These phases do not overlap. With K=min(262144,floor(B/4)+1), the key table uses
8*S bytes, where S is the smallest power of two at least 2*K. Consequently
8*S is less than 32*K and at most `8*B+32`. The maximum configured decoder
stack requires `128+129*48=6320` bytes. The emitted integer-domain canonical
JSON is no longer than its original JSON: redundant whitespace and escape
spelling only shrink, object sorting preserves byte lengths, and -0 becomes 0.
The checked `8*B+8192` buffer therefore covers all three uses.

The other canonical arena retains the original checked `64*(B+1)+4096`
allocation, rounded up to 4096 bytes. Its preflight stack needs 4256 bytes;
for B equal to 0 or 1 the rounded buffer is already 8192 bytes, and for larger
B the unrounded allocation exceeds 4256. The subsequent arena needs at most
`64+56*N+D`, where the node count N and total decoded string/key bytes D
are each at most B. The allocated arena exceeds that bound.

All multiplication, addition and page rounding are checked before allocation.
A capacity or allocation failure remains a fatal, non-retried bridge failure,
and cannot be relabeled as a successful transaction. The original 8 MiB JSON,
262144-node, depth-128 and compiler limits are unchanged. Source tests cover
exact workspace and output boundaries without any platform effect; native
tests must exercise small values, depth 128, a dense 2048-key object, accumulated
large retained columns and a 128 KiB generation response in real SQLite.

## Build and runtime custody

`build_hia_sqlite_store.py` requires an actual compiler and cold report before
creating its output directory. A production build must bind every component
source into the matching cold map. Explicit development builds separately
admit their compiler against an explicitly supplied frozen compiler source and
record `current_source_cold_qualified: false`.

The current development source snapshot includes the full declared source
closure, every Python package source, the unchanged contract bytes, and every
component build input. It is compared byte-for-byte before publication, but is
not called a validated release contract. This lets an unregistered development
component be compiled without rewriting the frozen compiler's source contract.
Production builds retain the original current-contract validation and matching
cold-source gate.

The builder compiles the store and canonicalizer images, embeds their actual
bytes in the assembler object, links against the explicitly selected system
SQLite library, checks the complete external symbol/DT_NEEDED inventory, and
re-reads source/compiler/report/images/ELF/tool/dependency bytes. Unknown
symbols, RPATH/RUNPATH/TEXTREL and writable-executable segments are rejected.

The Python custody adapter hashes code and sources and executes a fully
sealed memfd with seal readback. It passes a clean loader environment and
observes the actual child mappings before SQL starts. It captures arguments
and exposes the returned HIA status/bytes; it never calls `sqlite3.connect`,
reads a DB row, or runs a statement.

This still leaves hosted build, code custody, object transport and process
supervision. A raw standalone dynamically linked executable also depends on
the administrator supplying the admitted loader/library namespace. These
boundaries must remain explicit until the native installer/worker replaces
them.

## Verification that must actually run

The source module includes real Core rejection tests for unauthorized platform
effects/types, full authoring roundtrip and all original logical argument
limits, malformed extent/partial-publication VM controls, and stale event
resource controls.

The native module requires an actual explicitly supplied build, with no
implicit compiler seeding and no missing-prerequisite skip. It checks real
SQLite release/restart, outer/basic/full-descriptor rejection, a real engine
constraint failure with rollback, and BLOB JSON plus inactive-row short
circuit. Its rows are explicitly declared fixtures.

The separate integration module reuses the original public
`AgentToolCase.build_pair` verify/emit/encoding/evaluate/adopt flow. It acquires
a real lease, rolls back the current slot while retaining the lease, closes
the original service, poisons the hosted release/lease/SQLite owners, and
executes the new native process. The original service then reopens the same
state with the same artifact roots and observes the release and retained
artifact/version data. This is the required first meaningful cross-owner case.

All tests, native compilation and system SQLite execution remain unrun until
their actual recorded run. A static assembly object using explicitly empty
image placeholders proves syntax only and is never an executable artifact.

## Known remaining compatibility and closure work

The first prototype only attaches to an already-created official DB; it does
not yet replace root/artifact-directory creation or artifact-file publication.
It does not yet migrate request-journal or budget business effects, public
worker dispatch, ordinary defaults, full installed distribution, or its own
hosted build/control tools.

The normal issued artifact domain contains exactly three string leaves.
Arbitrary manually corrupted SQLite JSON values with Python's mixed
numeric/bool equality are not evidence that the integer canonicalizer is a
general Agent-data object-equivalence replacement. Full corrupt-data/error
compatibility, including exact SQLite extended diagnostic text and Python
encoding-error classes, needs separate implementation and controls before a
default replacement can be claimed. Current responses retain the actual
primary SQLite code, but do not claim byte-identical engine error messages.

COMMIT interruption/lost acknowledgement, process-death observations,
same-connection request+slot atomicity, restart replay and budget two-connection
fault controls are mandatory continuation gates. Passing the first release
transaction must not be presented as completing them.


## Development iteration 04: internal journal transaction stages

This independent source adds a separate `sqlite_agent_transaction.hepta` module.
Its entry is reachable only through closed effect 13 from the trusted store HIA
image. The bridge switches between two fixed, build-bound HIA entries while the
same private SQLite handle table and main connection remain live. It does not
select SQL statements or interpret request outcomes. Effect 14 invokes the
unchanged, source-bound `agent_journal.hepta` image and copies its declared raw
state and output bytes; effect 15 copies a real clock_gettime result.

These are internal stages under development, **not a new public rollback
implementation**. No `NativeSqliteStore.call` or `rollback` method is exposed.
The implemented stages bind the actual tool catalog in HIA, produce the request
identity in HIA, read the original requests row, perform the original journal
lookup, reserve an absent request through real parameterized SQL, acknowledge
that insert before COMMIT, and decode/replay an already completed response
without writing a cost or repeating an effect. A fresh durable reservation ends
at an explicit non-success continuation marker until the rest of the same-main
transaction is connected. The complete context/profile/artifact admission,
retained Core/signature chain, slot mutation, immutable receipt publication and
artifacts row, response validation, inline request ACK, COMMIT and finally cost
path remain required before any ordinary entrypoint is enabled. A native static
build of this intermediate module does not establish those missing behaviors.

The bridge effect namespace is explicitly version 2 in the build manifest;
request/effect field framing remains version 1. All fixed code images are bound
individually. It still uses the original main connection and the existing
prototype budget connection. A later bundle with both execution and candidate
budget owners requires three independent connections and must version its
handle-role table; this iteration does not claim budget business completion.

Each module independently retains the original 128 function, 8192 instruction
and 16 logical parameter/edge limits. The journal scratch allocation is checked
`72*(B+1)+73728+F`, rounded by the existing mapping allocator, where B is the
actual component input and F its raw foreign-type observation length. This
covers the original 56-byte decoded nodes, decoded strings, key table, parser
stack and 32768-byte private session area. Output is the original two 8-MiB
regions plus its 512-byte state header. These are allocation proofs, not new
application input limits. The main store workspace still grows from actual
observed packet extents; its multi-row/history extension must be separately
proved or streamed before use. The source preparation records all generated
CFG item maxima and preserves the original 13 test IDs without executing them.

## Internal agent capacity boundary

This proof applies to the current one-row request lookup/replay prefix in the
separate agent image. It is not a proof for the unfinished retained-Core,
receipt, history, or budget continuations.

M is the maximum complete request/event frame observed in this process. It is
not an 8 MiB application limit. The input adapter has no additional total-frame
or aggregate-memory gate. The assembly bridge checks multiplication, addition
and page rounding and preserves allocation failure as a fatal non-retried
failure. SQLite column extents are the actual nonnegative C-int results of
sqlite3_column_bytes, at most 2^31-1 each; the bridge does not replace SQLite's
own limits with a smaller row cap. Earlier frames in the same process may make
M larger than the current request.

The following values remain live together at the first journal lookup:

| Segment | Actual extent or bound |
| --- | --- |
| Fixed driver prefix | 1024 bytes |
| Captured database path | P <= M-136 |
| Captured current request | R <= M |
| Alignment and agent state | at most 7 + 4096 bytes |
| Six captured request-row columns | sum(C0..C5), each Ci <= M-136 |
| JSON lookup document | L <= 6*(C1+C3)+90 |

The JSON bound includes the two object keys, punctuation, quotes, and the
existing non-TEXT storage-class marker objects. C0 bytes may expand to six
bytes; ordinary valid UTF-8 is emitted unchanged. Thus the whole live end is
at most 20*M+2633 bytes. The agent's checked private workspace allocation is
32*M+65536, rounded to 4096. Every new request resets its append cursor, and
the six columns are all consumed in their original order before lookup.

The effect buffer needs at most L+648 for the lookup state plus wire, or one
captured payload plus fixed framing. The checked agent allocation is
16*M+4096, rounded to 4096. This capacity is distinct from the unchanged
journal semantic admission: every JSON stage other than the UTF-8-only stage
10 still has B <= 8388608, raw foreign-type observations F <= 262144, and each
returned response/cost area <= 8388608. A larger mapping does not publish or
admit a larger JSON document.

ACTIVE_DRIVER=0 retains its original 16*M+65536 workspace and 2*M+4096
output sizing. The selected agent branch uses unsigned full-width multiply,
checks the high product word, checks both additions, and uses the unchanged
allocator's checked 4096-byte rounding and mremap growth. HIA retains offsets,
not raw pointers, across relocation; no live workspace is cleared or retried.

During a journal call the additional component mappings are
round4096(2*8388608+512) and
round4096(72*(J+1)+73728+F), where J is the actual component input. For ordinary
JSON stages J <= 8388608. Stage 10 is the existing UTF-8-only exception and may
scan a larger retained BLOB before the JSON-size rejection. The current bridge
still allocates this conservative J-based scratch there; it is not an added
semantic allowance. These mapping formulae exclude SQLite's own private
allocations and the ELF/loader mappings; there is no invented aggregate
application-memory limit.

The source05 capacity result does not establish ordinary public error
transport, SQLite TEXT materialization or oversized lookup-wire equivalence.
The following source-only revision implements and plans separate controls for
those internal error paths. An internal protocol refusal remains insufficient
evidence. Neither revision activates a public rollback adapter or completes
the still-unfinished request, receipt and costs continuation.


## Sequential SQLite TEXT materialization and lookup-wire refusals

The next internal transaction-prefix revision keeps two original routes
separate. Ordinary reference journaling compares the materialized row directly.
The existing selected HIA journal first encodes its observed digest/state object
through the original bounded wire function. An abnormal retained row can
therefore encounter a different first error on those original routes. This
component currently follows the selected-journal route; equality with every
reference-route abnormal-row diagnostic remains a default-cutover blocker.

SQLite materializes the six columns of `SELECT * FROM requests WHERE key=?` in
column order. For each TEXT column, the HIA agent directly checks the complete
captured byte span before requesting the following column. It mechanically
reuses the existing journal generator's `utf8_codec` and `utf8_failure` bodies,
relocating only source reads and the three diagnostic stores. No session phase,
lookup decision, error branch, byte order or UTF-8 acceptance rule is changed.
The real journal continuation remains in phase 1 during row materialization.
Its stage 10 still requires phase 5 and is used only by the existing cached
BLOB path. BLOB, INTEGER, FLOAT and NULL retain their storage-class observations
without an invented TEXT conversion. The six-column valid row is followed by
the original fetchone step before the statement is finalized. The first
invalid TEXT stops later column reads and that extra step.

The driver verifies the inline codec return code, diagnostic start/end span and
reason before it formats the current default-`str` SQLite diagnostic. The CPython 3.12.3 and 3.14.0 implementations used as source evidence
format at most 198 original bytes, stop `%s` at NUL, then decode that message
as ASCII with replacement. This formatting limit does not truncate the actual
UTF-8 validation: an invalid byte after an embedded NUL still rejects the
column. Each non-ASCII message byte becomes U+FFFD, and the resulting complete
message is serialized by HIA into the error object. Original C0 controls,
quotes and backslashes retain the original JSON escaping behavior.

The private 4096-byte agent state has disjoint diagnostic regions:

| State-relative bytes | Purpose | Bound |
| --- | --- | --- |
| 608–639 | Error pointer, length, pending flag, temporary writer limit | Four u64 fields |
| 640–663 | Inline UTF-8 failure start, end and reason | Three u64 fields |
| 1024–1535 | Original journal continuation state | 512 bytes |
| 1536–1733 | Truncated SQLite message before ASCII replacement | At most 198 bytes |
| 1792–2385 | ASCII replacement message | At most 594 UTF-8 bytes |
| 2560–4095 | Complete canonical error object | At most 1536 bytes |

For the last region, each of the at most 198 original message bytes contributes
at most six JSON bytes; every non-ASCII byte contributes three, and original
ASCII C0 controls contribute at most six. The fixed object fields and quotes
keep the complete result below 1536 bytes. The region is additionally checked
at each byte store. These bounded regions do not consume the variable row or
lookup arena and do not change the source05 private allocation formulas.

After a valid row materializes, the driver computes the original UTF-8 wire
extent of the state string before the digest string, matching the original
dictionary preflight's LIFO traversal. An individual string exceeding 8 MiB
has the original `JSON string exceeds byte budget before encoding` diagnostic;
only after both strings pass does the complete lookup encoding encounter
`JSON encoding exceeds byte budget`. Other SQLite classes retain the existing
selected-journal type marker objects. The public 8 MiB JSON limit is unchanged.
A lookup exactly 8 MiB remains admitted to the original journal instruction.

A domain diagnostic is captured before finalization, then the original main
transaction is rolled back. A finalize or rollback SQLite failure retains the
existing SQL failure/fence behavior. The internal response status 15 carries
only the exact error object; it is not a new public adapter method, a complete
public response, a request outcome commit, or costs-finally implementation.
Those continuations remain necessary before ordinary native rollback can be
exposed.

The same existing native test ID now contains an additional declared matrix:
eight invalid-TEXT cases spanning digest/tool/state/response/started_ns,
including an invalid byte after NUL, message truncation, non-ASCII replacement,
C0 controls, and two bad columns; one valid TEXT NUL/Unicode case; three original
selected-journal wire-budget refusals; and one exactly-8-MiB lookup. The ordinary
service supplies invalid-TEXT oracles. The original `JournalSession.lookup`
supplies budget exceptions before any image call and the original service
`_error` supplies its error object. The real native process then opens and reads
the actual database independently after Python closes it. Raw columns, exact
component calls, SQLite step order, error bytes and every table's bytes/storage
classes are retained. The trace must show no stage-10 call during LOOKUP;
the real phase-1 journal state is compared byte for byte when the row reaches
the journal lookup. Separate actual-image column fixtures compare all three
inline UTF-8 diagnostic words with Python's complete byte-codec oracle, while
preserving the complete journal state and all buffer canaries. No generic
protocol refusal is accepted as an equivalent public error. The key column's invalid-TEXT case is not claimed reachable by
this valid hashed-key lookup.

These controls are a pending test plan until a new development run reports
their actual outcomes. Source preparation and assembly syntax checks are not
native execution evidence. The original 13 top-level IDs, all previous
assertions, compiler limits and workflow budgets remain unchanged.

## Explicit close after a fenced component failure

The original source08 run is retained as HOLD: a TEXT row was incorrectly sent
to journal stage 10 while its real continuation was phase 1, and the component
correctly rejected that protocol. The first statement remained live. The
budget connection closed successfully, but sqlite3_close on the main
connection returned SQLITE_BUSY (5). The adapter correctly rejected the
resulting error frame instead of accepting EOF. The source09 revision fixes
the TEXT call described above and independently fixes the cleanup path; it
does not relax the adapter's EOF, exit-code, final-opcode or custody checks.

Only an explicit, valid close request can enter the additional cleanup path.
The HIA driver first finalizes its recorded owned statement (phase 52). It
clears that handle after the actual finalize event, because SQLite consumes
the statement even on an error. An error is returned with its real code and
the fence remains set; it is not silently treated as successful cleanup.
After a successful finalize, a transaction known to be open before COMMIT
(state 1) is rolled back through the existing SQL prepare/step/finalize chain
and phase 53. Then the budget connection and main connection close in the
original order, ending with opcode 12. Neither a malformed component event
nor its rejection itself gains new SQL authority.

State 2 retains the original uncertain-COMMIT fence. Close does not issue a
compensating ROLLBACK for that state and does not label the transaction outcome.
It may finalize its known statement and close the owned SQLite connections;
the SQL engine's own connection teardown is not published as a business
rollback or success. Existing finalize, ROLLBACK and connection-close errors
remain errors and never become a successful close.

The same thirteen original test IDs retain their inputs and budgets. New
declared VM and actual-image state fixtures cover owned-statement cleanup,
deterministic rollback, uncertain COMMIT, and cleanup errors. These fixtures
do not claim to execute SQLite. A separate real cached-BLOB UTF-8 refusal
uses the unchanged journal phase-5 codec and the actual native SQLite process;
it proves the fence blocks another business call, explicit close rolls back
the still-open transaction, all table bytes remain equal, and process teardown
reaches the original EOF/rc0/opcode12 contract. The existing real six-column,
long-control, original thirteen TEXT/wire cases still must execute successfully.
These are development controls, not full rollback, budget, default-entry or
matching-current-source qualification.


## Development 10: connected rollback schema and terminal transaction

This continuation uses closed platform ABI 3. Existing operation 3 is the
retained private request-prefix control; operation 4 follows the ordinary
rollback request after durable reservation. Neither operation is registered as
an ordinary service selector. The original release operation and its authority
rules remain unchanged.

The third module authored by \`generate_hia_sqlite_store.py\`,
\`sqlite_rollback_policy.hepta\`, is connected to the native transaction driver by
effect 16. It consumes the same captured request that the real journal has
parsed, numeric-checked and hashed. The assembly bridge only copies buffers and
invokes the source-bound HIA image; it does not select a schema, error, field,
statement, transaction, or response. The module is deliberately not a replacement
for all \`bounded_json_wire\` or catalog validation APIs.

Generation reads the actual rollback input schema from the bound catalog.
Unsupported future schema keywords fail generation instead of being ignored.
The currently supported vocabulary preserves exact object/string types,
required-field messages in sorted order, decoded child traversal order,
closed object fields, Unicode character lengths, and the three actual regex
patterns. Python's \`$\` semantics permit one final LF after the matched ASCII
body. That behavior is retained; later u64 admission remains a separate gate.
All field values are copied from the admitted HIA arena, not supplied as
Python-derived decisions.

A schema or catalog rejection is written as the complete original error JSON
by HIA. The transaction module builds the original rejected response and calls
the actual journal terminal stage. The journal's actual response, details,
status and flags drive the HIA-authored costs INSERT, followed by the request
outcome UPDATE when a running intent was actually reserved. Replay returns the
original cached response without another costs row. The costs field records the
native process's observed monotonic interval; this internal operation is not yet
an ordinary Python-call timing replacement.

Policy scratch is separate from the live SQLite owner: the unchanged native
JSON decoder receives a 4 MiB key-table buffer and
\`72 * (request_bytes + 1) + 73728\` checked private bytes. Its arena needs at most
\`64 + 56 * min(262144, ((B+1)>>1)+1) + B\`; the final 32768 private bytes hold the
schema diagnostic. A message stops after 4096 Unicode characters and uses at
most 16384 UTF-8 bytes before JSON escaping; its escaped output fits 4 MiB.
The public 8 MiB JSON, 262144 nodes and 128 depth limits are unchanged. The
existing SQLite owner's checked 32M/16M private maps remain unchanged.

Source-only controls add the policy module to the original assembly roundtrip
and existing compiler profile checks. The same 13 top-level tests retain their
original IDs and budgets. One existing native test adds 22 actual original
service rejection comparisons, exact response-byte comparison, real native
costs/request SQL, and no-cost replay. They are declared tests until actually
executed; static discovery is not execution.

**Remaining business continuation.** Valid schema/catalog currently reaches an
explicit internal dependency boundary. Installation observations, context and
profile retrieval, retained artifact I/O and identity, original Core verification,
slot/lease snapshot, CAS, ABI/epoch, receipt publication, success ACK/COMMIT and
finally costs still require the next connected phases. Core verification must
consume actual retained bytes and return its complete actual result; a hosted
approval Boolean is not sufficient. Artifact file operations will use closed
ASM descriptor capabilities and fixed syscalls, with policy in HIA. No full
rollback, ordinary default, matching-current cold or whole-native claim follows
from this source preparation.


## B12: actual artifact bytes and closed file capabilities

This increment keeps the existing release, request lookup/replay, schema/catalog
and terminal SQL controls. Internal request operation 5 is an admitted descriptor
byte transport, not a new public service or environment selector. The HIA agent
uses the same main SQLite connection to execute the original artifacts SELECT.
All six columns are observed and TEXT is materialized in the original order
before descriptor/kind decisions, including the otherwise unused content_key.

HIA constructs the file path from the actual database root and retained sha256
column. A private role/slot/generation table holds all real descriptors. No fd or
address is published as a scalar handle. The bridge performs closed Linux
openat/fstat/read/write/fsync/linkat/unlinkat/close/getrandom/getdents64 calls and
checked private mapping growth; it contains no path/digest/SQL/business policy.
For the reference stable_read route, an independent readable capability opens
the complete HIA-chosen path with O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK. A
directory capability also supports raw getdents64 for the pending installed
source traversal; its existence does not claim that traversal is complete.

The read policy preserves 0..64 MiB files. 64 KiB is only a syscall transport
chunk. HIA validates regular-file/type/initial size, reads through EOF or the
original 64 MiB+1 growth observation, compares original dev/ino/size/mtime_ns/
ctime_ns and exact read length, closes the actual file, then finalizes the
existing HIA sha256_stream image and compares the complete lowercase digest.
No syscall count or fixed workspace becomes a smaller artifact limit. A checked
growth effect reserves file_start+64 MiB+1 live workspace and, only after
verification, the exact final response capacity. Existing ACTIVE0/ACTIVE1
initial capacity rules remain unchanged. Growth preserves live bytes and has
no reset/retry path. Integer additions and page rounding remain checked.

The stream component transfers its complete 1184-byte private state and command
plus <=65536 bytes. The bridge calls only the source/image-bound existing HIA
entry and returns that state and its actual 32-byte digest. No C/Python hashing
decision is introduced. Runtime external C symbols remain the original closed
20-symbol set with system SQLite and libc dependencies.

A successful internal status 17 is an ordered raw dependency request, not a
completed Store.get, Core admission or rollback. Its 96-byte little-endian
header is: HIASAF01, version 1, file length, metadata length, metadata SQLite
storage class, id/sha256/uri/kind byte lengths, kind SQLite storage class,
metadata-admitted=0 and reserved=0. It is followed by the complete actual file,
actual metadata bytes and the four retained row strings in that order. This
keeps malformed/decimal/exponent metadata as a real subsequent dependency;
the integer-only Core canonicalizer is not substituted for decode_data. A
status 18 contains the HIA-chosen reference artifact failure code/message.
Ordinary service remains unselected and full Core/metadata/context/publication/
slot/receipt/journal commit/finally-cost continuation remains unfinished.

The real native controls run after the original controls within the same
original test ID. They include byte chunk edges, an actual 64 MiB ordinary
file, wrong identity/kind before I/O, missing/symlink/directory/FIFO/over-limit
files, actual corrupted content before malformed metadata, raw malformed and
BLOB metadata dependency requests, SQLite invalid UTF-8 in metadata and unused
content_key before identity, and a real file timestamp change after the actual
native fstat observation. Python SQLite, Store.get and stable_read are poisoned
only while the independently opened native process handles its real database
and file. The original retained Python owner runs beforehand as the explicit
error oracle. No success is claimed for unfinished metadata/Core ownership.

Whole/default remains false. Directory enumeration/name filtering/sorting and
native-helper installation custody still need their actual HIA caller, including
Python-version pathlib symlink/error semantics; the raw kernel effect alone is
not installation_manifest completion.


## B15: actual artifact metadata, internal operation 6

This source candidate continues the same HIA-owned artifacts SELECT, identity
and kind checks, fd identity and complete 64 MiB content SHA chain. Operation 5
retains its exact raw dependency receipt. Internal operation 6 adds the actual
default bytes/text metadata parser path after successful content digest checks.
It has the same five captured request fields; the last is two little-endian u64
observations: kind-present and the actual Python int-max-str-digits setting.
Zero retains the unlimited setting. This is an explicit private transport;
ordinary AgentStore.get/call and valid rollback are not cut over.

HIA owns this order: SQLite materializes all six columns (and rejects the first
invalid TEXT UTF-8 column); artifact identity/kind; actual file identity/read/SHA;
metadata type; complete UTF-8 before the 8 MiB data gate; the original
outside-string fractional/exponent-token replacement; full original preflight
at 262144 nodes and depth 128; actual Agent-data arena of the transformed
wire; then native mapping to original spans and callbacks in source order. Quoted strings remain byte-identical in the
preflight input. Incomplete number suffixes stay for the original grammar
rejection. Original reference preflight messages contain reasons, not offsets.
Int parsing and future JSON wire formatting have different conversion/error
orders and are not conflated.

Closed ABI v5 adds three fixed HIA calls, with no added foreign C symbols:
effect 30 invokes the original json_preflight image and returns its real u32
status plus native reason/cursor words; effect 31 invokes agent_data_json on the admitted transformed bytes and
returns that complete HIADATA1 arena; effect 32 invokes agent_binary64 on the
actual original lexeme and returns its real status/bits. The same build pins all
nine images and every source. The bridge has no JSON grammar, float algorithm,
integer-limit decision, schema, SQL selection or public error template.

The HIA continuation formats original default-path metadata rejections. An
invalid BLOB's complete UnicodeDecodeError text follows the existing native
UTF-8 codec's actual start/end/reason observations. The parser enforces the
captured integer digit limit before any later float; it retains valid integer
lexemes, including values wider than u64, and does not materialize a host bigint.
The native binary64 routine handles full finite range, signed zero, subnormals
and correct rounding. A finite-overflow refusal is E_HIA_JSON; a component
profile/protocol failure fences the process instead of claiming an equivalent
public refusal.

Success status 19 publishes a HIASAF02 v2 frame: 16 little-endian u64 header
words (magic, version, file bytes, raw metadata bytes, SQLite metadata kind,
id/sha/uri/kind lengths, SQLite kind-field kind, metadata admitted=1,
arena bytes, nodes, bit-slot bytes, actual int digit limit, zero), then actual
file, raw metadata, id/sha/uri/kind bytes, complete original arena and 8-byte
binary64 slots per original node. Nonfloat slots are zero. No host-provided
bits, sorted query, metadata object or approval boolean enters the process.
The next HIA context stages can consume this tree; complete metadata wire,
installation rglob/getdents policy, Core admission, rollback business mutation,
receipt+request atomic commit and both budget owners remain separate unfinished
steps. A successful metadata prefix is not whole-native delivery.

Capacity proof: let B<=8388608 be metadata bytes, N=min(262144,((B+1)>>1)+1),
and F<=67108864 be actual artifact bytes. The transformed span is <=B.
The decoder output upper bound is U=64+56N+B<=23068736; its key table needs
at most 4194304 bytes, and 6320 bytes covers both original depth stacks.
The HIA continuation explicitly requests live storage for the existing prefix
P plus F, transform B, arena U, alignment and 8N bit slots. The added bound is
F+B+U+8N+14, below 96 MiB+78, without lowering any public byte/node/depth gate.
The complete output adds original identity lengths and a fixed 264-byte
protocol/header prefix. Checked additions, shifts and multiplication reject
private address overflow before allocation. The arena event has its input
mapping but does not count as a new application M for the old 32M allocation:
only its success path skips redundant driver growth, after phase 420's actual
buffer-capacity receipt. The next scalar event resumes the original reserve
path. All original request/column growth and ACTIVE_DRIVER=0 behavior remain.

The original 13 IDs and all 214 existing controls remain. The same native test
ID additionally declares 42 actual SQLite/File metadata cases: maximum bytes
and nodes, UTF-8/size/grammar crossings, duplicate escaped keys, both surrogate
refusals, malformed fractions/exponents, actual digit limits including zero,
source order versus sorted-key order, overflow and subnormal/signed-zero bits,
storage-class type errors and digest failure before metadata. Each oracle is
the original Store.get before its Python DB owner closes. Runtime calls poison
host SQLite, Store.get, stable_read and decode_data. The original preflight
wrapper is observed transparently for exact transformed-wire comparison;
native arenas/number slots are checked only as explicit test oracles afterward.
All rows, response bytes and the genuine close/exit trace remain asserted.
These new cases are source-only until the original 1800-second full component
owner actually executes them; no static receipt claims native qualification.

The integer/real/NULL storage-class negative fixtures explicitly rebuild only
the fixture artifacts table with a non-affinity, nullable metadata column before
binding values, then assert SQLite's actual typeof(metadata). The ordinary TEXT
NOT NULL schema would convert numbers to text and reject NULL. Both the original
Store.get oracle and the independent native process read this same declared
fixture database; production schema/SQL remain unchanged.


B14 source01 passed only generation/structure/discovery, not native execution.
Its proposed full raw decoder before callbacks had a reachable ordering defect:
--1.2 transforms to -0; 1-1.2 transforms to 10. Therefore the first preflight
can succeed even though the original json.loads must subsequently reject.
In [1e309,--1.2], the original float callback rejects before the later grammar
error. B14's full raw preflight would have obscured that first error. Its static
receipt and unexecuted candidate remain preserved; they are not execution proof.

The corrected HIA continuation decodes the already-admitted transformed wire.
It retains two monotone scanner cursors, not a host map or per-byte pointer
table. Each original transformation copies a raw span or replaces a complete
ASCII fraction/exponent token with one nonempty zero. Quotes, key spellings,
container punctuation and whitespace are unchanged. Thus, after transformed
preflight succeeds, any hidden raw syntax failure belongs to the original
continuous span of a transformed numeric atom. It cannot originate in a string
or a different structural subtree. The mapper covers that entire atom span,
including adjacent original tokens, rather than one replacement alone.

For every numeric atom, HIA finds the first greedy original JSON-number prefix.
A missing prefix yields the original Expecting value diagnostic immediately.
Otherwise the actual int-limit or binary64 callback runs before examining any
remaining raw characters in that atom. A remaining suffix then produces Extra
data at the root, or Expecting ',' delimiter within an array/object. No later
raw syntax is inspected before earlier numeric callbacks. JSONDecodeError
locations count original raw Unicode codepoints, with only LF advancing lines;
CR and literal backslash escape characters retain their original positions.

On complete success, the node count, parent/sibling/child links, decoded string
pool and key offsets are identical to an ordinary raw DataJSON decode: pool
base depends on actual node count, and number replacement changes no strings
or structure. HIA updates the original raw byte length, all literal/integer
atom spans, and fraction/exponent tags; it preserves every integer lexeme.
Tests compare the entire result arena against a second actual invocation of
the already-built source/hash-bound original DataJSON image on raw bytes.
That invocation is a test oracle after runtime success, not a runtime policy
or a host materialization shortcut.

The 11 additional controls preserve the original 31 candidates and add doubled
minus, adjacent-number merging at root/array/object, both earlier-number
failures versus later raw syntax, raw syntax before later overflow, integer
limit before a merged suffix, Unicode with CRLF, literal escaped characters,
and a negative prefix. Original 13 IDs, all old 214 controls and all budgets
remain. Native execution is still required before declaring this continuation
correct.

The raw-boundary mapper is a private helper called only twice per actual
kind 0..3 node, at its complete transformed atom start and end, in native
preorder. Containers and strings never pass their child or pool offsets to
it. It is not an arbitrary-offset map; a target inside a quoted token is
outside this private call domain. The source preparation records these
actual call sites and retains the original 31 metadata controls plus 11
additional masked-grammar and raw-character-position controls.
