# Store transaction native owner

The complete transaction continuation is implemented in HIA. Explicit selection
routes the actual public `AgentStore.transaction` to this owner. The original
decorated body is retained for the unselected route and independent checks.
Its class-AST check alone does not establish the current public binding.

The independent oracle freezes 521 finite cases. An initial development-image
diagnostic matched all 521 on CPython 3.12, after six independent VM cases.
The later public unselected forwarder matched all 521 against each runtime's
own original on CPython 3.12.14 and 3.13.5. Three real AttributeError metadata
differences between those runtimes remain in their original observations.
Formal component, installed, loss and original-caller evidence is recorded
separately. This source declaration never substitutes for its result.

The implementation base is the published commit
`5bf69586b890706290c5fbfe93065ec0d3af40b1`, advanced normally from the
unchanged production source at `5da589f0bf6444c2c0acd95e2ba778c7e4ae1cfd`.
Its complete original
`AgentStore.transaction`, including its decorator, is byte-identical to the
c019 fragment with SHA-256
`23d89d8ae63bf196203cbd53a5cc8970083470a77fdd16625eb96d618e0a5587`.
The previously reported 17-case archive was not recovered and supplies no
evidence for this implementation.

## Ownership and public boundary

HIA owns the complete lock, BEGIN, one body suspension, COMMIT, ROLLBACK,
context exit, suppression, and terminal control. The selected route cannot
invoke the retained transaction body. SQLite, lock/object protocols, Python
generator/context-manager ABI, and the caller's body remain foreign effects.

The seven existing static callsites stay unchanged: the two ordinary journal
transactions, the two native journal transactions, slot acquire, slot release,
and reference execution-budget claim. Each still performs its original dynamic
`store.transaction()` call. This list is not a proof of exhaustive dynamic
coverage. No extra transaction, SAVEPOINT, retry, deadline, numeric restriction,
or connection-configuration change is introduced.

The test-facing factory is
`store_transaction_context(image, store, *, namespace=None)`. It returns a real
`contextlib.contextmanager` object with its ordinary generator ABI. The frame
is created on the first actual advance, not when the context manager is
constructed. Construction, pre-start throw/close, non-None send before start,
and generator reentrancy remain interpreter behavior. Default selection and
the retained route are resolved lazily at the original execution boundary.

## HIA control graph

| State or original event | HIA successor |
| --- | --- |
| Initial advance | Read the original lock and bind its special methods in the observed runtime's actual order |
| Successful enter | BEGIN IMMEDIATE |
| Successful BEGIN | Confirm the unique BODY_WAIT suspension |
| Normal body resume | COMMIT, then normal lock exit, then normal terminal |
| Exceptional body resume | Evaluate the original dynamic BaseException matching operation |
| Match succeeds | ROLLBACK, then exception lock exit with the original active error |
| Match fails or matching itself raises | Exception lock exit; no ROLLBACK |
| BEGIN failure | Exception lock exit; no ROLLBACK |
| COMMIT failure | Exception lock exit; no ROLLBACK |
| ROLLBACK failure | Exception lock exit with the replacement error and original context |
| Exception exit returns | Observe its truth; HIA selects suppression or propagation |
| Enter, lookup, or exit fails without an entered lock | Propagate the current original error; do not issue another exit |

Normal exit return values are discarded without truth testing. The exception
exit runs in the actual original active-except domain, including bare raise,
replacement error context, and outer `sys.exception()` restoration. A
suppressed failure before the unique yield ends the generator without yielding;
the real contextlib wrapper then produces its original `generator didn't yield`
result. No Python rollback or unlock fallback substitutes for an HIA decision.

## Continuation ABI

The new protocol has its own versioned request, result, and state magic. It
uses a fixed 80-byte request, 96-byte result, and 128-byte state; these are
transport extents, not new limits on Store objects or caller values. Opaque
objects and errors are retained by the host, not serialized into a restricted
JSON domain.

Requests carry an event, exact issued sequence/port, one observation fact,
mode, a two-word invocation identity, and zero reserved words. Events are
initialize, claim foreign effect, confirmed foreign success, confirmed foreign
exception, normal body resume, and exceptional body resume. Every observation
must match the outstanding state and sequence. Invalid or repeated delivery
cannot authorize another effect.

Phases distinguish newly issued effect, claimed effect, normal terminal,
exception terminal, confirmed BODY_WAIT, leave-active-handler, and refusal.
BODY_WAIT has no SQL or cleanup permission. Only its one matching resume event
can leave it. The entered-lock flag is cleared when an exit is claimed, before
the effect, so an ACK failure never permits a second exit. A state checksum,
identity echo, guarded buffers, reserved-field checks, and exact receipt/state
agreement follow the existing continuation-owner pattern.

The 13 mechanical ports are lock lookup, context-special lookup/order, enter,
the three distinct literal SQL calls, dynamic exception matching,
normal/exception exit, exit truth, and terminal object release. The generated
source has 13 functions, 231 blocks and 666 operations in 43,682 bytes and
1,155 lines. Source controls check the original one-MiB, 16,384-line,
128-function, 1,536-block, 8,192-operation, 256-block-per-function,
16-block-parameter and 2,048-distinct-SSA-name-per-function limits.

HIA explicitly chooses terminal release after leaving the handled-exception
domain. A preallocated one-shot generator preserves a genuine bare-reraise
state across that release; no error attributes or traceback chain are rewritten.
Normal CALL operands are consumed at their original call point. The oracle
retains distinct raw throw/close, caller-with, suppression, replacement and
explicitly bounded GC observations.

Each SQL effect retains the original literal method call and fresh dynamic
`self.db`/`execute` lookup. Its constant argument is passed through the shared
delivery guard immediately before the actual call. This preserves the original
callee and argument order while preventing an attribute getter from swallowing
a real child loss and proceeding to SQL. The returned cursor is discarded at
the original point. The adapter does not cache a connection or read
`in_transaction`.

## Suspension, actual resume, and custody

There is no fixed creator-thread rejection on the persistent transaction frame.
The Python generator supplies its ordinary concurrent-execution guard. Each
actual advance obtains a fresh DeliveryRecord with the current PID and thread,
associates the already-held Store identity, and follows only real active
ancestry and explicit resource associations. A fully confirmed BODY_WAIT ends
and retires that native invocation segment.

The yielded body carries an explicit Store resource activation, rather than an
unconfirmed native call spanning the suspension. Its deactivation must work
when a legal resume occurs in a different Context or thread: it must not reset
a token belonging to a different Context or change an old record's PID/thread.
The shared resource implementation is owned by the D5 work and supplies this
mechanical interface. A new advance creates a new current activation. Copied
inactive or foreign-PID/thread activations do not create ancestry. Confirmed
paused state is not refused merely because the next valid advance has a new
thread or process; exact original fake observations must establish this path
before qualification.

A growable frame-custody slot is reserved before the first lock or SQL effect.
The frame does not own its generator, so retaining a healthy frame does not
prevent the original generator finalization/close operation. Confirmed normal
or ordinary exceptional terminal releases custody. Actual unknown delivery
retains the frame, Store, and still-live continuation references until process
exit, without claiming rollback, unlock, or cleanup.

During BODY_WAIT, a real child loss on the active call/resource chain associates
that loss with the exact Store. The next advance detects the recorded loss
before sending a body-resume ACK. HIA therefore remains in BODY_WAIT and has
authorized neither COMMIT nor a speculative cleanup. This is not a classification
from an exception type. A swallowed or replaced error cannot create a normal
body receipt. A safe ordinary error, including MemoryError, retains its original
identity and follows the original HIA cleanup path when no actual loss exists.

## Shared resource dependency

The transaction owner uses the shared resource interface:

- `DeliveryRecord.associate(resource)`
- `resource_scope(resource)` and its cross-context deactivation operation
- `bind_resource_lifetime(resource, *, unknown=...)`
- `check_resource_retirement(resource, *, unknown=...)`
- `reserve_resource_observation(owner, resource)` before BEGIN

Associations are identity-only. They do not perform user `getattr`, equality,
or hashing, or infer resources from owner structure. Transaction initially
associates only its already-held Store. It cannot claim association of a DB or
lock that the original expression did not expose as a retained object. The
exact Store association must block later Store/lifecycle retirement after an
unknown transaction even after the original invocation's ambient scope ended.
Healthy unrelated Store instances remain usable. New resource guards must
follow an original owner-specific refusal when that refusal is already due.

The preallocated observation token marks an actual body resume before any new
record or packet allocation. Allocation failure cannot discard that observed
foreign outcome. The token is distinct from a native handoff and does not
invent cross-thread ancestry. Later Store close checks the exact retained
resource loss before its original close effect. Dedicated component controls
are required for this integration.

## Independent evidence and separate gates

The independent oracle uses the complete original body and strict fake
providers. It must distinguish generator `gi_running` protection, paused legal
resumption, actual RLock's own failures, custom-lock success, Context changes,
forked confirmed suspension, dynamic DB lookup, dynamic exception matching,
PEP479, enter/exit suppression, cleanup replacement, and object release.
Expected observations are never generated from the candidate.

`tests/test_hia_store_transaction_native.py` declares three Source and eight
Native methods. Its complete selected public comparison repeats the same 521
frozen cases under two explicit finite histories, in two new interpreter
processes. H0 has no preceding transaction. H1 has three real SQLite and three
ControlStore transactions; two contexts remain suspended until the complete
observations are written. One factory-parameterized history function drives
both the original and selected routes, with the original output written before
any native image mapping. Each process poisons both retained aliases and uses
the one component image already built by the parent. Parent, child and fork
grandchild counts are not conflated. The observed exact CPython 3.12.14 and
3.13.5 H0 output hashes are checked on those runtime builds; other builds use
their own complete original output. No live code reset, extra warmup loop, or
exception-field normalization is permitted.

The original R1 mixed-history comparison remains retained as a failure. A
separate original-only diagnostic showed that the declared H1 history was
sufficient to reproduce its five AttributeError name/object differences across
the complete 521 observations. It did not capture the old process's caches or
prove a particular old adaptive guard hit. New history comparisons supply
their own results and do not rewrite that evidence or prove all histories.

The installed worker checks actual durable request intent,
normal replay and lost COMMIT acknowledgement, with later close refused for
that exact unknown resource. Whole packet/output/state observations compare
the Native image with the independent VM.

`tools/qualify_hia_store_transaction_callers.py` runs all nine original ordinary
modules and their ordered 112 methods. `tools/qualify_hia_store_transaction.py`
runs the complete original journal, execution-budget and slot-ledger modules,
21 + 25 + 15 = 61, under their original fixture/deadline contracts and a common
1,800-second outer allowance. Its independently frozen static inventory must
match real TestLoader discovery. The original 130-method Store/artifact group
remains a distinct gate. No original administrator bundle gains this helper
implicitly. A passing subset never replaces another group's failure.

All previous failures remain separate evidence; no deadline, fixture, skip or
source check is relaxed. Development uses an explicit compiler and supplies
no matching-current-source cold evidence. SQLite, foreign providers, CPython
generator behavior and the surrounding hosted stack remain present.
