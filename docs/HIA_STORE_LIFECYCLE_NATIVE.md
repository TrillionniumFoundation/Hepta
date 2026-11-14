# Native AgentStore lifecycle

This component replaces the current `AgentStore.__init__` and `AgentStore.close`
control with `examples/hia_bootstrap/store_lifecycle.hepta`. Selection is explicit
through `HEPTA_HIA_STORE_LIFECYCLE_MANIFEST`, including the existing pinned worker
helper bundle. The ordinary unselected bodies remain unchanged and available.
An empty or invalid explicit selection refuses before directory creation.

## Exact boundary and baseline

The independently retained baseline is the published commit
`ad352eeb77d804c14d7407713e23d37e7f037cf1`, tree
`9c56113194795c738d3e7804eb1a89f8a1803cbd`. Its two original bodies are frozen in
fixture `store_lifecycle_ad352ee.py.txt`, SHA-256
`098ef2094a48b93782f740762ed932e7eaf0b734f71db49dac57c29260c877e3`.
The source test checks their complete AST against the retained production bodies.

HIA selects every lifecycle operation and every conditional, short-circuit,
sidecar iteration, cleanup entry and exception propagation. Fixed foreign ports
perform Path/OS operations, Python object and Boolean protocols, SQLite calls,
the execution-budget provider and actual CPython exception delivery. In
particular, SQLite storage and foreign predicate observations are not described
as native implementations.

Construction keeps the current cleanup region: it begins immediately after
the database connection assignment succeeds. Failures in chmod, post-open file
identity, PRAGMA setup, schema creation, sidecar admission or budget construction
all issue the original database close. Cleanup failures add the original note
and retain the original exception object. If adding that note fails, the same
new exception propagates. Ordinary `close` calls the budget owner first and does
not close the database when that first call raises.

The earlier R20 Store implementation is a design reference, not a replacement
baseline. Its constructor already used four subowners and started its cleanup
region later. Its native workflow run `43560753071` at
`26fd6c4c1a71dc970ae11b00c8a9ff74c5c8508d` passed the lifecycle component and 48
agent callers, but failed three of the 35 nested namespace callers. Two expired
the original 3,000 ms frozen context before baseline emission; a native timeout
test took 6.143223637 seconds against the original less-than-5-second assertion.
The process did not hit the 1,800-second group timeout. Those failing subowners,
the R20 reference constructor and altered deadlines are not imported here.

## Continuation custody

Each fixed effect requires a native claim before Python can perform it. Its
observation is then acknowledged by the same native state. Sequence, mode,
frame identity, sidecar index and state seal bind each receipt. Replayed claims,
foreign identity, corrupted state and malformed returns refuse without a new
effect. Construction-time selection is held by object identity; changing the
ambient selector cannot change that Store's close implementation.

Custody storage grows before the first external effect. Allocation failure
therefore refuses before creating a new directory or database, and there is no
arbitrary maximum number of active or nested Store lifetimes. Confirmed normal
returns release the custody slot. Confirmed original exceptions release the
slot while their traceback retains the ordinary object locals until that
traceback is released.
After fork, only the representation lock is rebuilt; inherited unknown owners
remain held. A process-identity guard runs before lock acquisition so a failed
fork callback cannot cause a child to wait on a vanished parent's thread.

A lost native claim, acknowledgement or foreign-observation storage has a different outcome: its frame and
actual Store/connection remain held until the worker process exits. The frame
and the affected Store cannot be replayed, reinitialized or automatically
closed, even if the selector is later removed. This is retained **unknown**
custody; it is not confirmed database cleanup. There is no in-process recovery
or automatic close API. A test loses the acknowledgement after a real SQLite
connection is created, collects garbage, verifies the original connection is
still open, and verifies that neither close nor finalization was invented.

## Qualification

`tests.test_hia_store_lifecycle_native` exercises the actual compiled image,
independent Core VM receipts and state, all 18 ordinary branches, 15 returning
rejection branches and 420 complete foreign-effect failure combinations. It
compares effects, active exceptions, exception identities, notes, Store fields
and close counts to the frozen original. It also covers normal traceback
lifetime, unknown custody, selection drift, administrator bundle restoration,
real wheel installation, and a complete installed worker CLI request with both
retained lifecycle bodies forbidden.

`tools/qualify_hia_store_lifecycle_callers.py` runs all **50** tests in the four
current original Agent tools, campaign, buffer and lease-snapshot modules. The
ordered IDs and exact source hashes are pinned in
`tests/fixtures/store_lifecycle_callers_ad352ee.json`. This includes the two
current initialization/SQLite durability tests absent from R20's 48-test
denominator. The gate forbids retained lifecycle bodies, counts actual machine
entries for both modes, rejects skips and checks final source/input identity.
Original 3,000 ms contexts and less-than-5-second timeout assertions are intact.

The build tool accepts either a matching current-source cold report or explicit
development mode. Test setup accepts `HEPTA_HIA_STORE_LIFECYCLE_COLD_REPORT` or
`HEPTA_HIA_STORE_LIFECYCLE_DEVELOPMENT_COMPILER`, never both, and optionally writes
component evidence under `HEPTA_HIA_STORE_LIFECYCLE_EVIDENCE`. Without either
compiler selector, ordinary full discovery builds a development compiler.
Development output does not establish matching-source cold qualification or
whole-stack native delivery.

Unconfirmed native continuation errors use `StoreLifecycleUnknown` when their
ordinary exception class would otherwise be mistaken for a request rejection.
Existing non-rejected `RuntimeError` identities and process-control signals
remain intact, as do confirmed foreign exceptions. Store construction occurs
before worker request entry, while Store close occurs afterward; their original
worker error classifications remain distinct. Unknown lifecycle observations
retain the actual Store and connection until process exit.
