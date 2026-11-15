# Occurrence-aware SQL resource proposal — not implemented

## Why the existing single tap is insufficient

The base shared module is 33,720 bytes, SHA-256 `939eff3e5144ccd0dec5f25d5084f03c4ec338b812ccaefa85380d5464f4eb95`. Its `NativeCall`/`DeliveryRecord` APIs already identify actual native handoff, complete receipt confirmation, current ancestry and exact explicit resources. They do not carry a sequence of foreign SQL observations through a Python driver with several independent SQL calls and native transitions.

The separate read weak-R3 proposal has one `_borrow_prepared` / `_borrow_armed` pair per foreign activation. It cannot be reset for a second SQL call. Its healthy child ACK closes only that activation's own weak slot; another actual ancestor has an independent slot. It does not constitute a generic multi-SQL operation owner and is not admitted as a dependency by this design.

Unconditional `record.associate(db)` before native plan12 is also too broad: it makes a DB resource applicable before any SQL attempt, and loses the distinction between association and effect occurrence. Applying `ResourceScope(db)` to the whole method would similarly arm parent facts merely when the scope exits, including branches which performed no SQL. A strong Store association followed by a weak tap cannot restore the original temporary Store lifetime.

## Three levels of responsibility

### 1. Selected operation scope

A proposed foreign-effect sequence reserves a real delivery record and growable fact custody at the selected operation's entry. It installs an ambient `foreign(observation=False)` while the original body runs. This receives real child loss without pretending that Python method entry is native handoff or that ordinary return is a HIA ACK.

It spans the actual operation only. `release` calling dynamic `lease` has a genuine nested operation; neither scope rewinds or aliases the other's SQL facts. Direct `_execute` without a containing selected operation gets a standalone occurrence and preserves its original connection argument.

The record owner may retain the original driver while its original `self` local is alive. A resource fact must nevertheless use the actual Store receiver and connection obtained at their original expressions: the driver's mutable `store` attribute is not a substitute for a captured identity.

### 2. One fresh SQL occurrence

Each original `_execute` invocation gets a new mechanical occurrence, allocated before its effect. Proposed fields are: containing sequence identity, occurrence index, creator PID/thread, exact captured connection, optional weak registered Store generation, reserved promotion/custody slots, attempted flag, original outcome state and final disposition. Any scope/holder links must not accidentally strongly retain the weak Store.

This is an API contract proposal, not a new public input restriction. Original connection and provider types stay accepted. No SQL string parse, operation-name allowlist, DB pathname or guessed receiver layout determines identity or loss.

| Stage | Fact | Failure semantics |
|---|---|---|
| Reserve | All slots exist; original connection is held by the original argument/local; no attempt. | Preparation failure can release an unarmed occurrence. A genuine reentrant child loss remains sticky in the current chain. |
| Arm | Original method lookup and parameter evaluation have completed; final guard passes immediately before the literal call. | Interruption here cannot be certified as pre-effect. Arm performs no new container allocation. |
| Provider outcome | Original `execute` has returned or raised. | Preserve the exact outcome. An ordinary provider exception does not by itself establish native delivery loss or reveal internal partial SQL work. |
| Operation outcome delivered | Original whole method return or ordinary refusal has been delivered and there is no genuine pending child loss. | Release the operation's own facts. Do not call DB close, SQL retry, rollback or refund. A known refusal after earlier INSERTs keeps original semantics. |
| Actual loss | A real transport/native delivery origin in this live operation remains unconfirmed while a relevant occurrence was attempted. | Preserve the pre-reserved exact resources and causal origin. Reject reuse/retirement on that exact identity. Normalize only the original request-rejection families where required; retain MemoryError and process-control identities. |

A returned SQL outcome is not an ACK for later native7/8/9. Conversely, native9 is not an ACK for the SQL suffix after it. Occurrences survive unrelated intermediate receipts until the whole operation's original outcome is delivered, or until their independent parent holder's actual ACK.

Do not call `DeliveryRecord.confirmed()` merely because `execute` returned. That API marks complete native receipt/state validation. Do not set `observed()` to manufacture a HIA protocol where none exists. Any additional internal foreign-outcome bookkeeping obligation must be explicit and pre-reserved; instrumentation exceptions cannot be classified by name as real loss. The ordinary SQL provider's own error behavior remains the original hosted boundary.

### 3. Parent observation

An actually opted-in outer activation can reserve a distinct occurrence fact before the SQL attempt. That parent fact belongs to its activation ID, PID/thread and original resource policy. Inner operation retirement cannot clear it. The parent closes it only at its actual complete ACK, and actual parent loss can retain it independently after the child is healthy and retired.

Existing public/journal ambient scopes use `capture_resources=False`; they have no holder for this activation. A different live opted-in ancestor may independently have a holder, but that does not make the false-capture parent captured. Explicit caller wiring or a narrowly specified new parent-series policy is necessary before claiming late-journal-ACK coverage. No global enable, child-terminal inference, custody-count heuristic or exception-class test is acceptable.

## Preserve the original expression boundary

Caller evaluation remains: original `self._execute` lookup, DB argument, SQL literal, complete tuple left-to-right, then helper body. The helper's original `self.store.db is not connection` check stays before the SQL method lookup.

At each original receiver expression a weak tap may observe the Store object actually returned by that lookup. It must return that same object without another lookup and without keeping a healthy temporary Store alive through `.db`, tuple evaluation or ACK. It must reserve weak generation/promotion slots before any effect. If no registered still-live generation exists, this is an explicit unbound receiver boundary, not permission to guess the Store from the connection.

After receiver preparation, check the current record and known registration again before proceeding to the next original provider. At the SQL point retain the literal shape `connection.execute(statement, guarded_original_parameters)`, with the guard as the final argument and returning the original parameters object. This preserves the original method lookup, its AttributeError metadata and full argument order. A captured-method rewrite or a second execute lookup is forbidden.

The guard must check actual loss again after all original argument expressions, including reentrant getters which swallowed or replaced a genuine child loss. It must then arm the already-reserved occurrence without allocating. Parameters are not recomputed; no `Store.db` is re-read. `_execute` overrides remain dynamic foreign callables and cannot silently be replaced with the canonical helper.

## Identity and lifetime rules

### Captured connection

The actual connection is already strongly held by the original local or parameter. It can be strongly referenced by an operation fact during that same original interval. Unknown keeps that exact object using pre-reserved custody. Healthy completion must release at the original boundary. A non-weakrefable connection is handled by exact retained object identity, not `id()` alone, a path, or a mutable driver attribute.

An operation must not poison all workspaces or all connections because they share an image or DB path. Known loss on exactly the same connection can affect another Store using that connection; a different connection at the same path is not thereby the same resource. Two Stores using one connection and one Store rebound to a second connection need separate actual controls.

### Registered Store

The weak fact contains the actual lifetime token and weak reference only, plus pre-reserved promotion storage. Loss promotion uses the same still-live generation. Healthy retirement must not acquire a strong local by dereferencing the Store, nor retain it through an owner, link or closure. A Store which died before `.db`, during tuple evaluation or before ACK cannot be reconstructed; a renewed registration does not authorize reuse of an old generation fact.

Public `AgentStore.close` checks the Store resource. Retaining a DB alone does not prove that Store retirement is fenced. Keeping a Store alone does not prove retention of a replaced connection. Raw external connection close and opaque objects with no retained actual owner remain separate unqualified boundaries.

### Reentrancy, other contexts and cleanup

Preparation can run real finalizers/native children. Recheck after the last preparation allocation and at the final SQL argument. Only actual live PID/thread/activation ancestry carries causal loss. A new loss on an already captured exact resource in another Context/thread is resource evidence, not guessed ancestry; the next boundary checks it.

Do not overwrite creator identities. Preserve original owner guards before entering a new ambient scope on an invalid creator path. Use the existing reentrant custody lock rules and fork resets. Reserve all containers necessary for unknown retention before effect; loss promotion must not depend on a fresh dict/list append succeeding after the failure.

Complete retirement must be marked before releasing healthy references that can run finalizers. A confirmed cleanup exception cannot re-arm the old SQL occurrence. A new real child call during cleanup is a new event and must be classified on its actual active chain. This requirement mirrors the existing completed-holder discipline, but the multi-SQL implementation still needs its own real controls.

## Explicit implementation decision still required

The proposed API needs an occurrence-aware sequence and independently owned parent facts. There is no approved implementation here. The next patch must choose a precise mechanical representation, freeze it with independent controls and prove that it preserves original temporary lifetimes. It may not use a synthetic native ACK for SQL, reset the one-SQL read tap, or globally turn every ambient parent into a strong resource holder.

The first implementable bounded claim is: while one selected slot operation is actually running, real child-native loss after an attempted SQL retains the exact affected connection and any still-live same-generation Store receiver, and prevents another SQL or successful outcome. Late outer ACK retention is a further claim requiring explicit parent integration. Neither claim follows from the existing frozen transition patch alone.

Peer boundary confirmation: cleanup_audit separately confirmed the false-capture parent and single-SQL limitation in a static message. It did not execute or independently review this whole proposed API; no broader peer approval is claimed.
