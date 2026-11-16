# Cursor SQL and exact resource delivery

This is the design of the separately reviewed R3 shared implementation now
included in the static read composition. Neither that composition nor its
new resource controls have been executed. The candidate still reports the
direct SQL resource qualification boundary open.

## Original boundary

Both SQL expressions obtain `service.store`, obtain that object's `db`, bind
`execute`, evaluate the original SQL and tuple, and call `execute`. SELECT
then binds and calls `fetchone`; INSERT discards the returned cursor. Keep
the original `LOAD_METHOD` form and all dynamic lookups.

A temporary Store may be released immediately after obtaining its DB. A
temporary DB may be released after execute. Strong custody through a parent
ACK changes those healthy lifetimes. A second Store/DB getter is also
invalid: it may change, raise or return another object.

The current `capture_resources=True` learns from actual downstream native
or ResourceScope boundaries. Direct SQLite has neither. Its final argument
guard stops known child loss but supplies no direct resource identity.

There is a prior capture interaction: if `service.store` constructs a real
AgentStore, that construction already enters a ResourceScope or selected
lifecycle child. The current strong parent capture would retain the Store
before any later weak SQL tap. Adding a weak tap alone cannot undo that
lifetime change. The read activation therefore needs an explicit, separately
reviewed weak-registered holder policy from its creation. Existing strong
capture remains the default for other owners; each actual ancestor retains
its own policy, with no global downgrade.

## Proposed narrow primitive

Use the already allocated ForeignCall as an explicit token, with a new weak
registered-resource observation. Reuse the existing exact lifetime weakref
and generation; do not call equality/hash, inspect object fields, guess a
receiver from its type, or first create a strong observation and weaken it.

```python
activation.borrow_registered_resource(service.store).db.execute(
    original_sql,
    activation.resource_call_arguments(guarded(original_tuple)),
)
```

SELECT keeps its original direct `.fetchone()` chain. Both helpers return
their argument unchanged and contain no SQL selection/application branch.
Each user value is obtained once at its original position. Explicit tokens
prevent nested getters/calls from consuming another operation's fact.

Borrowing an already registered resource reserves a weak identity/generation
fact before new effects. An unregistered opaque receiver passes unchanged,
without a guessed ownership relationship or new input-domain restriction.
Reserve any later promotion slot before the foreign handoff, so a lost-ACK
path does not need to allocate its only custody record.

After all weak-slot preparation, borrowing rechecks the live record and the
exact registered generation before returning the receiver to the original
`.db` lookup. A final unconditional live-record check follows that identity
query: its own allocation/GC can run an actual child whose loss concerns a
different resource. Such a loss still invalidates the current causal call.

The argument helper runs after original argument evaluation, rechecks live
delivery and the exact registered generation, then makes the same final
unconditional record check before marking this exact foreign call attempt.
No original provider is invoked by those checks. This is not proof of
a durable SQL mutation. Lookup/argument preparation failure before that point
has no call fact. Ordinary provider refusal still receives the original
RAISED ACK. Only actual delivery loss makes the observation unknown.

After complete success/error ACK validation, retire the weak fact. On actual
loss, retain the origin and promote only the still-live, same-generation
weakref target into its pre-reserved slot. Existing retirement checks can
then refuse the exact Store's later close before any budget/DB close call.
Never use object IDs to reacquire dead objects, re-read a getter, change an
activation's creator, or attach loss to a reused identity.

Healthy execution releases only weak bookkeeping. A temporary whose original
lifetime ended before ACK is not resurrected or kept alive artificially.

Links, facts and closures must also stay weak; a weak observation hidden
behind a strong resource tuple would defeat the design.

## Proposed ancestor rule

The direct SQL borrow is a distinct fact with a distinct retention rule. At
the original Store receiver point, reserve its weakref, lifetime token and
promotion slot in the current read activation and every then-live opted-in
ancestor. This happens before DB lookup, argument evaluation and SQL. No
registration, attribute probing or equality/hash call is added for an
unregistered opaque receiver.

The read activation uses weak-registered capture from its creation, including
native-child and ResourceScope facts observed while obtaining that receiver.
This prevents a temporary Store constructor from first creating a strong read
capture that a later weak borrow could not undo. Other owners retain their
existing capture policy for their native-child and ResourceScope facts.

An ancestor with the existing strong policy receives the new direct-SQL fact
through a separate `reserve_borrow` operation. That operation reserves a weak
entry, not a strong ResourceObservation. It does not weaken, delete or replace
any independently established strong fact. If an existing outer owner already
retains the same resource under its own policy, that separate retention is
unchanged; this proposal makes no claim to override its lifetime semantics.

The last-argument helper checks the exact still-active read activation and
then marks the pre-reserved direct-call fact. Each already-linked ancestor
sees that same occurrence. Getter/tuple failure before that cutpoint leaves
this SQL fact unarmed; any actual native or ResourceScope fact in those
getters remains independently classified. The marker identifies an attempted
call, not a durable SQLite success.

Each activation owns and retires its own entry at its complete original ACK.
The read ACK therefore retires only its entry. An outer entry stays weak until
that outer activation's own ACK; a later actual outer loss can promote the
still-live, same-generation Store using the slot reserved before SQL. An outer
ordinary provider exception with a complete RAISED ACK retires normally.
There is no post-read-ACK traversal to guess an ancestor, no second receiver
lookup, no late registration and no new custody-container allocation on loss.

The weak entry is registered before effects even when its strong promotion
slot is empty. Retirement checks must recognize its exact weakref/token plus
an actual holder loss, so interruption during per-entry promotion cannot
launder a known loss. A successful ACK marks the holder completed before any
bookkeeping retirement, so a later ordinary cleanup error cannot reclassify
an already-confirmed outcome. Cleanup recovery must only retire this confirmed
bookkeeping, never repeat SQL or an ACK.

Each weak slot is also rechecked against an existing recorded loss for its
exact registry weakref/token before its owning activation confirms its ACK.
The query does not acquire a healthy target as a new strong reference. A
lossy record's already-held object can match only the same numeric identity
and actual weak target; weak observations match the exact reserved weakref
and token. This is explicit resource evidence across Contexts or threads,
not a claim that an inactive or foreign-thread activation is an ancestor.
Completed holders cannot re-arm old facts because a later cleanup child
fails. Other owners' independently pending facts and strong associations
retain their original behavior.

This protocol has an exact static implementation and peer review, but no
runtime qualification. The separate controls below must establish the
declared limited boundary before nested direct-SQL custody is claimed.

| Cutpoint | Stored fact | Allowed result |
| --- | --- | --- |
| Foreign activation creation | Empty, pre-reserved weak holder | No user resource retained |
| Original `service.store` receiver | Registered weakref, exact lifetime token, ancestor slots | Original object is returned unchanged |
| All new slot preparation completed | Same weak facts; actual chain and exact generation rechecked | No `.db` lookup after a known preparation-time child/resource loss |
| `.db` / `execute` lookup or tuple failure | SQL occurrence remains false | Original error proceeds to its RAISED ACK; separate actual child facts remain |
| Final tuple guard | Same fact marked as an attempted call | Original tuple returned unchanged; direct `execute` call follows |
| SELECT result / INSERT result or ordinary provider error | Outcome awaits the original read ACK | No new strong retention merely because SQL returned or raised |
| Complete read ACK | Read entry retired; outer entries still weak | Continue original HIA graph |
| Actual native/observation loss | Still-live same-token object promoted in pre-reserved slot | Exact Store retirement refused; no retry or fabricated terminal |
| Complete outer ACK | That outer entry retired | No weak fact or healthy strong reference retained |

At the two literal call sites, bind the instrumentation callables before
entering the original expression. Preserve the original method-call form,
including SELECT's direct `.fetchone()` and INSERT's discarded return. The
helpers do not choose SQL, change the tuple, perform a provider call or decide
the read branch.

## Exact guarantee and remaining boundary

The guarantee covers the exact registered Store obtained at the original SQL
expression. Its public close cannot retire resources after that Store's
unconfirmed delivery. The DB is used through the original expression, with
no additional lookup or healthy lifetime extension.

Stock SQLite connections cannot be weak-referenced. Object ID alone does not
provide persistent DB custody, nor prove that a live Store still points at
the same DB after an arbitrary provider rebind. Independent opaque
`connection.close()` and an object whose original lifetime already ended
remain outside this guarantee. Full independent DB retention requires an
explicit lifetime identity at that DB's construction/ownership boundary; it
cannot be retroactively inferred from this read expression.

An already-recorded loss continues to forbid rebinding the same object's
lifetime, using the existing retirement check. The weak guarantee does not
attach an old fact to a different registration created before that loss became
known. A provider that replaces its lifetime or underlying DB while an outcome
is pending is therefore outside the original single-generation borrow. The
controls distinguish these two orders and retain the unknown read owner in
both cases; they do not claim independent retention of the old opaque DB.

## Validation before a narrower closure claim

Keep all 86 base and 6,286 original fault cases unchanged. Add separate
delivery controls for registered temporary destructor order, missing/raising
or rebinding getters, nested reentry, pre-handoff reservation failure,
ordinary SQL refusal and post-effect refusal with a confirmed RAISED ACK.

Actual SQLite controls must establish a persisted INSERT before losing its
read ACK, no falsely completed terminal response, and refusal of the same
Store's later close. The original read catalog forbids `request_key`; it has
no durable running-intent replay protocol. A fresh-process repeated read
therefore executes the owner again and preserves the original deterministic
cursor/INSERT-OR-IGNORE behavior. Different Stores, recycled
numeric IDs, synthetic Unknown exceptions and foreign errors after complete
ACK must not inherit the loss. All promotion/retirement failures retain raw
evidence and original exception identity.

No original body, fixture, test budget, catalog or input domain changes. No
whole-project, all-input or arbitrary opaque-resource closure is claimed.
