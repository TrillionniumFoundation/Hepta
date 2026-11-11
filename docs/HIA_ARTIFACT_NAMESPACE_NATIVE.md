# HIA artifact namespace owner

## Development scope

This document specifies the next owner under implementation. It is not a
qualification report, runtime default change, or full-stack closure claim.
The source baseline is the exact tree
`ac479ebeceef01fccae7260f2954d5766f44640e` recovered from the saved request-journal
archive. Recovery commit `829e1d6cd626d8479dcce160a59523381a12e9f9` has new
history; it does not recreate original commit `56cf394`.

The indivisible boundary is `AgentStore.put`, `json`, `get`, `get_json`,
`resolve_uri`, `profile` and `check_profile`. A separate native byte publisher
already performs content hashing, bounded reads, immutable no-replace
publication, file fsync and directory fsync. The remaining namespace decisions
must move together: content/metadata binding, reference issuance, exact row and
kind authority, URI resolution, and profile-to-artifact correspondence.

The existing tables remain authoritative:

```text
main.artifacts(id, sha256, uri, kind, metadata, content_key)
main.profiles(id, sha256, artifact)
```

There is no replacement database, namespace reset, row migration, content
overwrite, reference garbage collection, or automatic retry of an unknown
operation. Existing caller-owned transactions retain their atomic boundary.

## Native state and effect interface

One retained HIA state belongs to each selected `AgentStore`. It carries a
store nonce, monotonic sequence, current operation identity, captured immutable
input bytes, exact SQL connection/scope identity, pending effect token and
outcome. It is not reconstructed from Python boolean flags on each call.

Every foreign effect has three native transitions:

1. Stage the exact effect and its immutable inputs.
2. Consume its launch claim before SQL or publisher execution.
3. Accept one matching outcome for that claim and operation/scope identity.

Pending or unknown effects block ordinary reentry. A Python return-value or
diagnostic-store interruption cannot restore launch authority. Observation is
a separate read-only native entry; it cannot clear a claim or authorize replay.
State corruption, sequence exhaustion, wrong owner/connection/epoch and stale
outcome tokens refuse. Checksums are corruption checks, not protection against
malicious code with same-process access to native memory.

The native policy composes the exact canonical content-key bytes from retained
kind, metadata and content hash. The existing canonical JSON codec remains a
foreign value bridge, and metadata is frozen once before effects. Content and
binding hashes come from the admitted HIA publisher. HIA forms UUID4 reference
bytes from supplied entropy. A selected namespace requires that native byte
dependency; it has no hosted hash/read/write fallback.

## Exact row and file custody

An existing content-key row must match the exact content hash, kind and frozen
metadata before it can be reused. A publication receipt does not issue a
database reference. `INSERT OR IGNORE` permits a concurrent dedup winner only
after exact row readback; an unrelated ID/URI collision cannot supply a ref.
References are checked against their original namespace row before file reads.
URI resolution binds the observed URI row and its subsequent identity lookup.

Profile registration and verification include the profile row, the referenced
artifact row, its `profile` kind and actual file bytes. Success at one lookup
cannot replace the remaining observations. Every SQL statement is qualified
with `main`; TEMP namespaces cannot become authority. Each observation has its
own native outcome token.

Known input/authority refusals preserve ordinary rejection semantics.
Unconfirmed publication, SQL execution or acknowledgement preserves the native
pending operation and raises a nonterminal error. That error must bypass the
request-journal terminal rejection formatter. Files may remain after a failed
or interrupted database step; their presence alone never proves completion of
the original request.

## Transaction scopes

Three connection scopes are distinct:

| Scope | Required custody |
| --- | --- |
| Original official connection in autocommit mode | Original main/WAL identity, creator PID, actual connection and no enclosing transaction |
| Existing `AgentStore.transaction()` | Native-issued scope nonce/epoch bound to the original official connection, plus exact BEGIN/end claims |
| Explicit request `_EffectConnection` | Its actual native request nonce, connection identity, transaction epoch and pending callback token, rechecked before effects |

The namespace owner never commits an explicit request capability. It returns
row authority within that supplied transaction; the request owner still commits
slot changes and exact response together. A revoked request capability cannot
be replaced with the autocommit connection to finish a pending operation.

The four original service `store.transaction()` callers are the reference
request admission/atomic path and lease acquire/release; the retained reference
budget also uses that original transaction helper. Their original connection and
transaction boundary remain. Native scope state must preclaim BEGIN, COMMIT
and ROLLBACK and retain unknown outcomes. Namespace-operation and enclosing
scope pending slots are distinct: one legitimate SQL rollback may follow an
unknown namespace operation without overwriting that operation's uncertainty.
The original request intent remains the durable operation journal.

When namespace and request owners are both selected, their adapters share the
original `AgentStore.lock`. Both official and private transaction entry take
that lock before SQLite's write lock. This prevents a private request callback
waiting for the namespace lock while a legacy transaction holds that lock and
waits for the private SQLite writer. The database handles and HIA states remain
distinct. Unselected request behavior retains its original separate lock.

## Explicit compatibility limits and strengthenings

The supported public input scope uses exact byte payloads, UTF-8 string kinds
and profile identifiers, canonical issued artifact references, and the original
bounded JSON value bridge. Payloads retain the inclusive 64 MiB quota; canonical
JSON and each text field are bounded by 8 MiB. A supported legacy profile row
contains the exact canonical 176-byte artifact reference emitted by the
original `wire(ref)`. Arbitrarily edited SQLite rows, nonstring kinds and
unbounded diagnostic identifiers are not claimed as an arbitrary-object API
equivalence result.

Metadata is serialized once. Both newly issued and existing rows bind that
exact byte string. Read operations also recompute the content-key binding from
the observed content hash, kind and metadata, using the native byte owner's
hash operation. Profile lookup verifies that its artifact hash equals the
profile hash. These are explicit integrity strengthenings of the reference
implementation's weaker row checks.

The fixed publisher bridge now distinguishes an actual returned process refusal
from unavailable execution or a lost/invalid receipt. It retains the original
`PublicationRejected` superclass and message. HIA may accept an exact confirmed
read-only/hash refusal; no mutating publication refusal or unconfirmed handoff
grants a retry. Byte-owner admission can cancel only a first staged namespace
operation whose native launch count is still zero. This cancellation cannot
clear any operation that has started an effect.

The native scope cleanup guard consumes its epoch even when the original
connection is observed outside a transaction. A later foreign transaction
cannot acquire that old cleanup authority. A lost COMMIT/ROLLBACK receipt keeps
the scope uncertain even when an independent observation finds no transaction.
The original reference method bodies remain separately named and selected only
when the namespace owner is absent.

## Required qualification before integration

The completed owner needs independent VM and actual-machine policy controls,
original/native API comparisons, exact metadata binding and UUID formatting,
content dedup races, main/TEMP isolation, profile/row/file corruption controls,
native publisher receipt loss, actual SQL acknowledgement loss, reentry and
revoked-scope controls, process-crash/restart observations, and installed-wheel
execution with original namespace policy and authoring imports forbidden.

Joint controls must run the actual request and execution-budget owners, actual
adopt/rollback and leases, and the existing byte publisher. Development compiler
reuse remains labelled development. Integrated qualification requires one
matching current-source cold report for all selected dependencies. No passing
result or completed implementation is asserted by this design checkpoint.
