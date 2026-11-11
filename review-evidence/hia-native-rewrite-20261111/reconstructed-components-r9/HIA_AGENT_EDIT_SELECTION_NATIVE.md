# Native selection before query construction

This development component continues the exact `0ef9541b2fc12f4b01ab5078b05d0b304cfa90f5`
worktree. It is not selected by the installed product, does not retire Python
owners and does not close the public foreign-object capture or fixed driver.

## Behavior and ordering

`agent_edit_selection.hiaasm` consumes an actually admitted immutable Core
SourceIndexLease and a separately captured general Graph of selector values.
It checks the original unique nonempty list-or-tuple field subset before the
three exact string identities. It then resolves function, block and the unique
value-producing instruction in the original order. An absent or malformed
name is compared as captured bytes; it is never prematurely sent through a
JSON encoder. Unmatched lone surrogates and names exceeding one MiB therefore
retain the original lookup failure instead of a new serialization error.

Successful output is the entire typed `[Core, selection]` packet. Core bytes
are copied from the actual immutable input. Names come from the matched Core
declarations; field order is preserved and tuples become the selection list.
The real native packet issuer must validate the output and produce its index
before the facts and complete query kernels consume it. A handcrafted bitmap,
matching header or digest is not a substitute for that issuing call.

There is no new JSON envelope around the independent 8 MiB public Core input.
The 64 MiB typed transport bound is separate. Each accepted Core JSON node
contributes at most 24 bytes of packet overhead, while decoded scalar payloads
fit the independently admitted input. Even the 8 MiB / 262,144-node source plus
the small verified selector lies below the transport bound. Private workspace
capacity grows from the actual measured complete packet extent.

The three-buffer entry is `(CoreSourceLease, command-plus-Graph, workspace)`.
The second buffer is borrowed read-only. The 128-byte `HIAQSC01` command binds
lease, request, sequence and the four Graph node IDs. Workspace starts at
1,024 zero bytes. A `HIAQSE01` event at offset 256 returns DONE, GROW or the
original semantic reason, with the full packet at offset 1,024 on success.
Continuation pins the actual immutable source headers, lengths and command;
the fixed issuer owns payload immutability. Replay, dirty initialization,
changed identity and stale sequences permanently poison the invocation.
Short buffers are discarded even when they cannot hold a poison marker.

## Exact original development observations

Authoring r1 failed because the existing authoring builder does not implement
`break`. Its original source and exception are retained. Authoring r2 uses
the equivalent bounded loop condition and keeps all original compiler limits.
It contains 34 functions, 376 blocks, 79 maximum blocks in one function,
1,350 operations and at most 9 block parameters.

Independent VM controls executed seven complete cases and nine entries before
the actual qualified B3 compiler was used. They cover successful tuple fields,
the last declared function and all five original selection diagnostics,
including surrogate names. The generated HIA source is 85,553 bytes with SHA-256
`ac2ce78ddd068991024b386528336a2ded14284f26cf50ad93578d706c66ce55`.
Its actual image SHA-256 is
`e9c2c70d841000c2eb004ba0ee4d291653a0c234398f05464a82439d17376e2c`.
The compiler is the unchanged 669,556-byte B3 with SHA-256
`35ee92b7258134b0bdf517448b51cfdef4c191a510af26ae581b81ad2924ee5b`.
The original 10 CPU seconds, 20 wall seconds, 256 MiB address-space and 1 MiB
compiler source/output/workspace limits remain unchanged.

Native test r2 completed 19 full query cases, then its independent VM assertion
was incorrectly placed inside the region that forbids the old JSON decoder.
That harness failure and all preceding raw entries remain failed original
evidence. Native test r3 performs the independent VM comparison outside that
guard; it changes no production HIA source or image.

Native r3 passed all 121 semantic/whole-query cases and 11 private protocol
controls in 19.188625915 seconds. It made 181 actual selector entries. Six
independently admitted Core inputs passed the actual integer JSON decoder,
integer arena-to-packet codec and packet/index issuer, with complete input,
output and workspace objects saved by content hash. Thirty-eight complete
queries then passed native facts (76 entries), query projection (114), packet
to Graph (76), packet issuer (114), general wire scan (76) and emit (114).
Complete final query bytes equal the retained implementation. The tests disable
the hosted verifier, query/slice owners, JSON materializer, typed encoder,
detached index decoder and `json.loads` during the actual native chain.

Controls include all 30 ordered nonempty field permutations with list/tuple
forms, exact-kind refusals, cyclic fields, missing/surrogate/large names,
first-error ordering, v8 read/mutable loans, both outputs of one instruction,
the last of 1,024 functions, the last of 4,096 blocks and the last of 256
operations. Full workspace VM pairs, unchanged inputs and boundary canaries
are retained. These are component/development observations, not cold performance
or a new whole-stack qualification.

## Missing-field continuation, source r3 and native r4

The batch/single input prefix represents an absent fields value with Graph node
ID zero, matching the original dictionary get result. Source r3 permits zero
only for that fields node and emits the original fields refusal first. All
identity nodes still require valid nonzero Graph IDs. This is the only source
change from r2; all r2/r3 observations above remain original evidence.

The current source SHA-256 is
c921bd39eb8819c19333c2fd1efaf802e39e45b16178801fb4a9258875e200e7;
image SHA-256 is 9312bb84ebd8f418f4d489f239b95156a6d51eb21a4b65fcbd5c934fb1ae8434.
Its 34 functions contain 378 blocks and 1,357 operations, with at most 81 blocks
per function and 9 block parameters. Eight independent VM cases made ten entries
before compilation. Native r4 passed 122 cases and 11 private controls in
20.388103152 seconds, with 182 selector entries and 38 complete native queries.

## Remaining composition

The public controller must admit the original program first, preserve input
and normalized Core digests separately, issue the immutable Graph capture,
extract selectors with the original single/batch prefix ordering, compare the
complete reconstructed query, enforce each original response wire gate, and
run complete patch admission before publishing a candidate or receipt.
Generic foreign-object dictionary lookup/equality hooks and public incremental
capture remain open; the current Graph domain does not establish arbitrary
Python-object compatibility. Native raw JSON routes have no custom equality
hooks, but still require their complete ordinary driver and installer gates.
