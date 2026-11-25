# Native proof lookup paths

These three HIA components preserve their existing wire protocols, public
profiles, diagnostic order and workspace requirements while removing repeated
linear scans from large admitted Core inputs.

## Admission

The final diagnostic body is authored first, including the independent
capability-closure pass before predecessor comparison. Four edge-argument
loops then traverse the existing decoded linked arrays in order. They retain
all value, type, duplicate-capability, live-owner, closure and join checks in
their original order. This removes repeated traversal from the head for every
array index. It does not cache a previous admission decision.

## Typed proof graph

The original name workspace holds an open-addressed table for each block.
Each occupied word retains the full decoded node index and the full slot
index. Hash collisions compare the complete decoded text. Duplicate names in
private, unadmitted input preserve the first declaration, as before. The table
is sized for twice the current block's definitions, cleared before use, and
bounded by the original reserved arena. The former linear path remains
available for private layouts that cannot use that table. The output graph
and selection records are unchanged.

## Independent reference projection

The projector retains its original block table and ordered value rows.
An optional exact-text index uses scratch beyond the historical required
arena. If that extra space is unavailable, lookup uses the former ordered
linear scan. Every block resets its index; definitions update it only after
the original row has been written. Existing 48 MiB and compact workspace
contracts remain valid, including the previous minimum accepted extent.

## Current evidence

Exact source, image, compiler and report hashes are recorded in
`HIA_NATIVE_PROOF_LOOKUP.json`. A once-captured, sealed native source compiler
rebuilt all three emitted HIA sources with an empty PATH; every result matched
the separately compiled image byte for byte.

The changed components passed 13 unchanged original Core native semantic
tests, all 14 original reference-wire tests, and five independent Core source
VM tests. The run observed 6047 actual native calls, including resource
ownership, returned loans, branch joins, full diagnostic bytes and original
memory limits. Compiler provenance and strict-builder tests are outside this
specific lookup semantic suite; its setup injects the actual native image and
does not replace any semantic oracle.

The proof graph passed 2864 exact-byte controls across 477 original sources,
31 refusal controls, and 1463 selection-only controls across 487 sources.
A further 36 private comparisons matched the prior native images with
128 names in one hash bucket, duplicate first-definition lookup, block reset,
embedded NUL names, missing names, poisoned work and the original minimum
reference workspace. Those private malformed names are not described as
admitted Core.

A complete nine-role primitive proof candidate also passed the ten general
boundary cases with the qualified general solver's exact graph and initial
CNF identities. The 45000-block-parameter case, previously stopped by the
65-second external harness timeout, completed within its unchanged 60-second
proof budget. The 4097-parameter case fell from about 14.5 seconds to about
2.8 seconds in the recorded complete executions. These are observed timings,
not guarantees or the separate 180-second cold-release gate.

This component checkpoint does not activate a release or certify the public
proof facade, call profiles, complete multiversion runtime, HTTP integration,
or final cold-release run.
