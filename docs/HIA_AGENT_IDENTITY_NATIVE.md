# Selected HIA Agent scalar identity admission

This ordinary HIA Core application checks canonical decimal u64 values and
exact 64-byte lowercase ASCII hexadecimal digest strings. It does not compute
a digest or grant authorization. High-level Hepta language expansion is frozen.

`HEPTA_HIA_AGENT_IDENTITY_MANIFEST` selects a pinned Linux x86-64 native image.
The existing store sequence decoder and worker digest-format validator then
invoke HIA without reference numeric/regex fallback. A bad manifest or native
result fails closed. Ordinary worker discovery no longer eagerly imports the
foreign Rust-comparison module via macro advice; explicit native NDU calls
still reuse its unchanged bounded process pump and charge first-import time to
the original deadline. No selection leaves the existing reference route intact.

The host retains JSON/value-kind/ASCII transport checks and the 64-character
transport bound. Every in-profile digit, leading-zero, overflow and lowercase
hex decision is made by HIA; the reference code is not an equivalence oracle at
runtime. This is trusted immutable executable code, not a submitted-code sandbox.

## Byte ABI

The source is `examples/hia_bootstrap/agent_identity.hepta`, authored by
`tools/generate_hia_agent_identity.py`. Input is a 16-byte little-endian header
(`HIAIDP01`, operation u64), followed by at most 64 ASCII bytes. Operation zero
checks u64 decimal and returns its value; operation one checks digest grammar.
A 24-byte result (`HIAIDR01`, valid u64, parsed value u64) returns length 24.
Rejected scalar text produces valid=0/value=0; valid digest produces value=0.
Operations 2–6 admit context budgets, classify measured outcomes and aggregate
costs. Operation 7 compares workload declarations, reference executions, or
native execution observations. Its header adds the comparison mode, followed
by five pairs of length-prefixed fields: status, scalar result, external buffer
observations, first trap and resource counters. A declaration can omit its
external buffers. Reference comparison requires matching first traps and
resource counters; native comparison uses status, result and buffer bytes
represented by their exact observation records. The result value is 1 for
agreement, 0 otherwise.

Operation 8 decides Store record authority. Its header adds a stored-row
presence flag, followed by four pairs of length-prefixed fields: namespace ID,
digest, URI, and required kind. Cursor groups use an empty URI and no kind.
The decision is 0 for an authorized row, 1 for a missing or mismatched
identity, or 2 for an existing identity with the wrong required kind.

Operation 9 consumes the issued creation timestamp, current wall-clock
timestamp (both nanoseconds), and frozen total wall-clock budget in
milliseconds. Its 32-byte response contains the magic, strict expiration
flag and the low/high words of the remaining whole milliseconds. At the
exact deadline admission has not expired but no complete millisecond
remains. Clock adjustments and a duration beyond one word are supported
without multiplying the budget by one million inside the native image.

Operation 38 consumes a single bounded JSON array of artifact kind, metadata
and verified SHA-256. HIA builds the canonical Store content-key object.
When the selected Store also pins the HIA SHA-256 stream, that stream hashes
the object; the resulting key is unchanged for previously retained records.

Operation 44 admits one case of a frozen evaluation workload at a time.
Its two input words are the accumulated external snapshot bytes and either
the current case's validated snapshot size or an all-ones word for an
unavailable entry. The response contains the magic, a decision (0 accepted,
1 unavailable entry, or 2 aggregate budget exceeded), and the accumulated
bytes. Exact 32 MiB is accepted. A refusal ends admission before any later
case requests a snapshot observation.

Malformed input packet returns 0xfffffffd. Insufficient output returns
0xfffffffe without writing output. Operation 44 does not use scratch workspace.

Build with `python -B -m tools.build_hia_agent_identity --compiler B3.image.bin
--cold-report cold.json --output NEW_DIRECTORY`. A complete matching cold
qualification and unchanged inputs are required before publishing a manifest.

Tests interpret full result-byte witnesses before native seed compilation,
compare overflow boundaries and randomized integer oracles, mutate all byte
values, check canaries and concurrent calls, and execute real store and
evaluation callers with their former Python decisions disabled.

## Remaining authority

This component takes only framed observations and scalar policy inputs. It
does not own the Store, filesystem, worker correlation or proof solver, and
does not qualify native-only installation, production activation or retirement
of the hosted Agent.
