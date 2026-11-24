# Cold SHA with preserved foreign-alias behavior

The public six-word state ABI, complete 1,184-byte state, original stream guards,
and every cold hash/custody pass remain unchanged. The composite flat contains
the entire previously qualified fallback, followed by a separate HIA
implementation for disjoint input/output/state views. An 89-byte mechanical
prefix checks only unsigned pointer ranges. Any empty view, overflowing endpoint,
or pairwise overlap selects the original entry. It changes no argument register
or stack value and performs no input read, copy, or SHA computation.

## HIA compression and complete-state equivalence

For disjoint views, the update loop transfers each complete 64-byte block as
eight checked little-endian word loads/stores. Compression decodes its sixteen
big-endian input words through eight checked `buffer.load.u64.be` operations,
splitting each word into its high and low 32-bit halves. The existing complete
state guard covers all eight-byte reads; the pending input and schedule ranges
are disjoint. The source computes each group address once for four schedule or
round operations. The operation and state-write order remain the same.

The choice expression is `g ^ (e & (f ^ g))`; its low 32 bits equal the original
expression even when state words contain arbitrary high bits. The majority
expression `(a & b) | (c & (a | b))` is a bitwise identity at full width. Only the
existing final masked `a` and `e` assignments consume these round temporaries.
Masks were removed from rotate left arms before XOR/addition and from temporary
`t1`/`t2` before those final assignments. No unmasked result is shifted right
before being reduced. All visible schedule/chaining writes and their masks
remain. Full-u64 noncanonical state and constants are included in the original
differential qualification.

The original 27,043 native/VM/state transitions and 2,000 displaced foreign-alias
calls pass with identical complete buffers. Another 5,894 six-word range cases
use independently distinguishable branch stubs, including adjacency, all
ordering permutations, zero extents, overflowing endpoints and overlap. The
native HIA constructor has 51 positive/atomic-refusal cases, including both
maximum 1 MiB inputs and undersized outputs. Canary bytes and rejected outputs
remain unchanged.

## Independent endian seed

`seed_endian_backend.hepta` is a separate explicit seed profile. The original
v1 and word-store profiles are unchanged. The new profile adds only the existing
Core v9 big-endian u64 load (resource 25), accepting read or mutable buffers with
two inputs and one result. Its complete unsigned eight-byte range guard precedes
the load. HIA emission produces the existing load followed by `BSWAP`.

The independently qualified native assembler, projector, original v1 seed and
backend packer construct the new seed from HIA source. Two subsequent native
self-rebuilds reproduce the complete flat and ELF byte for byte. The backend
packer preserves its existing 1 MiB workspace; the generic filter wrapper is
not the backend's wrapper. No target or successor compiler participates.

The native seed and independent full HIA VM agree on 1,210 BE-load cases (the
original 605 boundary vectors for each buffer kind), including 558 bounds traps.
All 605 original word-store controls also pass. The 75 original wire refusals,
five ABI refusals, 103 word-descriptor refusals and 101 BE-descriptor refusals
retain atomic outputs. The old word profile still refuses the new operation.
The original fifteen source rebuilds, seven native tool images, original word
profile and B0 remain byte-identical. Exact pins and scope are recorded in
[the endian seed qualification](HIA_INDEPENDENT_SEED_ENDIAN_QUALIFICATION.json).

## Native SHA construction

Compile `cold_sha256_stream.hepta` (unchanged fallback),
`cold_sha256_nonalias.hepta`, and `cold_sha256_alias_packer.hepta` with their
explicit independently qualified seed profiles. The nonalias source requires
the endian profile. The fallback and constructor retain their qualified bytes.
The first two are ordinary pure HIA flats; the third is the native constructor.
Its input is `HIASHA01`, two little-endian u64 lengths, then the fallback flat
and nonalias flat. Each flat length is 1 through 1,048,576 bytes; the frame has
no trailing data. The constructor returns the mechanical prefix followed by
both flats with exact relative jumps. It returns u32 `0xffffffff` for invalid
input or `0xfffffffe` for short output, without output writes.

The complete public SHA flat is 109,766 bytes: an 89-byte prefix, the unchanged
64,588-byte fallback, and the 45,089-byte nonalias implementation. It uses all
existing SHA companion slots without changing their ABI or limits. The checked-in
HIA packer embeds the fixed mechanical template; production construction runs
no assembler or linker. The adjacent `.S` describes that mechanical template.

## Consumer evidence and remaining release gate

The actual archive consumer passes its original nineteen live/refusal/custody
controls and nineteen AZ02 controls, including source, journal and output
mutation. A separate six-run interleaved comparison of the unchanged real
original-chain input compares the entire 28,828,792-byte archive on every run.
All bytes agree. Median archive time decreases from 3.9948 to 3.5183 seconds.
The full SHA semantic harness measures approximately 54 MiB/s for 1, 4 and
8 MiB messages.

[The adjacent record](HIA_COLD_SHA_ALIAS_NATIVE.json) binds actual sources,
flats, native construction, complete tests and measurements. The construction
report's original pending annotation is retained as historical chronology;
the separately pinned semantic reports establish the completed component
result. These measurements do not establish the complete 60-phase deadline or
the remaining consumer integration. Those release gates remain explicit.
