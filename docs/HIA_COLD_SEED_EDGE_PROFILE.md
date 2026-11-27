# Native cold seed profiles with identity edges and compact constants

The cold construction graph explicitly selects two separate native profiles:
`seed_cold_bulk_backend.hepta` and `seed_cold_endian_backend.hepta`. Their
admission rules and instruction capabilities are inherited from the existing
bulk and endian seeds. The original v1, word, bulk, division/bulk and endian
sources remain unchanged. The old qualification plans, 60 phases, 479,882
nodes, 180-second cold limit, 3-second cleanup limit and scheduler capacities
are unchanged.

The two cold profiles also select the existing 32-bit MOV encoding when an
immediate value is less than 2**32. Writing a 32-bit general register clears
its upper 32 bits, so the complete u64 value equals the original 64-bit MOV.
Both forms preserve flags. Registers eight through fifteen keep the original
REX.B prefix. Values at least 2**32, including wrapped negative u64 values,
retain the original 64-bit form. The encoder and its admission checks are
unchanged; the author rejects an unexpected parent helper shape.

## The transformation

An admitted block edge transfers a list of source slots into destination slots
`0..count-1`. The existing emitter first copies every source into a private
bounce slot, then copies every bounce slot into its destination. The cold
profiles omit a transfer only when its source slot equals its destination
index. Both the capture and writeback passes omit the same identity transfer.

Every destination index is unique. Therefore an omitted identity destination
cannot be overwritten by a different assignment. Nonidentity transfers read
all their sources before any destination is written, including sources that
refer to an omitted identity slot. Swaps, cycles, fanout and mixed identity
transfers consequently preserve their original parallel-assignment values.
The admitted register area and bounce area do not overlap.

Call argument staging remains byte-for-byte the original function. Every call
rewrites its complete argument bounce list and reads its own returned result.
Skipping an edge transfer cannot expose a stale bounce value to a call. Stack
allocation and page probing, all buffer bounds guards, the admission pass,
relocation resolution, arithmetic, traps and the SysV direction-flag behavior
are retained. The generated code changes in size, so the new actual images
and their source bindings are independently constructed and qualified.

The scratch value in the caller-clobbered RAX register can differ between
blocks; subsequent instructions load their declared operands. This is a HIA
value and buffer behavior claim, not a claim that an asynchronous host signal
observes identical instruction pointers or scratch register bits.

## Native construction and qualification

The original independent v1 seed constructs each new profile's B1. That B1
emits the smaller B2; B2 emits byte-identical B3. These new fixed points are
recorded explicitly. The original bulk and division/bulk profiles still pass
their original B1 == B2 == B3 gate. The new profiles do not inherit a completed
cold qualification from either their parents or the initial compiler roots.

`tools/qualify_hia_seed_cold_backend.py` creates reference wire directly,
without using the authoring CFG or its register assignment. An independent
tuple-assignment oracle supplies the expected full-u64 output. Each profile
executes 475 valid cases, covering all maps on zero through four values,
identity and empty edges, swaps, cycles, fanout, both conditional directions,
17-step loop backedges, consecutive calls, 64-argument and 2,048-register
boundaries, plus complete u64 observations around 2**31, 2**32, 2**63 and the
u64 maximum through jumps, calls and both branch directions. Thirteen invalid-wire controls retain the original complete
refusal observations. Five actual SIGILL cases compare the original bounds
failure and every byte written before the trap.

Separate qualification retains the complete SHA transition, arbitrary-u64
state, padding, large-stream, concurrency and foreign-offset alias cases. The
codec gate retains all original 45 cases, its original input bounds, 1,000
random/structured chunks, 2,000 grammar mutations and 2,028 full-workspace
malformed/overlap comparisons. Actual samples from a retained failed cold run
also compare complete 4 MiB workspaces and canonical encoded bytes.

These finite component qualifications support running the next exact-source
cold chain. They do not assert all-input correctness, a full cold pass, a
matching release, an installed rebuild or permission to retire the old stack.

The explicit native source authority adds only the two new HIA source files.
Python authors and observers remain development inputs outside the native
export. Native preparation regenerates the real construction plans and source
contract, and the seven-stage construction rebuilds and compares the newly
matched bootstrap driver before the full cold can be admitted.

The compact-immediate evidence is retained under
`docs/evidence/cold-compact-immediates-20261127-2807/`. The same-input native
emitter observation reduces the three sampled cold tool images by about six
percent. Its timings exclude projection and process launch and do not qualify
the complete cold deadline. `tools/qualify_hia_cold_seed_emitter.py` reproduces
that bounded observation against an explicit baseline Git commit.
