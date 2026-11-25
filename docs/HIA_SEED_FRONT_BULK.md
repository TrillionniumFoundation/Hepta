# Independent native frontend word profile

This separate profile accelerates the unchanged HIA assembly frontend and the
existing HIAERW02 reference projector. The qualified generic sources now include the deterministic lookup changes
documented in [the lookup checkpoint](HIA_NATIVE_PROOF_LOOKUP.md). The original
seed profiles remain unchanged. The current executables are independently built
through qualified native assembly, projection, the explicit word-store seed,
and native packers. No target selfhost compiler or successor is used. Runtime
inputs, outputs, limits and frontend CLI options remain unchanged.

The development author matches complete canonical Core function bodies,
excluding only function name and declared effects. It replaces ten word readers,
eight word writers, one literal comparator and one variable-width word reader
across eight of the ten component sources. The generated source map binds each
original and selected source, function body and replacement hash. The unchanged
driver and publication-policy modules retain their original paths.

An eight-byte read uses the existing v9 little-endian word instruction only when
the complete range is legal. Other ranges execute the original byte loop. Each
writer similarly uses one word store only for a complete valid eight-byte range.
Otherwise the original byte stores execute in their original order, preserving
every partial-write prefix before a bounds trap. Four writers retain their
original input-value return, while four draining writers retain their original
zero return.

The literal comparator preserves the initial length mismatch and zero-length
cases. For lengths one through twenty-four it compares masked word chunks only
when every complete loaded chunk lies inside the actual view. Other cases run
the original byte loop, including its checked shift at larger widths and its
early return on a mismatch before later bounds checks. The variable-width
reader likewise uses one masked word load only for widths one through eight and
a complete legal load; zero and fallback behavior remain unchanged.

These transformations use the independently qualified word seed and existing
instructions. No profile capacity, alignment restriction, opcode, trap rule or
numeric limit is expanded. The packers and mechanical ABI remain unchanged.

## Current qualification

The [qualification record](HIA_SEED_FRONT_BULK_QUALIFICATION.json) binds actual
sources, image pins and evidence. All 1,599 original source fixtures across
thirteen cold families compare live against the previous qualified frontend.
All 965 original reference calls are represented. The 2,090 function projections
compare complete return code, stdout and stderr bytes.

The current full corpus compares the qualified indexed frontend against the
key and SHA candidate: cumulative assembly time is 57.247 versus 41.068 seconds;
projection is unchanged at the same image pin (18.918 versus 18.841 seconds).
These complete-corpus regression timings are not the whole-cold budget result.
The separate complete-phase timing below includes native driver and archive work.

The three earlier literal/word helper transformations passed 8,172 controls against the
original and new native images, both independent full HIA VM programs, and an
independent bytewise arithmetic oracle. These include 4,327 normal returns,
3,690 bounds traps and 155 checked-shift traps. Tests compare complete views,
full u64 return values, trap kind and detail, and partial-write snapshots. VM
instruction counts are excluded from semantic comparison. The unchanged
word-store transformation also retains its earlier 858 controls, including
513 bounds traps. Roots are rehashed after execution.

All fifteen unmodified original frontend/seed inputs retain exact Core, wire
and machine bytes when compiled by the new frontend, and the seven original
native roots repack identically. These original inputs are kept distinct from
the current qualified admission and reference sources.
All ten current frontend components reproduce their independent construction
when rebuilt by the new frontend itself. Both new frontend executable images
are byte-identical under this self-rebuild. The original word seed and B0 image
also remain unchanged. Every semantic construction step executes an actual
native child with an empty PATH.

## Indexed reference lookup

The preceding indexed-lookup checkpoint applied the unchanged complete-function
helper matches to the qualified admission and reference lookup sources. Those
two selected component sources changed, while its helper pattern and replacement
hash multisets stayed identical to the earlier literal qualification.

The actual independently built reference component additionally passes twenty-four
old/new controls: 128 deliberately colliding names, first duplicate-name behavior,
per-block reset, an embedded NUL, a missing name, poisoned work, and extents at
and around the original minimum of 355,128 bytes. When the optional index cannot
fit, the original linear lookup still runs. No workspace minimum or source limit
is raised. The unchanged helper arithmetic retains its previously recorded
8,172 and 858 controls; those historical helper checks are distinguished from
the new complete-input and lookup comparisons.

This checkpoint qualifies the two new bootstrap executables as components. It
does not mark the sixty-phase, 180-second native cold replay gate as passed.

## Exact key dispatch and workspace SHA

A subsequent native instruction sample identified repeated key-comparator calls
and the diagnostic module's complete input SHA as concrete assembly costs. The
new development author additionally matches the exact canonical key and SHA
function bodies and their callees. It does not substitute functions based on
names alone. The generated map records the matched body hashes, all new helper
hashes and the complete retained fallback functions.

Key dispatch reads the original node metadata in the original order. Within a
complete legal sixteen-byte range it compares masked little-endian words,
grouped by the original key lengths. Outside that range it executes the full
original key function, preserving early mismatches, wrapping node arithmetic
and the original first bounds trap.

The diagnostic SHA still initializes the same round constants and chaining
state. Its fast arm is admitted only when the original base at work offset 40
is at least 48 and the complete 1,120-byte region fits. This excludes writes to
the base word itself. Every initial message word still consumes its original
four bytes in order and writes that word before consuming the next. Thus input
and work aliases observe the same intermediate writes; there is no message
prefetch or new scratch region. Only subsequent schedule and compression work
is accelerated. Constants, final schedule, chaining state and serialized digest
retain every original workspace byte. Other layouts run the entire original
function, including truncated partial writes.

The new helpers pass 981 independent bytewise-oracle/native comparisons, 376
pairs of complete HIA VM executions, and 104 actual native overlapping-input
cases. Both old and new functions compare full u64 results, every view byte,
controls, first trap details and partial writes. The QA fork child disables
core dumps before native entry; actual SIGILL remains the trap observation.
The first harness's apport-pipe delay is retained separately and is not a
production cold-performance claim. The unchanged production observer already
sets and verifies PR_SET_DUMPABLE=0.

All 1,599 original sources, 2,090 projections and 965 reference calls still
compare exactly across thirteen families. The original fifteen bootstrap
inputs, seven roots and B0 retain their bytes; all ten current components and
both current frontend roots self-rebuild exactly through native assembly,
projection, the unchanged word seed, and native packers.

A quiet four-phase replay executes every node of the original signed and
capacity reference plans, then the actual archive process. Signed driver time
is 12.587 versus 11.311 seconds; its archive is 2.801 versus 3.171 seconds.
Capacity driver time is 14.220 versus 10.423 seconds; its archive is 0.842 versus
0.886 seconds. Every publication matches the earlier actual reference bytes,
and every archive entry matches the phase's full produced file. No reference
result is substituted or cached. These component/phase passes leave the full
sixty-phase 180-second gate open until a complete actual replay succeeds.
