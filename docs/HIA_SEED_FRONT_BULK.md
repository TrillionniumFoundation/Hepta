# Independent native frontend word profile

This separate profile accelerates the unchanged HIA assembly frontend and the
existing HIAERW02 reference projector. Original generic sources and initial seed
profiles remain unchanged. The current executables are independently built
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

Cumulative assembly time is 57.098 versus 47.607 seconds, and projection time is
35.337 versus 32.287 seconds. A separate 29-case hot-input comparison also
preserves every result. These are serial old/new component-regression timings;
the original 180-second whole-cold deadline remains a separate gate.

The three newly selected helper transformations pass 8,172 controls against the
original and new native images, both independent full HIA VM programs, and an
independent bytewise arithmetic oracle. These include 4,327 normal returns,
3,690 bounds traps and 155 checked-shift traps. Tests compare complete views,
full u64 return values, trap kind and detail, and partial-write snapshots. VM
instruction counts are excluded from semantic comparison. The unchanged
word-store transformation also retains its earlier 858 controls, including
513 bounds traps. Roots are rehashed after execution.

All fifteen original frontend/seed component sources retain exact Core, wire
and machine bytes, and the seven original native roots repack identically.
All ten current frontend components reproduce their independent construction
when rebuilt by the new frontend itself. Both new frontend executable images
are byte-identical under this self-rebuild. The original word seed and B0 image
also remain unchanged. Every semantic construction step executes an actual
native child with an empty PATH.
