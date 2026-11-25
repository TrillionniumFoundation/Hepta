# Independent native frontend word profile

This separate profile accelerates the unchanged HIA assembly frontend and the
existing HIAERW02 reference projector. Original generic sources and initial seed
profiles remain unchanged. The current executables are independently built
through qualified native assembly, projection, the explicit word-store seed,
and native packers. No target selfhost compiler or successor is used. Runtime
inputs, outputs, limits and all frontend CLI options remain unchanged.

The development author matches complete canonical Core function bodies,
excluding only function name and declared effects. It replaces ten word readers
and four word writers across eight of the ten component sources. An eight-byte
read uses the existing v9 little-endian word instruction only when the complete
range is legal. Other ranges execute the original byte loop, retaining the
original trap kind.

A write uses one existing v9 little-endian word store only when its full unsigned
eight-byte range is valid. Otherwise it performs the original eight byte stores
in their original order. Every partial-write prefix before a bounds trap is
therefore preserved. The return value is unchanged. The original independently
qualified word seed already supports this operation; no seed profile, opcode,
alignment restriction or numeric limit is expanded.

The generated source map records each complete source hash, function identity
and replacement hash. The unchanged driver and publication-policy modules keep
their original paths. The packers and mechanical ABI remain unchanged.

## Current qualification

The [qualification record](HIA_SEED_FRONT_BULK_QUALIFICATION.json) binds actual
sources, image pins and evidence. All 1,599 original source fixtures across
thirteen cold families compare live against the previous qualified native
frontend. All 965 original reference calls are represented. The 2,090 function
projections compare complete return code, stdout and stderr bytes.

Compared with the preceding checked-load frontend, cumulative assembly time is
55.598 versus 52.394 seconds, and projection time is 34.705 versus 31.997
seconds. A separate 29-case hot-input comparison also preserves every result.
These are serial old/new component-regression timings. The original
180-second whole-cold deadline is a separate gate.

Another 858 controls compare original and new compiled helpers with the
independent full HIA VM, including 513 bounds traps and complete partial-write
snapshots. Read and mutable buffers, zero/short/full extents, arbitrary u64
values, extreme offsets and byte-by-byte fallback ordering are covered.

All fifteen original frontend/seed component sources retain exact Core, wire
and machine bytes, and the seven original native roots repack identically.
All ten current frontend components reproduce their independent construction
when rebuilt by the new frontend itself. Both new frontend executable images
are byte-identical under this self-rebuild. The original word seed and B0 image
also remain unchanged.
