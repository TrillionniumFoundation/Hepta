# Independent native frontend word profile

This separate profile accelerates the unchanged HIA assembly frontend and the
existing HIAERW02 reference projector. The original sources and standalone
roots remain unchanged. Both new executables were built by the qualified
original native frontend/projector and the independent strict bulk seed, without
a target selfhost compiler or successor. Runtime inputs, outputs, limits and
all frontend CLI options are unchanged.

`tools/generate_hia_seed_front_bulk.py` matches complete canonical Core function
bodies, excluding only function name and declared effect order. It replaces ten
word readers and four word writers across eight of the ten component sources.
An eight-byte read uses the existing v9 little-endian word instruction only when
the complete range is legal. All other ranges execute the original byte loop,
including the original trap kind. A word write executes the same eight byte
stores in the original order, with constants instead of a loop. Short buffers
therefore retain precisely the original prefix writes before trapping. No new
resource opcode, unaligned-access restriction or input budget is introduced.

The generated source map records each full source hash, function identity and
replacement hash. Unchanged driver and publication-policy modules continue to
use their original source paths. The packer and mechanical ABI are unchanged.

The adjacent qualification record binds all evidence and exact image pins.
Every one of the 1,599 source fixtures from the thirteen original cold families
was compared live against the preserved native frontend. All 965 original
reference calls are represented; a total of 2,090 function projections compared
complete return code, stdout and stderr bytes. The cumulative assembly time was
135.186 seconds versus 60.264 seconds, and projection time was 114.567 seconds
versus 36.916 seconds. These are serial old/new component-regression timings,
not a claim about the separate original 180-second whole-cold gate.

Another 858 tests compare the original and new compiled helpers with a fresh
complete HIA VM, including 513 bounds traps and full partial-write snapshots.
Both read-only and mutable word reads, zero/short/full buffers, arbitrary u64
values, extreme offsets and byte-by-byte write ordering are covered. All fifteen
original frontend/seed component sources preserve exact Core, wire and machine
bytes, the original native roots repack identically, and all ten new frontend
components reproduce their independently constructed bytes when rebuilt through
the new frontend itself. The original B0 image remains unchanged.
