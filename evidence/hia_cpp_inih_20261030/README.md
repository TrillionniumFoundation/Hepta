# Executed real INIReader partial migration

The final recorded invocation completed all **48 process commands** successfully
on native Linux x86_64 using GCC/G++. Its wall time was **14.970647653 seconds**.
This is automatic qualification time, not measured human migration cost or
runtime superiority. `RESULT.json`, `COMMANDS.json`, source bindings, generated
code and original process streams are retained verbatim.

| Observation, for each actual upstream revision | Result |
| --- | --- |
| Explicit original C++ member dispositions | 18/18 |
| Source-derived Hepta decision-bearing bodies | `GetBoolean`, `ParseErrorMessage`, `ValueHandler` |
| Native Boolean results compared | All 10,780 ordered result bits retained and compared byte for byte |
| Retained input state and complete reader lifetimes | 64; C and ordinary C++ tracked allocations balance |
| C allocator refusal | Real `-2`, zero live parser allocation |
| Callback lifecycle negative controls | 11/11, including stale, forged, wrong-thread, reentrant, duplicate owner and quota |
| Tested scalar lease transition pairs | 36/36 |
| Deliberately wrong Hepta Boolean implementation | Compiles and exits successfully; original native oracle rejects output |
| Actual C++ callback `std::bad_alloc` | Same exception reaches caller; original C live allocation = 1, repaired path = 0 |

The original exceptional resource leak is preserved in raw observations. Its
removal is an explicit repair, not an equivalence result. Test-only cleanup of
the observed original allocation occurs after measurement and is not credited
to the original component.

The maintenance test uses actual parent
`de720a6f4066587618edfba3960ea9ed4132c665` and actual upstream correction
`2d5ec7b59abbb8e1797e48060965001aaac6996a`. Reading a directory reports old
success `0`, then new error `-3`, with matching original and migrated behavior
within each revision. The changed implementation is the real C parser and C++
error-message method, not an authored caller-only update.

The 9 source-integrity, inventory, rejection and actual frontend/backend unit
tests also pass. Their separate execution is retained in `UNIT_TESTS.json`
and `unit-tests.stderr`; it is not added to the native run as independent
performance evidence.

`ARCHIVE.json` identifies 134 UTF-8 files copied from the final invocation
(637,006 bytes) and the exact hashes/sizes of 18 omitted ELF objects/executables.
Those ELF files were genuinely built/executed locally, but are not published
by this text export. Reproduction rebuilds them. Invocation command paths refer
to the original working directory recorded by the run.

`HISTORICAL_AGGREGATE_RUN.json` binds the earlier successful run's compressed
UTF-8 evidence export (86,575 bytes). That run kept a Boolean checksum and
ordinary traces. The final run additionally retains every Boolean result bit,
so it supports per-case byte comparison without relying on checksum equality.
The source change and previous observation remain explicit; the two overlapping
runs are not pooled into a larger sample.

The route is checked Hepta → existing independent C11/GCC backend → native
C++ INIReader and C parser. Parser, STL storage, locale normalization, string
formatting and the native callback registry remain foreign trusted boundaries.
This is a substantive partial component migration and scoped callback repair.
It does **not** close full C++ migration, foreign memory safety, arbitrary async
cleanup, native compiler refinement, human-cost advantage, or performance
superiority.

See `docs/HIA_REAL_CPP_INIH_COMPONENT.md` for the implementation and exact scope,
and run `tools/qualify_cpp_inih_component.py` with a new output directory to
repeat the actual native qualification.
