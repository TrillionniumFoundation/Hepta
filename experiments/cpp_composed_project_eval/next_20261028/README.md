# Complete captured C++ owner transfer: final native qualification

**Final3 passes both declared macro configurations after the loader identity fix.**
`FINAL_ACCEPTANCE.json` and `final3/qualification.json` are the authoritative
final native records. `cli2/commands.json` retains the prior successful CLI
observation; subsequent integration CLI checks are reported separately. Original C++ objects are linked only into the
reference binaries, never the translated targets.

The fixture has a real common owner header and separate `entry.cpp` and
`consume.cpp` implementations. The caller constructs and prepares a two-buffer
owner, moves it locally, then passes the complete owner by value to the other
translation unit. The consumer can return early, reject an index, move its
parameter or borrow the fields for its scalar result. Every declared variant is
captured and translated independently. The two macro variants change the
initialization mask and arithmetic weight; both execute natively.

| Final configuration | Cases per implementation | Allocations | Frees | Refusals | Final live | Observation digest |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| three_weight | 437 | 401 | 401 | 196 | 0 | `79fca1db8d2f0865` |
| five_weight | 437 | 401 | 401 | 196 | 0 | `dd7575852bb30d54` |

Each row is independently observed in the separately compiled C++ reference
and the standalone HIA native target, then compared with an independent
integer/allocation oracle. It covers allocation refusal, partial-construction
cleanup, zero-length buffers, moved ownership, boundary indices and return
paths. Each allocation identity/size and release order contributes to the
comparison. The target is compiled from an independently verified standalone
Core document; it has no source C++ link input, Rust codegen or C codegen fallback.

Every configuration accounts for 139 active declaration occurrences across the
two translation units, including header copies; 219 total inventory rows also
list compiler implicit declarations. This is not a claim of 139 unique source
declarations. There is one actual translated cross-unit owner transfer, with
all declarations assigned dispositions and no unconverted declarations.
An omitted linear drop in actual generated Core rejects before publication.
Structural tests also reject moved-from uses, unsequenced move/observation
arguments, unsupported active declarations, unresolved definitions, ODR
mismatches, forward attributes and omitted build configurations.

## Exact external scalar ABI and CLI

The final C++ reference wrapper and observation harness use exactly the same
`uint64_t(size_t,size_t,uint8_t,size_t,uint32_t,uint32_t) noexcept` C-linkage
signature. The internal original `run_pair` retains its C++ signature; the
wrapper performs the ordinary unsigned conversion on return. Final2 avoids
relying on different C++ integer types merely sharing the same machine registers.

The actual CLI command `hia import-cpp-composed-matrix` verifies both declared
variants and publishes `three_weight`. Subsequent `hia verify` and `hia run`
both exit 0. The published standalone Core hash is
`9b7d0514f96007510672f06fc9414dd2cfe87a8eea1264f4e0f232b8a939d44c`.
Execution with `[3,5,7,0,0,0]` returns 318 with two allocations, two frees,
29 loans started/ended and no live owner, loan or byte.

`initial_smoke` remains as early real native evidence. `final`/`cli` remain as
the pre-typedef-correction observations; their actual values and machine ABI
observations were retained, but they are superseded by final2/cli2 for the clean
reference declaration. Neither supersession changed the migrated algorithm or
selected a better runtime performance result.

Final3 repeats this exact correctness matrix after the production runtime loader
identity repair changed the compiler-wide source hash. The migration module,
qualifier, complete fixture and precise C typedefs are unchanged. All outputs,
resource digests and negative controls match final2. This is source-identity
requalification; no performance measurement or timing selection occurred.
The prior final2 native run and CLI2 observations remain readable and archived.

## Scope

This extends the checked leaf/composed-owner protocol to real cross-unit
by-value consumption and declared build matrices. It is not a general C++
translator, arbitrary destructor/allocator model, class-layout or mangled ABI
preservation, formal source-equivalence proof, cross-platform execution claim
or performance qualification. Unsupported declarations reject rather than
acquire a bridge/support label. The qualified external ABI is scalar C on the
executed Linux LP64 target.

The module is bound by `compiler_hash()` over all `hepta/*.py` before/after
translation. The final qualifier also checks its own source and fixture file
bindings before/after execution. The original `evidence.tar.xz` is retained unchanged through final2/CLI2; the
additional `evidence-final3.tar.xz` preserves the new complete matrix and
identity snapshots. Both contain every original and target native artifact;
only verified duplicate ELF files are removed from the loose directory. JSON, source, logs, CLI records and bound snapshots remain
readable. `RAW_MEMBERS.json` and `ARCHIVE.json` identify every archived member.
