# P1/P3/P5: unreachable-resource CFG refusal + native-export convergence

Date: 2026-10-25. This document describes one **unqualified integration candidate**, not production safety closure.

## Parent and exact donor identities

- Unified parent: PR #139 at `daf3f51fca6a441834c5cf9fdae5cdf26558d28e`.
- Native symbol donor: PR #140 at `915b9b53ca7741299d31cde5c24580985d99eee1`.
- Donor comparison base: PR #138 at `8ad9a3bfa4217f7ed3992cba36aa2d0dc4074c9c`.
- Exact donor: `hepta/object_symbols.py` blob `3a08491cc38f5340afd7215ed89cf92a2e8b708c`, `tests/test_object_executable_exports.py` blob `b3acf662915a59296605279163a9c9b5b9a84ed0` and donor audit memo blob `32884c4aea94895b5786ba3d8ee6323e45bc4283`.
- An exact three-way tree inventory established that all three parent paths were byte-identical to #140's base (the memo was absent at both). The donor blobs were imported without overwriting native publisher / resource policy / compiler authorities.

## P1: actual independent-verifier acceptance gap

The resource verifier previously validated *shape* of operations and all branch target names throughout the CFG, but applied `self.operation(op, state)` only to blocks reached from the entry.

Consequently a syntactically correct dead block could contain a semantically invalid known operation, for example `{"op":"drop","src":"missing_owner"}`, and avoid the owner/liveness checks altogether. The whole document could be returned as `resource_cfg_verified`, while `operations_checked` did not cover all syntactically present operations.

The new bounded structural reachability preflight starts at the verified entry, traverses the already checked successor graph, and rejects if any block is not reached. This policy is deliberately strict: the current checked Hepta lowering does not emit structurally dead blocks. It does **not** solve path-feasibility, termination or C/LLVM backend refinement.

The new tests add:
1. forged unreachable known `drop` of an unknown owner (previously not semantically inspected);
2. a correctly shaped but structurally dead block (cannot be included in a blanket graph certificate);
3. a positive checked Hepta program exercising both diamond joins and a loop, requiring `reachable_blocks == total_blocks`.

This strengthens the independent verifier's **coverage**, not the completeness of source semantics or the safety of arbitrary FFI.

## P3/P5: preserve strongest native-object guard

#140's reviewed scanner refuses defined data/nonfunction exports, ELF STB_GNU_UNIQUE, weak ELF/Mach-O exported functions, and ELF executable sections lacking allocation. This is integrated atop #139's exact published-object inode/byte/source replay, not used to replace or weaken the publisher.

The donor PR documented isolated direct native Clang 17 execution on real five-target object files and targeted mutations; the result belongs to **the donor source SHA only**. This combined SHA does not inherit that result.

## Immediate local native checks (not CI)

```sh
python -m unittest tests.test_resource_ir tests.test_resource_views -v
python -m unittest tests.test_object_executable_exports tests.test_artifact_publication -v
python -m unittest tests.test_static_resource_policy tests.test_static_resource_lowering -v
```

Then run actual bounded source→IR→LLVM checks on the same exact checkout and record fresh source/compiler/artifact identities. No CI result, Linux-host-only test or emulated target counts as all-target ABI or physical hardware qualification.

**Current P0–P7 scope:** selected finite language profiles can progress independently of CI queue status. General type/lifetime and pointer provenance soundness, arbitrary C/C++ L2/L3, global allocator/FFI accounting, all-target ABI runtime execution, full owned-LLVM coverage, live AI model A/B, sustained production workloads and physical DMA/GPU/NPU testing remain open.

`whole_project_blockers_closed=false`.

## Follow-on: reject all unreviewed named ELF bindings, not just GNU_UNIQUE

PR #140's first symbol guard rejected binding 10 (GNU unique), and explicitly
permitted GLOBAL=1/WEAK=2 while **continuing past** every other binding
number. That left a second closed-profile bypass: a defined public data symbol
can be retagged as a reserved/OS/processor-specific binding (3..9,11..15) and
disappear from the verifier's exact `defined`/`undefined` inventory.

The combined branch changes only the existing ELF symbol filter: accept
recognized LOCAL=0, GLOBAL=1 and WEAK=2, with local names not counted as
external API; reject **every other named binding**. It does not infer that
any particular vendor-specific binding is public or private: unknown linkage
semantics are not permitted to claim a safe exact native export inventory.

Two real Clang 17 LLVM-to-ELF compilations were executed directly on this
host targeting x86-64 Linux and AArch64 Linux. Each included a declared
`hepta_symbol_target` function and an extra global data object. The real
symbol entry for the data object had original STB_GLOBAL+STT_OBJECT
(`st_info=0x11`). Independently mutated that byte to all of the bindings
`3,9,10,11,12,13,15` while retaining the ELF header, symbol strings,
section table and byte length. All 14 mutation specimens passed the
**separate structural/field-level assertions** (not the full Hepta scanner
runtime); under the pre-patch logic 12 of the 14 would be silently skipped,
while binding=10 was already rejected. Under the closed new filter all
14 must reject with `E_OBJECT_SYMBOL_EXPORT_KIND`.

A new exact-source regression is committed in
`tests/test_object_executable_exports.py`, compiling the two target objects
and invoking the actual object scanner on all 14 mutations. That **repository
test has not been executed** on this final combined HEAD, and no whole-Hepta,
cross-host ABI, LLVM-refinement or real-device qualification follows.
