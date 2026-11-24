# Independent native seed toolchain

This toolchain produces the first selfhost compiler image from HIA source without
running that compiler or inheriting a successor image. It is an explicitly pinned
native bootstrap trust boundary. It does not claim that the original Python cold
replay certificate has become a native certificate.

The initial seed backend was compiled once by the independent general Core
backend. The checked Core digest, machine text, object, linked image, toolchain,
and loaded implementation digests are recorded in
`HIA_INDEPENDENT_SEED_PROVENANCE.json`. The HIA seed backend then rebuilt itself
with identical native bytes. It compiled all HIA assembly frontend, admission,
canonicalization, reference projection, and packing kernels. No target compiler
was used to build this source-to-B0 toolchain.

## Native interfaces

| Executable | Arguments | Standard input | Standard output |
| --- | --- | --- | --- |
| `hia-seed-assembly` | `--agent-compact` | Complete HIA assembly source | Canonical admitted Core JSON |
| `hia-seed-projector` | None | JSON array `[Core, "f0", 1]` | Raw `HIAERW02` reference register program |
| `hia-seed-backend` | None | Raw `HIAERW02` program | Native flat machine image |
| `hia-seed-filter-pack` | None | `HIAFLT01`, little-endian u64 image size, image | Standalone filter ELF |

The source frontend uses the existing nine HIA syntax, admission, presentation,
and Core import kernels. Its assembly adapter is the existing mechanical
`tools/hia_core_edit_import_assembly.S`. The seed backend performs wire admission,
register and control-flow lowering, machine encoding, capacity accounting, and
relocation in HIA. The original numeric machine encoding owner is embedded in
its HIA source; it is independent of the selfhost compiler's emitter.

`HIA_INDEPENDENT_SEED_PROFILE.json` describes the finite accepted profile and
fixed limits. This bootstrap backend handles unsigned scalars, single-result
functions, branches, calls, and borrowed byte views. It deliberately refuses
owned allocation, loans, chains, signed operations, checked arithmetic, and
multiple-result calls. The upstream full Core admission is required: structural
wire checks alone are not general Core type checking. Runtime traps are native
UD2, and generated functions have no VM step or recursion counters. The backend
is not the full VM or the independent general allocator oracle.

## Reproduction and evidence

The retained HIA sources listed in `HIA_INDEPENDENT_SEED_SOURCE_FILES.json` were
passed through the three native interfaces above. All fifteen source kernels
reproduced their original independently constructed Core, register wire, and
flat machine bytes. Newly produced HIA packers then rebuilt all four initial
executable roots with identical bytes. A fresh invocation of the rebuilt chain
produced the same B0. Every observed semantic process used an empty PATH and had
one initial execve and no further execve or execveat.

The construction evidence records 75 rejected wire controls, five producer ABI
controls, and seven full independent VM observations, including all byte-view
contents. This is a seed component gate. It is not a replacement for the original
nineteen cold qualification families, their modified variants, allocator event
witnesses, exported ABI observations, or their original budgets.

For the recorded original selfhost source, B0 has SHA-256
`a587e546c73adae16615bfeb41a08d2b4564746c708ce89978cd6495d14cfdeb`.
B1, B2, and B3 each have SHA-256
`acb6478d1a466d17210611c5fcbbd5aeec3109b0813e917f0bb5c8419f3c33a9`.
These are measurements for that source, not constants to substitute for a fresh
cold run. The complete native cold owner must freshly construct and observe both
original and modified generations using the authenticated independent roots.

The old attempt to execute the complete compiler in the independent VM exhausted
its unchanged 10,000,000-step budget at step 10,000,001. That refusal is preserved.
No larger limit or resumed task is used. The native seed route is a distinct
bootstrap construction, with its initial executable trust roots explicitly
listed and pinned.

Python author scripts and the original general backend appear only in initial
construction provenance and development qualification. They are not inputs to
the native production source chain. The checked-in HIA files, mechanical adapter,
pinned initial executable roots, and native cold orchestration are the retained
production boundary. Final repository retirement must also retain the separate
cold qualification and oracle closure; this seed source list is not that full
repository deletion list.
