# Safe Core loader order and deterministic hash tables

The original checker at `2598f4309791d3a023cd5df585ad26810b20c744`
accepted all three supplied ELF images: the original, a first/last `PT_LOAD`
record swap, and a first/second swap. The first/last swap failed to load in an
actual bounded child process. Section bytes and semantic queries alone did
not enforce the program-header ordering consumed by the loader.

The repaired checker validates `PT_LOAD` virtual-address order before its
sorted page-overlap check. A separate positive control permits changes to the
relative order of non-load headers. Both malformed load orders are rejected
before solver identity is read.

The producer also requests both SysV and GNU lookup tables explicitly. GNU
ld defaults differ across hosts; the original producer on this host omitted
`.hash`, which the closed Safe Core consumer requires. Shared C-driver linkage
uses the corresponding `-Wl,--hash-style=both` flag. An independent C-driver
smoke observed both exact section names and a correct wrapping-u32 result.

The [ELF gABI PT_LOAD contract](https://gabi.xinuos.com/elf/07-pheader.html)
requires the load headers to be ordered by virtual address. These changes
check that input contract; they do not prove a general loader, the complete
ISA, arbitrary ABI/FFI, or the selfhosting compiler.

## Evidence and replay

`raw-evidence.tar.xz` retains the reconstructed original counterexample,
exact object/images, old independent proofs, native child outcomes, the new
red test log against the old modules, and the final Safe Core qualification.
All archived runs occurred after the scratch-environment recovery. The old
module Git blobs are checked by `elf-order-evidence/reproduce_original.py`.
Do not run mutated shared libraries in a controller process.

The candidate qualification passes 42 tests with zero skips, three positive
models, five semantic negative controls and 29 retained SMT-query replays.
The raw local qualification has no Git HEAD because its source was restored
from pinned files; its source-identity map records the actual tested bytes.
The final combined source must pass its own exact-commit CI. The independent
selfhost and NDU records in adjacent directories are separate test populations.

Run the final candidate with:

```sh
python -B tools/qualify_hia_safe_core.py --output /absolute/new/evidence
```

Archive size/digest and bounded claims are in `validation.json`.
