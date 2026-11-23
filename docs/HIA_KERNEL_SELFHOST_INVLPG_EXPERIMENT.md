# Isolated kernel-tlb selfhost compiler experiment

The locked Core v8 compiler has 8,136 instructions in its own authored
source, only 56 below the historical 8,192 instruction ceiling. The isolated
candidate extends its private instruction admission bound to 8,448; the
original 12,000 relocation records still cover the worst case (11,778).
Neither the historical generator nor its checked-in source, qualification
contract, limits, or HeptaKernel toolchain lock is edited.

The candidate authoring path extends the actual compiler's scanner,
declaration/effect parser, opcode/type/arity admission and x86 emitter.
The kernel-tlb profile requires an explicit scalar ELF export and privilege
effect. It does not grant a CPU privilege capability. A candidate compiler is
generated as genuine Core v8 HIA source, bootstrapped through B0 and three
native generations, then rebuilt twice using only the candidate executable
with PATH empty. It lowers a typed INVLPG operation; no guest source can
supply arbitrary instruction bytes. GNU as is an independent byte oracle,
not the compiler. The emitted privileged object is never executed as a
Linux host process.

This is a draft qualification experiment, not a release candidate. The
expanded keyword set may reserve previously usable v8 names in this
experimental compiler; full legacy language equivalence has not been
established. Generated HIA source, actual B0/B1/B2/B3, exact binary receipts,
negative outcomes and ELF text must be retained by the dedicated workflow.
A timeout, failure or missing artifact is not a pass. QEMU execution of the
*selfhost-generated* object, authentic CPL0 authority, interrupt entry,
CRx, IPI, atomics, and all Linux ABI and driver obligations remain open.
No upstream main, HeptaKernel lock or acceptance ledger is changed.

## CPL0 continuation

The first exact candidate `495cc2c1037d555229731949c8c820c188c691e5`
passed its dedicated native bootstrap and byte-oracle run
[45288826211](https://github.com/TrillionniumFoundation/Hepta/actions/runs/45288826211).
It authored 125 functions, 1,503 blocks and 8,242 operations; the generated
compiler SHA-256 was 98671aa213f037e52f636cdadc5d65494fd43d4bda38e727c92eb00cb624db75.
The subject ELF SHA-256 was 6920a8123ebe9ea8bf143fb60223376a766b4912252b5f1548c011be8cf7a7d9.
The first run did not execute privileged instructions.

The continuation takes the exact newly rebuilt ELF from the same workflow,
not the earlier Python-authored backend's output. It independently requires
no unresolved symbols and no ELF relocations, binds the entire original
HIA text to both linked ELF64 and bootable ELF32, and executes the existing
NON-HIA observer on PC and Q35. A same-width NOP replacement is independently
relinked, and restoring the actual mapping is a distinct positive control.
The observer re-derives the page-table slot after the call, rather than
incorrectly assuming the SysV caller-saved r9 is preserved. Wrong-address
observations remain diagnostics since INVLPG permits over-invalidation.
No result from the earlier candidate is credited to this continuation.
