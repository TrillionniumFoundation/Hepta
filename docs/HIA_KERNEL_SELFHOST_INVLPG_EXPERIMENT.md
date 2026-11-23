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
