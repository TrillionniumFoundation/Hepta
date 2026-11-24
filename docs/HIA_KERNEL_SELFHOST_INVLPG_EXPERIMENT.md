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


## Experimental native MSR continuation

The isolated compiler now accepts typed x86.msr.read(u32) -> u64 and
x86.msr.write(u32,u64) -> no result only in the explicit kernel scalar ELF
profile. Both require privilege and trap effects. The compiler constructs
RDMSR/WRMSR and the EDX:EAX split/join itself; the external assembler is
only an independent byte oracle. The helper stays within the existing
1 MiB candidate workspace and per-function name limit. No historical
Core v8 source or production toolchain lock is changed.

The PC/Q35 oracle uses actual FS_BASE and GS_BASE MSRs with distinct
canonical high-half values, independently checks both after each write,
and restores both original registers before reporting. Separate no-access
and high-half truncation mutations must be detected by exact readback.
All original scenarios, compiler byte identity, malformed input refusals
and custody controls remain mandatory. The caller must establish valid
selector, CPL0 authority, machine capability and suitable register state;
this is not a general MSR authority proof, syscall dispatch, context switch,
or Linux completion. No privileged instruction is executed in a host process.


## Integrated 2 MiB private scratch candidate (2026-11-24)

This separate draft combines the typed MSR/MMIO/atomic candidate and compact 16-byte private relocation records with the independently exercised 2 MiB workspace layout and 192-function admission from #949. The historical 1 MiB source/output and 128 export limits remain. Candidate tests must exercise 192 functions, 2048 blocks, 10000 operations, 16000 private relocation slots, old and one-byte-short workspace refusals, source over-limit refusal, dense and external relocation witnesses and all prior guest scenarios. The original 60 s store and 5 s ordinary native lifecycle gates remain unchanged. Neither parent's PASS establishes the merged candidate's qualification; this is not the production compiler or full Linux acceptance.


## Native IDTR continuation

The experimental scalar-ELF profile now admits `x86.idtr.load(u64)`
and `x86.idtr.store(u64)`, with no result, explicit privilege/trap and
read or write effects respectively. Both lower to one real 10-byte
descriptor access (LIDT/SIDT), guarded by a 16-byte alignment test.
The guard is a deliberate experimental restriction, not an x86 alignment
requirement; it does not prove canonicality, mapping, ownership, descriptor
contents, interrupt quiescence or memory safety. The ordinary Core v8
compiler and production lock remain unchanged.

The independent QEMU observer creates two IDTs with different limits,
different handlers, and different 64-bit bases (including a mapped
supervisor high-half alias). LIDT must actually change delivery of INT
0x40 and must restore the original IDT through the same HIA subject.
SIDT must store exactly ten bytes in each state, leaving every other
byte of the 32-byte canary buffer unchanged. No-access mutations must
produce the unchanged state. A separately assembled exact #UD witness
checks the aligned-access guard and unchanged state; deleting the guard
must actually perform the unaligned access in the isolated guest.
The handler and IRETQ remain explicitly non-HIA observer code. No native
interrupt entry, return, cross-CPU synchronization or resource authority
claim is made. All existing selfhost generation, byte-custody, malformed
input, capacity and guest regressions remain mandatory.
