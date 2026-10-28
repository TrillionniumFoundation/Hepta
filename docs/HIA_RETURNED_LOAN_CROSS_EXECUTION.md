# Finite v8 returned-loan execution on AArch64 and RV64

`tools/qualify_hia_returned_loans_cross.py` extends execution evidence for the
existing parameter-bound internal loan contract. It uses the current canonical
Core verifier and direct LLVM object compiler, the existing finite RV64
allocator, the established AArch64 ELF inspector and RV64 LLVM ELF reader.
It does not introduce another lowering or language authority.

## Actual execution boundary

Both targets execute Linux userspace ELF files under QEMU:

| Target | Declared interface |
| --- | --- |
| AArch64 | Little-endian LP64, scalar C public wrappers |
| RV64 | RV64GC LP64D, scalar C public wrappers |

The `readbuf`/`mutbuf` and multiple-result descriptors remain internal LLVM
interfaces. The fixture exports only `u8` results with `u8`/`usize` parameters.
This does not qualify foreign loan handles, callbacks, external lifetimes,
physical boards or device protocols. Existing compiler receipts continue to
say `native_compiled_not_executed`; the separate qualification report records
which binaries were subsequently executed and observed.

## Fixed corpus and denominators

`examples/hia_program/returned_loans_cross_target_v8.hia` contains 38 functions
and 19 scalar exports. It preserves the existing returned-loan test programs
with globally distinct names. Its calls cover read/mutable forwarding, direct
child returns, CFG renaming, recursion, shared multiple results, independent
mutable origin swaps, fallible allocation and returned chain-head loans.
It also retains a partial-result allocation trap and a post-return bounds trap.

Each target has one positive executable with 128 actual calls, four trapping
executables and two deliberately incorrect native controls. Therefore the
combined denominator is **256 normal/error-value-return calls**, **8 trap
executions**, **4 mutation executions**, and **14 target execution processes**.
There are **128 returned and 4 trapped VM observations**, evaluated once for
the architecture-independent reference. They are not doubled or added to unit
test method counts. Five invalid Core mutations reject before any codegen.

The incorrect-value control changes an admitted Core increment from 5 to 6;
the fixed independent arithmetic oracle rejects its actual output. The
missing-free control deliberately removes native free calls from emitted IR
and cannot receive a qualified HIA artifact receipt. It returns the correct
value but fails the independent allocator ledger. Neither negative artifact
is described as an accepted compiler result.

## Allocator and failure observations

The existing `finite_riscv64_runtime.c` now also selects AArch64 Linux syscall
registers. Its legacy RV64 output remains unchanged. New observation fields
track requested allocation sizes, live payload bytes and peak payload bytes.
The runtime still owns 64 fixed 4096-byte slots, has no concurrency or realloc,
and checks exact live pointer identity. Payload peaks exclude the observer's
fixed arena, stack, executable and total process memory.

For every positive call, seven actual native quantities are recorded:
attempts, successful allocations, frees, outstanding allocations, live bytes,
peak bytes and null frees. Six have corresponding VM resource quantities;
null frees has an independent zero oracle. Native code does not create or
count VM loan objects, which are statically checked and erased by LLVM.

The observer emits the stopped allocation state before `abort` exits with 134.
A bounds trap after a returned child retains one live byte. Failure while
forming the second result retains the caller allocation. Initial allocation
failure leaves no allocation, and a failed chain-node push releases the
fallback payload before its empty-head trap. These cases do not claim native
stack unwinding or cleanup after a trap.

## Reproduction and evidence

```sh
python tools/qualify_hia_returned_loans_cross.py \
  --output-directory /new/empty/path \
  --clang /absolute/path/to/clang \
  --linker /absolute/path/to/ld.lld \
  --readobj /absolute/path/to/llvm-readobj \
  --qemu-aarch64 /absolute/path/to/qemu-aarch64 \
  --qemu-riscv64 /absolute/path/to/qemu-riscv64
```

The output directory must not already exist. It retains original/Core inputs,
LLVM, canonical objects, compiler replay objects, C drivers, linked ELFs,
actual commands, raw stdout/stderr and the final report, including failures.
The replay compiler command uses retained LLVM and must reproduce the exact
canonical object bytes. Source bindings include the compiler/tool Python
surface, fixed corpus and runtime. Tool executable identities and retained
artifact hashes are checked again after execution.

`validate_qualification` independently reconstructs the fixed cases and
arithmetic/resource expectations, checks raw process output and artifact
identities, and rejects changed counts, boolean counters, target identities,
missing observations and promoted negative artifacts. It validates retained
evidence; it does not itself claim to reexecute native code.

The finite corpus does not prove LLVM refinement, whole-language soundness,
general lifetime support, performance superiority, or P0–P7 production closure.
