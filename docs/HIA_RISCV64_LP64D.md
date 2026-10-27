# Standalone HIA on RV64GC / LP64D

The existing verified Core → LLVM → object path now accepts
`riscv64-unknown-linux-gnu` with explicit `-march=rv64gc -mabi=lp64d`.
The object scanner requires ELF64, machine 243 and the exact reviewed RISC-V
flags value 5 (RVC and double-float ABI). The exercised exports are integer
scalars; adding the LP64D target does not add floating-point instructions or
foreign resource entry points to HIA.

Primitive versions 1–7 retain independent target profile identifiers. Existing
composite inputs still normalize through the one schema registry before LLVM
emission. Cross-target publication produces objects only; execution requires
an explicit target runtime. RV32, other OS targets and unreviewed ABI variants
continue to reject. The checked higher-level source bridge has its own narrower
target admission; standalone Core target support must not silently widen it.

## ABI correspondence

The [RISC-V psABI integer convention](https://github.com/riscv-non-isa/riscv-elf-psabi-doc/blob/master/riscv-cc.adoc)
widens narrow integer values by their signedness to 32 bits, then sign-extends
them to XLEN. Consequently, both `i32` and **`u32`** need `signext` at the RV64
C-call boundary. Signed 8/16-bit values use `signext`; unsigned 8/16-bit and
Boolean values use `zeroext`. The full-width 64-bit values have no extension
attribute. An actual Clang 20 C-to-LLVM probe independently checks all eleven
supported scalar type signatures against the emitted HIA wrappers.

The executable qualification covers:

- C callers entering HIA integer exports, including signed and unsigned
  extremes, twelve arguments spanning registers and the stack, and assembly
  observers reading raw return-register bits.
- HIA calling its existing explicit C allocator/memory/runtime imports.
  Owners and views remain internal capabilities; this is not general arbitrary
  C function import or callback support.
- Original nominal input and independently read normalized Core compiled as
  separate objects and linked into separately executed target binaries.
- Real allocation refusals, memory operations, normal/error cleanup and bounds
  traps. The runtime has 64 independent 4096-byte slots and records actual
  allocation/release events, outstanding allocations and their peak.
- The actual primitive v7 and composite v2 recursive-chain fixtures, compiled
  into separate objects and linked to a third target executable. Twenty-one
  calls cover lengths 0/1/17/32, cancellation, mutable head loans, stored loans,
  task outcomes, payload/header allocation refusals, returning the original
  payload and tail on failed construction, and empty payloads/pop. A separate
  executable checks the empty-head trap. Every positive call checks an
  independent arithmetic/resource specification against both the VM and actual
  target return values, allocation attempts, allocations, releases, final live
  count and observed `free(NULL)` calls. Counters reset only after the preceding
  call has no outstanding allocations; the allocation-slot state is retained.

`tools/qualify_hia_riscv64.py` retains each input, Core, LLVM IR, C/assembly
driver, object, linked executable, tool identity and command output. It uses a
hash-bound LLVM reader to check the actual static executable's segments,
entrypoint and complete external-function inventory. Dynamic-loader/TLS
segments, writable-executable loads, executable stacks, unresolved symbols and
unexpected global functions reject.

## Fixed execution denominator

| Observation | Count |
| --- | ---: |
| Positive ABI binaries / recursive-chain binary | 2 / 1 |
| Scalar/stack/raw-register calls per ABI binary | 88 |
| Bulk-resource calls per ABI binary | 18 |
| Actual C-to-HIA ABI / recursive-chain calls | 212 / 21 |
| Total actual C-to-HIA calls | 233 |
| Interpreter comparisons, ABI / recursive | 192 / 21 |
| Allocations / releases per positive ABI binary | 31 / 31 |
| Actual allocation refusals per positive ABI binary | 2 |
| Peak / final live allocations per positive ABI binary | 2 / 0 |
| Negative target executions, ABI / recursive | 6 / 1 |

The negative executions are a valid but semantically wrong Core program, a
deliberately altered assembly return transport, an explicitly **unqualified**
IR control with actual `free` calls removed, and three different bounds traps.
The additional recursive negative execution traps on an empty chain head.
The removed-free IR is never admitted through the verified compiler entry.
These are finite detection controls, not a proof that every lowering error
will be detected.

```sh
python tools/qualify_hia_riscv64.py \
  --output-directory /tmp/hepta-riscv64-new \
  --clang /usr/lib/llvm-20/bin/clang \
  --linker /usr/lib/llvm-20/bin/ld.lld \
  --readobj /usr/lib/llvm-20/bin/llvm-readobj \
  --qemu-riscv64 /usr/bin/qemu-riscv64-static

python -m unittest tests.test_hia_riscv64 tests.test_hia_program_llvm -v
```

## Evidence boundary

These are real RISC-V machine-code executions under **Linux userspace QEMU**.
They are not physical hardware, an RV32 data model, a bare-metal kernel, a
device protocol, an interrupt/DMA test, a general allocator or a whole-backend
refinement proof. Trap termination does not promise resource cleanup.

The initial development qualification reached the first bounds driver and
failed its strict C warning check because the resource reporting helper was
unused in that driver. That failed run was retained; the driver now reports
resources only if the expected trap incorrectly returns. The subsequent
complete run passed all positive and negative target executions. Execution
receipts bind their exact source hashes; later implementation changes require
fresh qualification before making an integrated acceptance claim.
