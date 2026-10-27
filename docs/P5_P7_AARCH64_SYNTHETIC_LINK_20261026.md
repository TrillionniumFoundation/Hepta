# P5/P7: AArch64 freestanding synthetic link qualification

This is an **optional, real Clang/lld static relocation probe**, not a
production AArch64 Linux runtime. It advances the selected Owned LLVM CPU
object path from format/symbol verification to *bounded synthetic
linkability*, while keeping all runtime and device verdicts explicitly open.

## Source identity and delegation

The underlying source build is still the **one existing** checked Hepta
frontend → canonical semantic snapshot → independently verified Resource IR
→ Owned LLVM emitter → Clang AArch64 ELF object path. It still requires
the pinned native Rust reference gate. No alternate language parser, SSA
authority, C/C++ migration engine or Owned LLVM emitter is introduced.

The existing object checker first requires complete ELF64 machine 183,
correct source-export function symbols and only the reviewed undefined
imports (`malloc`, `free`, `abort`, `memset`, `memcpy`, `memmove`).

The opt-in qualifier constructs a separate, **private** temporary target
image using a fixed, header-free C11 file with dummy functions for those
six imports and a synthetic `_start`. It uses real Clang
`--target=aarch64-unknown-linux-gnu` and `-fuse-ld=lld -nostdlib -static`.
The shim is **deliberately nonfunctional**: `malloc` returns null and
memory functions are not real implementations. Do **not** execute or ship
this ELF. It is destroyed after inspection and never substitutes for the
requested source-bound relocatable `.o`.

The verifier independently rejects wrong ELF class/endianness/machine,
ET_DYN/ET_REL, dynamic loader PT_INTERP/PT_DYNAMIC, missing executable
entrypoint, out-of-file program sections, missing/undefined/weak symbols,
extra global functions and a mismatched `_start`. It retains complete
SHA-256 identities of the original object, fixed shim and temporary
linked ELF as an observation receipt. No target execution is claimed.

## User-facing explicit qualification

On a host with the pinned Hepta Rust reference compiler, Clang and lld,
from the full repository checkout:

```sh
python -m hepta.llvm_owned_aarch64 examples/llvm_owned/owned.hepta \
  --output /tmp/hepta-owned-arm64.o --synthetic-link-probe
```

Supply an applicable source entry exporting scalar C functions and producing
the finite Owned LLVM profile. The CLI reports
`synthetic_link_probe.status=synthetic_freestanding_link_only_not_executed`
**only** if the exact staged object passed native source/object checks and
the optional synthetic link probe passed. It leaves the requested `.o`,
never publishes the dummy target ELF.

Focused tests, independent of the full pinned Rust source pipeline:

```sh
python -m unittest tests.test_owned_target_layout \
  tests.test_owned_aarch64_link tests.test_llvm_owned_aarch64 -v
```

## Execution truth

A locally authored LLVM function using imported `malloc`/`free`
was compiled into a real AArch64 ELF64 relocatable object. Real Clang
and lld then produced a **statically linked AArch64 ET_EXEC** with
the expected `hepta_owner_test`, `_start` and six shim functions,
and no undefined symbols. This was a direct local toolchain smoke test;
**it did not run the Hepta compiler or execute the target**.

No whole-repository exact-head Rust/Clang/QEMU/hardware suite has been
executed for this new branch. Historical evidence belongs to its
previous source SHA, not this integration.

**Still open:** real cross-target libc/allocator/DMA, ARM64 runtime
execution/foreign ABI calling equivalence, all-target MSVC/Clang/GCC
qualification, compiler ownership/provenance refinement, physical device
and GPU execution, durable resource/p99 and real Agent/model A/B.
`whole_project_blockers_closed=false`.
