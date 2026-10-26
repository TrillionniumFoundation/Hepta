# P2/P3: fail closed on unsafe x86-64 shared ELF segment permissions

**Exact code parent:** PR #236 initial integration commit
`438bb9b7ff2abc16416fe115c08940e2076d906c`, containing
PR #234 startup isolation and PR #233 source-publication ABI reinspection.

## Concrete gap

The single shared-ELF scanner (`hepta.elf_shared_abi.inspect_owned_shared_elf`)
validated ET_DYN, dynamic symbols, loader-linked import inventory and an
executable PT_LOAD. But it **accepted a PT_LOAD with PF_W|PF_X and ignored
PT_GNU_STACK permissions**. The same correct exported C functions can occupy
unsafe writable+executable loader mappings, or the file can request an
executable process stack. A correct symbol inventory is not a segment policy.

This code path is reused by existing Owned LLVM, scalar-host-LLVM and the
HIA Core source-facing dynamic ELF reinspection. No new ABI parser, linker,
lowerer, or proof language is introduced.

## Exact finite policy

- PT_LOAD must have precisely `PF_R`, `PF_R|PF_X`, or `PF_R|PF_W`
  (4, 5 or 6). RWX, W-only, X-only and unknown/OS-defined extra flag
  bits are unsupported in this reviewed native profile.
- An explicit **single** PT_GNU_STACK is mandatory and must carry precisely
  PF_R|PF_W (6); executable, missing or duplicate stack descriptors reject.
- Retain the existing required executable-load, PT_DYNAMIC,
  section/symbol/DT_NEEDED and source-export checks. The receipt's schema
  and existing false proof flags remain unchanged.

The checked native toolchain is required to emit an ELF with a non-executable
GNU stack. This deliberate fail-closed policy may refuse other valid ELF
binaries outside the reviewed host profile. It is not a whole loader
verification, W^X runtime enforcement, or immunity to dynamic dependencies.

## Actually executed local native transport controls

Using installed Clang and GCC on Linux x86-64, compiled four genuine ELF64
shared libraries (each -O0 and -O2). Each has RX and RW PT_LOAD plus a
single RW PT_GNU_STACK. Independently examined raw program headers; **four
valid originals passed** the same finite permission predicate. For each
real binary, independently modified RX→RWX, RW→RWX,
GNU_STACK RW→RWX, deleted GNU_STACK and duplicated GNU_STACK:
**all policy mutations rejected**. This is a standalone native
program-header predicate control; it is **not** the entire new in-repository
ELF scanner, Hepta source/native execution or a formal security proof.

An actual in-repo Clang integration regression is added to
`tests/test_elf_shared_abi_native.py` and uses the real scanner with
positive and negative program-header cases. The test has been committed
but **not executed on an exact complete checkout**.

## Reproduce on the integrated commit

```bash
python -m unittest tests.test_elf_shared_abi_native tests.test_scalar_host_abi -v
python -m unittest tests.test_hia_native_source_reinspect \
    tests.test_hia_native_startup_isolation -v
```

The remaining blockers are broader source/Core/LLVM refinement, memory
provenance beyond the finite byte-owner profile, arbitrary C/C++ migration,
cross-target ABI execution, physical DMA/IRQ/GPU/NPU, live Agent A/B and
stabilized production performance. CI status is not an engineering stop.

`whole_project_blockers_closed=false`.
