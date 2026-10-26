# P7 finite Owned LLVM Linux runtime: real memory operations, bounded scope

This is a **real** freestanding test runtime, not a general libc, production
allocator, DMA/IRQ/device driver or proof that all Hepta code is safe. It is
separate from the deliberately nonfunctional synthetic link-only shim in
`hepta.owned_aarch64_link` and never changes that shim's claims.

## Single selected ABI

The checked and source-bound public function is exactly:

```c
uint64_t owned_case(size_t size, uint8_t value, size_t index,
                    uint32_t reject, uint32_t early);
```

The source-facing `llvm_owned_aarch64.build_owned_aarch64_source` verifies the
function name and **all parameter types/modes and return type** from the
already Rust-reference-validated Hepta Program before permitting the runtime
probe. Other exports, raw pointers, unsafe/foreign declarations, extra
parameters, unsupported machine layouts, or unrelated source code may not
borrow this ABI evidence.

`examples/llvm_owned/finite_aarch64_runtime.c` implements a fixed,
16-byte-aligned, 4096-byte storage area with **one live allocation**.
`malloc` returns null on zero or oversize or overlapping requests, and
`free` aborts invalid/double frees. It provides bytewise `memset`,
`memcpy` and overlap-correct `memmove` on **valid caller-owned ranges**.
These functions cannot enforce pointer provenance on arbitrary C callers.
Linux syscall 93 exits on ARM64 and syscall 60 exits on x86-64.

An explicit `_start` executes seven fixed `owned_case` controls (normal
read, first-byte mutation, early return, checked out-of-range, rejected
construction, out-of-budget allocation, and zero-length), and verifies
balanced allocations/releases plus observed allocation refusal. A nonzero
exit means a failed actual runtime observation.

The literal exact reviewed runtime SHA-256 is
`c258eae09d7f2d506bd18e4ce0f0db89c5296dcc9d9772759a2283984cf855cb`.
The probe refuses silently changed runtime C source. Source, compiler,
original target object, functional runtime object and linked ELF identities
are retained in the typed receipt.

## Real execution performed on 2026-10-25 (local Clang 17 and lld 17)

A freestanding independent C implementation of that one exact ABI was used
as a **stand-in** to test the C runtime before attempting the whole Hepta
backend:

- Native x86-64 Linux: real Clang objects → lld static executable → actual
  process exit **0**. A deliberately wrong stand-in return was checked
  to exit **11**.
- Real AArch64 object + actual functional runtime compiled with Clang,
  linked by lld to AArch64 ELF64 **ET_EXEC** machine 183. Linked ELF SHA-256
  (for the local independent stand-in smoke run):
  `49ed2309ab33b2895a2726506f7272d3ec8032deaef633d638649a7df6949dd3`.
- This local environment did **not** have `qemu-aarch64`; the AArch64 image
  was **not executed**. The x86-64 success is not target execution and the
  independent C stand-in is not a source-bound Hepta native build.

The in-repository `tests/test_owned_aarch64_runtime.py` exercises that
behavior and hostile input controls. These new repository tests are committed
but **not yet run against a complete checkout and pinned Rust/Clang20 Hepta
toolchain**. The Clang/lld standalone observations above do not qualify them.

## Reproducible source-bound invocation

On a checkout with the selected rustc, Clang and lld:

```sh
python -m hepta.llvm_owned_aarch64 examples/llvm_owned/main.hepta \
  --output /tmp/hepta-owned-arm64.o --finite-runtime-link-probe
```

This publishes the checked ARM64 `.o`, not the test ELF. When the exact
`owned_case` source and finite runtime link succeed, the receipt status is
`finite_real_runtime_linked_not_executed`.

With an explicit QEMU **user-mode** binary installed, the optional:

```sh
python -m hepta.llvm_owned_aarch64 examples/llvm_owned/main.hepta \
  --output /tmp/hepta-owned-arm64-qemu.o \
  --finite-runtime-link-probe --qemu-aarch64 qemu-aarch64
```

must actually execute the linked, temporary functional ARM64 image and
observe exit 0 before reporting `finite_qemu_userspace_execution_passed`.
QEMU is emulation, **not physical hardware**. If unavailable or failing,
the tool rejects rather than publishing a successful qualification.

No timing or production CPU/RSS result is inferred from this finite test.
The runtime deliberately cannot support nested allocations, concurrent
owners, arbitrary C++ RAII, larger workloads, production libc, DMA,
interrupts, GPU/NPU, or full Hepta language semantics.

**Production blockers remain open:** general memory/provenance soundness,
true ARM64 Hepta source-to-runtime execution qualification on pinned tools,
production allocator/FFI budgets, Windows/ARM platform matrices, real
devices, reliable p99, and genuine AI model A/B. Keep
`whole_project_blockers_closed=false`.
