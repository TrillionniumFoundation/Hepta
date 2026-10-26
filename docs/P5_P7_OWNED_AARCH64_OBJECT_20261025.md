# Owned LLVM AArch64 Linux relocatable-object profile (P5/P7)

This increment extends the **existing** Hepta-owned LLVM backend through
`hepta.llvm_owned_aarch64`. It does **not** add a second type checker,
ownership IR or LLVM source emitter.

## Supported entry points

```sh
python -m hepta.llvm_owned_aarch64 examples/llvm_owned/owned.hepta \
  --output /tmp/hepta-owned-arm64.o --rustc /absolute/pinned/rustc --clang clang
python -m unittest tests.test_llvm_owned_aarch64 -v
```

The high-level entry requires an actual checked Rust reference and an
unchanged exact project graph; invokes the **one** checked source-to-LLVM
generator; independently recomputes the resource graph; and stages the new
AArch64 object until all source checks pass. No Rust or C code is emitted to
make the target artifact.

The compiler-owned LLVM source is retargeted by replacing **only** the sole
`target triple = "x86_64-unknown-linux-gnu"` line with
`target triple = "aarch64-unknown-linux-gnu"`. The original source LLVM
SHA-256 and the exact retargeted LLVM SHA-256 are both retained. The verifier
rejects an extra or unexpected target triple or `target datalayout`.

Clang compiles `--target=aarch64-unknown-linux-gnu -x ir -O3 -fPIC -c`.
Before any no-overwrite publication, Hepta checks the resulting **real ELF64
AArch64 machine number 183** using the existing `object_structure` parser,
then examines `object_symbols` to require exactly the source-declared C
export function inventory, strong executable code and only bounded external
imports (malloc, free, abort, memset, memcpy, memmove). This is a conservative
allowlist, not a proof of foreign allocator behavior.

The shared `artifact_publication` verifier binds the original exact object
bytes, regular inode and destination identity; a high-level staging wrapper
checks the source graph both before and after publication and retracts only
its own linked path on failure. The CLI never links or executes an AArch64
program, never silently falls back to x86, Rust or C, and never overwrites a
previous output.

## Actually executed *independent* toolchain control

In a separate local Debian x86-64 environment with LLVM/Clang available but
no full Hepta checkout or pinned Rust, the following LLVM fragment was compiled
with real Clang into an AArch64 relocatable object:

```llvm
target triple = "aarch64-unknown-linux-gnu"
declare ptr @malloc(i64)
declare void @free(ptr)
define i64 @hepta_owned_target_smoke(i64 %n) {
entry:
  %p = call ptr @malloc(i64 %n)
  %is_null = icmp eq ptr %p, null
  br i1 %is_null, label %error, label %ok
ok:
  call void @free(ptr %p)
  ret i64 %n
error:
  ret i64 0
}
```

`clang --target=aarch64-unknown-linux-gnu -x ir -O3 -fPIC -c`
returned **exit 0**. The generated file was a real little-endian
AArch64 ELF64 relocatable object, 656 bytes, with
`hepta_owned_target_smoke` defined as an externally visible text symbol.
This is compiler target-support evidence only. The new complete Hepta
source-to-ARM object tests are committed but **not yet executed** on the exact
new branch source; this control must not be presented as that qualification.

## Qualification boundaries still open

- No AArch64 link or QEMU/physical target run.
- No AArch64 Rust borrow/type parity or source-to-LLVM refinement proof;
  x86 source-checked layout assumptions have not been independently proved
  ABI-equivalent on target.
- No libc allocator semantics, cache/coherence, DMA, IRQ, GPU/NPU or
  device-driver support qualification.
- No multi-target C++ bridge ABI, loaded shared-library or exception
  interoperability, and no assertion of universal resource/performance gains.
- No automatic promotion of the previous unified candidate's 44/46 result.
- **`whole_project_blockers_closed=false`**.

Before considering promotion, run `tests.test_llvm_owned_aarch64` on an exact
source checkout with the locked toolchain, followed by full source/reference
integration and a real AArch64 C caller under a qualified target runtime.
