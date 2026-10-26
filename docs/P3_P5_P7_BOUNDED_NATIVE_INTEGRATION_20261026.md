# Hepta P3/P5/P7: bounded native tool identity and functional ARM64 probe
2026-10-26 — source-level integration checkpoint, not production certification.

## Exact parent and donor
- Parent: PR #158 `1b5868a4e516786c61d1aead8ac7ec0c12f28d40`, including the P7 runtime 4259-byte source admission fix.
- Shared tool-identity donor: PR #152 `3994e34f5a737edcb1a2c7085fbd96e55c14d8b8`, based on #149 `80da2e7ec168eaf308475a7f2178b92280066321`.
- Six unchanged, source-compatible Git blobs were transplanted after verifying that their old base blobs match the parent: `hepta/native_tool_identity.py`, `tests/test_native_tool_identity.py`, `hepta/c_project.py`, `hepta/llvm_ssa_backend.py`, `hepta/llvm_ssa_target.py`, and the original donor scope document.
- Two changed source paths overlap with later Owned LLVM work; `hepta/llvm_owned_backend.py` and `hepta/llvm_owned_aarch64.py` were **manually reconciled** to preserve current target-layout probes, source/resource checks and object publication. No duplicate parser, compiler, HSIR, resource checker or alternative LLVM backend was added.

## Source changes and reviewed scope
1. **P3/P5/P7 tool identity:** One shared `digest_executable` streams at most 1 MiB at a time, enforces a finite 1 GiB tool-image limit, refuses untrusted path/object changes, and is called before and after native compilation. Both scalar and Owned LLVM backends now use it. This is compiler byte identity, **not** authenticated compiler provenance.
2. **P7 target layout and linkage:** The existing AArch64 static-layout and dummy freestanding link probes require an unchanged selected Clang executable. Link-time dummy allocator binaries remain nonfunctional and **must not execute**.
3. **P7 functional runtime:** `owned_aarch64_runtime.py` uses the shared digest guard on the selected compiler and optional runner. The exact reviewed 4259-byte runtime C source is read with a 8193-byte maximum attempted read, regular-file/inode/path pre/post checks, and SHA-256 pin; the 4096-byte actual runtime heap limit is unchanged. The compiler-produced runtime object and linked ELF are checked for finite size and stable regular-file identity **before** bytes enter memory. Emulator post-checks also use the same bounded ELF reader.
4. All source-facing paths retain checked C ABI scope, original Hepta AST/Resource IR, final-use constraints, no-overwrite artifact publication and explicit open proof obligations.

## Actually executed tests in this interaction (non-CI)

- **8/8 Python 3.13 isolated tests** for the **exact unchanged** donor `hepta/native_tool_identity.py` and `tests/test_native_tool_identity.py` (local Git blob hashes `231e44d443a0bd77bb9caf30072d1ba3d7dcc8db` and `0a245df1414c69e6512f52d2a8a7c0229f1fe28d`). Includes real Clang digest, empty/missing, FIFO/symlink, sparse 1-GiB+ file, path swap and inode mutation.
- **5/5 isolated helper-shape Python tests** for the P7 bounded source/artifact reader: exact reviewed runtime SHA, tampering, symlink/FIFO/sparse oversize, pre-open path replacement and bounded native object bytes. These tests use a standalone extracted helper, not the complete imported Hepta module.
- The exact C runtime source `5caa9cbc33df5734626ff17045159add08b850abceb021b038ddb110db6f402c` compiled with local Clang 17/lld 17, linked and **executed on native x86-64 with exit code 0** using the explicitly scoped C `owned_case` stand-in. The same runtime and stand-in **linked to AArch64 ELF64 ET_EXEC machine 183**, with RX code, RW data and nonexecutable stack. No AArch64 execution or full Hepta source→LLVM result is claimed.

## Exact-source acceptance still required

On a full checkout of the final integration HEAD, without gating further code changes on remote CI:

```sh
python -m unittest \
  tests.test_native_tool_identity tests.test_owned_target_layout \
  tests.test_owned_aarch64_link tests.test_owned_aarch64_runtime \
  tests.test_c_project tests.test_llvm_ssa_backend \
  tests.test_llvm_ssa_target tests.test_llvm_owned_backend \
  tests.test_llvm_owned_aarch64 -v
```

Then run source-facing Rust-validated Hepta `--finite-runtime-link-probe`, target layout/native ABI and proof audits, true qemu-aarch64 execution if a runner exists, and independent external oracle/negative controls. Exact target hardware and performance qualification are separate. A new source SHA cannot inherit an ancestor's 40/40 or 44/46 receipts.

## Permanent open blockers

- P0/P1: General memory/provenance/lifetime/formal refinement still open.
- P2/P3/P4: Arbitrary industrial C/C++ source migration, ownership inference and cross-host C/C++ ABI parity not proved.
- P5: Whole-language, pointer/borrow/Drop lowering and general Rust performance superiority not proved.
- P6: Real provider/model 2x2 A/B, budgets and independent task score remain unavailable.
- P7: Real ARM64 execution of actual Hepta-compiled Owned program, physical board, DMA/IRQ, GPU/NPU and sustained production service p99 are **not** qualified.

`whole_project_blockers_closed=false`. Retain Draft until exact-source native tests and honest receipts are available.
