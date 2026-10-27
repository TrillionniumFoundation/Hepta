# P3/P5: source-facing scalar LLVM native dynamic ABI guard

## Executable integration and trust boundary

The scalar32 source-facing LLVM host build now verifies the **actual staged
Linux/x86-64 ELF64 shared object** before no-overwrite publication. It uses
the same `hepta.elf_shared_abi.inspect_owned_shared_elf` parser as the
existing Owned LLVM path; `hepta.scalar_host_abi` adds a **stricter
nonallocating scalar foreign-import policy**, rather than another ELF parser.

Mandatory sequence:

1. Check the actual project through pinned Rust reference; ensure import-graph
   byte/path identity is stable.
2. Require canonical-source hash and full independent Resource IR CFG
   verification via `hepta.native_resource_gate`, rejecting all external and
   unmodelled semantics in this scalar subset.
3. Require exact verified scalar CFG/SSA→LLVM origin and closed LLVM grammar.
4. Run real Clang. Check its native receipt, staged bytes and target-specific
   object symbols for cross-objects.
5. **Host shared case**: decode real ELF `ET_DYN`, loader dynamic section,
   dynamic symbol table, executable symbol extents, reviewed runtime libraries
   and exact source C export list using existing `elf_shared_abi`.
6. Check that the scalar-specific dynamic undefined-symbol inventory is a
   subset of `abort`, `__cxa_finalize`, the two compiler-generated ITM clone
   registration hooks and `__gmon_start__`. In particular, `malloc`,
   `calloc`, `free`, `memcpy`, `memmove`, `memset`, `getpid` and
   arbitrary foreign APIs are refused for the finite scalar machine-code
   profile. This does **not** claim all-process allocation accounting.
7. Enforce exact typed, closed dynamic ABI receipt fields and explicit
   `native_execution_proven=false`,
   `whole_language_memory_safety_proven=false`,
   `backend_refinement_proven=false`.
8. Recheck unchanged source graph; publish exact staged bytes by the existing
   atomic no-overwrite hardlink and post-publish verifier. The final receipt
   records `host_elf_dynamic_symbols_checked=true`, but does not claim that
   native C calls have executed under the full Hepta compiler.

Unsupported host formats fail closed at the strict source-facing entrypoint
rather than silently acquiring Linux/x86-64 ABI qualification. Target object
generation retains separate ELF/COFF/Mach-O structural and symbol validation.

## Direct native smoke, independent of CI

On the current Linux/x86-64 execution container:
- Clang 17 produced a real 14,984-byte shared ELF from a strict scalar LLVM
  sample exporting `hepta_scalar_probe`. A separate GCC 14 C executable
  dynamically opened it, invoked `hepta_scalar_probe(41)` and exited 0.
- A native library containing an additional `unexpected_export` exposed
  that unexpected symbol in the real dynamic symbol table.
- A native library invoking `getpid` exposed the disallowed imported
  symbol in its dynamic symbol inventory.
- An independent `malloc` IR example with a retained volatile store
  continued to expose the dynamic `malloc@GLIBC_2.2.5` import under
  `-O3`, confirming this malicious-profile fixture is not optimized away.

Native object SHA-256 fingerprints for three sample libraries:

| Case | Real native SHA-256 |
| --- | --- |
| Expected single scalar C export | `59052231400be9af065216a7f0f99698631bc6b9120b59220f5e377cd650d580` |
| Extra public function | `32aa0be1d93fbcc7c7cea24d6d189789e3e61b69fe18c7a5fe5c96b6cf4b347b` |
| Extra `getpid` import | `f07184522ff8eba976eb270acc0f4b06127d6199d1c6e4b931eab191e07b7df3` |

These **actual native compiler and C caller observations** are not execution
of the entire Hepta-native integration suite, or even a claim that the
source-facing Hepta path has passed on this new commit. The isolated
`tests/test_scalar_host_abi.py` now contains five genuine Clang/ELF
positive/negative cases, including profile-differentiated `malloc` rejection.
The pinned Rust/Clang full-project tests remain unrun here.

## Remaining blockers and policy

- **P0/P1**: general lifetime, trait, pointer provenance and source/backend
  refinement are unproved.
- **P2/P3/P4**: arbitrary C/C++ implementations, exceptions, general RAII,
  binary ABI across real Windows/MSVC/ARM/Apple hosts remain unqualified.
- **P5**: Owned LLVM breadth, stable p99/throughput/RSS performance and full
  executable semantics are not proved. Frozen previous scalar and owned LLVM
  performance reports still have two quality-gate failures; no thresholds
  have been relaxed.
- **P6**: actual controlled Agent-model 2×2 with real costs has not run.
- **P7**: physical board, DMA, GPU/NPU and long-lived target service
  measurements are missing.

`whole_project_blockers_closed=false`.
