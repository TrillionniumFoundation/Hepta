# P5/P7: bounded and file-descriptor-checked LLVM native artifacts

## Reproduced gap

The LLVM SSA backends previously bounded compiler stdout/stderr but read
compiler-produced .so/.o files and the compiler executable with unbounded
`Path.read_bytes()`. A compiler error, misconfiguration or unexpectedly
oversized native image could exhaust the Hepta qualification process's own
memory after the Clang capture had already succeeded. Staged output paths
also require explicit rejection of nonregular files and symlinks before
parsing native object headers or publishing a result.

## Implementation

`hepta.native_output_guard` is the sole bounded binary-read helper used
by host SSA shared-library compilation and ELF/COFF/Mach-O SSA target
object compilation. It opens with O_NOFOLLOW/O_NONBLOCK on platforms that
support these flags, checks the actual descriptor's regular-file mode
and nonzero size, rejects outputs exceeding 64 MiB before any byte read,
and computes compiler SHA-256 by streaming up to 1 GiB rather than
materializing the toolchain executable in RAM. Both backends map invalid
native outputs to LLVMSSARejected, check staged bytes before os.link, and
check the published path's digest with bounded streaming afterwards.
The existing no-overwrite and artifact/header/export/import gates remain.

These budgets are deliberately conservative for the strict 1..32-function
i32 SSA pilot. They may reject large legitimate objects; broad language
support must introduce separately justified profile budgets, not silently
disable this constraint.

## Actual verification completed locally

Python 3.13.5, Linux x86_64: 7/7 standalone
`tests.test_native_output_guard` tests passed, including real Clang
objects for five ELF/COFF/Mach-O targets, a 64-MiB+1 sparse file,
empty file, live/dangling symlinks,
FIFO, exact budget boundary and streaming hash. GitHub blobs for
`hepta/native_output_guard.py` and `tests/test_native_output_guard.py`
exactly matched the tested local `git hash-object` SHAs; the expanded
seven-test file has blob `00f0293e05048b32729b00dd6716ff914762d7a8`.
All five real cross-object byte-format checks passed locally, not platform execution.

An additional in-repository `tests.test_llvm_native_output_limits`
exercises actual SSA emitter-backed API calls with an intentional fake
compiler that emits oversized/empty/symlink outputs. This repository
integration suite is committed but has not run in the current container,
which cannot obtain the full repo or pinned rustc over its network.

## Limits and remaining blockers

Filename-to-fd race checks are strongest on POSIX with O_NOFOLLOW.
This is not a sandbox for malicious native compilers or a defense against
same-user writers that mutate files in place without a size change.
64-MiB process artifact limits do not cap Clang's own RAM, CPU, disk scratch,
or external C/C++ libraries. Verified LLVM grammar is not a source-to-code
refinement proof. Cross-target object compilation does not qualify ABI,
real host execution or hardware. All P0-P7/P01-P12 obligations remain OPEN;
`whole_project_blockers_closed=false`.

Reproduce:

    python -m unittest tests.test_native_output_guard -v
    python -m unittest tests.test_llvm_native_output_limits -v
    python -m unittest tests.test_llvm_ssa_backend tests.test_llvm_ssa_target -v

## End-to-end source entrypoint hardening

The top-level `hepta.llvm_ssa_pipeline.build_llvm_ssa_source` previously
called unbounded `stage.read_bytes()` even if its child LLVM backend
respected an artifact cap. It now reuses `read_native_artifact` before
publication, matches the staged hash and byte count to the native receipt,
and re-fingerprints the published path through bounded streaming.
An explicit over-budget forged-native-receipt regression is committed in
`tests.test_llvm_ssa_cli`; its real native rustc gate remains necessary.
These additional tests were not run locally in the partial checkout.
