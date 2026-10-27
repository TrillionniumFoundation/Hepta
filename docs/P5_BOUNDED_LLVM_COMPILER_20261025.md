# P5: bounded Clang execution for host and cross-target LLVM SSA

The original host SSA shared-library backend and target-object backend used `subprocess.run(..., capture_output=True)` with timeouts, but no in-flight stdout/stderr byte budgets. A hostile compiler or huge diagnostic output could exhaust the local Agent host's memory before the subprocess returned.

This increment reuses **the same** existing file-backed `hepta.clang_capture.run_bounded` introduced in PR #71. It does not add a competing subprocess implementation. `hepta.llvm_ssa_backend._clang_run` is the single P5 helper, shared with `hepta.llvm_ssa_target`. Both compiler identity and LLVM compilation now have stdout=64KB, stderr=256KB, stdin=0B and explicit 10s/45s wall-time limits. Compiler capture errors are surfaced as `LLVMSSARejected(E_LLVM_SSA_CAPTURE)`, not counted as native acceptance. POSIX process-group descendant cleanup and the original no-overwrite artifact-publication guards remain in force.

The local compiler tool was actually exercised on CPython 3.13 with real Clang 17: compiler version query, native ELF shared-library compilation, and Apple ARM64 Mach-O cross-object compilation all returned exit status 0 under these caps. These tests qualify bounded Clang capture on one host, **not** the full Hepta source-to-LLVM compiler or real macOS execution.

The added test `tests/test_llvm_ssa_capture.py` also checks budget propagation, failure/timeout/encoding rejection, and no output file after capture failure. Run `python -m unittest tests.test_llvm_ssa_capture tests.test_llvm_ssa_backend tests.test_llvm_ssa_target -v` in a complete Hepta checkout. Not run on this container's incomplete project checkout.

This addresses one P5 resource-exhaustion vector. It is not an OS sandbox (untrusted compiler scripts can write to filesystem, spawn independent session descendants or use resources before a polling check). Full P5 LLVM lowering semantics, pointer safety, cross-target ABI, hardware and performance blocker acceptance remains open. `whole_project_blockers_closed=false`.
