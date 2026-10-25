# Independent GCC/Clang native host baseline (2026-10-25)

The verified host-only probe in `tools/probe_dual_c_host.py` compiles a C11 record-by-value callee and independently compiled C11 caller with GCC/Clang at O0/O2. The executable validates ordinary aggregate offsets, scalar and array fields, by-value return and copying of original arguments.

**Observed on Linux x86_64:** 8/8 native compiler-pair runs passed, 2/2 deliberately wrong cross-compiler implementations exited 42 with oracle mismatch. Exact recorded compiler executable hashes, source hashes, output executable and object hashes are retained in `evidence/dual_c_host_20261025.json`.

This is an independent *C↔C* compiler baseline; no Hepta source, C++ ABI, MSVC, physical device, GPU, or proof of universal ABI correctness is involved. The more comprehensive `tools/validate_native_host.py` remains the Hepta-specific qualification authority and must run with pinned rustc on each target host.

Replay: `python tools/probe_dual_c_host.py > /tmp/dual_c_host.json`.
