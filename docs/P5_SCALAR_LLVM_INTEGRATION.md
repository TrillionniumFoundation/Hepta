# P5 LLVM-native scalar integration, additive to P0/P1

Frozen base: PR #43 head 3937cfd964d5ec3e58ed1f00d5012a547c14b1df.
Original LLVM SSA source: PR #37 af3f406f4d980ae2e8c5fca23b4ed12bee5195af.
Security-reviewed native artifact publications:
PR #41 bbf1d0eaec8337abde4a3af8f23c0f341f543247
and PR #42 0851f0a37a377ef9f704c8b3a72567693b530f0c.

This integration carries the two independently repaired LLVM backend modules
as exact Git blobs, import-path-only adaptations of three original tests,
the limited benchmark harness, and a source→Rust reference check→canonical
HSIR→CFG→independently checked SSA→LLVM→native C ABI execution test.

The i32 pure/panic C-export scalar subset only is accepted. Foreign, borrow,
owner, allocation, generics and other unsupported code reject. The native
codegen is direct LLVM and does not compile emitted Rust or C as its final
codegen. However the pinned Rust compiler MUST first validate the Hepta source.

Security: both object and shared-library output paths reject existing
files and live or dangling leaf symlinks; output publication is no-replace.
These guards are the specific fixes reviewed in PR #41/#42, not arbitrary
filesystem or compiler sandbox guarantees.

Qualify on an exact head:

    python -m unittest tests.test_ssa_differential tests.test_llvm_ssa_backend tests.test_llvm_ssa_target tests.test_llvm_ssa_integration -v

The last test requires pinned rustc 1.90.0 and actual Clang on the host.
Successful tests cannot establish compiler refinement proof, full Rust-level
soundness, general C/C++ ABI, physical hardware performance, or universally
better CPU/RSS/tail latency. P0–P7 and P01–P12 remain OPEN/PARTIAL.
