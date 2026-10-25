# P6: experimental HSIR-to-LLVM scalar backend

`hepta.llvm_scalar_backend` is a **direct** LLVM IR text generator, not a Rust
or C source translator. It takes the canonical `hepta.hsir.v0` typed semantic
snapshot and generates a native host object/shared library through actual
Clang/LLVM. There is no required Python runtime in the produced library.
This is a very narrow prototype: **P6 remains open**.

## Strict acceptance profile

- Only `export "C"` functions with 0–16 `i32` value parameters and an `i32`
  return, and exactly one return statement per function.
- Literals, parameter references, unary plus/minus, checked signed
  `+`, `-`, `*` and explicitly wrapping `wrapping_add/sub/mul`.
- Both declared and inferred function effects may only contain `panic`; the
  resource clauses may only be the empty set or the known zero-heap / no
  block, suspend, spawn quartet.
- Structs, ADTs, generics, imports, pointer operands, FFI, unsafe, allocation,
  concurrency, external assumptions, dynamic dispatch and complex control flow
  **reject**, instead of silently lowering to Rust or C.
- The byte/hash check prevents stale and accidentally changed snapshots; it
  is **not a cryptographic signature of successful type checking**. Caller
  must run the actual Hepta frontend and reference Rust native check.

For checked signed arithmetic, LLVM `llvm.s{add,sub,mul}.with.overflow.i32`
feeds an explicit branch to libc `abort()`. This preserves the prototype's
panic-abort policy rather than introducing LLVM poison via unchecked `nsw`
arithmetic. This profile is hosted only; it is **not no_std** and does not
support Windows or board ABIs. Wrapping arithmetic uses ordinary modular i32
LLVM operations.

## Reproduce

```sh
# Real Hepta source -> checked HSIR -> LLVM IR -> host shared library.
# The pinned rustc validation is mandatory, with no frontend-only fallback.
python -m hepta build-llvm-scalar examples/llvm_scalar.hepta \
  --output /tmp/hepta_scalar.so \
  --rustc /path/to/pinned/rustc \
  --clang clang

python -m unittest discover -s tests -p test_llvm_scalar_backend.py -v
```

The `build-llvm-scalar` driver validates the actual source with the existing
Rust backend and pinned compiler **before** invoking this experimental LLVM
lowerer. A Rust failure rejects the build. There is no evidence that a
`frontend_only` result suffices. The LLVM path is strictly additive: it does
not change the default Rust and C backends. 

The suite executes a Clang-produced shared library from emitted LLVM IR,
links a separate GCC-compiled C reference, and compares 100 seeded inputs
for each of addition, subtraction, and multiplication where C has defined
behavior. It separately confirms two's-complement wrapping at the boundary
and aborts a child process on overflow. Safety-negative inputs are refused.
A parser/checker/HSIR integration case runs when the full bootstrap compiler
modules are available. If it skips, do not record a complete integration pass.

## Still open for P6

The emitted subset is not a full Hepta backend. It lacks control flow, heap,
borrows, generics, symbols beyond this C ABI subset, debug information,
optimizer tuning, alternative LLVM versions, and target profiles. It has no
formal refinement proof and no evidence of general Rust performance parity,
CPU/RSS or tail-latency superiority. The next acceptance sequence is typed CFG
and SSA/phi; value ownership and loan states; backend semantics comparison;
large application differential tests; multihost target ABI; and representative
performance/resource regression gates with explicit sample counts.
