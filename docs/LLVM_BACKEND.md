# P6: experimental HSIR-to-LLVM scalar backend

`hepta.llvm_scalar_backend` is a **direct** LLVM IR text generator, not a Rust
or C source translator. It takes the canonical `hepta.hsir.v0` typed semantic
snapshot and generates a native host object/shared library through actual
Clang/LLVM. There is no required Python runtime in the produced library.
This is a very narrow prototype: **P6 remains open**.

## Strict acceptance profile

- Only `export "C"` functions with 0–16 `i32` value parameters and an `i32`
  return, with one root return statement, or one root `if/else` whose two
  branches each consist of exactly one `return`. The condition may be a
  typed boolean literal or a signed `i32` comparison (`== != < <= > >=`).
  The additional **single-local SSA profile** accepts exactly three root
  statements: a mutable i32 `let`, one `if/else` with one direct assignment
  to that same local on both paths, and a final `return`. LLVM `phi i32`
  merges those branch values. When either arm contains checked arithmetic,
  the incoming label must reference its actual post-overflow continuation
  block; failing to do so is rejected by the native LLVM verifier. Arbitrary
  nested flow, loops, multiple locals and general phi-node SSA remain open.
- Literals, parameter references, unary plus/minus, checked signed
  `+`, `-`, `*` and explicitly wrapping `wrapping_add/sub/mul`.
- Both declared and inferred function effects may only contain `panic`, and
  each must **include** it whenever checked arithmetic can trap. A forged
  zero-panic effect declaration is rejected. Resource clauses may only be
  empty or the known zero-heap / no-block/suspend/spawn quartet.
- Structs, ADTs, generics, imports, pointer operands, FFI, unsafe, allocation,
  concurrency, external assumptions, dynamic dispatch and complex control flow
  **reject**, instead of silently lowering to Rust or C.
- The snapshot and LLVM IR digest checks prevent accidentally changed semantic
  snapshots and emitted IR. They are **not cryptographic attestations of
  successful type checking**: a caller must first run the actual Hepta
  frontend and pinned Rust native check. The Clang identity and executable
  SHA-256 are recorded in the resulting host compilation report.

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
python -m unittest discover -s tests -p test_llvm_scalar_phi.py -v
python -m unittest discover -s tests -p test_llvm_scalar_targets.py -v

# Object-only cross compilation: output is NOT executed on target.
python -m hepta build-llvm-scalar examples/llvm_scalar.hepta \
  --rustc /path/to/pinned/rustc --target aarch64-unknown-linux-gnu \
  --output /tmp/hepta_aarch64.o
```

The `build-llvm-scalar` driver validates the actual source with the existing
Rust backend and pinned compiler **before** invoking this experimental LLVM
lowerer. A Rust failure rejects the build. There is no evidence that a
`frontend_only` result suffices. The LLVM path is strictly additive: it does
not change the default Rust and C backends. 

The suite executes Clang-produced native shared libraries from LLVM IR,
links independent GCC-compiled C references, and compares 100 seeded inputs
per arithmetic operation. An additional 103-case differential test exercises
the `if/else` integer-comparison CFG and explicitly rejects malformed
branches and unsupported boolean operations. It separately confirms two's-complement wrapping at the boundary
and aborts a child process on overflow. Safety-negative inputs are refused.
The `test_llvm_scalar_phi.py` suite covers 804 valid integer pairs against
a separately GCC-compiled C implementation and a checked-overflow predecessor
SSA regression, plus structural/effect/symbol-inventory rejection cases.
The LLVM compile receipt verifies its function-name inventory against actual
`define i32` declarations before publishing the native artifact.
A parser/checker/HSIR integration case runs when the full bootstrap compiler
modules are available. If it skips, do not record a complete integration pass.

## Exact cross-target object support (not runtime qualification)

The low-level `compile_scalar_object` API and public
`build-llvm-scalar --target` CLI accept only three object profiles:
`x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`,
`x86_64-pc-windows-msvc`. Clang compiles the same checked scalar IR to
ELF/COFF objects, and the driver validates the architecture tag before
publishing the object via same-filesystem no-overwrite hardlink.

The CLI first runs the pinned **host** Rust reference validation. That is
not validation under the cross target's calling convention or execution
environment. Cross-object reports include the exact Clang executable hash,
IR/object hashes, target identity, and `target_execution_verified=false`,
`foreign_c_abi_verified=false`, `backend_semantics_proved=false`.

`tests/test_llvm_scalar_targets.py` actually compiles all three objects on
the available Linux Clang host; all four object/profile/integrity test cases
passed locally. Native target execution, cross-target ABI roundtrips and
hardware measurements remain open. CI attempts the same three targets using
the actual Hepta frontend and pinned Rust reference.

## Still open for P6

The emitted subset is not a full Hepta backend. It supports only the two
explicit control-flow patterns above and still lacks general CFG/SSA, heap,
borrows, generics, symbols beyond this C ABI subset, debug information,
optimizer tuning, alternative LLVM versions, and target profiles. It has no
formal refinement proof and no evidence of general Rust performance parity,
CPU/RSS or tail-latency superiority. The next acceptance sequence is typed CFG
and SSA/phi; value ownership and loan states; backend semantics comparison;
large application differential tests; multihost target ABI; and representative
performance/resource regression gates with explicit sample counts.
