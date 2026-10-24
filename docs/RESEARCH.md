# Design antecedents

These are primary sources used for the design discussion. Hepta's implementation
and measured claims are recorded separately in SPEC.md and artifacts; none of
these sources proves the correctness or performance of this new compiler.

- Rust ownership: https://doc.rust-lang.org/book/ch04-01-what-is-ownership.html
- Aliasing and optimization: https://doc.rust-lang.org/nomicon/aliasing.html
- Resource cleanup limits: https://doc.rust-lang.org/std/mem/fn.forget.html
- C layout: https://doc.rust-lang.org/reference/type-layout.html
- Foreign interfaces: https://doc.rust-lang.org/nomicon/ffi.html
- RustBelt (POPL 2018): https://plv.mpi-sws.org/rustbelt/popl18/
- Flux (PLDI 2023): https://ranjitjhala.github.io/static/flux-pldi23.pdf
- Verus spec/proof/exec: https://verus-lang.github.io/verus/guide/modes.html
- Typed Holes and ChatLSP (OOPSLA 2024): https://arxiv.org/abs/2409.00921
- Koka effects: https://koka-lang.github.io/koka/doc/book.html
- Austral linear types and capabilities: https://austral-lang.org/spec/spec.html
- MLIR bufferization: https://mlir.llvm.org/docs/Bufferization/
- Clang target ABI classification: https://clang.llvm.org/doxygen/classclang_1_1CodeGen_1_1ABIInfo.html
- Linux DMA semantics: https://docs.kernel.org/core-api/dma-api-howto.html
- Volatile is not atomic synchronization: https://doc.rust-lang.org/std/ptr/fn.read_volatile.html

## Attribution of novelty

Ownership, linear resource obligations, effect types, structured editing, C ABI
interop and compiler-guided generation all have prior art. The research
hypothesis is that a coherent small systems language and an evidence-bearing
change interface can improve agent development while preserving the relevant
native cost model. This hypothesis requires its own controlled evaluation.
