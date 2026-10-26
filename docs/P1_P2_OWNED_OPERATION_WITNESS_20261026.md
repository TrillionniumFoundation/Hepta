# P1/P2 Owned LLVM: source-bound operation-site witness

**Status:** narrow implemented candidate; full HIA ownership SSA/backend
soundness is **OPEN**. Source base: PR #160
`7c58713ab1d1597beea4ac196e3ad10310b0c382`. This work is stacked,
never a second parser, resource checker, LLVM backend or C/C++ migrator.

## Existing authority, actual changes

1. Preserve `semantic_ir.lower_checked_program` as the sole checked-source
   snapshot and `resource_lowering.lower_resource_ir` plus
   `resource_ir.verify_resource_ir` as the existing ownership/CFG authority.
2. The new `owned_operation_witness` consumes **the just verified, source-derived
   Resource IR** and checks exact resource graph digest, closed schema, proof
   claims, function inventory, reachability and operation coverage.
3. The existing Owned LLVM emitter schedules nongeneric function compilation
   from the verified graph's function order, rather than a separately
   enumerated unchecked function list. Every emitted concrete function
   specialization must match the graph's **static syntactic buffer,
   try_buffer and drop site inventory**.
4. An allocation is counted only after the existing emitter has appended
   its actual `@__hepta_owned_try_buffer` LLVM call. The witness separates
   `buffer` (infallible, requires an emitted conditional abort path) from
   `try_buffer` (returns a fallible Result). A drop is counted only after
   the concrete `@__hepta_owned_drop*` call is appended. Missing calls,
   missing observations, changed site counts, promoted claims and forged
   graph/receipt identities fail before native compilation.
5. Existing source/native postcheck, bounded Rust reference compiler,
   Clang-based host backend, strict dynamic ELF verifier and no-replace
   artifact publication remain unmodified.

## What this proves and what it does NOT

This is a **static operation-site conservation check**, not a dynamic
allocation/free counter: a single loop site may execute many times. It
does not prove the correctness of drop helpers, buffer-pointer provenance,
machine code, numerical values, branch conditions, alias lifetimes, or
optimizations. A malicious backend might emit an incorrect call while
preserving the counted call sites. It does **not** consume all Resource IR
operations for LLVM lowering. The ownership graph's
`native_codegen_uses_this_ir=false` and whole-language/backend-refinement
false claims remain unaltered.

The resource graph still deliberately abstracts copied scalar values.
Existing Owned LLVM instruction semantics are generated from checked AST;
general executable HIA SSA has not been implemented. Do not represent
this as closure of P1/P2, Rust-universal safety, arbitrary C/C++ migration,
full ABI/physical hardware, or P0-P7 blockers.

## Negative and positive tests

```sh
python -m unittest tests.test_owned_operation_witness \
  tests.test_llvm_owned_backend tests.test_resource_ir -v
python tools/release_check.py
```

The added source test covers a real checked Buffer allocation/drop,
fallible Result-based try_buffer, early-return plus generic-owner-transfer
branch, original native LLVM emission, fake receipt/claims,
integer-for-Boolean forgery, dropped allocation/drop call, missing infallible
abort guard, incorrectly tagged constructor mode and missing event observation.
Historical evidence and another commit's unit run must not be inherited.

**Acceptance boundary:** full exact-source compiled/tested receipt not yet
available for this change; `whole_project_blockers_closed=false`.

## Next strongest engineering step

Lower numerical operations and resource transitions into one SSA graph.
Require the native emitter to obtain *each* move/borrow/load/store/drop
operation and its operands from verified HIA Core instead of from a
separate AST visitor. Create a finite reference interpreter and Rust/native
differential corpus on the same graph, then model unwind/error edges,
provenance, all owned-type combinations and exceptional foreign behavior.
