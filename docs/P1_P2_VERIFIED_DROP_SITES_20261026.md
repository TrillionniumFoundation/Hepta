# P1/P2 increment: source-verified Resource IR authorizes native static Drop sites

**Implementation status:** finite non-generic Drop-site coverage, **not** HIA Owned SSA v1 or general native/backend refinement.

## Exact scope and ancestry

- Parent: PR #166 HEAD `3ed1631b1110d88cc71b484dfa8f7f79d9aa01c3` (already stacked on PR #165).
- Keep `hepta.semantic_ir`, `resource_lowering`, `resource_ir.verify_resource_ir`, `llvm_owned_backend`, the Rust reference route, C/C++ migrators, native object verifier and artifact publisher intact.
- This change adds **one finite consumer** of verified Resource IR static `drop` operations, not a second parser, owner checker or LLVM emitter.

## Implemented source/native contract

`hepta.owned_drop_sites.qualify_drop_sites(graph, verified)` accepts a
source-generated, independently checked graph and an exactly matching verifier
receipt. It independently binds the graph's byte identity, exact false safety
claims, external obligation state, function inventory, local/parameter slots
and explicit `drop` operation source types. For each non-external function it
exports an immutable, per-type multiset of **static source Drop sites**.

`emit_owned_llvm` now requires Resource IR receipt status
`resource_cfg_verified`, exact graph digest, declared source/project identities,
no foreign assumptions and strictly false proof claims. Its current emitter
receives the resulting inventory. For **non-generic functions**, each native
`drop(move owner)` / `release(move owner)` must consume exactly one
corresponding Resource IR `drop` site of the same concrete type, and every
verified site must be accounted for after generating the function. Missing,
extra, wrong-type and wrong-function sites fail with
`E_LLVM_OWNED_DROP_SITE` *before any native Clang compilation/publication*.
The existing independently verified resource **type table** still directs
nested Drop helper choice as in PR #166.

This is stronger than a mere digest check: the native compiler is now gated by
an instruction-level finite subset of the independently checked resource CFG.

## What this cannot prove

A static per-type Drop multiset is not an executable SSA memory/ownership graph:
it does not establish ordering, branch path equivalence, error unwinding,
provenance, allocator/refusal behavior or LLVM refinement. It is not the complete
Resource IR driving native codegen. Generic function specialization currently
retains the older checked-source Drop lowering, because source Resource IR has
symbolic `@function::T` rather than per-specialization concrete call sites;
the new static site gate does not falsely claim coverage of those instances.
Borrow operations, moves, allocation sites and numerical computation still
follow the existing checked AST in Owned LLVM. The original verified Resource IR
and pinned Rust native reference remain required. No arbitrary C/C++ program,
foreign ABI, physical board, DMA/GPU or formal whole-language safety claim is
closed by this increment.

## Executed evidence and reproduction

- Offline **Python 3.13** `tests/test_owned_drop_sites.py`: **4/4 passed** against
  the precise new helper bytes (Git blob
  `dac946fa95ddba7cb34636a4ad24c87186f39847`) using a **stubbed only**
  `resource_ir._CLAIMS` dependency. Includes malformed `src` list/dict,
  duplicate/missing source identities, rehashed falsified claims and verified
  static multi-block site inventory.
- This does **not** run the full Hepta parser, Resource IR verifier or real
  LLVM backend in this environment. Exact-head full-source tests and pinned
  Rust/Clang execution remain to be performed; do not promote unrelated
  ancestor receipts.

On a complete checkout of this exact commit:

```bash
python -m unittest tests.test_owned_drop_sites tests.test_owned_drop_sites_llvm tests.test_owned_drop_plan tests.test_owned_drop_llvm -v
python -m unittest tests.test_resource_ir tests.test_llvm_owned_backend tests.test_cpp_owned_llvm -v
```

The follow-up P1/P2 blocker is a **single operational type/value/owner/loan/Drop/
provenance/effect SSA** that the Owned LLVM emitter consumes exclusively. All
other P0–P7 production blockers remain OPEN/PARTIAL.
`whole_project_blockers_closed=false`.
