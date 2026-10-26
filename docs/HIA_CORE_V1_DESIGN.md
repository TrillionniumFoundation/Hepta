# HIA Core v1: proposed executable ownership-SSA contract

**Status: design only.** This is not the implemented HIA scalar-core.v0,
not a new semantic authority and not evidence of whole-language safety.
Current authority remains Hepta canonical checked source and the existing
strict, independent verification passes. A new v1 may replace this design
status only after producer/consumer proof and negative native qualification.

## Operational scope

HIA Core v1 should be a single typed SSA control-flow graph that contains
both executable scalar computation and resource transitions. Resource IR
must stop being an independent approximation beside a numerical AST backend:
the same graph must be verified and consumed by native lowering. Each typed
operation is either executable or an explicitly checked compile-time token.
An unknown field, opcode, region, effect, ABI or proof claim is an error.

### Types and identities

- Value: fixed width scalar, float, enum, aggregate, or explicitly typed raw
  pointer with no implicit safety or provenance.
- Place: an addressable storage identity with base allocation, path,
  initialization state, alignment, layout and provenance class.
- Own: exactly one owning resource capability for a Place or composite value.
  Copy requires a proven Copy type; no default owner cloning.
- Loan: a shared or unique permission derived from a live owner or parent
  loan, tied to a region in the control-flow graph and a precise place path.
- Memory/effect token: explicit sequencing for aliased reads/writes, atomics,
  foreign effects and externally observable operations. Token erasure is
  permitted only after the backend preserves the operational order.
- External capability: separate authority for allocator, runtime thread,
  unsafe foreign call, MMIO, DMA or device access; not mintable by integer cast.

### Minimal required operations

1. **Control:** block arguments, conditional/unconditional branch, switch,
   normal return, trap and explicit exceptional/error edge where supported.
   All successors and phi-like block arguments must be type checked and
   resource-state consistent, including backedges and early returns.
2. **Numerics:** typed checked/wrapping arithmetic and explicit conversion,
   with exact defined trap/overflow/NaN semantics. No unjustified fast-math.
3. **Allocation:** allocate/try_allocate/free with matching allocation
   identity, layout/size/alignment and allocator capability. No unrecorded
   allocations can satisfy a static zero-allocation contract.
4. **Ownership:** move, field extraction/reinsertion, pack/unpack, drop and
   transfer to return/call. Every owned leaf on every reachable normal exit
   is exactly accounted for. Abort, termination and process death are not
   disguised as eventual Drop proofs.
5. **Borrows:** shared/unique begin, reborrow, end and return provenance.
   Overlapping mutable accesses reject; no move/drop while a conflicting
   loan is alive. Cross-block loans are checked by an explicit dataflow
   verifier, not an AST-local lexical heuristic.
6. **Memory:** load/store/init/unaligned variants, checked access extent,
   definite initialization and provenance. Raw pointers remain unsafe
   until all external validity preconditions are discharged.
7. **Concurrency:** atomic and fence operations with target-valid memory
   order; spawn/join/structured cancellation with moved capability states.
   A resource graph alone cannot prove fairness, progress or deadlock freedom.
8. **Foreign/target:** exact C ABI by-value shapes and exception policy;
   C++ ABI only under a target-specific, compiler/toolchain-qualified profile.
   MMIO/DMA requires separately typed device/region capability and platform
   coherence contracts, not an arbitrary integer-to-pointer conversion.

### Ownership state model

A verifier should track initialized places, active loans, owning leaves and
control-flow edge obligations. Place disjointness requires an explicit proof
using field/index projections and known alias relations. CFG joins may combine
states only if resource alternatives are represented explicitly and neither
edge can duplicate an owner. Drop/unwind behavior and fallible construction
must be verified across *all modeled exits*, including error edges. Generic
instantiation and target layouts must preserve these constraints.

A source to Core transformation must carry canonical project identity,
checked type/effect/resource contract identity and complete external
obligation inventory. An IR hash alone proves no correspondence to the source.
An independent verifier checks the graph, then the native backend consumes
exactly those verified value/resource operations. A backend must not regenerate
numerical semantics from a different AST interpreter while claiming Core
consumption.

## Minimal P1/P2 closure tests

P1: positive and adversarial programs for double move/drop, use after move,
conflicting mutable borrow, disjoint field loans, returned borrow lifetime,
branch/loop owner phi, fallible constructor cleanup, safe/unsafe pointer
origin, checked bounds, transitive effects and forged resource budgets.
Verify both structural coverage and value semantics against the fixed
source profile. Require deterministic source-bound witness IDs and clear
false claims for unproved translation soundness.

P2: (a) run the same source through pinned Rust reference and a separate
LLVM backend generated exclusively from verified HIA Core; (b) compare actual
return values, memory effects, traps, allocator-failure cleanup and ABI
calls over frozen finite corpora; (c) test negative native IR/backend
miscompilation controls and mismatch rejection before publication; and
(d) run representative x86-64 and AArch64 host/target executions where
possible. No cross-target physical execution claim from ELF headers alone.

## Integration sequencing

- Keep the existing hepta.semantic_ir canonical producer and version it
  instead of creating a second parser or conflicting HSIR v0 schema.
- Evolve Resource IR and scalar SSA with a reviewed lossless mapping for
  supported values, lifetime edges and effects. Reject unsupported constructs.
- Switch scalar and owned LLVM emitters to consume the one verified operational
  IR before removing direct AST interpretation; retain Rust as a reference.
- Only after the above publish new C/C++ migration levels, AI IR patch
  transactions, target ABI profiles and formal refinement claims.

This design does not satisfy P1/P2 until implemented and actually executed.
whole_project_blockers_closed=false.
