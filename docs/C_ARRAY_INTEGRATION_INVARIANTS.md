# Canonical array integration: required invariants and counterexamples

Design only, based on #617 `17ff778a85b2f3342f0feafeb555e0fc61e84eb6`.
No production compiler, ABI admission, resource gate or workflow change.
The handwritten C prototype proves neither complete Hepta lowering nor safe
lifetimes. This document is a review checklist, not a theorem or implementation.

## Existing boundaries measured, not inferred

Relevant production sites are `CEmitter.typ`, `sequence`, `place`, `value`,
`parameter`, `signature` and `call` in `hepta/c_backend.py`; pointer builtins in
`hepta/checker.py`; `_Types.add` and builtin lowering in
`hepta/resource_lowering.py`; and `c_decl`/`emit_header` in `hepta/backend.py`.

- Internal nested arrays currently contain **wrapper-valued elements**. Raw
  pointers produced by `ptr_read`/`ptr_mut` target those elements. Public headers
  instead declare pointers to real C arrays, and C emission rejects them.
- The frontend checks unsafe context, pointer/value types, declared effects and
  mutable versus const access. That is not a raw-pointer lifetime proof.
- A static-only checked function can return a raw row pointer obtained from its
  own local nested array, and C source emission succeeds. Its returned pointer
  would outlive the array. The new test records this existing unsafe boundary
  but deliberately never compiles or invokes the function. It is not a request
  to preserve this acceptance forever; a future explicit lifetime policy should
  replace this witness with the new documented diagnostic.
- Direct resource lowering of that source rejects raw-pointer semantics. Adding
  a generic identity call to a raw-row read activates the independent C resource
  gate and produces `E_C_RESOURCE_IR` wrapping `E_RIR_LOWER_UNSUPPORTED`.
  Existing resource exclusion must not be bypassed by relabeling raw pointers as
  scalar values, omitting functions, or using the C prototype as a certificate.

## Integration invariants

### 1. Shape and representation are total over the admitted type graph

Define separate storage and value mappings for each supported concrete type.
For arrays, storage is an actual C array of recursively canonical storage, while
an assignable value contains exactly that native payload. A nested array cannot
remain an array of value wrappers when a raw pointer views it as a native array.

The mapping must cover every reachable type, including locals, fields, generic
substitutions, slice elements, raw-pointer targets, function arguments/returns,
cast targets and pointer-bearing records. Unsupported shapes must fail before
emission rather than acquire an implicit representation based on usage context.
Keep this first integration scalar-leaf/nonzero and retain explicit exclusions.

### 2. Places identify original objects and typed subobjects

A source place must retain one storage identity across indexing, field
projection, borrows and raw-pointer creation. Reads may form independent value
copies; acquiring an address must not silently create a temporary copy.
Maintain extents at each rank: a pointer to one row advances by a complete row;
a pointer to a plane advances by a complete plane. No fabricated array object,
flattened pointer arithmetic across unrelated objects or wrapper-pointer cast.

Raw-pointer extraction from an array-valued field must address the field's
native payload inside the original containing object. It must not point into a
new by-value wrapper returned by a projection helper. This is especially critical
when a raw pointer passes through several internal function boundaries.

### 3. Load/store preserve value semantics without changing storage type

A load yields an independent value snapshot. A store copies the value payload
into existing target storage, with immediate visibility through permitted
aliases. Copies use canonical payload type/size, not wrapper size or padding.
For storage without declared type, the source object of a memcpy also determines
the effective-type argument. Do not copy an enclosing wrapper and then access
the destination as a native array. No UB-based test is evidence for this rule.

### 4. Calls compose the same representation, in both directions

Public declarations, definitions, extern calls and exported entry bodies must
agree, including nested const qualifiers, return declarators and record fields.
Internal helpers must use the same raw-pointer target representation. Foreign
pointer identity, alias observations and pointer-slot rebinding must survive
forwarding through helper chains. Do not expose private value wrappers as a
public aggregate ABI merely because their size happens to match.

By-value array values may remain private wrappers; converting them at calls is
not permission to convert raw-pointer arguments into copy-in/copy-out buffers.
Compile generated headers together with definitions as well as link independent
translation units: ordinary linking alone does not check C type compatibility.

### 5. Compiler-created storage cannot shorten source-valid lifetimes

A representation rewrite must not introduce new dangling pointers in executions
whose original unsafe obligations are satisfied. Values copied into temporary
storage have only that temporary's lifetime. Returning, storing, or passing its
address to a retaining foreign callee does not extend that lifetime.

The current language's unsafe raw pointers still require caller-established
lifetime, initialization, alignment, extent, mutability and race-freedom duties.
Do not advertise the mapping as verifying these duties, silently impose a new
"callee never retains" restriction, or infer non-escape from parameter mode.
If a future bounded profile prohibits escapes, enforce and document it explicitly
at each return, field store, pointer-slot write and extern call; unknown foreign
retention cannot be proven absent from a header alone.

### 6. Pointer slots, aliases and constness retain every layer

`raw mut raw mut [i32;3]` permits modifying a slot containing a mutable row
pointer; a slot containing a pointer to const rows is a different type. Preserve
both the original slot address and qualifiers at every depth. Copying the slot
value into a local variable and forwarding its address loses rebinding effects.
No implicit `T **` to `const T **`, cast-away-const, restrict assumption or new
alias exclusion. C11 pointer-to-array qualification requires deliberate audited
conversion rules, not indiscriminate casts to silence incompatible declarations.

### 7. Evaluation, traps and effects are preserved

Pointer, index and value evaluation must occur once in source order. Existing
rejection of effectful nested raw-store operands/index expressions remains.
Array indexing bounds/traps, short-circuit behavior, integer semantics and
private value copies must remain unchanged. Canonical representation alone
adds no raw-pointer bounds check and grants no permission to remove one.

### 8. Resource and lifetime authority is unchanged

Raw-pointer operations have no current resource transition model. Preserve the
existing gate for all profiles that require it, including unused generic bodies,
owned values and stored/returned views. Do not erase raw operations from the
graph, reclassify them as pure scalar copies or introduce an implicit loan end.

Any later resource integration needs explicit provenance/origin, live storage,
alias capabilities, transfer/drop and invalidation semantics, plus independently
checked transitions for raw load/store, extraction, escape and foreign calls.
Whole-program refinement from those transitions to emitted native operations is
still a separate obligation. A source branch excluded today cannot be admitted
merely because a standalone C helper passes UBSan.

### 9. Ownership, cleanup and foreign retention remain explicit

A pointer is not an owner. Copies/rebindings must not allocate, free, drop or
transfer ownership implicitly. Caller-owned heap storage remains live through
all uses and is freed by its established owner. If a pointer can survive an owner
move/drop or an external call can retain it, those conditions require an explicit
contract or a separately supported verification rule. This experiment provides
neither, and must not quietly claim owner/borrow interoperability.

### 10. Admission and evidence fail closed by shape and profile

Maintain recursive public rejection until each admitted shape has complete
storage/value/call lowering. Direct-row success does not cover nested arrays,
pointer-to-pointer arguments, pointer-bearing records, borrowed returns or
resource-gated programs. Keep zero-sized/volatile/unsupported layouts rejected.
Require native correctness evidence per shape/profile rather than marking all
array pointers supported after one direct scalar-row demonstration.

## Safe executable counterexamples

`experiments/c_array_integration/counterexamples.c` uses #617's genuine native
storage and live objects to disprove three tempting bridges:

1. Copy-in/copy-out changes a callee's observation through an alias: direct
   mutation observes 77 immediately; a scratch mutation sees the original 1,
   even though copy-out later leaves the original storage containing 77.
2. Copying a pointer slot before calling a rebinding helper leaves the caller's
   slot unchanged, unlike forwarding the original slot.
3. A returned-pointer identity observation inside the callee boundary differs
   when a temporary payload replaces original storage. The comparison happens
   while the temporary is alive; no pointer to expired storage is executed.

An additional actual Hepta-to-C execution control preserves the existing internal
wrapper profile: a raw row pointer extracted from a nested-array struct field
passes through two helpers, writes the original field, and leaves an earlier
loaded snapshot independent. It runs at O0/O3 with UBSan and uses no public ABI.
This is a migration regression obligation, not canonical-storage integration.

The static-only unsafe escape witness complements these dynamic counterexamples.
It demonstrates absent lifetime verification, not a runtime failure. All actual
native tests avoid dangling dereferences/comparisons, uninitialized reads and
intentional aliasing UB. Successful detection of the defined-behavior semantic
mismatches is evidence against the proposed bad strategies, not proof of a
complete safe alternative.

## Required implementation order and current blocker

First, design and test a closed-ABI representation refactor covering nested
literals, field/index projections, internal array values/copies/calls and raw
pointer creation/load/store/casts coherently. Preserve existing ordinary ABI,
source order/traps and resource refusals. Compare against real Rust where its
profile applies and all existing independent C controls.

Only then admit one explicitly bounded direct-row extern/export shape with real
Hepta-generated implementation and genuine C callers/callees, pointer returns,
internal forwarding, aliases and lifetime-valid escapes. Retain rejection for
all transitive shapes not yet mapped. Qualify x86-64/AArch64 exact heads before
claiming those hosts, without converting local missing-toolchain tests to passes.

**Current blocker:** no implemented total canonical mapping or compiler-to-native
place/lifetime/resource correspondence exists. #617 only exercises hand-written
C helpers; this document and its counterexamples do not close those obligations.
Production admission remains blocked. No limits, unsafe contracts, resource
semantics or ABI guards are weakened by this deliverable.

Reproduce the new controls:

    python -m unittest discover -s tests -p test_c_array_integration_design.py -v

The two admission controls are Python/static only; the C counterexamples actually
compile separate objects and run at O0/O3 under strict C11, strict aliasing,
warnings-as-errors and UBSan on the local Linux x86-64 GCC host. No Rust or ARM
result is implied.
