# Public fixed-array pointers: design and executable boundary controls

Status: design only. Based on #591 commit
`544fd37ac3fc9682c112be053c4830ddc6a7ff77`. No production emitter, ABI
admission, public header, runtime, or qualification gate is changed.

## Reproduced gap and why a declaration-only fix is unsafe

The frontend and public header generator accept `raw mut [i32;3]`, nested
arrays, nested pointers, and pointer return values. The independent C emitter
refuses these types when reachable from an extern/export signature, including
through record fields. Its private array value is a named C struct with a
`data` array, and its raw pointer points to that struct. The header instead
promises a pointer to a C array. Identical size and alignment do not make those
C types compatible.

`tests/test_c_public_array_abi_design.py` supplies three executable controls:

1. The checked source still fails the actual independent C backend with
   `E_C_BACKEND_SUBSET`, specifically the public-declarator boundary.
2. The actual generated header compiles with separate C caller/callee units at
   GCC O0/O3, strict C11, strict aliasing, warnings-as-errors and UBSan. These
   **C stand-ins**, not Hepta-generated implementations, establish intended
   pointer identity, row/plane stride, mutation visibility, const-input reads,
   pointer returns and pointer-to-pointer rebinding.
3. A wrapper-pointer implementation is rejected for conflicting types when
   compiled against that header, despite size/alignment static assertions.

These are local Linux x86-64 GCC controls only. No Rust execution, AArch64
execution, language memory-model proof or completed public ABI support follows.
UBSan success alone cannot prove the absence of strict-aliasing violations.

## Required representation contract

Separate three concepts explicitly:

- Public C storage types: native C array declarators with exact extents, nesting
  and qualifiers at every pointer layer. Reuse/audit `backend.c_decl`; do not
  invent flat `T *` aliases for `T (*)[N]`.
- Private Hepta value types: assignable wrappers used for locals, return values,
  copies and internal by-value calls. A C array itself is not assignable or a
  legal C function return value.
- Raw-pointer target storage: a single coherent representation throughout the
  function graph, including public entry, internal helper, casts, returned
  pointer, pointer-bearing records and public exit. The same Hepta type must
  not silently switch between native-array and wrapper-pointer representations
  based only on which function currently emits it.

The preferred direction is canonical native-array storage for fixed-array
pointees, with explicit value/storage conversion helpers. This is an emitter
representation change, not a signature-only patch. Before implementation,
resolve the storage representation of nested internal arrays: today outer
arrays contain wrapper-valued elements. Casting those elements to native nested
arrays does not itself create the corresponding C array object or establish
legal pointer arithmetic over it.

An initial scalar-leaf prototype should define native storage typedefs and
assignable value wrappers whose payload is that canonical native storage.
Loads/stores convert at the value boundary without dereferencing a foreign
pointer as a wrapper lvalue. `memcpy` can copy compatible object representations
but cannot be used to assert arbitrary struct/native-array layouts are equal;
prove or statically enforce each admitted layout, and retain full initialization,
alignment, lifetime, extent and mutability obligations at the unsafe edge.
For storage without a declared type, copy from the canonical native payload,
not the enclosing wrapper: the source object also matters to the destination
effective type. Byte copying is not a general effective-type escape hatch.
All internal indexing, array literals, nested copies, `ptr_read`/`ptr_mut`,
raw loads/stores, pointer casts and helper calls must consume the same layout.
Do not perform unaligned typed accesses through a byte-cast workaround.

Extern calls need symmetric argument/result handling. Exported bodies need the
same storage contract, not a temporary copy-in/copy-out bridge. Such bridges
break pointer identity, overlapping aliases, foreign reentrant observation,
pointer escape, returned pointers and writes through pointer-to-pointer arguments.
Even a scalar-row-only first implementation must reject unsupported transitive
shapes explicitly rather than letting private representation escape.

## Narrow staged implementation plan

1. Specify storage/value helpers for nonzero arrays of currently admitted
   fixed-width scalar leaves, preserving all existing internal value tests.
   Audit nested arrays before admission; explicitly retain rejection for them
   if this first stage does not give them canonical storage. Keep public ABI
   admission closed during this representation refactor.
2. Admit direct const/mutable scalar-row pointers at extern/export boundaries
   only after both inbound and outbound real Hepta/C paths work. Include
   internal helper forwarding and pointer returns, not just scalar summaries.
   Keep pointer-to-pointer, record-transitive pointers, nested arrays,
   zero-sized arrays, volatile aggregate accesses and unsupported scalar kinds
   rejected until each has its own completed representation path.
3. Extend individual compound shapes with separate qualification. Qualification
   of direct rows does not imply pointer-to-pointer rebinding or record ABI.
   Generated-header compatibility must be checked in one translation unit as
   well as actual linking across independently compiled units: linkers generally
   cannot diagnose incompatible C declarations.

No pointer ownership or alias guarantee is inferred from an ABI declaration.
There is no new borrow-checking exception, hidden resource-gate bypass or
conversion of foreign unsafe contracts into verified safety.

## Acceptance matrix before widening the boundary

- Genuine C-to-Hepta exports and Hepta-to-C extern calls through the generated
  header, separately compiled, at O0/O3 with strict aliasing and UBSan.
- Native x86-64 and AArch64 under existing pinned-host qualification, plus a
  same-source Rust oracle where supported. Preserve missing-toolchain skips
  locally rather than counting them as execution.
- One row, multiple rows, nonzero row offset, immediate foreign mutation,
  return identity and alias-visible mutation through an internal helper.
- Exact-once ordered evaluation of pointer/index/value operands and unchanged
  effect restrictions; array loads remain independent value copies.
- Mutable-to-const conversions at the proper layer; no writes through const.
- Header-definition compatibility for parameter and return declarators.
- Explicit negative controls for every unsupported transitive shape, zero
  extents, volatile aggregate accesses and const stores.
- All existing internal #591 array-pointer and ordinary scalar/struct ABI
  controls. Broader suite failures must retain their actual reasons.

The independent C backend currently lacks this storage/value distinction.
Keeping the public rejection is the safe outcome of this investigation; the
executable design corpus prepares a bounded implementation without claiming
that a cast or private-wrapper export has closed the gap.
