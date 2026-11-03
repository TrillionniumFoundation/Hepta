# Canonical native-array storage experiment

Isolated handwritten C prototype following draft #616. Not a Hepta compiler
implementation, foreign-ABI admission, lifetime verifier or production runtime.
The source lives only under experiments; no emitter/checker/header is changed.

## Representation invariants

`NativeRow` is `int32_t[3]`; `NativePlane` is a true array of two native rows.
Every traversed row/plane pointer addresses those objects, never an array of
wrapper structs. `RowValue` and `PlaneValue` are assignable value wrappers with
native-array payloads. All load/store copying uses the exact payload type/size,
not wrapper size, assumed padding, layout coincidence or wrapper-pointer casts.
Nested payloads therefore remain genuine arrays rather than wrapper arrays.

Mutable native pointers and aliases retain identity through helpers. There is
no copy-in/copy-out scope, `restrict`, hidden ownership transfer, allocation in
the helpers, retained pointer or automatic lifetime extension. Pointer-to-pointer
rebinding writes through the original slot. Loaded values remain independent
copies, and later changes to a stored value do not change target storage.

The caller must provide initialized live aligned objects, valid index/extent,
permission to write, and freedom from concurrent data races. Returned pointers
remain borrowed from the caller; the experiment does not validate those duties.
Only nonzero i32 rows/planes are implemented. No volatile, atomic, zero-sized,
recursive, generic, resource-containing or public record ABI claim is made.

C11 qualification conversions for pointers to arrays are not generally the
implicit conversions available in C23. Read-only views use explicit conversions
at the correctly typed native-array layer; no const removal or `T **` to
`const T **` cast is used. Negative controls preserve this distinction.

An allocated-storage case copies from a declared `NativePlane` payload into
suitably sized malloc storage before reading it. The effective-type argument
is tied to that exact source object, not an arbitrary wrapper copy or a general
claim that memcpy makes all aliasing legal. The pointer is freed only after its
last use; no lifetime escape is tested or allowed.

## Evidence and scope

Run:

    python -m unittest discover -s tests -p test_c_native_array_storage_experiment.py -v

Separate actual C caller/callee objects are compiled and linked at GCC O0/O3
with strict C11, strict aliasing, warnings-as-errors and UBSan. Tests exercise
row and plane stride, copied snapshots, immediately visible overlapping aliases,
returned pointer identity, pointer-slot rebinding, genuine const storage, nested
payload updates and initialized allocated storage. Four separately compiled
negative callers refuse const stores, incompatible nested qualification on
rebinding a slot containing a pointer to const rows, wrapper
pointers and arrays of wrappers at native-pointer boundaries. Two wrong-helper
controls (no-op store and no-op rebinding) must compile successfully and then
terminate specifically with assertion SIGABRT at both optimization levels;
arbitrary compiler errors or unrelated process failures do not count.

This establishes finite local C representation behavior, not end-to-end Hepta
source lowering or a proof of the C memory model. UBSan does not generally detect
all effective-type violations. The existing #616 design controls and #591
public rejection remain unchanged. Rust/AArch64 execution and integration into
all internal array value paths are still required before any production change.

## Still blocking production admission

The production emitter's nested arrays contain wrapper elements. Replacing that
layout affects literals, indexing, projections, `ptr_read`/`ptr_mut`, copies,
casts, generic instances, returned values and transitive record fields. This
prototype does not establish those lowering/refinement invariants or the
resource/borrow graph correspondence. An implementation must first preserve the
existing closed ABI while changing that representation coherently and proving
its finite test matrix. A correct standalone storage helper is not permission
to bypass those missing invariants or expose private wrappers publicly.
