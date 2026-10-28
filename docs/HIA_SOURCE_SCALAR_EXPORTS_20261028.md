# Preserve source calling conventions in native scalar exports

The standalone source adapter now writes the existing verified `exports`
field into primitive Core v1. It selects that set from the original checked
source declarations, before generic specialization or aggregate scalarization.
Neither the Core schema nor the native public ABI is expanded.

## Concrete failure

A source helper accepting `Packet { word: u64 }` was previously flattened into
one `u64` argument. With no explicit Core export inventory, the LLVM backend
correctly inferred a scalar wrapper from that flattened signature. The source
adapter had lost the fact that this helper used an internal nominal calling
convention. A real Clang shared-library build exposed both `inspect_packet`
and its intended scalar caller `public_identity`.

The same problem applied to an aggregate result, a `read u64` parameter, or a
`mut u64` parameter whose updated value becomes an internal return value.
Concrete generic instances could also acquire native entrypoints after their
template identity disappeared. The composite Core adapter already retained an
explicit export inventory; the source adapter now retains the same boundary.

## Finite rule

An original, non-foreign, non-generic function is a native convenience entry
only when every parameter uses `value` mode and an existing scalar type, and
its value result is scalar or `Unit`. Ordinary scalar helpers without an
explicit `export "C"` marker remain eligible, preserving the established
standalone source and migration behavior.

Nominal records, Results, borrowed/taken parameters, returned loans, and
generated generic instances remain internal even when their primitive layout
happens to contain only scalar slots. Their bodies and internal calls are
still compiled and executable. A module with only such functions has an
explicit empty export list instead of accidentally acquiring scalar wrappers.

The existing Core verifier checks the export names, uniqueness and primitive
types. The inventory survives serialization and independent verification of
the canonical bytes. The existing LLVM emitter and actual ELF scanner use that
verified inventory without another compiler or runtime authority.

The source adapter continues to emit v1 operations. The checked owned-source
bridge continues to demand that same version and repeat its existing source,
Resource IR and Core checks. Primitive v8 returned-loan semantics are unchanged;
this change neither exposes a foreign loan ABI nor claims that all source loan
forms are lowered to v8.

## Regression evidence

`tests/test_hia_source_exports.py` checks original signatures, immutable Core
round trips, concrete generic instances, ordinary scalar/Unit compatibility,
empty export sets and the existing checked owned-source bridge. Its native
control builds a real LLVM shared object, inspects its dynamic symbols with
`nm`, links and executes a C caller for ten scalar calls, and confirms five
internal helper names cannot be found by the loader or linked by C.

These controls qualify this export-boundary correction. They do not establish
C aggregate ABI compatibility, general callbacks, foreign lifetime safety,
source-to-Core refinement, or typed uninitialized memory support.
