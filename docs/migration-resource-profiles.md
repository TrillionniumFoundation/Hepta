# Bounded migration of two independent upstream components

This extension adds a real SQLite codec component to the existing real
Microsoft GSL final-action component and expands supported cleanup callbacks.
It does not claim automatic whole-library C/C++ migration or Rust-equivalent
language safety. Native evidence and source identities are separate from
formal source-equivalence proofs, which this work does not provide.

## New supported semantics

C project slice contracts accept fixed positive extents from 1 through
65,536. Both the safe-core length check and generated ABI bridge preserve
the actual extent, including the inherited record-view bridge. Zero,
negative, Boolean and oversized extents reject. SQLite's complete original
four-byte read/write functions are selected with portable preprocessor
flags and a four-byte caller contract.

The C importer admits a signed shift only when an interval calculation
establishes a nonnegative left operand, an exact legal shift count, and a
representable signed left-shift result. It emits an unsigned shift and a
value-preserving cast back, recording operand and result intervals. It
does not infer arithmetic bounds or use a narrowing cast as a proof.
Potentially negative right shifts, dynamic counts and signed overflow
remain rejected. This is a deliberately small interval rule, not a general
abstract interpreter.

The GSL importer now translates scalar const locals, bitwise operations,
pure Boolean conditions and bounded nested if/else in synchronous callbacks.
Local reads bind to captured Clang declaration IDs; lexical scopes are
preserved. Traversal has explicit depth and statement budgets. Static local
storage, pointer rebinding, callback early returns and loops reject.
GSL's actual final_action constructor, move, destructor and finally factory
remain source-captured and checked for the admitted pattern. Callback AST
capture now uses the existing bounded Clang subprocess-output collector.

## What is automatic and what remains authored

| Area | Automatic in this profile | Explicitly outside the result |
| --- | --- | --- |
| SQLite | Two exact complete codec functions per version, fixed slice contracts, bounded promoted-byte shifts | Rest of SQLite, alternate preprocessor paths, arbitrary raw-pointer validity, execution of Rust ABI bridge |
| GSL | Captured admitted class/factory bodies and two newly supported callback shapes | Automatically porting the surrounding C++ client, arbitrary exceptions/ABI, async callbacks, escaping captures, real allocator or file-descriptor callbacks |
| Integration | Hepta checking, independently checked HIA, direct LLVM native build | Authored Hepta client, scalar C harness, Python oracle, contract selection |

Original GSL reference execution crosses separately compiled entry,
consume and callback translation units. The target uses an explicitly
authored Hepta client around the automatically imported component. Cleanup
order, move deactivation and the selected exception outcomes are compared
against both the original program and a separate Python model; this does
not establish general C++ exception translation.

The SQLite denominator is 2 selected candidate functions per version. GSL
reports captured method/factory/statement counts rather than a percentage
of the library. Manual engineering time and agent token cost are unknown.
The runner measures migration plus target preparation time and every native
command time. None of those setup measurements are a runtime performance
comparison. Remaining upstream code, original and target trusted runtimes,
and authored integration sizes are recorded separately.

## Reproduction and negative controls

```sh
HEPTA_CLANG=/path/to/clang python -m unittest tests.test_c_fixed_slice_shift tests.test_cpp_gsl_branching_callback tests.test_cpp_gsl_final_action -v
python tools/qualify_migration_resource_profiles.py --clang /path/to/clang --output /tmp/hepta-migration-fresh
```

The native runner compiles original C with GCC and original C++ with G++;
the target is checked Hepta lowered through independently verified HIA to
LLVM and linked with a scalar C harness. Target objects never link original
component objects. Both native sides must agree with a separate oracle.
The bounded corpus covers every byte value in every codec byte position,
complemented values, seeded random cases, boundary values and GSL lifecycle
modes. The runner retains exact source/compiler identities and raw results.

Negative controls include invalid fixed extents, signed-shift overflow and
width, a safe-core short buffer that terminates before reading, unsupported
callback constructs, and a wrong-but-typed shift that still compiles but
must fail the semantic oracle. Finite differential observations do not
prove equivalence on every input.

## Related P3 audit chain

PRs #424–429 address the separate strict-scalar `c_migrate` path: source
freshness, bounded initial and repeated reads, subprocess-output capture,
AST nesting and breadth. This extension uses project-capture verification
and bounds the GSL capture path; it does not transplant the chain or reuse
its CI results as evidence for these new paths. Integration and independent
regression of that chain remain the responsibility of the aggregate change.
Immutability against noncooperative concurrent writers, whole-process RAM,
Clang child resources and arbitrary filesystem races are not guaranteed by
a last-moment identity check or a bounded output collector.
