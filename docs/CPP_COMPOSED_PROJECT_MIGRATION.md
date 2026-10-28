# Captured C++ ownership transfer across compilation units

`hepta.cpp_composed_project.lower_composed_matrix` now captures a declared build
matrix and translates a complete, narrow C++ ownership project into standalone
HIA. It extends the existing composed-owner source translator with actual
by-value calls between separately defined functions in different translation
units. The generated target contains the new implementation of the constructors,
move operations, borrows, scalar algorithm, early returns and destruction; it
contains no original C++ object or call to an original C++ implementation.

## Concrete supported project

The checked fixture is `examples/cpp/composed_project_migration`. `owners.h`
defines the existing complete `OwnedBytes` protocol and a `PairedBytes` owner
with two byte buffers. `entry.cpp` allocates and initializes the pair, moves it
to another local, and transfers that complete owner by value to `consume.cpp`.
The consumer can return early, reject an index, move its parameter to another
local, or borrow the fields for its calculation. Every path destroys the live
resources exactly once in reverse construction order. Allocation refusal and
exceptions during partial construction still clean up the successfully
constructed fields.

The compilation database has four commands: two source units in each of two
macro configurations. The configurations change both the initialization mask
and the arithmetic weight. They are captured, translated, compiled and executed
separately; one successful configuration does not attest to another.

The capture binds actual compiler identity, ordered frontend arguments, macro
environment and local dependencies. Translation checks the complete class ASTs
for consistent definitions within a configuration, binds free functions by
actual Clang symbol/signature identities, resolves every forward declaration to
a captured definition, and rejects a missing or duplicate implementation. Each
active declaration in every captured translation unit has its own disposition.
Header copies are accounted for as declarations bound to the same checked
implementation. Compiler-generated declarations are listed separately. The
result includes no `unconverted_declarations` and cannot succeed by silently
omitting an unsupported active declaration.

## Boundaries that reject

The accepted cross-unit parameter is one complete composite owner, first in the
parameter list, passed by value through the checked move constructor. Other
arguments must be scalars and must not observe the moving owner. Ownership calls
must occupy a complete sequenced value expression. Nested calls in arithmetic
and calls whose other arguments inspect the moving owner reject because the
C++ argument-order rules would otherwise permit unmodeled sequencing.

The current project profile requires one scalar lifecycle entry, one to eight
by-value owner consumers, and implementations in at least two translation
units. It retains the existing exact leaf allocation/move/destruction protocol.
It does not support arbitrary containers, custom allocators, inheritance,
virtual dispatch, `shared_ptr`, arbitrary reference aliases or pointer escapes.
Other active project declarations, foreign/system declarations, mismatched
class definitions, unresolved functions, attributes and defaults reject.
Unlisted build variants have no qualification.

This is source migration. The externally observed scalar C wrapper ABI is
preserved on the qualified Linux LP64 target. Original C++ object layouts,
mangled symbols, binary exception ABI and arbitrary C++ binary compatibility
are not preserved. Compatibility with an existing C++ binary would require an
explicit reviewed boundary outside this profile.

## Real native qualification

Run:

```sh
python3 tools/qualify_cpp_composed_project.py --workdir /tmp/new-cpp-project-run \
  --clang /path/to/clang-20 --clangxx /path/to/clang++-20 --cc gcc
```

For each configuration the tool builds `entry.cpp`, `consume.cpp` and a scalar
wrapper into separate C++ objects and links those only into the reference
binary. It independently lowers the migrated Hepta source to a standalone Core
document, invokes the standalone HIA native compiler, inspects the target object
symbol inventory and links only that object with the C observation harness.
The original C++ object paths never enter the translated target command.

The qualification executes 437 cases per configuration. An independent integer
and allocation model checks the return value, allocation/refusal counts, every
allocation identity/size, release order, total frees and final live allocation
count. It exercises zero-length buffers, boundary indices, move/early-return
paths, each partial-construction failure and each actual allocator refusal.
The initial successful execution observed 401 allocations, 401 frees, 196
refusals and zero live allocations in each configuration. The two configurations
have distinct result digests. A deliberately omitted linear `owner.drop` in
actual generated Core rejects before target publication.

`tests/test_cpp_composed_project.py` also checks moved-from use in the remote
consumer, unsequenced move/observation arguments, active unsupported declarations,
missing definitions, cross-unit class disagreement, forward attributes and an
omitted matrix configuration. These are rejection controls, not supported
source features.

Finite native observations and source checking do not constitute a formal proof
of general C++ equivalence. This gate makes no performance or universal memory
safety claim and does not measure portability beyond the executed native target.
