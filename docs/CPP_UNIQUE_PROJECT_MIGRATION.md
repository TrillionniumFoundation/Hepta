# Captured `std::unique_ptr<byte[]>` implementation migration

The `cpp20-captured-unique-byte-array-default-deleter-v1` profile translates a
complete, explicitly checked byte-array owner backed by the actual C++ standard
library. Its two-field composite, algorithms, exception paths and by-value
cross-translation-unit calls are structurally lowered into standalone HIA.
The translated object does not link the original C++ implementation.

The original `cpp-composed-project` profile remains unchanged. The new public
Python entry points are `lower_unique_project` and `lower_unique_matrix` in
`hepta.cpp_unique_project`. The example compilation database contains both
`entry.cpp` and `consume.cpp` under two separately captured macro configurations.

## Accepted ownership contract

`OwnedBytes` stores `std::unique_ptr<unsigned char[]>` with its default deleter
and a size. Its complete Clang AST must match compiler-owned contract source;
renaming the leaf class is allowed, but replacing operations is not. The source
constructs a zero-initialized array, automatically destroys a successfully
constructed field if the leaf constructor throws, transfers ownership with the
actual unique-pointer move constructor, and uses default destruction.

The supported observations are scalar results, owned byte-array allocation identity and size,
allocation failure, normal and exceptional cleanup, and reverse field cleanup
order. The HIA owner has linear move/drop semantics and explicit fallible
construction. Its array views are bounded by the existing checked source/Core
lowering. A source owner cannot be observed after a move. A transfer argument
cannot race an unsequenced observation of the same owner in another argument.

Shared pointers, custom deleters, allocator substitution, `release`, `reset`,
move assignment, pointer escape, virtual dispatch, arbitrary templates, and
C++ object-layout/exception ABI preservation are outside this profile. Such
source changes are rejected instead of receiving an implicit foreign bridge.

A separate [move-assignment profile](CPP_UNIQUE_MOVE_ASSIGNMENT.md) admits a
checked self-move guard, defaulted memberwise assignment and complete sequenced
owner replacement. Its entry points and fixture are separate; this original
profile does not silently broaden its contract.

## Complete capture and the standard-library boundary

Including `<memory>` produces hundreds of megabytes of Clang JSON in the
qualified local toolchain. The separate streaming reader hashes every byte,
parses every complete top-level object, checks the entire JSON envelope and EOF,
and bounds total bytes, JSON values, nesting, individual subtrees and wall time.
It retains project AST nodes and a complete declaration census while releasing
each processed system subtree. A truncated stream, unknown outer field,
duplicate JSON field, malformed value, timeout or budget exhaustion fails
closed. Existing C/C++ capture limits are unchanged.

Every project declaration receives a structural translation, exact leaf
contract, bound forward declaration, or compiler-implicit disposition. Every
captured standard-library declaration receives the explicit disposition
`standard_library_dependency_not_migrated`, with its unit and AST path. The
`top_level_file` field is the enclosing top-level declaration's origin; it is
not a fabricated exact file location for every nested instantiated declaration.

Two checks bind the trusted library contract. First, the build capture hashes
all compiler-discovered source and header dependencies and verifies them after
translation. Second, it compares expanded system-header content against a fresh
compiler-owned reference using the default toolchain headers. Project include
paths and `-D`/`-U` options are removed from the reference. A project therefore
cannot redefine the library that validates its own wrapper. Macro changes to
standard-library behavior, local template/deleter specializations, uncaptured
inputs and unmodeled declarations reject. Header pragmas remain in the expanded
content comparison. Process-local Clang declaration addresses are replaced with
bound declaration/type/specialization identities; semantic types and operations
remain in the comparison.

Standard-library semantics are an **explicit trusted contract**. The comparison
does not formally verify libstdc++ or libc++, Clang, LLVM, the allocator, the
operating system or hardware. Project implementation migration is separately
counted from dependency inventory. Neither a large census nor successful native
examples establishes general C++ source equivalence.

## Native qualification and cost accounting

`tools/qualify_cpp_unique_project.py` independently builds the original C++
translation units and an observation harness, then builds only generated HIA
plus its C harness. Both consume the same deterministic case table and
independent value/lifecycle oracle. The harness observes actual byte-array allocation
refusals, allocation identities, sizes, destruction order and final live count.
It instruments C++ `new[]`/`delete[]` and the generated HIA allocation calls;
it does not inventory the C++ exception runtime's internal allocations.
The target's object-symbol inventory rejects unaccounted original imports.
A removed linear drop must fail compilation without publishing an object.

The qualifier records migration wall time and qualification wall time through
the final source checks (before serializing the qualification report),
process and child peak RSS, all compiler commands, input and artifact identities,
every declaration disposition and each configuration's actual observation.
Process startup, report serialization, later archive creation and human
engineering time are not included in those two timers. Human engineering time
remains unknown. This is a correctness and finite
lifecycle qualification, not a language-speed comparison or evidence of a
general low migration cost. Its output records whether the actual run passed;
the implementation and tests do not predeclare success.

```sh
python3 tools/qualify_cpp_unique_project.py \
  --workdir /tmp/hepta-unique-new-run \
  --clang /path/to/clang-20 --clangxx /path/to/clang++-20
```

Use a new output directory for each run. Full raw ASTs are not retained;
complete-stream hashes, byte counts, capture arguments, dependency hashes and
the full declaration census are retained. A reviewer can recapture from the
bound inputs. Process-local Clang addresses can change the raw JSON bytes, so a
fresh capture is not promised to reproduce the prior raw hash. The hash records
the exact stream consumed in that invocation; it is not a substitute for the
source checks or native qualification. The prior migration/benchmark/Agent
experiment records are not edited by this feature.
