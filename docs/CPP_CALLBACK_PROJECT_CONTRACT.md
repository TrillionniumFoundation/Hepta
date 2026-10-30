# Captured C++ synchronous borrowed callback migration

## Scope and acceptance

`hepta.cpp_callback_project` adds profile
`cpp20-captured-unique-owner-synchronous-borrowed-callback-v1` on top of the
existing captured default-deleter unique byte-array owner profile. The example
is `examples/cpp/callback_project_migration/`.

The source component has two translation units, a complete shared owner header,
and three implemented free functions. The entry constructs and fills two owned
byte arrays, moves their composite into a separately compiled consumer, and
passes an actual C++ function pointer. The consumer synchronously calls that
pointer with a const reference to its live owner. The callback returns a value
or an explicit error code. Every exit releases all completed resources.

The migration translates the callback body, consumer body, entry body,
composite algorithms, resource moves and failure cleanup into checked Hepta
source and standalone HIA Core. The migrated native target contains no original
C++ object and no C++ callback thunk. A compiler-owned, freshly checked
`unique_ptr<unsigned char[], default_delete<unsigned char[]>>` leaf contract is
trusted; the implementation of the standard library itself is not migrated.

Only a **closed** callback binding is supported. The importer verifies one
function-pointer argument against one complete captured callback definition,
then specializes the consumer to a direct HIA call. This does not claim support
for general function pointers, dynamically loaded callbacks, closures, stored
references, asynchronous callbacks, reentrancy, custom deleters or arbitrary
C++ RAII. Unmodeled declarations and operations reject the whole input.

## Resource and event contract

| Event/path | Value behavior | Ownership behavior |
| --- | --- | --- |
| Construction | Initialize left then right; zero length uses no allocation | Each successful nonzero allocation creates one unique owner |
| Allocation refusal | Return `1001` | Unwind previously completed fields in reverse initialization order |
| Leaf constructor rejection | Return `1002` | Release that leaf's allocation, then preceding completed fields |
| Composite constructor rejection | Return `1003` | Release right then left |
| Cancel before cross-unit move | Return `2001` | Destroy the entry's live owner |
| Cancel after cross-unit move | Return `2002` | Destroy the consumer's live owner |
| Index outside both-array limit | Return `2003` | Do not call the callback; destroy the consumer's owner |
| Callback error | Return `4001` | End the read loan, then destroy the consumer's owner |
| Successful callback | Return the source-derived weighted byte score | End the read loan, then release right then left |

The callback type is exactly:

```cpp
unsigned long long (*)(const PairedBytes&, unsigned long, bool) noexcept
```

The callback may only read the whole borrowed owner through admitted const
methods and compute scalar expressions. It cannot mutate, move, return or
store that borrow. Its consumer makes exactly one syntactic callback call on
the selected success/error path. The pointer is neither returned nor saved.
The callback is checked from its source body; its safety is not inferred merely
from the spelling `const` or `noexcept`.

At the Hepta boundary, the owner parameter is `take HeptaComposite` and the
callback parameter is `read HeptaComposite`. The existing source checker and
standalone Core verifier enforce owner consumption and read-loan lifetimes.
The return value is evaluated before any owner cleanup. Cancellation and error
values have no authority to bypass cleanup.

## Source identity and completeness

The importer captures both declared build variants from the actual compilation
database, hashes local/system dependencies, compares the complete leaf AST
against a compiler-owned reference, and checks the macro-expanded standard
headers. Duplicate declarations are mapped to captured mangled definitions;
all active project declarations receive an explicit disposition. Missing
definitions, mismatched headers and unsupported active declarations reject.

The two variants deliberately change the byte score's weight and xor mask.
They are lowered separately. A source mutation affects the generated algorithm;
the composite and callback bodies are not selected by matching an example
string. The bounded leaf protocol remains an explicit trusted contract.

The compiler checks its complete Python-source hash before and after capture.
Concurrent compiler edits therefore reject publication. A qualification run
must use a frozen compiler snapshot or a settled integration tree; evidence
from a temporary frozen snapshot is not evidence for a later modified tree.

## Independent qualification

Run with actual Clang 20+ and C/C++ toolchains:

```bash
python tools/qualify_cpp_callback_project.py \
  --workdir /tmp/new-callback-qualification \
  --clang /path/to/clang --clangxx /path/to/clang++
```

The destination must be new. The report records source/compiler hashes,
tool commands, generated Hepta/Core, original and migrated object identities,
raw native output, allocation/refusal/free traces and performance samples.

An independently written Python oracle derives expected values and resource
events from input cases. A C/C++ harness observes actual allocator calls,
allocation refusal, release order, double or unknown frees, and final live
counts. It is compiled separately for the original C++ component and the HIA
object. The test matrix includes zero length, unequal lengths, byte extremes,
in/out-of-range indices, all constructor failures, both cancellations, callback
error and allocation refusal at each possible attempt.

Negative controls have separate meanings:

- Removing a Core owner drop must fail resource verification before object
  publication.
- Reversing two complete-owner releases remains resource-safe but must fail
  the independent native event oracle.
- Changing the callback error or cancellation result remains resource-safe
  but must fail the independent native value oracle.
- Null callback binding, borrowed-reference escape, mutation through a cast,
  observation of a moved-from owner, repeated callback execution and omitted
  callback definition must reject source migration.

These controls distinguish resource correctness from source semantics. Native
differential agreement on the declared cases is not a formal equivalence proof
for all inputs, and the reports explicitly retain that limitation.

## Coverage and costs

Coverage counts implementation definitions, inventoried declarations and
remaining foreign/trusted boundaries separately. All three component free
function definitions are migrated; no original C++ function is counted as a
migrated implementation merely because it has a bridge. Standard-library body
coverage and general C++ coverage are not inferred from this small profile.

The qualifier records measured migration/qualification wall time, build/link
commands, process peak RSS, binary size and repeated native loop timing. A
separate allocator-hook run checks live-byte and live-owner high-water marks
against the independent event oracle for every declared case. The performance
benchmark includes both separately compiled `-O3 -fno-lto` C++ and a strong
Clang `-O3 -flto`/LLD C++ baseline. Generated HIA uses `-O3` on one LLVM module;
all three implementations use the same separately compiled C caller and inputs.
Measurement order rotates across implementations; the qualifier checks result
digests and reports success-only and mixed
error/cancellation workloads separately. Runtime allocations, callback work
and cleanup are inside the timed loop. Compiler, capture and verification
costs are reported separately rather than silently amortized away.

Each benchmark also reports a reuse break-even estimate against an already
built LTO C++ baseline. It charges the whole measured two-variant migration
cost, plus that target's actual HIA build/link time, to each scenario; it does
not invent an unmeasured per-variant division. Runtime savings at the measured
call count can therefore be negative after upfront costs even when steady-state
execution is faster. The estimate excludes unobserved human contract work and
cannot guarantee future workload reuse.

This profile itself required implementation and contract work. Automatically
measured tool wall time is not human engineering time: the report leaves
`human_engineering_seconds` null unless externally observed time is supplied.
It claims neither zero-cost migration nor universal speed superiority. Any
runtime speedup must be assessed with the one-time migration/build costs and
the actual number of subsequent invocations.
