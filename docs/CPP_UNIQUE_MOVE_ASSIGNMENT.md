# Captured unique-array move assignment across translation units

The separate `cpp20-captured-unique-byte-array-move-assignment-v1` profile adds
replacement of an already-live owner to the captured default-deleter array
profile. Its Python entry points are `lower_unique_assignment_project` and
`lower_unique_assignment_matrix` in `hepta.cpp_unique_project`. The previous
`lower_unique_project`, `lower_unique_matrix`, and composed-owner routes keep
their original contracts and continue to require deleted move assignment.

## Source contract and lowering

The complete leaf AST must match a compiler-owned `OwnedBytes` contract. Its
move assignment is `noexcept`, checks `this != &other`, move-assigns the real
`std::unique_ptr<unsigned char[]>`, transfers the extent, clears the source
extent, and returns `*this`. The actual toolchain's default-deleter standard
library remains a trusted, captured dependency. The composite declares its
move assignment `noexcept = default`; custom composite assignment bodies do
not enter this profile.

An accepted assignment is one complete top-level lifecycle statement with an
explicit rvalue cast. Both operands must resolve to complete live local owners
or by-value owner parameters. These bindings cannot alias through references,
subobjects or escaped pointers. A literal self move keeps the entire owner
state unchanged, as required by the exact leaf guard. A distinct-source move
consumes the source. Subsequent source observations, repeated moves, and
assignment into a previously consumed destination are rejected.

The HIA implementation consumes the old destination, drops its fields **in
declaration order**, then returns the consumed source as a fresh destination
binding. This preserves the actual defaulted assignment's release order.
Ordinary destruction continues to release fields in reverse declaration
order. All generated paths go through the existing checked source lowering and
standalone Core resource verifier; a live linear slot is never overwritten.
Each source local retains its original lexical cleanup position despite its
fresh generated binding. No original C++ object is linked into the HIA target.

Assignments nested in conditional or explicit block scopes are rejected. Such
assignments would need explicit branch-merge support for changed resource
bindings. Copy assignment, chained assignment expressions, method-body owner
replacement, arbitrary lvalue/rvalue casts, `reset`, `release`, custom deleters,
and raw-pointer adoption are also rejected. This extension does not claim a
general C++ move-assignment theorem or preserve C++ class/mangled/exception ABI.

## Complete declaration and source accounting

The profile retains the original full-stream Clang capture, bounds, dependency
hashes, macro-sensitive standard-header comparison, cross-unit definition
checks, and disposition census. It adds explicit dispositions for the checked
leaf assignment and defaulted composite assignment parameter. Every captured
active declaration still requires a disposition.

Project function implementation migration, foreign bridge count, standard
library bodies translated, general source equivalence proofs and performance
comparison remain separate fields. A large `<memory>` declaration census does
not count as migrated standard-library implementations or a source-equivalence
proof. The report's `native_execution_qualified` stays false until a distinct
native qualification is actually performed; serialized reports do not confer
deployment authority.

## Native qualification

`examples/cpp/unique_assignment_project_migration` contains two real C++
translation units and two captured macro configurations. The source constructs
a pair, initializes it, constructs a second pair with reversed sizes, overwrites
the second pair by move assignment, performs a self move, and transfers the
result by value to a separately compiled consumer. That consumer self-moves its
parameter before an early return or final move/read.

`tools/qualify_cpp_unique_assignment_project.py` builds the original C++ objects
and the independently generated HIA object. Both consume the same deterministic
case table and an independent Python value/resource oracle. Cases exercise
zero extents, byte boundaries, source constructor rejection, each of four
possible allocation refusals, partial destination construction, early returns,
replacement of nonempty fields, self move and cross-unit consumption. The
instrumented native harness checks allocation identities, sizes, exact release
order, values, refusals and final live count.

Two distinct negative controls have different meanings:

- Removing an actual linear Core drop must be rejected before an artifact is
  published.
- Reversing only the assignment helper's two destination drops keeps resources
  balanced but changes observable cleanup order. The deliberately mutated
  fixture must execute and fail the independent lifecycle oracle. Its binary is
  retained as a negative-control artifact, never labeled as a verified source
  migration.

The second control demonstrates why resource balance alone is insufficient for
source behavior. The qualified migration still relies on its exact checked
source profile and independent native observations. It does not claim a formal
end-to-end proof of arbitrary C++ source refinement.

```sh
python3 tools/qualify_cpp_unique_assignment_project.py \
  --workdir /tmp/hepta-unique-assignment-new-run \
  --clang /path/to/clang-20 --clangxx /path/to/clang++-20
```

Use a new output directory for each run. The qualifier retains actual source
bindings, compiler arguments, independent case expectations, Core/native
artifacts, observations, refusals, capture/declaration receipts and measured
costs. Migration time is contained within qualification time; they must not be
added together. Process/report/archive overhead outside the recorded timers
and human engineering costs remain separately unmeasured. This is a finite
value/lifecycle qualification, not a performance or low-migration-cost claim.
