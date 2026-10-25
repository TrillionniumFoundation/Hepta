# Selected C++ resource-owner implementation migration

`hepta.cpp_owned_migrate` translates a real exclusive byte-array owner and
its complete lifecycle operation into Hepta ownership operations. The
original class allocates storage with `new[]`, transfers it through a move
constructor and frees it in a nontrivial destructor. The resulting Hepta
code owns `Buffer<u8>` storage, returns fallible construction as `Result`,
uses checked borrows, moves owners and consumes them on every supported
exit. The target programs do not link the original C++ implementation.

This is the closed
`cpp20-exclusive-zeroed-u8-array-move-and-lifecycle-v1` protocol. It is a
real implementation migration for that protocol, with deliberately narrow
recognition. It is not a general C++ parser-to-Hepta translator, an arbitrary
RAII rewrite, a class ABI bridge or a proof of whole-language safety.

## Complete native AST binding

The entire input translation unit must contain one complete owner class
and one lifecycle function. The class contains the two coupled pointer and
extent fields, the selected constructor, move constructor, destructor,
deleted copy/assignment operations and the five selected access methods.
Every class member has an inventory entry. Clang-generated implicit
declarations are also present in the complete AST comparison; they are not
an opening for silently skipped source declarations.

The compiler embeds versioned C++ protocol rules and their Hepta lowering.
It compiles the rules independently with the same native Clang compiler and
compares the complete normalized source AST with the rule AST. Both trees
retain all bodies, operators, literals, casts, qualifiers, exception
handlers and declaration references. The normalizer removes only source
coordinates, opaque node addresses and symbol spelling/ABI metadata that
are replaced by checked declaration identities.

Declaration bindings are assigned before references are normalized. Reading
another same-type variable cannot be hidden by changing its name or by
altering which reference is visited first. Class, field, method, function,
parameter and local renaming are accepted when their identities and bodies
still match. Inserting a statement, changing the destructor, using another
allocation extent, changing a method body or observing a moved-from source
causes a complete rejection. Equivalent but unmodeled source syntax may
also be rejected; this profile does not guess equivalence.

The example files are separate from the compiler-owned rules. Changing an
example's implementation cannot make the compiler automatically accept the
change while retaining an old Hepta body. Before publication, the generated
Hepta source must pass both supported frontend/lowering routes and the
independent resource verifier. Native traits additionally confirm that the
source class is non-copyable, movable without throwing, nontrivially
destructible, and destructible without throwing.

## The resource semantics that are translated

The complete source is
[`owned_bytes.cpp`](../examples/cpp/owned_migration/owned_bytes.cpp). The
checked expected Hepta output is
[`expected.hepta`](../examples/cpp/owned_migration/expected.hepta).

| Source operation | Generated Hepta operation |
| --- | --- |
| Pointer and extent fields with a verified common invariant | `OwnedBytes { data: Buffer<u8> }`; extent comes from `len(data)` |
| Zero-initialized array allocation for nonzero length | `try_buffer(size)` |
| Zero-length construction | Empty `Buffer`; no storage allocation |
| Allocation exception | `Result::Err(1)` |
| Constructor rejects after acquiring storage, explicitly releases and throws `2` | `drop(move bytes)` followed by `Result::Err(2)` |
| Move constructor takes the pointer/extent and resets the source to null/zero | A `take` parameter and `return move owner` |
| Nontrivial array destructor | Consume/drop the owner and its actual buffer storage |
| Const pointer view and extent | A returned `read [u8]` borrow tied to the receiver |
| Fill, indexed read and indexed write | Checked `read`/`mut` access to the owned buffer |

No new language builtin or resource type is introduced. The output uses
the existing `Buffer<u8>`, `Result`, `try_buffer`, `move`, `take`, `read`,
`mut`, `len`, indexing and `drop` operations. No task/runtime resource
clauses are added to this resource-IR profile.

### Whole lifecycle operation

The source `run_owned` function is migrated together with the class. It
constructs the owner, fills it, updates the first byte when present, moves
ownership, handles an early exit, checks the requested index, reads through
a borrowed view and returns a scalar. The generated operation inserts
explicit owner consumption on both early error exits and after computing
the successful result. The constructor's post-allocation error also drops
its resource before returning an error.

These cleanup paths are generated from the completely matched lifecycle
body. They are not manually supplied by a Hepta consumer and then counted
as migrated C++ destruction. The separate consumer fixture only exports a
scalar C ABI wrapper and converts integer flags to the existing internal
Boolean parameters.

### Moved-from and borrowing boundaries

C++ permits observing this class's moved-from null pointer and zero extent.
Hepta consumes the moved source. The accepted lifecycle never observes the
moved-from source; its remaining original C++ destructor only sees null and
does not free storage. A source change that reads the moved-from object is
rejected. The tool does not silently reinterpret an observable empty C++
object as a usable consumed Hepta owner.

The source's pointer view is confined to a checked index read before the
owner leaves scope. The target replaces this with a receiver-tied slice
borrow and ends it before dropping the owner. Escaping the view, retaining
it across a move or adding unmodeled pointer manipulation is rejected.
Source out-of-bounds access is outside the equivalence domain; the accepted
lifecycle explicitly checks the index, and the target also has checked
buffer access.

The source's private pointer representation is replaced, rather than
preserved as a C++ layout or access-control ABI. General legacy callers,
field access rules and arbitrary C++ call sites are not automatically
ported. Allocation functions and the compiler/runtime remain part of the
execution environment; arbitrary external replacements of allocation,
deallocation or `new_handler` behavior are not proved equivalent by this
source protocol.

## Real native qualification

The qualifier compiles the original source and executes it alongside
independently compiled Hepta/Rust and Hepta/C programs. Each program runs
the same 475 input vectors and checks every result against an integer
oracle. Cases include fixed edge conditions, 256 seeded random vectors,
zero-length input, actual allocator refusal, recovery after refusal,
constructor rejection after allocation and both exits after a move.

| Executed case family | Cases per implementation |
| --- | ---: |
| Borrowed read success | 172 |
| Real allocation refusal | 98 |
| Constructor rejection after allocation (or zero-length rejection) | 116 |
| Early return after move | 71 |
| Range error after move | 18 |
| **Total** | **475** |

There are 18 zero-length cases. Every original C++, Hepta/Rust and Hepta/C
run observed **359 successful buffer-storage allocations, 359 releases,
98 actual allocation refusals and zero live buffers after every call**.
The compact observation digest was `76b9c7dcdcefd304` for all three. These
are actual buffer lifecycle observations; they do not count process
startup, report printing or C++ exception-runtime allocations as buffer
storage.

Refusal is injected into the actual allocation path: C++ `operator new[]`,
Rust's global allocator, and C's allocation calls. It is not a flag that
makes the translated function return an error before trying to allocate.
The C harness supports wrapped `calloc` and `malloc` and marks observation
state volatile because the linker applies wrapping after optimization.
This same source fixture and harness can be shared with an independent
native backend using the same existing owner semantics.

The qualifier also removes the actual generated C buffer-release call,
compiles the faulty implementation and executes it. Its first case returns
the expected scalar but records allocation `1`, release `0`, live `1` and
exit code `3`. The release gate therefore cannot mistake a successful
compile or a correct scalar answer for correct resource management.

The executed reference uses Clang 20 to compile both C++ objects with UBSan
and G++/libubsan to link them. The available Clang installation has no
standalone UBSan runtime archives, so both driver identities and all three
commands are recorded. This does not lower the Clang 20 AST/compilation
requirement. Hepta/C uses GCC with UBSan; Hepta/Rust uses the pinned Rust
1.90 toolchain. No original C++ object participates in either Hepta build.

Performance timing is explicitly `not_run`. The observed allocation counts
bound this particular lifecycle workload; they are not a universal speed or
memory-footprint comparison against Rust or C++.

## Reproduce

```sh
python -m hepta.cpp_owned_migrate \
  examples/cpp/owned_migration/owned_bytes.cpp \
  --output /tmp/migrated-owner.hepta --clangxx clang++

python -m tools.validate_cpp_owned \
  --workdir /tmp/owned-qualification \
  --out /tmp/owned-qualification.json \
  --clangxx clang++ --rustc /path/to/pinned/rustc --cc gcc

python -m unittest tests.test_cpp_owned_migrate -v
```

Use Clang 20 or newer on the checked native LP64 host, the repository's
pinned Rust toolchain, and the qualified GCC/G++ installation. Outputs must
be new; the migration output parent must already exist. Source/compiler
changes during the operation reject publication, and existing files or
symlinks are preserved.

Library entrypoints are `migrate_cpp_owned`, `qualify_cpp_owned` and
`tools.validate_cpp_owned.validate_report`. The JSON receipt binds the
complete source and protocol AST, compiler identity, generated Hepta,
resource graph and exact source replay, compiled source plus observation
harness, actual native artifacts, executed paths and deterministic case
denominator. It preserves a compiled-and-executed destructor-leak negative
control. Default validation (`current_inputs=True`) reads the retained
published Hepta and consumer files again. The canonical frontend runs with
`native=False` to regenerate the complete resource graphs, generated Rust/C
implementations and typed semantic identities. These must match the receipt
exactly; a different legal resource graph cannot pass by recomputing all its
hashes and the receipt's own seal. Current compiler and input identities are
checked before and after replay. Missing or changed source files reject
current qualification; this check does not rerun the native executables.

`current_inputs=False` is an explicitly weaker archival inspection of
internal structure and identities. It cannot establish agreement with the
current source and must not be used as a release gate. Neither mode is
cryptographic authentication of arbitrary third-party receipts.

The regression suite includes 32 source rejection variants, 29 inconsistent
receipt controls, a consistently resealed but unrelated legal resource graph,
fresh source/codegen/semantic replay controls, declaration-renaming acceptance,
publication safety and the complete native qualification. General resource
classes, multiple owned allocations, arbitrary constructor/destructor effects, custom
allocators, inheritance, templates, retained views, moved-from observations
and complete C++ projects remain unsupported. The earlier scoped RAII
bridge still retains C++ implementations; it is not counted as this
implementation migration.
