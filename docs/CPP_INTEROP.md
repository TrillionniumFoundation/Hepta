# C++ interoperation: declared contracts, native checks and measured costs

The C++ bridge APIs have two entry points. The original `bridge_cpp` imports
one flat scalar-method class through a bounded, name-filtered Clang AST. The
new `bridge_cpp_contracts` binds explicitly selected functions and concrete
C++ types. Neither translates arbitrary C++ source into safe Hepta, certifies a
foreign library, or makes raw pointers into safe references.

For actual implementation translation of a complete, bounded scalar value
class, see [CPP_CLASS_MIGRATION.md](CPP_CLASS_MIGRATION.md). That separate
entrypoint emits Hepta fields, construction and method bodies, verifies a
trivial lifecycle, and qualifies independent Rust/C builds. It does not
extend the bridge's C++ resource-lifecycle claims into a general RAII rewrite.

The further [selected resource-owner migration](CPP_OWNED_MIGRATION.md)
translates an exclusive byte-array class and its complete construction,
move, borrow and error-cleanup operation into real Hepta `Buffer` ownership.
Its complete native AST must match the closed resource protocol, and actual
allocator refusal and destructor-leak controls qualify both target backends.
The target programs do not retain the original C++ class implementation.

## Generate and execute

The standalone entry point does not change the main compiler CLI:

```sh
python -m hepta.cpp_contracts examples/cpp/stdlib/foreign.hpp \
  --contract examples/cpp/stdlib/contract.json --output-dir /tmp/cpp-bindings \
  --cxx g++ --rustc /path/to/pinned/rustc

python -m tools.validate_cpp --output /tmp/cpp-native-qualification.json \
  --cxx g++ --rustc /path/to/pinned/rustc

python -m unittest tests.test_cpp_bridge tests.test_cpp_contracts -v
```

The generator requires a new output directory. It writes `bridge.cpp`,
`bridge.h`, `bridge.hepta`, `contract.json` and `report.json` only after real
C++ object compilation and Hepta's real Rust validation gate have succeeded.
An absent or rejecting native compiler cannot produce frontend-only success.
Generation does **not** link the foreign library or execute it. Its report
sets `native_link_qualified=false` and `paired_toolchain_abi_qualified=false`.
The separate qualifier links and executes a C++ caller, a Hepta static library,
the generated wrapper and the real C++ implementation.

## Four cost routes

| Route | Actual generated behavior | Cost boundary |
| --- | --- | --- |
| Direct scalar/POD | Calls an exactly typed C++ function pointer; `noexcept` is checked by the native type system | No wrapper heap allocation, registry or lock. POD fields are copied into/out of matching native aggregates. A compiler may remove the adapter; the generator does not promise universal zero overhead. |
| Checked borrowed span | Passes the original pointer/length as `std::span`; rejects null nonempty spans, impossible extents and misalignment; translates C++ exceptions into status | No wrapper buffer copy, allocation, registry or lock. Validation branches and an exception boundary remain. Foreign code may allocate when its declared contract permits it. |
| Dynamic handle | Keeps C++ objects in a C++-owned registry, obtains a local shared owner, serializes each object and copies scalar/POD results out | A successful initialized call has one registry lookup, two lock acquisitions and two shared-owner copies. Creation additionally allocates owners and a map node, with possible map growth and foreign allocations. |
| Call-scoped C++ RAII (v3) | Constructs one selected object, executes bounded method calls, copies its result and destroys the object before returning | No wrapper heap allocation, registry, mutex or shared-owner copy. Foreign allocations, stack and exception costs remain; see [CPP_SCOPED_RAII.md](CPP_SCOPED_RAII.md). |

The cost report describes generated operations, not measured nanoseconds.
`tools.validate_cpp` separately records actual timing samples, checksums,
compiler/standard-library identities and the executable hash. The benchmark
compares identical scalar and span operations and a native `vector::size`
helper with the wrapper paths, using separate translation units and no LTO.
Creation, destruction and process startup are outside its timed loops. It uses
one host and sequential measurement order, so the report does not establish
universal performance, tail latency or superiority over Rust.

The checked-in [native qualification](../evidence/cpp/native_qualification.json)
contains seven observed samples of one million calls per route, using G++
13.3.0 and libstdc++ release 13. This run measured the following medians; these
are observations from that run, not contractual latency limits:

| Operation | Native C++ ns/call | Bridge ns/call | Observed ratio |
| --- | ---: | ---: | ---: |
| Scalar mix | 1.668834 | 1.950910 | 1.1690 |
| Sum of eight borrowed integers | 3.874820 | 5.239283 | 1.3521 |
| Vector size | 1.416853 | 18.307124 | 12.9210 |

The handle result makes the cost distinction concrete: a registry and two
locks are expensive relative to a trivial getter. Batch object operations or
use direct value/span interfaces for hot paths when the foreign API permits
it. A single global claim of "zero-cost C++ interoperability" would be false.

## The concrete library integration

`examples/cpp/stdlib` actually uses the installed C++ standard library:

- `std::vector<std::int64_t>` is owned, mutated, read, concurrently accessed
  through the serialized handle path, and destroyed in the C++ module.
- `std::string` is constructed from a borrowed byte span, including embedded
  NUL bytes; its allocations remain in C++.
- `hepta_example::twice<std::uint64_t>` is a concrete C++ template
  instantiation exposed through a scalar C ABI.
- Scalar calls, POD returns and borrowed spans make a complete
  **C++ caller -> Hepta -> generated C++ wrapper -> C++ library** round trip.

This is a real library integration with selected operations. It is not a port
of the C++ standard library or an automatically translated C++ application.
The qualification report records `_GLIBCXX_RELEASE`/`__GLIBCXX__` or the
equivalent libc++ version macro from the compiler actually used.

## Contract schema and verification

The original `hepta.cpp-contract.v1` remains supported. The
`examples/cpp/stdlib` descriptor is a complete v1 example. V2 adds explicit,
bounded constructor argument lists and named constructor entry points; see
[CPP_CONSTRUCTORS.md](CPP_CONSTRUCTORS.md) and `examples/cpp/constructors` for
actual nondefault Boost.Math construction, STL size/fill constructors, failure
injection and separately measured lifecycle costs. V3 adds a required `scopes`
array for operations on call-local C++ automatic objects, reusing the selected
constructor/method checks. Cleanup precedes output publication; the scoped
ABI never exposes its local object or a reference into its storage. This
does not introduce a general Hepta owning type or translate C++ source.
Unknown fields and
unsupported types are errors. Names are
bounded identifiers, with namespace qualification for C++ names; template
arguments are explicit supported scalar types. Arbitrary C++ expressions are
not accepted in the descriptor.

`pod_types` declare the native type and all exposed scalar fields. Generated
native checks require a trivial, standard-layout aggregate, matching field
types, size, alignment and every field offset. Structured binding also checks
the exact aggregate field count, preventing an omitted field from hiding in
padding. Union, packed/overaligned layouts that disagree with the generated
C ABI, nontrivial lifetimes and recursive pointer layouts are outside this
route. Actual Hepta layout interoperability is separately exercised by native
bidirectional calls.

Free functions have explicit `exception`, `threading`, `reentrancy` and
`allocation` policies. A native function pointer checks the exact argument
and result types, including a declared `noexcept`. Values cross the ABI by
value. `const_ref` parameters receive a reference to the wrapper's call-local
value; `borrow_const` and `borrow_mut` receive `std::span` over caller storage.
All reference modes require `retention=call_only`. This is an explicitly
unproved foreign obligation, not a theorem obtained by writing it in JSON.

Handle descriptors specify a concrete C++ type, threading, reentrancy,
allocator ownership and destruction policy. Methods select const/nonconst
receivers, parameter modes, return type and exception policy. Returning a
reference requires `return_mode=copy_from_reference`; it is materialized as a
scalar/POD value before crossing the ABI. C++ references and STL object
layouts never cross the ABI. `Unit` methods are supported, including
`vector::push_back`.

For a function's `allocation=none_declared`, the report explicitly says that
foreign allocation has not been verified. Functions declared `cpp_internal`
carry the Hepta `alloc` effect. Handle operations conservatively carry
`alloc`, `block`, `write`, `ffi`, and `unsafe`: the wrapper uses blocking
locks, may lazily initialize a registry, and invokes an unverified method.
Other foreign effects remain obligations of the selected API. The example's
small arithmetic fixtures also have ordinary C++ arithmetic preconditions;
the finite qualification input set does not prove them for all integers.

## Lifetime, reentrancy and concurrency

The registry mutex is released before invoking a constructor, method or
destructor. Registry insertion retains a local owner so an allocation failure
cannot destroy a foreign object while holding the registry mutex. Same-object
calls use a recursive mutex. `reentrancy=allow` permits a callback to reenter;
`reentrancy=reject` reports status 6 before a nested operation on the active
object. Different objects do not acquire a global method lock. This does not
prove freedom from lock-order deadlocks across multiple foreign objects.

`threading=creator_thread` checks the creation thread before calls and
destruction, returning status 5 on another thread. `serialized` permits
multiple threads through the per-object lock. Neither policy proves that
foreign global variables, external aliases, callbacks or worker threads obey
the same discipline. Affinity uses a retained thread-local identity token,
not a recyclable `std::thread::id`. This adds a token allocation on the first
affine bridge use of each thread and prevents a later thread from inheriting
an abandoned object's authority through operating-system thread-ID reuse.

`destruction=nothrow_defer_inflight` is checked using native destructor traits.
Destroy removes the handle and waits for ordinary same-object calls. If an
allowed reentrant method destroys its own handle, its local shared owner
keeps the object alive until that method finishes. A native test reads an
owned allocation after such reentrant destroy and verifies exactly one later
destructor. C++ `noexcept` violations terminate; they cannot be made into
recoverable status codes by `catch (...)`.

All object allocation/deallocation remains with the same C++ shared owner.
The ABI does not expose `free`, `delete`, allocator function pointers or STL
storage ownership to Hepta. Each module issues monotonic, non-reused handles
across its types; passing another type's live handle within that module is
rejected. Handles from other independently loaded modules are not authenticated
capabilities. Raw numeric bindings remain unsafe and callers must preserve
their module/type association.

The registry itself has process lifetime. This intentionally prevents leaked
thread-affine objects from being destroyed on an arbitrary shutdown thread.
Callers must explicitly destroy handles; abandoned objects are not reclaimed
before process exit. This bridge has no automatic Hepta RAII owner and makes
no leak-freedom claim. Safe affine language wrappers can be layered on the
existing unsafe ABI only when the language's owner/destructor semantics cover
all control-flow paths.

## Status and external obligations

| Status | Meaning |
| ---: | --- |
| 0 | Success |
| 1 | Null output, or null input with nonzero extent |
| 2 | Stale, wrong-type-within-module, or unknown handle |
| 3 | Caught C++ exception, including allocation or constructor failure |
| 4 | Handle space exhausted |
| 5 | Wrong thread for a creator-thread object |
| 6 | Reentrant operation forbidden by policy |
| 7 | Span extent cannot fit the supported pointer-difference range |
| 8 | Misaligned pointer |

Output values are written only after a successful operation. An exception
does not undo changes to the foreign object or a borrowed mutable buffer;
the native negative test demonstrates partial buffer mutation. The wrapper
cannot establish that a nonnull pointer names a live allocation of the claimed
length, that aliases are permitted, or that C++ never retained a span. An
invalid but aligned pointer remains a caller error. Hardware faults,
undefined behavior, races, nontermination and process termination are outside
C++ exception translation.

Reports retain the root header hash and the compiler's user-header dependency
list. They do not establish a hermetic lock of transitive headers, sysroot or
linked implementation libraries. Rebuild and qualify against the actual
headers, library objects, target and toolchains before using the output.

Native tests cover both successful execution and rejection: wrong signatures,
false noexcept declarations, incorrect POD layout, nontrivial POD types,
reference-result policy, unsupported retention/allocator choices, missing
compiler, thread affinity, reentrancy, deferred destruction, constructor
exceptions, and output preservation. These are scoped execution evidence,
not a whole-language or arbitrary-C++ soundness proof.
