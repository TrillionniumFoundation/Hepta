# Selected C++ RAII operations through Hepta

`hepta.cpp-contract.v3` adds a bounded **call-scoped C++ object** route.
The selected object is constructed, used and destroyed inside one C++
wrapper invocation. Hepta calls that wrapper through the existing C ABI.
This closes automatic cleanup for this finite route. It does not introduce
arbitrary Hepta destructors, translate C++ classes, or establish memory
safety of a foreign implementation.

V1 and v2 retain their original descriptor shapes and entry points. V3
uses v2 explicit constructors and additionally requires a `scopes` array.

## Supported contract

One operation selects a concrete handle type, a named constructor, one to
sixteen declared methods, and input parameters. It reuses those declarations'
native checks. Arguments are input parameter names, without arbitrary
expression strings, callbacks, branches or stored intermediate results.
The last method determines the scalar/POD/`Unit` result type.

```json
{
  "name": "vector_roundtrip",
  "handle": "Vector",
  "constructor": "filled",
  "params": [
    {"name": "count", "type": "usize", "mode": "value"},
    {"name": "initial", "type": "i64", "mode": "value"},
    {"name": "appended", "type": "i64", "mode": "const_ref", "retention": "call_only"},
    {"name": "index", "type": "usize", "mode": "value"}
  ],
  "constructor_args": ["count", "initial"],
  "calls": [
    {"method": "append", "args": ["appended"]},
    {"method": "at", "args": ["index"]}
  ],
  "lifetime": "call_scoped_cpp_raii"
}
```

The complete example in `examples/cpp/scoped/contract.json` binds the
installed `std::vector<int64_t>` size/fill constructor, `push_back` and `at`.
`Probe` and `PairOwner` in that directory are authored lifecycle probes,
identified separately from the real standard library.

Input types, modes and retention must match the selected contracts exactly.
Argument counts, names and use are checked; unused parameters are rejected.
The native generator retains const/nonconst receiver categories. It does
not silently choose an overload on a different receiver category. Generated
argument expressions are bounded scalar/POD conversions and span values;
there are no arbitrary side-effecting argument expressions to reorder.

## Cleanup and output semantics

Pointer slots and spans are checked before construction. Inside a C++
exception boundary, a lambda constructs one automatic object and calls the
selected methods in sequence. Typed prvalue construction uses guaranteed
C++17 elision, so the object need not be copyable or movable. The selected
native destructor must satisfy `std::is_nothrow_destructible_v`.

The lambda has an explicit **value return type**. A final `const T&` result
is therefore copied while its owner is still alive. C++ then destroys that
owner before the lambda returns to the wrapper. Only afterward is the output
slot written. The scoped ABI exposes no object handle, view, pointer or
reference into that local object. Intermediate results are discarded and
must also have supported scalar/POD/`Unit` types.

A fully constructed object is destroyed exactly once on normal completion
or a catchable method exception. A failing constructor instead triggers
normal C++ destruction of its already constructed subobjects. Failure stops
later method calls. `Unit` operations omit the output slot but use identical
cleanup rules. Status 1/7/8 pointer/extent/alignment rejection precedes
construction. Status 3 denotes a caught C++ exception, including allocation
refusal. The wrapper leaves the output slot untouched on failure.

Foreign input mutations and other side effects are not rolled back. A native
regression mutates a borrowed input then throws during construction; the
input change remains, the output sentinel remains, and member cleanup runs.
Output validity/nonoverlap, input liveness, aliasing and `call_only` retention
remain explicit external obligations. A local object cannot turn a false
foreign retention claim into a theorem.

The report keeps `foreign_nonretention_proved=false` and
`whole_library_memory_safety_proved=false`. RAII cleanup is not promised after
`longjmp`, process termination, Rust abort, nontermination or foreign UB.
Scoped calls remain explicitly unsafe FFI with conservative `alloc`, `block`
and `write` effects. Declared `noexcept` violations terminate, rather than
becoming recoverable status codes.

The handle descriptor supplies the concrete type and signatures; its registry
and shared-owner policy still applies to its ordinary handle entry points.
A scoped operation instead uses a local C++ automatic object, with no
registry insertion, shared owner or wrapper mutex. Construction and
destruction run on the calling thread. This does not prove synchronization
of foreign global state or bound total stack use.

## Reproducible execution

```sh
RUSTC=/path/to/pinned/rustc python -m hepta.cpp_scoped \
  --output /tmp/cpp-scoped-qualification.json --cxx g++ --iterations 50000

RUSTC=/path/to/pinned/rustc python -m unittest \
  tests.test_cpp_scoped tests.test_cpp_contracts tests.test_cpp_constructors \
  tests.test_cpp_bridge tests.test_cpp_contract_capture -v
```

The qualifier compiles real Hepta to a Rust-backed static library, compiles
the generated wrapper and foreign C++ implementation, links an executable
and runs it. Generator acceptance alone never claims linking or execution.
Existing qualification output is never overwritten. Source, compiler,
object, executable and stdout/stderr hashes are recorded, and source/compiler
identities are rechecked afterward. This is not a hermetic transitive-header
or sysroot lock.

The native qualifier covers sixteen C++/Hepta vector result comparisons;
immovable-object success, constructor failure, middle-method failure and
final-method failure; separately counted member and object destruction;
output publication after destruction; POD-reference copying before original
fields are overwritten by a destructor; `Unit` success/failure; invalid
output pointers; vector length and bounds exceptions; refusal and recovery
at every observed ordinary C++ allocation site. Additional tests reject
escaping handles, raw/reference results, retaining inputs, code strings,
wrong types/modes, malformed scopes and a native throwing destructor.

## Measured complete-lifecycle cost

The executed GCC and Clang 20 identities, example/produced-source hashes,
native output hashes, allocation observations and raw timing samples are
retained in [the compact qualification summary](CPP_SCOPED_RAII_QUALIFICATION_20261025.json).
The five C++ test modules passed all 39 tests without skips under Rust 1.90.0;
the dedicated qualifier also linked and executed successfully with Clang 20.1.2.

On the executed GCC 13.3/libstdc++ 13 host, constructing a vector, appending,
reading an element and destroying it required two ordinary C++ `new` calls
natively, two through Hepta's scoped route and five through the warmed
handle route. Every operation returned to its pre-call live-allocation
baseline. The warmed process-lifetime handle registry is intentionally part
of that baseline. Counters observe replaced ordinary C++ `new`/`delete`, not
every allocator in the process or every possible library operation.

The first seven-sample run, with 50,000 complete lifecycles per sample and
no LTO, observed:

| Route | ns per complete lifecycle | Ratio to native C++ |
| --- | ---: | ---: |
| Native C++ vector | 30.86238 | 1.0000 |
| Scoped C++ ABI wrapper | 32.36320 | 1.0486 |
| C caller -> Hepta -> scoped C++ wrapper | 32.30192 | 1.0466 |
| Existing handle route including creation/destruction | 147.65038 | 4.7842 |

The separate static report records zero wrapper heap allocations, registry
lookups, mutex acquisitions and shared-owner copies for scoped operations.
Foreign allocations, stack objects and exception machinery remain costs.
These are observations on one host with sequential samples and possible
concurrent load, not tail-latency guarantees or evidence of superiority over
Rust. Tests assert results, checksums and allocation accounting; they impose
no machine-specific nanosecond thresholds.

## Still open

General owning Hepta values with custom destructors, cleanup across arbitrary
Hepta control flow, asynchronous cancellation, returned foreign views,
callback ownership, concurrent object transfer and automatic C++ class/STL
source conversion remain outside this increment. Numeric handles still
require explicit destruction. This is selected foreign-library integration
with C++ RAII, not C++ source rewriting.
