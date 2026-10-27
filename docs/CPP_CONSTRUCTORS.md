# Typed C++ constructor contracts

`hepta.cpp-contract.v2` adds finite, named constructor contracts to the existing
C++ handle bridge. `hepta.cpp-contract.v1` remains accepted and keeps its
zero-argument `Type_new(uint64_t* out)` entry point. V2 does not add a general
C++ expression language, import STL object layouts into Hepta, or make foreign
code safe by declaring a contract.

The executed example in `examples/cpp/constructors` uses the installed,
unmodified **Boost.Math `students_t_distribution<double>`**, which has no
default constructor, and actual `std::vector<int64_t>` size/fill constructors.
The small `SpanOwner` and `NoThrowValue` classes are authored protocol probes;
they are identified separately from those real libraries.

## Descriptor

The v1 handle fields still describe the concrete C++ type, scalar template
instantiations, synchronization, reentrancy, allocator pairing and destruction.
Each v2 handle additionally requires `constructors`, containing one to eight
entries. Each entry has exactly `name`, `params`, and `exception`:

```json
{
  "name": "Student",
  "cpp_type": "boost::math::students_t_distribution",
  "template_args": ["f64"],
  "threading": "serialized",
  "reentrancy": "reject",
  "allocator": "cpp_shared_owner",
  "destruction": "nothrow_defer_inflight",
  "constructors": [{
    "name": "new",
    "params": [{"name": "degrees", "type": "f64", "mode": "value"}],
    "exception": "catch_status"
  }],
  "methods": [{
    "name": "degrees",
    "cpp_method": "degrees_of_freedom",
    "const": true,
    "params": [],
    "returns": "f64",
    "return_mode": "value",
    "exception": "catch_status"
  }]
}
```

This is one handle inside the normal top-level contract. The checked-in
`contract.json` is a complete example with all four object types. Names share
the handle's export namespace: constructors cannot collide with methods or
`destroy`. Constructor parameters also reserve the generated locals `entry`,
`registry`, and `lock`, in addition to `handle` and `out`.

Every constructor accepts at most sixteen parameters using the existing
finite grammar:

| Mode | Generated native argument | Boundary and remaining obligation |
| --- | --- | --- |
| `value` | Typed scalar value or fieldwise converted POD value | POD shape, layout and scalar fields are natively checked. |
| `const_ref` | Reference to the wrapper's call-local scalar/POD value | Requires `retention: "call_only"`; the constructor must not store the reference. |
| `borrow_const` | `std::span<const T>` over the original pointer/length | Requires `call_only`; null/extent/alignment guards run before construction. Live allocation extent, aliasing and nonretention remain external obligations. |
| `borrow_mut` | `std::span<T>` over the original pointer/length | The same lifetime obligations apply. Construction may mutate the buffer, even if it later throws. |

Reference parameters with missing retention or an object-lifetime retention
claim are rejected. No callback, arbitrary template expression, factory-body
string, raw owning pointer parameter, or escaping C++ reference is accepted.

## What the native checks establish

The generator checks `std::is_constructible_v<Object, ArgumentTypes...>`.
With `exception: "noexcept"`, it also checks
`std::is_nothrow_constructible_v<Object, ArgumentTypes...>`. The emitted
`make_shared` invocation uses the same argument categories: value arguments
are typed prvalues, `const_ref` arguments are const lvalues, and spans are
typed span values. A regression distinguishes an rvalue-only constructor from
a deleted const-reference overload.

These checks establish whether the selected C++ compiler accepts that typed
construction expression. They **do not establish an exact constructor
parameter signature**. C++ constructors cannot be taken as function pointers,
and the language may apply implicit conversions during overload resolution.
A native regression constructs a `double`-taking class from the declared
`u64` argument and verifies that the report retains
`exact_constructor_parameter_signature_proved: false`.

`noexcept` describes object construction, not registry or shared-owner
allocation. Every generated constructor entry point still returns a status
and catches ordinary C++ exceptions, including wrapper allocation failure.
An actual violation of C++ `noexcept`, process termination or undefined
behavior is outside that catch boundary.

## Publication, failure, and lifetime

The bridge validates the output slot and borrowed spans, creates local shared
owners, constructs the object, obtains its thread token when required, and
inserts the handle into the registry. It writes the output handle **only after
successful insertion**. A failed construction or insertion destroys the
partially built owners in the same C++ module. Registry locks are released
before foreign destruction during unwinding.

The native harness replaces the actual C++ allocation functions and refuses
each observed allocation site in a warmed `std::vector(size)` bridge call.
It checks status 3, an unchanged handle-output sentinel, the live-allocation
baseline, successful recovery, and paired destruction after every refusal.
The warmed process-lifetime registry is part of the baseline and is not
misreported as reclaimed memory. A separate probe refuses wrapper allocation
for a class whose object constructor is `noexcept`.

The pointer checks do not prove that a nonnull aligned address is live or
writable. Output slots must satisfy the existing nonoverlap obligations.
Output preservation concerns writes made by the wrapper; it cannot prevent
arbitrary foreign code from changing aliased/global storage. Mutable input
writes and other foreign side effects are not rolled back on exceptions.

The native suite includes a deliberately retaining constructor whose JSON
claims `call_only`. Its backing array stays live while the test changes an
element and observes the change through the object. This demonstrates the
remaining foreign obligation without executing a dangling-pointer access.
The bridge remains explicitly unsafe and reports `borrow_retention_proved:
false`. A separate throwing mutable-span constructor demonstrates unchanged
handle output alongside an already modified input buffer.

## Reproducible qualification and costs

The host needs the pinned Rust compiler, a C++20 compiler, and Boost development
headers. On the Ubuntu CI profile, the dependency is `libboost-dev`. The
qualification records the version actually observed by the selected C++
compiler and by native execution, along with SHA-256 identities of all headers
reported by `-M`, including system/Boost headers, before and after the run.
It rejects a changed header snapshot. This is an observed build dependency
snapshot, not a hermetic lock of runtime libraries or the entire operating
system.

```sh
python tools/validate_cpp_constructors.py \
  --iterations 100000 --output artifacts/cpp-constructors-001.json
python -m unittest tests.test_cpp_constructors tests.test_cpp_contracts tests.test_cpp_bridge -v
```

The output path must be new. Required evidence includes:

- Five valid and three invalid-domain Boost.Math constructor calls, including
  a member call on each successfully created object.
- Eight actual vector size/fill constructor cases, an impossible-length
  exception, POD/span construction and copy observation, five pointer-boundary
  rejections, and no remaining authored fixture objects.
- Every observed vector-construction allocation refusal site and its recovery;
  the current required minimum is four. All failure paths preserve the output
  slot under the stated caller obligations.
- Eight schema/native rejection controls: empty constructors, retaining or
  missing borrow lifetime descriptions, export/local-name collisions, false
  `noexcept`, missing arguments for the nondefault Boost type, and wrong arity.
  None may publish a generated output directory.
- Eight timing rows with seven raw samples each. Native and handle
  **create-and-destroy** pairs are measured separately for Student and vector.
  Separate member rows measure `degrees_of_freedom` and `size` on existing
  objects. Lifecycle rows contain no getter call; member rows exclude object
  creation/destruction. A native create/destroy pair and a bridge pair allocate
  the same kind and size of foreign object, while the bridge additionally
  allocates and manages its handle machinery.

The static operation/cost report and observed timings are separate. Warmup,
one host/compiler/library build, sequential case order and no LTO limit the
timing evidence. It does not establish universal zero overhead, Rust
superiority, real-time latency bounds, or Agent productivity.

For upstream API semantics, see the
[Boost.Math Student's t distribution documentation](https://www.boost.org/doc/libs/1_83_0/libs/math/doc/html/math_toolkit/dist_ref/dists/students_t_dist.html).
The qualified installed version is read from the report rather than inferred
from that documentation URL.
