# Real Microsoft GSL final_action migration

This profile migrates a small, real upstream RAII component into standalone
Hepta. It is an additional implementation migration example alongside the
authored `cpp_callback_project` fixture and the nlohmann/json bridge. It does
not turn either of those earlier examples into a full third-party rewrite.

The upstream code is Microsoft's maintained GSL, specifically
`gsl::final_action<GslCallback>` and the instantiated `gsl::finally` factory.
The complete utility header, assertion-header dependency and MIT license are
retained for each selected version in `tests/fixtures/gsl_final_action/`.
`lock.json` records upstream commit identities, byte lengths, SHA-256 values,
Git blob SHA-1 values and per-file source URLs.

| Release | Fixed upstream commit | Utility header |
| --- | --- | --- |
| [3.1.0](https://github.com/microsoft/GSL/tree/0f6dbc9e2915ef5c16830f3fa3565738de2a9230) | `0f6dbc9e2915ef5c16830f3fa3565738de2a9230` | `include/gsl/gsl_util` |
| [4.0.0](https://github.com/microsoft/GSL/tree/a3534567187d2edc428efd3f13466ff75fe5805c) | `a3534567187d2edc428efd3f13466ff75fe5805c` | `include/gsl/util` |

## What is automatically translated

`hepta/cpp_gsl_final_action.py` invokes real Clang 20 against the retained
headers and a compiler-owned C++20 instantiation/type probe. It retains the
unmodified JSON AST output, command receipts and complete `-M` preprocessor
dependency closure, including the host standard library. It checks source and
compiler identities before returning a migration receipt.

The importer inspects the actual instantiated method bodies:

1. The value constructor must move its by-value callback into `f_`; the
   activation value is read from the captured initializer.
2. The move constructor must move `other.f_` and transfer activation through
   `std::exchange(other.invoke_, false)`. A moved-from destructor can then be
   eliminated because its captured condition is false.
3. The destructor must test its own captured activation field and invoke its
   captured nullary callback exactly once when active. Extra statements,
   unmodeled branches and unconditional invocation are rejected.
4. Each supported `finally` instantiation must return a constructed owner
   from the captured parameter. GSL 3.1's separate `const F&` overload copies
   directly; the forwarding overloads use the actual `std::forward` expression.
   Both AST forms are checked rather than inferred from the release label. The importer checks
   the real move/copy constructor and return type after template substitution.
   It does not implement a general template instantiation engine.

The separately authored `GslCallback::operator()` is also translated from its
actual AST. Its statements are bounded unsigned-64-bit scalar assignments,
initialized const locals and nested conditionals. Addition, subtraction and
multiplication become explicit wrapping operations; supported bitwise and
Boolean operations retain their scalar meaning. Pointer rebinding, pointer escape, extra active
translation-unit declarations and unsupported expressions are rejected.
Changing the real callback source from multiplier 31 to 37 causes a different
generated program and a new successful original/migrated/oracle comparison.

The compiler-owned probe and AST checks require a trivial, aggregate callback
with one `GslState*` and one `unsigned long long` tag, a state containing two
unsigned 64-bit scalars, an exact `void operator()() noexcept` signature,
noncopyable/nonassignable owners and nothrow owner move/destruction. Bytes must
have eight bits and `unsigned long long` must have 64 bits.

## A real upstream upgrade with an observable consequence

GSL 3.1's forwarding overload retains an `F` reference when a nonconst lvalue
is passed to `finally`. In the selected case it attempts to instantiate
`final_action<GslCallback&>` and cannot initialize that reference from the
constructor's moved expression. GSL 4.0 removes cv/reference qualifiers from
the factory's owner type and accepts the same source program.

This is tested at both source and migrated boundaries:

| Input category | Original 3.1 | Migrated 3.1 | Original 4.0 | Migrated 4.0 |
| --- | --- | --- | --- | --- |
| Rvalue callback | Compiles/runs | Captured factory adapter | Compiles/runs | Captured factory adapter |
| Nonconst lvalue callback | Reference-binding compile error | `GslFinallyLvalue` is absent; caller rejected | Compiles/runs once | Actual lvalue factory AST is lowered; caller runs once |
| Const lvalue callback | Separate `const F&` overload directly copies | Captured direct-copy adapter runs once | Unified forwarding overload copies after cv/reference removal | Captured forwarding-copy adapter runs once |

Both released class implementations use the same essential cleanup algorithm.
The migration does not claim that their runtime destructor algorithms differ.
The observed upgrade is the changed generic factory type contract, and the
4.0-only adapter is emitted only after capturing and validating that successful
instantiation. Generic factories for arbitrary callable types remain outside
the profile.

## Independent acceptance

Run from the repository root with a real Clang 20 installation:

```sh
HEPTA_CLANG=/path/to/clang-20 python -m unittest tests.test_cpp_gsl_final_action
python tools/qualify_cpp_gsl_final_action.py \
  --clang /path/to/clang-20 --cxx g++ --cc gcc \
  --output /tmp/hepta-gsl-final-action-evidence
```

The qualifier builds the original C++ as three independent translation units
with GCC, without LTO. It separately compiles the generated Hepta through the C
backend and links only that generated object and a C observation harness into
the migrated target. No original C++ object or GSL bridge is linked there.
Both targets are checked against a Python oracle that does not call the
importer, the Hepta interpreter, or either compiled implementation.

There are 416 inputs per release, with zero, maximum-width values and seeded
random cases. The eight control-flow families exercise normal destruction,
early return, exception cleanup after a cross-unit transfer, a second move,
cancellation before transfer, nested reverse cleanup order, an exception after
construction, and failure before any guard is constructed. Observations are
the wrapping callback trace, exact callback count and status result. The 4.0
nonconst-lvalue factory additionally has 416 independent original/migrated
comparisons. The actual callback-source mutation has another 416 comparisons.
Each version additionally has 416 original/migrated const-factory comparisons,
covering 164 distinct seed/tag pairs; the factory intentionally ignores the
eight caller-mode values. The qualifier records this distinction explicitly.

The report records negative controls:

- A wrong multiplier remains acceptable to the resource checker but is
  rejected by the independent value/trace oracle.
- Consuming an owner twice and returning without consuming it are rejected by
  the Hepta checker.
- Actual emitted C with the unchanged export name but a narrowed return or a
  signed argument is rejected by an independent C11 signature probe before
  an incompatible native call can occur. The probe includes the actual generated
  definitions, rather than merely restating a caller-side declaration.
- The unit suite starts from real compiler-produced ASTs and rejects a move
  that leaves the source active, unconditional/extra destructor work, extra
  factory statements, an unsupported callback operation, a nontrivial factory
  transfer, real source pointer rebinding, an unmodeled global declaration and
  an altered compiler-owned type probe.

The evidence directory contains the retained source/type probe, raw ASTs,
dependency lists and hashes, generated Hepta/Core/C, checker receipts, exact
commands, original and migrated observations, binary identities, case inputs
and `report.json`. Qualification wall time and generated/authored source sizes
are measured. Human migration time is explicitly unmeasured; no labor or
performance saving is inferred from these measurements.

## Resource and semantic boundaries

The generated owner contains a zero-length `Buffer<u8>` token so the existing
Hepta and independent Core verifiers can enforce consumption of a linear
resource. On the current C backend a zero-length buffer allocates no payload.
This is ownership of a cleanup obligation, not a migrated arbitrary heap
allocator or a general C++ object representation.

The callback's state pointer is specialized to the one synchronous state in
the authored, closed client. There is no claim to infer arbitrary pointer
lifetimes, support stored/escaping callbacks or preserve a public C++ class
ABI. The externally observed native interface is scalar C ABI. `std::move`,
`std::forward`, `std::exchange`, the frontend, code generator and captured host
toolchain remain explicit trusted dependencies. Hashes identify inputs; they
are not an attestation of compiler correctness.

`client.hepta`, `factory_client.hepta` and `factory_const_client.hepta` are explicitly authored integration
clients. They are excluded from the automatic-translation count. The former
expresses the tested C++ exception/early-exit paths as explicit status returns
and cleanup calls. General C++ exception ABI translation is not implemented.
The native evidence shows the behavior of these closed clients, not all
possible clients of the original generic library.

Resource checking proves the supported linear-consumption obligations. It
does not, by itself, prove the callback's mathematical result or that every
cleanup has the desired external effect: the deliberately wrong but linear
negative control demonstrates why independent semantic acceptance is needed.
There is no machine-checked whole-translation equivalence theorem here.

This establishes a real, reproducible maintained-component migration and
upgrade boundary. Broad C++ migration remains open: large generic libraries,
custom allocation/deallocation, arbitrary exceptions, inheritance and virtual
dispatch, asynchronous or escaping callbacks, concurrency, and general
pointer/lifetime reconstruction need separate supported profiles and evidence.

The qualifier records the measured Linux LP64 native host and checks the
selected Clang, C and C++ compiler target identities against it. Native calls
exercise the exact `u64(u64,u64,u32,u32)` C export. This does not qualify a public
C++ class layout, an arbitrary cross-target ABI or physical-device behavior.
See `CPP_GSL_CONST_FACTORIES_20261031.md` for the two const-reference AST paths.
