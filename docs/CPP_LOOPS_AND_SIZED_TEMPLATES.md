# Stateful class migration and sized template instantiations

This increment adds two executable capabilities to the existing C++ routes:

| Route | New accepted input | Executing implementation | Lifetime authority |
| --- | --- | --- | --- |
| Complete scalar value class migration | Initialized automatic scalars, bounded `for`/`while`/`do` syntax and field updates | Generated Hepta, compiled independently through Rust and C | Trivial C++ value lifecycle; Hepta receiver borrows |
| Explicit C++ contract v4 | Scalar type arguments mixed with literal `std::size_t` arguments | Original selected C++ specialization through a generated C ABI | Existing handle or call-scoped C++ RAII contract |

The two routes retain different trust boundaries. A migrated class has its
method implementation replaced. A bridge continues executing the foreign
library. Neither route establishes general C++ equivalence, whole-language
soundness or universal performance parity.

## Complete stateful value class migration

`hepta.cpp_class_migrate.migrate_cpp_class` retains the existing
`cpp20-public-scalar-value-class-trivial-lifecycle-v1` profile and its complete
translation-unit/member inventory. All accepted classes are still standard
layout, trivially copyable and trivially destructible, with public scalar
fields, an explicit field-initializing `noexcept` constructor, and exact
scalar `noexcept` method signatures.

Methods may now contain a prefix of single-variable, initialized, automatic
scalar declarations. The same exact `i32/u32/i64/u64` type restrictions apply
to locals as to fields. Locals may read prior initialized locals, scalar
parameters and the current receiver's fields. Const methods may update their
automatic locals while their receiver remains a Hepta `read` borrow.

Ordinary local declarations must precede executable statements in the method's
outer compound block. A `for` initializer may instead declare one initialized
scalar with loop scope. Every local reference is matched to its Clang
`VarDecl` identity and exact scalar type before renaming. Parameters use
`ParmVarDecl` identity; fields use `FieldDecl` identity on the actual `this`
receiver. A local called `state` and a field called `state`, or two consecutive
for loops that both declare `state`, therefore remain separate bindings.

The shared `hepta.c_migrate._stmt` implementation lowers scalar assignments,
increments/decrements and loops. There is no separate arithmetic semantics
for C++ methods. An admitted `for` becomes initialized storage plus a `while`
with its step after the body. Its declaration is renamed with a source-offset
identifier so lifting its scalar storage does not capture another variable.
A `do` body is emitted once before an equivalent `while`; the shared lowerer
rejects declarations, return/jump control and nested `for`/`do` in that body.

The migrated `examples/cpp/class_loops/mixer.cpp` contains an unsigned
linear-congruential state update, a read-only checksum, a stateful do loop,
and two separate loops whose indices shadow a field. The consumer executes
multiple method calls on the same value, takes a value snapshot, and checks
that read-receiver calls preserve state. Generated Hepta uses wrapping
unsigned arithmetic. Signed source inputs with undefined arithmetic are
outside the equivalence domain; generated checked arithmetic does not grant
meaning to source undefined behavior.

The extended profile continues to reject uninitialized locals, static or
thread-local storage, const/volatile/reference/pointer locals, declaration
lists, late or nested declarations, in-loop local declarations, `break`,
`continue`, `goto`, missing for conditions and C++ condition declarations.
Constructor bodies remain empty. No custom destructor, owning-pointer
protocol, callback, escaping view, inheritance or foreign method call is
introduced by this extension. These are whole-unit rejections: no partially
translated class is published.

## Typed non-type template arguments

`hepta.cpp-contract.v4` retains v3's exact descriptor shape, including the
required `scopes` array, and adds one permitted template-argument value:

```json
{
  "cpp_type": "std::array",
  "template_args": ["u32", {"kind": "size", "value": 4}]
}
```

This becomes `std::array<std::uint32_t, static_cast<std::size_t>(4)>` in
generated C++. The same form can instantiate a function template, such as
`add_size<static_cast<std::size_t>(4)>`. The actual C++ compiler checks the
selected concrete specialization, constructor, method receiver, return type,
declared `noexcept` properties and nothrow destructor as before. Reports list
each concrete specialization with `selected_instantiation_native_checked=true`
and `all_template_instantiations_qualified=false`.

The size is an exact JSON integer in `[0, 65536]`. Booleans, floats, negative
numbers, larger integers, expression strings and extra object fields are
rejected. Template argument lists remain limited to four entries. V1, v2 and
v3 remain type-only schemas; adopting v4 is explicit. This is not template
argument inference, arbitrary constexpr evaluation, dependent-expression
translation, template definition migration or a bound on total stack use.
Native language conversions of the typed size argument still follow the
selected C++ declaration's rules.

`examples/cpp/template_sizes/contract.json` selects the installed standard
library's `std::array<uint32_t,4>` with `fill` and checked `at`. Its scoped
operation creates a local array, fills it, copies one scalar result and ends
the object lifetime before publishing the result through the C output slot.
`CountedArray<T,N>` in the example is separately identified as an authored
lifecycle witness around the same standard-library storage. It counts live
members and completed-object destruction. Constructor failure after member
initialization exercises subobject cleanup; an out-of-range method exception
exercises completed-object cleanup.

The generated handle route remains available for the same specialization,
with explicit creation/destruction and stale-handle rejection. Its registry,
shared ownership and mutex costs are separate from the scoped route. The
scoped wrapper itself adds no handle registry or wrapper heap allocation;
the foreign class and methods may still allocate, block or mutate external
state. A scalar `noexcept` free function retains its direct-value ABI.

## Reproducible native evidence

Run from the repository root, selecting Clang 20+ and the pinned Rust 1.90
toolchain:

```sh
PYTHONDONTWRITEBYTECODE=1 \
RUSTC=/path/to/rust-1.90.0/bin/rustc \
CLANGXX=/path/to/clang++ \
python -m tools.validate_cpp_extensions --output /tmp/new-cpp-qualification

PYTHONDONTWRITEBYTECODE=1 \
RUSTC=/path/to/rust-1.90.0/bin/rustc \
CLANGXX=/path/to/clang++ \
python -m unittest tests.test_cpp_extensions -v
```

The output directory must be new. The qualifier records actual tool paths,
executable hashes and version-process results, source hashes, generated-source
hashes, native build receipts and original stdout/stderr. It rechecks its
source inputs after execution. It retains generated sources, linker maps,
per-vector class observations and the specialization source diff. Native
binaries are removed by default to limit disk use; their receipts use
`path_during_execution` and `retained=false`, not a readable artifact claim.
Pass `--keep-native` to retain them.

The class qualifier executes 296 stateful traces and 296 receiver-preservation
checks for each of the independent C++, Hepta/Rust and Hepta/C libraries.
It checks all 592 results per backend against a Python integer oracle, using
unsigned extrema, zero iterations and seeded random inputs. An actually
compiled altered multiplier must produce a mismatch. Migrated native link
maps are retained; their inputs must exclude the original C++ reference.
Native symbol tables must contain the reference-only marker in the C++ oracle
and omit it from both migrated libraries. This source/build/symbol evidence
is specific to these produced artifacts, not a general translation theorem.

The bridge qualifier executes both `N=4` and `N=8` specializations. Each
variant performs 24 standard-array differential cases, 24 counted lifecycle
cases, six function-template comparisons, constructor-failure cleanup, two
null-output rejections and seven handle transitions. Success and failure
results include the output value; failures must preserve the sentinel and
all completed calls must restore the live-member count to zero. Separate
negative tests require native rejection of the wrong template argument
category, wrong function result and throwing destructor.

The `N=4` to `N=8` experiment changes three descriptor values, requires zero
consumer source edits, and checks that the generated public C header remains
byte-identical. Its receipt measures generation/native-check time, generated
C++ bytes, added/removed source lines and native object sizes for both
variants. These are bounded regeneration measurements. Human maintenance
minutes are unmeasured, and this experiment is not an upstream library-version
upgrade study or an execution-performance comparison.

## Explicit external obligations and remaining work

The scalar class route uses generated safe Hepta with no introduced foreign
assumptions, subject to the existing frontend, backend and trusted compiler
boundaries. Finite execution does not prove all programs safe or equivalent.
The bridge route remains caller-unsafe FFI. Allocation provenance, actual
allocation size, initialization, aliasing, concurrent foreign access,
output-pointer liveness/nonoverlap and foreign non-retention remain external
requirements. C++ exceptions are caught according to the contract;
termination, hardware faults, `longjmp`, foreign UB and nontermination are
outside the RAII cleanup guarantee. Effects do not imply transactional
rollback of foreign writes. Transitive toolchain/sysroot headers are not
hermetically pinned by this qualifier.

For complete C modules, the existing [captured project route](C_MIGRATION.md)
already emits actual `source.hepta`, a separate ABI bridge, generated Rust,
and a native library when `verify_native=True`. Its inventory denominator is
active declarations in all listed preprocessed translation units. Unlisted
macro configurations and actual foreign pointer validity remain unproved.
This C++ increment does not substitute declaration counts for executable C
migration or change that denominator.
