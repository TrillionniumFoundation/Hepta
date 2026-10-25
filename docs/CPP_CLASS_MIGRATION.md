# Selected C++ class implementation migration

`hepta.cpp_class_migrate` translates one complete, public scalar value class
into a Hepta struct, a constructor function and receiver-borrowing free
functions. The generated implementation contains the actual field
initializers and method bodies. It introduces no C++ calls, handle registry,
foreign pointer or fallback implementation.

This is the bounded
`cpp20-public-scalar-value-class-trivial-lifecycle-v1` L1 profile. The
migrator performs native Clang checks and a Hepta frontend check before
publishing a candidate. The separate qualifier builds and executes both
Hepta backends. Neither operation proves general source equivalence,
whole-language memory safety or preservation of the original C++ class ABI.

## Lifecycle boundary

The admitted class must be standard layout, trivially copyable and trivially
destructible. The tool checks these facts in Clang's complete AST and again
with native compiler traits against the original source. An implicit
destructor or an explicitly defaulted trivial destructor has no resource
cleanup to translate. Its disposition is recorded in the declaration
inventory; it is not silently omitted as unconverted code.

Resource-owning classes remain outside this migration profile. An owning
pointer, `std::vector`, file descriptor, lock guard, custom destructor,
exception cleanup protocol or other nontrivial resource lifecycle is
rejected. This includes a user-provided empty destructor: being empty is not
the same as being trivial under this profile's native trait checks.

The existing [call-scoped RAII bridge](CPP_SCOPED_RAII.md) can execute and
destroy selected nontrivial C++ objects in C++. That route retains the
foreign implementation. It does not turn the foreign destructor into Hepta
resource management. The two routes have distinct claims:

| Route | Method implementation | Object cleanup | Original C++ code in target |
| --- | --- | --- | --- |
| Scoped C++ RAII bridge | Selected foreign C++ methods | Original C++ RAII | Retained |
| Selected scalar class migration | Generated Hepta bodies | Native-checked trivial lifecycle | No foreign class implementation |

## Accepted source and output

The source unit contains exactly one complete `struct`, or a `class` whose
members are explicitly public. Every source declaration and every member
must have an explained disposition. The complete Clang AST is bounded by
the shared AST capture limits; source size is limited to 256 KB. This is not
a name-filtered extraction that leaves unrelated declarations unnoticed.

The accepted forms are:

- One to sixteen ordinary public fields of exactly `int`, `unsigned int`,
  `long long` or `unsigned long long`, mapping to `i32`, `u32`, `i64` and
  `u64` on the checked native host.
- One explicitly defined `noexcept` constructor, with at most sixteen value
  parameters, an empty body and an explicit initializer for every field.
  Initializers may use the checked scalar expression subset and constructor
  parameters; they cannot read other fields or call foreign code.
- One to thirty-two uniquely named, in-class `noexcept` methods returning
  one of those scalar types or `void`. Parameters are scalar values. Bodies
  may read fields and parameters, assign their own fields, return a checked
  scalar expression, and use the supported pure scalar conditions in `if`
  statements. `void` maps to `Unit`.
- Const methods become `read` receiver parameters. Other methods become
  `mut` receiver parameters. Source field references are checked by Clang
  `FieldDecl` identity on the actual `this` receiver; parameters are checked
  by `ParmVarDecl` identity and renamed by position. A source parameter
  called `receiver` or `arg0` cannot capture generated names.

The scalar expression and assignment rules reuse `hepta.c_migrate` rather
than implementing a second C++ arithmetic lowerer. Unsigned addition,
subtraction and multiplication preserve the existing checked modular
lowering. Signed arithmetic is subject to Hepta's checked arithmetic; source
C++ inputs that cause undefined signed arithmetic are outside the
equivalence domain. The qualification fixture exercises signed extrema
through comparisons and assignment, without relying on signed overflow.

For example:

```cpp
struct Counter {
    unsigned int value;
    Counter(unsigned int initial) noexcept: value(initial) {}
    unsigned int add(unsigned int delta) noexcept {
        value = value + delta;
        return value;
    }
    unsigned int get() const noexcept { return value; }
};
```

The relevant generated bodies are:

```text
pub struct Counter {
    value: u32,
}

pub fn Counter_new(arg0: u32) -> Counter ... {
    return Counter {value: arg0};
}

pub fn Counter_add(receiver: mut Counter, arg0: u32) -> u32 ... {
    receiver.value = wrapping_add(receiver.value, arg0);
    return receiver.value;
}

pub fn Counter_get(receiver: read Counter) -> u32 ... {
    return receiver.value;
}
```

The omitted annotations in this explanatory excerpt are emitted by the
tool: explicit effects and zero heap allocation/blocking/suspension/spawn
resource declarations for these scalar bodies. The full generated file is
ordinary Hepta source. Native allocation instrumentation and performance
timing are not part of this qualification, and no timing advantage is
claimed.

## Rejections are part of the profile

Private/protected members, mutable or volatile fields, const fields,
bitfields, default field initializers, inheritance, virtual functions,
templates, overloaded methods, static state, friends, nested declarations,
attributes and unmodeled implicit special members are rejected. The Clang
`mutable: true` field marker is checked explicitly, including when no const
method would otherwise expose that difference.

Pointer/reference parameters and returns, escaped `this`, method calls,
foreign calls, default arguments, constructor side effects, missing
initializers and undefined method bodies are rejected. This first profile
also rejects local declarations and loops inside methods. Preprocessing,
includes, namespaces, additional classes, globals and hidden `extern`
declarations require another project migration profile; none are dropped
from an accepted translation unit.

An output path must be new and have an existing parent directory. Existing
files and symlinks are preserved. Source/compiler changes during migration
reject publication. A staged file is linked into place without overwriting
an output created by another writer.

## Reproduce the migration and native qualification

Use Clang 20 or newer, the repository's pinned Rust 1.90 toolchain, and the
qualified native GCC toolchain. The source model must match the actual
64-bit host with 8-bit bytes, 32-bit `int` and 64-bit `long long`.

```sh
python -m hepta.cpp_class_migrate \
  examples/cpp/class_migration/scalar_state.cpp \
  --output /tmp/scalar_state.hepta --clangxx clang++

python -m tools.validate_cpp_class \
  --workdir /tmp/class-qualification \
  --out /tmp/class-qualification.json \
  --clangxx clang++ --rustc /path/to/pinned/rustc --cc gcc

python -m unittest tests.test_cpp_class_migrate -v
```

The qualification directory and report file must be new. The standalone
entrypoints do not change the main compiler CLI. Library callers can use
`migrate_cpp_class`, `qualify_cpp_class` and
`validate_cpp_class_qualification` (also exported as `validate_report`).

## What was actually executed

The complete `examples/cpp/class_migration/scalar_state.cpp` fixture has four
scalar fields, one constructor, nine methods and an explicitly defaulted
trivial destructor. Its methods cover wrapping updates, scalar reads,
signed clamping, replacement, and a `void` update. The consumer additionally
checks value-copy independence and preservation of the other fields across
each mutation.

The native qualifier builds the original C++ implementation as an isolated
reference library with Clang and UBSan. It builds the migrated Hepta
implementation twice: Rust and independent C/GCC, with UBSan on the C
route. Neither Hepta build links any original C++ object or library. The
original caller and the Hepta consumer are explicit test harnesses; automatic
migration of C++ call sites or a whole build graph is not claimed.

Each Hepta backend executes these cases against both the original C++
result and an independent Python integer oracle:

| Case family | Cases per backend | Behaviors exercised |
| --- | ---: | --- |
| `word_trace` | 305 | `u32` wraparound, updates, replacement, copy/read |
| `wide_trace` | 305 | `u64` xor and wraparound, successive updates, copy/read |
| `balance_trace` | 599 | Signed extrema, nested conditions, clamping, read |
| `position_trace` | 305 | Signed 64-bit extrema, replacement, read |
| `state_guard` | 263 | Every field preserved through unrelated updates |
| **Total** | **1,777** | **3,554 Hepta-to-C++ differential observations** |

Every family includes 256 seeded random cases and explicit edge cases. The
observed outputs were identical across original C++, Hepta/Rust and
Hepta/C. The qualifier then modifies a migrated arithmetic return, actually
compiles the wrong Hepta/C implementation, and executes it. The negative
control reports an observed `2147483649` against the expected `2147483647`
in its first case; a successful compile alone cannot pass qualification.

The JSON receipt records source, compiler, generated-source and binary
identities, frontend and actual build results, process output hashes and
the executed library paths. The validator recomputes the complete expected
observation digest from the integer oracle, checks both frontend/build
chains, requires the actual mutated library in the negative-control
command, and rejects stale current-input/compiler identities. This is
structural evidence validation, not cryptographic authentication of an
arbitrary third-party report.

The tests include thirty source refusal variants and twenty-two evidence
mutations, as well as the real native differential and compiled negative
control. They establish this selected-class slice. Resource-owning C++ RAII
migration, class ABI preservation, automatic project/call-site translation
and a general C++ safety proof remain open work.
