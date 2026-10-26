# Captured C++ concrete implementations to standalone HIA

`hepta.cpp_project_migrate.lower_cpp_project` translates actual Clang-instantiated
function bodies. It shares C project's scalar expression and statement lowerer
and the independent HIA verifier/interpreter/native backend. The target contains
no original C++ function implementation. The source text is a reviewable migration
product; executing its emitted HIA does not require Clang or the original source.

## Input and identity

The input is a real `compile_commands.json` with one explicit C++20 configuration
per translation unit. The common capture/replay authority uses the distinct
`hepta.cpp-build.v1` schema. Every listed command, allowed semantic option, macro
inventory, compiler identity, scalar data model and compiler-discovered dependency
is recorded and rechecked. A C++ capture cannot be relabeled as C by merely
recomputing its hash: language-specific driver, standard and suffix checks replay
against the original database. Shell commands, response files, compiler plugins,
unmodeled flags and duplicate configurations reject.

This capture describes the listed build only. It does not establish that every
possible platform, macro configuration or dependency version has been listed.

## Executable profile

The admitted profile contains integer and Boolean parameters/results, initialized
scalar locals, ordinary control flow and direct calls to captured implementations.
Functions must explicitly be `noexcept`. Clang-resolved overloads are identified
by declaration identity and symbol, including namespace and translation-unit
identity for internal linkage. Calls are never resolved by spelling alone.

Function templates may have ordinary type parameters and integer non-type
parameters. Clang supplies the finite concrete instances used by the captured
project; each instance's actual body is translated and independently checked.
Unused template patterns with no concrete executable destination reject. The
pattern and its parameters remain inventoried as the source of the concrete
instances. A repeated inline/template definition may merge only when normalized
instantiated body semantics agree across translation units. A macro-dependent
definition mismatch rejects.

Every active project declaration receives a disposition, including namespace and
language-linkage containers, prototypes, patterns, parameters and instances.
System/compiler declarations are separately identified; a call to a system or
uncaptured implementation still rejects. The finite input budgets are the common
32-entry compilation database and 32 MB Clang output limit, plus 8,192 declaration
rows and at most 120 concrete functions in this frontend.

Class templates, STL objects, pointer/reference interfaces, exception unwinding,
custom destructors, global state, template packs/defaults, dependent constraints,
`if constexpr` and general C++ class or mangled ABI preservation are not in this
profile. They fail closed rather than being silently omitted.

## Behavior, safety and ABI

Unsigned arithmetic retains C++ modulo semantics through explicit wrapping HIA
operations. Signed arithmetic remains checked in HIA. Equivalence claims are
restricted to defined source executions: C++ signed overflow, invalid shifts and
division outside the defined domain are not treated as source behavior to match.
The qualifier separately executes an HIA signed-overflow input and requires a
real native abort; it does not invoke the original C++ program on that undefined
input.

Extern-C scalar function names are preserved. C++ internal symbols receive stable
generated HIA names. The native backend supplies scalar C wrappers, and the
qualifier executes signed and unsigned 32/64-bit and Boolean cases through those
wrappers. This does not preserve C++ class layout, exception ABI, mangled symbol
ABI or arbitrary aggregate calling conventions.

## Reproduction

```bash
python tools/qualify_cpp_project_hia.py \
  --workdir /tmp/hepta-cpp-template-qualification \
  --clang /usr/lib/llvm-20/bin/clang \
  --clangxx /usr/lib/llvm-20/bin/clang++
```

The output directory must be new. The fixture consists of two translation units
and a macro-dependent local header. It uses four concrete instances (u32/u64
mixing and i32/i64 clamping), overloaded helpers, prototypes and cross-unit calls.
There are 227 fixed oracle cases, 227 interpreter results and 454 native result
observations, plus one real HIA overflow abort. Original C++ objects link only into
the reference library. The HIA target links the directly generated object only;
the receipt validator reconstructs that exact allowed link command independently
of editable expected-command fields.

The qualifier retains the input database/header/sources, generated Hepta and HIA,
LLVM, original and target objects/libraries, complete invocation and raw execution
records, declaration inventory and file hashes. It reports translation wall time
and artifact size as observations. Human review, long-term maintenance and total
development-cost improvement have not been measured by this finite experiment.

These checks provide finite implementation and ABI evidence. They are not a
whole-language C++ translation theorem or evidence that unrestricted C++ can be
rewritten at a particular cost.
