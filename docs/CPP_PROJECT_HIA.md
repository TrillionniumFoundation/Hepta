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
against the original database. Shell programs, response files, compiler plugins
and unmodeled flags reject. Duplicate configurations reject when imported into
one standalone artifact; the explicit matrix entry point below keeps them in
separate artifacts.

Accepted optimization (`-O0`/`-O1`/`-O2`/`-O3`/`-Os`/`-Oz`) and PIC
(`-fPIC`/`-fpic`) options remain in the captured frontend argument order because
they change compiler-provided preprocessing macros. This applies equally to
dependency discovery, AST selection, replay and original native comparison
builds. A later comparison command must not override the captured mode with a
new `-O2` or `-fPIC`. Old captures that omitted these semantic options must be
recaptured; a resealed receipt cannot authorize a different active source tree.
The shared C/C++ capture also preserves `-pedantic-errors`, which can change
Clang's `__has_extension` builtin operator without changing its ordinary `-dM`
macro dump. It is a source-selection option, not an omitted diagnostic-only flag.

The original source operand and working directory also remain part of the
selected source semantics. A normalized absolute file identity must not replace
the original relative or symlink spelling in dependency, preprocessing, AST or
native comparison commands. Otherwise quoted includes can select another header,
and already-supported concrete template arguments such as
`sizeof(__FILE__) + sizeof(__BASE_FILE__)` can instantiate different functions.
The shared command parser recovers the operand from the bound original argv;
response-file, stdin and option-like operands still reject. Older captures that
rewrote this spelling require recapture, even after resealing their hashes.

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
instantiated body semantics and complete template-pattern identities agree
across translation units, including definitions at different source locations.
A macro-dependent definition mismatch rejects even when it occurs only in a
discarded template branch.

An `if constexpr` with no init/condition-variable declaration is admitted when
the captured concrete Clang AST supplies an exact Boolean `ConstantExpr`.
Only its selected branch is lowered; a false condition without an else emits
no runtime statement. Nested selections, full-definition identities and every
discarded subtree receive explicit dispositions. Unknown conditions are never
guessed. Selected operations remain subject to all scalar/lifetime rules;
discarding a class/throwing branch does not enable its execution. See
[CPP_CONSTEXPR_MIGRATION.md](CPP_CONSTEXPR_MIGRATION.md) for the exact boundary
and its separate finite native qualification.

Every active project declaration receives a disposition, including namespace and
language-linkage containers, prototypes, patterns, parameters and instances.
System/compiler declarations are separately identified; a call to a system or
uncaptured implementation still rejects. The finite input budgets are the common
32-entry compilation database and 32 MB Clang output limit, plus 8,192 declaration
rows and at most 120 concrete functions in this frontend.

Class templates, STL objects, pointer/reference interfaces, exception unwinding,
custom destructors, global state, template packs/defaults, dependent constraints,
`if consteval`, constexpr init/condition-variable statements, and general C++
class or mangled ABI preservation are not in this
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

## Complete declared build matrices

One compilation database can contain multiple builds of the same source units.
Use an explicit `hepta.build-matrix.v1` manifest to identify which commands form
each complete build. Indices refer to the original database; zero is its first
entry. For a database containing two units in each of two macro configurations:

```json
{
  "schema": "hepta.build-matrix.v1",
  "language": "c++",
  "database": "compile_commands.json",
  "variants": [
    {"name": "small", "command_indices": [0, 1]},
    {"name": "large", "command_indices": [2, 3]}
  ]
}
```

Every command must occur exactly once, every variant must contain the same
complete source-unit set, and one variant cannot contain two builds of one unit.
Names, driver consistency and index types are checked before compiler execution.
The current finite budget is eight variants and 32 total compilation commands.
Cross-target switches remain outside the admitted build-flag profile.

The shared C/C++ capture creates `hepta.c-build-selection.v1` or
`hepta.cpp-build-selection.v1` records with the original database hash and
original command indices. These records explicitly claim a selected scope; they
cannot be relabeled as a full database capture. The matrix verifier replays the
original manifest and database to establish the complete declared partition.
Changing a header, compiler, database or selection invalidates the capture.

`lower_cpp_project_matrix` translates every declared variant independently.
Declarations, template instances, generated Hepta and verified HIA remain
separate. The CLI verifies all variants before publishing the one selected by
name; `--report` retains the complete matrix and declaration inventories:

```bash
python -m hepta hia import-cpp-matrix matrix.json \
  --clangxx /usr/lib/llvm-20/bin/clang++ --variant large \
  --output large.hia.json --report matrix-report.json

python tools/qualify_cpp_project_matrix.py \
  --workdir /tmp/hepta-cpp-matrix-qualification \
  --clang /usr/lib/llvm-20/bin/clang \
  --clangxx /usr/lib/llvm-20/bin/clang++
```

The qualifier executes two complete macro configurations, two translation units
per configuration, and cross-unit calls and concrete template bodies. There are
204 fixed oracle cases per variant, 408 interpreter results and 816 native result
observations across original C++ and direct HIA. Each target links only its own
generated object. Invalid missing/overlapping command selections, repeated source
units and inconsistent drivers are retained as rejected controls. This is finite
evidence for the listed matrix; it does not qualify unlisted builds, C++ classes,
general RAII, exceptions, STL or a whole-language equivalence theorem.
