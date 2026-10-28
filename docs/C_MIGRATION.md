# Captured C project migration

This implementation translates a bounded, explicitly checked C subset into a
safe Hepta core and a separate caller-unsafe C ABI bridge. It captures the build
configuration, lists active declarations, rejects unsupported project input,
checks the generated Hepta, and can require a real Rust native build. A separate
qualification command compares the native result with the original C compiled
by GCC, including deterministic allocation refusal and cleanup checks.

Successful translation is **not a source-equivalence proof**. In particular,
pointer annotations are supplied by the caller and can restrict the original
C input domain. Native compilation validates the generated Rust ownership and
types; it does not prove an arbitrary foreign pointer valid. Finite differential
execution covers the recorded inputs, configuration, platform and compiler.

## Entry points and replay

The existing scalar pilot `migrate_c` remains available. The project API is:

```python
from hepta.c_migrate import migrate_c_project

report = migrate_c_project(
    "compile_commands.json",
    "build/migrated",                 # must not already exist
    contracts=contracts,              # dictionary, optional for scalar projects
    clang="clang",
    rustc="rustc",
    verify_native=True,
)
assert report["ok"], report["diagnostics"]
```

The separate command line tool does not require a main-CLI change:

```sh
python tools/migrate_c_project.py compile_commands.json \
  --output build/migrated \
  --contracts contracts.json \
  --clang /path/to/clang --rustc /path/to/rustc --verify-native
```

An example database entry is:

```json
[
  {
    "directory": "/absolute/path/to/project",
    "file": "native.c",
    "arguments": ["clang", "-std=c11", "-Iinclude", "-O2", "-c", "native.c", "-o", "native.o"]
  }
]
```

The database's compiler command is parsed as data; it is never executed through
a shell. The explicitly selected Clang performs preprocessing and AST capture.
Recognized database driver spellings such as `gcc` and `cc` are recorded
metadata; the original driver executable is neither executed nor attested.
The captured compiler identity, predefined macros, data model and AST belong
to the explicitly selected Clang. This does not qualify the original GCC's
default macros or establish equivalence to the database's original driver.
Original-driver semantic equivalence needs separate evidence; preserving the
listed options alone does not close that build-replay boundary.
Compiler wrappers, response files, plugin flags and unknown options are
rejected. Accepted compile standards are explicit C99, C11 and C17. Includes,
macro definitions, plain-char signedness, accepted optimization levels
(`-O0`, `-O1`, `-O2`, `-O3`, `-Os`, `-Oz`), `-fno-builtin`, and PIC modes (`-fPIC`, `-fpic`) are
preserved in their original order. Optimization and PIC modes can select source
branches through compiler-defined macros such as `__OPTIMIZE__`,
`__OPTIMIZE_SIZE__`, `__NO_INLINE__`, `__PIC__` and `__PIE__`. Dependency discovery,
preprocessing, AST generation and macro replay must observe the same options;
the original native comparison build must not append a conflicting mode.
`-pedantic-errors` is also preserved: it changes Clang's `__has_extension`
builtin preprocessing operator even when the ordinary `-dM` macro dump is
unchanged. For example, C99 `__has_extension(c_static_assert)` selects a
different branch under this option. Captured dependency discovery and function
bodies must preserve that selection too.
Output and diagnostic-only flags are recorded with the reason for omission.
Unmodeled semantic options such as `-fwrapv` still reject. Multiple configurations
for one source must be qualified in separate complete database runs or an
explicit build matrix.

The source operand is preserved exactly as spelled in the original argv, and
Clang runs in the captured working directory. The normalized `source` path is
only a dependency/file identity; it is not substituted into compiler commands.
This matters for `__FILE__`, `__BASE_FILE__`, `__has_include(__FILE__)`, and quoted
header lookup when the main source is reached through a symlink. Dependency
discovery, preprocessing, AST generation, replay and original comparison builds
use the same source operand. It is recovered through the same strict command
parser from the hash-bound `original_arguments`, rather than trusted as a new
independent manifest field. Leading `@` response operands, bare `-` stdin and
option-like source operands are rejected; an explicit `./` filename prefix
does not become a driver option.

Captures made by older compilers which omitted these semantic options do not
become valid by recomputing the receipt hash. They must be recaptured from the
unchanged compilation database so the actual selected declarations and
dependencies can be checked again. The generated HIA backend may optimize its
already-selected program independently; this does not authorize changing which
source branch was imported. The same recapture requirement applies to receipts
produced by replacing a relative or symlink source operand with its normalized
absolute path; replay checks the original spelling's dependency graph and
preprocessed bytes.

To reproduce the native differential qualification:

```sh
python tools/qualify_c_migration.py \
  --clang /path/to/clang --rustc /path/to/rustc \
  --output evidence/c_migration/qualification.json
```

This command requires GCC for the original C oracle. It records GCC identity,
Clang capture, Rust build receipts, source hashes, implementation identity,
comparison counts and allocator fault results. Shared libraries are temporary;
the generated Hepta and the separate ABI bridge are retained beside the report
for review. The qualification does not measure performance parity.

## Build identity and declaration denominator

Capture records every listed translation unit, its normalized frontend
arguments, dependency paths and SHA-256 digests, preprocessed digest, predefined
macro digest, selected Clang executable digest, compiler version and target.
Both `-M` and `-MM` dependency sets are retained to distinguish system input from
project input. Before publishing, capture recomputes its canonical build-manifest identity, reloads every compile-database entry to verify the full configuration denominator, and checks the complete dependency inventory. It rechecks the selected compiler identity and target, source and header bytes, dependency discovery, preprocessing, both predefined-macro inventories and the separate ABI-model probe. Changes reject; a manifest merely rehashed after removing an input or changing the measured C ABI model is not accepted. This catches
changed includes and a newly selected header even when the previously selected
header's contents remain unchanged. It is not a hermetic build-system or
compiler-binary attestation.

The accepted data model is a measured hosted 64-bit model: 8-bit bytes, 32-bit
`int`, 64-bit `long long` and pointers, and 32/64-bit floats. `long`, `size_t`
and plain-char interpretation come from the captured compiler model. Arbitrary
cross-target flags and freestanding targets require another profile.

Each active top-level AST declaration is listed in the receipt. Project
definitions, prototypes, typedefs and records receive explicit statuses;
system/compiler declarations are also enumerated. Unsupported globals, unions,
attributes and other project declarations reject the whole bundle. Declaration
collection continues through unsupported top-level declarations before reporting
that rejection, so a trailing declaration is not silently omitted. If capture
or AST collection cannot complete, `declaration_inventory_complete` is false.

The coverage denominator is **active declarations in every listed preprocessed
translation unit**. A declaration repeated through a header in two units is
counted twice because it occurs in both captured ASTs. It is not a count of all
textual declarations across inactive `#if` branches, all repository files, or
all unlisted build configurations. System declarations have a separate count.
A `function_converted` status means lowering succeeded for that declaration;
the overall bundle still has to pass the frontend and requested native gate.

## Implemented subset

| C construct | Current handling |
| --- | --- |
| Scalar parameters and returns | Fixed-width integers, `size_t`, supported floats and bool, with captured C promotions and explicit conversions. |
| Automatic locals | Ordinary scalar locals require an initializer or a successful all-path definite-assignment check before an unobservable safe initializer is introduced. Pointer/record-view profiles retain separate initialization rules. Mutable Hepta locals preserve reassignment; shadowed source names receive distinct generated names. |
| Control flow | `if`/`else`, `while`, `for` with optional initialization and mandatory condition/increment, lazy pure scalar conditional values, the separately admitted conditional-return slice profile, and supported statement-position comma sequencing. |
| Function calls | Direct calls to definitions captured in the project; static functions receive per-unit names. Missing external implementations reject. |
| Ordinary structs | Complete named records with supported value fields, generated `repr(C)`, field access and complete initialization. |
| Integer arithmetic | Unsigned add/subtract/multiply use modular operations. Signed overflow is not given a new C-defined meaning; generated checked operations may fail outside C-defined inputs. |
| Pointers with lengths | Explicit read or mutable slice contracts; safe-core indexing and a separately marked unsafe ABI bridge. |
| Opt-in checked cursors | The record-view profile also accepts cursor-only modules with no records and complete slice contracts; local cursors are scalar offsets into borrowed storage. |
| Allocation | One nonescaping byte owner with the exact guarded malloc/calloc pattern below. |

Unsupported constructs reject rather than generating placeholders. These
include locals that may be read before assignment, arbitrary local pointers or arrays, pointer
arithmetic/reassignment, function pointers, variadics, unresolved external
functions, static/thread-local/global storage, unions, packed/attributed or
bitfield records, incomplete records, `goto`, `break`, `continue`, `switch`,
`do` loops, inline assembly, atomics and volatile operations. Signed shifts,
implementation-defined signed narrowing, and float-to-integer conversions
require another model. C++ is outside this profile.

Sequencing is conservative: effectful calls nested inside expressions reject,
including calls through scalar helper functions that transitively allocate.
Explicitly initialized locals can sequence such calls. All generated functions
use a conservative effect upper bound; an allocating project includes `alloc`
and `block` in that bound. This is not a minimal-effect inference engine.

## Pointer contracts and the C ABI boundary

### Original parameter spelling before type adjustment

Clang's JSON parameter type alone is insufficient to admit a slice contract.
The declared `const unsigned int data[++n]` and
`const __typeof__(unsigned int[++n]) data` can both appear as
`const unsigned int *`, while entering the original function increments `n`.
A caller-supplied `length=n` cannot recreate this erased source effect.

The shared collector checks captured declaration bytes and independently reads
original types from a serialized AST emitted by the selected captured Clang.
Both checks run **before** record-view decomposition changes record-pointer
parameters into value placeholders. Ordinary slice and record-view routes use
the same admission; one original-type capture per compilation unit covers all
project function declarations, including result types and header prototypes.

The finite spelling profile accepts type-name/qualifier identifiers followed
by a single explicit pointer token and the declared identifier. It also accepts
a single array suffix only when the independently bound original type is a
fixed `ConstantArray` or `IncompleteArray`. Whitespace, ordinary comments and
phase-2 line splices are handled before matching. Fixed macro bounds can pass
this combined gate; a lexical suffix alone does not establish a safe bound.
Computed types such as `typeof`, ambiguous macro locations, macro-supplied
pointer tokens, parenthesized declarators, qualified/static array suffixes and
other unsupported forms reject with `E_C_PARAMETER_DECLARATOR`. Actual variable
array types reject with `E_C_VLA_PARAMETER`, including a macro-hidden bound
that mutates a scalar on entry. Missing or inconsistent original-type evidence
rejects with `E_C_ORIGINAL_TYPE`.

The parameter name and full range are checked against the hash-bound source or
header dependency, with the existing 8 MB dependency limit, and are independently
matched to actual serialized-AST cursor locations. Result/parameter canonical
shape, qualifiers and fixed extents are recorded in the versioned
`hepta.c-original-parameter-types.v2` receipt. The actual matching libclang,
Python executable and reader worker are content-bound trusted components.
This finite gate is not a general C declarator parser or source-equivalence
proof; [original-type admission](C_ORIGINAL_PARAMETER_TYPES.md) defines its
scope, budgets and replay command.

The rejecting declaration is retained as `status=rejected` with its diagnostic
code; later unattempted declarations remain separately identified. Header
prototypes are checked against their header bytes, not the including C file.
Clang's dump elides physical filenames globally across nested `loc`, `range`,
and macro spelling/expansion positions. The collector restores that physical
file state in the original JSON order, using the same out-of-band map for
top-level declaration inventory and pointer-parameter admission. It does not
rewrite the AST. `includedFrom` and `presumedFile`/`#line` names never select
physical source bytes. Missing physical locations refuse admission.

This finite profile requires the parameter name and both range endpoints to
belong to the same physical file as the function declaration. An include
inside a parameter list or a parameter range spanning files therefore rejects,
even if a coincident offset in the function file contains plausible pointer
text. Entire function prototypes in ordinary headers remain supported.
The location compression behavior is documented by the pinned
[Clang 20.1.8 JSONNodeDumper implementation](https://github.com/llvm/llvm-project/blob/llvmorg-20.1.8/clang/lib/AST/JSONNodeDumper.cpp).
Resolving this source identity does not establish general declarator semantics
or whole-source equivalence.
The strict driver flag allowlist is unchanged: an unsupported `-Werror=vla`
entry is still refused by capture. Native warning-suppression controls execute
outside that capture route; they do not turn warnings into admission authority.

Regression coverage includes actual Clang ASTs, native `-O0`/`-O2` entry-effect
observations, both migration routes, header attribution and ordinary pointer
positives. Earlier wrong-result observations belong to their recorded earlier
source identities; current qualification must be rerun on the combined source.

### Contract intake before compiler work

Only an omitted Python `None` contract requests the empty scalar-project
default. An explicit `{}` is an invalid envelope and is refused. Both CLI
entry points use the same bounded JSON loader, reject duplicate keys (including
escaped duplicates), nonfinite/fractional values, invalid Unicode, and
nonordinary/symlink contract files before starting capture. The Python API
accepts an exact built-in JSON tree, rejects container subclasses and cycles,
and snapshots it without invoking caller hooks. The translator and record-view
adapter retain detached snapshots so later caller mutation cannot change a
checked obligation. Concurrent mutation during intake has no atomic
point-in-time snapshot guarantee; every value actually admitted is validated
as it enters the detached graph. Reports bind the canonical contract digest and its origin
as caller-declared, not inferred or proved. The limits are 1 MiB input, 32,768
nodes, depth 32, 4,096 UTF-8 bytes per string and bounded 64-bit integers.

For the frozen example:

```json
{
  "schema": "hepta.c-contracts.v1",
  "functions": {
    "native_transform": {
      "slices": {
        "data": {"length": "count", "access": "read"}
      }
    }
  }
}
```

Each pointer parameter needs an exact contract and either a supported unsigned
length parameter or the fixed integer length `1`. Read slices cannot be written. A function can have multiple read
slices; a function with a mutable slice must have exactly one pointer parameter.
Rejecting the multi-pointer mutable case avoids inventing a nonaliasing
guarantee for C code whose overlapping-buffer behavior may be defined.

The Hepta core takes `read [T]` or `mut [T]` and performs checked indexing. Its
entry assertion checks the claimed length against the actual safe slice. C
callers use the generated `bridge.rs`: it retains the original symbols and raw
C signatures, then constructs the slice inside an explicitly unsafe boundary.
The bridge checks non-null for nonempty data, alignment and representable slice
size; a null pointer with zero length maps to an empty slice. Contract violations
detected at this boundary abort rather than inventing an original C error code.

The C caller must still establish one live allocation, initialized elements,
sufficient allocation size, validity throughout the call, and exclusive access
for mutable slices. Foreign concurrent writes to a read slice are also outside
the contract. Runtime checks cannot establish provenance, initialization or
absence of aliasing. A caller can therefore invoke undefined behavior through
this unsafe boundary despite the safe generated core. Safe Hepta callers get
the core's ownership and slice checks, subject to the compiler's own limitations.

Contracts can be stronger than a particular original function needs. For
example, a source function may ignore a pointer on one branch, while a supplied
whole-call slice contract requires that pointer valid for the declared length.
The receipt explicitly records `may_narrow_original_c_input_domain`; this must
not be relabeled as unrestricted equivalence.

For `void *`, a contract additionally specifies the concrete C `element` type.
An ordinal key such as `"0"` binds the first parameter even when a legal C
prototype uses a different name from its definition. A parameter cannot have
both a name and an ordinal selector. For example:

```json
{"schema":"hepta.c-contracts.v1","functions":{"int_hash":{"slices":{
  "0":{"length":1,"access":"read","element":"int"}
}}}}
```

The captured model makes this an `i32` read slice while the external signature
remains `void *`. The caller must establish the dynamic object's type as well as
validity, alignment and initialization. A C cast to another element type rejects;
the annotation is not permission for arbitrary reinterpretation. `*p` lowers to
checked slice element zero. The accepted read-alias pattern is a function-body
prefix of plain pointer declarations followed by unconditional, direct
initializations from the contracted read parameters. Every alias must be
initialized before other statements. Conditional initialization, pointer
reassignment, escaping aliases and writes through read aliases reject. The
generated core uses the original safe slice directly and introduces no raw
pointer or unchecked operation for these local aliases.

## Fallible allocation and release

The implemented pattern is deliberately narrow and useful:

```c
int64_t example(size_t count) {
    if (count == 0) return 0;
    unsigned char *data = malloc(count);
    if (!data) return -1;
    for (size_t i = 0; i < count; ++i) data[i] = (unsigned char)(i % 251);
    int64_t result = 0;
    for (size_t i = 0; i < count; ++i) result += data[i];
    free(data);
    return result;
}
```

`calloc(count, 1)` is also accepted without the source initialization loop.
The owner must be an `unsigned char *` or `uint8_t *` automatic local. Size must
be the unchanged `size_t` parameter: a narrowing cast of that parameter is not
treated as the same size. There must be one allocation and one final free.
The original zero-length branch is required because C allocator behavior at
size zero cannot be replaced silently by an always-present empty buffer.
An immediate allocation-failure return is required. Malloc requires a complete,
unconditional, ascending initialization loop before any read. The initialization
expression cannot read the owner or have side effects. Owner escape, passing it
to another function, changing its length, early return while live, reallocation,
and use after free reject.

Lowering uses `try_buffer(count) -> Result<Buffer<u8>, u8>`, consumes the result
through `match move`, forwards the original failure return on `Err`, and consumes
the successful buffer exactly once with `release(move data)`. Capacity failure
and allocator refusal remain ordinary failure results. They are not changed
into aborts. Source malloc reads occur only after the retained full-initialization
loop; generated zero initialization does not assign a meaning to an uninitialized
C read. The extra zeroing may have a performance cost and must be measured.

Allocation success itself is an external outcome. A Rust allocator and a C
allocator need not make the same success decision or expose the same custom
allocator side effects. The accepted profile models standard allocation as
success or null, does not infer custom allocation contracts, and does not claim
allocation-outcome equivalence. Qualification supplies both implementations
with the same explicit fault policy to test the failure path and later recovery.

## Frozen inputs and native evidence

`tests/fixtures/c_migration/native/` contains byte-identical copies of the
pre-existing `examples/interop/native.c` and `.h` at commit
`d29a246cabaec5ddd8c5f6043b6b234b56ae8b67`. Its `PROVENANCE.md` records the two
Git blob identities and original notice status. The qualification tool verifies
those identities before use. No external source or new license assignment was
introduced. This is a repository example module, not a production-library
coverage claim.

`buffer_ops.c` and `owned_bytes.c` are separately labeled authored conformance
fixtures. They exercise read/mutable buffers, a helper function, unsigned modular
arithmetic, local loops, and guarded malloc/calloc/free. They are not described
as independently obtained real-world modules.

The default replay performs 1,046 native comparisons: 256 each for scalar add,
value-struct transformation, read-buffer processing and mutable-buffer processing,
plus 11 each for malloc and calloc, including zero and `SIZE_MAX`. Mutable-buffer
comparisons check the result and all output bytes. Ten further allocation
fault/recovery calls reject allocation size 65,519 in both C and Rust, verify
the original failure return, check live allocation counts return to zero after
each call, and verify later successful calls in the same process. A deliberately
wrong result is detected as an oracle negative control. The report records the
actual counts and outcomes; the command failing is not a passing receipt.

Costs include captured project bytes/files/configurations, number of explicit
slice contracts, generated Hepta/bridge lines, native build timings and migration
elapsed time. Human review hours and agent token counts remain null because
they were not measured. No percentage reduction in developer effort, general
automatic-conversion rate, or performance superiority follows from this corpus.

## Bundle publication and remaining scope

The output contains `source.hepta`, `bridge.rs`, `generated.rs`, `migration.json`
and, when requested, `libtranslated.so`. Existing outputs are refused. Files are
staged, source identity is rechecked, and the manifest is published last using
no-overwrite links. This is not a crash-atomic directory transaction. A rejected
translation publishes no successful bundle; a failed publish only removes files
created by that attempt when their content still matches.

The next useful expansion is measured coverage of larger independently sourced
modules, with explicit licenses and immutable source identities, followed by
additional ownership/alias and control-flow patterns. It requires preserving
the full declaration denominator and expanding the differential corpus. This
implementation does not establish arbitrary C/C++ conversion, full ABI coverage,
formal semantic equivalence, compiler soundness, or Rust-level performance.

## Complete third-party module qualification

The additional fixture `tests/fixtures/c_migration/c_algorithms/` freezes the
complete `compare-int` and `hash-int` source/header modules from
[fragglet/c-algorithms](https://github.com/fragglet/c-algorithms/tree/23d453792ed89a28ed7d2c8d4311a4d9f7822edd)
at commit `23d453792ed89a28ed7d2c8d4311a4d9f7822edd`. The upstream project
explicitly defines each `.c`/`.h` pair as an independently usable module.
Both complete modules are compiled without source changes; no unsupported
declaration was cut out to obtain a passing result. This is not a migration of
the full C Algorithms data-structure library. `UPSTREAM.json` records immutable
URLs and Git blob identities. The original per-file ISC notices, full
`COPYING.md`, and upstream README are preserved.

```sh
python tools/qualify_c_algorithms.py --clang /path/to/clang \
  --rustc /path/to/rustc --output evidence/c_algorithms/qualification.json
```

The complete captured denominator is six active project declarations: three
prototypes and three function definitions, across two translation units and
four source/header files. All are processed. The five explicit annotations give
the `void *` inputs a one-element C `int` interpretation. This is an unsafe
caller obligation and is not inferred from a cast. Read inputs are allowed to
alias; the differential corpus exercises equal pointer addresses directly.

The replay compiles the complete original modules with GCC and the generated
core/bridge with Rust. It uses 121 integer-boundary pairs and 4,096 deterministic
random pairs across the full signed-32-bit range. Each pair tests compare,
equality, both hashes, and same-address comparisons, yielding 25,302 native
return comparisons, including 8,434 same-address alias cases. It also checks an
independent arithmetic expectation and that input storage remains unchanged.
Two separate child processes confirm null/misaligned inputs abort at the
generated bridge before slice construction; these invalid inputs are not
executed in the original C oracle or counted as equivalent behavior.

The receipt preserves actual implementation/source/compiler identities,
complete inventory, counts and elapsed times. Reviewable generated sources
retain the upstream terms alongside them. These tests establish this finite
qualification result; they do not prove all inputs equivalent, ownership
inference for arbitrary void pointers, or broad low-cost library migration.

## Generic musl comparison component

The fixed musl 1.2.5 `memcmp.c` and `bcmp.c` component adds unchanged real
upstream source with read-only byte cursors, an omitted loop initializer,
sequenced comma increments and a lazy scalar conditional return. Its explicit
platform adapters and four pointer annotations are separate from the 319 bytes
of original algorithm source. Both complete functions and all five active
declarations per configuration are translated. Actual GCC, Clang and generated
Hepta native routes execute the same corpus under captured `-O0` and `-O2`
component configurations.

See [C_MUSL_COMPARE.md](C_MUSL_COMPARE.md) for provenance, exact acceptance
denominators, retained resource/failure observations, refusals and reproduction.
This gate covers the selected generic component on the executed host; it does
not qualify the full libc, its architecture assembly, or standalone HIA LLVM
slice lowering.

## Complete six-function stb_divide library component

The unchanged v0.94 single-header library is now translated in two complete
macro configurations. The qualifier retains all original bytes, all 12 active
declarations in each build, generated Hepta/HIA/native artifacts and actual C
callers. See `C_STB_DIVIDE.md` for the separate source, AST, functional, resource,
trap and platform denominators, including the actual C++ profile refusal.
