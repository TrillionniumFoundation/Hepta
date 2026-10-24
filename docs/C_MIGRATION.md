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

The existing scalar pilot `migrate_c` remains available with the required
[pinned same-instance frontend](C_SCALAR_FRONTEND.md). The project API is:

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
Compiler wrappers, response files, plugin flags and unknown options are
rejected. Accepted compile standards are explicit C99, C11 and C17. Includes
and macro definitions are preserved; output, optimization and diagnostic flags
that do not belong to this semantic frontend invocation are recorded with the
reason for omission. Semantic options such as `-fwrapv` are not silently
discarded. Multiple configurations for one source must be qualified in separate
complete database runs.

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
project input. Before publishing, capture rechecks source and header bytes,
reruns dependency discovery and preprocessing, and rejects changes. This catches
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
| Automatic locals | Require an initializer; mutable Hepta locals preserve reassignment. Shadowed source names receive distinct generated names. |
| Control flow | `if`/`else`, `while`, explicit `for` initialization/condition/increment, return and expression statements. |
| Function calls | Direct calls to definitions captured in the project; static functions receive per-unit names. Missing external implementations reject. |
| Ordinary structs | Complete named records with supported value fields, generated `repr(C)`, field access and complete initialization. |
| Integer arithmetic | Unsigned add/subtract/multiply use modular operations. Signed overflow is not given a new C-defined meaning; generated checked operations may fail outside C-defined inputs. |
| Pointers with lengths | Explicit read or mutable slice contracts; safe-core indexing and a separately marked unsafe ABI bridge. |
| Allocation | One nonescaping byte owner with the exact guarded malloc/calloc pattern below. |

Unsupported constructs reject rather than generating placeholders. These
include uninitialized locals, arbitrary local pointers or arrays, pointer
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
