# C interoperability in v0.2

Hepta has two complementary C components. [`hepta.c_import`](../hepta/c_import.py)
translates a bounded header subset using facts measured by the native C compiler.
[`hepta.c_backend`](../hepta/c_backend.py) lowers checked Hepta syntax directly to
C11 and GCC objects, without generating Rust or invoking rustc. The C backend
shares the Hepta frontend and implements its own conservative borrowing checks.
It provides an independent native compilation path; it is not an independent
LLVM backend or a second implementation of the entire language.

## Importing an existing C API

```sh
python -m hepta import-c examples/interop/native.h \
  --module native_api --output build/native_api.hepta
```

This command writes the generated source and the accompanying
`build/native_api.hepta.imports.json`. Keep these files together. The Python API
returns both values without writing them:

```python
from hepta.c_import import import_header

result = import_header("examples/interop/native.h", module="native_api")
print(result.source)
print(result.manifest)
```

Supported input includes include guards or `#pragma once`, `stdint.h`, `stddef.h`
and `limits.h`, plain function prototypes, simple scalar/pointer typedefs, named
structs and typedef structs, fixed nonempty array fields, const-qualified raw
pointers, and integer constant macros. A fixed array dimension may be a positive
literal or a separately probed integer macro. Named nested records are supported.
Parameter names become `arg0`, `arg1`, etc.; external C symbol names are retained.
Typedefs are resolved into concrete Hepta types and recorded in the manifest.

Generated records use `pub repr(C) struct`, so another module can use the type
through `import native_api;` and `native_api::TypeName`. Imported extern functions
are visible module bindings. Integer macros become public `cconst_NAME()`
accessors; negative accessors conservatively declare `panic` for signed negation.
The importer does not add a global constant declaration to the language.

The importer compiles and executes a GCC probe against the original header. Its
manifest records the compiler version and executable hash, native target, host
OS/architecture/pointer width, header and generated-source hashes, probe source
and executable hashes, fundamental type sizes/alignment/signedness, struct
sizes/alignment/field offsets, and constant values with their native integer
types. `long` width, plain `char` signedness, and record padding come from that
probe. A changed input header during import is an error.

### Binding identity and target restrictions

The CLI and [project loader](../hepta/modules.py) recognize generated bindings by
their `// hepta:c-import:v1` marker and enforce the following bundle checks:

- The `.hepta.imports.json` sidecar must exist and have the expected schema.
- The complete generated-source hash must match its sidecar. The sidecar itself
  becomes part of the loaded project snapshot and identity.
- The recorded host OS, architecture, and pointer width must match the current
  host. A mismatch requires a new native probe.
- If the original header still exists inside the package root, its bytes must
  match the recorded hash and become part of the project snapshot. An external
  or system header is a recorded probe input, not an automatically revalidated
  package dependency.
- A project containing native C imports rejects an explicit `--target`, including
  attempts to reuse its bindings for a foreign ABI. Target-specific import
  profiles are not implemented.

These checks are applied by project loading; direct calls to low-level `parse`,
`check`, or `emit_c` are not a replacement for loading a binding bundle. Hashes
identify the source and probe evidence. They do not prove a foreign
implementation correct or make a host probe qualify another platform.

### Foreign contracts and rejected syntax

C declarations do not determine ownership, lifetimes, thread safety, allocation,
blocking, callback retention, or hardware ordering. Imported functions therefore
declare all currently known effects by default. The Python API permits an
explicit contract to narrow that upper bound:

```python
result = import_header("native.h", contracts={"native_add": {"ffi", "unsafe"}})
```

The manifest labels this as `caller_supplied_assumption`. The importer always
includes `ffi` and `unsafe`; narrowing effects does not prove memory safety or
any other semantic promise. Probe facts and these assumptions remain separate.

Unsupported constructs produce explicit errors: attributes/packing, bitfields,
varargs, function pointers, unions, enums, opaque records, function definitions,
old-style unspecified `()` prototypes, array-parameter decay, volatile/restrict/
atomic/bool types, and conditional or general-purpose preprocessing. Unsupported
typedefs are rejected even when unused. Failure does not return a partial set
of declarations. The importer's supported syntax is broader than the independent
C backend's record subset; for example, an imported array field currently
requires the Rust backend.

## Independent C11/GCC backend

```sh
python -m hepta run benchmarks/borrowed.hepta --backend c
python -m hepta build examples/ffi/abi.hepta --backend c \
  --crate-type staticlib --output build/libhepta-c.a
```

For a checked, single-source program, the low-level API is:

```python
from hepta.parser import parse
from hepta.checker import check
from hepta.c_backend import emit_c, compile_c

program = parse(open("benchmarks/borrowed.hepta").read())
checked = check(program)
c_source = emit_c(program, checked, crate_type="bin")
build = compile_c(c_source, output="build/borrowed-c", sanitize=True)
```

`compile_c` supports `bin`, `obj`, `staticlib`, and `cdylib`, with `link_args`,
`check_only`, `optimize`, and an explicit `cc` when needed. A `check_only` success
requires a real, nonempty GCC object. Reports include compiler identity, flags,
source and artifact hashes; successful destination replacement is atomic.
The current C profile is native-host compilation: the CLI rejects both
`--target` and `--no-std`. Cross-GCC and freestanding C profiles are not qualified.

Generated C has a static assertion requiring 8-bit bytes and 64-bit `size_t` and
`intptr_t`. This is an explicit supported data model, not an assertion of
portability to all C machines. The minimum `isize` literal is emitted as
`INTPTR_MIN`; it is not computed by negating an out-of-range signed literal.

Supported features include fixed-width integers through 64 bits, native-size
integers within that profile, booleans, basic floating arithmetic, ordinary
structs, nonempty array values, read/mut slices, read/mut scalar and struct
parameters, conditionals, loops, calls, checked indexing, and explicit raw
pointer operations. C-compatible scalar and ordinary-struct extern/export
functions retain their ABI symbol names. Internal array values use wrappers;
`repr(C)` array fields are rejected by this backend.

Expressions use ordered temporaries to preserve left-to-right evaluation and
short-circuiting. Integer add/subtract/multiply use checked GCC builtins.
Division, remainder, shift counts, and indices have explicit failure checks.
Wrapping operations and integer casts use unsigned arithmetic and exact-width
bit copies to avoid signed-overflow and narrow-promotion undefined behavior.
Arithmetic right shift is implemented explicitly. Failed checks abort, matching
the prototype's panic-abort policy. GCC diagnostics can differ from rustc's
compile-time constant-overflow lints.

Borrows are limited to ephemeral parameter arguments. Multiple borrows of the
same root are rejected if any is mutable, including disjoint fields that a more
advanced analysis might accept. Effectful nested calls in borrowed argument
lists, indices, and raw-store operands are conservatively rejected. Raw-pointer
validity and foreign contracts remain external obligations.

Buffer, Task, channel and task-group runtimes, generic declarations, ADTs,
zero-sized layouts, recursive type definitions, pointers to arrays, `repr(C)`
array fields, and float/integer numeric casts are not currently lowered.
Unsupported semantics produce `E_C_BACKEND_*` diagnostics. Acceptance by the
Rust backend does not imply acceptance by this smaller C backend.

## Evidence and platform qualification

The native tests exercise actual C-to-Hepta-to-C calls, imported public structs
used across modules, safe-slice execution with `RUSTC` deliberately unavailable,
seeded arithmetic comparisons, minimum `isize`, and matching abort behavior for
dynamic overflow, division, shifts, and bounds. The dedicated C backend
differential tests enable GCC UBSan. Reproduction commands are:

```sh
python -m unittest discover -s tests -p 'test_c_*.py' -v
python -m unittest discover -s tests -p test_cross_feature_audit.py -v
python tools/validate_cross.py --output artifacts/cross-execution.json
```

The qualification levels are deliberately separate:

| Evidence | What it exercises | Qualification boundary |
|---|---|---|
| [Host native validation](../artifacts/native-validation.json) and [ABI matrix](../artifacts/abi-matrix.json) | Real host C compiler callers/callees, ordinary aggregate layout and by-value calls; the seeded matrix uses the Rust backend | Finite host cases; no blanket coverage of C extensions or every ABI |
| Independent C backend tests | Direct Hepta-to-C11/GCC code generation, imported C implementations, supported scalar/struct/slice semantics | Current 64-bit native-host profile and supported subset |
| Cross-target object generation in native validation | Rust-backend objects for AArch64 Linux, Cortex-M, and Windows x64 | Compilation and object inspection alone do not establish execution |
| [AArch64 QEMU execution](../artifacts/cross-execution.json) | Produced AArch64 `no_std` sum/copy code actually runs under QEMU user-mode Linux emulation; lengths 0 through 4, wrapping edge values, untouched destination suffix, and a wrong-result negative control | A Rust extern-C syscall harness is the caller; an independent AArch64 C compiler ABI roundtrip is not qualified |
| Physical hardware and devices | No corresponding qualification in these reports | No physical board/CPU, interrupts, DMA, GPU, Windows execution, or device-ordering result |

The QEMU report records both a successful program and a deliberately incorrect
sum rejected with the expected exit code. This is execution evidence beyond
cross-compilation, while remaining separate from physical hardware and cross-C
ABI validation. It is not a performance result. All reports must be read with
their source/compiler hashes and declared scope; the tests establish finite
correctness evidence, not general language soundness or superiority over Rust.
