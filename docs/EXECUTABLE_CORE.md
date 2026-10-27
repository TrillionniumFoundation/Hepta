# Executable safety core, version 1

This implementation connects the source checker, an independent core
interpreter, the resource verifier and native code generation for a deliberately
closed language profile. The core contains executable value, control and resource
operations. It is not only a JSON summary of separate compiler passes.

The implementation is in `hepta/executable_core.py`, the independent interpreter
in `hepta/executable_core_runtime.py`, and the repeatable native qualification in
`hepta/executable_core_qualify.py`. The regression tests are in
`tests/test_executable_core.py`.

## What is unified

Each expression carries its checked type, source span and executable opcode.
Functions carry parameter ownership modes, declared and inferred effects,
resource contracts and structured bodies. Numeric expressions can occur inside
the same branches, loops and calls that manipulate owned buffers and Results.

The document binds the exact source, source path, compiler implementation,
semantic projection, independently verified resource graph and optional project
identity. The interpreter executes its operation nodes directly. The native
path decodes those same nodes into **new** AST objects, checks them again,
requires an exact encode/decode round trip and passes the decoded program to
the existing LLVM ownership backend.

Source replay is an integrity and correspondence check, not a formal proof of
source-to-IR refinement. The decoder and interpreter are separate implementations
but still share the frontend's type model and profile rules. The independent
resource graph verifier is an additional check; it does not establish a theorem
about the frontend or native backend.

## Closed profile

Admission also runs the existing LLVM emitter on the newly decoded core AST,
without invoking a native compiler. This makes the accepted profile the
intersection of the executable reference and native profiles. For example,
boolean `&`, `|`, `^` and effectful index expressions are rejected when creating
the core, rather than being accepted by the interpreter and rejected only at
native build time. This representability check is not native execution or a
compiler-refinement proof; the pinned Rust gate and actual native compilation
are still required for a build.

Index operands are scalar-only in v1: compute `let offset = index(mut data);`
before accessing `data[offset]`. Borrowing or otherwise accessing an owner
inside an index (including `len(data)`) is rejected conservatively. This closes
the case where an effect-free helper still takes a mutable loan while Rust's
indexing loan is active. Pure scalar index arithmetic and scalar helper calls
remain supported. The current resource representation also rejects
`Result<Unit, E>` construction; a scalar payload must be used instead.

The wire schema is `hepta.executable-core.v1`; its profile is
`checked-integer-buffer-result-structured-v1`.

| Area | Accepted operations | Boundary |
| --- | --- | --- |
| Values | `bool`, `Unit`, signed/unsigned 8/16/32/64-bit integers, `usize`, `isize` | Pointer-sized integers are 64-bit in this profile; no floats or arbitrary-width values |
| Arithmetic | Checked add, subtract, multiply, divide, remainder, negate; explicit wrapping arithmetic; shifts, bit operations, comparisons, min/max, integer casts | Shift count and value have the same integer type; casts truncate to the destination width |
| Control | Local bindings, scalar assignment, `if`, `while`, `for`, short-circuit boolean operators, returns and direct function calls | One source module; no dynamic dispatch or arbitrary control-flow graph mutation |
| Ownership | `Buffer<u8>`, allocation, `try_buffer`, byte reads/writes, length, move, drop/release, owned function parameters and returns | Explicit transfer and consumption; no nominal owned aggregates or raw pointers |
| Borrowing | Read/mutable call arguments over named byte buffers and byte slices; nested call-scoped reborrows | No stored loans, borrowed returns, explicit lifetime parameters or borrowing other types |
| Results | Concrete `Result` construction, matching, scalar/owned payloads and nested concrete Results | No user-defined enums, generic functions or generic call instantiation |
| Effects | Declared/inferred `alloc`, `block`, `panic`, `write`, with the existing resource contracts | No foreign calls, unsafe blocks, I/O, tasks, channels, suspension or cancellation |
| Native boundary | Supported integer C exports, checked against the existing native backend's ABI profile | The native builder may reject a core if the host/backend cannot implement its boundary |

Unsupported constructs are rejected during core creation/verification. They
are not deferred to an interpreter "unknown operation" fallback. Imports,
nominal structs/enums, generic functions, lifetime records, borrowed-return
functions, task/cancellation types and FFI are explicit negative regressions.

`Result<Buffer<u8>,u8>` is a concrete supported resource composition; it does not
mean generic functions or the language's entire type system have been integrated
into this core. Existing Hepta generic, stored-borrow and task facilities remain
separate compiler profiles. Work package 2's general combination of generics,
stored loans and cancellation is therefore **not complete** here.

## Numeric and control semantics

The interpreter uses Python integers only as an implementation mechanism. Every
typed arithmetic result is checked or narrowed according to its fixed-width
opcode. Signed division truncates towards zero; remainder is derived from that
quotient. Division by zero and `MIN / -1` or `MIN % -1` trap. Checked arithmetic
overflow traps. Explicit wrapping operations and integer casts narrow modulo the
destination width. Shifts reject negative or out-of-width counts; shifting left
discards high bits, including for signed operands. Signed right shift preserves
the sign. The negative minimum integer literal is handled as a single signed
literal operation rather than first interpreting its positive magnitude.

Boolean conjunction/disjunction short-circuit. Function arguments evaluate
left to right; each borrow remains active until the call finishes. `for` bounds
are evaluated once and the range excludes the endpoint. Indexed assignment
evaluates the right-hand value before evaluating the target index, matching the
current native backend. Branch and loop blocks have lexical local scopes;
assignments to an outer scalar binding survive exiting a block.

These are specified and executable semantics for the listed profile. Finite
native comparisons verify selected inputs, not all possible input values.

## Resource and failure semantics

Each interpreted buffer has an owner identity, byte storage, liveness state and
active loans. Moving an owner invalidates its source local. Mutable/read loans
have explicit identities and ancestor relationships; nested reborrows finish
before their parent loans. Conflicting live loans, use after move, double drop,
copying an owner, dropping a borrowed owner and returning with an unconsumed
owner are resource errors. The frontend and independent resource verifier reject
the corresponding invalid source forms before execution; the interpreter also
maintains these checks while executing accepted core operations.

Byte indexing is checked at runtime. `try_buffer` returns an error for a capacity
larger than `isize::MAX`, and the reference interpreter can deliberately refuse
a selected nonzero allocation attempt. `buffer` converts allocation refusal
into a trap. Empty buffers still have an owner that must be consumed, but require
zero allocator allocations/frees. Normal and explicit error returns must consume
their owned resources. This version has abort-on-guard behavior and does not
promise destructor execution, unwinding or cleanup after a runtime trap.

The following evidence must remain separate:

| Evidence | What it establishes | What it does not establish |
| --- | --- | --- |
| Frontend and independent resource graph acceptance | Listed type, effect and linear-use rules pass their implemented checks | Whole-language soundness or complete borrow checking for excluded profiles |
| Core interpreter execution | Actual core opcodes produced the reported results and resource events under the recorded limits | Native execution, unbounded termination or host allocator behavior |
| Reference allocation-failure injection | The specified error branch consumes preceding owned resources in the reference semantics | An operating-system OOM event |
| Linked native allocator wrapper | The generated LLVM implementation handles a real `NULL` return from its allocator boundary and frees preceding allocations | Real machine memory exhaustion or all allocator implementations |
| Native differential corpus | The observed core/LLVM/Rust/C return values agree on identical listed inputs | Compiler refinement or a universal performance claim |

The interpreter reports `returned`, `trapped` and `budget_exhausted` separately.
A harness step/heap limit is never reported as a language allocation error.
Limits also bound recursion depth, owner identities and resource events. The
default budget is 1,000,000 steps and 1 MiB of live bytes, with hard configurable
ceilings of 10,000,000 steps and 16 MiB. The executable core itself is limited to
4 MiB of bounded JSON, 100,000 wire nodes and depth 96; input source is limited
to 1 MiB. These are harness acceptance limits, not program termination bounds.

## Source binding and rejection

Every public verification, execution or decoding entry point reparses and
checks the supplied source. It independently lowers the resource graph, then
requires byte-for-byte canonical equality with the freshly reconstructed core.
Changing an opcode operand, type, effect, resource identity or proof flag and
recomputing the outer hash does not make a forged document valid. Mutating an
already parsed AST without changing its associated source is also rejected.

Decode reconstructs the executable AST from the supplied core only after this
source correspondence check, checks the new AST and encodes it back to the exact
same document. There is no public "skip round trip" parameter. Hashes are useful
identities, not signatures or proof certificates. The supplied source itself is
the authority; verification does not establish who authored it.

## API

```python
from hepta.pipeline import analyze
from hepta.executable_core import (
    lower_executable_core,
    verify_executable_core,
    execute_executable_core,
    decode_executable_core,
    build_executable_core_source,
)

checked = analyze(source, path="module.hepta", native=False)
core = lower_executable_core(checked.program, checked.checked)
verification = verify_executable_core(core, source=source)
execution = execute_executable_core(
    core, "lifecycle", [31, 249, 0], source=source,
    max_steps=1_000_000, max_heap_bytes=1_048_576,
)
decoded_program, decoded_check = decode_executable_core(core, source=source)
native = build_executable_core_source(
    "module.hepta", "module.so",
    rustc="/path/to/rustc-1.90.0", clang="/path/to/clang-20",
    kind="shared",  # or "object"
)
```

The execution entry accepts only scalar external arguments and returns; owned
parameters and results are allowed between internal functions. Exact Python
input types are checked: a `bool` cannot impersonate an integer, and values
outside their entry type's range are rejected. Source/core errors use
`ExecutableCoreRejected`, a subclass of `ValueError`.

Native construction requires a new output path and an actual pinned Rust
reference check. It then emits LLVM from the freshly decoded core program,
checks the backend's native ABI/identity receipt and publishes only the staged
artifact that matches that receipt. Source and compiler identities are checked
again before and after publication. No generated Rust or C supplies this
artifact's machine code, and no alternative backend is used as fallback. The
build status is `native_compiled_not_executed`; building alone does not confer
execution qualification.

## Compiler commands

The regular Hepta CLI exposes the same validated entry points:

```sh
python3 -m hepta executable-core module.hepta -o module.core.json
python3 -m hepta verify-executable-core module.hepta module.core.json
python3 -m hepta run-executable-core module.hepta --core module.core.json \
  --function lifecycle --arguments '[31,249,0]'
python3 -m hepta build-executable-core module.hepta -o module.so \
  --rustc /tmp/hepta-ai-rust-1.90.0/bin/rustc \
  --clang /usr/lib/llvm-20/bin/clang --kind shared
```

`run-executable-core` can lower the source itself when `--core` is omitted.
It also accepts `--max-steps`, `--max-heap-bytes` and the explicitly labeled
`--allocation-fail-at` reference-test injection. Commands emit structured JSON;
stale or forged cores and reference traps produce a failing command status.
Core/native output paths must be new. CLI regression tests cover source
changes, malformed input, runtime guard failure and overwrite rejection in
`tests/test_executable_core_cli.py`.

## Repeatable actual-native qualification

Run the standalone qualification after freezing compiler edits:

```sh
PYTHONDONTWRITEBYTECODE=1 \
RUSTC=/tmp/hepta-ai-rust-1.90.0/bin/rustc \
CLANG=/usr/lib/llvm-20/bin/clang \
CC=cc \
python3 -m hepta.executable_core_qualify --report core-qualification.json
```

The report path must be new. Missing tools, compilation failures, unexpected
signals, mismatched results, changed compiler identities or allocator-observation
failures produce rejection, with a nonzero process exit. This entry never uses
mocked native execution and cannot silently skip an unavailable native backend.
Temporary native artifacts are deleted after their hashes and observations have
been recorded. Source and input identities are stable; complete receipt hashes
also bind execution-specific temporary paths and tool output.

The fixed source is `QUALIFICATION_SOURCE` in the qualification module. It
combines arithmetic, `while` and `for`, branches, byte mutation, nested read
borrows, mutable calls, ownership transfer, concrete Result matching and early
error cleanup. The corpus records:

- **56 input cases and 168 real native return-value executions:** an independent
  core interpreter versus decoded-core LLVM, original-source Rust and
  original-source C. Native calls run in a separate process so an unexpected
  abort cannot be mistaken for an ordinary return value.
- **Two native SIGABRT observations:** an out-of-bounds access and integer
  overflow, each compared with a reference-core trap.
- **Four native allocation paths:** successful nonempty allocation, empty
  allocation, an actual allocator-boundary refusal for the second allocation,
  and capacity refusal before the allocator. The observer sees **5 allocations,
  5 frees, 0 live allocations and 1 allocator refusal**. Capacity refusal is
  accounted separately; the reference interpreter labels its corresponding
  injection explicitly.
- Source, input, compiler, core, generated-language and artifact SHA-256
  identities, compilation receipts, individual results and resource counts.

The regression suite also rejects rehashed forged core content, conflicting
mutable borrows accepted by the preliminary frontend, stale source/AST
associations, unsupported profiles, invalid entry values and over-deep input.
It checks negative minimum literals, explicit Result construction, typed casts,
integer division edge cases, short-circuit behavior and distinct runtime versus
harness limits.

```sh
PYTHONDONTWRITEBYTECODE=1 \
RUSTC=/tmp/hepta-ai-rust-1.90.0/bin/rustc \
CLANG=/usr/lib/llvm-20/bin/clang \
python3 -m unittest tests.test_executable_core -v
```

The native unit-test class may explicitly skip when tools are unavailable, as
normal for a portable unit-test suite. Such a run is not qualification. Use the
standalone entry above for a fail-closed native acceptance gate.

## Remaining work

This provides an executable correspondence loop for a finite profile. It does
not replace every existing IR or backend. The core still uses the AST as the
native backend projection instead of being the universal input of every backend;
Rust and C in the differential qualification remain original-source references.
General generic functions, stored lifetime composition, cancellation/unwinding,
nominal ADTs, full-module migration, concurrency and arbitrary target hardware
remain outside this implementation. The core document and all receipts keep
whole-language soundness, formal refinement, general lifetimes, concurrency and
universal performance claims false.
