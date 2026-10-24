# Hepta 0.1 implemented semantics

This is the specification of the implemented bootstrap subset, not of every
feature discussed in the research proposal. The normative compiler behavior is
versioned with the source snapshot and the conformance evidence. Source and
specification discrepancies are defects, not permission to reinterpret a test.

## Compilation and trust

UTF-8 source is lexed and parsed into a closed AST. No source fragment is copied
into generated Rust. Names in generated Rust are mechanically prefixed. The
frontend checks declarations, types, effects and normal-path resource flow.
rustc 1.90.0 then validates the generated types and borrows before compilation.
The optimizer runs at opt-level=3 with overflow-checks=yes, panic=abort and one
codegen unit. No LTO or native-CPU tuning is silently enabled.

The trusted computing base includes this frontend/lowering, rustc/LLVM, the
linker, the standard/runtime libraries, the OS, and every accepted external
contract. There is no machine-checked proof of frontend soundness or translation
preservation. Successful tests do not constitute that proof. The compiler's
identity check prevents accidental wrong-tool execution and missing outputs;
it does not attest an adversarially forged compiler installation.

## Lexical rules

Identifiers are ASCII. Unicode is accepted inside comments. Comments are `//`
and nested `/* ... */`. The only string syntax is the ABI string `"C"`.
There are no arbitrary string expressions, macros, method calls, paths or Rust
escape blocks in 0.1. Function and body spans use Python Unicode code-point
offsets, with one-based line and column. CRLF counts as one newline. The parser
and AST enforce depth limits and produce structured diagnostics on rejection.

## Units and declarations

An optional `module name;` names a single compilation unit. There is no import
resolver or multi-file package language yet. A unit can contain ordinary
structs, `repr(C)` structs, functions, and `extern "C"` declarations.
Functions may be `pub` and/or `export "C"`. Every function must declare
`effects { ... }`. Extern declarations end in a semicolon and have no body.
Resources clauses apply to implemented functions.

## Types and parameters

- Fixed-width signed/unsigned integers, `isize`, `usize`, `f32`, `f64`, `bool`, Unit.
- Ordinary by-value structs and fixed arrays `[T; N]`.
- Unsized slices `[T]`, only as `read`/`mut` parameters.
- Raw pointers `raw const T` and `raw mut T`.
- Linear owned `Buffer<T>`; the constructor currently creates only Buffer<u8>.
- Linear hosted `Task<u64>`, restricted to local handles.
- Unconstructible `Cancellation`, restricted to read parameters.

Parameter modes are value, read, mut, take. Owned Buffer parameters must use
take; read/mut parameters borrow. Bare use of a borrowed Copy scalar reads its
value; Rust lowering dereferences the borrow. A call-site read/mut expression
creates or reborrows an argument. Storing local reference aliases, returning
references, arbitrary lifetime parameters and resource-containing aggregates
are not in this subset. Local shadowing is rejected.

The implementation intentionally rejects nested linear values, Task parameters
and returns, and owned/constructed Cancellation values. These restrictions
make its actual checked resource model explicit. They are not limitations of
all possible ownership languages.

## Arithmetic and evaluation

Expressions have the documented conventional operator precedence. Evaluation
uses the corresponding Rust expression semantics and preserves short circuit
`&&`/`||`. Numeric literals receive contextual types; default integers are i64
and default floats f64. Integer literal range is checked. Regular integer
arithmetic has overflow checking in both debug and optimized output. Explicit
wrapping_add/sub/mul operate modulo the integer width. Division, remainder,
shifts and integer negation have conservative panic effects. Floating-point
operations use Rust/LLVM's ordinary floating semantics; no fast-math mode is
enabled. Numeric `as` casts follow Rust numeric cast semantics.

Pointer/integer conversion and arbitrary pointer reinterpretation are rejected.
The supported raw_mut to same-pointee raw_const conversion requires unsafe.
There is no mathematical-integer or real-number proof layer.

## Effects and resource clauses

Known effects are alloc, panic, io, block, spawn, ffi, unsafe and write.
Declarations are upper bounds. Each implementation is checked against them;
the call graph is iterated to a fixed point and calls respect declared bounds.
An unknown effect or missing effect is an error. Mutation of local variables
does not create write; mutation of borrowed inputs and raw stores does.

The intrinsic summaries are deliberately conservative:

| Operation | Effect upper bound |
| --- | --- |
| buffer | alloc, block, panic |
| release | alloc, block |
| print_i64 | io, block, alloc, panic |
| assert / indexing | panic |
| wrapping arithmetic / len / min / max | no intrinsic effect |
| raw load | unsafe |
| raw store | unsafe, write |
| spawn | alloc, block, spawn, panic plus worker effects |
| join / cancel_and_join | alloc, block, panic |
| cancelled | atomic read, no allocation/blocking effect |

`alloc` covers allocator interaction, including deallocation. Consequently
heap_allocations=0 conservatively excludes release as well as allocation.
This stricter meaning is intentional and documented; it is not a proof of
process-wide peak RSS or total allocation bytes.

Supported resource clauses are exactly heap_allocations=0 and
may_block=false, may_suspend=false, may_spawn=false. Unsupported clauses,
nonzero numeric budgets or wrong literal types are rejected. Suspension is not
part of this subset. Resource checking covers the modeled call graph; foreign
effect summaries remain explicitly accepted external assumptions.

## Linear resources and control flow

A local Buffer owner must be released, moved into an owning parameter, or
explicitly moved into a Buffer return. Task handles must be joined locally.
Both continuing branches must leave compatible live resources. Repeated loop
bodies cannot consume an incoming owner while continuing; loop-local owners
must be consumed on every normal exit from their scope. Early returns check
every resource still owned by that path. Double moves, moves of borrowed
resources, resource-discard expressions, short-circuit consumption and hidden
resource temporaries are rejected.

This is a normal-path property. Panic uses abort; process failure, termination,
infinite loops and external failure do not receive language-level eventual
cleanup guarantees. All leak-detection claims are scoped accordingly.

## Hosted tasks and cooperative cancellation

`spawn(worker, move buffer)` takes an implemented function with signature
`(take Buffer<u8>, read Cancellation) -> u64`. The worker must have no
transitive spawn, ffi or unsafe effect. The generated runtime creates a real
OS thread and an Arc<AtomicBool> cancellation flag. The buffer moves into the
thread; it is never shared by hidden cloning.

`join(move handle)` waits for completion. `cancel_and_join(move handle)` sets
the flag with Release ordering then waits. `cancelled(read token)` reads with
Acquire ordering. A cancellation worker must cooperate. Cancellation has no
deadline guarantee, and general termination/deadlock freedom is not proved.
Task locality/consumption prevents silently detaching a handle on modeled
normal paths, but does not establish global numeric thread-count bounds.
There are no channels, select, lightweight async executor or async FFI yet.

## C boundary and hardware profile

Supported C boundary values are fixed C99-width numeric scalars through 64
bits, pointer-width numeric scalars, raw pointers and nonempty repr(C) structs
with recursively compatible fields. Arrays are allowed as struct fields or
pointer pointees, not as direct function arguments/returns. bool, i128/u128,
zero-length array fields, ordinary Rust-layout structs, Buffer, Task and slices
are rejected at C boundaries. Unit is supported as void return/pointee.

Headers include stdint.h and stddef.h, emit `hepta_Name` typedefs, preserve
accepted field and symbol spellings, and provide extern-C linkage for C++.
Compiler-internal Rust structs/fields use H_/h_ prefixes. C/C++ keywords,
standard typedef/macro names, generated typedef collisions and implementation
reserved boundary identifiers are rejected rather than producing broken C.
The precise conservative reserved-name policy is implemented in checker.py.

External calls and calls to functions declaring unsafe require an explicit
unsafe block. Raw loads/stores and pointer extraction require unsafe too.
Foreign ABI/effect contracts and pointer preconditions are listed in reports
as assumptions. No safe wrapper is inferred solely from a C declaration.
Supported types do not make arbitrary C implementations memory-safe.

No_std object/library generation rejects hosted allocation, I/O and tasks.
Standalone no_std objects/static libraries use a spin-loop panic handler.
This is an explicit non-returning fault policy, not a hardware reset policy.
The current implementation does not provide a bare-metal binary entrypoint.
No_std binary requests are rejected. Cross-compilation evidence is distinct
from device execution, drivers, DMA, MMIO, interrupts, startup and GPU kernels.

## Non-goals of this release

General algebraic data types, Result syntax, user-defined generics, imports,
closures, channels, async/await, C header importing, bitfields, packed layout,
varargs, arbitrary callback lifetime protocols, refined functional contracts,
an independent backend, a self-hosted compiler and formal soundness are still
open work. Their absence is recorded in the blocker ledger, not silently
reclassified as a completed production requirement.
