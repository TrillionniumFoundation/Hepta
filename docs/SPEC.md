# Hepta 0.2 implemented semantics

This document specifies the implemented bootstrap language and its supported
compilation profiles. It does not make every feature in the research proposal
part of the language. The specification, compiler snapshot, and executable
evidence must agree; a discrepancy is a defect.

## 1. Compilation profiles and trust

UTF-8 source is parsed into a closed AST. The module loader resolves an explicit
file graph, checks imported-name visibility, and renames declarations in the
AST. The shared frontend checks declarations, types, effect upper bounds, and
normal-path resource flow. Source fragments are never inserted verbatim into
generated Rust or C.

The default Rust profile lowers checked AST nodes to Rust and uses pinned
rustc 1.90.0 for native type/borrow validation and machine-code generation.
Generic bodies are checked parametrically by Hepta and lowered to bounded Rust
generics; Rust performs monomorphization. Optimized builds use edition 2021,
opt-level=3, overflow-checks=yes, panic=abort, and one codegen unit. No LTO,
fast-math, or native-CPU tuning is silently enabled.

The optional `--backend c` profile lowers a smaller subset directly to C11 and
GCC-compatible native compilation. It does not generate Rust or invoke rustc.
It shares the frontend and supplies separate conservative borrow checks. Its
current qualified data model requires 8-bit bytes and 64-bit `size_t` and
`intptr_t`. Unsupported syntax or semantics fail closed; there is no automatic
fallback from C to Rust. Section 12 defines the subset boundary.

`check` compiles validation metadata or an object; it does not execute the
user program or prove that a future final link will succeed. `build` performs
the requested artifact build. `run` builds and executes a binary. A
`frontend_only` result explicitly skips the native gate and is not equivalent
to a complete check.

The trusted components include this parser/loader/checker/lowering, the selected
compiler and linker, runtime libraries, the execution environment, and accepted
foreign contracts. Compiler identity and nonempty-artifact checks prevent
accidental wrong-tool acceptance; they do not attest an adversarially forged
toolchain. There is no proof of whole-language soundness or of either actual
backend's translation correctness.

## 2. Lexical rules and source positions

Identifiers are ASCII. Comments support Unicode and use `//` or nested
`/* ... */`. Numeric literals include the supported integer bases and finite
floating literals. Strings are accepted only as the ABI literal `"C"` in an
ABI clause. Arbitrary string values, macros, method calls, indirect calls, and
raw target-language escape blocks are unsupported.

Qualified names use `::`; explicit expression type arguments use `::<...>`.
The compiler's generated `M` + 16 lowercase hexadecimal digits + `_` module
namespace is reserved and cannot be spelled in project source.

AST spans use zero-based Python Unicode code-point offsets with an exclusive
end, and one-based line and column. They are not UTF-8 byte or LSP UTF-16
offsets. CRLF counts as one newline. Function spans include the entire
declaration; body spans include both braces. Syntax and AST depth limits
produce positioned diagnostics rather than exposing arbitrarily deep trees to
later recursive passes.

## 3. Modules, visibility, and local packages

A file may begin with an informational module name, then import declarations:

```hepta
module app::main;
import model;
import utilities::math as arithmetic;
```

The final path component is the default alias. A local import resolves from the
owning package's `source_root`; a standalone project uses the entry file's
directory. If the first component names a manifest dependency, resolution uses
that dependency's entry or source root. Imports must precede declarations.
Cycles, missing files, duplicate aliases, alias/declaration collisions, and
source-root escapes are rejected. The same resolved file is loaded once.
File identity owns the namespace; `module` spelling does not redirect imports.

Files may declare structs, enums, functions, and `extern "C"` functions. Use
`pub struct`, `pub enum`, or `pub fn` to make a named declaration importable.
`extern "C"` and `export "C"` functions are also available through their
module aliases. Private helper names remain available inside their own module.
An imported type/function is referenced as `alias::Name`; an imported enum
variant is `alias::Enum::Variant`. Re-export declarations and glob imports are
not implemented. Visibility is checked during name resolution, not treated as
a security boundary against arbitrary access to the repository's files.

An optional `hepta.toml` declares a local package:

```toml
[package]
name = "application"
version = "0.2.0"
kind = "bin"
source_root = "src"
entry = "src/main.hepta"

[dependencies]
math = { path = "../math" }
```

`name` is an ASCII identifier and `version` is an explicit `major.minor.patch`
triple. `kind` is `bin` or `lib`. The default source root is `src`; default
entries are `src/main.hepta` and `src/lib.hepta`. Dependencies must be local
path dependencies declaring `kind = "lib"`. Network/registry resolution,
version solving, build scripts, and package plugins are not implemented;
unknown manifest keys are errors.

`hepta lock PACKAGE` records manifests, dependency topology, all `.hepta`
sources under the participating source roots, and adjacent C-import sidecars
in `Hepta.lock`. `--locked` requires an exact matching snapshot, including
currently unimported source files. This is content locking of local packages,
not a signature, remote provenance guarantee, or record of arbitrary linker
inputs. Source edits require a refreshed lock.

The project report identifies the resolved entry, source hashes, resolved
import edges, and package state. Lexical path bindings are rechecked as well,
so retargeting an import symlink cannot silently preserve a validated graph.
Equivalent requests through a package directory, its manifest, and its entry
identify the same resolved project. Validation covers the complete loaded
graph; it is not whole-repository impact analysis or an incremental verifier.

## 4. Types, declarations, and parameter modes

The shared frontend supports:

- Signed and unsigned fixed-width integers through 128 bits; `isize`, `usize`,
  `f32`, `f64`, `bool`, and `Unit`.
- By-value structs and enums, including supported resource payloads, and
  fixed arrays `[T; N]` with Copy elements.
- Unsized slices `[T]`, behind `read`/`mut` parameters, immediate borrowed returns or supported stored-reference fields.
- Raw pointers `raw const T` and `raw mut T`.
- Linear `Buffer<T>` owners; the allocation builtin currently constructs only
  `Buffer<u8>`.
- Local linear `Task<u64>` and `TaskGroup` handles.
- Unconstructible `Cancellation` and `Sender<u64>` capabilities, accepted only
  as `read` parameters.
- The runtime's ordinary Copy `GroupReport` snapshot type.
- Lifetime-parameterized shared/mutable borrowed records in the bounded Rust profile.
- Linear hosted `IoReactor` / `IoRequest` owners and Copy I/O reports.

Backend and ABI profiles further restrict these types. In particular, shared
frontend acceptance does not imply C-backend support.

Functions require an explicit return type and `effects { ... }`. Extern
declarations have no body and end with `;`. Implemented functions may add a
`resources` clause. Parameter modes are value, `read`, `mut`, and `take`.
Owning Buffer and resource-bearing data parameters require `take`. Calls supply explicit `read`, `mut`,
or `move` syntax for the corresponding modes. Bare reads of a borrowed Copy
value read its contents; Rust lowering dereferences the parameter borrow.

Local bindings are immutable unless declared `let mut`. Local shadowing and
standalone reference local values are rejected. View records may store
`read 'a T` / `mut 'a T` fields with up to eight named lifetime parameters;
multiple regions, shared copies, affine mutable views and nested views retain
native Rust lifetime checking. Outlives clauses, higher-ranked bounds, mixed
type/lifetime parameters, self-referential ownership, stored capabilities and
arbitrary storage inside ADTs/arrays remain excluded; see `BORROWED_STORAGE.md`.
A returned
read/mut view derives from the unique borrowed input or the input named by
`-> read/mut Type from parameter`; see `PARTIAL_PLACES.md`.
Task and TaskGroup handles cannot be user-function
parameters or returns. GroupReport cannot be constructed with a source struct
literal; runtime operations return it, after which it is a normal Copy value.

## 5. Finite generic constraints, enums, and Result

Generic functions, structs, and enums declare type parameters with `<T, E>`:

```hepta
pub struct Pair<T, E> { left: T, right: E }
pub enum Maybe<T> { None, Some(T) }

fn identity<T>(value: T) -> T effects {} { return value; }
fn forward<T: Owned>(value: take T) -> T effects {} { return move value; }
```

Function parameters default to sized `Copy`; explicit `T: Copy` has the same
meaning. `T: Owned` instead requires a supported sized resource value and
checks an ownership obligation for every such parameter/local. Generic data
declarations can be instantiated with either Copy or supported Owned values.
The compiler checks every generic body, even when it is never instantiated.
Copy parameters can be copied; Owned parameters require transfer, borrowing or
drop. Both can be placed in known generic constructors, matched through known
enum types, and passed to compatible generic functions. Neither implies
numeric, equality, ordering, or other operator capabilities. Trait declarations,
specialization, higher-kinded/const generics, general lifetime constraints, and
higher-order functions are not implemented. Explicit bounded record/function
lifetime parameters are a separate profile and cannot be mixed with these
type parameters.

Function calls require explicit type arguments, such as
`identity::<u64>(17)`. Constructors can also be explicit:
`Pair::<u64, bool> { left: 17, right: true }` and
`Maybe::<u64>::Some(17)`. A constructor may obtain arguments from an exact
expected nominal type, as in `let item: Maybe<u64> = Maybe::Some(17);`.
This is limited contextual constructor inference, not general type-argument
inference for calls. Duplicate/shadowing type parameters and unused
struct/enum parameters are rejected. Generic `main` and generic C boundary
functions are rejected. Compiler monomorphization limits still apply.

Enums have named unit variants or positional payload variants. Unit variants
omit parentheses. Payload arity and types are checked. Payloads and generic
arguments may contain Buffer and supported resource-bearing data. Scoped Task,
TaskGroup, Cancellation and Sender capabilities cannot be stored in data types
or passed as function type arguments. Resource arrays, resources behind raw
pointers and nested resource buffers remain unsupported, including through
generic substitution. Whole owned values and nested named owned struct fields
move explicitly. A completely moved-out field can be restored in a mutable
local aggregate while its enclosing structs remain initialized. Every exit
consumes each remaining owned leaf; see `PARTIAL_PLACES.md`.
Recursive by-value layouts are rejected across structs and enums. The layout
check tracks generic arguments used by value, so supported raw-pointer
indirection can break a layout cycle; this does not prove pointer validity.

`Result<T, E>` is a reserved enum with `Ok(T)` and `Err(E)` and lowers to
`core::result::Result`. It supports explicit constructors and expected-type
inference. There is no `?` operator or exception propagation. A Result with an
owned payload, such as `Result<Buffer<u8>, E>`, is itself an owner even when its
current variant contains only copied data. `OWNED_GENERICS.md` specifies finite
constraints and the independently verified generic resource graph profile.

## 6. Exhaustive statement matching

```hepta
fn choose<T>(value: read Maybe<T>, fallback: T) -> T effects {} {
    match value {
        Maybe::None => { return fallback; },
        Maybe::Some(payload) => { return payload; },
    }
}
```

`match` evaluates its scrutinee once and requires every variant exactly once.
Patterns name the exact enum and variant. Payload names are immutable and
scoped to one arm; `_` ignores one payload. Missing/duplicate variants,
wrong enum names, and payload arity errors are rejected.

Matching a borrowed Copy enum copies its selected payload values; patterns do
not return references. Matching an owned enum consumes it with `match move`;
each owned payload must be bound and consumed, so `_` cannot discard it.
Match expressions, guards, nested or alternative
patterns, integer patterns, and catch-all arms are unsupported. All arms
participate in effect and ownership checking. Returning arms must discharge
live owners; every continuing arm must leave the same owners live.

## 7. Expressions, arithmetic, and evaluation

Named calls, struct/array construction, fields, indices, casts, unary operators,
and the supported arithmetic/comparison/bitwise/logical binary operators use
the parser's conventional precedence. Default literals are `i64` and `f64`;
expected types can constrain them. Integer range checking includes native
target checks for pointer-sized integers.

Evaluation preserves left-to-right argument/operand evaluation and short
circuiting of `&&` and `||`. The C backend uses ordered temporaries for its
supported expressions. Regular integer arithmetic has enabled overflow checks
in both optimized and unoptimized profiles. `wrapping_add`, `wrapping_sub`,
and `wrapping_mul` operate modulo the integer width. Indexing, division,
remainder, shifts, and integer negation have conservative panic effects.
Failed runtime guards abort.

The Rust profile uses ordinary Rust numeric casts and floating semantics,
without fast-math. The C subset supports basic floating arithmetic but rejects
float/integer casts; its supported integer casts and wrapping operations use
explicit bit semantics. Pointer/integer conversion and arbitrary pointer
reinterpretation are rejected. Converting `raw mut T` to `raw const T`
requires unsafe and preserves the pointee type.

Statements include bindings, assignments, returns, expression statements,
`if`/`else`, `while`, half-open `for name in start..end`, `unsafe` blocks, and
exhaustive matches. Unsupported statement forms are errors.

## 8. Effects and resource clauses

Known effects are `alloc`, `panic`, `io`, `block`, `spawn`, `ffi`, `unsafe`, and
`write`. Declarations are upper bounds. The checker visits all bodies and
iterates call-graph effects to a fixed point across loaded modules and generic
calls. Unknown or missing effects are errors. Mutating a local variable alone
does not create `write`; mutation through borrowed inputs, raw stores, and
modeled channel operations does.

| Operation | Conservative intrinsic effects |
| --- | --- |
| `buffer` | alloc, block, panic |
| `release` | alloc, block |
| `print_i64` | io, block, alloc, panic |
| `assert`, checked indexing | panic |
| Wrapping arithmetic, `len`, `min`, `max` | None |
| Raw load, pointer extraction | unsafe |
| Raw store | unsafe, write |
| Volatile integer load | unsafe, io |
| Volatile integer store | unsafe, io, write |
| `spawn` | alloc, block, spawn, panic, plus worker effects |
| `join`, `cancel_and_join` | alloc, block, panic |
| `cancelled` | No modeled allocation/blocking effect; an atomic read |
| `task_group`, `group_snapshot` | alloc, block, panic |
| Group send/receive/seal/fail/join operations | alloc, block, panic, write |
| `group_spawn` | alloc, block, spawn, panic, write, plus worker effects |

`alloc` covers allocator interaction, including deallocation. Therefore
`heap_allocations=0` conservatively excludes `release` too. Supported function
clauses are exactly `heap_allocations=0`, `may_block=false`,
`may_suspend=false`, and `may_spawn=false`. Wrong literal types, unsupported
clauses, and other numeric values are rejected. Suspension is not implemented.
These clauses do not prove process-wide memory, CPU, or thread-count bounds.
TaskGroup runtime budgets are a separate mechanism described below.

## 9. Linear resources and hosted tasks

A local Buffer must be released, moved into a `take` argument, or explicitly
moved into a Buffer return. Task/TaskGroup handles must be joined locally.
Continuing branches preserve compatible live-owner sets; repeated loops cannot
consume incoming owners while continuing. Local owners must be consumed on
each normal scope exit, including early returns. Double moves, moves of
borrowed resources, discarded owners, short-circuit consumption, and hidden
resource temporaries are rejected.

This is a normal-path property. Abort, process failure, infinite loops, and
external failure do not receive eventual-cleanup guarantees.

`spawn(worker, move data)` requires an implemented, nongeneric worker with
signature `(take Buffer<u8>, read Cancellation) -> u64`. Its complete
transitive effects cannot include `spawn`, `unsafe`, or `ffi`. The runtime
creates an OS thread and transfers the buffer without cloning it.
`join(move task)` waits; `cancel_and_join(move task)` sets a shared atomic flag
with Release ordering and waits. `cancelled(read token)` uses Acquire ordering.
Cancellation requires worker cooperation. Task locality prevents implicit
normal-path detachment; it does not bound worker duration or prove global
thread-count limits, deadlock freedom, or termination.

## 10. Bounded task groups and channels

`task_group(task_limit, input_byte_limit, queue_slots)` creates one local linear
group with a fixed `u64` channel. The limits bound total admissions during that
group's lifetime, cumulative lengths of admitted input buffers, and queued
message count. Finished admission slots are not recycled. Queue capacity must
be positive; dynamic values are checked at runtime.

`group_spawn(mut group, worker, move data)` consumes the input on both success
and rejection. Group workers have exactly
`(take Buffer<u8>, read Cancellation, read Sender<u64>) -> u64`, are nongeneric,
and obey the same transitive worker-effect restrictions as ordinary tasks.
`Sender<u64>` is a runtime-supplied read capability, not an owned channel value.

| Operation | Semantics |
| --- | --- |
| `group_send(read sender, value)` | Blocks while full; returns false after closure/cancellation/failure. |
| `group_send_timeout(read sender, value, milliseconds)` | Timed send returning `Result<bool,u8>`; one monotonic deadline across wakeups. |
| `group_seal(mut group)` | Ends admission. |
| `group_receive(read group, mut value)` | Requires sealing; receives into a u64 destination or returns false when closed and drained. |
| `group_receive_timeout(read group, mut value, milliseconds)` | Timed receive; unchanged destination on timeout or closed/drained channel. |
| `group_cancel(mut group)` | Closes/discards the channel and requests cooperative cancellation; preserves the obligation to join. |
| `group_join(move group)` | Requires a drained channel and joins all admitted workers. |
| `group_drain_and_join(move group)` | Seals, discards remaining messages while draining, then joins. |
| `group_cancel_and_join(move group)` | Requests cancellation, closes/discards queued messages, wakes channel waiters, and joins. |
| `group_snapshot(read group)` | Returns a Copy observational GroupReport without joining. |
| `group_fail(read sender, code)` | Reports a nonzero cooperative error; the first error wins and requests sibling cancellation. |

Join operations return GroupReport with task, admission, queue, result, failure,
and cancellation observations. Reports are copyable data, not attestations.
Unsealed receives and undrained normal joins fail runtime guards. Panic still
aborts the process; `group_fail` does not contain panics or forcibly terminate
workers. OS thread-creation errors are handled by rejecting the admission and
releasing transferred input.

Timed operations accept `u64` milliseconds and return `Ok(true)` on progress,
`Ok(false)` on closure, `Err(1)` on observed timeout, or `Err(2)` for an
unrepresentable host deadline. Zero duration polls readiness. Timeout itself
does not cancel or consume the group. Mutex scheduling and joining are not
hard real-time bounded; see [BOUNDED_CONCURRENCY.md](BOUNDED_CONCURRENCY.md).

`resource_contracts` reports these budgets as
`scope=one_runtime_instance` and
`enforcement=runtime_admission_and_fixed_queue`. They exclude other groups,
pre-submission allocations, worker allocations, stacks, runtime metadata,
allocator overhead, process RSS, CPU time, and cancellation latency. There is
no general `select`, async executor, or channel type parameter beyond u64.
See [BOUNDED_CONCURRENCY.md](BOUNDED_CONCURRENCY.md) for the complete API.

### Shared reservations, trees and hosted I/O

`group_select_receive` uses event registration across two groups. Explicitly
attached groups can share thread/input/queue/requested-stack reservations; the
same fixed counters do not cover arbitrary worker/FFI allocations or process
RSS. See `SHARED_RUNTIME.md`.

`group_adopt(mut parent, move child)` transfers the actual child's subtree and
join ownership into its parent. Admission is bounded to 256 groups and 16
levels. Refusal still consumes, cancels and joins the child; it can block until
cooperative workers finish. Cancellation propagates down, failure reaches the
root and siblings, and both old flat and new tree join interfaces wait for
descendants. Snapshot reports are observations, not global atomic snapshots.
`TASK_TREES.md` defines topology locks, effects, budget identity and the
independent concurrent IR's normal-exit adoption protocol.

The hosted I/O profile has owned `IoReactor` and `IoRequest` values, tokenized
local socket endpoints, nonblocking operations, an explicit `io_poll` readiness
pump, monotonic deadlines, cancellation and explicit completion consumption.
Only `x86_64-unknown-linux-gnu` is admitted. It has fixed metadata/request limits
and counts actual retained Buffer capacity. `ASYNC_IO.md` specifies refusal,
partial progress, EOF, shutdown and remaining obligations. This is not
async/await, TCP/TLS, an executor, or composition with task-tree cancellation.

## 11. C ABI and native header import

Supported C boundaries include numeric scalars through 64 bits, pointer-sized
integers, raw pointers, and nonempty nongeneric `repr(C)` structs with
compatible fields. Arrays may appear in supported struct fields or as pointer
pointees, not directly as function parameters/returns. `Unit` maps to a void
return/pointee. Bool, 128-bit integers, zero-length array fields, ordinary
language-layout structs, enums, Result, generic structs/functions, owned
resources, capabilities, GroupReport, and slices are excluded.

Generated headers include standard integer/size headers, use `hepta_Name`
typedefs, preserve accepted field and external-symbol names, and provide C++
extern-C linkage. Imported module type names may be resolved internal names in
these generated typedefs. The checker rejects conflicting C/C++ keywords,
standard/generated typedef and macro names, and implementation-reserved
boundary names. Language enums and generic layouts have no stable C ABI promise.

External calls, calls with an unsafe effect, raw loads/stores, and pointer
extraction require an explicit unsafe block. Reports retain foreign effect/ABI
assumptions and raw-memory obligations. No ownership, lifetime, thread-safety,
or hardware-ordering proof is inferred from a C signature.
An exported or public function with `unsafe`/`ffi` effects is also emitted as
an unsafe public Rust function. Consuming its generated Rust library must not
erase these caller obligations. C calling conventions remain unchanged.

`hepta import-c HEADER -o bindings.hepta` parses a restricted declaration
subset, compiles and executes a native C probe, and emits public C-compatible
structs, extern declarations, constant-accessor functions, and an
`imports.json` sidecar. Facts include actual native type/layout/constant data
and toolchain/probe hashes. Foreign functions conservatively declare all known
effects unless a caller supplies an explicitly assumed narrower contract via
the Python API. Unsupported declarations and preprocessing fail closed.

Project loading checks the binding-source hash and host fingerprint against
the generated sidecar. An available original header inside its owning package
also participates in identity checking; loading does not read arbitrary
external header paths from sidecars. Native import facts are not portable ABI
proofs, and projects containing these imports currently reject any explicit
`--target` request. See [C_INTEROP.md](C_INTEROP.md) for exact accepted header
constructs.

## 12. Independent C backend subset

The C profile supports scalar integers through 64 bits, native-size integers,
bool, basic floating arithmetic, supported nongeneric structs, nonempty fixed
arrays, borrowed slices, read/mut scalar or struct parameters, ordinary calls,
conditionals/loops, checked indexing, and supported raw-pointer operations.
Its borrow arguments must be named places. Multiple borrows of one root reject
if any is mutable; this deliberately rejects some disjoint-field cases.
Effectful nested calls in borrowed argument lists, indices, and raw-store
operands are conservatively rejected.

Integer arithmetic, division/remainder, shifts, wrapping operations, casts,
and indices use explicit checked/bit-level lowering. Failed checks abort.
GCC diagnostics and Rust constant-evaluation diagnostics need not coincide.
The owned C profile additionally supports Buffer-bearing structs/enums, Result,
finite generic monomorphization, explicit returned borrows and partial named
field moves/restoration. That profile must pass the independent resource IR
before C emission; native error/cleanup behavior is qualified separately in
`C_OWNED_BACKEND.md`. Stored lifetime records and hosted task/group/I/O runtimes,
unsupported zero-sized layouts, pointers to arrays, `repr(C)` array fields and
float/integer casts remain rejected. No silent substitution or Rust fallback is
permitted.

The C compiler API supports bin, object, static-library, and shared-library
artifacts. Default C `check` analysis uses an object validation artifact rather
than a Rust rlib. Explicit foreign targets and `--no-std` are rejected. A
successful C report leaves Rust borrow validation `not_run` and records its
own `c_types_codegen` result and `rustc_used=false`.

## 13. Rust no_std and hardware scope

The Rust profile can generate supported no_std objects/libraries and rejects
hosted allocation, printing, tasks, groups and the hosted I/O reactor. An I/O
effect alone does not require std: integer volatile access or explicit BSP
foreign calls may be used in a no_std library. Standalone no_std object/static-library
profiles use an explicit spin-loop panic handler. This is a non-returning fault
policy, not a reset policy. A general bare-metal Hepta binary entrypoint is not
implemented; a supplied Rust/assembly BSP can link the generated library.

Target compilation, emulated ISA execution, and physical-device execution are
distinct evidence. `SYSTEM_BOARD.md` specifies the implemented volatile contract
and the pinned Cortex-M4 QEMU system profile: actual reset, linker/data/BSS
initialization, UART MMIO and external timer IRQs, with compiled negative
controls. The AArch64 user-mode harness remains a separate ISA execution gate.
Neither emulator qualifies physical boards, DMA, interrupt ownership soundness,
GPUs, hardware timing or arbitrary foreign implementations on every target.

## 14. Agent transactions, proof scope, and remaining work

Inspection and body-only patch protocols are specified in
[AGENT_PROTOCOL.md](AGENT_PROTOCOL.md). V1 is a single-source operation; v2
binds one body replacement to the loaded dependency graph and frozen interface.
V2 uses shared per-source locks so overlapping graph transactions coordinate.
Neither protocol proves that the new body computes the old result.

Separate Lean artifacts check abstract loan-count resource transitions,
task-group admission/queue bounds, and a wrapping-expression-to-stack-machine
translation. They are not proofs about the actual Hepta AST/checker,
emit_rust/emit_c, raw pointers, FFI, scheduling, or hardware. Normal check/patch
does not invoke a general functional prover. See [formal/README.md](../formal/README.md).

Remaining work includes general combinations of stored borrows and ADTs, richer
trait and lifetime systems, closures, async/await, general channels/select, broad C/C++
header support, stable generic/enum foreign layouts, verified refinement from
the abstract proofs to the implementation, a self-hosted compiler, and wider
production qualification. The executable agent pilot is an evaluation harness;
fixture qualification provides no measured AI productivity advantage.
