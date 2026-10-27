# Independent C backend: owned values and finite specialization

The hosted C11/GCC backend accepts `Buffer<u8>`, owned structs, tagged enums,
`Result`, consuming `match`, and finite `Copy` / `Owned` function generics.
The compiler emits C directly from its checked AST. No Rust source, compiler,
borrow checker, object, or metadata participates in this path. There is no
fallback to Rust when a C feature is unsupported.

## Ownership gate and representation

Programs with owned expressions, generic functions, or returned borrows first
lower their whole program to the independent resource CFG. The compiler
serializes and verifies that graph before emitting any C. This includes unused
generic function bodies; an uninstantiated owned function may not leak its
parameter. Overlapping mutable/read loans, a move under an outstanding loan,
and failure to consume an owner on a normal exit reject C compilation.

This is a checked abstraction, not a proof that Python lowering preserves
every source or scalar semantic. The source-to-IR and source-to-C refinement
claims remain false. The actual native code is emitted from the AST, with
the resource graph acting as a required gate for this profile.

`Buffer<u8>` is represented by a pointer and length. A zero-length buffer does
not allocate. Nonempty buffers use zero-initialized `calloc` storage and are
limited to `PTRDIFF_MAX` bytes. `try_buffer` returns `Result::Err(1)` on size
or allocation refusal and can be retried. `buffer` aborts on refusal.
Recursive `drop` frees every owned struct field or the active enum payload,
exactly once along each accepted normal path. Invalid internal enum tags abort.
There is no collector, reference counting, per-object registration, or implicit
heap allocation for generic or ADT values.

The generated C may contain inert copies of an owned representation while
transferring it. Only the destination remains usable according to the source
checker and independent resource verifier. Inactive copies have no automatic
C destructor. Only explicit `drop`/`release` and consuming callee cleanup invoke
the generated destructor. As with the existing Rust `panic=abort` profile,
process abort does not promise unwinding or destructor execution.

## Concrete generics and immediate borrowed results

Every reachable generic function receives a concrete specialization for its
ordered type arguments. Specializations use value layouts and ordinary C calls.
Repeated recursion at the same concrete type reuses the same function.
Potentially expanding polymorphic recursion is bounded by 512 total function
instances, 64 levels / 4,096 nodes of type arguments, 4,096 argument spelling
characters, and 4,096 value types / 128 active layout levels. Exhaustion is
`E_C_SPECIALIZATION_LIMIT`; it never produces a partial artifact.

Generic structs and enums have concrete layouts. Generated type/instance names
use compiler-owned namespaces and distinct indices rather than concatenating
user names with unverified type strings. User struct names such as `array_0`
cannot collide with generated array layouts.

Read/mutable borrowed returns use C pointers; returned slices use a pointer and
length. They remain immediate source places, not first-class local references.
Call arguments are materialized in source order. The independent loan gate
tracks a returned view through subsequent reborrows and rejects overlap with a
later mutable borrow or owner transfer. Distinct named struct fields remain
disjoint. An explicit `from parameter` origin can select one borrowed input;
non-origin argument loans end after that call, while the selected origin stays
live through its consumer. Borrowed results do not acquire a public C ABI.

The resource-IR-v3 place extension also supports moving individual nested owned
struct fields and restoring an entirely moved field. C lowers the checked move
to a representation transfer and the restoration to a field assignment. A
fully consumed aggregate has no C destructor left to run. The source checker
and graph verifier reject reading, moving or dropping missing fields, and
reject overwriting live owned fields. Native C allocator tests cover early
returns, real allocation refusal/recovery, and five loop restorations: the
tested sequence reports 16 allocations, 16 frees, zero live allocations and
one refusal.

## Reproduction and observations

```sh
python -m hepta build examples/c_owned_backend/main.hepta --backend c -o artifacts/c-owned-example
artifacts/c-owned-example
python tools/validate_c_owned.py --output artifacts/c-owned-qualification.json
python -m unittest tests.test_c_owned_backend -v
```

The qualifier requires a fresh output name, retains generated C/Rust and the
resource graph, and records actual native compiler/artifact identities. It runs:

- A two-file owned generic library on both C and Rust: 128 sizes × success/error
  = 256 paired calls. Both independently checked outputs must equal `13504`.
- Six allocator cases per backend: normal ownership, early error cleanup,
  actual allocator refusal, successful recovery, oversized refusal, and empty
  allocation. Each reports exactly three allocations, three frees, zero live
  allocations, and one actual allocator refusal.
- A separately compiled C mutation that removes the Buffer destructor. Its
  observed `3 0 3 1` allocation trace and unsuccessful exit are mandatory.
- Six rejection controls, including aliasing, move-under-loan, an unused
  generic leak, raw/owned combination, specialization exhaustion and tasks.

All C executions use GCC undefined-behavior sanitization with recovery disabled.
The report validator checks raw/native identities, exact observations and
denominators, verifies the retained CFG again, and rejects upgraded proof claims.
The unit tests also exercise consuming nested enums, disjoint field loans,
mutable returned slices, local loop allocations, and source-line directives.

The qualifier's artifact paths identify the actual run. Reproduce on another
checkout by rerunning the command into a new output rather than relabeling old
report identities. This is a correctness/resource qualification; it makes no
performance comparison claim.

## Remaining scope

This increment is host-only, uses a checked 64-bit C data model, and retains
the existing checked arithmetic and bounds behavior. Tasks, channels, native
async I/O, raw pointers combined with this owned/generic graph profile, stored
references, general traits, and C ABI export of enums/owned values remain
outside this backend profile. Some otherwise valid Rust-backed expressions
are conservatively rejected when the resource abstraction cannot represent
them, including borrowed projections that the graph cannot retain and some
`Unit` payload/call combinations. There is no complete-language backend or
soundness/refinement claim.

Function and statement `#line` directives preserve Hepta source names and line
numbers for compiler diagnostics and optional native debug information. Every
generated physical instruction line resets the owning source number, so
temporaries cannot acquire the following Hepta statement's location. This
alone does not certify debugger behavior; that requires an actual debugger run.
