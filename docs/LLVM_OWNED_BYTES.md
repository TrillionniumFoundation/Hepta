# Direct LLVM lowering for owned bytes

The owned-byte host profile compiles actual checked Hepta source to LLVM IR
and uses Clang to produce a Linux x86_64 object or shared library. Application
functions, control flow, values, moves and drops are emitted from the checked
syntax. No generated Rust or C code supplies the machine code.

The source-facing command is:

    python3 -m hepta.llvm_owned_pipeline examples/llvm_owned/main.hepta \
        --output /new/path/owned.so --clang clang --rustc /path/to/rustc

Add --kind object for a host object. A pre-existing output or symlink is
rejected, and publication uses a staged file plus a no-replace hard link.
There is no foreign-target resource mode and no automatic fallback.

## Closed scope

- Buffer<u8>, initialized to zero; buffer and fallible try_buffer.
- Finite structs/enums/Result containing supported scalar and owned fields.
  Their native layouts are private to this LLVM module.
- Integer types through 64 bits, usize/isize on the fixed 64-bit host, bool
  and Unit; checked arithmetic, comparisons, integer casts and wrapping
  operations used by the resource code.
- Ordinary source functions, explicit take/move/drop/release, named field
  transfer/restoration, if/while/half-open for and exhaustive enum matching.
- Immediate read/mut borrows of supported values and byte slices, including
  checked borrowed returns, byte indexing, len and mutation.
- Finite Copy/Owned generic function instances and aggregate layouts. All
  generic source bodies still pass the shared and independent resource gates;
  code is generated only for concrete instances. Limits are 256 function
  instances, 256 concrete native aggregate layouts and depth 32/4096 nodes
  per concrete type, and 256 scalar/pointer leaves per aggregate return.
- Public C exports contain only supported ordinary scalar values. Internal
  pointers, owner layouts and slice descriptors do not cross that boundary.

Stored lifetime records, arrays, floating point, 128-bit values, raw pointers,
foreign declarations, tasks/groups/I/O and target-specific resource ABIs are
outside this profile. Unsupported concrete expressions and types reject before
publication.

The LLVM owned profile additionally preserves **the finite source-checked
resource clauses** `heap_allocations=0`, `may_block=false`,
`may_suspend=false` and `may_spawn=false` when their precise types and
transitive effect exclusions have already been established by the frontend.
These are compile-time restrictions; they are not a whole-process memory/CPU
budget, allocator instrumentation, or an extra LLVM runtime promise.
Conflicting `alloc`, `block` or `spawn` effects and unknown clauses fail
closed. Foreign functions remain forbidden on this backend, so external
contracts cannot silently satisfy these clauses. This is separate from the existing scalar
SSA backend; it does not widen that backend's proof claims.

## Source and resource checks

The source entrypoint freshly loads the actual project, runs the shared
checker and pinned native Rust reference metadata validation, and constructs
the canonical typed semantic snapshot and independent resource graph.

The resource graph deliberately abstracts numerical values. The LLVM emitter
therefore consumes the exact checked AST for numerical/control-flow code,
after independently verifying that AST's resource projection. The graph is
not misrepresented as executable numeric IR or a proof of native memory
operations.

Before invoking Clang, the native API regenerates the entire LLVM module from
the supplied checked source again and requires exact equality, including
concrete generic instances, aggregate/Result tags, borrow operations and drop
helpers. Receipts bind the semantic, resource graph, resource verification,
compiler and LLVM hashes. The source-facing pipeline additionally checks the
actual source inventory before and after native compilation, and checks the
staged artifact against its receipt before publication. A rehashed altered
LLVM body cannot pass this gate.

As with other source replay paths, these checks do not create an atomic
filesystem snapshot against a noncooperating concurrent writer.

## Allocation and cleanup

An internal Buffer is a pointer/length pair. A zero-length buffer performs no
allocation. Sizes above isize::MAX and a null allocation result produce
Result::Err(1); buffer uses the same operation and aborts if it fails.

The small native runtime uses malloc followed by explicit LLVM zero
initialization, then free on drop. Clang may combine allocation and zeroing
into calloc, so native failure instrumentation wraps both allocation APIs.
The malloc declaration/call carries the no-builtins boundary. A tiny LLVM
runtime entry with noinline/optnone preserves that fallible native call:
merely marking malloc while permitting normal free recognition allowed Clang
to remove constant allocations in actual counter tests. The explicit entry
restores the same 7/7 and nested 11/11 allocation/free observations without
changing failure branches. Standard free retains its ordinary library contract: it releases storage
without reading the user payload. This permits deletion of unobserved stores
before cleanup without asserting that malloc succeeds. Custom deallocators
that inspect payload bytes are outside this profile. Both the successful and
injected-refusal native counters must continue to pass after optimization.
LLVM documents its built-in recognition and allocation-family semantics in the
[LLVM 20 language reference](https://releases.llvm.org/20.1.0/docs/LangRef.html#function-attributes).

An explicit move materializes the value and clears the moved-from owned
place. Independent resource checking must already reject reuse, overlapping
loans and duplicated ownership; clearing is not a substitute for those
checks. Generated drop helpers recursively release only the active enum
variant and the owned fields. The existing language rejects whole-parent
drop after a field move until that field is restored; the backend does not
invent a destructor for a partially initialized remainder.

Internal aggregate and slice results use a fresh caller-owned result slot.
Its noalias property describes the result-slot storage, not the borrowed
data pointer inside a returned slice. Fields are written individually so
optimization can track Result tags and payloads across inlined returns.
Scalar public C signatures are unchanged. Empty buffers skip free because
standard free(NULL) has no observable effect in this runtime. These changes
let the ordinary optimizer eliminate dead initialization on constructor
rejection and redundant bounds checks whose equality follows from the source;
no bounds or overflow guard is omitted based on benchmark inputs.

Every supported normal or explicit error return must discharge its live
owners. Bounds failures, arithmetic failures and infallible allocation
failures abort, matching the selected abort-on-panic profile. No eventual
cleanup is claimed for abort, process termination or nontermination. The
allocator, machine, compiler and operating system remain trusted components.

## Executed validation

With actual Clang 20.1.2, pinned Rust 1.90.0 and GCC:

- Eleven new tests completed without skips.
- The same owned-library source executed 996 deterministic cases on LLVM,
  Rust and the independent C backend: 2988 matching observations. Cases
  exercise byte writes/reads, returned slice access, moves, zero length,
  constructor rejection, early cleanup, range errors and oversized refusal.
- Additional initialization/generic-transfer checks agreed on all three
  backends. Six child-process bounds/overflow cases all aborted.
- A native allocator oracle observed 7 allocations, 7 frees, zero live
  allocations and one injected allocation failure. The failed second
  allocation occurs while the first owner is still live and must release it.
- Nested generic structs in the second and third owned enum variants, an
  empty owned enum variant, and partial field move/restoration followed by
  whole-owner drop produced 11 actual allocations and 11 frees with no live
  allocation. GCC C callers also checked u8/u16 zero extension and i8/i16
  sign extension across the native LLVM export ABI.
- A deliberately compiled wrong LLVM module with free removed was rejected
  by the native allocation oracle. Clang can eliminate unused allocations in
  this wrong program; the test requires that its actually observed remaining
  allocations leak, rather than inventing counts for removed operations.
- Rehashed code alterations fail before Clang is called. Independent
  resource checks reject an owner move while an earlier argument loan is
  active. A source change after native compilation prevents publication.
  A source edit that normalizes to identical LLVM text still cannot rebind
  the old semantic/resource identity to the edited source.

Run these checks with:

    PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_llvm_owned_backend -v

No resource performance result is claimed by these correctness tests.
Resource-workload measurement requires its separately frozen protocol and
retained native samples. Neither these finite observations nor successful
compilation establish whole-language soundness, native refinement, universal
performance, foreign resource ABI equivalence or general stored-borrow support.
