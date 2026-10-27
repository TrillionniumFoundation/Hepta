# Real C resource modules across complete build variants

`hepta.c_resource_matrix.migrate_c_resource_matrix` extends the complete build
partition used by the scalar C/C++ adapters to the existing contracted C
resource frontend. Each declared variant gets its own complete native target
and an explicit contract. Every compilation command belongs to exactly one
variant, and every variant contains the same translation-unit set.

The implementation reuses `migrate_c_project`, `CRecordViewTranslator`, the
ordinary Hepta checker and its Rust backend. This route is **safe Hepta/Rust
implementation migration with a caller-unsafe C ABI edge**. Its report sets
`standalone_hia_lowering_qualified=false`. Supporting scalar HIA matrices does
not make pointer-bearing record lowering available in standalone HIA.

## The real module and new composition

The fixture is the complete, unchanged `ringbuffer.c` and `ringbuffer.h` from
[AndersKaloer/Ring-Buffer](https://github.com/AndersKaloer/Ring-Buffer/tree/8de8fff55a0baee4fef2a1c6a82d258a27c3c0ba),
with its MIT license and exact Git-blob/SHA-256 identities already recorded in
`tests/fixtures/c_migration/ring_buffer/UPSTREAM.json`.

`examples/c/resource_matrix/client.c` is a separately counted authored caller.
It queues an input slice through the upstream module, dequeues into a different
mutable output slice, and transforms the returned bytes according to a captured
macro. It receives the same persistent record and backing storage as later
calls. The two builds are C11/output-mask 0 and C17/output-mask 90; both use
the upstream module's explicit NDEBUG and unsigned-char configuration.

All four commands are retained in one compilation database, partitioned into
two builds of two translation units each. A native C object is generated for
each original unit. The union of their actual defined function symbols must
equal the generated target's public function symbols. Target construction uses
only generated Hepta/Rust code and its ABI shim, without linking original C
objects.

The first executed development qualification observed **37 active declarations
per build**, all classified: ten converted functions, sixteen resolved
prototypes, two complete records, two record forwards, four type aliases and
three repeated inline definitions. A repeated header body receives its own
disposition rather than disappearing from the denominator.

## Resource and definition rules

The record-view route already checks every numerical mutable range pair before
constructing Rust references. It now admits multiple separately contracted
slice parameters using those same guards. The plain value/slice C route keeps
its earlier rejection because its ABI shim has no equivalent disjointness
checks. Internal cross-module calls remain subject to Hepta's actual borrow
checker and emitted extent/bounds checks; a read-only caller contract cannot
invoke a mutable callee.

The shared header has external inline definitions seen in both translation
units. Coalescing requires the same source file and offset, different units,
inline declarations, matching signatures and matching complete Clang ASTs
after removing per-invocation node IDs, source positions and use annotations.
Different macro-expanded bodies reject even at the same header offset.
Ordinary repeated external definitions and different source locations reject.
Actual linkage is still verified independently on native objects. This does
not relax the separate standalone scalar adapter's static-inline-only policy.

Generated record-field and cursor parameter names must remain distinct from
ordinary source parameters. Ambiguous names reject before generated bindings
can shadow one another.

| Kind of condition | Current scope |
| --- | --- |
| Static | Complete declared configuration partition; declaration disposition; type/access/length contracts; unchanged pointer decomposition; checked internal borrow calls |
| Dynamic | Non-null, alignment, representable numeric extents, mutable-range nonoverlap, cursor and element bounds |
| External | Live initialized records and allocations of the claimed extent; pointer provenance; no unsynchronized foreign alias access; truthful selected build and contracts |

Contracts are explicit caller-supplied restrictions and can narrow the valid C
input domain. They are not inferred ownership facts or a translation theorem.
The upstream ring module itself does not allocate, so its caller-owned storage
must not be counted as an inferred upstream allocator protocol.

## Execute and retain

```sh
python tools/qualify_c_resource_matrix.py \
  --workdir /tmp/new-real-c-resource-matrix \
  --clang /absolute/path/to/clang \
  --rustc /absolute/path/to/pinned/rustc
```

Each variant executes 2,048 upstream state transitions and 1,536 composed
cross-unit transitions against an independent deque oracle. All backing bytes,
scalar state, returns, output sentinels and immutable input bytes are compared.
Counts explicitly distinguish paired observations from actual native calls.
Both actual C and Rust layouts are probed. Five child-process boundary controls
per variant exercise aliases, null buffers and inherited bad indices. Three
contract controls cover read-to-mutable escalation, a missing callee contract
and a missing variant contract.

Failed variants remain in the matrix report alongside successful variants.
New directories are required; a rejected request cannot write a report into
an existing destination. Publication is manifest-last, not a crash-atomic
whole-matrix transaction.

This qualification has no new performance threshold. Its report keeps
`performance_floor_established=false`. Behavior, safety boundaries, native ABI
and migration/build cost are separate from any performance-superiority claim.
