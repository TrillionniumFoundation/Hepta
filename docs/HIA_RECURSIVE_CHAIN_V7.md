# Recursive owned buffer chains: primitive v7 and composite v2

This extension adds an actual runtime-sized inductive resource:

```text
chain = Nil | Node(buffer payload, chain tail)
```

Each nonempty node owns its payload and successor exclusively. Node count is
determined by executed control flow, not by a source-level depth parameter or
statically expanded nominal layout. The examples construct 4,097 nodes with the
same loop body used for zero or one node. The native implementation allocates
one header per node and releases recursive chains with an explicit loop.

The first profile fixes the payload type to `buffer`. Generic products and
enums can contain chains, but this is not a generic `List<T>` representation,
arbitrary recursive algebraic data types, shared/cyclic graphs, or foreign
object ownership. The existing `recursive_heap_adts_supported` claim remains
false; `recursive_buffer_chains_supported` identifies this precise extension.

## Version rules

| Input namespace | Primitive execution namespace | Recursive chain capability |
| --- | --- | --- |
| `hepta.hia.program.v1` through `.v6` | Unchanged | Rejected |
| `hepta.hia.composite.v1` | `hepta.hia.program.v6` | Rejected |
| `hepta.hia.program.v7` | Unchanged | Admitted and independently verified |
| `hepta.hia.composite.v2` | `hepta.hia.program.v7` | Admitted and independently verified |

The central schema registry defines these rules. Existing composite v1 input
is not silently upgraded. A pre-existing v1 nominal definition or generic
parameter named `chain` retains its nominal meaning; only composite v2 reserves
that spelling as a primitive type. The historical ambiguous nominal program-v2
adapter still targets composite v1 and does not import new operations.

## Primitive operations

Every operation has an empty attribute object. `chain` is a linear owner type,
not a scalar, integer address, buffer descriptor or borrow. Public native and
interpreter entry points remain scalar-only. Internal functions may consume
and return chains under the ordinary closed-SSA resource rules.

| Operation | Inputs | Outputs | Required effects |
| --- | --- | --- | --- |
| `chain.empty` | none | `chain` | none |
| `chain.try_push` | `chain`, `buffer` | `chain`, `buffer`, `bool` | `alloc` |
| `chain.pop` | `chain` | `chain`, `buffer`, `bool` | `alloc` |
| `chain.is_empty` | `chain` | `bool` | none |
| `chain.head_read` | `chain` | `readbuf` | `read`, `trap` |
| `chain.head_mut` | `chain` | `mutbuf` | `read`, `trap` |
| `owner.move` | `chain` | `chain` | none |
| `owner.drop` | `chain` | none | `alloc` |

The `read` effect of head borrowing accounts for reading the header descriptor.
Subsequent byte operations declare their existing read/write/trap effects.

### Fallible construction preserves both inputs

`chain.try_push(tail, payload)` always consumes the two input SSA capabilities.
The three output capabilities have this meaning:

| Result | Returned chain | Returned buffer | Boolean |
| --- | --- | --- | --- |
| Header allocation succeeds | New node owning the original payload and tail | Valid empty owner | `true` |
| Header allocation fails | Original tail, unchanged | Original payload, unchanged | `false` |

Both returned owners must be consumed on every ordinary path. The success
fallback buffer is an empty logical owner and causes no allocation/free call.
The failure path does not destroy, truncate or mutate either input resource.
`chain_recover` reads a known payload byte after a forced header refusal and
then traverses the original tail, making preservation observable.

`chain.pop` consumes a chain. For a nonempty chain it frees exactly the header
and returns the owned successor, owned payload and `true`. For Nil it returns
Nil, a valid empty buffer owner and `false`. Returned payloads use the existing
buffer borrowing and bounds semantics. No payload allocation occurs in pop.

### Borrowing and ownership

Head borrowing requires a nonempty chain at runtime; Nil produces the specified
`bounds` trap before any pointer dereference or loan creation. The primitive
checker gives the head loan the chain's root provenance. Existing rules then
prevent push, pop, move, drop, consuming calls or return of that chain while a
head loan is live. Reborrows suspend their parent until the child is ended.
Conflicting mutable/shared head loans are rejected.

A payload with a live borrow cannot be transferred into a node. A chain cannot
be passed twice to a consuming call, duplicated across an edge, returned twice,
selected as a scalar, constructed from an integer or exposed through the scalar
ABI. New nodes can only point at an already owned tail. Under the allocator's
freshness contract and these linear transitions, construction cannot create a
cycle or share an owned suffix. This is an implementation argument and tested
checker invariant, not a machine-checked soundness theorem.

## Interpreter and native representation

The supported 64-bit object model uses a 16-byte buffer descriptor and one
8-byte successor pointer. Every node requests **24 bytes** from the allocator.
The LLVM header layout is `{ %hia.buffer, ptr }`. All header fields are written
before read; no uninitialized bytes become program-visible. The runtime uses
the same real `malloc`/`free` boundary as the existing byte-owner backend.

The direct interpreter independently represents nodes and payload owners. It
charges all 24 header bytes, as well as payload bytes, to its live-byte budget.
Header allocations consume the same deterministic allocation-failure sequence
as payload allocations. These are requested object bytes, not allocator
metadata, process RSS, or total Python object overhead.

Normal destruction frees each nonempty payload and each header once. Empty
payloads cause no `free(NULL)` call. Both VM and native destruction are
iterative; data depth does not create one host/native call frame per node.
Each VM destruction step consumes the evaluator step budget. A trap or budget
stop reports its stopped resource state; it does not fabricate normal-path
cleanup, and native process termination is not claimed to execute destructors.

New reports distinguish chain handles from node storage:

- `chains_created`, `chains_consumed`, `live_chains` count root capabilities.
- `chain_nodes_created`, `chain_nodes_dropped`, `live_chain_nodes` count nodes.
- Existing allocation/free/live-byte counters include node and payload storage.

The supported generic record/enum/task elaboration uses real empty chains as
inactive owner padding and drops them explicitly. A stored head loan keeps the
original primitive chain root through record construction/unpacking and CFG
edges. Task cancellation invokes the checked state-consuming cancellation
function, which can destroy the entire remaining chain. These are cooperative
task semantics; there is no preemptive destructor guarantee or escaping loan.

Existing resource-budget analyses and Rust shadow profiles that admit only
v1–v6 must reject v7 until their own semantics are extended. Recognizing the
new wire format alone is not sufficient to inherit a cost or safety receipt.

## Executable evidence

The two complete source fixtures are:

- `examples/hia_recursive_chain/core_v7.json`: dynamic construction,
  cross-function transfer, traversal, iterative drop, head mutation, empty
  pop/trap, zero-byte payloads and recovery after a failed push.
- `examples/hia_recursive_chain/composite_v2.json`: generic records and error
  enums, locally stored reborrows, repeated cooperative polling, cancellation
  before/after a poll, and scalar result extraction.

Run the targeted regression tests and dedicated finite qualification:

```sh
python -m unittest tests.test_hia_recursive_chain
python tools/qualify_hia_recursive_chain.py \
  --output-directory /tmp/hepta-recursive-new \
  --clang /absolute/path/to/clang
```

The dedicated collector freezes a 324-case plan before execution. It compares
actual native scalar results and separate header/payload allocation ledgers
against an independent arithmetic specification and the direct interpreter.
The plan includes every allocation-refusal position in a 17-node construction,
normal completion with 4,097 nodes, zero-length payloads, stored loans, error
enums and task cancellation. Native negative controls actually remove header
or payload deallocation from the emitted runtime, compile and execute the
mutants, and require observed leaked bytes. Empty-head trapping is executed in
a child process. All commands, outputs, artifacts and unsuccessful results are
retained, with compiler identity checked before/after.

Those finite observations do not prove every program, arbitrary recursive
resources, LLVM refinement, physical device behavior or a Rust performance
advantage. Native allocator freshness, size/alignment guarantees, the native
toolchain, loader and target execution environment remain external premises.
