# HIA v8: explicit parameter-origin returned byte loans

HIA Core v8 supports actual internal calls returning parameter-bound `readbuf` or `mutbuf` capabilities.
This source-facing guide uses the canonical [v8 contract](HIA_PARAMETER_LOAN_RETURNS_V8.md).
The earlier branch spelling `return_origins` is not an alias in the executable grammar;
current producers and fixtures now emit `return_loans` explicitly.
The Python verifier remains the executable admission authority. The separate
Rust owner verifier, both finite VMs, and the declared LLVM target profiles implement
the declared subset. This is an executable contract with differential and native
observations, not a machine-checked source/compiler soundness proof.

## Version and signatures

The primitive wire schema is `hepta.hia.program.v8`, with profile
`closed-ssa-parameter-loan-returns-64-v8`. All v7 byte and chain operations
remain available. V1-v7 still reject borrowed results and the new function field.
The existing composite v1/v2/v3 grammars continue normalizing to primitive v6/v7;
they do not silently gain this contract. Neither old upgrade adapter accepts v8
input as an implicit downgrade.

The separately versioned [composite v4](HIA_COMPOSITE_RETURNED_LOANS_V4.md)
grammar maps bounded original-parameter/record-field origins to the actual
flattened entry parameters of primitive v8. Its structured origin annotations
are not an alternative spelling of primitive v8 annotations, and neither the
source route nor the older composite grammars inherit that new wire format.

A function that returns a view must carry `return_loans`, an array with exactly
one element for each result. A borrowed result names an entry borrowed parameter;
every scalar result has `null`. Each borrowed result carries its own declared origin. Multiple result capabilities
remain distinct and must satisfy the canonical aliasing and resource-transfer rules.
The source examples in this guide exercise one returned view at a time.

```json
{
  "name": "view",
  "params": [{"name": "input", "type": "readbuf"}],
  "returns": ["readbuf"],
  "return_loans": ["input"],
  "effects": ["read"],
  "entry": "entry",
  "blocks": [{
    "id": "entry",
    "params": [{"name": "input", "type": "readbuf"}],
    "ops": [],
    "term": {"op": "ret", "values": ["input"]}
  }]
}
```

`mutbuf` results require a `mutbuf` origin. A `readbuf` result may originate from
either borrowed permission. An owner or scalar parameter is never an eligible
origin. A function without a borrowed result can omit `return_loans`; if it
provides the field, every element must be `null`.

## Lifetime and resource transitions

Each incoming borrowed capability has an origin equal to its entry parameter
identity. CFG edges rename SSA names, roots and parent capabilities, while keeping
this origin unchanged. For functions declaring borrowed results, a join requires equal capability states
including origin. Functions without borrowed results retain the older compatible
loan-graph join rules.
Renaming a capability cannot make it originate from another parameter.

A returned view must be either the declared incoming view itself or a live,
direct child of that view. A direct child may have been produced by another
internal call. The origin root must still be external to the callee, and every
local resource except the transferred returned child must have been consumed.
A returned capability cannot have outstanding children. A returned child whose
parent is another local loan rejects, even if that local loan ultimately derives
from the declared parameter. This conservative rule avoids transferring an
unrepresented local parent graph.

The caller retains its argument capability. The returned capability is a new
direct child in the caller's static state. Until that child ends, byte reads and
writes through the parent, ending the parent, and moving/dropping its owner
reject. The child can itself be reborrowed; descendants must end first. The
existing immutable descriptor-length operation does not grant byte access.

At runtime there are two distinct cases:

1. Returning the incoming view itself creates a fresh child view at the return
   terminator. It increments `loans_started` and never transfers permission to
   end the original caller loan.
2. Returning an existing direct child transfers that exact child. It does not
   create a second loan or discard its parent relation. A forwarding helper can
   pass this child through multiple returns without extra increments.

Both VMs validate the runtime parent identity. The independent Rust executor uses
`bounded-cfg-byte-owner-loan-returns-v4` for v8 without chains and
`bounded-cfg-owned-memory-v5` when chain signatures or operations occur.
Its scalar-only execution mode rejects v8. Distinct call-formal witnesses are
not counted as source loan events; [the shared Machine contract](HIA_RUST_RETURNED_CHAINS_V8.md)
defines the typed resource roots and exact returned-child accounting.

Every return terminator already consumes one VM step. If the step budget stops
there, the implicit child has not been created. Trap, heap, step, and call-depth
stops report the actual remaining owners, loans and bytes. They do not invent
cleanup, exception unwinding or asynchronous cancellation. Existing cooperative
task cancellation remains the separate composite contract.

## Real source frontend

The source API requires explicit selection:

```python
from hepta.hia_program_source import lower_source
core = lower_source(source, core_schema="hepta.hia.program.v8")
```

The shared source route takes the same explicit `core_schema` option. The CLI
publishes those checked bytes with `hepta hia lower source.hepta --core-schema
hepta.hia.program.v8 -o program.json`; ordinary `hia verify`, `run`, `emit` and
`build` then consume the selected wire contract. This option exists only on
source lowering. It cannot override a submitted Core schema or silently
reinterpret a historical import. The default CLI lowering contract stays v1.

The default remains Core v1, with the established source projection-helper
inlining behavior. Under v8, borrowed helpers are emitted as actual Core function
definitions with `call`, `ret`, and `return_loans`. They are not inlined by this
lowering pass. `examples/hia_returned_loans/returned_views.hepta` exercises read
and mutable returned views and conditional return paths.

The v8 source subset requires an explicit `from parameter`. Its origin can be a
borrowed `Buffer<u8>`/byte slice or a concrete borrowed record containing byte
buffers. For a record origin, each source return must directly project the same
nested byte-buffer field. The lowering binds that field to its named primitive
argument, which need not be the first scalarized argument. Different fields on
different return paths reject even when they belong to the same source record.
The canonical Core verifier and independent Rust verifier still check the
emitted origin and every resource transition; source inference grants no
admission authority.

Immediate indexed or length consumption ends temporary argument loans only
after the returned child. Mutable scalar fields keep the established explicit
return/writeback convention. `returned_record_views.hepta` passes a record field
as a primitive argument. `returned_nested_field.hepta` instead passes an entire
record with two nested buffer fields and scalar prefix/suffix fields to real
read/mut helpers; both return the second nested buffer, and the mutable helper
also changes a scalar field. Its source-derived Core is checked byte-for-byte
against `returned_nested_field.json`, then consumed by independent Rust tests.

Local storage of returned borrows, arbitrary lifetime parameters, returned
borrowed records, and record-origin forwarding through a new local temporary
parent remain outside this source profile. These cases reject rather than
selecting a different semantic path. Primitive Core offers
direct identity returns and forwarding of calls whose argument is the incoming
view itself, including finite recursion.

## Native and external boundaries

LLVM uses its existing private byte-descriptor calling convention for internal
helpers and a v8-specific native profile. This source-specific qualifier executes
Linux x86-64. The separate [cross-target qualifier](HIA_RETURNED_LOAN_CROSS_EXECUTION.md)
executes finite AArch64 and RV64 cases under QEMU. Public entry
arguments/results remain scalars; declaring a borrowed helper as a public Core
export or C ABI export rejects. A private helper's descriptor return does not
establish a safe external C or C++ lifetime contract.

Native artifacts do not implement the finite VM step, heap and call-depth
budgets. Native recursion bounds, stack bytes and asynchronous interruption are
not established by the returned-loan checks or this qualification.

The native observer measures scalar results and real allocator attempts,
allocations, frees, live addresses and live bytes. Compile-time loan capabilities
are erased and have no native runtime loan ledger. A deliberately wrong value
and a missing `free` are compiled only as negative observer controls; canonical
native admission rejects their modified LLVM first.

## Evidence and limits

`python tools/qualify_hia_returned_loans.py --output <fresh-folder>/qualification.json`
runs `tests.test_hia_returned_loans`, retains every positive Python/Rust ledger,
all negative module bytes and raw Rust failures, and copies actual native
objects/executables, drivers and negative-control binaries. Its source inventory,
Git state, compiler receipt hashes and executable digests bind the observations
to exact bytes. Dirty development runs are marked dirty; they are not clean
commit qualification.

The corpus covers identity/direct-child/forwarded returns, stable CFG origins,
mutable-to-shared call arguments, a view plus scalar results, nested reborrows,
recursion, chain heads, scratch owners, every observed step boundary, heap and
allocation failures, and original-parent access after the returned child ends.
Negative modules include local/incorrect origins, local intermediate parents,
escaping siblings, early ending/dropping/moving, missing effects, old versions,
public resource exports, hidden unsupported suffixes, and uncalled bad helpers.

The scalar translation validator produces `unknown` for functions involving
resources/calls. The separate [v8 resource-budget profiles](HIA_V8_RESOURCE_BUDGETS.md)
retain their own finite acceptance boundaries; the original analyzers do not
silently gain chain or returned-loan bounds. No finite differential or native corpus admits an unproved
optimization, proves arbitrary memory safety, establishes Rust-level performance,
or closes the entire resource-core milestone.
