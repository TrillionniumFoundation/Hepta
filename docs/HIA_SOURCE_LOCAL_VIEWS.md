# Local borrowed records through executable HIA

The checked source adapter now carries the existing finite local-view resource
profile into the canonical executable Core. Both default primitive v1 and the
explicit v8 source route use the same existing owner/loan operations. The
interpreter, independent Rust Machine and direct LLVM emitter consume the
emitted Core; no alternate runtime or primitive instruction is introduced.

```hepta
struct Read<'a> { data: read 'a [u8], tag: u64 }
struct Edit<'a> { data: mut 'a [u8], tag: u64 }

export "C" fn probe() -> u64 effects {alloc,block,panic,write} {
    let mut data = buffer(2);
    let view = Edit {data: mut data, tag: 7};
    let mut moved = move view;
    moved.data[0] = 19;
    let answer = moved.tag + moved.data[0] as u64;
    drop(move moved);
    drop(move data);
    return answer;
}
```

## One existing admission and explicit scope

Fresh source checking runs before lowering. When a stored-reference declaration
is present, the adapter calls the existing public `lower_resource_ir`, which
constructs and independently verifies the complete source resource graph. Its
v4/v5 rules remain the local-view admission: one direct shared or mutable
`[u8]` field, one declared region, and at most four ordinary scalar labels.
The adapter then lowers the actual value/control operations and the result
passes `hepta.hia_program.verify_program` normally.

View values are inferred local record instances. View parameters, view returns,
named function lifetimes, nested view records, multiple reference fields,
owning fields in a view, and arbitrary lifetime relations remain rejected.
Shadowing an existing local name with a view remains rejected. The default v1
source route retains its direct named-origin subset. Explicit v8 additionally
admits the bounded returned-call construction below; it does not change the
standalone borrowed-return contract or the legacy source backends' profiles.

Every declaration, including an unused declaration, must fit the existing
resource profile. Unsupported declarations are not ignored merely because a
function has no instance of them. A scalar or borrowed record that happens to
flatten to a scalar signature still does not acquire a public C ABI.

## Returned calls in the same v8 source route

The stored field must explicitly borrow the call result, as required by the
unchanged source checker:

```hepta
fn bytes(data: read [u8]) -> read [u8] from data effects {} {
    return read data;
}
fn inspect(data: read [u8]) -> u64 effects {} {
    let view = Read {data: read bytes(read data), tag: 7};
    let copy = view;
    return copy.tag;
}
```

`data: bytes(read data)` lacks the required explicit outer `read` and still
fails source checking. The accepted construction uses the existing v8 call and
return-loan origin contract. Its helper has exactly one byte-slice or byte-buffer
borrowed formal, with the same read/mut mode as the stored field and return;
all other formals are ordinary scalar values. The actual origin is a direct
named byte owner, borrowed parameter or ordinary owner-record field. Nested
returned-call arguments, local-view origins, aggregate borrowed formals,
multiple borrowed formals and permission changes remain outside this source
increment. View parameters/returns and named lifetime escape remain refused.

The argument loan and returned child remain distinct primitive capabilities.
The producer retains the hidden parent value while a View or shared copy holds
the child, and includes both capabilities in ordinary CFG interfaces. A shared
copy aliases this complete obligation; an exclusive move transfers it and
invalidates the old value. The final shared alias, or explicit exclusive drop,
ends the returned child before its argument parent. Ending an inner shared
copy preserves the obligations of retained outer copies. Source and Core
verification continue to reject owner release, frozen exclusive-parent reborrow and
inconsistent branch resource states. No implicit exclusive cleanup is added
at an early return.

There is no new configuration option, schema, evaluator or execution route:
use the existing `--core-schema hepta.hia.program.v8` option. ResourceIR still
provides the local stored-view admission, and the emitted program is reverified
by the same primitive checker before Python, Rust Machine or LLVM use.

## Shared aliases and mutable transfer

A shared view copy names the same primitive loan capability. Copying the record
does not introduce a child loan or suspend its original. Scalar labels retain
ordinary value-copy semantics: assigning a label in one copy does not update
another copy. CFG edges carry the owner, loan and all record aliases through
the existing resource-alias rules.

Shared views end at lexical scope exit and before each normal/early return.
Ending an inner copy does not end a loan still held by an outer copy. The last
local alias emits one `loan.end` for a direct-origin view, or the returned child
and then its parent for the bounded v8 returned-call case. This is the existing
conservative lexical profile, not Rust nonlexical lifetime inference.

Mutable local views remain affine. A whole-local `move` transfers the producer's
binding to the same primitive capability and invalidates the old local. Explicit
`drop(move view)` emits `loan.end` and does not free the borrowed buffer. Every
normal path must consume an exclusive view; scope exit does not invent a
destructor. Byte indexing uses ordinary checked reborrows of that capability.
Parent access, owner release or an overlapping second mutable view still
rejects through the existing resource and primitive verifiers.

Construction evaluates fields in source order. A scalar initializer following
a mutable reference cannot access its borrowed origin while that loan is live.
Disjoint named owner fields may be borrowed independently. Branches, loops and
Result arms retain their normal exact resource-state joins.

## Executed values and cleanup boundaries

`examples/hia_program/source_local_views.hepta` includes shared copies with
independent scalar labels, inner-scope aliases, early returns, moved mutable
views in loops, disjoint record-field loans, and fallible allocation inside a
helper holding a local shared view. The independent arithmetic corpus contains
31 entry/argument requests and runs through both primitive source versions.

`examples/hia_program/source_returned_local_views.hepta` uses the same 31
arithmetic requests with actual v8 returned-loan calls in each stored field,
plus two exclusive early/normal-return requests. The latter explicitly drop
the View on both paths before the caller reads and drops the underlying owner.
Its 33-request corpus uses only the existing v8 source route. The native C
surface remains the five source-selected scalar wrappers; borrowed helpers
and View descriptors are internal.

For `failure_case(7)`, the normal path returns `50`, with two allocations/frees,
peak requested payload `10` bytes, and no remaining owner or loan. A refused
second allocation returns `41`, with one allocation/free and peak requested
payload `3` bytes. The native observer injects an actual allocator `NULL` result
at that call and checks allocations, frees and live bytes independently.

A VM budget stop preserves the actual stopped owner/loan ledger. It does not
run lexical cleanup after the stop. The native backend does not implement VM
step/heap limits, asynchronous cancellation or trap unwinding. Payload counters
are not process RSS or allocator metadata measurements.

## Reproducible checks

```sh
python -m unittest -v tests.test_hia_source_local_views
python -m unittest -v tests.test_hia_source_returned_local_views
python -m unittest -v tests.test_hia_program_source tests.test_hia_source_partial \
  tests.test_hia_returned_loans tests.test_hia_source_exports tests.test_hia_routes
```

The targeted module compares full Python/Rust resource reports, including every
step boundary of one mutable-loop execution and allocation/heap failures. Its
native path compiles the same fixture through the existing source-to-Rust
backend and canonical-Core-to-LLVM backend, then compares both with the fixed
arithmetic oracle. Existing invalid stored-view aliases and borrowed-return
escape controls remain rejections. Removing the emitted final loan end is also
rejected by the canonical primitive checker.

The returned-call module additionally compares the same primitive v8 with the
independent Rust Machine and actual LLVM calls. Its five raw Core adversaries
end a parent with a live child, drop the live owner, reborrow an exclusive parent
while its mutable child is live, omit the final parent end, or swap parent/child
on one CFG edge. The forbidden reborrow includes its own `loan.end`, so an
unclosed extra loan cannot mask the actual exclusivity rejection. A balanced
shared reborrow is a separate accepted Python/Rust neighbour: read-only parents
are not universally suspended. Both Python and raw Rust admission must refuse
the five actual generated invalid programs. Eighteen
source controls retain the alias, mode, shape, default-storage and export
boundaries. Development, frozen-source and public-source observations must
retain their separate source identities; registration alone is not execution.

Actual toolchains are required for Rust/native methods; skips cannot qualify
them. These finite checks do not establish general provenance, source-to-Core
refinement, full language soundness, arbitrary stored lifetimes or production
authority for the Rust shadow Machine.
