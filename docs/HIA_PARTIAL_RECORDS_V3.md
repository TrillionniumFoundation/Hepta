# Composite v3: explicit partial-record typestates

`hepta.hia.composite.v3` adds partial construction, field movement and
reinitialization of finite nominal records. It normalizes to the existing
`hepta.hia.program.v7` primitive grammar. Composite v1/v2 keep their existing
operations and type grammar; neither accepts these new operations or types.

This is a structural initialization model, not an address-based uninitialized
allocation API. A missing field has no primitive slot and no invented value.
There are no new LLVM assumptions or unchecked memory instructions.

## Exact wire types and operations

A partial type has exactly two fields:

```json
{"partial":{"name":"Pair","args":["buffer","usize"]},"initialized":["first"]}
```

`partial` must resolve to a declared nominal record. `initialized` lists the
present field names exactly once in declaration order. A partial type is
distinct from a complete record even when every field is initialized. Generic
record instantiations, nested finite records, enums, tasks and chains can be
field types. A base record containing a stored loan anywhere in its flattened
layout is rejected in this version. Existing ordinary records retain their
stored-loan behavior.

For a record `R` with fields `a: A, b: B`, use `P{}` / `P{a}` / `P{a,b}` below as
abbreviations for the exact partial wire types, not additional wire syntax.
Instructions retain the ordinary `op`, `args`, `out`, `attrs` shape.

| Operation | Inputs | Outputs | Exact attributes |
| --- | --- | --- | --- |
| `record.begin` | None | `P{}` | `{}` |
| `record.insert` | `P{}`, `A` | `P{a}` | `{"field":"a"}` |
| `record.insert` | `P{a}`, `B` | `P{a,b}` | `{"field":"b"}` |
| `record.finish` | `P{a,b}` | `R` | `{}` |
| `record.take` | `R` or `P{a,b}` | `A`, `P{b}` | `{"field":"a"}` |
| `record.take` | `P{a}` | `A`, `P{}` | `{"field":"a"}` |
| `record.abandon` | `P{}` | None | `{}` |

`record.get` and `record.borrow` can inspect an initialized field of a partial
record under their existing scalar-copy and primitive-buffer-loan restrictions.
Reading or borrowing a missing field, inserting an already initialized field,
finishing before every field is initialized, or abandoning any remaining field
rejects. To replace a field, take it, explicitly use/drop it, then insert its
replacement. Cleanup order is the explicit instruction order chosen by the
program, including error and cancellation functions.

Partial states are exact types on CFG edges and function signatures. Different
initialized sets cannot merge implicitly. Ordinary nominal consumption checks
reject use after movement and missing partial states on an edge or return.
Functions returning a partial record remain internal: public entries continue
to use primitive scalar parameters and results only.

## Independent Core obligations and observable events

Each partial record normalizes to a **real zero-length buffer Owner token**
followed by the initialized fields, in declaration order. The token is private
to elaboration; no field projection can access it. This preserves linearity
in the independently checked primitive program even for an empty partial
record or a record containing only scalar fields.

- `record.begin` lowers to a `usize` zero constant and `buffer.try_new(0)`.
- Taking a field from a complete record creates one such token for the new
  partial remainder. Taking from an existing partial record carries its token.
- Every primitive owner in a taken field is transferred by a real
  `owner.move`. The primitive verifier therefore rejects taking a borrowed
  owner, including an owner nested inside a larger field.
- `record.insert` carries the existing token and each field's actual primitive
  identity. It emits no default writes for absent fields.
- `record.finish` and `record.abandon` explicitly `owner.drop` the token.

The token contributes one logical owner creation and destruction. Because its
length is zero it produces no allocator attempt, allocated payload byte, native
`free(NULL)` call or allocator-failure index. The ordinary `alloc` effect is
still required for creation/drop instructions. No token event is removed from
the interpreter or independent Rust resource ledger. Budget stops retain the
actual partial execution state, without promising implicit cleanup.

Live external loans may refer to initialized owner fields. Independent Core
checks still require the root and loan graph to travel together across CFG
edges, and prohibit moving/dropping a borrowed owner. A caller cannot pass an
owning partial state while retaining a conflicting loan. Partial states in
task/enum slots use the same existing padding and task cleanup rules, and the
whole normalized program is reverified before execution.

## Limits

All existing type-depth, instantiation, flattened-field, generated-name and
elaborated-slot budgets remain enforced. Partial typestates count against the
instantiation budget. Recursive by-value declarations, including cycles through
partial type references, reject even when unused.

Unused declarations must also satisfy partial-reference constraints. A concrete
partial reference is resolved and checked even inside an unused generic record.
An unconstrained `partial(T)` is rejected because `T` has no declared record
kind. A symbolic application such as `partial(Box<T>)` has a known record
declaration: its field names/order and any statically known stored loans are
checked immediately. Unknown type-argument loan-free conditions are checked
again at each actual instantiation; no arbitrary placeholder type is selected
as evidence that every argument is safe.
The declaration-constraint analysis memoizes identical symbolic conditions and
has an independent 32,768-step budget (`E_HIA_LIMIT`), including construction of
memo keys. Repeated fields can share proof work, while distinct symbolic paths
cannot expand without bound before any concrete layout is instantiated.
Symbolic argument substitution additionally has a 64-level nesting ceiling;
exceeding it also rejects with `E_HIA_LIMIT` before Python recursion exhaustion.

This extension does not add arbitrary memory layouts, stored loans inside
partial states, raw-pointer initialization, escaping borrows, arbitrary heap
ADTs, concurrent tasks or destructor cleanup after abort/budget exhaustion.
Tests and actual native execution records are reported separately; this design
document is not an execution certificate or a whole-language soundness proof.

Primitive v8 remains the separate, current grammar for parameter-bound returned
loans. Composite v3 normalizes to primitive v7: a v8 `return_loans` declaration
inside this nominal input is rejected, never silently erased. The primitive v8
verifier, VM and existing returned-loan execution path are unchanged.

The existing synchronous-call-depth analyzer reverifies the actual normalized
Core and bounds its closed call graph. For the qualification corpus it finds
two frames for `partial_case` and four for `partial_task` and
`partial_pair_task`. Its receipt does not
bound ticks, payload, process RSS or native stack bytes. Existing all-function
static tick and live-payload analyzers still refuse this v7 profile; the
qualification report preserves those unsupported analyses as `unknown`.

## Planned independent execution qualification

`tools/qualify_hia_partial_records.py` independently constructs a generic record
with two buffers and a scalar tag. Its fixed plan has 121 distinct scenario
requests (76 construction/error/cancellation requests, 18 single-payload task
requests and 27 two-payload task requests), 11 VM budget boundaries (10 expected
stops and one normal-return control), and two LLVM input routes (nominal and
normalized Core), for 242 positive native program executions. Missing-free,
wrong-byte and wrong-cleanup-order native controls
are separate from that denominator. Planned execution is not a recorded pass;
the actual terminal report is required before any qualification claim.

The independent scenario specification separately predicts logical owner
counts and allocator-visible events. The C observer cannot observe erased
logical tokens; their creation/drop accounting is compared between the two VMs
and the independent scenario count. The normal native path observes a
distinguishable release order. `partial_pair_task` acquires buffers of sizes
`n` and `n + 1` and carries their full partial-record state into a cooperative
task. For `n` in `0, 1, 7`, each request independently selects pending cancel,
running cancel, or completion followed by cancel and join, and either no
failure or allocation-failure index one or two. The two failure branches run
explicit cleanup of the initialized fields. On positive extents, pending and
running cancellation must free allocation IDs `[2, 1]`. Repeated pending
cancellation and cancellation of an already ready task must not repeat cleanup.

The third native control keeps the scalar result, allocator totals and zero
live bytes correct, but deliberately frees those fields in order `[1, 2]`. The
independent observer must expose that mismatch. Only a terminal report with
all positive cases and all controls passing sets
`two_live_payload_cancel_order_qualified` to true. This claim covers the fixed
explicit cleanup protocol; it does not assert an unwinder, cleanup after a trap
or budget stop, or arbitrary destructor ordering. A separate step-stop test
observes both payloads still live before cancellation begins.

The Rust command uses the existing `--owned-run FUNCTION JSON_ARGS MAX_STEPS
MAX_HEAP_BYTES FAIL_AT|none` interface. This byte-only v7 corpus requires
`hepta.hia.rust-byte-owner-execution.v1` and
`bounded-cfg-byte-owner-bulk-v3`; a stale or unrelated execution report is not
accepted as this qualification.
