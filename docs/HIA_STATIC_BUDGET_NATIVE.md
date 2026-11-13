# HIA structural resource ownership

This component moves the complete policy of `qualify_vm_call_depth`,
`analyze_static_budget`, and `qualify_bounded_resources` into the checked
`examples/hia_bootstrap/static_budget.hiaasm` program. It also provides the
complete whole-module resource-profile audit used at the existing private
heap-analysis boundary. The public entry signatures and receipt schemas are
unchanged. The default path retains the independent original implementation;
`HEPTA_HIA_STATIC_BUDGET_MANIFEST` explicitly selects the native image. A
selected image failure cannot delegate to the retained policy.

This is a structural-resource owner, not a claim that the complete project,
all heap analyses, normalization, JSON serialization, or verification is
already HIA native. The controller requests the original public heap APIs at
their original points. Those APIs are separate owners, and their current
selection and qualification remain independent. The retained Python bodies
are still required as review/test oracles until the complete project retires
them through its normal qualification process.

## Exact ownership

HIA owns the following decisions and constructions:

* Exact policy kinds and bounds, with the original order of guards for each
  public entry. The depth entry checks its policy before verification. The
  event entry checks allocator, tick, depth, then optional heap limits before
  verification. The composed entry captures a shallow policy copy, checks its
  exact inventory and values, and then verifies the input.
* Full-module profile review, including uncalled private definitions, all
  declaration/output types, terminators and opcodes. A bad declared type is
  deferred until the end of its function, while an unreviewed terminator or
  opcode refuses at its original earlier point. V8 synchronous depth permits
  chains; V7/V8 event accounting retains the original byte-only review.
* Closed call-graph and CFG construction, duplicate-edge elimination, stable
  topology, first cyclic/unknown dependency refusal, and all-definition
  coverage. The original initial lexical queue and lexical successor order
  are preserved; newly ready nodes are appended at the queue tail.
* Per-block and per-function allocator/tick maxima, root-inclusive call depth,
  duplicate call-site contributions, and separate syntactic maxima for
  allocator and tick events. A CFG loop can still receive a synchronous frame
  certificate while failing finite event qualification.
* Arbitrary-precision integer calculation and comparison, including numbers
  wider than u64 and limits that have no public upper bound.
* Optional heap-inventory completeness and value checks, per-function heap
  comparisons before event limits, and the original function/key iteration
  order for the first exceeded policy.
* The complete bounded-resource composition: nested event re-verification,
  event-row mapping, every requested V8 entry heap qualification, legacy heap
  comparisons, shallow export-row copies, and preservation of shared counter
  integer identities between the static receipt and export rows.
* Every receipt/error field, all schema/profile variants, the final request
  to serialize, and insertion of the returned digest into the chosen report.
  No bridge-side opcode inventory, graph walk, budget comparison, row plan,
  profile decision or error-message catalogue exists.

The four original source bodies are mechanically retained as
`_reference_audit_resource_profile`, `_reference_qualify_vm_call_depth`,
`_reference_analyze_static_budget`, and
`_reference_qualify_bounded_resources`. Tests compare their complete source
segments after restoring only the original function name. This avoids an
`ast.dump` representation dependency between Python releases. The original
`_bound_function`, `_topological`, `_limit` and `_successors` also remain for
independent controls and separately pending heap paths; the selected event or
frame owner never invokes them.

## Foreign continuation boundary

`hepta/hia_static_budget_native.py` holds a monotonic-ID `NativeObjectPool` with explicit native-selected releases.
Pool IDs express identity and custody, not opcodes or semantic plans. HIA
chooses the operation, operands, order, and next phase. Fixed continuations
perform only these operations:

| Request | Fixed foreign operation |
| --- | --- |
| 1 | Exact built-in kind and integer sign/bit-length/low-word representation |
| 2 | `verify_program`, followed by `as_dict`; structured-input attribute only when HIA requests it |
| 3–5 | Shallow object copy, set construction, and requested inequality |
| 6–7 | Dictionary-value iterator and requested item lookup |
| 8 | Canonical sign plus little-endian integer magnitude; no decimal conversion |
| 9 | Verified source identities, with input identity read only when requested |
| 10–11 | Existing constant-live-heap or entry-live-heap public API |
| 12 | Original final `json.dumps` options, UTF-8 encoding and SHA-256 |
| 13–17 | Requested item assignment, iterator next, holding a complete HIA-produced value, sequence iterator, or release of an owned temporary handle |
| 100–101 | Physical workspace/output growth preserving existing bytes |

Python exact-object metadata is representation only. In particular, a huge
positive integer is not decimalized merely to check its sign or compare its
bit length. A custom key that compares equal to a required policy name is not
prematurely rejected by a generic JSON-pool validator. Set/hash/equality/item
operations remain explicit foreign protocols in the exact native-selected
sequence. The final JSON operation retains its original late key-sort and
integer-digit failures. Policy lookups use native-selected opaque references
to the actual four Python literal objects, rather than newly decoded equal
strings. The initial packet holds these constants as fixed representation
data; HIA selects their IDs and decides each lookup. Temporary set results and
iterators are released by HIA at their original completed predicate/iteration
points. Released IDs are never reused and stale references are rejected.
This preserves reachable custom-key identity and reference-count observations,
without prematurely deep-copying or admitting foreign objects. The composed
entry still performs its nested
`analyze_static_budget` verification even when that second verification
rejects an expanded canonical Core that passed the original first boundary.

Heap continuation calls do not certify that a particular heap implementation
is native. `analyze_constant_live_heap` and
`qualify_entry_live_heap_budget` keep their names and signatures so the heap
owner can independently pin or replace its own selected policy. The native
private audit is available as
`NativeStaticBudget.audit_resource_profile(document, schema=..., allow_chain=...)`
for an already verified Core and the reviewed fixed schema/boolean domain.

## Private framing and custody

The image ABI is `(readbuf source, mutbuf output, mutbuf workspace) -> u32`.
The executable header stores magic, phase, sequence, request and four request
words at byte offsets 0 through 56. The shared graph arena uses offsets
64/72/80 for used bytes, minimum requested extent and arena error. Offset 88
is the acknowledged sequence. Status/output length/reply pointer/mode are at
96/104/112/120. Graph writing uses 152/160 for cursor/overflow. Status 1 is a
complete success value; status 2 is the complete semantic error pair. A
transport invariant is refused as such and never fabricated into a budget
receipt. Unused request words and the two optional-attribute flags must be
canonical.

Every returned frame is an exact frozen `BudgetFrame`. Its exact integer
kinds, request words, identity, sequence, and decoder-created graph are bound
before a foreign operation can run. Native-created dictionaries/lists retain
shallow edge snapshots; replacement, insertion, ordering or scalar-identity
changes are refused. Opaque referenced objects retain identity and the pool's
stable-custody contract; their arbitrary internals are not recursively copied
or scanned. This boundary is private transport correctness, not protection
against hostile arbitrary code inside the same Python process.

A callback permission is consumed before the callback. A completed callback
reply is acknowledged only after materialization and storage complete. An
exception or interrupt permanently closes the context, prevents resuming or
replaying the request, and preserves the original foreign exception identity.
Terminal permission is also consumed once before materializing a refusal or
returning the already chosen object.

Workspace and output growth retain both old and new mmap objects across
assignment, interruption, and old-arena close. Partial construction and all
abort paths release every owned arena without masking the original error.
Revocation is permanent; physical close is retryable when an exported buffer
causes `BufferError`. A failed close retains the object for the later retry.
The bridge introduces no success report for a foreign `MemoryError`, JSON
failure, Core refusal, heap refusal or callback `BaseException`. Still-live
foreign identities remain with an exceptional context for as long as its
original exception traceback remains held, matching the original locals'
custody. They are not eagerly destroyed while propagating a refusal. This
retention includes no live native arena or resumable permission. Normal
success and explicit caller-owned private `close()` release the pool; the
native-selected completed temporary releases still occur at their earlier
original points.

## Numeric and representation bounds

There is no new public source-byte, JSON-node, output-value, counter-bit or
limb quota. The original public normalization can admit a final Core whose
real node inventory is larger than its earlier structural traversal saw.
The static owner therefore uses actual representations, not a presumed
262144-node bound.

Each typed source/reply node has its own 16-byte header. The HIA reader bounds
nodes by actual packet length divided by 16, and bounds container children by
the actual payload extent. The decoder opts into
`decode_bound_native_graph(..., extent_bounds=True, binary_integers=True,
objects=...)`. Its node/concat bounds follow actual encoded extents; it does
not import the generic codec's old fixed node/expansion quotas. The historical
codec defaults used by other components are unchanged. Its depth 128 remains
a private grammar bound: verified primitive Core and this fixed wrapper have
at most ten enclosing containers, and generated receipts have fixed shallow
shape. Arbitrary foreign objects remain opaque and are not admitted through
that grammar.

Workspace allocation follows actual packet size, actual graph inventories,
and the proven counter width. Let `F` be the verified number of functions,
`M` the total instruction-plus-terminator inventory, and `B=M+2`. For an
acyclic call graph, a per-function event count is less than `B**(F+1)`:
local events and call occurrences are bounded by `M`, and each additional
call height multiplies the previous conservative bound by less than `B`.
The HIA controller reserves
`ceil(((F+1)*bit_length(B)+1)/32)` limbs for each calculated count. This is an
allocation proof from the actual verified graph, not a cap on a supplied
integer. Block scratch is reclaimed after each complete function; permanent
function summaries are separate. Every base-2**32 limb occupies one u64 slot,
so addition/multiplication intermediates satisfy the shared bigint contract.
Static event accumulation itself only needs the shared addition/comparison
and binary-export functions.

The Core verifier's own function inventory bound remains unchanged. Counts
can greatly exceed u64 even with only 71 functions. A policy or heap result
may be arbitrarily wider than the calculated counter: HIA first compares
signs and bit lengths, requesting raw magnitude bytes only when necessary.
No supplied number is constrained to the count arena's limb capacity. The
original final Python JSON conversion retains its own integer-digit policy
and exact original late error channel.

Output grows to the complete graph byte count requested by HIA. Large
integers use canonical tag 12 binary magnitudes, and complete foreign values
use explicit tag 13 pool references. Report composition does not recursively
re-encode or duplicate opaque existing heap/event receipts. Physical address
space or allocation exhaustion remains an ordinary foreign failure; it is
not converted to a new language limit.

## Validation and qualification scope

`StaticBudgetSourceTests`, `StaticBudgetAdapterTests`, and
`StaticBudgetNativeTests` cover the checked source, original compiler limits,
exact retained source, selected failure behavior, actual mmap cleanup,
canonical private words, graph/permission custody, complete native execution,
and independent original semantics. The controls include:

* All eight Core schemas, exact policy/error ordering, CFG loops, recursion,
  duplicate call sites, shuffled call DAGs and whole-module profile refusals.
* Exact allocator/tick counts wider than u64; equality and one-off arbitrary
  integer limits; 720 layers of eight repeated calls; final 640-digit JSON
  refusal versus an earlier explicit budget refusal.
* A real accepted Core with 262145 repeated unit returns, proving that the
  original public node gate is not used as a new private capacity assumption.
* Actual heap continuations, inventory/type failures, bounded V3/V8 receipts,
  counter identity, and a custom policy key's exact equality/verification/heap
  trace followed by the original final JSON sort error.
* Complete source/output/workspace comparison against the retained independent
  Python Core VM at actual native frames, not two executions of the new owner.
* Original static/depth/returned-loan/composed public suites with the selector
  set to the actual compiled HIA image. Separately retained source or heap
  APIs remain distinguishable from those selected public controls.
* Actual callback-return interruption, same-sequence forgery, mutable issued
  graph mutation, three retained-old/new-arena transition windows in each of the workspace
  and output paths, and close retry after a real exported-buffer error.

The fixture requires either `HEPTA_HIA_STATIC_BUDGET_COLD_REPORT` or
`HEPTA_HIA_STATIC_BUDGET_DEVELOPMENT_COMPILER`, and rejects both together before
reading inputs or creating output. `HEPTA_HIA_STATIC_BUDGET_EVIDENCE` chooses
the external evidence directory. Cold mode requires the existing strict
current-source builder and `static-budget` candidate registration; it never
substitutes a development manifest. Retained-compiler mode is explicitly
`PREDECESSOR_COMPILER_DEVELOPMENT_COMPONENT`.

The initial development smoke used the retained compiler and matched all 12
complete original reports/refusals with 173 actual native entries. The first
full development run retained its actual 20 PASS / 1 FAIL outcome: its one
interruption test had not enabled opcode tracing on an outer frame, so the
recorded probe observed zero opcode events and no injected exception. This
was a harness failure, not evidence of a callback replay or of a product
cleanup pass. The corrected probe requires exactly one real opcode hit;
three targeted controls then passed with 41 actual entries, including six
arena-swap interruption windows. Those raw runs remain separate. Subsequent
complete gate results, exact file/compiler/image identities and source
before/after records are written alongside each immutable evidence run.

A later frozen 27-control development run passed, but a subsequent actual
custom-key probe found two additional public foreign-protocol differences in
that frozen image: a decoded equal lookup string changed identity and caused
an early `KeyError`, and a retained temporary policy set changed the key's
reference-count trace from `[6,5,5,5]` to `[6,6,6,6]` on that CPython run.
Those original negative observations remain unchanged. The literal-object
and native release revision addresses those concrete findings and has its
own fresh controls; the earlier 27-control pass is not relabelled as covering
them. An additional actual refusal probe then showed that clearing all
foreign identities on exceptional close destroyed a policy key before the
caller observed the error, whereas the original retained traceback still held
the shallow policy copy. That original negative result is also retained.
Exceptional cleanup now immediately closes owned arenas/permissions while
retaining the still-live foreign pool with the traceback. A separate actual
control checks both the destructor trace and the absence of live mmaps.

## Pending v69 integration

The selected image is registered as the `static-budget` cold candidate and
`HEPTA_HIA_STATIC_BUDGET_MANIFEST` worker helper. Installed source resources,
the release source closure and checker identity include its HIA source,
adapter, shared graph/limb/transport dependencies and the separate heap
continuations. The v6 qualification runner and native CI group select the
same current-source cold report for static policy and its independent graph
and bigint controls. A development compiler cannot override that selection.

`tests/test_hia_static_budget_integration.py` builds an actual source archive,
wheel and isolated installation. Its child refuses `tools` and `tests`
imports, disables the retained structural policies and VM, and selects both
native images from one pinned worker bundle. The comparison includes all
three public structural APIs, counts wider than 64 bits, exact refusal
reports and bounded execution with normal allocation and injected allocation
failure. Separate controls cover installed source drift and a fresh worker
installation receipt. These controls are registered; their eventual result
belongs to the exact source, compiler, package and manifests actually run.

Fresh whole-source cold qualification and final repository release/retirement
gates remain separate. A component development pass does not inherit an older
compiler's cold result or authorize removal of the independent hosted reference.
