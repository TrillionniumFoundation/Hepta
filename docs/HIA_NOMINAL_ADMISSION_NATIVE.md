# Native nominal declaration admission

`nominal_admission.hiaasm` owns nominal root admission and the declaration
sequence formerly implemented by `_Elaborator.__init__`. It checks exact root
and function fields, schema/profile compatibility, names, duplicate functions,
function inventory, return-list shape, borrowed-return eligibility and effects.
It orders native parameter/type/origin/task requests and selects the exact
points at which the bridge assigns the original owner fields and registries.
The original body is retained unchanged as `_reference_initialize` during
migration and supplies an independent behavioral reference.

## Ordered policy and retained prefixes

Root fields and schema are checked before the legacy control is observed.
The module name is checked before assigning document, serial and value_slots.
Type construction occurs before native_types/types assignment and before the
parameter-loan flag. Function inventory is checked before creating the
function/signature/origin/helper registries. Each function's field/name and
duplicate checks precede parameter resolution. Every return reference is
resolved before checking whether any stored loan escapes. In v4, returned-loan
origins are assigned before validating effects, and function/signature bindings
are assigned only after that validation succeeds.

Concrete task declarations are checked after all functions have been bound,
including unused tasks. The native type owner supplies resolution, parameter
admission, loan-origin paths and protocol checks. This declaration owner does
not copy those policies into a host dispatcher. A selected declaration owner
requires that native dependency; it cannot fall back to `_Types`.

HIA requests each operation. The fixed bridge performs only that operation,
retains its exact returned objects, applies the indicated assignment, and
acknowledges it once. Native and foreign callback errors propagate at their
original points. A failure closes the private context, so its outstanding
action cannot be replayed after an uncertain or interrupted return.

## Original foreign legacy control

The existing Python API applies truth conversion to `legacy` twice. The first
conversion follows root/schema admission and precedes the module-name check.
The second follows assignment of document, serial and value_slots, but precedes
assignment of nominal_operations. Stateful conversions and exceptions at the
second call therefore have observable behavior. Caching one boolean or requiring
an exact bool would change that interface.

Two explicit HIA requests preserve those observations. The bridge performs
`bool(original_legacy)` only when requested and returns the observed primitive
boolean. HIA decides profile compatibility, operation inventory and every later
policy branch. A native caller may provide its primitive control at the same
ports; arbitrary Python execution is not part of the HIA source language.

The reply also carries a fresh typed snapshot of the live document. A foreign
truth conversion can change an otherwise ordinary JSON field. Native checks
after that observation use the new snapshot without repeating earlier guards.
For example, a changed invalid module name after the first conversion is refused
before any owner fields are assigned. A failure on the second conversion leaves
exactly the three preceding fields. Missing keys and unhashable JSON schema
values retain their original KeyError/TypeError and assignment order, including
whether nominal_operations has already been assigned.

The semantic domain remains the existing bounded, exact-JSON HIA document.
This does not claim emulation of arbitrary Python objects injected into that
document by foreign code, unbounded post-admission mutation, or concurrent
outside mutation of private owner state. The fixed native type/parameter/origin
callbacks do not mutate the original document. The foreign truth observer is
an explicit interoperability boundary, not a hidden hosted declaration branch.

## Protocol and input custody

Entry ABI: `(source: readbuf, output: mutbuf, workspace: mutbuf) -> u32`.
Private capacities are 32 MiB input, 1 MiB output and 40 MiB workspace.
The initial packet is `[null, private_nonce, original_document]`. The native
entry validates and copies those exact bytes into its own retained workspace.
The nonce is a private 32-character context identity. Subsequent policy reads
use that captured arena. The two foreign truth replies contain
`[observed_boolean, current_document]` and refresh that arena at the explicit
observation points. No digest is used instead of complete retained bytes.

Return-resolution replies contain only `[held_type_kind, held_flat_layout]`.
Other acknowledgements have a null input. Thus a long return list does not
retransmit the complete document for every resolved type. HIA validates the
kind/layout representation and scans the primitive slots for loans itself;
the bridge does not supply a precomputed loan-escape decision.

Both acknowledgement and result frames have eight u64 fields. Acknowledgements
carry magic, exact sequence, action, function/declaration index, return index
and three reserved zero fields. Results carry magic, error, action, index,
return index, sequence, graph size and reserved zero. Every resumed action
must match the retained state and monotonically increasing sequence. Closed
states refuse resumption. Generic graph decoding checks the complete indicated
assignment values; it contains no declaration or type policy.

| Action | Fixed bridge operation selected by HIA |
| --- | --- |
| 9 | First foreign legacy truth observation and live document capture |
| 10 | Assign original document and native-produced initial counters |
| 11 | Second foreign legacy truth observation and live document capture |
| 1 | Assign the complete native-produced operation inventory |
| 12 | Construct the selected native type session with native-produced flags |
| 2 | Assign the native-produced parameter-loan flag |
| 3 | Create the original empty registries |
| 4 | Resolve this function's complete parameters through the native owner |
| 5 | Resolve the next original return reference through the native owner |
| 6 | Resolve and assign this function's native returned-loan origins |
| 7 | Bind the original function and its held resolved signature |
| 8 | Resolve and check this concrete task through the native owner |
| 0 | Close successfully or raise the native-selected original refusal |

## Bounds and original limits

The public source limits remain 8 MiB, 262,144 value nodes and depth 64.
Typed object keys add at most one node per existing value edge. Conservatively
charging 32 bytes per public value node for typed value/key headers, eight
more bytes per container and the complete 8-MiB public payload gives less
than 19 MiB, below the 32-MiB private input region. Envelopes stay below the
8,388,608-node and depth-128 transport bounds. The captured input starts at
1 MiB; its full 32-MiB capacity therefore fits below 33 MiB in the 40-MiB
workspace. All control tables lie below that arena.

The original 1,024-function limit bounds the duplicate-name table. It does
not constrain parameter/return arity beyond the original source budget.
Only the current return's at-most-512-slot layout is transported at a time.
Signature returns remain uncharged to the 32,768 elaborated-value-slot quota;
the test with 33,280 signature slots retains zero reserved slots and zero
generated names. The type owner retains its original instantiation, layout
and symbolic-declaration limits. No public budget is raised or silently lowered.

## Selection and evidence

`HEPTA_HIA_NOMINAL_ADMISSION_MANIFEST` selects the source/image-bound owner.
The cold builder candidate is `nominal-admission`; its tests build both this
image and composite-types from the same current-source cold report. Installed
wheels carry both ordinary HIA sources and use no authoring imports.
Missing, changed or malformed selected source/image custody is a final refusal.

Controls compare original/native errors, complete partial owner state and exact
native type-command traces. They include all four schemas, root/function/effect
errors, all-return-resolution precedence, origin-before-effect assignment,
1,024/1,025 functions, unreserved wide returns, the two foreign truth calls,
live JSON changes, original KeyError/TypeError order, replay/malformed frames,
nonzero scratch, canaries, complete independent VM/native frames and retained
workspace bytes. The unchanged 75-test resource/partial/returned-loan suite runs
with the hosted constructor, type resolver, parameter policy, origin policy and
task check disabled. Installed-wheel and real allocator/refusal/cleanup controls
retain the actual public verification and machine-code paths.

The first development candidate's four legacy-control compatibility mismatches
are retained. Its original 14-test success does not cover the corrected ABI.
The next candidate adds both observations and fresh snapshots. Five affected
controls passed, including thirteen stateful/live-document scenarios and all
twelve VM/native continuation frames. The independent original-behavior witness
that exposed the second truth call is preserved separately.

Current development source SHA-256:
`5d2ecf397596e5a41290502439d7843a891289870102236525f817b751bdaebb`.
Actual image SHA-256:
`c784d367b510028cde0ffa59c739f6ec26b5c5451d8c617c0be7b634b134182e`.
It was compiled by retained predecessor
`0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8`.
This is development evidence. Fresh integrated cold qualification, complete
native-owner composition and full retained regression remain required. No
whole-product native default, live migration or old-stack deletion is claimed.
