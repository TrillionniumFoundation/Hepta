# Proposed kernel-checked Core syntax connection

Design only, following PR #600 head 04374a076928460649153eefae670145e0157efb.
No new proof, evaluator, CI execution or admission result is supplied here.
All twelve global obligations stay unproved, actual_core_bridge_proved=false,
and DENY_ALL. Production zero initialization and gates remain unchanged.

## Smallest missing link

The accepted #600 theorem concerns HiaGuardedUsizeSlice.Descriptor and its partial
scalar evaluator. Python currently decides which Core definitions, names, slots,
branch arm and literal produce that descriptor. Kernel acceptance of Valid d
cannot establish that d describes the supplied Core. A forged, internally valid
descriptor for a different program would still satisfy the current theorem.

The next deliverable should close only this syntactic selection gap for the
concrete inputs. It should not execute the body prefix or introduce another
memory/initialization model. Reuse Descriptor, Valid and selected_successor.
Existing HiaSelectedCore defines a separate u32 register machine and explicitly
excludes its exporter; it supplies no existing general Core JSON connection.
HiaInitializationPrefix already supplies the relevant arithmetic theorem.

## Exact input and deliberately restricted transport

Reconstruction of the current real candidates gives:

- linear: 14,466 canonical bytes, 1,348 JSON value nodes, SHA-256
  c7b8b9ef7619700fd9c5ec0dedb06fbf7ecc801563813b6cb7abaf7e08a467d3;
- affine: 15,228 bytes, 1,424 nodes, SHA-256
  91f11c6cf67610dc0682640d0c24cbd2572a0fcbdea25fdf94ff7671cf1cc861.

Both full documents contain only objects, arrays, nonnegative integers and
printable ASCII strings without quote or backslash. This is an observed fixture
property, not a general Core format guarantee. hepta/hia_program.py currently
canonicalizes with sorted keys, compact separators, ensure_ascii=False and
allow_nan=False. The experimental connection must refuse rather than normalize
any unsupported transport: negative/floating numbers, bool/null, non-ASCII,
control characters, quotes/backslashes within strings, or repeated object keys.
This excludes some legitimate Core inputs and is acceptable for this experiment.

Proposed Lean data is a restricted inert JSON tree, not a preinterpreted slice:
string bytes, Nat integer, ordered array, ordered list of key/value object pairs.
Store the complete document, including unselected blocks, attributes and edges.
A total checked serializer independently enforces the restricted string domain
and strictly increasing object keys; emits decimal digits canonically (zero is
one digit, no leading zeros), and emits exact compact JSON punctuation. No raw
fragment constructor or caller-provided serialized node is allowed.

For each full input, embed a separate literal list of byte numerals read directly
from the verified canonical bytes, not from the descriptor or tree serializer.
The kernel must prove checkedEncode rawTree = some exactBytes. Also prove the
restricted encoding is injective on accepted trees (or an equivalent checked
round-trip/determinacy lemma) before claiming it identifies a unique raw tree.
Do not substitute matching SHA strings for byte equality or assume injectivity.
The transport builder and kernel extractor must be separate implementations;
Python may propose trees/descriptors/proof scripts, never accepted proof facts.

File-to-byte provenance remains an explicit I/O trust boundary: the external
runner must compare exactBytes against independently reread canonical bytes and
bind the full source/Core/tool identities before and after. The kernel checks
its supplied byte literal, not GitHub, SHA-256, Python verification, parsing of
original source, lowering, filesystem freshness or the running Python VM. Hash
binding is not a theorem about those components or an atomic execution snapshot.

## Kernel-side reconstruction, not another Python assertion

A total, bounded/fuelled Lean function should traverse rawTree and return an
Option Descriptor. Locator inputs provide only function, header, target and
operation locations plus candidate index/extent parameter names. A supplied
descriptor is an expected result to check, not an input used to derive facts.
Any exhausted bound, missing field, ambiguity or unsupported selected shape
returns none; it cannot be encoded as a permissive other case and still pass.

Reconstruction must check at least:

1. Exact required schema/key sets for each interpreted object, duplicate-free
   function/block names and per-block binder inventories. Do not use first-match
   lookup to resolve duplicate definitions. Preserve all unselected syntax;
   unexecuted operations are not silently assigned semantics.
2. Header has the admitted sole usize compare.lt, two real operands, one bool
   output and empty attributes. Branch condition names that output. Select the
   labelled then arm, not whichever arm happens to reach the named target.
3. Source positions come from the actual ordered header parameters/definitions.
   Every selected edge argument resolves there. Target parameter count equals
   argument count, names are unique, and ALL ordered argument/parameter bindings
   are retained, including resource operands. This is syntax, not resource proof.
4. Index and extent slots are found in target parameters with real usize types;
   their incoming names match the two comparison operands. Equal target names
   on then/else arms do not identify the arms or permit using else arguments.
5. Actual selected addition has exactly two arguments, one usize output, empty
   attributes and checked or wrapping opcode. Its first operand is the selected
   target index parameter. Its second resolves to the unique earlier const
   definition with usize type, no arguments, exact value=1 and no extra attrs.
   Reject later/missing/duplicate definitions, and binder collisions. Do not
   replace body execution by an assertion that the literal executes successfully.
6. Reconstruct all Descriptor fields and prove extraction equals the separately
   proposed d. The same d must be used in Valid and selected_successor; reject
   shadowed names, alternate maximum, stale descriptor or a different raw input.

Also define a declarative SliceSyntaxRelation over raw syntax and descriptor,
using explicit membership, ordered lookup, uniqueness, scope and edge-arm facts.
It must not be defined as the equation extract raw hint = some d. Prove a generic
extract_sound theorem deriving this relation from successful reconstruction.
That exposes the checker's intended contract independently of its traversal;
concrete extraction equalities alone would only certify that traversal ran.

A narrow generic composition statement may have this shape:

  extract raw hint = some d -> Valid d ->
  evalGuard maximum d env = some true ->
  the existing projected selected-successor conclusion.

That composition is deliberately modest. Per-input kernel certificates supply
extraction and Valid, rather than accepting Python booleans as either premise.
The existing generic theorem supplies the conditional arithmetic conclusion.
Concrete small/upper witnesses remain required to rule out unusable descriptors.
An implementation must not relabel this syntactic connection as actual VM
execution: runtime compare updates a bool binding, executes ticks, transfers
all edge values simultaneously, and executes each body instruction before add.
Those semantics, traps, quotas, resource identities and body-arrival remain open.

## Refutable acceptance tests

Use three independent kinds of negatives; preserve which layer rejects them.

- Transport: alter one canonical byte with tree held fixed; omit an irrelevant
  field/block; reorder an array; duplicate/reorder object keys; inject unsupported
  escapes, Unicode, floats/bools, negative values or ambiguous decimal spelling.
  Expected result is failed byte equality or checked transport rejection.
- Syntax: with a freshly byte-bound mutated Core, keep the old descriptor/hint
  and mutate condition, then/else arguments, extent phi, parameter order alone,
  literal value/type/order, add opcode/operand, definition uniqueness or attrs.
  Require failed extraction/Valid, not merely a Core verifier failure. Include
  well-typed mutations such as wrong extent phi and same-target opposite arms.
- Implementation: change Lean reconstruction to always choose slot zero, select
  else arguments or accept a second definition. Existing concrete certificates
  and distinct-slot witnesses must fail at intended theorem locations. A test
  suite that checks only the pristine Python exporter is insufficient.

Positive controls: both real full Core documents and their eight slices; the
existing crossed-parameter/all-ingress permutation; alpha-renaming with a newly
bound document; unchanged irrelevant syntax retained byte-for-byte. Mutations
outside interpreted slice semantics may legitimately yield a fresh valid slice,
but can never reuse the original whole-document byte certificate. Test successful
zero/one and maximum-minus-one/maximum witnesses for every accepted descriptor.
Add a scope control with a trapping instruction before the selected add: syntax
extraction may still succeed, but no result may claim actual arrival or successful
execution. Never assign an unknown body operation no-op semantics to pass a proof.
Missing tools, unsupported input, timeout or unexpected errors are unknown/failed,
not a successful negative or a claim that an obligation is proved.

## Implementation and CI boundary

Start with the serializer/injectivity and one actual slice; measure kernel input
size and checker resource use before expanding to eight/nine slices. Proposed
initial hard bounds: 32 KiB input, 4,096 JSON nodes, depth 32 and 128 blocks; check
before allocating generated proof text. Fuel exhaustion returns none. These are
experimental bounds to verify against actual inputs, not general Core support.
Do not raise limits or use native_decide to make difficult equalities pass.

Reuse the existing SHA-locked Lean 4.19.0 kernel lane and 56-theorem baseline.
New proofs require explicit additional named axiom inventory, all-positive-first
ordering, intended-location negative failures and nonvacuity witnesses. No new
imports until their transitive support identity is covered. Retain per-process
and job deadlines, exact HEAD, readonly token, no target/native execution, no
artifact upload, and fail-closed source/tool/input binding. No local installation.

The first success could only be described as kernel-checked extraction from an
exact byte-bound restricted Core syntax document into the existing projected
scalar theorem. It would not complete any of the twelve global obligations or
prove Python/Core/runtime/exporter refinement, body prefix, all-edge transfer,
whole-loop induction, memory initialization, quota equivalence or performance.
Implementation, proof elaboration and actual locked CI still need independent
review. This design alone authorizes or proves none of them.
