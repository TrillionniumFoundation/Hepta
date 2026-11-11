# Native edit presentation: complete reference map and pending ABI

This new isolated component starts from the exact public renderer sources
recorded in reference/source.json. No product selector has changed. This is a
design and source-analysis checkpoint, not a native execution result.

## Owner boundary

The complete target is render_edit_context and render_batch_context, including
their checked bodies, display_atom, display_signature, and all comparisons,
deduplication, formatting and refusal order they perform. Native program
admission, query preparation, edit application, immutable source capture and
general bounded-JSON services are separate owners with explicit interfaces.
Neither renderer may rely on its input having come from prepare_edit.

The single checked body is about 150 lines plus 45 shared display-validator
lines. The batch checked body is about 140 lines. Validation and presentation
can be split into multiple HIA images sharing one private state without raising
compiler limits. Any such split must preserve one complete owner and old error
ordering, not expose a hosted semantic plan.

## Public entry and error boundaries

Single entry accepts an in-memory value. It checks exact dict/root fields and
schema before calling bounded_json_wire. It does not decode the resulting wire;
all subsequent checks observe the original types and insertion order.
Consequently tuple values in some iterable operation fields are accepted,
while exact-list requirements in signature/fields/dependency/downstream
positions remain exact-list requirements.

Batch entry first calls _bounded(query, 1 MiB, "query"). For bytes/text this
checks the original payload length and decodes it; for another value it calls
bounded_json_wire before decoding. This converts tuples to lists and admissible
nonstring object keys to their JSON spellings before renderer validation. The
text path also retains predecode node/depth/duplicate-field/Unicode behavior.

Both wrappers preserve HIAEditRejected unchanged. They catch KeyError,
IndexError, TypeError, AttributeError, ValueError, UnicodeError and
RecursionError from other operations and wrap them as respectively:

- E_HIA_QUERY: malformed edit presentation
- E_HIA_EDIT_BATCH: malformed batch presentation

HIAProgramRejected is a ValueError. An invalid/reserved ASCII identifier from
_ident therefore becomes the generic malformed presentation error, rather than
the explicit invalid Agent display identity error for wrong type/empty/too-long
values. This distinction must remain.

The bounded-JSON owner emits E_HIA_EDIT diagnostics, which pass through these
wrappers. Its DFS examines dict keys in insertion order before visiting values;
values/list children are stacked in insertion order and visited in reverse.
Keys do not count as value nodes. The gate covers exact dict/list/tuple, aliases,
active cycles, queued counts, depth 128, node budget min(maximum,262144),
per-string escaped length, scalar/key kinds and key conversion collisions,
followed by sort_keys=True/ensure_ascii=True canonical encoding and the
cumulative byte limit. Finite floats must retain binary64 value and exact
canonical printing. Unsupported values and mixed incomparable sort keys retain
their old refusals; metadata not used by the renderer is still scanned by this
gate.

## Single renderer sequence

1. Require exact root keys schema/base_sha256/input_sha256/selector/fields/
   operation_sha256/context/scope and schema edit-query.v2 or v3.
2. Call complete bounded canonical wire on the whole query, maximum 1 MiB.
3. Require exact context and selector dict types, selector keys exactly
   function/block/output, and fields a nonempty unique list from op/args/attrs
   of at most three entries.
4. Fetch context.function. Validate its exact four-field signature, plus
   return_loans only for v3. Validate name, exact three list fields, each exact
   name/type parameter dict, parameter uniqueness, and every returns/effects
   atom. For v3 validate origin list arity, null nonloans, loan parameter source
   and mutable-origin compatibility, in that order.
5. Require callees to be a list and validate every callee signature completely.
6. Validate selector function and function signature name; require equality.
   Validate selected output atom, then every operation output name, then require
   membership. Do not stop the list comprehension on the first matching name.
7. Form the function line and selected-block header, validating all names/types
   in their original iteration order. V3 canonicalizes return_loans here.
8. Require exact nonnegative int operation_index (bool does not qualify).
   Require dependencies and consumers lists. Combine dependencies, consumers
   and selected operation; reject more than 256. Fetch all indices before
   checking integer/nonnegative/duplicate conditions.
9. Stable-sort by index; render each operation, prefixing EDIT on the selected
   index. Operation formatting validates all output names/types, then all args;
   truthy attrs are canonicalized before validating the opcode as dotted atoms.
   Append the complete canonical terminator.
10. Require downstream list and total blocks at most 64. For each block in
    input order:
    - Require its exact eight keys.
    - Validate id; reject selected/duplicate ids.
    - Require params and affected_params lists; require exact parameter dicts.
    - Validate every parameter name before duplicate-name rejection, then names
      and types for header construction, then every affected atom.
    - Require control_reachable exact bool; require affected nonempty unless
      control-reachable, unique affected names and membership in parameter names.
    - Require dependency/consumer lists, add their entries to the cumulative
      256-operation budget, require exact operation-record fields.
    - Fetch all indices, then validate exact nonnegative int/uniqueness.
    - Require branch_condition_affected exact bool and terminator exact dict.
    - Add downstream header and optional control-reachable text.
    - If branch_condition_affected, require term.op == "branch" before adding
      the branch-dependence text.
    - Sort and format its operations, then append canonical terminator.
11. Canonicalize each callee in original list order, prefix "callee ".
12. Join all lines using one newline, with no trailing newline.

Context does not have an exact-key check. Same-block operation records do not
have the downstream exact-record check. Operation attrs and terminators are not
silently strengthened to dicts outside the stated original checks. Scope and
digest fields are not validated as strings by the single renderer. These
intentional observations prevent adding new display-language restrictions.

## Batch renderer sequence

1. Complete _bounded and decode as above before checking exact outer keys and
   batch-query.v2/v3 schema. This fixes the corresponding nested query version.
2. Require sites exact list with 1..16 entries.
3. Process sites in their given order:
   - Require exact site/query dict fields, exact int site, site equals its index.
   - Require exact nested query keys and matching schema.
   - For base_sha256 then input_sha256, require the OUTER value exact str and
     compare complete canonical wires with the nested value. Canonical equality
     cannot use Python bool/int/float equality.
   - Require nested context and selector dicts.
   - Run the full single renderer with its original errors and side effects,
     discarding its completed text only after it succeeds.
   - Reject repeated (function,block,operation_index), including aliases from
     different SSA outputs of one operation.
   - Retain function signature; conflicting canonical bytes for one name reject.
     Selected function insertion order is first occurrence, value last write.
   - Retain selected block by (function,block); compare canonical params before
     canonical terminator, rejecting contradictions with earlier downstream or
     selected appearances.
   - Merge dependencies, consumers and selected operation in that order,
     checking canonical equality for each previously present index before
     replacing it. Record selected marker (site,fields).
   - Retain callee signatures globally, then each callee in that block by name,
     preserving first-insertion order and last value.
   - Process downstream blocks in order, compare params/term metadata, union
     affected names, OR control_reachable, and merge dependency then consumer
     operations with the distinct downstream-conflict diagnostic.
4. Render selected functions in first-insertion order. Render blocks for that
   function in global block first-insertion order, including downstream-first
   appearances. Sort affected names lexically. Sort operations by numeric index.
   Emit exactly one @site{fields} marker per retained selected index, with fields
   in their supplied order. Preserve different single/batch spacing.
5. Append block canonical terminator and block callee records in first-insertion
   order. Join all lines without a trailing newline.

The batch renderer reuses standalone validation but has additional signature,
block and operation equality constraints. It does not require every signature
name to appear in the selected-functions table. It deduplicates callees per
block, not once for the whole display.

## Exact diagnostic vocabulary to assign native codes

Single explicit diagnoses:

- expected exact prepared edit query fields
- malformed edit context/selector
- invalid rendered selector fields
- invalid rendered field selection
- displayed function signature requires exactly its declared fields
- invalid displayed function signature lists
- invalid displayed parameter
- duplicate displayed parameter
- return_loans must match displayed return arity
- nonloan return must have a null origin
- returned loan must name an input loan parameter
- mutable returned loan needs a mutable input loan
- invalid Agent display identity
- invalid displayed callee list
- rendered function disagrees with selector
- rendered SSA output disagrees with selector
- rendered operation index must be a nonnegative integer
- rendered SSA context lists are malformed
- rendered SSA operation budget exceeded
- duplicate or noninteger rendered SSA indexes
- missing verified CFG downstream presentation
- rendered CFG context exceeds block budget
- malformed downstream CFG block presentation
- duplicate/selected downstream CFG block
- invalid downstream SSA block parameters
- invalid downstream typed SSA parameter
- duplicate downstream block parameter
- invalid control-reachable CFG flag
- unbound downstream affected SSA parameter
- invalid downstream SSA operation collections
- rendered CFG context exceeds SSA operation budget
- invalid downstream SSA operation record
- duplicate or invalid downstream SSA operation index
- invalid downstream branch-affect flag
- invalid downstream terminator
- non-branch CFG flagged as affected condition

Batch explicit diagnoses:

- invalid query (the _bounded conversion catch boundary)
- query exceeds byte budget
- expected exact prepared batch query fields
- invalid query sites
- batch display sites must retain unique ordered integer identities
- invalid nested edit query presentation
- nested edit query belongs to a different snapshot
- invalid nested edit context/selector
- batch display sites overlap one instruction
- conflicting displayed function/callee signature
- conflicting displayed CFG block metadata
- conflicting displayed operations
- conflicting downstream SSA operation

There are also propagated bounded JSON and decode errors, plus the two generic
wrapper failures described above. Their categories and first-error order must
not be replaced by one universal validation error.

## Interface under coordination

A pre-normalized integer-only packet is insufficient. The production input must
preserve the caller's exact single-renderer types, insertion order and shared
container identity. A generic value/IR lease can keep tuple and foreign-kind
tags alongside JSON kinds, raw binary64 bits for floats, exact integers, and
reference identities for cycles/aliases. A fixed capture bridge may transport
these facts but must not select fields, normalize values, decide limits, validate
identifiers, merge contexts or format output.

A general canonical-wire native service may be called through typed
continuations at the exact old _wire positions. A corresponding native
bounded/decode service is required at batch entry. The renderer itself owns
which value is requested, the ordering and complete equality/format decisions.
Public-object capture and service shape are being aligned with the parent
Agent edit coordinator before authoring the complete kernels.

Candidate actions are WIRE(value,maximum,options), DECODE(raw,limits), GROW,
DONE(text), REFUSAL(error/cause), with immutable source leases and all offsets
reborrowed after GROW. No new semantic quota is introduced by storage growth.
This is not yet a frozen ABI; implementation and actual differential evidence
will establish a new revision.

## Required independent comparisons

Use all retained edit query/batch/CFG/control/identity/transitive tests as
reference input producers. Add malformed multi-error cases to establish the
sequence above, valid float attrs and unused metadata, true/1/1.0 canonical
distinctions, tuple positions, numeric keys and mixed-key refusal, reserved and
invalid ASCII identities, parameter/origin cases, no-result effects, reversed
selection order, downstream-first metadata conflicts, source mutation/custody,
exact 1 MiB/256-operation/64-block/16-site boundaries, cycle/alias and depth/node
boundaries at the general wire service.

Both actual HIA images and the entire source-bound service chain must be run
before any new public selection or complete-native claim. Missing services must
remain explicit blockers, not hidden Python callbacks.
