# Real structured edit interface: engineering stage

This directory implements an actual structured editing interface before a new
Agent experiment. It does not relabel v4/v5/v6 whole-function replacement as node
editing. No model main cohort has been registered or run under this interface.
The fresh v6 model still failed the unchanged eligibility gate; reference controls
cannot make that model eligible.

## What a model can change

The host derives a complete node catalogue from the actual public source and the
trusted editable symbol scope. It includes no golden node choice, correct edit,
hidden input or answer menu. A response contains an actual project revision, a
complete query digest, and up to sixteen named node edits. A request cannot name
an arbitrary file or command, replace a whole file/function, alter omitted
helpers, change the edit scope, or forge its own query. All four physical source
files contribute to the transaction revision; the HIA Core/input identities are
also retained.

Rust entries are expression or type nodes parsed from the actual source, with
byte spans, shape and syntactic operator anchors. A replacement must parse as one
complete fragment of the same category. The adapter then reparses the entire
function and checks every unselected node and enclosing syntactic anchor.
Replacing `x` with `a+b` inside `x*2` cannot silently change the multiplication's
parse tree: the request must supply `(a+b)`, otherwise it is refused. The host
does not insert parentheses, casts or repairs. Duplicate and overlapping
ancestor/descendant selections are refused before reconstruction.
Parameter and return type nodes are read-only under the host's `preserve`
policy; their migration requires the explicit query-bound `migrate` policy.

This is a finite ASCII Rust parser, covering scalar/Vec types, calls, permitted
method-call forms, arithmetic, casts, indexing, simple lets, assignments,
returns, if/block expressions and the disclosed `vec![value;length]` form.
Comments, Unicode, strings, attributes, macro definitions, closures and general
Rust syntax are outside its scope. CRLF offsets are real ASCII byte positions.
Both recursive descent and the constructed AST are bounded to depth 64, including
else-if recursion and long iterative postfix/binary chains.
The parser is not a type checker or a general Rust compiler. Its result is
explicitly a `syntax_proposal_unadmitted` until whole-source admission and actual
rustc validate it.

HIA entries identify instructions, terminators, block parameter types and
function signature types. Ordinary output-bearing SSA instruction field edits
use the existing production `prepare_batch`/`apply_batch`. Remaining instruction
and terminator edits use the production patch verifier. The production patch API
currently has no granular signature, block-parameter, insertion or deletion
action. For those operations the adapter rebuilds exactly the affected function
containers from the original source plus the selected node edits, reports those
containers in the receipt and calls the existing explicit v2 patch API. No
function body comes from the model. Signature migration requires the host's
explicit migration policy; parameter names and arities are unchanged. No claim
is made that external ABI callers are proven compatible.

## Transaction and validation boundary

`ValidatedTaskSession` is the runnable tool boundary. It reconstructs its query
from the current complete project, checks both response identities, prepares all
node changes, preserves unchanged files, and invokes the existing finite source
admission and actual compiler. It then runs bounded public native observations
only when the compiler result is explicitly `compiled`; a failed compiler
identity gate prevents execution even if a binary had already been emitted.
and, for HIA, the existing independent VM/resource observations. A failed syntax,
type/borrow, public functional or resource check leaves the complete project
revision unchanged. The successful validation receipt is retained before the
single in-memory revision update. No candidate is published into the repository.
A per-session reentrant lock covers source/query reads and the entire validation,
receipt and commit transaction. A second request based on the old revision cannot
overwrite an intervening accepted edit. Event-barrier mocked-compiler regressions
exercise that concurrency boundary and receipt-storage failure; these mocks are
not counted as native executions or model successes.

Hidden observations are a terminal external evaluation step, not edit feedback.
The engineering control runner retains them separately. Both languages use the
same sixteen-edit and 64 KiB response caps, fixed compiler invocation, memory/CPU/
wall bounds and public feedback format. A future model comparison must also
preregister equal model, generation, tool-call and repair budgets. These engineering
checks alone do not establish Agent efficiency or language superiority.

## Verification

The static suite tests real HIA atomic loan swaps, rejection of invalid ownership,
type/signature migration, insertion with terminator changes, source/query binding,
unknown and unauthorized nodes, duplicate/overlapping selections, macro/statement
escape, byte offsets and preservation of enclosing Rust syntax. The no-model native
runner is `tools/qualify_hia_structured_controls.py`. It must run only after its
source and this protocol are committed and retains complete source snapshots,
compiler identities, queries, responses, generated code and results.

Native controls cover real multi-file Rust expressions, type/API upgrades and
moved-owner repairs; incorrect compiler/semantic cases must leave revisions
unchanged. HIA controls execute actual production SSA batch and explicit type
migration paths. Every control is labelled as a human reference and excluded
from model-success counts. They use dedicated already public calibration semantics,
not modified main-task hidden cases or solution hints. Query/response envelopes
can be inspected without running any model.

This remains a small four-file study tool. It does not yet measure long-term
production maintenance, and the HIA editing base must already be valid Core.
Handling syntactically/ownership-invalid HIA inputs is a separate frontend repair
problem; the production Core safety boundary is not relaxed to make those inputs
editable.
