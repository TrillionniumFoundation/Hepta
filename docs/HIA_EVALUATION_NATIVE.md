# Native Agent evaluation control

`examples/hia_bootstrap/evaluation.hepta` owns the complete control flow of
`HIAAgentService._hia_evaluate` frozen at published product commit
`19065d2f97c92d3cf28a4de1fe7387c2d5c66a02`. The original method is retained as
`_hia_evaluate_reference`; its independent original text and original
`_value_observation` are frozen in `hia_evaluate_19065.py.txt`
and `hia_evaluation_value_19065.py.txt` under `tests/fixtures/`.

A present `HEPTA_HIA_EVALUATION_MANIFEST` explicitly selects this owner. An
empty or invalid selection refuses. There is no fallback after source/image
admission or a native execution failure. An absent selector preserves the
original route and does not import the optional evaluation adapter.

## Owned policy and unchanged effects

HIA chooses every evaluation branch and loop, maintains the original
`correct`, `complete` and `budget_exceeded` flags, selects the six outcomes in
their original precedence, and issues each permitted foreign operation.
The continuation retains the original order:

1. Context, baseline/candidate artifacts and build receipt; then shared-image,
   ABI, frozen-baseline, required-claim and workload checks.
2. One deadline snapshot and baseline-then-candidate reference execution.
3. Every workload observation and its original normal/trapping classification.
4. Original native budget claim; baseline then candidate, each normal batch
   before its individual trap calls; unchanged post-exit buffer observations.
5. Confirmed budget completion, metric construction and ordered outcome choice.
6. Measurements, cost-ledger construction, cost-ledger publication, evaluation
   receipt publication and final result.

An incomplete reference still creates and completes the original budget claim
and retains both empty native-run records. A reference value/resource mismatch
does not skip the later native workload. A failed normal batch skips that arm's
trap calls. Budget/fault/invalid trap results stop only the original trap loop
and preserve the subsequent original arm/termination behavior.

The local remaining-time calculation keeps the one original deadline snapshot;
it is not replaced with repeated context SQL lookups. The existing HIA signed
integer kernel is compiled into this same image for exact-int deadlines,
differences and comparisons. Its storage follows actual operand byte extents,
with no additional integer magnitude or decimal-digit quota.

The integer true division `(before-after)/before` remains the original CPython
binary64 operation, as does its binary64 threshold comparison. Its rounding,
signed zero, overflow and exceptions are not replaced by a fixed-width or
fixed-point approximation. These operations are explicitly **hosted**, not
claimed to be HIA arithmetic. The zero-denominator branch is selected by HIA.

## Foreign boundary and custody

Opaque Python row/object/iterator/equality protocols, original schema and
buffer validators, claims/artifact providers, clocks, SQLite, runner processes,
execution-budget objects and Store publication remain fixed foreign ports.
The `_value_observation` helper also retains its current contract. The adapter
does not invoke the old evaluation body or compute the final outcome itself.
The original child, VM, workload, memory, instruction and wall-clock limits
are unchanged. No new frame-count quota or service-wide exclusion is imposed.

Each private frame uses identity, sequence, claim and acknowledgement state.
An unconfirmed native result fences the frame and retains its actual foreign
owners in process custody. It cannot rerun a child, repeat a publication or
implicitly complete/refund the native budget. `EvaluationUnknown` is a
`RuntimeError`, so the original request wrapper cannot misclassify uncertainty
as an ordinary rejected-and-completed request. Confirmed foreign exceptions
retain their original Python class and payload; budget completion is not
moved into a `finally` block. Confirmed terminal paths release process custody.
Ordinary exceptions at the native transport boundary are classified as
`EvaluationUnknown`; process-control signals keep their original classes.

The 128-byte state and 112-byte observation are a private six-argument byte
ABI. The helper allowlist admits this single image through the existing whole
bundle hash and packaged source identity. Context integer routines are part of
this image, not an implicitly injected companion executable. The wheel retains
`_data/examples/hia_bootstrap/evaluation.hepta`.

## Independent qualification

`tests/fixtures/evaluation_callers_19065.json` freezes 183 original methods in
twelve complete modules: seven ordinary modules with 81 methods, the four
original administrator-scope modules with 90 methods, and the original
cost-ledger component's 12 methods. The ordinary qualifier runs all 81 methods
with the retained evaluation body forbidden and records actual continuation
and integer entries. Explicit administrator bundles keep their original scope;
the qualifier never injects the new helper into those old bundle inputs.

Independent scenarios derive expected effects, results, exceptions and all
publication payloads from the frozen original method, rather than following
the new image's issued ports. Core VM and actual native byte observations,
real ordinary callers, lost-acknowledgement controls and the installed original
worker are separate evidence boundaries. A development build is not matching
source cold qualification. These component observations do not establish
whole-project dynamic-caller closure, general compiler correctness, whole
native delivery or readiness to delete the retained reference.

An additional public composition control pins six owners together: evaluation,
cost ledger, service context, Store lifecycle, execution budget and candidate
budget. It uses the original Agent fixture to freeze a 3,000 ms context, build
both artifacts and evaluate a real workload under the original 1,000 ms native
budget. Every selected image must receive real entries while its retained
policy is forbidden. It reads the actual measurements, ledger, evaluation
receipt and durable budget row; exact request replay must add no native entry
or SQLite change. The original request journal, runner, SQLite and object
protocols remain hosted. This integration check supplements the independent
original-caller and installed-worker gates.
