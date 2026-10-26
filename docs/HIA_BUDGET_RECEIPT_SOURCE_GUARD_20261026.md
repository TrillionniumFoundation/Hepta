# HIA P1/P2: exact function-denominator static budget receipt guard

Scope: source-facing build_checked_hepta_hia_native using the existing
verified HIA Program and the existing analyze_static_budget computation.
No second resource analyzer, parser, ownership checker, VM or LLVM backend.

## Discovered trust-boundary defect

The old builder accepted an otherwise plausible resource receipt whose
functions array was empty: the check for unacceptable row values used
any(...), which returns false on an empty array. An accidentally truncated
or deliberately forged (and self-rehashed) budget could therefore be
accepted without covering the executable program's complete functions.

The corrected source gate re-verifies the immutable Core, compares its
exact function inventory and order against all budget rows, refuses an
empty/partial/duplicated/reordered set, and checks every required finite
integer field. The analyzer's status, exact schema fields, current Core
SHA, canonical payload digest, exact requested limits, and every proof
claim have strict type and field-set checks. Boolean false is not Python
integer zero. In particular the receipt cannot claim proof of CPU/RSS,
whole-language soundness or source-to-Core refinement.

All explicit limits are independently checked against each function row
before the native LLVM emitter runs or artifact publication starts. The
original static analyzer remains the only authority that computes those
upper bounds; the new gate is a source-bound receipt and proof-scope
integrity check. A self-sealed fake row with a smaller numeric upper bound
cannot generally be proven false by checking the receipt metadata alone:
correctness of the underlying analyzer is still a separate test/proof
obligation. A receipt SHA authenticates bytes, NOT theorem truth.

## Regression

    python -m unittest tests.test_hia_budget_receipt_guard -v
    python -m unittest tests.test_hia_heap_bound tests.test_hia_heap_intervals \
        tests.test_hia_static_budget tests.test_hia_static_budget_cli -v

Committed adversarial cases include intentionally rehashed empty and
missing function inventories, duplicate/wrong order, bool-as-int proof
forgery, unknown proof fields, deleted/extra per-function quantity,
wrong source identity, oversized/mismatched policy, and a mocked native
preflight verifying refusal occurs before emit_program_llvm.

No successful physical execution, native ABI completeness, Rust-equivalent
all-program proof, performance superiority, or complete P0–P7 closure follows
from validating receipt shape and source identity.

whole_project_blockers_closed=false
