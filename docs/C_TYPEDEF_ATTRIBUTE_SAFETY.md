# Project typedef attributes: fail closed before canonical lowering

The project translator does not implement attributed-typedef ABI layout.
Canonical `int` is not sufficient evidence that a typedef has ordinary layout:
Clang can retain `aligned` on TypedefDecl while desugaring the field type to int.

At exact baseline `e221d0e182c322d6b9a06ed9787f37c521dbe908`, automatic run
40152643065 passed the existing 19 prototype gates / 723 tests / zero skips,
then **failed** the additional source-unchanged typedef regression probe.
Original artifact 12582748803, SHA-256
`2ad9b1881db95f2478b5273a815cd066c9ce1226a0245702f20d5c1dcde85191`, contains
four attributed cases and two ordinary controls. Actual Clang 19.1.7 and GCC
14.2 original C layout was size/alignment/field offsets `32/16/16/20`; actual
translated C and Rust 1.90 layout was `12/4/4/8` at O0/O2. The ordinary controls
matched. All 36 comparisons used separate layout-only executables; no call
through a mismatched ABI was executed. This is historical RED evidence, not
a passing result for the repaired source.

The repair retains complete TU-local typedef declarations, including repeated
same-name declarations. It rejects every unqualified `*Attr` child with
`E_C_ATTRIBUTE` before resolving an active project alias or using a referenced
alias's desugared canonical type. Spelled alias chains are checked as well.
There is no semantic-attribute whitelist and no new alignment code generation.
Type nodes and nonsemantic `FullComment` nodes remain accepted. Existing
record/field, macro/provenance, function-signature and pointer-contract policies
are unchanged.

System typedefs remain context: a referenced attributed system alias is
rejected, while an unrelated attributed system declaration does not reject an
ordinary project. Rejection occurs before publication of the output bundle.

Twelve compiler-free regression methods cover local/header, direct/chained,
redeclared and desugared aliases, TU separation, used versus unused system
context, ordinary aliases, documentation and cycles. They are unit-policy
coverage, not new native evidence. The original six-case native probe retains
its fixtures and layout oracle; when repaired negatives reject before emitting
a bundle, no generated layout binary exists for those negatives. The original
36 baseline comparisons remain in the baseline artifact, never recounted as
new runs. Both positive controls must still execute their six comparisons.

The probe binds the repaired translator's exact SHA and explicitly records
the old red source/artifact separately. Merge/qualification requires a fresh
exact-final-head 19-gate run and passing added native regression. P01–P12,
source equivalence, foreign safety and whole-language soundness remain open.
