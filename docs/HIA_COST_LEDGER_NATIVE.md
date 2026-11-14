# Native Agent cost-ledger owner

`examples/hia_bootstrap/cost_ledger.hepta` owns the control flow of the frozen
`HIAAgentService._cost_ledger` body from product commit
`b569c210a807af29a3ad816679f2b9437c5c6875`. Its independent original fixture is
`tests/fixtures/cost_ledger_b569c210.py.txt`. The portable method remains the
unchanged reference; a present `HEPTA_HIA_COST_LEDGER_MANIFEST` selects the native
owner and never falls back after an admission or execution failure.

## Exact policy and foreign operations

The native continuation requests the original SQLite query with `ORDER BY
sequence LIMIT 10001`, selects only the first 10000 returned rows and records
truncation from the original returned count. It projects and decodes every
retained row before loading the cost policy. It makes the external-completeness
choice and iterates the copied keys when unknown values must become `None`.
It then scans the retained rows twice, first for the exact context identity,
then for null/unscoped rows. Only selected rows reach the original `int()`
conversion. Row comparison and all signed addition execute HIA instructions.
The final schema, field order, fixed values and `str()` conversion order match
the original method.

SQLite query/fetch, JSON decode, CPython row and object access, `dict`/list
allocation and `int`/`str` conversions are explicit retained foreign primitives.
The native signed byte adder has no extra magnitude or byte ceiling. Allocation
sizes follow the actual input representations, and redundant sign bytes are
trimmed by HIA. Negative values, cancellation and values beyond u64 retain the
original behavior. The adapter performs no ledger sum or attributed-row filter.
Python's configured decimal-conversion limits and exact first exceptions remain
owned by the original conversion primitives.

The method performs no persistent ledger write or commit. Issued effects use
identity/sequence/claim/observation state; an unconfirmed return fences the
current frame and cannot replay a read. Ordinary foreign exceptions are
propagated by HIA and preserve their original Python exception. Frame buffers
are private and cannot be resumed from another thread or process. This does
not replace the service's journal, SQLite engine or worker authority.

## Evidence and packaging

`tools/build_hia_cost_ledger.py` keeps the existing compiler profile, CPU and
buffer bounds. Strict construction requires the complete current source cold
report; explicit `--development` construction has a separate development scope.
The worker helper allowlist admits the sole cost-ledger image using its existing
whole-bundle digest and packaged source custody. A real ordinary wheel includes
`_data/examples/hia_bootstrap/cost_ledger.hepta`. Native controls run the installed
original worker with the old ledger forbidden, bind the actual helper bundle,
and observe exact journal replay without repeating ledger arithmetic.

`tools/qualify_hia_cost_ledger_callers.py` runs all **81 methods in seven complete
ordinary caller modules** under their original budgets. It poisons the retained
ledger method in the test process, records actual continuation/add/equality
entries, and checks exact planned/started/stopped identities, zero anomalies and
source/image readback. Child processes inherit selection; the report does not
claim that Python monkeypatches propagate into a fresh child.

The inventory `tests/fixtures/cost_ledger_callers_b569c210.json` also freezes the
90 original methods in four separate administrator-scope modules: candidate
budget, execution budget, slot-ledger integration and worker native helpers.
Those modules construct their own narrower pinned bundles and clear inherited
selection. Their original owner/full-discovery gates remain required. The ledger
caller gate never injects a helper into those bundles. The new installed worker
witness separately proves the explicit cost-ledger composition.

Source generation, independent Core VM observations, native differential cases,
real SQLite error precedence, 10001-row cutoff, wide signed sums, lost-read-ACK
fencing and actual installed worker controls are retained separately. None of
these component observations establishes whole-project dynamic-caller closure,
whole-native delivery, formal correctness of the compiler or deletion readiness
for the portable reference.

## Recorded performance boundary

The final isolated development run retained 10,000 rows in two cutoff cases.
The original method took 113.114 and 95.455 ms; the selected HIA path took
1,413.735 and 1,429.640 ms. These observations show a roughly 12.5–15-fold
regression and do not establish a performance benefit. All original test and
product deadlines remain unchanged. Evaluation samples its own elapsed time
before ledger generation, while the outer request cost includes generation;
there is no original context-deadline recheck around the ledger call. The
selected path preserves that existing measurement and deadline behavior.
