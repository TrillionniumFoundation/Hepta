# Preparation-aware invocation on the actual HIA cost path

`hepta.hia_ndu_cost` is the full-cost model used by
`tools.qualify_hia_ndu_cost.py`. Its previous gate granted every valid artifact
free preparation and proof. The exact continuation search still charged those
costs, so this was not a claim of an incorrect optimum. It did cause optional
search to run when even the most optimistic recoverable savings could not pay
for preparation. The separate native dynamic-cache experiment had already
addressed a related issue; its implementation did not change this HIA path.

The replacement gate keeps the old lower bound and adds a second relaxation.
All dynamic control arms use this gate. The current call, startup, cleanup,
every remaining gate, actual preparation and proof, and the executor's own
admission checks retain their existing accounting and authority boundaries.

## Finite-model bound

For one verified artifact in one uninterrupted valid segment, sum the positive
baseline-minus-artifact execution savings after subtracting that artifact's
holding cost for each batch. Call this sum `S`. If the artifact is initially
resident and valid, it can recover at most `S`. Otherwise it must first pay its
nonnegative preparation plus proof cost `P`, and can recover at most
`max(0, S - P)`. Every invalid batch ends the initial resident credit. An artifact
larger than the entire quota cannot be prepared and supplies no saving.

Subtract the sum of these per-artifact segment savings from the all-baseline
cost. This remains a lower bound because it grants free retirement, ignores
competition for resident memory, ignores negative holding intervals, and allows
overlapping artifact savings to be added even though only one artifact can
supply the minimum execution cost of a batch. Within a valid segment it grants
free release/reacquisition between useful intervals after the first preparation;
a real schedule cannot obtain more benefit at a lower preparation cost.

Taking the maximum with the previous free-execution lower bound prevents
overlapping savings from weakening that bound. Add the unchanged common gate,
current invocation/startup and required session-close costs. If the resulting
optimistic invocation cannot improve a feasible incumbent, skip the optional
search. If neither delivery nor any invocation can fit the supplied budget,
refuse. This does not deny an improving or budget-feasible schedule within the
declared finite model.

The calculation is linear in artifacts times the remaining horizon (currently
at most two artifacts and four batches). It builds no plans, launches no native
process and retains no request state. Nonnegative zero costs remain legal under
the existing schema; negative, boolean and otherwise invalid cost values are
rejected before either bound is evaluated.

## Evidence and interpretation

The dedicated regression checks include preparation/proof that cannot amortize,
initial residency, repeated invalidation, over-quota artifacts, overlapping
savings, holding costs that make release worthwhile, zero-cost ties and invalid
input costs. A fixed 256-model finite set is compared against the existing
independent enumeration of every complete schedule, including committed-call
costs and budgets immediately below, at and above each exact minimum. These are
finite implementation checks, not a machine-checked general theorem.

The actual HIA qualification retains the original four arms, three scenarios,
three repetitions, training/evaluation seeds and all original budgets. It runs
once on the newly frozen source, keeps every sample and reports all costs and
negative outcomes. Prior source combinations and their measurements are not
replaced. No model-training or Agent-generation cohort is repeated.

Stronger invocation bounds do not establish NDU's independent value. Native NDU
must still beat the same-information strong fixed, lightweight and exact-DP
controls after measured overhead. This bound has no authority to activate code,
certify program safety, guarantee physical deadlines or assert global machine
instruction optimality. Production authority remains `DENY_ALL`.
