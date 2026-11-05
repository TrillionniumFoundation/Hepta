# Preparation-aware invocation bound

The dynamic cache experiment previously used the sum of the faster direct or
packed execution costs as its optimistic lower bound. This assumes that every
announced artifact can become resident for free. On short requests the gap to
that bound can exceed the solver cost even when preparing the data cannot pay
for itself. Native beam then spends time constructing and replaying up to four
full witnesses, although retaining the current cache is already preferable.

The replacement keeps preparation costs and declared version boundaries in a
separable lower bound. It relaxes shared capacity, retirement and future solver
costs. The exact same bound and measured gate construction overhead apply to
light, exact DP, beam and beam plus NDU.

## Arithmetic argument and limits

For artifact i in one announced epoch, let S_i be the sum of positive predicted
direct-minus-packed savings across requests for that artifact. If the artifact
is initially resident at the matching epoch, all S_i can be recovered for free.
Otherwise recovering savings requires at least its nonnegative preparation
cost P_i, so the maximum recoverable savings is max(0, S_i-P_i). A version
change starts a new absent segment. Subtract these independent savings from
the all-direct cost and include the common per-step gate cost.

Any feasible original schedule has no more savings: it pays for every required
preparation and additionally observes a shared quota, nonnegative retirement
costs and future solve costs. Dropping those restrictions cannot increase the
minimum. Thus the new bound is no larger than the exact minimum under the
supplied deterministic model, and is at least as tight as the old free-prepare
bound. There is no general runtime or language-safety theorem in this argument.
Forecast errors can still make actual execution slower than expected.

Admission still charges current call/startup and reserved cleanup, retains
independent epoch/quota validation and checks budget again at actual prepare.
A skip is not a claim of whole-program global optimality; it only rejects a
solver request whose best modeled improvement cannot pay for its modeled cost.

## Verification

The added tests compare 240 generated finite models with independent bottom-up
state enumeration. They also exercise repeated data epochs, matching and stale
initial residents, and a short burst whose preparation cannot amortize. The
finite checks support implementation conformance; they do not constitute a
machine-checked general theorem.

The original 432-episode result and 0/24 NDU net-win result are preserved. A new
single registered run uses all six schedule families, the same six arms and
cost rules, and prospective dimensions 320/1024 with seeds 104729/130363 chosen
before observing these timings. It remains an independent native cache
experiment and does not qualify HIA compiler integration. Complete end-to-end
service, training/calibration/build, control refusals, oracle gap and audit
costs must be reported, including negative outcomes.
