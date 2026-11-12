# Guarded scalar specialization and NDU cost pruning

This change adds a finite, executable optimization action and an experiment
that can report a negative result. It does not close general NDU superiority,
arbitrary native instruction search, Rust-level whole-language soundness, or
automatic C/C++ resource-contract inference.

## Candidate semantics

`hepta.hia_specialization.propose_guarded_specializations` accepts one public
acyclic scalar function and one to eight explicit `(parameter, value)`
assumptions. It emits an equality guard, an SSA-renamed specialized clone with
the corresponding constant argument, and an SSA-renamed generic clone with
the original arguments. The guard is actual canonical HIA control flow. A
profile observation is never a precondition that removes other valid inputs.

The complete request is checked before applying the output cap. Integer values
must have the exact declared range, Booleans must be exact Booleans, candidate
identities bind canonical program bytes, and existing block/instruction bounds
apply after cloning. Other functions, exports and module identity remain
unchanged. Resource operations, calls and cycles remain outside this proposal
profile. The consumer still has to perform fresh canonical verification and
all-input behavior validation on the exact selected before/after pair.

The generator can represent specified scalar traps, including division by zero
and signed minimum divided by minus one. This does not extend the native
multiversion runtime: that runtime continues to admit only total, effect-free
scalar programs. The experiment below uses only wrapping additions and xor.

## Independent proof and the single-arrival encoding reduction

The prior translation validator encoded even a block with one incoming edge
as `If(edge_guard, argument, zero)`. That expression was nested inside every
subsequent arithmetic expression, despite all observable outcomes already
being guarded by the same reachability condition.

For **exactly one** arrival, the encoder now directly uses the argument.
Whenever the block executes its edge guard is true, so the old and new
parameter expressions agree. Outside the guard, scalar bitvector expressions
remain total Z3 terms, while traps, return observations and successor edges
remain masked by reachability. Zero-arrival defaults, multiple-arrival guarded
phi merges, complete outcome guards, missing-path detection and ordered
first-trap guards are unchanged. There are no new axioms, optimization-specific
proof shortcuts, longer timeouts or accepted serialized proof authorities.

`tests.test_hia_encoding_guard` contains a frozen prior encoding and asks the
real solver for UNSAT of its difference from the revised encoding. Cases
cover a single-entry chain, a permanently unselected trapping branch,
division before a branch with a later trap, a multiple-predecessor merge, and
an internally constructed zero-arrival block which canonical admission still
rejects. It also requires a concrete replayed counterexample when a generated
guard is replaced with `true`. Existing tests continue to cover unknown,
solver absence, missing symbolic paths, stale/forged receipts, concurrency,
checked arithmetic and first-trap semantics.

Development attempts are retained separately. Under the prior encoding, the
eight-round `add+xor` specialization and the wider multiply/add/xor experiment
returned `unknown` after the unchanged 5-second limit. A bounded generic Z3
tactic experiment did not reliably resolve them and was not adopted. The
single-arrival reduction resolved the add/xor proof in a development check;
the multiply/add/xor example still timed out and remains rejected. The initial
u64 checked division/remainder specialization also timed out in the prior
encoding. No performance result is attributed to those unproved candidates.

## Avoiding economically dominated proof work

The ranking adapter now checks a monotone lower bound on already paid search
cost before solving a candidate's all-input query. It may refuse the query
when that cost already exceeds the resource cap, or when the measured
candidate upper cost plus paid work cannot improve the incumbent lower cost.

This check can only refuse work. A pruned candidate has `proof: null` and
`equivalence_proved: false`; it is sent to NDU with a hard violation. Canonical
verification, exact observation hash checks and the real native bridge
identity/invocation still occur. A selected candidate still needs a fresh
proof and an actual final cost gate. No cost observation establishes resource
safety or functional equivalence.

The two integrated bridges remain distinct:

| Purpose | Upstream pin | Request protocol | Authority |
| --- | --- | --- | --- |
| Candidate ranking, used here | `d3c2d760eca5065fc966820379c35c6e8d56e855` | `hepta.hia.ndu-request.v1` | `ADVISORY_ONLY` |
| Recursive utility, unchanged | `2590c0c94c5bf9a9004caeeb7b75edd6faf3eb8b` | `hepta.hia.ndu.request.v1` | `DENY_ALL` |

The separate PR326 candidate at `46bcef9` uses another upstream pin and an
observational byte-swap pipeline. Its similarly named modules are not copied
over either integrated bridge. Its interpreter dispatcher is not evidence
for this experiment's native publication behavior.

## Frozen native experiment

Run the committed source with the existing configured toolchain:

```sh
python tools/qualify_hia_specialization.py \
  --clang /absolute/path/to/clang \
  --cargo /absolute/path/to/cargo \
  --upstream /absolute/path/to/pinned-ndu-checkout \
  --artifacts /absolute/path/to/new-evidence-directory
```

The tool refuses an existing evidence directory. It writes the source-bound
protocol and all training/holdout inputs before building. The protocol has
no performance-tuning command-line switches. It builds the original ranking
NDU with a fresh target directory and retained source/build receipt; an
existing dependency cache is explicitly allowed.

The workload is an authored research function over all pairs of u32 values:
eight rounds of wrapping addition by `1, 3, 5, 7, 11, 13, 17, 19`, each followed
by xor with a runtime mask. The two proposals guard masks `0` and `0xffffffff`.
The generic path remains available for every other mask. LLVM can collapse
the guarded paths, while the baseline retains runtime mask-dependent work.
The tool records actual `calculate` disassembly and refuses to qualify if the
three functions are identical. This is not a third-party production benchmark.

Each of three profiles has 64 deterministic inputs: 62 matching the zero
guard, 62 matching the all-ones guard, or all mixed masks. Training and holdout
use different fixed seeds. All selectors receive the same measured table.
Five 500,000-call training batches per artifact/profile are retained without
dropping outliers. The uncertainty rule remains the existing conservative
rounded maximum deviation, with a minimum one nanosecond, and is not a
statistical confidence interval.

The six arms are fixed stop, fixed zero, fixed all-ones, a fixed action selected
by aggregate training cost, a direct minimum-cost table search (`light`), and
the original native NDU. Each runs twice on each profile, totaling **36
episodes** and **six NDU episodes**. Each holdout episode really executes
250,000,000 C-loop calls; this is not a projected horizon substituted for
actual work. Artifact, executable driver and input table bytes are sealed
before child execution. Actual argv, wall/CPU time, checksums, context switches
and page faults are retained. A separately written integer formula checks
every input and the whole loop checksum.

Each arm creates the same native baseline runtime. Any publication repeats
independent all-input proof and actual native build/probes, checks an actual
preparation budget, and swaps only against the current generation and epoch.
The NDU arm uses `BackgroundOptimizer` with the real bridge. The prior lease
is checked after publication, the selected lease is checked on all holdout
inputs, and published generations are rolled back while the selected lease
remains usable. This is total scalar native lifecycle evidence; it is not a
heap, loan, stack or foreign-object migration protocol.

## Cost accounting and the primary comparison

There are two separate accounting questions:

1. **Equal-information selector comparison.** Every arm is charged the same
   full measured proposal/proof/compilation/training corpus once per standalone
   episode, plus that arm's real episode wall time through runtime cleanup.
   The corpus physically runs once in the campaign; repeated full charges are
   deliberately conservative standalone accounting, not claims of repeated
   actual spending. Fresh NDU cold-build cost is additionally amortized over
   exactly its **six** episodes, never over all 36 arms' episodes.
2. **Deployment versus directly running the baseline.** The fixed-stop arm's
   observed episode wall time, with no shared optimization corpus charge, is
   the direct baseline control. Optimized episodes are compared against that
   observation while still paying their required full corpus and, for NDU,
   amortized cold build. Equal-information wins cannot be called deployment
   savings merely because the baseline was charged unnecessary search.

Warm installed-bridge admission and cold deployment economics are explicitly
separate. The runtime may publish under a warm cost gate while the separately
reported cold result is negative. Already installed Python, Z3, Clang, Rust
and prior dependency-cache creation are excluded and disclosed. All measured
build, validation, bridge, preparation and failed work remains in its ledger.

The **primary metric** is the median paired cold-amortized full-cost saving of
NDU against **every** predeclared fixed control and light across the six
matching profile/repetition pairs. The no-increment region is the larger of
1 ms and 1% of the control's median. Descriptive superiority requires exceeding
that threshold against every control and a positive median in every profile.
Even that would not establish statistical or general NDU advantage. Source
changes during the campaign, failed native observations, unproved candidates
or missing episodes prevent qualification; stop decisions and economic
publication rejections are preserved as results.

The resulting `RESULT.json` and `EPISODES.jsonl` should be interpreted at their
recorded source commit. Integrating the implementation later does not change
the campaign's source identity. Broad roadmap conditions 4 and 6 remain open
until reproducible incremental value and appropriate state/resource profiles
have their own evidence.
