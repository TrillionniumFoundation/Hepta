# Finite economic search and total byte specialization

This change adds a bounded measurement controller and a new, explicitly authored
native research workload. It does not establish an NDU performance advantage.
The prior `01310b2` experiment remains a negative result: every holdout used the
baseline and none of its small warm timing differences was an optimization gain.

## Why the previous ranking had no extra decision power

The existing candidate-ranking adapter uses upstream
`d3c2d760eca5065fc966820379c35c6e8d56e855`. Its actual Rust entry point is
`evaluate_candidates_with_policy`, with:

- one `hia-compiler` contribution per candidate;
- one `total-ms` utility axis, minimized;
- a `search-ms` hard resource ceiling;
- zero Pareto tolerance and no scalarization profile;
- all runtime observations supplied before the call.

After infeasible candidates are removed, the unique minimum on that single
utility axis is the unique Pareto recommendation. Equal minima produce a slow
path/tie rather than a new observation or an intelligent tie break. Uncertainty
was already included in the host's conservative total-cost scalar. The bridge
does not generate instructions, predict omitted measurements, or learn a policy.
An exact simple minimum over the same legal rows can make the same decision.

Source: `rust/hia-ndu-bridge/src/main.rs` and the pinned upstream
`codex-rs/hepta-ndu/src/evaluator.rs` / `scoring.rs`. This diagnosis concerns the
specific wired adapter, not every possible future NDU application.

## What the new controller actually does

`hepta/hia_economic_search.py` uses the separate recursive adapter at upstream
`2590c0c94c5bf9a9004caeeb7b75edd6faf3eb8b`, through
`hepta.hia.ndu.request.v1`. This is not the ranking adapter's hyphenated schema,
build receipt, or source pin. The new module checks the recursive source pin and
uses `NduBridge` to verify the executable and request/response bindings.

The real upstream implementation evaluates

`U[k] = project(instant[k] + discount[k] * U[k+1])`

on a supplied finite path, then applies feasibility and Pareto selection. Its own
`recursive.rs` describes a scalar, zero-noise recursion, not a learned FBSDE. This
integration uses unit discount and rejects no costs by clipping. Native utility
and resource units are explicitly milliseconds and microseconds in Q32.32.

The host constructs bounded prospective paths:

1. Prepare a candidate, if it has no artifact. The executor must obtain fresh
   canonical, totality and equivalence acceptance before it can build/run it.
2. Buy the remaining sample quorum. At most one actual sample is performed before
   feedback is incorporated and all continuation paths are recomputed.
3. Pay the estimated cost of fresh native publication, then receive a *modeled*
   saving over the known remaining workload.

There are explicit actions to stop with the baseline or a fully measured
incumbent. Blocked candidates, insufficient measurement slots, resource ceilings,
and ties never grant execution permission. The native request's `verified` bit
only describes the bounded advisory action envelope; its support record says so.
It is not an HIA proof. There is no caller-supplied proof import or native-effect
authority in this module.

The calibration and empirical runtime envelopes are trusted host observations.
Future rates and preparation costs are declared model estimates. They can be
wrong. Actual elapsed work, including failed attempts, remains in the executor's
cost ledger. Already paid cost is bound in the snapshot but is not charged a
second time to each hypothetical future path. The final publication decision
separately charges all prior search work and its actual preparation budget.

The `arithmetic` backend is an intentionally strong control. It evaluates the
same no-discount scalar paths with exact integer arithmetic, the same feasibility
conditions, and the same treatment of ties. Equal decisions are expected. A
measured native-overhead loss must be reported; calling ordinary cost arithmetic
"NDU intelligence" would misrepresent this implementation.

## A workload with actual code-generation space

The research function is a total `u8,u8 -> u8` function:

```text
calculate(x, d) = x                            if d = 0
                  ((x / d) + (x % d)) mod 256 otherwise
```

Three proposals guard the parameter `d` with constants 3, 10 and 16. Each retains
the complete generic fallback. The original LLVM backend generates a hardware
unsigned divide in the generic function. Constant division on the guarded path
can become arithmetic or shifts/masks. This is actual machine-code diversity,
not constant folding that LLVM has already applied to identical input programs.

The canonical function declares the `trap` effect because it contains checked
division/remainder. The normal multiversion profile still refuses those opcodes.
The runtime must explicitly opt into `prove_total=True` and prove every input
returns normally, in addition to proving candidate equivalence. Unprotected zero
division, signed overflow and unproved cases cannot enter this runtime profile.

`hepta/hia_scalar_totality.py` asks whether the encoder's outcome tag is nonzero.
Positive tags are first traps; negative tags are incomplete symbolic paths. Only
UNSAT proves normal return. A SAT trap is independently replayed by the canonical
interpreter. Each proof has a new Z3 context and records the exact program,
input, totality-validator and scalar-encoder identities. Runtime admission
recomputes the obligation instead of trusting a stored receipt.

The measured workload is a serial byte recurrence in a C child process:

```text
state = calculate(state XOR input[index mod 64].x,
                  input[index mod 64].d)
```

Its data dependency exposes division latency instead of only the throughput of
independent calls. The recurrence is part of the predeclared workload for every
arm, including the baseline. It is not a claim about arbitrary application code.
The state is the C harness's local `uint8_t`; these are not millions of
`ScalarStateSession` atomic commits. The parent runtime separately holds old/new
generation leases, checks their behavior, performs publication, and rolls back a
published generation while its selected lease remains alive.

The native driver checks all 65,536 typed input pairs against an independent C
integer specification before each timed batch. A separate Python specification
checks the long recurrence's checksum and final state using cycle acceleration
over at most `64 * 256` states. These are finite ABI/backend observations, not a
machine proof of LLVM. Driver, library and input bytes are sealed before child
execution. Exact selected artifact bytes are retained for review.

## Frozen experiment contract

The normative protocol is the `PROTOCOL` object in
`tools/qualify_hia_economic_search.py`, saved before any measurement with the
source HEAD and hashes. The intended campaign has:

- three profiles: denominator 3 hot, denominator 16 hot, and mixed;
- separate frozen calibration, online and holdout seeds;
- three guarded candidates and the baseline;
- five calibration batches of 250,000 calls per artifact/profile;
- two successful online samples before a candidate can be published;
- at most six candidate samples and a two-second search budget per episode;
- 64 million actual holdout calls per episode, two repetitions per profile;
- eight arms: direct baseline, fixed 3, fixed 10, fixed 16, globally selected
  fixed action, exhaustive simple search, model-matched arithmetic, and native NDU;
- 48 total episodes in a rotating/reversed order, with no dropped attempts,
  retries, or post-result tuning.

The two-second search budget is a cooperative stage/admission limit, not hard
real time. An in-flight solver or compiler can overrun it up to its separately
bounded timeout; that actual cost remains charged and no subsequent candidate
execution or publication is allowed after the observed overrun.

The online empirical interval is the min/max observed batch runtime converted
to integer picoseconds per call. It is not a confidence interval or a proven
worst-case execution-time bound. Both baseline lower and candidate upper rates
are used in the publication gate. Picoseconds prevent integer-nanosecond rounding
from fabricating a one-nanosecond uncertainty floor in a few-nanosecond kernel.

Before formal execution, the source commit, protocol, seeds, sample count,
candidate set, measurement budget and cost denominators must be frozen. Focused
correctness tests use small explicit inputs and do not substitute for the formal
campaign. A failed proof/build/child retains its evidence and cost. No benchmark
result can change the source or cause an automatic retry until it wins.

## Cost accounting and acceptance

The same-information table and direct-deployment table are distinct:

- **Direct baseline** pays its actual baseline preparation, holdout, cleanup and
  required common driver/holdout-input setup. It pays no candidate calibration.
- **Model-dependent strategy deployment** (`fixed_selected`, arithmetic and NDU)
  additionally pays its required shared calibration and its actual online
  control/proof/compilation/measurement work. Fixed single-candidate strategies
  and exhaustive search use their own online measurements; they pay catalogue
  generation and online-input setup, not an unused calibration corpus.
- **Same information** brings every strategy's search-setup charge to the same
  full calibration amount, solely for an equal-information comparison. That accounting is never used to
  claim a deployment gain over a baseline that did not need the search corpus.
- **Native NDU cold cost** includes a fresh build of the real recursive bridge
  with an empty target directory and an existing declared dependency cache.

Common setup, calibration, bridge identity setup and bridge cold build are each
charged once per standalone strategy serving the six declared episodes. Their
per-episode amortization denominator is six, not 48. The physical research run
shares its calibration once across strategies; the accounting does not pretend
the shared work was physically repeated. A separate single-episode table charges
all required setup in full, including the cold bridge build.

The main NDU incremental condition requires all episodes to complete, at least
one actual NDU publication, and a paired median cold full-cost saving larger than
`max(1 ms, 1% of control median)` against **every** fixed/simple control, with
positive median savings in every profile. Those conditions must hold using
**actual required deployment costs** and, separately, same-information costs.
Adding unnecessary calibration costs to a fixed strategy cannot satisfy the
primary gate. No statistical significance or general advantage follows from
that descriptive condition.

A separate mechanism metric compares aggregate full cost over six deployments
against the direct baseline. It is reported separately for warm and cold costs,
requires real publication, and uses the same one-percent/one-millisecond
threshold. Native runtime-only speedups do not establish this metric. A useful
specialization can coexist with negative cold economics and with no incremental
NDU advantage. All three conclusions must be reported independently.

Search admission is checked before each online baseline batch, each controller
call, after controller return, and between proof/build/measurement stages. A
known overrun stops search and retains the baseline for the requested holdout.
Native child timeouts deduct sealing/oracle overhead before process launch.
Every episode additionally requires an after-close observation of complete
native release, no pending retirement, and absence of its owned runtime
directory. Later filesystem changes remain outside that observation.

The formal source check requires a clean worktree both before and after the
campaign. The recursive upstream must be clean at its exact pin before and after
the fresh build, and every source file recorded by that build is compared with
the actual pinned Git blob as well as the working bytes. Merely labelling dirty
source with an unchanged upstream HEAD is insufficient.
