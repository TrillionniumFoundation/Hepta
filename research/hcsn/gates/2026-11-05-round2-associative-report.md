# Learned raw-token associative memory: executed structural test, unresolved resets

**All four planned training runs completed. P2 scientific acceptance remains OPEN;
production activation remains false.** Ordinary gates improve bounded keyed
memory sharply in this new experiment, while one of two HCSN seeds fails to
learn. Every mode/seed still fails the complete repeated-reset sequence target.
This is a result that narrows the blocker, not a closed HCSN quality claim.

## What changed, and what was preserved

The previous raw-token recurrent experiment and all of its failures are retained
unchanged. A new independent audit reloaded all six actual checkpoints, regenerated
all nine held-out panels, and replayed **51,504 queries across 54 model/panel
pairs**. Predictions, probabilities and per-sequence counts match exactly:
maximum probability discrepancy **0**. Its **14 tests** were rerun successfully.

The existing local `p2_associative_memory.py` candidate and
`2026-11-05-round2-associative-protocol.json` were present but their campaign had
not been executed. This continuation completes that frozen protocol, adds ten
causal/learned-address tests, saves model/query evidence, and independently
replays it. It does not replace the old negative evidence or lower its targets.

Execution began from exact tracked #512 HEAD
`cad9fa2dedee8d13061282e19f59980bf215b703`. The copied P2 sources were previously
untracked; the execution record hashes each actual source and the protocol
before training and checks unchanged hashes after evaluation. The protocol was
local before evaluation, not an external preregistration or evaluator attestation.
It retains its older provenance base `d54ee89fb93a685716bac5a5ab5b66096444d1e5`.
The actual execution HEAD is independently recorded in the result.

## The structural intervention

Both learned modes use the same learned token embeddings, normalized address
projection, content projection, 8-by-16 associative state, three-token causal
control window, write/reset gates, and readout. There are **2,301 trainable
parameters** and **160 persistent state float values**, including the previous
two token embeddings. Every semantic token ID executes the same model code.

The model receives only token IDs, elapsed times, and its own optional streaming
state. The harness does not provide parsed key routing, correct values, write
masks, a true reset boundary, or a per-key memory table. `WRITE/key/value` and
`ASK/key/READ` are observable adjacent triples. The model learns to distinguish
`IGNORE/key/value`, which presents a plausible key/value pair that must not be
written. The deterministic causal grammar interpreter produces labels and is
never called by forward execution.

This changes the inductive bias and state size relative to the previous RNN
(48 state values and 10,197 parameters). It also narrows the training mixture to
four keyed tasks and adds an IGNORE token. It is **not a controlled isolation of
structure alone against the old RNN**, nor a Selective Copy solution. Within this
new architecture, ordinary and HCSN runs have exactly paired initialization,
training streams, parameter counts and update budgets.

HCSN uses the simplified stopping Call/Put channels, not the original full HX
or a solved neural QVI. The ordinary channel uses softplus. Global functions
and FLOPs differ; equal parameter counts do not establish equal optimization
geometry. Mapped Put+linear is derived from each fitted HCSN without retraining.

## Frozen training and complete accounting

- Seeds **401 and 503**, modes ordinary and HCSN; **300 Adam updates each**,
  batch 16, learning rate .006, norm clip 1.0.
- Updates 1–140 train MQAR and overwrite; updates 141–300 add tracking and
  visible RESET/rebinding. There is no checkpoint selection or retuning.
- **24,960 training queries per model**, **99,840 total**. All losses and all
  preclip gradient norms are retained. No nonfinite loss or gradient occurred.
- All four fits finish before any held-out panel is constructed or scored.
  Each model/panel is scored once; metrics and raw arrays use that same forward.
- Development probes at updates 140 and 300 remain progress-only. The earlier
  ordinary seed-73 development run remains marked development-only and its
  46.9539 wall seconds are conservatively charged in the budget.
- The new-training soft stop is 230 process CPU seconds. Actual training used
  **164.573 CPU seconds**; complete new campaign **170.021 CPU / 170.624 wall
  seconds**; peak RSS **325,947,392 bytes**. Adding the old development wall
  charge gives **216.975 seconds**, explicitly a mixed prior-wall/current-CPU
  accounting quantity, not a measured combined CPU total.

The finite diagnostic thresholds are unchanged from the preceding raw-token
campaign: query accuracy at least 95%, whole-sequence exact match at least 90%.
They were embedded in the hashed runner before training. Passing them would be
bounded experimental evidence, not independent scientific acceptance.

## Results: query accuracy / whole-sequence exact accuracy

Each panel contains 96 sequences. Model seeds reuse the same held-out streams;
there are not four independent datasets.

| Panel | Ordinary 401 | HCSN 401 | Ordinary 503 | HCSN 503 | Queries per model |
| --- | ---: | ---: | ---: | ---: | ---: |
| contextual_false_writes | 100.000% / 100.000% | 29.167% / 0.000% | 100.000% / 100.000% | 100.000% / 100.000% | 384 |
| irregular_time | 99.861% / 98.958% | 23.056% / 1.042% | 100.000% / 100.000% | 100.000% / 100.000% | 720 |
| mqar_id | 100.000% / 100.000% | 26.562% / 0.000% | 100.000% / 100.000% | 100.000% / 100.000% | 384 |
| mqar_long_distractors | 100.000% / 100.000% | 25.260% / 0.000% | 100.000% / 100.000% | 100.000% / 100.000% | 384 |
| overwrite | 100.000% / 100.000% | 30.990% / 1.042% | 100.000% / 100.000% | 100.000% / 100.000% | 384 |
| repeated_visible_resets | 99.002% / 81.250% | 16.363% / 0.000% | 99.479% / 89.583% | 99.262% / 83.333% | 2304 |
| short_intervals | 99.167% / 93.750% | 20.139% / 0.000% | 99.444% / 96.875% | 99.583% / 97.917% | 720 |
| state_tracking | 100.000% / 100.000% | 27.778% / 0.000% | 100.000% / 100.000% | 100.000% / 100.000% | 1152 |

Ordinary passes **7 of 8 bounded panels for each seed**. HCSN seed 503 passes
7 of 8; seed 401 passes **0 of 8**. No mode passes every panel for every seed.
The new evidence establishes that learned raw-token addresses can solve these
bounded MQAR, overwrite, tracking and contextual false-write tasks. It gives no
HCSN-specific gain and exposes a seed-dependent optimization failure.

### Why repeated resets remain a blocker

The repeated-reset panel issues four visible RESET commands and scores all
queries, including old keys not rebound after a reset. Ordinary seed 401 gets
2,281/2,304 queries right, but only **78/96 complete sequences**. Ordinary seed
503 gets 2,292/2,304 right and **86/96 complete sequences**; HCSN seed 503 gets
2,287/2,304 and **80/96 complete sequences**. All miss the 90% sequence target.

For these three substantially learned fits, respectively **23, 12 and 17**
wrong answers are false acceptances of unavailable old state; the raw metrics
record the same counts as stale answers emitted. This is a specific forgetting
and rebinding defect that a ~99% query average would hide. HCSN seed 401 is a
more general learning failure, not just a reset failure.

RESET is a visible command and no model state is externally cleared. These
results do not demonstrate autonomous first-passage or endogenous reset timing.
Clock panels remain discrete-token updates with independent elapsed-time inputs;
they do not certify a continuous-time semigroup or arbitrary event chronology.

### Channel attribution and exploratory diagnostics

Full FP32 mapped Put+linear maximum logit discrepancies are **2.3842e-7** for
HCSN seed 401 and **3.3379e-6** for seed 503. Double-precision values and gradients
also pass explicit equivalence tests. The second channel adds no independent
information in this parameterization.

A separately labelled **post hoc development-only** diagnostic inspects learned
addresses and gates without fitting or touching the held-out sets. Failed HCSN
seed 401 has maximum key off-diagonal inner product **0.4177**, versus roughly
**0.0443–0.0610** for the three learned fits. Its mean write gate on ignored
values is **0.0627**, versus **0.00143–0.00720**. These associations help locate
failed address separation and selective writing; they are not a universal causal
proof about a function family. Mean reset gate at the literal RESET token is
not a complete reset-timing metric because the causal window spans later tokens.

## Verification and retained evidence

**10/10 new tests pass**: grammar interpretation of IGNORE/overwrite/reset,
absence of label inputs, causal-prefix and chunk equivalence, generic semantic-ID
permutation equivariance, batch independence, mapped values and gradients,
actual query-loss gradients through learned address parameters, whole-sequence
scoring, invalid inputs, and matching parameter counts.

The semantic-ID permutation test simultaneously permutes all token IDs and the
embedding rows; predictions remain exactly unchanged. This would fail if the
forward path secretly branched on which ID meant WRITE, KEY, VALUE or RESET.

The independent artifact audit reloaded the four final checkpoints, regenerated
the eight panels, recounted all raw predictions and sequence metrics, and replayed
**25,728 queries across 32 model/panel pairs**. Maximum probability discrepancy
is **0**; all source, protocol, dataset and checkpoint hashes agree. This is
computational consistency checking, not an external independent attestation.

The existing independent scientific gate was executed unchanged with `--strict`:
**actual exit 2**, P0–P6 remain OPEN. It was neither renamed nor weakened to fit
this six-stage roadmap.

## Reproduce

Use the pinned source files, NumPy and PyTorch CPU; the result records exact
versions. Run from repository root with fresh output paths:

```bash
export OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 MKL_NUM_THREADS=1
python -m unittest research.hcsn.test_p2_round2_raw_tokens research.hcsn.test_p2_associative_campaign -v
python -m research.hcsn.audit_p2_raw_token_artifacts \
  --report research/hcsn/gates/2026-11-05-round2-p2-raw-token-results.json \
  --output /tmp/fresh-raw-token-audit.json
python -m research.hcsn.p2_associative_campaign \
  --protocol research/hcsn/gates/2026-11-05-round2-associative-protocol.json \
  --output /tmp/fresh-associative-results.json
python -m research.hcsn.audit_p2_associative_artifacts \
  --report research/hcsn/gates/2026-11-05-round2-associative-results.json \
  --protocol research/hcsn/gates/2026-11-05-round2-associative-protocol.json \
  --output /tmp/fresh-associative-audit.json
python -m research.hcsn.independent_gate --bundle research/hcsn --strict
# Expected final command exit: 2, because scientific acceptance remains open.
```

The soft CPU budget is retained. A slower environment may preserve a partial
training run without scoring any held-out panel; this is an incomplete budgeted
run, not a passing replay. No interrupted or failed run is discarded.

## Remaining work now made concrete

1. Prevent stale answers after repeated learned resets and preserve that result
   across all seeds and whole sequences; the 95% query threshold alone is insufficient.
2. Diagnose HCSN seed 401's training basin using development data and a new frozen
   budget before any new evaluation. Do not select only the successful seed 503.
3. Implement genuine ordered Selective Copy in a suitable learned state structure;
   this keyed-memory candidate deliberately does not cover that task.
4. Extend beyond adjacent triples and four fixed symbolic keys, then test unseen
   keys, delayed syntax, continuous event dynamics and real encoder inputs.
5. Demonstrate a Call/Put benefit beyond ordinary gates, reparameterization and
   extra state; none is established here.
