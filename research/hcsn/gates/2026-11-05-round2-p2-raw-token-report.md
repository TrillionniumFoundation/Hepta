# Round 2 P2 — raw-token joint memory remains a measured blocker

**Research only. All scientific P0–P6 gates remain OPEN; production activation
is false.** The real experiment finished: six fits, three new seeds, matched
inputs and parameter counts, 543,600 training query labels and 51,504 held-out
query answers. This is not a planned-only benchmark or a new custom gate in
place of training.

## Source and frozen protocol

The work continues the existing Draft #512. The protocol's starting baseline was
`8e352b84a1286836d156a281e28956d07a60157e`; the recorded repository HEAD when
execution began was `d54ee89fb93a685716bac5a5ab5b66096444d1e5` (the parent's
P3/P4 protocol commit). New P2 source/test/protocol SHA-256 values were frozen
before the run and checked unchanged afterward. The adjacent P2 protocol was
written locally before scoring; **it was not an external preregistration**.
All six training runs completed before any held-out panel was scored.

Seeds are **101, 211, 307**, each with exactly 600 Adam updates, batch 24,
learning rate .003 and norm clipping at 1.0. Both models have **10,197 trainable
parameters**, 48 recurrent state dimensions and 16-dimensional token embeddings.
Initialization, training tokens, clocks, query labels and update budgets are
paired. Training-stream hashes match within all three pairs. There is no early
stopping, favorable-checkpoint selection, excluded failed run, or test-driven
retuning.

## The removed input shortcut

The learner receives **only a sequence of 19 token IDs and elapsed times**.
Raw WRITE/key/value and ASK/key/READ instructions appear in the observable
stream. No key one-hot routing, per-key memory slots, parsed write mask,
true state, episode number, reset label, query answer, or teacher-forced answer
is an input. Embeddings, recurrent dynamics and readout learn these relations.
A separate causal finite-state interpreter checks the generator's labels but
is never called by either neural model.

Selective Copy includes three independently sampled values at varying positions
among irrelevant symbols. After RECALL, three READ tokens must produce **all
values in order**. This prevents a last-value-only model from passing the task.
MQAR binds four raw keys to four values and asks multiple queries in a different
key order. Overwrite, interleaved state tracking and repeated commanded resets
are separate held-out panels.

RESET is an **observed command token**. The neural hidden state is never cleared
by the harness. Correct response to this token is learned from normal answer
loss, but it is not autonomous endogenous boundary detection or spike timing.
Elapsed time is sampled independently of token content and answers. A token
arrives as an instantaneous observation; its update is not multiplied by a
small exposure duration. This explicitly changes the preceding duration-scaled
write model's semantics, and cannot be presented as a proof that its no-go
result disappeared.

## Matched models and attribution

The HCSN candidate inserts the **simplified stopping** Call/Put channels into a
learned recurrent update. The fixed analytic parameters give beta=2, K=1 and
boundary 2/3. This is not the original coupled He–Xiong model or a solved neural
QVI. The ordinary control uses a softplus pair in the same architecture and
matches the initial signed update-logit slope at the channel origin. Parameter
counts, data and update budgets match; global channel slopes and FLOPs do not.

A separate Put+linear path uses the identity `Call-Put=v-1` with transformed
canonical weights. Double-precision forward and gradient tests pass. After the
actual trained, long FP32 recurrences, maximum mapped logit discrepancies were
8.11e-6, 5.67e-5 and 5.89e-5 across the three seeds. These are reported numerical
reparameterization errors, not extra channel information or proof of globally
identical floating-point behavior.

## Executed held-out results

Entries are means across all three model seeds. Whole-sequence exact match
requires every requested answer in that sequence to be right.

| Task | HCSN query accuracy | Ordinary query accuracy | HCSN sequence exact | Ordinary sequence exact | Queries / seed |
|---|---:|---:|---:|---:|---:|
| Selective Copy, 24 distractor/value positions | 56.944% | 56.684% | 6.510% | 6.510% | 384 |
| Selective Copy, 128 positions | 41.753% | 41.319% | 5.729% | 6.250% | 384 |
| Four-key MQAR | 52.995% | 53.451% | 2.604% | 2.344% | 512 |
| MQAR, long distractor spans | 41.406% | 40.690% | 0.781% | 0.521% | 512 |
| Eight overwrites followed by four queries | 45.964% | 46.549% | 0.000% | 0.000% | 512 |
| Queries interleaved with eight updates | 58.377% | 58.746% | 0.000% | 0.000% | 1536 |
| Four visible RESET commands | 57.812% | 58.127% | 0.000% | 0.000% | 3072 |
| Independent irregular elapsed time | 51.994% | 51.754% | 3.125% | 3.125% | 836 |
| Very short event intervals, 0.005–0.02s | 52.911% | 52.592% | 4.427% | 4.948% | 836 |

Every model seed fails the frozen local operational requirement of query
accuracy >=95% and sequence exact >=90% across every panel. **No finite P2
quality gate is passed.** Small score differences between the two variants are
not evidence of independent HCSN benefit. The data are symbolic, the budget is
bounded, and only three model seeds are included.

A particularly diagnostic result: both models answer **all 512 immediate
post-RESET UNKNOWN queries correctly per seed**. Yet their accuracy after new
bindings following RESET is only about 48–49%, and **zero complete repeated-reset
sequences pass**. Checking only the immediate reset response would have hidden
the real memory/rebinding failure.

The previous keyed CTMC's ~99% result is not directly comparable: that experiment
provided exact key routing and measured expected sampled-state correctness.
The present task requires learned raw-token routing and exact ordered/multiple
answers. The new failure is evidence that the old easy interface did not
establish raw-token memory competence.

## A closed negative verdict for the old noise/short-write requirements

The separate `p2_round2_operating_witness.py` uses independent SciPy matrix
exponentials to verify the following conditional impossibility result.

For the old two-state model, write error <=epsilon after exposure d requires,
even with an ideal one-way write,

`lambda >= -log(epsilon)/d`.

With a shared nonzero input of amplitude x, the old x-squared-supported mixture
contracts terminal-state separation by `exp(-lambda*x^2*D)`. For one sampled
terminal binary observation, even a perfect initial separation cannot retain
balanced Bayes accuracy >=1-epsilon unless

`lambda <= -log(1-2*epsilon)/(x^2*D)`.

For epsilon=.01, d=.02s, x=.01 and D=4096s, the necessary bounds are
**lambda >=230.2585/s** and **lambda <=0.0493230/s**. The interval is empty by a
factor of 4668.38. Both write polarities must meet the fast-write target, so a
convex mixture cannot evade the lower bound by choosing one slow polarity.
Nonzero wrong-direction rates only make the optimistic write bound harder.

Independent matrix witnesses give:

| Rate choice | Write success after .02s | Retention accuracy after 4096s |
|---|---:|---:|
| Minimum rate for the fast-write target | 99.0000% | 50.0000% |
| Maximum rate for the noisy-hold target | 0.0986% | 99.0000% |

This rejects **that model family under those simultaneous requirements**. It is
not a theorem against general neural memory, real-valued hidden states, extra
states, content rejection, deadzones, or different noise processes.

An engineering operating range must therefore state its assumptions. Under the
same optimistic old model, preserving the fast-write target permits only about
**0.8774s** of the specified noise at the 1% retention-error target. A 4096s hold
would require noise amplitude at most about **0.00014636**; retaining amplitude
.01 would instead require write exposure at least **93.3676s**. Exact-zero
blank support remains a separate favorable regime. These are necessary bounds,
not sufficient deployment guarantees.

Four different equally likely unobserved final values also produce identical
raw token histories. The independent information ceiling is **25%**, or
abstention. Neural output cannot reconstruct information absent from all input.
All six actual missing-update checks obey this limit.

## Tests, cost and retained artifacts

- **14/14 focused tests pass**, covering independent language interpretation,
  ordered recall, overwrite/reset truth, clock independence, absence of label or
  episode inputs, causal prefix, streaming, batch independence, BPTT, active
  architecture use, exact Put+linear gradients, missing information and invalid
  input rejection. A small training smoke verifies the actual query-loss path.
- All six fits retain their complete loss traces, gradient norms, learned weight
  arrays and every held-out query's position, label, prediction and probability.
- Peak process RSS was **317,272,064 bytes**; total experiment wall time was
  **405.33 seconds** on one Torch/BLAS thread. Device energy is not measured.
  HCSN training used 73.28–81.23s per seed and ordinary training 50.83–59.30s in
  this shared CPU execution. These are local training diagnostics, not a fixed-
  quality end-to-end speed or energy qualification.
- No nonfinite loss or gradient occurred. Preclip gradient maxima reached 2.18;
  clipping was active, so this is not an unclipped/global gradient-stability
  theorem.
- The twelve small checkpoint/query NPZ files total **1,372,972 bytes**. They
  contain numeric arrays only and load with `allow_pickle=False`.
- Source, protocol, datasets, model checkpoints and raw query artifacts have
  explicit hashes. Prior source and negative results were preserved.

## Coverage and remaining blocker boundary

| Requirement | What this round actually establishes | Remaining result |
|---|---|---|
| Raw-token input without oracle routing | Executed learned embedding/recurrent path; independent causal labels and leakage checks | Implemented and tested input contract |
| Ordered Selective Copy | All three answers scored, short and long distractor spans | Quality fails |
| MQAR / overwrite / tracking | Multiple keys, repeated writes, online queries, per-sequence exact scores | Quality fails |
| Several resets | Hidden state is not externally zeroed; immediate UNKNOWN responses are correct | Rebinding and whole sequences fail; autonomous reset remains untested |
| Irregular / short intervals | Independent clock controls and real token updates | Quality fails; does not certify continuous event semantics |
| Old noisy continuous-write kernel | Disjoint necessary bounds plus independent matrix witness | Specified simultaneous requirements rejected |
| Missing writes | Identical observations / conflicting unseen labels stay within information bound | Requires explicit information-availability assumptions |
| Free-boundary-specific advantage | Matched ordinary pair and Put+linear identity retained | Not demonstrated |
| Scientific P2 acceptance | Actual quality failures remain visible | OPEN |

## Exact commands

```bash
OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 MKL_NUM_THREADS=1   python -m unittest research.hcsn.test_p2_round2_raw_tokens -v
OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 MKL_NUM_THREADS=1   python -m research.hcsn.p2_round2_raw_tokens_evidence   --output /tmp/hcsn-p2-round2-fresh.json
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1   python -m research.hcsn.p2_round2_operating_witness   --output /tmp/hcsn-p2-operating-witness.json
python -m research.hcsn.independent_gate --bundle research/hcsn --strict
```

Use a fresh output path for full reproduction; the runner refuses to overwrite
an existing study or artifact directory. The independent scientific gate remains
nonzero (exit 2). Passing implementation tests cannot override the measured
quality failures or authorize production activation.
