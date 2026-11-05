# HCSN P2 iteration 39 — protected holding works, and ordinary memory matches it

**Research-only; all P0–P6 scientific gates OPEN; production activation false.**

This experiment continues Draft #512 from exact source
`2140decfb47163aa93a5922795318e11f2f952bc`. It adds new files only and retains
iteration 38's positive-background-hazard counterexample.

## What changed and why

Iteration 38 established that a two-state memory with persistent positive blank
hazard forgets its last-write information exponentially. Here an observed signed
payload `x_k ∈ [-1,1]` controls the generator of key `k`:

`(a_k,b_k)=x_k² [(1-x_k)/2 · rates_minus + (1+x_k)/2 · rates_plus]`.

The two write-rate pairs contain **four trainable scalars**. They are learned
from requested last-value answers; no event-time, write-flag, reset-label, or
internal-state loss is supplied. However, the synthetic task grammar directly
provides exact signed key routing, and the square support function is hand
specified. This is **not** learned event recognition, a raw-token MQAR solver,
a free-boundary rule, or a He–Xiong/QVI derivation.

When payload is exactly zero, the whole generator is zero and probability is
held exactly for arbitrary elapsed physical time. A write to one key does not
change other keys. Requested queries read state and never enter the generator.

For `s=a+b`, the numerically stable exact transition is

`p_next = p + [-expm1(-s Δ)] · (a/s - p)`.

At `s=0` the multiplier is zero and a guarded denominator avoids division by
zero. There is no per-token decay approximation. Splitting the same physical
segment preserves its transition.

### The necessary attribution control

A four-parameter ordinary exponential memory is implemented separately in
coordinates `h=2p-1`:

`h_next = exp(-s Δ) h + [1-exp(-s Δ)] · (a-b)/s`.

This is an exact coordinate change of the protected CTMC probability update.
Therefore both have identical capacity, input information and trainable rate
parameters. They are independently trained with paired initialization, data and
optimizer budgets. A third control adds a fixed 0.04/s hazard in each direction,
including on blank keys. Unlike the preceding six-rate iteration-38 fit, the new
controls all use the same four learned write parameters; this is a fresh paired
experiment, not a retroactive remeasurement of the old architecture.

## Fixed local protocol and actual execution

The adjacent protocol was written before the full experiment. It is prospective
locally but **not externally preregistered or independently administered**.
Seeds 11/23/37 each receive 240 Adam updates, learning rate 0.065, and 64 fixed
28-segment training streams. Write durations are 0.75–1.5s; blank durations are
0.05–2s. There are four keyed binary memories and multiple requested queries.
All three models within a seed share initialization, examples and optimizer
budget. Held-out streams and their hashes are fixed separately.

The primary metric is expected correctness when the answer is obtained from
**one sampled binary memory state**. Hard thresholding an exact floating-point
probability is recorded only as a separate diagnostic. It is not substituted
for sampled-state accuracy, and cannot conceal near-erasure.

### Held-out results, mean of three seeds

| Task | Protected CTMC | Ordinary exponential | Positive-blank-hazard control |
|---|---:|---:|---:|
| 28-segment held-out ID | 99.1596% | 99.1596% | 86.5221% |
| 128-segment keyed overwrite / requested recall | 99.1143% | 99.1143% | 85.8246% |
| 128 segments, irregular blanks up to 32s | 99.1156% | 99.1156% | 75.6769% |
| One-key last-payload recall, irregular blanks | 99.1470% | 99.1470% | 91.7349% |
| Unseen short writes, 0.02–0.2s | **68.6365%** | **68.6365%** | 61.5525% |

These are finite synthetic tasks. The one-key task is a last-payload recall
probe; it is not the full Selective Copy benchmark. The keyed task supplies
routing and is not an unstructured learned associative memory.

### Long holding and retained failures

Opposite-order two-write histories followed by a common observed blank are
compared using the exact balanced endpoint Bayes accuracy. After **4096 seconds
of genuine zero payload**, protected CTMC and ordinary memory both retain
**98.5143%**, while the leaky control reaches **50%**. The less-than-perfect
protected figure comes from finite-duration writes, not subsequent blank decay.

The repair is deliberately challenged with a shared, sustained nonzero payload:

| Shared input during a 4096s hold | Protected CTMC / ordinary accuracy |
|---|---:|
| Exactly zero | 98.5143% |
| Amplitude 0.01 | **57.6726%** |
| Amplitude 0.05 | **50%** |

For any held nonzero input, the paired separation still obeys

`|p_B(D)-p_A(D)| = |p_B(0)-p_A(0)| exp[-(a(x)+b(x))D]`.

Thus exact-zero support repairs a known blank mechanism; it does not solve
persistent noise rejection. Faster write rates also increase the response to
nonzero distractors under this parameterization. The very short-write OOD
failure is preserved and was not used to retune the experiment.

Finally, two opposite unobserved final writes produce identical observed
streams. Their balanced answer bound remains **50%**. A missing true update
cannot be recovered from a zero-input holding convention.

## Independent numerical checks

- Ten focused tests pass: independent matrix exponentials; signed finite-
  difference gradients for all four rates; value/gradient ordinary-control
  equivalence; exact-zero hold; leaky counterexample; physical subdivision;
  chunk equivalence; causal prefix; read-only queries; other-key preservation;
  missing-information/noise negatives; training; malformed-input rejection;
  independent Gillespie endpoints.
- The full fixed study checks separate SciPy matrix exponentials with maximum
  absolute error **9.66e-15**. Ninefold physical subdivision differs by at most
  **3.33e-16**.
- Independently trained protected and ordinary outputs differ by at most
  **2.22e-16** over the 128-segment evaluation.
- **24,000 independent Gillespie trajectories** use exponential holding times
  and a separate RNG. They do not use the closed transition formula. Maximum
  descriptive endpoint deviation is **0.861 standard errors**. This is a finite
  numerical check, not a confidence theorem or scientific gate closure.
- The prior iteration-38 retention tests plus the new suite pass **17/17**,
  with no skips. The unchanged signed independent gate was actually executed
  and returned **2**, retaining all seven phases OPEN.
- The adjacent raw JSON binds source/test/protocol SHA-256 and train/held-out
  tensor hashes. Runtime: Python 3.12.14, PyTorch 2.10.0+cpu, single Torch/BLAS
  thread. Training wall times are diagnostic under shared CPU load and carry
  no efficiency or energy claim.

Training differentiates an exact expected-state likelihood. It does not
backpropagate through sampled spike times, and independent sampled endpoints do
not establish a learned event-time gradient.

## Reproduction

From the exact repository checkout and an environment with the existing HCSN
requirements:

```bash
OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 MKL_NUM_THREADS=1 \
  python -m unittest research.hcsn.test_p2_content_hold -v
OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 MKL_NUM_THREADS=1 \
  python -m research.hcsn.p2_content_hold_evidence --output /tmp/hcsn-content-hold.json
OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 MKL_NUM_THREADS=1 PYTHONPATH=research/hcsn \
  python -m unittest research.hcsn.test_p2_task_only_ctmc_retention research.hcsn.test_p2_content_hold -v
python -m research.hcsn.independent_gate --bundle research/hcsn --strict
```

The signed independent gate must return **exit 2**, with all phases OPEN.
`p2_content_hold_evidence --strict` also returns 2 after completing its study.
Wall/CPU timings naturally vary across reproductions; compare fixed numerical
results, data and source hashes, not byte identity of timing-bearing JSON.

## Acceptance boundary

This closes a narrow implementation question: exact-zero content support can
preserve information while learned writes update it, and the numerical operator
has an independently checked continuous-time implementation. The benefit is
**fully reproduced by ordinary exponential memory**. No HX-specific gain has
been demonstrated. Autonomous recognition of valid versus noisy updates, real
Selective Copy/MQAR, unknown input behavior, irregular-time weak-signal training,
full repeated-spike training, real encoders, hardware energy and scaled quality
remain outstanding. No production or full P2 acceptance is claimed.
