# HCSN P2 iteration 23 — hidden first-hit event time remains unobservable

**2026-11-01 — research-only; P0–P6 OPEN, DENY_ALL / NO_GO. No main merge or production activation.**

## Frozen source and overlap

- Repo `TrillionniumFoundation/Hepta`; main `125d11c5454835a7df1dc51915fc49901fbede5b`.
- Original research Draft #468 HEAD `00a9dc11714f35866be18cd4fece5ce3addefc4a` / base main.
- Stationary renewal Draft #481 HEAD `407201690a617629255d7f5d0968ce4c544c1b93` / base #468 branch.
- Two-state Markov renewal Draft #486 HEAD `1aa8eb5f0efc2661472aa5a11221c07553152a03` / base #481 branch.
- Additive change to Draft #512 branch `research/hcsn-edge-refractory-negative-20261031-gpt6`; exact parent `4de1b4eed9d400c80bee40a57ccce3fd59106cd9`, base #505 branch `research/hcsn-hardforward-ood-falsification-20261031-gpt6` (SHA `2ce3267ca148a6568497cc20b27c09c26058b739`).
- Other successors checked: #483, #487, #492, #498, #500, #503, #505, #509, #511, #513, #526, #527. Existing negative P1/P2 evidence is not overwritten. No conflicting filenames among the five new paths.

## New independently reproducible necessary-condition result

With positive observed margins `a,b` across a gap `T`, fixed diffusion `sigma`, constant relative drift, and a **deterministic affine** intra-gap boundary, the conditioned Brownian bridge has hidden-crossing probability

`p = exp[-2*a*b/(sigma²*T)]`.

The NEW time-sensitive result distinguishes a **posterior first-hit clock** from an actual observable spike. Let `alpha=u/T`, `s=sigma*sqrt(T*alpha*(1-alpha))`, `m=(1-alpha)*a+alpha*b`, `n=-(1-alpha)*a+alpha*b`. Then

`P(tau<=u | a,b) = Phi(-m/s) + p*Phi(n/s)`.

Divide this quantity by `p` for the first-hit time CDF conditional on a crossing. A separate implementation integrates the first-passage density times the Gaussian continuation density divided by the terminal endpoint density.

**Fixed witness:** `a=b=0.4, T=1s, sigma=0.4/sqrt(s)`. The hidden-hit probability is `0.1353352832366127`; conditional on a hit, the first-hit time is before `0.5s` with probability `0.6681020012231706` and after `0.5s` with probability `0.3318979987768294`. Its conditional median is `0.4032847880037541s`. Thus the exact same two observed safe endpoints do not identify whether a hit occurred before or after a physical refractory deadline. Assigning an endpoint/midpoint as the actual spike time is unjustified.

**Essential limitation:** This law is RETROSPECTIVE and requires the end-of-gap sample. Using it for a real-time decision before that sample would leak future information. It does not recover an actual hidden event timestamp, allow multiple resets, handle non-affine input-conditioned intra-gap barriers, or establish event-time gradients.

## Actually executed local tests

Reproduction commands from repository root:

```bash
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 python -m unittest research.hcsn.test_p2_hidden_first_hit_clock -v
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 python -m research.hcsn.p2_hidden_first_hit_clock_evidence --output /tmp/hcsn-iteration23-new.json
python -m research.hcsn.independent_gate --bundle research/hcsn --strict
```

- New unit tests **7/7 PASS**, zero skipped. Independent first-passage-density quadrature: 12 cases; maximum absolute FP64 disagreement `2.220446049250313e-16`.
- Independent sampled-bridge MC: seed `20261101`, `180000` paths, `35221` crossing by `u=0.57`; empirical `0.19567222222222222`, analytic `0.19605943174383744`, standardized deviation `0.4137866155510265`. Exploratory, not preregistered.
- All tests were run in a CPU **minimal reconstruction** consisting of newly added source/tests plus installed NumPy/SciPy, not a complete byte-identical remote checkout or GitHub CI.
- Original independent gate file matches fetched Git blob `4611f0569f62bff00d932b7b7e95743dbbccbc29`. Strict gate was **actually executed**: exit code `2`; `full_closure=false`, P0–P6 all OPEN, `production_activation=false`.
- For selected PR heads #468/#481/#486/#512/#513/#526/#527 the PR-triggered workflow-run query returned none, not a claim that no other workflow or independent test ran.

Source SHA256:
- `p2_hidden_first_hit_clock.py`: `9b95d1286a1ea079d18eba25f44676111899c8dfddfd6209b6216ada10086350`
- `test_p2_hidden_first_hit_clock.py`: `0b5b61adb6e467b3af3f006f158b6d7a100f85bd76f704d13c9b23a99169a138`
- `p2_hidden_first_hit_clock_evidence.py`: `c98d9c67453955b1ce7048303dc26995dda21bee84568ba489153ec6053c08d0`

Raw JSON: `research/hcsn/gates/2026-11-01-iteration23-hidden-event-clock.json`.

## Scientific blockers not closed

P0 original He–Xiong Eq8/11/12/A7 global equity obstacle, low-precision/QVI; P1 matched slope/parameters/FLOPs/training and independent positive OOD gain (existing ordinary gate negative result retained); P2 online input-driven learned dynamic boundaries, exact multiple autonomous events and long Selective Copy/MQAR OOD; P3/P4 held-out pretrained text, speech, image and video; P5 real CPU/GPU energy/RSS/p95/p99; P6 medium encoder quality–cost frontier. **All OPEN until independent signed evidence exists.**
