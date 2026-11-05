# HCSN P2 iteration 29 — exact physical-time clock candidate: new negative result

2026-11-02. Additive research on Draft PR #512 only. **P0–P6 OPEN, independent strict gate exit 2, production_activation=false.** No main merge or signature/trust-root relaxation.

## Pinned branch snapshot

main 125d11c5454835a7df1dc51915fc49901fbede5b;
#468 00a9dc11714f35866be18cd4fece5ce3addefc4a (base main);
#481 407201690a617629255d7f5d0968ce4c544c1b93 (base research/hcsn-qvi-nonlocal-and-p1-controls-20261031);
#486 1aa8eb5f0efc2661472aa5a11221c07553152a03 (base research/hcsn-stochastic-renewal-20261031-gpt6);
#512 768832323d3680c0f6bb7d2ee7fa096d797918f5 (pre-commit HEAD, base research/hcsn-hardforward-ood-falsification-20261031-gpt6, 40 changed paths).
All OPEN/Draft; changed filenames and dependencies were checked for the relevant HCSN successor PRs #463/#483/#487/#492/#498/#500/#503/#505/#509/#511/#513/#526/#527. The four new paths are additive and do not overwrite the existing research.
The upstream Git blob hashes were independently fetched at pinned #512 HEAD: p2_no_event_dynamic_boundary.py = c853aefe0c1e4c8d33fa8fac44c7bfc8d3c88709; independent_gate.py = 4611f0569f62bff00d932b7b7e95743dbbccbc29. Workflow/combined-status queries returned no confirmed checks; **not CI PASS**.

## Scope and independent numerical reference

Under a held-constant observed context c and elapsed time dt, integrate the deterministic model dL/dt=(c-L)/4 and dV/dt=(abs(c-L)-V)/tau, tau=-1/log(.9) with a cancellation-aware exact semigroup. This replaces the original V <- .9 V + .1 abs(c-L) **per token**; it does not infer hidden first-hit times or solve original He–Xiong Eq8/11/12/A7/QVI.

An independently implemented SciPy solve_ivp(DOP853) reference matched 48 randomized FP64 intervals with maximum absolute error 1.14e-13. With the original three trained seeds (11/23/37), 4/16/64 observations over the same four-second held-context span give corrected volatility within 2.9e-7 and a common probe result [true,true,true]; the original token-clock model retains [true,false,false].

**New falsifier: state-clock consistency is not event-law consistency.** The corrected model still fires at every sampled token above threshold. In the identical held-context four-second stream, the *trained* corrected models emit pre-probe events [1,6,25] for seeds 11/37 and [1,6,26] for seed 23 as sample count changes 4/16/64. No evidence supports continuous-time autonomous event-count invariance.

## Frozen paired CPU OOD experiment

Three fixed seeds 11/23/37, query-only supervised, Adam 40 steps, batch 16, 64-token train streams, identical sample seeds and four declared trainable scalars. ID 48x64/4 segments; OOD 48x128/6 segments, irregular time, noise .23. Four policies: corrected clock, original dynamic, instantaneous, no-reset. **FLOPs, signed slopes and wall time are not matched**; no P1 acceptance is claimed.

| OOD mean (3 seeds) | corrected | original dynamic | instantaneous | no-reset |
|---|---:|---:|---:|---:|
| Hard MQAR accuracy | 93.017% | 93.750% | **95.525%** | 72.222% |
| Soft MQAR accuracy | 96.373% | 96.952% | 97.029% | 72.222% |
| Event precision (applied-reset models) | 41.433% | 42.194% | **48.873%** | n/a |
| Event recall (applied-reset models) | **93.750%** | 93.194% | 85.278% | n/a |
| Applied resets/stream | 11.333 | 11.056 | 8.729 | 0 |

Paired OOD hard accuracy corrected minus original for seeds [11,23,37] = [-0.0092593,-0.0092593,-0.0034723]. Against instantaneous = [-0.0300926,-0.0243056,-0.0208334]. All paired differences negative. Retain earlier P1/P2 null/negative results; no-reset *detector* precision/recall is not applied-event evidence.

## Exact execution and stored bytes

The .json.gz is deterministic gzip of complete unfiltered original raw JSON; decompress with gzip -dc to compare to the original uncompressed SHA256.

```bash
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 PYTHONPATH=. \
 python -m unittest research.hcsn.test_p2_no_event_dynamic_boundary research.hcsn.test_p2_physical_clock_invariance research.hcsn.test_p2_physical_clock_candidate -v
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 PYTHONPATH=. \
 python -m research.hcsn.p2_clock_candidate_evidence --output /tmp/hcsn-iteration29-recomputed.json
gzip -dc research/hcsn/gates/2026-11-02-iteration29-clock-candidate-raw.json.gz > /tmp/hcsn-iteration29-pinned.json
sha256sum /tmp/hcsn-iteration29-pinned.json
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 PYTHONPATH=. \
 python -m research.hcsn.independent_gate --bundle research/hcsn/gates --strict
```

Minimal CPU reconstructed environment Python 3.13, torch 2.10.0+cpu, numpy 2.3.5, SciPy 1.17: **20/20 PASS, no skips**; actual strict independent gate exited **2** with external trust root not configured. No full repository CI, independent cryptographic attestation, GPU/energy or four-modality pretrained encoder evidence.

SHA256:
- p2_physical_clock_candidate.py 38c24dd7dd65d6ef9815c002005807a940991c6d81324504c260a72303df888b
- test_p2_physical_clock_candidate.py cb532f391ce7956ee43721063cf1160f02f977030633e5ce02565fb723a4b5ff
- p2_clock_candidate_evidence.py 59822fbd07b8b526eb7f67ad2548dcca61ac4f650d3f65df0a07493fd1f456b5
- full uncompressed raw JSON f8929fa27431e2ebcd5b8b0162df8b73860e9658df31304a78ce03239919788e
- committed raw JSON gzip 32644c4c1658f7ed52a7ccb4d86cace634e325cf5bbbadf46b4dd6bc4faaaf95

P2 remains OPEN until a causal repeated-event timing mechanism passes sampling invariance, event precision/recall and true multi-seed heldout Selective Copy/MQAR; P0, P1 and P3–P6 lack their separate independent full-domain evidence. Production remains disabled.
