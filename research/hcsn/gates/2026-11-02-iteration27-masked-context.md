# HCSN P2 iteration 27 — noisy-context learned dynamic boundary negative control

2026-11-02. Research-only additive follow-up for Draft PR #512; no merge to main, no signature change, no production activation. Every P0–P6 scientific phase stays **OPEN**.

## Scope / limitations

A genuinely input-driven, task-only learned boundary uses the causal rolling context level and volatility to set a variable softplus threshold. A same-declared-parameter instantaneous threshold uses current context magnitude rather than historic volatility; a no-reset comparator has two **inactive** threshold parameters. Training uses **query BCE only**, never hidden reset labels. A separate oracle consuming true events is evaluation-only and is not a feasible causal classifier. The model is a four-scalar, manually wired memory controller, not the original HX QVI, the #486 Markov kernel, a pretrained Encoder, or a valid P1 FLOP/signed-slope-matched scientific claim.

The synthetic stream hides the exact context transition label from inputs, exposing only a noisy continuous context proxy, sparse key/value writes, queries and positive delta times. ID: 4 segments × 64 tokens, context noise 0.08; OOD: 6 segments × 128 tokens, noise 0.23, positive irregular dt. 3 paired seeds 11/23/37, 40 task-only Adam steps, batch 16, eval 48 streams per seed, independent ID/OOD test seeds; **9 train runs, 18 evaluation panels**. Hard reset uses `margin > 0`, whereas soft training uses `sigmoid(8*margin)`; not true stopping-time differentiation. The OOD panel is a synthetic distribution shift and not preregistered externally.

## Observed means, three paired seeds (exploratory, not significance evidence)

| OOD hard metric | Learned dynamic threshold | Instantaneous threshold | No-reset |
| --- | ---: | ---: | ---: |
| Query accuracy | 93.7500% | 95.5247% | 72.2222% |
| Event precision | 42.1941% | 48.8733% | 9.2086% detector only |
| Event recall | 93.1944% | 85.2778% | 99.8611% detector only |
| Detected events / stream | 11.0556 | 8.7292 | 54.2222 |
| Applied resets / stream | 11.0556 | 8.7292 | **0** |
| Soft query accuracy | 96.9522% | 97.0293% | 72.2222% |

The dynamic threshold loses **1.7747 percentage points** OOD hard query accuracy versus the instantaneous ordinary control; all three per-seed comparisons are negative, with more false triggers. Although dynamic recall is higher, it is not a free gain. Its soft/hard difference is **3.2022 points**. This does not show analytic Call/Put superiority, is not strong matched compute, and does not justify a new gate closure. Prior P1/P2 negative results remain intact.

## Actual local commands / hashes

```bash
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 python -m unittest research.hcsn.test_p2_no_event_dynamic_boundary -v
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 python -m research.hcsn.p2_no_event_dynamic_boundary --steps 40 --batch 16 --length 64 --eval-n 48 --seeds 11 23 37 --output research/hcsn/gates/2026-11-02-iteration27-masked-context-raw.json
python -m research.hcsn.independent_gate --bundle research/hcsn/gates --strict
```

Python 3.13 / torch 2.10 CPU / numpy 2.3.5, 9/9 tests PASS, zero skipped. `independent_gate.py` Git blob `4611f0569f62bff00d932b7b7e95743dbbccbc29` matches the unchanged Draft #468 and actually exits **2** without an externally provided trust root; all P0–P6 OPEN and `production_activation=false`. This is a local focused test, NOT complete remote branch CI.

- `p2_no_event_dynamic_boundary.py` SHA256 `bff9aa7dba1b4b73ae3445fdba39a7ef115e9df4eed47548848be0f6318d23c6`
- `test_p2_no_event_dynamic_boundary.py` SHA256 `5ec13be73e6c5c91198de5458189831a12615505b431b63ef83c11ea8bf70117`
- Raw JSON SHA256 `59c5ae532d7d16406707ab1aca6062ed0c6ea724f431ab1d80cd7b6ab8f23a97`
- Frozen parent #512 HEAD before patch `9d769d7f2bdbc8a5fdef776ca8d2e3a470d24ca9`, base #505 `2ce3267ca148a6568497cc20b27c09c26058b739`, original #468 `00a9dc11714f35866be18cd4fece5ce3addefc4a`, main `125d11c5454835a7df1dc51915fc49901fbede5b`.

## Strict acceptance

No independent heldout pretrained text/speech/vision/video Encoder, coupled HX global-domain A7/QVI proof, P1 signed-slope/FLOP trial, true event-time gradients, full MQAR OOD multi-seed scientific acceptance, real CPU/GPU end-to-end energy/p95/p99, medium-model quality/cost frontier, external signed observer/evaluator evidence. **P0–P6 OPEN, DENY_ALL, NO_GO.**
