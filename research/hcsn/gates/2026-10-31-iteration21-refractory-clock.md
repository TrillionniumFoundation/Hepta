# HCSN P2 iteration 21 — physical-clock counterexample for token refractory

**2026-10-31 · research only · P0–P6 OPEN · NO_GO · production_activation=false**

## Frozen ancestry and branch isolation

Initial inspected heads: main 125d11c5454835a7df1dc51915fc49901fbede5b; #468 00a9dc11714f35866be18cd4fece5ce3addefc4a; #481 407201690a617629255d7f5d0968ce4c544c1b93; #486 1aa8eb5f0efc2661472aa5a11221c07553152a03 (all research PRs Draft). This additive patch is on **existing Draft #512**, branch research/hcsn-edge-refractory-negative-20261031-gpt6, starting SHA 52de111d3b6e6931a5500f3985e54c8f6eeac9dc, stacked on #505 at 2ce3267ca148a6568497cc20b27c09c26058b739. No modifications to #511, #513, main or production/evidence signing.

## New fixed-trace counterexample

In #512 the edge+refractory filter decrements cooldown **per token**, although irregular-time inputs have different physical delta times. Two sample grids with exact same raw detector pulses at physical times 0,1,2,3,4,5 seconds demonstrate the mismatch:

| Output event times | Grid 0.25s (23 samples) | Grid 0.125s (45 samples) |
|---|---|---|
| Edge + 5-token refractory | 0,2,4 seconds | 0,1,2,3,4,5 seconds |
| Edge + 2-second refractory | 0,2,4 seconds | 0,2,4 seconds |

No raw pulse has moved: extra samples are false detector states. The code includes an **independent bounded FP64 elapsed-clock reference** carrying causal state across chunks, explicit time-unit scaling, per-batch independence, invalid/nonmonotone clock rejection, and 100 seeded differential oracle traces.

This proves only a **fixed-detector clock-policy** counterexample. It does not show trained HCSN's full end-to-end behavior under resampling, genuine QVI event-time gradients, or a quality gain. Nor does it imply that 2 physical seconds is a good refractory threshold.

## Actually executed local evidence

Python 3.13.5, NumPy 2.3.5, CPU-only; focused **8/8 unittest PASS, 0 skip**. Executed local exact file bytes have these SHA256 digests:

- Source: cd84a55acd71aab45c83f70b8f989f23c60dfa1f9856aa4961dd510741f0e65f
- Tests: cc651616b74601e514ebc706bd5e463a05a23fcfd351a1b8fd2eb83e3453b541
- Reproduction generator: 545527a7411deef98d8baebdf70f26923a2767ccc49ed800adc270793cb4aa72

From repository root:

~~~bash
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 python -m unittest discover -s research/hcsn -p 'test_p2_refractory_time_invariance.py' -v
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 python -m research.hcsn.p2_refractory_time_evidence --output /tmp/hcsn-iteration21-raw.json
python -m research.hcsn.independent_gate --bundle research/hcsn --strict --output /tmp/hcsn-iteration21-strict.json
~~~

Third command **actually exited 2 in the local replay**, with P0–P6 all OPEN, full_closure=false and production_activation=false (no independent external trust root). Raw result JSON contains both grids' exact input SHA256 and timestamps. **No complete byte-identical GitHub checkout or remote CI was executed**, and the old model dependencies were not replayed.

## Remaining blockers

P0 original coupled Eq8/11/12/A7 global obstacle, interval low precision and QVI; P1 signed-slope/parameter/FLOP/budget-matched causal gain (preserve ordinary-gate negative results); P2 learned dynamic multi-event selective memory, true first-hit event training, multi-seed irregular-time OOD; P3/P4 pretrained four-modal encoder and independent heldout alignment; P5 actual CPU/GPU Joules RSS p95/p99; P6 medium-model frozen-budget frontier. **All OPEN**. Next independent experiment: integrate physical elapsed-time cooldown into the same frozen trained #512 models with unmodified ordinary and no-reset controls, measure actual event recall/precision and OOD query accuracy, and account for extra state/FLOPs.

No main merge, signature bypass or production activation.
