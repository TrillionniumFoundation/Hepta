# Scalar controls: frozen stop order and campaign interval reconciliation

The independent scalar-control verifier now checks two additional properties
of the existing registered experiment:

- Attempted calls form one uninterrupted prefix of the exact frozen schedule.
  The first call or audit failure ends that prefix. All later cells remain
  unstarted. Initial admission failure may leave every cell unstarted.
- Every attempted call interval lies inside the measured outer campaign
  interval. Original call durations, nonnegative integer overhead and outer
  duration reconcile without overlapping call intervals.

These are evidence validation changes. The selector, native evaluator, cost
metric, 64-pair registration and acceptance threshold are unchanged.

## Verification

Tested source commit: `0fed397e276505910e125eb54cbdfb902ee3e50c`, a child of
the #812/#814 integration `75e9a462465d94541d1706c2cebb5e30e623af27`.
The exact checker and test SHA-256 values are in `validation.json`.

All 15 evidence-control tests passed with zero skips. Three added tests cover
the stop boundary, valid initial/failed prefixes, and inclusive outer interval
and cost boundaries. The tests retain their explicit authored-fixture scope.

The updated independent verifier also read the original 1,283,026-byte archive
from `review-evidence/hia-ndu-scalar-controls-20261108-23d1/original-campaign.zip`,
SHA-256 `d9025d10bacdd5e8558625c26fce40130effc87e05fe962a2387bfd4680add6d`.
It verified 128 scheduled cells, 307 original objects, all 64 completed pairs,
and the 64 original successful native observations. No new native or provider
call was performed. `original-replay.json` retains the new verification result.

The original measurements are unchanged: complete ordinary calls totaled
4.460608 ms; native NDU calls totaled 938.923222 ms; zero of 64 pairs favored
NDU wall cost. The paired median ordinary-minus-NDU difference remains
-11.809995 ms. These are descriptive observations on the historical single
host and supplied scalar-cost profile, not independent training repetitions
or measurements on this source commit.

**P2 remains HOLD.** Byte integrity and accounting checks do not authenticate
clocks or provider billing, demonstrate incremental decision information, or
establish stable total benefit or an economic advantage.

## Reproduce the original-byte review

After extracting the original archive to a separate directory:

```bash
python -B -m unittest tests.test_hia_scalar_controller_controls -v
python -B tools/measure_hia_scalar_controller_controls.py verify \
  --directory /path/to/extracted/campaign \
  --expected-plan-sha256 882a8c1e8ed96c0b409c8f4183f6b6e079bafbe76a9872666b44304f1acbc493
```

The second command reads retained observations. It does not repeat the native
experiment or dispatch a provider request.
