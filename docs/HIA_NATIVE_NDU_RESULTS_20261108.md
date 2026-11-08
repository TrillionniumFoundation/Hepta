# Native NDU control experiment: original 2026-11-08 outcome

The eight scheduled cells completed. This four-pair experiment did not establish a stable time or economic benefit from NDU. It used one authored synthetic task with an explicit private teacher, zero learner/model calls, and a strong exhaustive ordinary control under the same proposal schedule and 30-second cell budget.

The immutable source was `d1c97d22d503b395ba9b0dfaa87e5a1c1b208fe6`; the entry was `93ef29d57090f62ffe71d7d05c5f40d0721f046f`. These results are not transferred to later source revisions. Original run: [42481215298](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42481215298).

## All paired outcomes

Positive delta means Ordinary took longer. Each cell includes its own real probe cost table; the table does not assume identical counterfactual timings.

| Pair | Order | Ordinary wall (s) | NDU wall (s) | Ordinary minus NDU (ms) |
| --- | --- | ---: | ---: | ---: |
| 1 | Ordinary → NDU | 28.444621243 | 28.151522011 | +293.099232 |
| 2 | NDU → Ordinary | 28.168215492 | 28.225260524 | -57.045032 |
| 3 | NDU → Ordinary | 28.099430130 | 28.265222647 | -165.792517 |
| 4 | Ordinary → NDU | 28.202310583 | 28.239202602 | -36.892019 |

The mean delta was **+8.342416 ms**, the median **−46.968526 ms**, and sample standard deviation **198.100220 ms**. One of four pairs favored NDU. Four pairs of one synthetic task do not establish a stable advantage or justify a general performance claim. The selected native artifact was byte-identical across all eight cells.

## Correctness, rejection and use

Every cell completed actual adoption, native consumer use on 256 inputs, and rollback. Each reduced its baseline artifact from 17,816 to 13,720 bytes. That shared improvement is not incremental NDU value. All 272 original events and all eight deliberately malformed/rejected proposals are retained; those rejection events consumed a measured 122.654640 ms in aggregate. The archive contains 664 content-addressed evidence objects.

The NDU rank stage took about 41.6–42.7 ms per cell, versus 31.7–32.5 ms for the ordinary control. The implementation ran the actual native evaluator; this task did not encounter a Pareto tie. The separate native ABI integration suite exercises that case.

## Cost boundary

The cell-wrapper total was 225.795785232 seconds. The enclosing experiment interval was 226.273419266 seconds, and the recorded workflow interval was 313.569457208 seconds from its first measurement step through final accounting. That workflow interval already includes checkout, dependencies and the 22.904358043-second build; nested intervals must not be added again. Queue time and final artifact upload were outside that observation interval.

The authored provider made **zero model calls**. ChatGPT coordination/authoring usage and fees, CI monetary cost, and complete billed cost are **unknown**. Unknown fields remain JSON null. No dollar saving, return on cost, or stable total benefit is claimed.

The generic underlying source result includes `teacher_used_by_provider=false`; the actual entry harness explicitly used the retained private teacher and records `private_teacher_used=true`. The original bytes are preserved. This experiment does not establish unfamiliar-Agent, blind-task or real-user-task performance.

## Reproducible evidence

The [original artifact ZIP](../review-evidence/hia-sixgap-20261108-c184/paired-native-original.zip) is retained byte-for-byte, with SHA-256 `a615bc5b3572179b8c23fef9aea6348b13fa653fe06ce52175e44a3901caac65` (3,924,231 bytes, 832 members). The [measured summary](../review-evidence/hia-sixgap-20261108-c184/paired-native-d1-summary.json) retains every scheduled cell, descriptive statistics, scope and unknown monetary fields. The [source and artifact provenance](../review-evidence/hia-sixgap-20261108-c184/paired-native-provenance.json) binds the original workflow and downloaded archive. An independent analyzer checked the original objects, 221 lock-bound source files, two additional exact-source files, 129 native build inputs and the actual native binary hash.
